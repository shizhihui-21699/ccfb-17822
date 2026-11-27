import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/dart/element/type.dart';

import '../src/range.dart';
import '../src/taint.dart';

/// Helpers for reading analyzer types without importing internals.
class TypeUtil {
  static bool isInt(DartType? t) => t is InterfaceType && t.isDartCoreInt;
  static bool isNum(DartType? t) => t is InterfaceType && t.isDartCoreNum;
  static bool isDouble(DartType? t) =>
      t is InterfaceType && t.isDartCoreDouble;
  static bool isDynamic(DartType? t) => t is DynamicType;
}

/// Flow-insensitive, fixed-point integer state computation for one
/// compilation unit.
///
/// The visitor walks post-order: every visit method first delegates to
/// [super] so child expression states are computed, then derives the state
/// of the current node. Element-level summaries (parameters, locals,
/// fields) are iterated to a fixed point by [CheckerDriver].
class IntStateVisitor extends RecursiveAstVisitor<void> {
  /// Latest state per expression node (rebuilt every pass).
  final Map<Expression, IntState> exprState = {};

  /// Summary state per declared element, carried across passes.
  final Map<Element, IntState> elementState;

  /// Elements explicitly annotated web-safe / web-unsafe.
  final Set<Element> safeElements;
  final Set<Element> unsafeElements;

  /// Method names (bare or qualified) configured as extra untrusted sources.
  final Set<String> extraSources;

  IntStateVisitor({
    required this.elementState,
    required this.safeElements,
    required this.unsafeElements,
    required this.extraSources,
  });

  static final BigInt _int32Min = BigInt.from(-2147483648);
  static final BigInt _int32Max = BigInt.from(2147483647);

  bool _outsideInt32(IntRange r) {
    if (r.lo == null || r.hi == null) return true;
    return r.lo! < _int32Min || r.hi! > _int32Max;
  }

  /// Top-level variables and static fields expose their implicit getter as
  /// the identifier's static element; normalize to the underlying variable.
  static Element? _canonical(Element? e) {
    if (e is PropertyAccessorElement) {
      // analyzer 6 exposes `variable`; analyzer 7 renamed it `variable2`.
      final dynamic accessor = e;
      try {
        return (accessor.variable2 ?? accessor.variable) as Element?;
      } catch (_) {
        return e;
      }
    }
    return e;
  }

  IntState _stateOf(Expression e) {
    final direct = exprState[e];
    if (direct != null) return direct;
    // Nested identifiers can be reached via binary-expression traversal
    // without their own visit having populated the table; fall back to the
    // element summary.
    if (e is SimpleIdentifier) {
      return elementState[_canonical(e.staticElement)] ?? IntState.noInt;
    }
    if (e is PrefixedIdentifier) {
      return elementState[_canonical(e.staticElement)] ?? IntState.noInt;
    }
    return IntState.noInt;
  }

  void _store(Expression e, IntState s) {
    exprState[e] = s;
  }

  // ---------------------------------------------------------------- literals

  @override
  void visitIntegerLiteral(IntegerLiteral node) {
    super.visitIntegerLiteral(node);
    final v = node.value;
    if (v == null) {
      _store(node, IntState.unboundedInt);
      return;
    }
    final range = IntRange.exact(BigInt.from(v));
    // A literal is a mathematically known value, hence a safe operand.
    // Over-large literals are still caught independently by WEB_INT_001.
    _store(node, IntState(range, const {}, safe: true));
  }

  @override
  void visitDoubleLiteral(DoubleLiteral node) {
    super.visitDoubleLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitBooleanLiteral(BooleanLiteral node) {
    super.visitBooleanLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitNullLiteral(NullLiteral node) {
    super.visitNullLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    super.visitSimpleStringLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitAdjacentStrings(AdjacentStrings node) {
    super.visitAdjacentStrings(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    super.visitStringInterpolation(node);
    _store(node, IntState.noInt);
  }

  // --------------------------------------------------------------- reference

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    super.visitSimpleIdentifier(node);
    final element = _canonical(node.staticElement);
    if (element != null) {
      final summary = elementState[element];
      if (summary != null) {
        _store(node, summary);
        return;
      }
    }
    if (TypeUtil.isInt(node.staticType)) {
      _store(node, IntState.unboundedInt);
    }
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    super.visitPrefixedIdentifier(node);
    final element = _canonical(node.staticElement);
    if (element != null) {
      final summary = elementState[element];
      if (summary != null) {
        _store(node, summary);
      }
    }
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    super.visitPropertyAccess(node);
    final element = _canonical(node.propertyName.staticElement);
    if (element != null) {
      final summary = elementState[element];
      if (summary != null) {
        _store(node, summary);
      }
    }
  }

  // ------------------------------------------------------------- parenthesis

  @override
  void visitParenthesizedExpression(ParenthesizedExpression node) {
    super.visitParenthesizedExpression(node);
    _store(node, _stateOf(node.expression));
  }

  // ------------------------------------------------------------- arithmetic

  static const _arithOps = {'+', '-', '*', '%', '~/', 'remainder'};
  static const _bitwiseOps = {'&', '|', '^'};
  static const _shiftOps = {'<<', '>>', '>>>'};

  @override
  void visitBinaryExpression(BinaryExpression node) {
    super.visitBinaryExpression(node);
    final op = node.operator.lexeme;
    final left = _stateOf(node.leftOperand);
    final right = _stateOf(node.rightOperand);

    if (op == '==') {
      _store(node, IntState.noInt);
      return;
    }

    // Double operands: IEEE-754 semantics are identical on every target.
    if (!TypeUtil.isInt(node.staticType)) {
      _store(node, IntState.noInt);
      return;
    }

    if (_arithOps.contains(op)) {
      final range = (left.isInt || right.isInt)
          ? RangeOps.binary(op == 'remainder' ? 'remainder' : op,
              left.range ?? IntRange.unknown, right.range ?? IntRange.unknown)
          : IntRange.unknown;
      _store(node, IntState.joinTaint(range, [left, right]));
    } else if (_bitwiseOps.contains(op)) {
      final range = RangeOps.binary(
          op, left.range ?? IntRange.unknown, right.range ?? IntRange.unknown);
      _store(node, IntState.joinTaint(range, [left, right]));
    } else if (_shiftOps.contains(op)) {
      final range = RangeOps.binary(op, left.range ?? IntRange.unknown,
          right.range ?? IntRange.unknown);
      _store(node, IntState.joinTaint(range, [left, right]));
    } else {
      _store(node, IntState.unboundedInt);
    }
  }

  @override
  void visitPrefixExpression(PrefixExpression node) {
    super.visitPrefixExpression(node);
    final op = node.operator.lexeme;
    final operand = _stateOf(node.operand);
    if (!operand.isInt && !TypeUtil.isInt(node.staticType)) {
      _store(node, IntState.noInt);
      return;
    }
    if (op == '~' || op == '-') {
      final range = RangeOps.unary(op, operand.range ?? IntRange.unknown);
      _store(node, IntState.joinTaint(range, [operand]));
    } else {
      _store(node, operand);
    }
  }

  // ----------------------------------------------------------- assignments

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    super.visitAssignmentExpression(node);
    final op = node.operator.lexeme;
    final rhs = _stateOf(node.rightHandSide);
    final lhsElement = _writeElement(node.leftHandSide);

    if (op == '=') {
      if (lhsElement != null) _joinElement(lhsElement, rhs);
      _store(node, rhs);
      return;
    }
    // Compound assignment: synthesize the binary state from current LHS.
    final bareOp = op.substring(0, op.length - 1);
    final lhs = _stateOf(node.leftHandSide);
    final combined = IntState.joinTaint(
      RangeOps.binary(
          bareOp, lhs.range ?? IntRange.unknown, rhs.range ?? IntRange.unknown),
      [lhs, rhs],
    );
    if (lhsElement != null) _joinElement(lhsElement, combined);
    _store(node, combined);
  }

  Element? _writeElement(Expression lhs) {
    if (lhs is SimpleIdentifier) return _canonical(lhs.staticElement);
    if (lhs is PrefixedIdentifier) return _canonical(lhs.staticElement);
    if (lhs is PropertyAccess) {
      return _canonical(lhs.propertyName.staticElement);
    }
    if (lhs is IndexExpression) return null;
    return null;
  }

  void _joinElement(Element element, IntState incoming) {
    final existing = elementState[element];
    elementState[element] =
        existing == null ? incoming : IntState.merge(existing, incoming);
  }

  // --------------------------------------------------------- control / merge

  @override
  void visitConditionalExpression(ConditionalExpression node) {
    super.visitConditionalExpression(node);
    _store(
        node,
        IntState.merge(
            _stateOf(node.thenExpression), _stateOf(node.elseExpression)));
  }

  @override
  void visitIfStatement(IfStatement node) {
    // Visit both branches; assignments are joined via element summaries.
    node.expression.accept(this);
    node.thenStatement.accept(this);
    node.elseStatement?.accept(this);
  }

  // ------------------------------------------------------------------- casts

  @override
  void visitAsExpression(AsExpression node) {
    super.visitAsExpression(node);
    final target = node.type.type;
    final inner = _stateOf(node.expression);
    if (TypeUtil.isInt(target)) {
      // Casting an external/dynamic number to int is the precise entry point
      // where untrusted precision enters the int world.
      _store(
          node,
          inner.isInt
              ? inner
              : IntState(IntRange.unknown, inner.taints, safe: inner.safe));
    } else {
      // A cast to Map/List/dynamic keeps provenance so later indexing can
      // recover the taint.
      _store(node, IntState(null, inner.taints, safe: inner.safe));
    }
  }

  // ------------------------------------------------------------- invocations

  static const _jsonMethods = {'jsonDecode', 'json.decode', 'JsonDecoder.convert'};
  static const _parseMethods = {'parse', 'tryParse'};
  static const _numConverters = {
    'toInt', 'round', 'floor', 'ceil', 'truncate',
  };

  @override
  void visitMethodInvocation(MethodInvocation node) {
    super.visitMethodInvocation(node);
    final name = node.methodName.name;
    final qualified = _qualifiedName(node);
    final args = node.argumentList.arguments.map(_stateOf).toList();

    // JSON sources.
    if (_jsonMethods.contains(qualified) ||
        _jsonMethods.contains(name) ||
        extraSources.contains(qualified) ||
        extraSources.contains(name)) {
      final isConfigured = !_jsonMethods.contains(qualified) &&
          !_jsonMethods.contains(name);
      _store(
          node,
          IntState(IntRange.unknown, {
            isConfigured ? TaintSource.configured : TaintSource.json
          }));
      return;
    }

    // int.parse / int.tryParse.
    if (_parseMethods.contains(name) && _targetIsInt(node)) {
      _store(node, _parseState(node, args));
      return;
    }

    // num conversions.
    if (_numConverters.contains(name) &&
        TypeUtil.isInt(node.staticType) &&
        (TypeUtil.isNum(node.realTarget?.staticType) ||
            TypeUtil.isDouble(node.realTarget?.staticType))) {
      _store(node,
          IntState(RangeOps.fromNumConversion(), {TaintSource.numConversion}));
      return;
    }

    // hashCode of an int-typed receiver is itself int, but identity-sensitive.
    if (name == 'hashCode' && TypeUtil.isInt(node.staticType)) {
      final target = _stateOf(node.realTarget!);
      _store(node, IntState.joinTaint(IntRange.unknown, [target]));
      return;
    }

    // Unknown int-returning method: clean unknown, no taint propagation.
    if (TypeUtil.isInt(node.staticType)) {
      _store(node, IntState.unboundedInt);
    }
  }

  IntState _parseState(MethodInvocation node, List<IntState> args) {
    final first = node.argumentList.arguments.isEmpty
        ? null
        : node.argumentList.arguments.first;
    if (first is StringLiteral) {
      final raw = first.stringValue;
      if (raw != null) {
        final parsed = BigInt.tryParse(raw);
        if (parsed != null) {
          return IntState(IntRange.exact(parsed), const {}, safe: true);
        }
      }
    }
    return const IntState(IntRange.unknown, {TaintSource.parse});
  }

  bool _targetIsInt(MethodInvocation node) {
    final target = node.realTarget;
    if (target == null) return false;
    final t = target.staticType;
    return t is InterfaceType && t.isDartCoreInt;
  }

  String _qualifiedName(MethodInvocation node) {
    final target = node.realTarget;
    if (target is SimpleIdentifier) return '${target.name}.${node.methodName.name}';
    return node.methodName.name;
  }

  // ------------------------------------------------------------ index access

  @override
  void visitIndexExpression(IndexExpression node) {
    super.visitIndexExpression(node);
    final target = _stateOf(node.realTarget);
    // Indexing into a JSON-derived dynamic map/array yields tainted data.
    // Keep the taint even when the static result type is dynamic (range
    // unknown until an `as int` or int-typed assignment).
    if (target.isTainted || target.safe) {
      _store(
          node,
          TypeUtil.isInt(node.staticType)
              ? IntState(IntRange.unknown, target.taints, safe: target.safe)
              : IntState(null, target.taints, safe: target.safe));
    } else if (TypeUtil.isInt(node.staticType)) {
      _store(node, IntState.unboundedInt);
    }
  }

  // ------------------------------------------------------------- collections

  @override
  void visitListLiteral(ListLiteral node) {
    super.visitListLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitSetOrMapLiteral(SetOrMapLiteral node) {
    super.visitSetOrMapLiteral(node);
    _store(node, IntState.noInt);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    super.visitMapLiteralEntry(node);
  }

  // ------------------------------------------------------------------ locals

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    super.visitVariableDeclaration(node);
    final element = node.declaredElement;
    if (element == null) return;
    final init = node.initializer;
    if (init == null) {
      if (TypeUtil.isInt(element.type)) {
        _joinElement(element, IntState.unboundedInt);
      }
      return;
    }
    final state = _stateOf(init);
    if (!state.isInt) {
      // Keep non-int provenance (taint) on the element but don't invent a
      // range; still seed so references resolve.
      _joinElement(element, state);
      return;
    }
    // A declaration's initializer is the defining value. Keep it exact
    // instead of merging with the unbounded seed, so `const m = 0xFF` reads
    // as the constant 255 at every use site. Later assignments still merge.
    final existing = elementState[element];
    if (existing == null ||
        (existing.range == null || existing.range!.isUnbounded) ||
        node.isLate ||
        element is LocalVariableElement) {
      if (element is LocalVariableElement) {
        elementState[element] = state;
      } else {
        elementState[element] = state;
      }
    }
  }

  @override
  void visitVariableDeclarationStatement(VariableDeclarationStatement node) {
    super.visitVariableDeclarationStatement(node);
  }

  // -------------------------------------------------------------------- loops

  @override
  void visitForStatement(ForStatement node) {
    final parts = node.forLoopParts;
    if (parts is ForPartsWithDeclarations) {
      parts.variables.accept(this);
      for (final v in parts.variables.variables) {
        final element = v.declaredElement;
        if (element != null &&
            TypeUtil.isInt(element.type) &&
            !elementState.containsKey(element)) {
          _joinElement(element, IntState.unboundedInt);
        }
      }
      parts.condition?.accept(this);
      for (final u in parts.updaters) {
        u.accept(this);
      }
    } else {
      parts.accept(this);
    }
    node.body.accept(this);
  }

  // --------------------------------------------------------- external inputs

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    super.visitFunctionDeclaration(node);
  }

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    super.visitMethodDeclaration(node);
  }

  // Exposed for the rule checker pass.
  bool isSafe(Element e) => safeElements.contains(e);
  bool isUnsafe(Element e) => unsafeElements.contains(e);
  bool outsideSafe(IntRange r) => r.canLeaveSafeRange();
  bool outsideInt32(IntRange r) => _outsideInt32(r);
}
