// Copyright 2026. All rights reserved.
//
// The analysis engine: a small abstract interpreter over integer expressions
// that decides, per operator, whether the JavaScript target can produce a
// different result from the VM/Wasm targets.
//
// Design notes
// ------------
// * Findings are driven by *intervals plus provenance*, not by operator
//   frequency. A `<<` on a loop counter whose range is [0..10] never reports;
//   the same `<<` on a value that came from `jsonDecode` always does.
// * Constant subexpressions are folded twice: once with exact 64-bit math and
//   once with the JavaScript model, so a difference is a fact, not a guess.
// * Taint is propagated through locals, fields, parameters, collections and
//   constructor initialisers, because in the incident the hostile id arrives
//   via `jsonDecode(...)['id'] as int` and travels several calls deep before it
//   reaches the checksum.
// * Each node is reported at most once per finding code, no matter how many
//   evaluation paths reach it.

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/constant/value.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/dart/element/type.dart';

import 'int_range.dart';
import 'model.dart';
import 'target_semantics.dart';

/// Options controlling how much the engine reports.
class AnalysisOptionsData {
  const AnalysisOptionsData({
    this.strictness = Strictness.standard,
    this.trustedFunctions = const <String>{},
    this.trustedParameters = const <String>{},
    this.entryPoints = const <String>{},
  });

  final Strictness strictness;

  /// Names of functions whose return values are considered trusted.
  final Set<String> trustedFunctions;

  /// Parameter name (`function.parameter`) or bare name that is trusted.
  final Set<String> trustedParameters;

  /// Functions treated as attacker-facing entry points: all their `int`
  /// parameters start untrusted.
  final Set<String> entryPoints;

  bool get strict => strictness == Strictness.strict;
  bool get minimal => strictness == Strictness.minimal;
}

/// Analyzes one compilation unit and produces findings.
class UnitAnalyzer {
  UnitAnalyzer({
    required this.unit,
    required this.content,
    this.typeProvider,
    this.options = const AnalysisOptionsData(),
    this.trustEntireLibrary = false,
  });

  final CompilationUnit unit;
  final String content;
  final Object? typeProvider;
  final AnalysisOptionsData options;

  /// When true, every `int` parameter of every function is treated as
  /// attacker controlled.
  final bool trustEntireLibrary;

  final List<Finding> findings = <Finding>[];

  /// Known values for locals and fields, keyed by element.
  final Map<Element, IntRange> _values = <Element, IntRange>{};

  /// The value a function returns, keyed by its element, for taint propagation
  /// through user function calls.
  final Map<Element, IntRange> _returnValues = <Element, IntRange>{};

  /// Guards against re-entrant evaluation loops.
  final Set<AstNode> _inProgress = <AstNode>{};

  /// Constant folds already computed, per AST node.
  final Map<AstNode, _ConstantFold> _constantFoldCache =
      <AstNode, _ConstantFold>{};

  /// De-duplication: one finding per (offset, code).
  final Set<String> _reported = <String>{};

  void analyze() {
    _collectDeclarations();
    // Two passes. Pass 1 walks every body to discover which call sites pass
    // attacker-controlled values into a function or constructor. Pass 2 does
    // it again with those parameters marked untrusted, so the taint is visible
    // inside the callee (the incident's `computeOrderChecksum(orderId, ...)`).
    unit.accept(_BodyVisitor(this));
    if (_propagatedTaint.isNotEmpty) {
      for (final entry in _propagatedTaint.entries) {
        final existing = _values[entry.key];
        if (existing == null || !existing.isUntrusted) {
          _values[entry.key] = entry.value;
        }
        // Element identity is not stable across passes for parameters that
        // were re-resolved; remember the name too so a freshly-seeded
        // parameter picks up the taint.
        final owner = entry.key.enclosingElement?.displayName;
        if (entry.key is FormalParameterElement && owner != null) {
          _propagatedNames['$owner.${entry.key.displayName}'] = entry.value;
        } else if (entry.key is FormalParameterElement) {
          _propagatedNames[entry.key.displayName] = entry.value;
        } else if (entry.key is FieldElement) {
          _propagatedNames['field:${entry.key.displayName}'] = entry.value;
        }
      }
      _reported.clear();
      findings.clear();
      // The constant-fold cache memoises *results*, not findings; keeping it
      // would make the second pass skip re-evaluating a literal that pass 1
      // already folded, and with it the literal itself would never be
      // re-reported. Clear it so the whole unit is genuinely re-walked.
      _constantFoldCache.clear();
      _inProgress.clear();
      _returnValues.clear();
      // Fields promoted during pass 1 must survive the re-seed, which
      // recomputes every field value from its declaration.
      final promotedFields = Map<String, IntRange>.of(_fieldTaintByType);
      _collectDeclarations();
      for (final entry in promotedFields.entries) {
        _fieldTaintByType.putIfAbsent(entry.key, () => entry.value);
      }
      for (final entry in promotedFields.entries) {
        final element = _fieldElements[entry.key];
        if (element != null) _values[element] = entry.value;
      }
      unit.accept(_BodyVisitor(this));
    }
  }

  /// Whether [identifier] refers to a parameter bound to a decoded JSON map.
  ///
  /// Element identity is not reliable across the two analysis passes (the
  /// analyzer may hand back fresh element instances for a re-walked body), so
  /// name + type is used as the key.
  bool _isJsonMap(SimpleIdentifier identifier) {
    final element = identifier.element;
    if (element != null) {
      if (_jsonMaps.contains(element)) return true;
      for (final e in _jsonMaps) {
        if (e.displayName == element.displayName &&
            e is FormalParameterElement &&
            element is FormalParameterElement) {
          return true;
        }
      }
    }
    return _jsonMapNames.contains(identifier.name);
  }

  /// Names of JSON-map parameters in the current unit.
  final Set<String> _jsonMapNames = <String>{};

  /// Parameters/fields discovered by pass 1 to receive attacker-controlled
  /// values at some call site.
  final Map<Element, IntRange> _propagatedTaint = <Element, IntRange>{};

  /// Propagated taint keyed by parameter/field name, used when element
  /// identity does not survive a second analysis pass.
  final Map<String, IntRange> _propagatedNames = <String, IntRange>{};

  /// Parameters bound to a decoded JSON map (e.g. a `fromJson` factory's
  /// `Map<String, dynamic>`), whose elements are untrusted.
  final Set<Element> _jsonMaps = <Element>{};

  // =====================================================================
  // Declaration seeding
  // =====================================================================

  void _collectDeclarations() {
    for (final decl in unit.declarations) {
      switch (decl) {
        case FunctionDeclaration():
          _seedFunction(decl);
        case ClassDeclaration():
          for (final member in decl.body.members) {
            switch (member) {
              case MethodDeclaration():
                _seedMethod(member);
              case ConstructorDeclaration():
                _seedConstructor(member);
              case FieldDeclaration():
                for (final v in member.fields.variables) {
                  _seedVariable(v, isField: true);
                }
              default:
                break;
            }
          }
        case TopLevelVariableDeclaration():
          for (final v in decl.variables.variables) {
            _seedVariable(v, isField: true);
          }
        case ExtensionDeclaration():
          for (final member in decl.body.members) {
            if (member is MethodDeclaration) _seedMethod(member);
          }
        default:
          break;
      }
    }
  }

  void _seedVariable(VariableDeclaration v, {required bool isField}) {
    final element = v.declaredFragment?.element;
    if (element == null) return;
    if (!_isIntLike(element.type)) return;
    final annotated = _originForAnnotations(v.metadata);
    if (annotated == Origin.untrusted) {
      _values[element] = _untrustedFrom(
        'field `${v.name.lexeme}` is marked untrusted',
        v.offset,
      );
      return;
    }
    final constant = _constantOf(v.initializer);
    if (constant != null) {
      _values[element] = IntRange.of(constant.toInt());
      return;
    }
    final seeded = (isField
            ? (_propagatedNames['field:${v.name.lexeme}'] ?? _propagatedNames[v.name.lexeme])
            : _propagatedNames[v.name.lexeme]) ??
        IntRange.unbounded(isField ? Origin.parameter : Origin.local);
    _values[element] = seeded;
    if (isField && seeded.isUntrusted) {
      final owner = element.enclosingElement?.displayName;
      if (owner != null) _fieldTaintByType['$owner.${v.name.lexeme}'] = seeded;
    }
    if (isField) {
      // Remember every class field name so a later constructor call can
      // promote it to untrusted without a fresh element identity.
      final owner = element.enclosingElement?.displayName;
      if (owner != null) _fieldElements['$owner.${v.name.lexeme}'] = element;
    }
  }

  void _seedFunction(FunctionDeclaration node) {
    final isEntry = _isEntryPoint(node.name.lexeme);
    for (final p in node.functionExpression.parameters?.parameters ??
        const <FormalParameter>[]) {
      _seedParameter(p, ownerName: node.name.lexeme, isEntryPoint: isEntry);
    }
  }

  void _seedMethod(MethodDeclaration node) {
    final owner = node.thisOrAncestorOfType<ClassDeclaration>();
    final ownerName = owner?.namePart.typeName.lexeme ?? '';
    final isEntry = _isEntryPoint(node.name.lexeme) ||
        _isEntryPoint('$ownerName.${node.name.lexeme}');
    for (final p in node.parameters?.parameters ?? const <FormalParameter>[]) {
      _seedParameter(p, ownerName: ownerName, isEntryPoint: isEntry);
    }
  }

  void _seedConstructor(ConstructorDeclaration node) {
    final owner = node.thisOrAncestorOfType<ClassDeclaration>();
    final ownerName = owner?.namePart.typeName.lexeme ?? '';
    final ctorName = node.name?.lexeme ?? '';
    // `fromJson`-style constructors take a decoded JSON object: its dynamic
    // fields are exactly the hostile input from the incident.
    final jsonish = ctorName.toLowerCase().contains('json');
    for (final p in node.parameters.parameters) {
      _seedParameter(
        p,
        ownerName: ownerName,
        isEntryPoint: false,
        jsonish: jsonish,
      );
      final element = p.declaredFragment?.element;
      if (element is FieldFormalParameterElement) {
        final field = element.field;
        final value = _values[element];
        if (field != null && value != null) _values[field] = value;
      }
    }
  }

  void _seedParameter(
    FormalParameter p, {
    required String ownerName,
    required bool isEntryPoint,
    bool jsonish = false,
  }) {
    final element = p.declaredFragment?.element;
    if (element == null) return;
    final name = p.name?.lexeme ?? '';
    final type = element.type;

    // Map<String, dynamic> in a fromJson-style constructor: untrusted payload.
    if (jsonish && _isDynamicMap(type)) {
      _values[element] = _untrustedFrom(
        'JSON payload parameter `$name` of `$ownerName`',
        p.offset,
      );
      return;
    }
    if (!_isIntLike(type)) return;

    final annotated = _originForAnnotations(p.metadata);
    final qualified = '$ownerName.$name';
    // A parameter that pass 1 saw receiving attacker-controlled data stays
    // untrusted regardless of its declared/default origin.
    final propagated = _propagatedNames[qualified] ?? _propagatedNames[name];
    if (propagated != null) {
      _values[element] = propagated;
      return;
    }
    final Origin origin;
    if (annotated != null) {
      origin = annotated;
    } else if (options.trustedParameters.contains(qualified) ||
        options.trustedParameters.contains(name)) {
      origin = Origin.local;
    } else if (isEntryPoint || trustEntireLibrary) {
      origin = Origin.untrusted;
    } else {
      // An unannotated `int` parameter can receive any 64-bit value: the type
      // system does not bound it. Treat it as wide, but not attacker supplied.
      origin = Origin.parameter;
    }
    _values[element] = origin == Origin.untrusted
        ? _untrustedFrom(
            'parameter `$name` of `$ownerName` is attacker controlled',
            p.offset,
          )
        : IntRange.unbounded(origin);

  }

  bool _isEntryPoint(String name) {
    if (options.entryPoints.contains(name)) return true;
    final lower = name.toLowerCase();
    return lower.startsWith('handle') ||
        lower == 'main' ||
        lower.startsWith('validate') ||
        lower.startsWith('submit') ||
        lower.startsWith('process');
  }

  Origin? _originForAnnotations(List<Annotation> metadata) {
    for (final a in metadata) {
      String n;
      try {
        n = a.name.name.toLowerCase();
      } on Object {
        continue;
      }
      if (n.contains('untrusted') ||
          n.contains('userinput') ||
          n.contains('external') ||
          n.contains('attacker') ||
          n.contains('tainted')) {
        return Origin.untrusted;
      }
      if (n.contains('trusted') || n.contains('internal')) {
        return Origin.local;
      }
    }
    return null;
  }

  // =====================================================================
  // Evaluation
  // =====================================================================

  /// Compute the abstract value of an integer expression.
  IntRange eval(Expression e) => _eval(e);

  IntRange _eval(Expression e) {
    if (!_inProgress.add(e)) return IntRange.unknown;
    try {
      final folded = _foldConstant(e);
      if (folded != null) return folded.range;

      switch (e) {
        case IntegerLiteral():
          return IntRange.of(e.value ?? 0);
        case ParenthesizedExpression():
          return _eval(e.expression);
        case PrefixExpression():
          return _evalPrefix(e);
        case BinaryExpression():
          return _evalBinary(e);
        case SimpleIdentifier():
          return _evalIdentifier(e);
        case PrefixedIdentifier():
          return _evalPrefixed(e);
        case PropertyAccess():
          return _evalPropertyAccess(e);
        case IndexExpression():
          return _evalIndex(e);
        case MethodInvocation():
          return _evalMethodInvocation(e);
        case AsExpression():
          return _evalAs(e);
        case ConditionalExpression():
          final a = _eval(e.thenExpression);
          final b = _eval(e.elseExpression);
          return _join(a, b);
        case InstanceCreationExpression():
          return _evalInstanceCreation(e);
        case FunctionExpressionInvocation():
          return _evalFunctionInvocation(e);
        case PostfixExpression():
          return _eval(e.operand);
        case SwitchExpression():
          var result = IntRange.unknown;
          for (final c in e.cases) {
            result = _join(result, _eval(c.expression));
          }
          return result;
        default:
          return IntRange.unknown;
      }
    } finally {
      _inProgress.remove(e);
    }
  }

  IntRange _join(IntRange a, IntRange b) {
    if (a.isExact && b.isExact && a.exact == b.exact) return a;
    return IntRange(
      a.min < b.min ? a.min : b.min,
      a.max > b.max ? a.max : b.max,
      IntRange.mergeOrigin(a.origin, b.origin),
      trace: a.trace ?? b.trace,
    );
  }

  // ---- unary -----------------------------------------------------------

  IntRange _evalPrefix(PrefixExpression e) {
    final operand = _eval(e.operand);
    switch (e.operator.lexeme) {
      case '-':
        return IntRange(
          _clamp64(-operand.max),
          _clamp64(-operand.min),
          operand.origin,
          trace: operand.trace,
        );
      case '~':
        return _evalBitNot(e, operand);
      default:
        return operand;
    }
  }

  // ---- binary ----------------------------------------------------------

  IntRange _evalBinary(BinaryExpression e) {
    final op = e.operator.lexeme;
    switch (op) {
      case '==':
      case '!=':
        final left = _eval(e.leftOperand);
        final right = _eval(e.rightOperand);
        _maybeReportEquality(e, left, right);
        return IntRange.of(0, origin: Origin.local);
      case '<':
      case '>':
      case '<=':
      case '>=':
        return IntRange.of(0, origin: Origin.local);
      case '&&':
      case '||':
        return IntRange.of(0, origin: Origin.local);
      case '??':
        return _join(_eval(e.leftOperand), _eval(e.rightOperand));
    }

    final left = _eval(e.leftOperand);
    final right = _eval(e.rightOperand);
    switch (op) {
      case '+':
        return _evalArithmetic(e, left, right, _Arith.add);
      case '-':
        return _evalArithmetic(e, left, right, _Arith.subtract);
      case '*':
        return _evalArithmetic(e, left, right, _Arith.multiply);
      case '~/':
        return _evalDivision(e, left, right, truncating: true);
      case '%':
        return _evalDivision(e, left, right, truncating: false);
      case '&':
      case '|':
      case '^':
        return _evalBitwise(e, op, left, right);
      case '<<':
      case '>>':
      case '>>>':
        return _evalShift(e, op, left, right);
      default:
        return IntRange.unknown;
    }
  }

  // ---- arithmetic ------------------------------------------------------

  IntRange _evalArithmetic(
    BinaryExpression e,
    IntRange left,
    IntRange right,
    _Arith kind,
  ) {
    final range = switch (kind) {
      _Arith.add => Ranges.add(left, right),
      _Arith.subtract => Ranges.add(
          left,
          IntRange(_clamp64(-right.max), _clamp64(-right.min), right.origin,
              trace: right.trace),
        ),
      _Arith.multiply => Ranges.mul(left, right),
    };

    final untrusted = left.isUntrusted || right.isUntrusted;
    // Report when the computation can escape the exact range *and* at least
    // one operand is itself of unproven-but-wide provenance. A small constant
    // added to an unknown-magnitude value does not, by itself, mean the value
    // was ever large - so this stays quiet on bounded business arithmetic.
    if (_shouldReport(range) && (untrusted || _provablyWide(left) || _provablyWide(right))) {
      final source = left.isUntrusted ? left : (right.isUntrusted ? right : null);
      _report(
        e,
        code: untrusted
            ? FindingCode.untrustedMagnitude
            : FindingCode.arithmeticLosesPrecision,
        severity: untrusted ? Severity.error : Severity.warning,
        range: range,
        taint: source,
        detail: switch (kind) {
          _Arith.add || _Arith.subtract =>
            'Addition/subtraction is exact on JS only while the result stays '
                'below 2^53; on the VM it wraps at 64 bits.',
          _Arith.multiply =>
            'Multiplication is exact on JS only while the result stays below '
                '2^53; on the VM it wraps at 64 bits.',
        },
        fix: switch (kind) {
          _Arith.add || _Arith.subtract =>
            'Use `Int64` (package:fixnum) for 64-bit wrap-around semantics, or '
                '`BigInt` if values may exceed 64 bits.',
          _Arith.multiply =>
            'Use `Int64` (package:fixnum) so multiplication wraps at 64 bits '
                'instead of silently losing precision above 2^53.',
        },
      );
    }
    return range;
  }

  IntRange _evalDivision(
    BinaryExpression e,
    IntRange left,
    IntRange right, {
    required bool truncating,
  }) {
    final untrusted = left.isUntrusted || right.isUntrusted;
    // `%` additionally diverges when the divisor can be negative: dart2js
    // computes an Euclidean remainder which the VM agrees with, but only while
    // the operands are exact. The rule is therefore "operands must be exact".
    if (_shouldReport(left) || _shouldReport(right)) {
      final source = left.isUntrusted ? left : (right.isUntrusted ? right : null);
      _report(
        e,
        code: untrusted
            ? FindingCode.untrustedMagnitude
            : FindingCode.arithmeticLosesPrecision,
        severity: untrusted ? Severity.error : Severity.warning,
        range: left,
        taint: source,
        detail: truncating
            ? 'Truncating division needs exact operands; above 2^53 the JS '
                'quotient is no longer the VM quotient.'
            : 'The remainder needs an exact dividend; above 2^53 the JS '
                'remainder differs from the VM remainder.',
        fix:
            'Compute with `Int64` (package:fixnum) or `BigInt` so quotient and '
            'remainder are exact on the web.',
      );
    }

    // Result range.
    final maxAbs = left.isUnbounded
        ? 0x7FFFFFFFFFFFFFFF
        : (left.max.abs() > left.min.abs() ? left.max.abs() : left.min.abs());
    if (truncating) {
      return IntRange(
        -maxAbs,
        maxAbs,
        IntRange.mergeOrigin(left.origin, right.origin),
        trace: left.trace ?? right.trace,
      );
    }
    final bound = right.isUnbounded
        ? 0x7FFFFFFFFFFFFFFF
        : (right.max.abs() > right.min.abs() ? right.max.abs() : right.min.abs());
    return IntRange(
      0,
      bound <= 1 ? 1 : bound,
      IntRange.mergeOrigin(left.origin, right.origin),
      trace: left.trace ?? right.trace,
    );
  }

  // ---- bitwise ---------------------------------------------------------

  IntRange _evalBitNot(PrefixExpression e, IntRange operand) {
    final result = IntRange(0, 0xFFFFFFFF, operand.origin, trace: operand.trace);
    if (!_withinInt32(operand)) {
      _reportBitwise(e, operand, '~');
    }
    return result;
  }

  IntRange _evalBitwise(
    BinaryExpression e,
    String op,
    IntRange left,
    IntRange right,
  ) {
    final origin = IntRange.mergeOrigin(left.origin, right.origin);
    final trace = left.trace ?? right.trace;
    final result = IntRange(0, 0xFFFFFFFF, origin, trace: trace);
    if (!_withinInt32(left) || !_withinInt32(right)) {
      final offending = left.isUntrusted
          ? left
          : (right.isUntrusted ? right : (!_withinInt32(left) ? left : right));
      // A *constant* operand outside int32 is unconditionally truncated on JS:
      // `x & 0x100000000` is `x & 0` there, a mask of 0. Report it regardless
      // of how wide the other operand is.
      final constantOutOfRange = _constOutsideInt32(left) || _constOutsideInt32(right);
      if (constantOutOfRange || _shouldReport(offending)) {
        _reportBitwise(e, offending.isUntrusted ? offending : (constantOutOfRange ? _wideOperand(left, right) : offending), op);
      }
    }
    return result;
  }

  /// Whether [r] is a known constant inside the exactly-representable range
  /// (so comparing anything against it is exact on every target).
  bool _isSmallConstant(IntRange r) =>
      r.isExact && r.exact!.abs() <= 9007199254740991;

  /// Whether [r] is a known constant outside the 32-bit signed window.
  bool _constOutsideInt32(IntRange r) =>
      r.isExact && (r.exact! < -2147483648 || r.exact! > 2147483647);

  /// Pick the operand that carries the out-of-range constant, for the message.
  IntRange _wideOperand(IntRange left, IntRange right) =>
      _constOutsideInt32(left) ? left : right;

  /// Whether a range is *provably* outside the region where JS matches the VM:
  /// a known, non-unbounded range that escapes the exact-double window, or
  /// (in strict mode) any untrusted value.
  bool _provablyWide(IntRange r) {
    if (r.isUntrusted) return true;
    if (r.isUnbounded) return false; // unknown magnitude is not provable
    return !r.fitsInJsSafe;
  }

  /// Whether a range deserves a finding at the current strictness.
  ///
  /// * untrusted values always qualify;
  /// * provably-wide ranges qualify (they cannot be correct on JS);
  /// * unknown-magnitude parameters qualify only in strict mode, because
  ///   reporting every `int` parameter would make the tool unusable on real
  ///   business logic (money, ids, pagination) that is in fact fine.
  bool _shouldReport(IntRange r) {
    if (r.isUntrusted) return true;
    if (_provablyWide(r)) return true;
    if (r.isUnbounded && options.strict) return true;
    return false;
  }

  /// True only when every value the range can take fits in signed 32 bits, so
  /// the JS `ToInt32` coercion is the identity.
  bool _withinInt32(IntRange r) {
    if (r.isExact) return r.exact! >= -2147483648 && r.exact! <= 2147483647;
    if (r.isUnbounded) return false;
    return r.min >= -2147483648 && r.max <= 2147483647;
  }

  void _reportBitwise(Expression node, IntRange offending, String op) {
    final untrusted = offending.isUntrusted;
    if (!untrusted && !_shouldReport(offending) && !_constOutsideInt32(offending)) {
      return;
    }
    _report(
      node,
      code: untrusted
          ? FindingCode.untrustedMagnitude
          : FindingCode.bitwiseTruncatesOnWeb,
      severity: untrusted ? Severity.error : Severity.warning,
      range: offending,
      taint: untrusted ? offending : null,
      detail: '`$op` runs through ToInt32/ToUint32 on JavaScript, so it sees '
          'only the low 32 bits; the VM/Wasm version used all 64.',
      fix: 'Wrap the bitwise work in `Int64` (package:fixnum), whose `&`, `|`, '
          '`^`, `~` and shifts stay 64-bit on every target. A plain `int` '
          'cannot be made portable here.',
    );
  }

  // ---- shifts ----------------------------------------------------------

  IntRange _evalShift(
    BinaryExpression e,
    String op,
    IntRange value,
    IntRange amount,
  ) {
    final vmRange = _shiftVmRange(op, value, amount);
    final untrusted = value.isUntrusted || amount.isUntrusted;

    // Decide whether the JS and VM/Wasm results are provably different.
    final Bool3 differs = _shiftDiffersOnJs(op, value, amount);

    if (differs != Bool3.no) {
      // `maybe` (amount not known) only reports when tainted or in strict mode.
      // `maybe` becomes reportable when the value is wide rather than a known
      // small local: an unknown-magnitude operand can leave the 32-bit window.
      final reportable = differs == Bool3.yes ||
          untrusted ||
          (differs == Bool3.maybe && (!value.isSmall || options.strict));
      if (reportable) {
        final amountBeyond31 =
            amount.isExact && (amount.exact! < 0 || amount.exact! > 31);
        if (!untrusted &&
            !amountBeyond31 &&
            !_shouldReport(value) &&
            !amount.isUntrusted) {
          return vmRange;
        }
        _report(
          e,
          code: untrusted
              ? FindingCode.untrustedMagnitude
              : FindingCode.shiftTruncatesOnWeb,
          severity: untrusted ? Severity.error : Severity.warning,
          range: value,
          taint: untrusted ? (value.isUntrusted ? value : amount) : null,
          detail: switch (op) {
            '<<' => 'JavaScript shifts are 32-bit: a shift amount above 31 '
                'yields 0, and the result is truncated to the low 32 bits.',
            '>>' => 'JavaScript shifts are 32-bit and the result is coerced to '
                'unsigned, so a negative operand or a wide shift differs.',
            _ => 'JavaScript `>>>` is a 32-bit unsigned shift; the VM/Wasm '
                'version shifts all 64 bits.',
          },
          fix: 'Use `Int64` (package:fixnum) with `<<`, `>>`, `>>>` so shifts '
              'stay 64-bit on the web; on plain `int` the JS backend masks the '
              'amount to 32 bits and returns 0 for amounts above 31.',
        );
      }
    }
    return vmRange;
  }

  /// Whether the result of `value <op> amount` differs between JS and the
  /// VM/Wasm.
  ///
  /// Returns [Bool3.yes] only when a divergence is *provable* for the range
  /// (including every value in a wide range), [Bool3.maybe] when only some
  /// values diverge and the range does not tell us which, and [Bool3.no] when
  /// the result is identical for every value in the range.
  Bool3 _shiftDiffersOnJs(String op, IntRange value, IntRange amount) {
    // The shift amount must be a known non-negative constant. Without that the
    // VM saturates at 64 while JS wraps the amount modulo 32, so divergence is
    // possible but not provable.
    if (!amount.isExact) {
      // The amount is itself a variable: the VM saturates at 64 while JS wraps
      // modulo 32, so the results can differ.
      return value.isUntrusted || amount.isUntrusted
          ? Bool3.yes
          : Bool3.maybe;
    }
    final n = amount.exact!;
    if (n < 0) return Bool3.yes; // both throw on the VM; JS also throws
    // JS: amount > 31 behaves like 0 for << and >>> and sign-fills for >>.
    final amountBeyond31 = n > 31;

    // Exact operand: compute both results and compare.
    if (value.isExact) {
      final v = value.exact!;
      final vm = _shiftVmRange(op, value, amount).exact;
      if (vm == null) return Bool3.maybe;
      final js = _shiftExactOnJs(op, v, n);
      if (js == null) return Bool3.maybe;
      return js == vm ? Bool3.no : Bool3.yes;
    }

    // Wide-range operand: decide from the operand window.
    // JS always produces a uint32 for <<, >>> and >>. If the VM result can
    // leave [0, 2^32), they cannot agree for all inputs.
    if (amountBeyond31) return Bool3.yes;
    if (value.isUnbounded) {
      return Bool3.maybe;
    }
    final uint32 = value.min >= 0 && value.max <= 0xFFFFFFFF;
    final int32 = value.min >= -0x80000000 && value.max <= 0x7FFFFFFF;
    switch (op) {
      case '<<':
        if (value.min < 0) return Bool3.yes;
        if (value.max > 0x7FFFFFFF) return Bool3.yes;
        return Bool3.no;
      case '>>':
        // VM: arithmetic shift of a non-negative value; JS: same, but coerced
        // to unsigned. They agree iff the operand fits int32 (so the arithmetic
        // shift never reaches the sign bit) or is non-negative.
        if (value.min < 0) return Bool3.yes;
        return int32 ? Bool3.no : (uint32 ? Bool3.no : Bool3.yes);
      case '>>>':
        if (value.min < 0) return Bool3.yes;
        return uint32 ? Bool3.no : Bool3.yes;
      default:
        return Bool3.maybe;
    }
  }

  /// The exact JS result of a shift on a known value.
  int? _shiftExactOnJs(String op, int v, int n) {
    // Mirror dart2js: shifts are 32-bit and results are unsigned.
    if (n < 0) return null;
    final effective = n > 31 ? 32 : n;
    final low = v & 0xFFFFFFFF; // ToUint32
    final signedLow = toInt32(BigInt.from(v)).toInt();
    switch (op) {
      case '<<':
        if (effective > 31) return 0;
        final shifted = (signedLow << effective) & 0xFFFFFFFF;
        return shifted;
      case '>>':
        if (v >= 0) {
          if (effective > 31) return 0;
          return (low >> effective) & 0xFFFFFFFF;
        }
        final clamped = n > 31 ? 31 : n;
        final signFilled = (signedLow >> clamped) & 0xFFFFFFFF;
        return signFilled;
      case '>>>':
        if (effective > 31) return 0;
        return (low >> effective) & 0xFFFFFFFF;
      default:
        return null;
    }
  }

  IntRange _shiftVmRange(String op, IntRange value, IntRange amount) {
    if (!amount.isExact) {
      return IntRange.unbounded(value.origin);
    }
    final s = amount.exact!;
    if (s < 0) return IntRange.unknown;
    if (s >= 64) {
      return switch (op) {
        '<<' || '>>>' => IntRange.of(0, origin: value.origin),
        _ => value.min < 0
            ? IntRange.of(-1, origin: value.origin)
            : IntRange.of(0, origin: value.origin),
      };
    }
    if (value.isExact) {
      final v = value.exact!;
      final result = switch (op) {
        '<<' => toInt64(BigInt.from(v) << s),
        '>>' => BigInt.from(v) >> s,
        _ => toInt64(toUint64(BigInt.from(v)) >> s),
      };
      return IntRange.of(result.toInt(), origin: value.origin);
    }
    if (value.isUnbounded) {
      return switch (op) {
        '<<' => IntRange.unbounded(value.origin),
        '>>' => IntRange(
            value.min, value.max, value.origin, trace: value.trace),
        _ => IntRange(0, 0x7FFFFFFFFFFFFFFF, value.origin, trace: value.trace),
      };
    }
    return switch (op) {
      '<<' => IntRange(
          _clamp64(value.min << s),
          _clamp64(value.max << s),
          value.origin,
          trace: value.trace,
        ),
      '>>' => IntRange(value.min >> s, value.max >> s, value.origin,
          trace: value.trace),
      _ => IntRange(
          value.min < 0 ? 0 : value.min >> s,
          value.max < 0 ? 0 : value.max >> s,
          value.origin,
          trace: value.trace,
        ),
    };
  }

  // ---- identifiers and properties --------------------------------------

  IntRange _evalIdentifier(SimpleIdentifier e) {
    final element = e.element;
    if (element == null) return IntRange.unknown;
    return _valueForElement(element);
  }

  IntRange _valueForElement(Element element) {
    final known = _values[element];
    if (known != null) return known;
    if (element is PropertyAccessorElement) {
      final variable = element.variable;
      final viaVariable = _values[variable];
      if (viaVariable != null) return viaVariable;
    }
    final type = _elementType(element);
    if (type == null || !_isIntLike(type)) return IntRange.unknown;
    if (element is FormalParameterElement) {
      return IntRange.unbounded(Origin.parameter);
    }
    if (element is FieldElement || element is PropertyInducingElement) {
      return _fieldValue(element) ?? IntRange.unbounded(Origin.parameter);
    }
    return IntRange.unknown;
  }

  /// Look a field up by name when element identity does not match.
  IntRange? _fieldValue(Element element) {
    final owner = element.enclosingElement?.displayName;
    final name = element.displayName;
    if (owner != null) {
      final keyed = _values.entries.where((e) =>
          e.key.displayName == name &&
          e.key.enclosingElement?.displayName == owner &&
          e.key is FieldElement);
      if (keyed.isNotEmpty) return keyed.first.value;
    }
    final byName = _values.entries.where(
        (e) => e.key is FieldElement && e.key.displayName == name);
    if (byName.length == 1) return byName.first.value;
    return null;
  }

  IntRange _evalPrefixed(PrefixedIdentifier e) {
    final element = e.identifier.element;
    final direct = element == null ? null : _values[element];
    if (direct != null) return direct;
    // `request.orderId`: the getter element may not be the element the field
    // was seeded under. Match on the receiver's static type + field name.
    final byType = _lookupFieldTaintByType(e.prefix.staticType, e.identifier.name);
    if (byType != null) return byType;
    if (element == null) return IntRange.unknown;
    return _valueForElement(element);
  }

  /// Field taint recorded for a class, keyed by `Type.field`.
  final Map<String, IntRange> _fieldTaintByType = <String, IntRange>{};

  /// All class fields, keyed by `Type.field`.
  final Map<String, Element> _fieldElements = <String, Element>{};

  /// Promote a field to untrusted when a constructor receives an untrusted
  /// value for it. Works even when element identity differs between passes.
  void _markFieldUntrusted(String owner, String name, IntRange value) {
    final key = '$owner.$name';

    _fieldTaintByType[key] = value;
    final element = _fieldElements[key];
    if (element != null) _values[element] = value;
  }

  IntRange? _lookupFieldTaintByType(DartType? receiverType, String fieldName) {
    if (receiverType is! InterfaceType) return null;
    final typeName = receiverType.element.name;
    return _fieldTaintByType['$typeName.$fieldName'];
  }

  IntRange _evalPropertyAccess(PropertyAccess e) {
    final name = e.propertyName.name;
    switch (name) {
      case 'hashCode':
        return _evalHashCode(e, e.realTarget);
      case 'length':
        return IntRange(0, 0x7FFFFFFF, Origin.engine);
      case 'bitLength':
        return _evalBitLength(e, e.realTarget);
      case 'sign':
        return IntRange(-1, 1, Origin.local);
      case 'isEven':
      case 'isOdd':
        return IntRange.of(0, origin: Origin.local);
    }
    final byType = _lookupFieldTaintByType(e.realTarget.staticType, name);
    if (byType != null) return byType;
    final element = e.propertyName.element;
    if (element != null) return _valueForElement(element);
    return IntRange.unknown;
  }

  IntRange _evalHashCode(Expression node, Expression? receiver) {
    if (receiver == null) return IntRange(0, 0x1FFFFFFF, Origin.engine);
    final receiverRange = _eval(receiver);
    final receiverType = receiver.staticType;
    final integerReceiver = receiverRange.isUntrusted ||
        (receiverType != null &&
            (receiverType.isDartCoreInt || receiverType.isDartCoreNum)) ||
        receiverType == null ||
        receiverType is DynamicType;
    if (integerReceiver) {
      _report(
        node,
        code: FindingCode.hashCodeNotPortable,
        severity: receiverRange.isUntrusted ? Severity.error : Severity.warning,
        range: receiverRange,
        taint: receiverRange.isUntrusted ? receiverRange : null,
        detail: '`int.hashCode` is not stable across targets: the VM and Wasm '
            'return the value itself mixed by the VM hash, while dart2js folds '
            'the double bit pattern. Strings also hash differently.',
        fix: 'Do not use `hashCode` for a value that must match on another '
            'runtime. Use an explicit checksum over the canonical decimal/hex '
            'string with `Int64` or `BigInt`, or hash serialized bytes with '
            'package:crypto.',
      );
    }
    return IntRange(0, 0x1FFFFFFF, Origin.engine);
  }

  IntRange _evalBitLength(Expression node, Expression? receiver) {
    if (receiver != null && _eval(receiver).isUntrusted) {
      _report(
        node,
        code: FindingCode.hashCodeNotPortable,
        severity: Severity.warning,
        range: _eval(receiver),
        taint: _eval(receiver),
        detail: '`bitLength` depends on the platform int width; on dart2js it '
            'is computed from a 32-bit window for large values.',
        fix: 'Fix the checksum width explicitly with `Int64`/`BigInt` instead '
            'of deriving it from `bitLength`.',
      );
    }
    return IntRange(0, 63, Origin.engine);
  }

  IntRange _evalIndex(IndexExpression e) {
    final targetType = e.realTarget.staticType;
    final indexRange = _eval(e.index);

    // Reading an element out of a map that carries untrusted JSON yields an
    // untrusted value.
    final receiver = e.realTarget;
    if (receiver is SimpleIdentifier && _isJsonMap(receiver)) {
      return _untrustedFrom(
        '`${_snippet(e)}` reads a field out of untrusted JSON',
        e.offset,
      );
    }
    if (targetType is InterfaceType && targetType.isDartCoreMap) {
      final keyType = targetType.typeArguments.isEmpty
          ? null
          : targetType.typeArguments.first;
      if (keyType != null && keyType.isDartCoreInt) {
        // An `int` key of unknown magnitude (typically an id parameter) is a
        // collision risk too: nothing in the type system bounds it to 2^53.
        // This is reported even at standard strictness because keys are
        // identity, unlike ordinary arithmetic.
        final wide = indexRange.isUntrusted ||
            !indexRange.fitsInJsSafe ||
            indexRange.isUnbounded;
        if (wide) {
          _report(
            e,
            code: FindingCode.integerKeyCollision,
            severity: indexRange.isUntrusted ? Severity.error : Severity.warning,
            range: indexRange,
            taint: indexRange.isUntrusted ? indexRange : null,
            detail: 'An `int` map key is a double on the web, so two distinct '
                'ids above 2^53 alias to one entry; the second write silently '
                'overwrites the first.',
            fix: 'Key the map by the canonical decimal string, or by `Int64` '
                '(package:fixnum) whose `==`/`hashCode` compare all 64 bits, so '
                'two distinct ids cannot alias on the web.',
          );
        }
      }
      // Reading a `dynamic`/`Object?`-valued map inherits the map's taint.
      final valueType = targetType.typeArguments.length > 1
          ? targetType.typeArguments[1]
          : null;
      if (valueType != null &&
          (valueType is DynamicType || valueType.isDartCoreObject)) {
        final mapRange = _eval(e.realTarget);
        if (mapRange.isUntrusted) return mapRange;
      }
    }
    return IntRange.unknown;
  }

  IntRange _evalAs(AsExpression e) {
    final target = e.type.type;
    final operand = _eval(e.expression);
    if (target != null && target.isDartCoreInt) {
      // Taint in, taint out: a cast never launders an untrusted value.
      if (operand.isUntrusted) return operand;
      final source = e.expression.staticType;
      // `x as int` where x is dynamic/Object? is the canonical way hostile
      // JSON numbers enter typed code.
      if (source == null || source is DynamicType || source.isDartCoreObject) {
        return _untrustedFrom(
          '`${_snippet(e)}` casts an unvalidated dynamic value to int',
          e.offset,
        );
      }
    }
    return IntRange(
      operand.min,
      operand.max,
      operand.origin,
      trace: operand.trace,
    );
  }

  IntRange _evalMethodInvocation(MethodInvocation e) {
    final name = e.methodName.name;
    final target = e.target;

    if ((name == 'parse' || name == 'tryParse') && _receivesInt(e)) {
      return _untrustedFrom(
        '`$name(...)` converts an external string into a 64-bit int',
        e.offset,
      );
    }
    if (name == 'fromEnvironment') {
      return _untrustedFrom(
        '`int.fromEnvironment` reads an externally supplied value',
        e.offset,
      );
    }
    if (name == 'jsonDecode' || name == 'jsonDecodeUtf8') {
      return _untrustedFrom(
        '`$name(...)` decodes untrusted JSON',
        e.offset,
      );
    }
    if (name == 'hash' || name == 'hashAll') {
      _report(
        e,
        code: FindingCode.hashCodeNotPortable,
        severity: Severity.warning,
        range: IntRange.unknown,
        detail: '`Object.$name` combines per-runtime hash values, so it differs '
            'between the VM, Wasm and JS even for identical inputs.',
        fix: 'Do not use `Object.$name` for a value that must match on another '
            'runtime; use `Int64`-based arithmetic over the canonical fields, '
            'or package:crypto over serialized bytes.',
      );
      return IntRange(0, 0x1FFFFFFF, Origin.engine);
    }
    if (options.trustedFunctions.contains(name)) {
      return IntRange.unbounded(Origin.engine);
    }
    if (name == 'toInt' ||
        name == 'truncate' ||
        name == 'round' ||
        name == 'floor' ||
        name == 'ceil') {
      return _evalDoubleToInt(e);
    }
    if (name == 'toUnsigned' || name == 'toSigned') {
      return _evalToUnsigned(e);
    }
    if (name == 'toDouble') {
      return target == null ? IntRange.unknown : _eval(target);
    }

    // Interprocedural: if this call passes attacker-controlled values, the
    // callee's parameters become untrusted for the second pass.
    _propagateCallArguments(e.methodName.element, e.argumentList.arguments);

    // A user-defined function whose body we have seen: propagate its return
    // value, including taint.
    final invoked = e.methodName.element;
    if (invoked is ExecutableElement) {
      final recorded = _returnValues[invoked.baseElement];
      if (recorded != null) return recorded;
      // Otherwise: if any argument is untrusted and the return type is int,
      // assume the taint survives.
      if (e.staticType?.isDartCoreInt ?? false) {
        for (final a in e.argumentList.arguments) {
          if (a is Expression) {
            final v = _eval(a);
            if (v.isUntrusted) return v;
          }
        }
      }
    }
    if (e.staticType?.isDartCoreInt ?? false) {
      return IntRange.unbounded(Origin.local);
    }
    return IntRange.unknown;
  }

  bool _receivesInt(MethodInvocation e) {
    final t = e.target;
    if (t is SimpleIdentifier && t.name == 'int') return true;
    if (t == null) {
      // Unqualified parse inside an int-extending context; check the return
      // type to avoid matching unrelated `parse` methods.
      return e.staticType?.isDartCoreInt ?? false;
    }
    return false;
  }

  IntRange _evalDoubleToInt(MethodInvocation e) {
    final target = e.target;
    final receiverRange = target == null ? IntRange.unknown : _eval(target);
    final receiverType = target?.staticType;
    final isDouble = receiverType != null &&
        (receiverType.isDartCoreDouble || receiverType.isDartCoreNum);
    if (isDouble) {
      _report(
        e,
        code: FindingCode.doubleToIntDiverges,
        severity: receiverRange.isUntrusted ? Severity.error : Severity.warning,
        range: receiverRange,
        taint: receiverRange.isUntrusted ? receiverRange : null,
        detail: 'Converting a double to int differs above 2^53: the VM '
            'saturates at ±2^63, while dart2js returns a non-integral double '
            'that is no longer exact.',
        fix: 'Check the magnitude before converting, or keep the value as '
            '`BigInt`/`Int64`. `dart2js` will hand back a double that is not '
            'an integer at all.',
      );
      return IntRange.unbounded(
        receiverRange.isUntrusted ? Origin.untrusted : Origin.engine,
      ).withTrace(receiverRange.trace);
    }
    return IntRange.unbounded(Origin.local);
  }

  IntRange _evalToUnsigned(MethodInvocation e) {
    final target = e.target;
    final receiver = target == null ? IntRange.unknown : _eval(target);
    final args = e.argumentList.arguments;
    final width = args.isNotEmpty && args.first is IntegerLiteral
        ? (args.first as IntegerLiteral).value
        : null;
    // dart2js implements toUnsigned as `this & ((1 << width) - 1)`, and its
    // bitwise operators are 32-bit, so any width above 32 is silently capped.
    if (width != null && width > 32) {
      _report(
        e,
        code: receiver.isUntrusted
            ? FindingCode.untrustedMagnitude
            : FindingCode.arithmeticLosesPrecision,
        severity: receiver.isUntrusted ? Severity.error : Severity.warning,
        range: receiver,
        taint: receiver.isUntrusted ? receiver : null,
        detail: '`toUnsigned($width)` is implemented with a 32-bit mask on '
            'dart2js, so widths above 32 are silently capped; the VM returns a '
            'full 64-bit result.',
        fix: 'Use `Int64.toUnsigned`/`Int64.toSigned` from package:fixnum, or '
            'mask explicitly with `BigInt` so the width is honoured everywhere.',
      );
    }
    return IntRange.unbounded(receiver.origin);
  }

  IntRange _evalInstanceCreation(InstanceCreationExpression e) {
    final ctor = e.constructorName.element;
    // ignore: avoid_print
    _propagateCallArguments(ctor, e.argumentList.arguments);
    final typeName = _instanceTypeName(e);
    // Int64 / BigInt values are portable; treat them as trusted so downstream
    // operations do not report.
    if (typeName == 'Int64' || typeName == 'BigInt') {
      return IntRange.unbounded(Origin.local);
    }
    if (typeName == 'Int64List' || typeName == 'Uint64List' ||
        typeName == 'Int32x4' || typeName == 'Float64x2') {
      _report(
        e,
        code: FindingCode.untrustedMagnitude,
        severity: Severity.error,
        range: IntRange.unknown,
        detail: '`$typeName` throws `UnsupportedError` on dart2js; it works on '
            'the VM and on Wasm, so the same code fails only on the web build.',
        fix: 'Store two 32-bit words, a `ByteData` written as two `setInt32` '
            'halves, or the decimal string, and convert with '
            '`Int64.parseInt`.',
      );
    }
    return IntRange.unknown;
  }

  /// Record any argument that carries attacker-controlled data onto the
  /// corresponding parameter of the callee.
  void _propagateCallArguments(
    Element? callee,
    List<Argument> arguments,
  ) {
    if (callee is! ExecutableElement) return;
    final parameters = callee.formalParameters;
    // Positional arguments map in order; named arguments map by name. Mixing
    // the two up is how `OrderSummary(itemCount: ...)` could otherwise taint
    // the wrong field.
    var positionalIndex = 0;
    for (final argument in arguments) {
      if (argument is NamedArgument) {
        final name = argument.name.lexeme;
        FormalParameterElement? match;
        for (final parameter in parameters) {
          if (parameter.isNamed && parameter.displayName == name) {
            match = parameter;
            break;
          }
        }
        if (match != null) _taintParameter(match, argument.argumentExpression);
        continue;
      }
      // Skip named parameters when walking positionally.
      while (positionalIndex < parameters.length &&
          parameters[positionalIndex].isNamed) {
        positionalIndex++;
      }
      if (positionalIndex >= parameters.length) break;
      if (argument is Expression) {
        _taintParameter(parameters[positionalIndex], argument);
      }
      positionalIndex++;
    }
  }

  void _taintParameter(FormalParameterElement parameter, Expression argument) {
    final value = _eval(argument);
    if (!value.isUntrusted) return;
    final target = parameter.baseElement;
    // Prefer the source with an actual trace (the real entry point).
    final existing = _propagatedTaint[target];
    if (existing != null &&
        (existing.trace?.isNotEmpty ?? false) &&
        (value.trace?.isEmpty ?? true)) {
      return;
    }
    _propagatedTaint[target] = value;
    // A field formal parameter (`this.id`) passes the value straight through.
    if (parameter is FieldFormalParameterElement) {
      final field = parameter.field;
      if (field != null) {
        _propagatedTaint[field] = value;
        final owner = field.enclosingElement.displayName;
        _markFieldUntrusted(owner, field.displayName, value);
      }
    }
  }

  String? _instanceTypeName(InstanceCreationExpression e) {
    final type = e.constructorName.type;
    final element = type.element;
    if (element is InterfaceElement) return element.name;
    return type.name.lexeme;
  }

  IntRange _evalFunctionInvocation(FunctionExpressionInvocation e) {
    final fn = e.function;
    if (fn is SimpleIdentifier) {
      final element = fn.element;
      if (element is ExecutableElement) {
        final recorded = _returnValues[element.baseElement];
        if (recorded != null) return recorded;
        if (e.staticType?.isDartCoreInt ?? false) {
          for (final a in e.argumentList.arguments) {
            if (a is Expression) {
              final v = _eval(a);
              if (v.isUntrusted) return v;
            }
          }
        }
      }
    }
    return IntRange.unknown;
  }

  // =====================================================================
  // Constant folding and VM/JS comparison
  // =====================================================================

  _ConstantFold? _foldConstant(Expression e) {
    final cached = _constantFoldCache[e];
    if (cached != null) return cached;

    // Literals first: a literal outside the exact double range is a hard
    // compile error on dart2js and must be reported even when nested.
    final literal = _literalValue(e);
    if (literal != null) {
      final fold = _ConstantFold(literal);
      _constantFoldCache[e] = fold;
      if (!isExactlyRepresentableAsDouble(literal)) {
        _reportLiteralNotRepresentable(e, literal);
      }
      return fold;
    }

    if (e is BinaryExpression ||
        e is PrefixExpression ||
        e is ParenthesizedExpression) {
      final pure = _foldPureInteger(e);
      if (pure != null) return pure;
    }

    DartObject? value;
    try {
      value = e.computeConstantValue()?.value;
    } on StateError {
      return null;
    }
    if (value == null) return null;
    final intValue = value.toIntValue();
    if (intValue == null) return null;

    final fold = _ConstantFold(BigInt.from(intValue));
    _constantFoldCache[e] = fold;
    final js = _evalConstantOnJs(e);
    if (js != null && !js.agrees(fold.vmValue)) {
      _reportConstantDivergence(e, fold.vmValue, js);
    }
    return fold;
  }

  BigInt? _constantOf(Expression? e) {
    if (e == null) return null;
    return _literalValue(e) ?? _evalVm(e);
  }

  _ConstantFold? _foldPureInteger(Expression e) {
    final vm = _evalVm(e);
    if (vm == null) return null;
    final fold = _ConstantFold(vm);
    _constantFoldCache[e] = fold;
    final js = _evalConstantOnJs(e);
    if (js != null && !js.agrees(vm)) {
      _reportConstantDivergence(e, vm, js);
    }
    return fold;
  }

  BigInt? _literalValue(Expression e) {
    if (e is IntegerLiteral) {
      final v = e.value;
      return v == null ? null : BigInt.from(v);
    }
    if (e is PrefixExpression && e.operator.lexeme == '-') {
      final inner = e.operand;
      if (inner is IntegerLiteral) {
        final v = inner.value;
        return v == null ? null : -BigInt.from(v);
      }
    }
    return null;
  }

  _JsConstant? _evalConstantOnJs(Expression e) {
    try {
      final result = _evalJs(e);
      return result == null ? null : _JsConstant(result);
    } on UndefinedIntegerOperation {
      return null;
    }
  }

  double? _evalJs(Expression e) {
    switch (e) {
      case IntegerLiteral():
        return e.value?.toDouble();
      case ParenthesizedExpression():
        return _evalJs(e.expression);
      case PrefixExpression():
        if (e.operator.lexeme == '-') {
          final inner = _evalJs(e.operand);
          return inner == null ? null : -inner;
        }
        return null;
      case BinaryExpression():
        final a = _evalJs(e.leftOperand);
        final b = _evalJs(e.rightOperand);
        if (a == null || b == null) return null;
        const ev = TargetEvaluator(Target.js);
        final result = switch (e.operator.lexeme) {
          '+' => ev.add(a, b),
          '-' => ev.subtract(a, b),
          '*' => ev.multiply(a, b),
          '~/' => ev.truncatingDivide(a, b),
          '%' => ev.modulo(a, b),
          '&' => ev.bitAnd(a, b),
          '|' => ev.bitOr(a, b),
          '^' => ev.bitXor(a, b),
          '<<' => ev.shiftLeft(a, b),
          '>>' => ev.shiftRight(a, b),
          '>>>' => ev.unsignedShiftRight(a, b),
          _ => null,
        };
        if (result == null) return null;
        return result is double ? result : (result as BigInt).toDouble();
      default:
        return null;
    }
  }

  BigInt? _evalVm(Expression e) {
    switch (e) {
      case IntegerLiteral():
        final v = e.value;
        return v == null ? null : BigInt.from(v);
      case ParenthesizedExpression():
        return _evalVm(e.expression);
      case PrefixExpression():
        if (e.operator.lexeme == '-') {
          final inner = _evalVm(e.operand);
          return inner == null ? null : -inner;
        }
        if (e.operator.lexeme == '~') {
          final inner = _evalVm(e.operand);
          return inner == null ? null : ~inner;
        }
        return null;
      case BinaryExpression():
        switch (e.operator.lexeme) {
          case '+':
          case '-':
          case '*':
          case '~/':
          case '%':
          case '&':
          case '|':
          case '^':
          case '<<':
          case '>>':
          case '>>>':
            break;
          default:
            return null;
        }
        final a = _evalVm(e.leftOperand);
        final b = _evalVm(e.rightOperand);
        if (a == null || b == null) return null;
        const ev = TargetEvaluator(Target.vm);
        try {
          final result = switch (e.operator.lexeme) {
            '+' => ev.add(a, b),
            '-' => ev.subtract(a, b),
            '*' => ev.multiply(a, b),
            '~/' => ev.truncatingDivide(a, b),
            '%' => ev.modulo(a, b),
            '&' => ev.bitAnd(a, b),
            '|' => ev.bitOr(a, b),
            '^' => ev.bitXor(a, b),
            '<<' => ev.shiftLeft(a, b),
            '>>' => ev.shiftRight(a, b),
            _ => ev.unsignedShiftRight(a, b),
          };
          return result is BigInt ? result : null;
        } on UndefinedIntegerOperation {
          return null;
        }
      default:
        return null;
    }
  }

  // =====================================================================
  // Reporting
  // =====================================================================

  void _reportLiteralNotRepresentable(Expression e, BigInt value) {
    final code = FindingCode.literalNotRepresentable;
    if (!_markReported(e, code)) return;
    findings.add(Finding(
      code: code,
      severity: Severity.error,
      offset: e.offset,
      length: e.length,
      message: 'Integer literal `${_snippet(e)}` cannot be represented exactly '
          'as a JavaScript number. `dart compile js` rejects the whole build '
          'with "can\'t be represented exactly in JavaScript", so the web '
          'release fails while the mobile build succeeds.',
      fix: 'Build the value portably: `Int64.parseInt(\'$value\')` from '
          'package:fixnum, or `BigInt.parse(\'$value\')`. If it is a mask or '
          'hash seed, express it as an `Int64` constant computed from two 32-bit '
          'halves.',
      sample: <Target, String>{
        Target.vm: value.toString(),
        Target.wasm: value.toString(),
        Target.js: 'compile error',
      },
      snippet: _snippet(e),
    ));
  }

  void _reportConstantDivergence(Expression e, BigInt vmValue, _JsConstant js) {
    final code = FindingCode.constantFoldsDifferently;
    if (!_markReported(e, code)) return;
    findings.add(Finding(
      code: code,
      severity: Severity.error,
      offset: e.offset,
      length: e.length,
      message: '`${_snippet(e)}` folds to $vmValue on the VM and Wasm but to '
          '${js.render()} on the JS target. Any constant derived from this — a '
          'default checksum, a mask, a seed — is wrong on the web before the '
          'program even runs.',
      fix: 'Express the constant with `Int64` (package:fixnum) or `BigInt` so '
          'every target agrees, or restructure it to stay within the 32/53-bit '
          'windows.',
      sample: <Target, String>{
        Target.vm: vmValue.toString(),
        Target.wasm: vmValue.toString(),
        Target.js: js.render(),
      },
      snippet: _snippet(e),
    ));
  }

  void _maybeReportEquality(BinaryExpression e, IntRange left, IntRange right) {
    // Comparisons against a small constant are exact on every target: on JS a
    // double of |v| <= 2^53 compares exactly, and every small constant is.
    if (_isSmallConstant(left) || _isSmallConstant(right)) return;
    // Constant comparisons are exact and uninteresting.
    if (left.isExact && right.isExact) return;
    final untrusted = left.isUntrusted || right.isUntrusted;
    // Only report an equality when at least one side can actually hold a value
    // above 2^53 - otherwise the comparison is identical on every target.
    final wide = _provablyWide(left) || _provablyWide(right);
    final unknownWide = options.strict &&
        ((left.isUnbounded && !left.isSmall) ||
            (right.isUnbounded && !right.isSmall));
    if (!untrusted && !wide && !unknownWide) return;
    _report(
      e,
      code: untrusted
          ? FindingCode.integerKeyCollision
          : FindingCode.arithmeticLosesPrecision,
      severity: untrusted ? Severity.error : Severity.warning,
      range: left.isUntrusted ? left : right,
      taint: untrusted ? (left.isUntrusted ? left : right) : null,
      detail: '`${e.operator.lexeme}` compares doubles on the web, so two '
          'distinct 64-bit ids above 2^53 can test as equal. This is exactly how '
          'duplicate-order detection is bypassed.',
      fix: 'Compare canonical decimal/hex strings, or compare `Int64` values '
          'from package:fixnum so all 64 bits participate.',
    );
  }

  /// Whether [node] is the outermost node of its operator chain: its parent is
  /// not an arithmetic/bitwise/shift expression in which [node] only supplies
  /// an operand. Reporting only the outermost node keeps one finding per
  /// expression instead of one per sub-operator.
  bool _isChainRoot(AstNode node) {
    final parent = node.parent;
    if (parent is ParenthesizedExpression) return _isChainRoot(parent);
    if (parent is BinaryExpression && parent.leftOperand == node) {
      return !_isArithmeticOp(parent.operator.lexeme);
    }
    if (parent is BinaryExpression && parent.rightOperand == node) {
      // `a + (b << 2)` reports the shift too: the shift is a *distinct*
      // operation with its own rule.
      return parent.operator.lexeme == '+' || parent.operator.lexeme == '-';
    }
    if (parent is PrefixExpression) return false;
    return true;
  }

  bool _isArithmeticOp(String op) =>
      op == '+' || op == '-' || op == '*' || op == '~/' || op == '%' ||
      op == '&' || op == '|' || op == '^' || op == '<<' || op == '>>' ||
      op == '>>>';

  bool _markReported(AstNode node, FindingCode code) =>
      _reported.add('${node.offset}:${node.length}:${code.id}');

  void _report(
    Expression node, {
    required FindingCode code,
    required Severity severity,
    required IntRange range,
    required String detail,
    required String fix,
    IntRange? taint,
    Map<Target, String>? sample,
  }) {
    if (!_isChainRoot(node)) return;
    if (!_markReported(node, code)) return;
    if (options.minimal && severity != Severity.error) return;

    final message = StringBuffer();
    final trace = taint?.trace;
    if (taint != null && taint.isUntrusted) {
      final from = (trace == null || trace.isEmpty)
          ? 'attacker-controlled input'
          : trace.first.description;
      message.write('Attacker-controlled value (from $from) reaches '
          '`${_snippet(node)}`. ');
    } else {
      message.write('`${_snippet(node)}` ');
    }
    message.write(detail);
    if (sample == null && range.isExact) {
      message.write(' Known value: ${range.exact}.');
    }

    findings.add(Finding(
      code: code,
      severity: severity,
      offset: node.offset,
      length: node.length,
      message: message.toString(),
      fix: fix,
      targets: const <Target>[Target.js],
      sample: sample,
      trace: trace == null
          ? const <String>[]
          : <String>[for (final t in trace) 'offset ${t.offset}: ${t.description}'],
      snippet: _snippet(node),
    ));
  }

  IntRange _untrustedFrom(String description, int offset) {
    return const IntRange.untrusted().withTrace(<TaintSource>[
      TaintSource(origin: Origin.untrusted, description: description, offset: offset),
    ]);
  }

  // =====================================================================
  // Helpers
  // =====================================================================

  int _clamp64(int v) {
    if (v > 0x7FFFFFFFFFFFFFFF) return 0x7FFFFFFFFFFFFFFF;
    if (v < -0x7FFFFFFFFFFFFFFF) return -0x7FFFFFFFFFFFFFFF;
    return v;
  }

  String _snippet(AstNode node) {
    final start = node.offset;
    final end = node.end;
    if (start < 0 || end > content.length || end <= start) {
      return node.toSource().replaceAll(RegExp(r'\s+'), ' ').trim();
    }
    final text = content
        .substring(start, end)
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    return text.length > 70 ? '${text.substring(0, 67)}...' : text;
  }

  bool _isDynamicMap(DartType? type) {
    if (type is! InterfaceType || !type.isDartCoreMap) return false;
    if (type.typeArguments.length != 2) return false;
    final key = type.typeArguments[0];
    final value = type.typeArguments[1];
    return key.isDartCoreString &&
        (value is DynamicType || value.isDartCoreObject);
  }

  DartType? _elementType(Element element) {
    if (element is VariableElement) return element.type;
    if (element is PropertyAccessorElement) return element.returnType;
    return null;
  }

  bool _isIntLike(DartType? type) {
    if (type == null) return false;
    return type.isDartCoreInt || type.isDartCoreNum;
  }
}

enum _Arith { add, subtract, multiply }

/// Three-valued logic for "does this differ between targets?".
enum Bool3 { no, maybe, yes }

/// A folded constant.
class _ConstantFold {
  _ConstantFold(this.vmValue);
  final BigInt vmValue;

  IntRange get range => IntRange(
        _clamp(vmValue.toInt()),
        _clamp(vmValue.toInt()),
        Origin.constant,
        exact: _clamp(vmValue.toInt()),
      );

  static int _clamp(int v) {
    if (v > 0x7FFFFFFFFFFFFFFF) return 0x7FFFFFFFFFFFFFFF;
    if (v < -0x7FFFFFFFFFFFFFFF) return -0x7FFFFFFFFFFFFFFF;
    return v;
  }
}

/// A constant evaluated under the JavaScript model.
class _JsConstant {
  _JsConstant(this.value);
  final double value;

  bool agrees(BigInt vm) => jsAgreesWithVm(value, vm);

  String render() {
    if (!value.isFinite) return value.toString();
    if (value == value.truncateToDouble() && value.abs() <= 9007199254740992.0) {
      return BigInt.from(value).toString();
    }
    return value.toString();
  }
}

/// Walks executable bodies, maintaining the flow-sensitive value map.
class _BodyVisitor extends RecursiveAstVisitor<void> {
  _BodyVisitor(this.a);

  final UnitAnalyzer a;

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final init = node.initializer;
    final element = node.declaredFragment?.element;
    if (init != null && element != null && a._isIntLike(element.type)) {
      a._values[element] = a.eval(init);
    }
    super.visitVariableDeclaration(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final op = node.operator.lexeme;
    final rhs = node.rightHandSide;
    IntRange value;
    if (op == '=') {
      value = a.eval(rhs);
    } else {
      final lhs = a.eval(node.leftHandSide);
      final right = a.eval(rhs);
      value = _compound(lhs, right, op.substring(0, op.length - 1));
    }
    final element = _targetElement(node.leftHandSide);
    if (element != null && a._isIntLike(a._elementType(element))) {
      a._values[element] = value;
    }
    super.visitAssignmentExpression(node);
  }

  IntRange _compound(IntRange left, IntRange right, String op) {
    switch (op) {
      case '+':
        return Ranges.add(left, right);
      case '-':
        return Ranges.add(
          left,
          IntRange(
            left.origin == Origin.constant ? -right.max : -right.max,
            -right.min,
            right.origin,
            trace: right.trace,
          ),
        );
      case '*':
        return Ranges.mul(left, right);
      case '&':
      case '|':
      case '^':
        return IntRange(
          0,
          0xFFFFFFFF,
          IntRange.mergeOrigin(left.origin, right.origin),
          trace: left.trace ?? right.trace,
        );
      default:
        return IntRange.unbounded(IntRange.mergeOrigin(left.origin, right.origin));
    }
  }

  Element? _targetElement(Expression target) {
    return switch (target) {
      SimpleIdentifier() => target.element,
      PrefixedIdentifier() => target.identifier.element,
      PropertyAccess() => target.propertyName.element,
      _ => null,
    };
  }

  @override
  void visitConstructorDeclaration(ConstructorDeclaration node) {
    // Factory constructors hold real code (`OrderRequest.fromJson` builds an
    // object from a JSON map). Their parameters are an entry point into typed
    // code just like a function's.
    if (node.factoryKeyword != null) {
      final owner = node.thisOrAncestorOfType<ClassDeclaration>();
      final ownerName = owner?.namePart.typeName.lexeme ?? '';
      final isJsonish = (node.name?.lexeme ?? '').toLowerCase().contains('json');
      for (final p in node.parameters.parameters) {
        final element = p.declaredFragment?.element;
        if (element == null) continue;
        // A JSON map parameter is the untrusted payload.
        if (isJsonish && a._isDynamicMap(element.type)) {
          a._values[element] = a._untrustedFrom(
            'JSON payload parameter `${p.name?.lexeme ?? ''}` of '
                '`$ownerName`',
            p.offset,
          );
          // Every `x['key'] as int` inside the body inherits this taint.
          a._jsonMaps.add(element);
          a._jsonMapNames.add(p.name?.lexeme ?? '');
          continue;
        }
        if (!a._isIntLike(element.type)) continue;
        final annotated = a._originForAnnotations(p.metadata);
        if (annotated == Origin.untrusted) {
          a._values[element] = a._untrustedFrom(
            'parameter `${p.name?.lexeme ?? ''}` is marked untrusted',
            p.offset,
          );
        } else {
          a._values[element] = IntRange.unbounded(Origin.parameter);
        }
      }
      // An expression-bodied factory (`=> Order(json['id'] as int)`) has no
      // statements to visit, so evaluate the construction here.
      final body = node.body;
      if (body is ExpressionFunctionBody) {
        a.eval(body.expression);
      }
    }
    super.visitConstructorDeclaration(node);
  }

  @override
  void visitFunctionExpression(FunctionExpression node) {
    for (final p in node.parameters?.parameters ?? const <FormalParameter>[]) {
      final element = p.declaredFragment?.element;
      if (element == null || !a._isIntLike(element.type)) continue;
      final existing = a._values[element];
      // Never downgrade taint that interprocedural analysis already proved.
      if (existing != null && existing.isUntrusted) continue;
      final origin = a._originForAnnotations(p.metadata) ?? Origin.parameter;
      a._values[element] = origin == Origin.untrusted
          ? a._untrustedFrom(
              'parameter `${p.name?.lexeme ?? ''}` is marked untrusted',
              p.offset,
            )
          : IntRange.unbounded(origin);
    }
    super.visitFunctionExpression(node);
  }

  @override
  void visitForStatement(ForStatement node) {
    final parts = node.forLoopParts;
    if (parts is ForPartsWithDeclarations) {
      for (final v in parts.variables.variables) {
        final element = v.declaredFragment?.element;
        if (element == null || !a._isIntLike(element.type)) continue;
        final init = v.initializer;
        if (init != null) {
          final start = a.eval(init);
          if (start.isExact) {
            // A loop counter walks upward from its initial value.
            final lo = start.exact!;
            a._values[element] = IntRange(
              lo,
              lo < 0 ? 0 : lo + 0x100000,
              Origin.local,
            );
            continue;
          }
        }
        a._values[element] = const IntRange.local(0, 0x100000);
      }
    }
    super.visitForStatement(node);
  }

  @override
  void visitPostfixExpression(PostfixExpression node) {
    _adjustCounter(node.operand, 1);
    super.visitPostfixExpression(node);
  }

  @override
  void visitPrefixExpression(PrefixExpression node) {
    final op = node.operator.lexeme;
    if (op == '++' || op == '--') {
      _adjustCounter(node.operand, op == '++' ? 1 : -1);
    } else {
      a.eval(node);
    }
    super.visitPrefixExpression(node);
  }

  void _adjustCounter(Expression operand, int delta) {
    if (operand is! SimpleIdentifier) return;
    final element = operand.element;
    if (element == null || !a._isIntLike(a._elementType(element))) return;
    final current = a._values[element] ?? const IntRange.local(0, 0x100000);
    a._values[element] = IntRange(
      current.min + (delta < 0 ? delta : 0),
      current.max + (delta > 0 ? delta : 0),
      current.origin,
      trace: current.trace,
    );
  }

  @override
  void visitBinaryExpression(BinaryExpression node) {
    a.eval(node);
    super.visitBinaryExpression(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    a.eval(node);
    super.visitMethodInvocation(node);
  }

  @override
  void visitIndexExpression(IndexExpression node) {
    a.eval(node);
    super.visitIndexExpression(node);
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    a.eval(node);
    super.visitPropertyAccess(node);
  }

  @override
  void visitAsExpression(AsExpression node) {
    a.eval(node);
    super.visitAsExpression(node);
  }

  @override
  void visitConstructorFieldInitializer(ConstructorFieldInitializer node) {
    final value = a.eval(node.expression);
    final field = node.fieldName.element;
    if (field is GetterElement) {
      a._values[field.variable] = value;
      a._values[field] = value;
    } else if (field != null) {
      a._values[field] = value;
    }
    super.visitConstructorFieldInitializer(node);
  }

  @override
  void visitReturnStatement(ReturnStatement node) {
    final expr = node.expression;
    if (expr != null) {
      final fn = node.thisOrAncestorOfType<FunctionDeclaration>();
      final element = fn?.declaredFragment?.element;
      final value = a.eval(expr);
      if (element != null) {
        a._returnValues[element] = value;
      }
      // A `return Foo(id, ...)` inside a factory is where the constructed
      // object receives its field values; evaluate it so taint reaches the
      // constructor's parameters even though there is no `new` statement.
      if (expr is InstanceCreationExpression) a.eval(expr);
    }
    super.visitReturnStatement(node);
  }
}
