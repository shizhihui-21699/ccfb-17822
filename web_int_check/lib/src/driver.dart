import 'dart:io';

import 'package:analyzer/dart/analysis/analysis_context_collection.dart';
import 'package:analyzer/dart/analysis/results.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/dart/element/type.dart';

import 'config.dart';
import 'finding.dart';
import 'range.dart';
import 'rules.dart';
import 'taint.dart';
import 'visitor.dart';

class _Snapshot {
  final Map<Element, String> sig;
  _Snapshot(this.sig);

  @override
  bool operator ==(Object other) =>
      other is _Snapshot && _mapEq(sig, other.sig);

  @override
  int get hashCode => sig.length;

  static bool _mapEq(Map<Element, String> a, Map<Element, String> b) {
    if (a.length != b.length) return false;
    for (final e in a.keys) {
      if (b[e] != a[e]) return false;
    }
    return true;
  }
}

/// Drives analysis over one or more package roots / files and collects
/// [Finding]s.
class CheckerDriver {
  final CheckerConfig config;
  final List<Finding> findings = [];
  final Set<String> _seen = {};

  CheckerDriver(this.config);

  Future<List<Finding>> analyzePaths(List<String> absolutePaths) async {
    final resolved = absolutePaths.map(_absolute).toList();
    for (final path in resolved) {
      if (!FileSystemEntity.isDirectorySync(path) &&
          !FileSystemEntity.isFileSync(path)) {
        throw FileSystemException(
          'Path does not exist (checked before analysis)', path);
      }
    }
    final collection = AnalysisContextCollection(
      includedPaths: resolved,
    );
    for (final context in collection.contexts) {
      final session = context.currentSession;
      final libs = context.contextRoot
          .analyzedFiles()
          .where((p) => p.endsWith('.dart'))
          .where((p) => !_isExcluded(p))
          .toList();
      for (final path in libs) {
        final result = await session.getResolvedUnit(path);
        if (result is ResolvedUnitResult) {
          _checkUnit(result);
        }
      }
    }
    findings.sort((a, b) {
      final c = a.filePath.compareTo(b.filePath);
      return c != 0 ? c : a.offset.compareTo(b.offset);
    });
    return findings;
  }

  static String _absolute(String p) =>
      File(p).isAbsolute ? p : File(p).absolute.path;

  bool _isExcluded(String path) {
    for (final glob in config.excludeGlobs) {
      if (_globMatch(glob, path)) return true;
    }
    return false;
  }

  static bool _globMatch(String pattern, String path) {
    final rx = pattern
        .replaceAll(r'\', '/')
        .split('')
        .map((c) {
          switch (c) {
            case '*':
              return '.*';
            case '?':
              return '.';
            case '.':
              return r'\.';
            default:
              return RegExp.escape(c);
          }
        })
        .join();
    return RegExp('(^|/)$rx\$').hasMatch(path);
  }

  // ------------------------------------------------------------- unit pass

  void _checkUnit(ResolvedUnitResult result) {
    final unit = result.unit;
    final safe = <Element>{};
    final unsafe = <Element>{};
    final initial = <Element, IntState>{};

    final scanner = _DeclarationScanner(
      config: config,
      safe: safe,
      unsafe: unsafe,
      initial: initial,
    );
    unit.accept(scanner);

    var previous = _Snapshot(const {});
    IntStateVisitor lastVisitor = IntStateVisitor(
      elementState: initial,
      safeElements: safe,
      unsafeElements: unsafe,
      extraSources: config.extraSourceMethods.toSet(),
    );

    for (var pass = 0; pass < 10; pass++) {
      lastVisitor = IntStateVisitor(
        elementState: initial,
        safeElements: safe,
        unsafeElements: unsafe,
        extraSources: config.extraSourceMethods.toSet(),
      );
      unit.accept(lastVisitor);
      final snap = _Snapshot({
        for (final e in initial.keys) e: _sig(initial[e]!),
      });
      if (snap == previous) break;
      previous = snap;
    }

    unit.accept(_RuleVisitor(
      driver: this,
      result: result,
      visitor: lastVisitor,
      safe: safe,
      unsafe: unsafe,
    ));
  }

  static String _sig(IntState s) {
    final r = s.range;
    final taints = s.taints.map((t) => t.index).toList()..sort();
    return '${r?.lo ?? '?'};${r?.hi ?? '?'};$taints;safe=${s.safe}';
  }

  // ------------------------------------------------------------ emission

  void emit(
    ResolvedUnitResult result,
    AstNode node,
    CheckRule rule,
    String message,
    String remediation,
  ) {
    final sev = config.severityOf(rule);
    if (sev == CheckSeverity.ignore) return;
    final loc = result.lineInfo.getLocation(node.offset);
    final key = '${rule.id}:${result.path}:${node.offset}';
    if (!_seen.add(key)) return;
    String? snippet;
    try {
      final file = File(result.path);
      if (file.existsSync()) {
        final lines = file.readAsLinesSync();
        if (loc.lineNumber - 1 < lines.length) {
          snippet = lines[loc.lineNumber - 1].trim();
        }
      }
    } catch (_) {}
    findings.add(Finding(
      ruleId: rule.id,
      severity: sev,
      message: message,
      remediation: remediation,
      filePath: result.path,
      offset: node.offset,
      line: loc.lineNumber,
      column: loc.columnNumber,
      codeSnippet: snippet,
    ));
  }
}

/// Scans declarations for `@webSafeInt` / `@webUnsafeInt` and seeds the
/// element state table for parameters and fields.
class _DeclarationScanner extends RecursiveAstVisitor<void> {
  final CheckerConfig config;
  final Set<Element> safe;
  final Set<Element> unsafe;
  final Map<Element, IntState> initial;

  _DeclarationScanner({
    required this.config,
    required this.safe,
    required this.unsafe,
    required this.initial,
  });

  bool _isInt(DartType? t) => t is InterfaceType && t.isDartCoreInt;

  bool _hasMeta(Element e, Set<String> names) {
    // analyzer 7 leaves the legacy `ElementAnnotation.element.name` empty.
    // Its `element2` points at the annotation constructor (name3 == 'new'),
    // so the annotation class name lives on the enclosing element. Handle
    // both shapes; fall back to the legacy getter for analyzer 6.
    for (final m in e.metadata) {
      final dynamic annotation = m;
      try {
        final dynamic e2 = annotation.element2;
        if (e2 != null) {
          final self = e2.name3 as String?;
          final enclosing = e2.enclosingElement2?.name3 as String?;
          if ((self != null && names.contains(self)) ||
              (enclosing != null && names.contains(enclosing))) {
            return true;
          }
        }
      } catch (_) {/* analyzer 6 has no element2 */}
      final legacy = m.element?.name;
      if (legacy != null && legacy.isNotEmpty && names.contains(legacy)) {
        return true;
      }
    }
    return false;
  }

  void _seed(Element element, DartType type) {
    if (!_isInt(type)) return;
    if (_hasMeta(element, config.unsafeAnnotations)) {
      unsafe.add(element);
      initial[element] =
          const IntState(IntRange.unknown, {TaintSource.annotated});
    } else if (_hasMeta(element, config.safeAnnotations)) {
      safe.add(element);
      initial[element] =
          const IntState(IntRange.unknown, <TaintSource>{}, safe: true);
    } else {
      initial.putIfAbsent(element, () => IntState.unboundedInt);
    }
  }

  @override
  void visitFormalParameterList(FormalParameterList node) {
    for (final p in node.parameters) {
      final element = p.declaredElement;
      if (element != null) _seed(element, element.type);
    }
    super.visitFormalParameterList(node);
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final element = node.declaredElement;
    if (element is FieldElement || element is TopLevelVariableElement) {
      if (element != null) _seed(element, element.type);
    }
    super.visitVariableDeclaration(node);
  }
}

/// Second pass: reads the computed states and emits rule findings.
///
/// Three reporting tiers:
///  1. hard warning/error — proven range overflow, untrusted (tainted) data
///     reaching a sensitive operation, or build-breaking literals;
///  2. info (WEB_INT_009) — web-safety cannot be *proved* for a semantics
///     cliff (bitwise/shift/hash); suppressed by `@webSafeInt`;
///  3. silent — ordinary arithmetic on untainted ints (unless strict mode),
///     and bitwise/shift forms whose result is provably identical on every
///     target (e.g. `x & 0x7fffffff`, small constant shifts).
class _RuleVisitor extends RecursiveAstVisitor<void> {
  final CheckerDriver driver;
  final ResolvedUnitResult result;
  final IntStateVisitor visitor;
  final Set<Element> safe;
  final Set<Element> unsafe;

  static final BigInt _int32Min = BigInt.from(-2147483648);
  static final BigInt _int32Max = BigInt.from(2147483647);
  static final BigInt _uint32Max = BigInt.from(4294967295);

  _RuleVisitor({
    required this.driver,
    required this.result,
    required this.visitor,
    required this.safe,
    required this.unsafe,
  });

  CheckerConfig get config => driver.config;
  IntState _s(Expression e) => visitor.exprState[e] ?? IntState.noInt;

  // ---------------------------------------------------------- 001 literals

  @override
  void visitIntegerLiteral(IntegerLiteral node) {
    super.visitIntegerLiteral(node);
    final v = node.value;
    if (v != null && v.abs() > 9007199254740991) {
      driver.emit(
        result,
        node,
        CheckRule.literalUnrepresentable,
        'Literal ${node.literal.lexeme} exceeds 2^53-1; dart2js rejects the '
        'build ("can\'t be represented exactly in JavaScript"), and even if '
        'constructed at runtime it would be rounded.',
        Remediation.int64OrBigInt('the literal',
            needsArbitrary:
                BigInt.from(v.abs()) > BigInt.from(9223372036854775807)),
      );
    }
  }

  // ------------------------------------------------------------ binary ops

  static const _bitwise = {'&', '|', '^'};
  static const _arith = {'+', '-', '*', '%', '~/', 'remainder'};

  @override
  void visitBinaryExpression(BinaryExpression node) {
    super.visitBinaryExpression(node);
    final op = node.operator.lexeme;
    final type = node.staticType;
    final isIntish = type is InterfaceType && type.isDartCoreInt;
    final isDynamic = type is DynamicType;
    if (!isIntish && !isDynamic) return;

    final l = _s(node.leftOperand);
    final r = _s(node.rightOperand);

    if (_bitwise.contains(op)) {
      _checkBitwise(node, op, l, r);
    } else if (op == '<<' || op == '>>' || op == '>>>') {
      _checkShift(node, op, l, r);
    } else if (_arith.contains(op)) {
      _checkArithmetic(node, op, l, r);
    } else if (op == '==') {
      _checkEquality(node, l, r);
    }
  }

  @override
  void visitPrefixExpression(PrefixExpression node) {
    super.visitPrefixExpression(node);
    if (node.operator.lexeme != '~') return;
    final s = _s(node.operand);
    if (!s.isInt && !TypeUtil.isInt(node.staticType)) return;
    // ~ is a hard 32-bit cliff; only a provably-int32 operand is silent.
    if (_provablyInt32(s.range)) return;
    if (s.isTainted) {
      driver.emit(
        result,
        node,
        CheckRule.bitwiseTruncated,
        'Bitwise complement (~) on an untrusted value runs on signed 32-bit '
        'values on JS; e.g. ~0 is -1 on VM/Wasm but 4294967295 on JS.',
        Remediation.bitwiseAdvice,
      );
    } else if (!s.safe) {
      _unproven(node, Remediation.bitwiseAdvice,
          'bitwise "~" whose operand cannot be proved to fit 32 bits',
          states: [s]);
    }
  }

  // --------------------------------------------------------------- bitwise

  void _checkBitwise(
      BinaryExpression node, String op, IntState l, IntState r) {
    if (_bitwiseResultPlatformIndependent(op, l, r)) return;

    final tainted = l.isTainted || r.isTainted;
    if (tainted) {
      driver.emit(
        result,
        node,
        CheckRule.bitwiseTruncated,
        'Operator "$op" on untrusted data is evaluated on signed 32-bit '
        'values in JS but full 64-bit values on VM/Wasm, so the checksum '
        'diverges across targets.',
        Remediation.bitwiseAdvice,
      );
      return;
    }

    // Proven overflow of the 32-bit body.
    final out = _s(node).range;
    if (out != null && !out.isUnbounded && _outsideInt32(out)) {
      driver.emit(
        result,
        node,
        CheckRule.bitwiseTruncated,
        'Result range $out of "$op" does not fit 32 bits; JS truncates it '
        'while VM/Wasm keep the full value.',
        Remediation.bitwiseAdvice,
      );
      return;
    }

    if (l.safe && r.safe) return;
    _unproven(node, Remediation.bitwiseAdvice,
        'bitwise "$op" with an operand that cannot be proved to fit 32 bits',
        states: [l, r]);
  }

  /// Provably identical result on VM, Wasm and JS.
  ///
  /// - `x & m` where `m` is a non-negative constant <= 2^32-1: the JS
  ///   ToInt32/ToUint32 conversions preserve the low 32 bits, so masking
  ///   yields the same value on every target (in-range non-negative result).
  /// - `x | c` / `x ^ c` with a non-negative constant that fits 32 bits,
  ///   only when `x` itself is provably int32.
  /// - any form where both operands are provably int32.
  bool _bitwiseResultPlatformIndependent(
      String op, IntState l, IntState r) {
    if (_provablyInt32(l.range) && _provablyInt32(r.range)) return true;
    if (op == '&') {
      final m = _nonNegativeConst(r.range) ?? _nonNegativeConst(l.range);
      if (m != null && m <= _uint32Max) return true;
    }
    if (op == '|' || op == '^') {
      final c = _nonNegativeConst(r.range);
      if (c != null && c <= _int32Max && _provablyInt32(l.range)) return true;
    }
    return false;
  }

  // ----------------------------------------------------------------- shifts

  void _checkShift(
      BinaryExpression node, String op, IntState l, IntState r) {
    final tainted = l.isTainted || r.isTainted;
    if (_shiftPlatformIndependent(op, l, r)) return;

    if (tainted) {
      driver.emit(
        result,
        node,
        CheckRule.shiftCountSemantics,
        'Shift "$op" on untrusted data: JS masks the count with 31 and works '
        'in 32 bits while VM/Wasm use 64 bits (verified: 1 << 32 is '
        '4294967296 on VM/Wasm but 0 on JS; (-1) >> 1 is -1 vs 4294967295).',
        Remediation.shiftAdvice,
      );
      return;
    }

    final count = r.range;
    final value = l.range;
    if (count != null &&
        !count.isUnbounded &&
        (count.lo! < BigInt.zero || count.hi! >= BigInt.from(32))) {
      driver.emit(
        result,
        node,
        CheckRule.shiftCountSemantics,
        'Shift count range $count reaches 32; JS computes count mod 32 while '
        'VM/Wasm use mod 64, so the result changes at exactly this boundary.',
        Remediation.shiftAdvice,
      );
      return;
    }
    if (op != '>>>' && value != null && !value.isUnbounded &&
        _outsideInt32(value)) {
      driver.emit(
        result,
        node,
        CheckRule.shiftCountSemantics,
        'Shifted value range $value does not fit the JS 32-bit shift body.',
        Remediation.shiftAdvice,
      );
      return;
    }

    if (l.safe && r.safe) return;
    _unproven(node, Remediation.shiftAdvice,
        'shift "$op" with an unconstrained count or value',
        states: [l, r]);
  }

  bool _shiftPlatformIndependent(String op, IntState l, IntState r) {
    final count = r.range;
    final value = l.range;
    if (count == null || count.isUnbounded || value == null ||
        value.isUnbounded) {
      return false;
    }
    if (count.lo! < BigInt.zero || count.hi! >= BigInt.from(32)) {
      return false;
    }
    if (op == '<<') {
      final worst = value.hi! << count.hi!.toInt();
      final worstNeg = value.lo! << count.hi!.toInt();
      return worst <= _int32Max && worstNeg >= _int32Min;
    }
    if (op == '>>') {
      return value.lo! >= _int32Min && value.hi! <= _int32Max;
    }
    // >>>: non-negative values within uint32 behave identically.
    return value.lo! >= BigInt.zero && value.hi! <= _uint32Max;
  }

  // ------------------------------------------------------------- arithmetic

  void _checkArithmetic(
      BinaryExpression node, String op, IntState l, IntState r) {
    final out = _s(node);
    final range = out.range;

    if (l.isTainted || r.isTainted) {
      driver.emit(
        result,
        node,
        _ruleForTaint(out.taints) ?? CheckRule.arithmeticRounded,
        'Arithmetic "$op" consumes ${_taintLabel(out)} data whose magnitude '
        'is unknown; above 2^53 JS rounds every step while VM/Wasm stay '
        'exact, so amounts and checksums diverge.',
        Remediation.arithmeticAdvice,
      );
      return;
    }

    if (range != null && !range.isUnbounded && range.canLeaveSafeRange()) {
      driver.emit(
        result,
        node,
        CheckRule.arithmeticRounded,
        'Result range $range of "$op" can exceed 2^53; JS rounds there '
        '(VM/Wasm wrap at 64 bits), so the value differs across targets.',
        Remediation.arithmeticAdvice,
      );
      return;
    }

    // Untainted, in-range or internally produced: ordinary small-value
    // arithmetic is silent unless the user opted into strict mode.
    if (config.strictArithmetic && !(l.safe && r.safe)) {
      _unproven(node, Remediation.arithmeticAdvice,
          'arithmetic "$op" on unbounded ints (strict mode)',
          states: [l, r]);
    }
  }

  // --------------------------------------------------------- boundary casts

  @override
  void visitAsExpression(AsExpression node) {
    super.visitAsExpression(node);
    final t = node.type.type;
    if (t is! InterfaceType || !t.isDartCoreInt) return;
    final s = _s(node);
    if (s.isTainted) {
      _reportBoundary(node, s, 'an `as int` cast');
    }
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    super.visitVariableDeclaration(node);
    final element = node.declaredElement;
    final init = node.initializer;
    if (element == null || init == null) return;
    final dt = element.type;
    if (dt is! InterfaceType || !dt.isDartCoreInt) return;
    final s = _s(init);
    if (s.isTainted) {
      _reportBoundary(
          init, s, 'the int variable "${node.name.lexeme}"');
    }
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    super.visitAssignmentExpression(node);
    if (node.operator.lexeme != '=') return;
    final lhsType = node.leftHandSide.staticType;
    if (lhsType is! InterfaceType || !lhsType.isDartCoreInt) return;
    final s = _s(node.rightHandSide);
    if (s.isTainted) {
      _reportBoundary(node, s, 'an assignment into an int variable');
    }
  }

  // ----------------------------------------------------------- method calls

  @override
  void visitMethodInvocation(MethodInvocation node) {
    super.visitMethodInvocation(node);
    final name = node.methodName.name;
    final s = _s(node);

    if ((name == 'parse' || name == 'tryParse') &&
        node.realTarget is SimpleIdentifier &&
        (node.realTarget as SimpleIdentifier).name == 'int') {
      final first = node.argumentList.arguments.isEmpty
          ? null
          : node.argumentList.arguments.first;
      final constantString = first is StringLiteral;
      if (!constantString &&
          (s.isTainted || s.range == null || s.range!.isUnbounded)) {
        driver.emit(
          result,
          node,
          CheckRule.parseRounded,
          'int.$name on a runtime string: values above 2^53 are rounded on '
          'JS (verified: int.parse("2^53+1") yields 2^53 on JS but stays '
          'exact on VM/Wasm).',
          Remediation.int64OrBigInt('int.$name', needsArbitrary: false),
        );
      }
    }

    const converters = {'toInt', 'round', 'floor', 'ceil', 'truncate'};
    if (converters.contains(name) &&
        s.taints.contains(TaintSource.numConversion)) {
      driver.emit(
        result,
        node,
        CheckRule.numConversion,
        'num.$name() returns a JS double above 2^53 — precision is lost at '
        'the conversion itself.',
        Remediation.int64OrBigInt('the conversion', needsArbitrary: false),
      );
    }

    if (name == 'hashCode' && s.isInt) {
      if (s.isTainted || (s.range?.canLeaveSafeRange() ?? false)) {
        driver.emit(
          result,
          node,
          CheckRule.hashIdentity,
          'hashCode of an int that can round on JS: distinct ids may share a '
          'hash and collapse in hash-based collections.',
          Remediation.hashAdvice,
        );
      } else if (!s.safe) {
        _unproven(node, Remediation.hashAdvice,
            'hashCode of an unbounded int',
            states: [s]);
      }
    }

    // Map/Set membership checks with int arguments.
    if ((name == 'containsKey' || name == 'contains' || name == 'add') &&
        node.argumentList.arguments.isNotEmpty) {
      final arg = _s(node.argumentList.arguments.first);
      if (arg.isInt &&
          (arg.isTainted || (arg.range?.canLeaveSafeRange() ?? false))) {
        driver.emit(
          result,
          node,
          CheckRule.hashIdentity,
          'Hash-based lookup with an int that can round on JS may collide and '
          'bypass idempotency/dedup logic.',
          Remediation.hashAdvice,
        );
      }
    }
  }

  // ------------------------------------------------------- keys / equality

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    super.visitMapLiteralEntry(node);
    final s = _s(node.key);
    if (!s.isInt) return;
    if (s.isTainted || (s.range?.canLeaveSafeRange() ?? false)) {
      driver.emit(
        result,
        node.key,
        CheckRule.hashIdentity,
        'Integer map key can collide after JS rounding (verified: ids '
        '2^53+3 and 2^53+5 collapse into one map entry on JS, defeating '
        'idempotency maps).',
        Remediation.hashAdvice,
      );
    }
  }

  @override
  void visitIndexExpression(IndexExpression node) {
    super.visitIndexExpression(node);
    final parent = node.parent;
    final isWrite = parent is AssignmentExpression &&
        parent.leftHandSide == node;
    if (!isWrite) return;
    // The key is the index argument, not the indexed collection's state.
    final key = _s(node.index);
    if (key.isInt &&
        (key.isTainted || (key.range?.canLeaveSafeRange() ?? false))) {
      driver.emit(
        result,
        node,
        CheckRule.hashIdentity,
        'Untrusted int used as a map key can collide on JS and bypass '
        'idempotency/dedup logic.',
        Remediation.hashAdvice,
      );
    }
  }

  void _checkEquality(BinaryExpression node, IntState l, IntState r) {
    bool hard(IntState s) =>
        s.isInt && (s.isTainted || (s.range?.canLeaveSafeRange() ?? false));
    if (hard(l) || hard(r)) {
      driver.emit(
        result,
        node,
        CheckRule.hashIdentity,
        'Equality on large/untrusted ints compares rounded doubles on JS — '
        'two different server ids can compare equal.',
        Remediation.hashAdvice,
      );
    }
  }

  // ------------------------------------------------------------- helpers

  void _reportBoundary(Expression node, IntState s, String where) {
    final rule = _ruleForTaint(s.taints) ?? CheckRule.jsonTaint;
    final remediation = s.taints.contains(TaintSource.json) ||
            s.taints.contains(TaintSource.configured)
        ? Remediation.jsonAdvice
        : Remediation.int64OrBigInt(where, needsArbitrary: false);
    driver.emit(
      result,
      node,
      rule,
      'Untrusted number (${_taintLabel(s)}) enters the int world at $where; '
      'on JS it is already rounded, so client/server checksums and '
      'idempotency keys can disagree.',
      remediation,
    );
  }

  CheckRule? _ruleForTaint(Set<TaintSource> t) {
    if (t.contains(TaintSource.json) ||
        t.contains(TaintSource.configured) ||
        t.contains(TaintSource.annotated)) {
      return CheckRule.jsonTaint;
    }
    if (t.contains(TaintSource.parse)) return CheckRule.parseRounded;
    if (t.contains(TaintSource.numConversion)) return CheckRule.numConversion;
    return null;
  }

  String _taintLabel(IntState s) {
    if (s.taints.contains(TaintSource.json)) return 'JSON-derived';
    if (s.taints.contains(TaintSource.parse)) return 'runtime-parsed';
    if (s.taints.contains(TaintSource.numConversion)) {
      return 'num-converted';
    }
    if (s.taints.contains(TaintSource.annotated)) {
      return 'annotated web-unsafe';
    }
    if (s.taints.contains(TaintSource.configured)) {
      return 'configured untrusted-source';
    }
    return 'untrusted';
  }

  void _unproven(AstNode node, String remediation, String what,
      {List<IntState> states = const []}) {
    // An explicit @webSafeInt boundary contract is the documented opt-out.
    if (states.isNotEmpty && states.every((s) => s.safe)) return;
    driver.emit(
      result,
      node,
      CheckRule.unprovenParameter,
      'Cannot prove web-safety: $what. Mark the boundary parameter '
      '@webSafeInt when its range is guaranteed, otherwise use Int64/BigInt.',
      remediation,
    );
  }

  bool _provablyInt32(IntRange? r) {
    if (r == null || r.isUnbounded) return false;
    return r.lo! >= _int32Min && r.hi! <= _int32Max;
  }

  bool _outsideInt32(IntRange r) {
    if (r.isUnbounded) return true;
    return r.lo! < _int32Min || r.hi! > _int32Max;
  }

  BigInt? _nonNegativeConst(IntRange? r) {
    if (r == null || !r.isExact) return null;
    final v = r.exactValue!;
    return v >= BigInt.zero ? v : null;
  }
}
