// Copyright 2026. All rights reserved.
//
// Core value types for the cross-platform integer semantics checker.

/// A compilation target whose `int` semantics differ.
///
/// The Dart ecosystem has three relevant `int` models:
///
///  * [vm]   – the Dart VM and AOT: signed 64-bit two's-complement integers
///             that wrap on overflow, 64-bit shifts and bitwise operators.
///  * [wasm] – `dart compile wasm`: exactly the same 64-bit semantics as the
///             VM. Kept separate because it is the web target that does *not*
///             suffer from the JavaScript `int` problem, and confusing the two
///             web targets is the most common source of bogus findings.
///  * [js]   – `dart compile js`: `int` is an IEEE-754 double (53-bit exact
///             integer range) and every bitwise operator runs through
///             `ToInt32`/`ToUint32`, i.e. 32 bits.
enum Target {
  vm,
  wasm,
  js;

  String get label => switch (this) {
    Target.vm => 'VM',
    Target.wasm => 'Wasm',
    Target.js => 'JS',
  };

  bool get isWeb => this == Target.js || this == Target.wasm;
}

/// Severity of a finding.
///
/// * [error]   – definitely wrong: either `dart compile js` rejects the source
///               or the result provably differs for the value in the code.
/// * [warning] – will differ for realistic values (attacker-controlled or
///               provably wide), but not for every input.
/// * [info]    – advisory: fragile pattern, or a divergence that only shows up
///               for inputs outside the normal range.
enum Severity {
  error,
  warning,
  info;

  String get label => switch (this) {
    Severity.error => 'error',
    Severity.warning => 'warning',
    Severity.info => 'info',
  };

  static Severity parse(String value) => switch (value) {
    'error' => Severity.error,
    'warning' => Severity.warning,
    'info' || 'hint' => Severity.info,
    _ => Severity.warning,
  };
}

/// How aggressively the checker reports.
///
/// The default is deliberately tuned for a real codebase: small, bounded,
/// non-sensitive arithmetic is never reported, so a project full of counters,
/// indices and flags stays quiet.
enum Strictness {
  /// Only report provable problems: oversized literals and constant
  /// expressions that fold differently, plus attacker-controlled magnitudes.
  minimal,

  /// The default. Adds values whose range provably exceeds the JavaScript
  /// limits, and integer keys used for identity/idempotency.
  standard,

  /// Also report bitwise/hash operations on integers of *unknown* range.
  /// Useful for security-critical packages, noisy on general code.
  strict;

  static Strictness parse(String value) => switch (value) {
    'minimal' => Strictness.minimal,
    'strict' => Strictness.strict,
    _ => Strictness.standard,
  };
}

/// Stable identifiers for the diagnostics this tool produces.
///
/// Every code maps to exactly one fix strategy so the report can always tell
/// the developer what to change.
enum FindingCode {
  /// An integer literal that `dart compile js` cannot represent exactly.
  /// The web build fails outright; this is the strongest possible signal.
  literalNotRepresentable(
    'web_integer_literal_not_representable',
    'Integer literal is not exactly representable as a JavaScript number',
  ),

  /// A constant expression that folds to a different value on JS than on the
  /// VM/Wasm (for example `1 << 40`, or `9007199254740992 + 1`).
  constantFoldsDifferently(
    'web_integer_constant_differs',
    'Constant integer expression has a different value on the JS target',
  ),

  /// `+`, `-`, `*`, unary `-`, `~/` or `%` on values that can leave the
  /// 53-bit exact range. Precision is silently lost on JS.
  arithmeticLosesPrecision(
    'web_integer_arithmetic_loses_precision',
    'Integer arithmetic can exceed the 53-bit exact range of JavaScript',
  ),

  /// A shift whose result differs on JS because shifts are 32-bit there and
  /// the shift amount or the operand is out of the safe window.
  shiftTruncatesOnWeb(
    'web_shift_truncates',
    'Shift is evaluated with 32-bit JavaScript semantics',
  ),

  /// `&`, `|`, `^` or `~` on values that are not provably confined to the
  /// 32-bit window, so the JS `ToInt32`/`ToUint32` coercion changes the result.
  bitwiseTruncatesOnWeb(
    'web_bitwise_truncates_32bit',
    'Bitwise operator is truncated to 32 bits on JavaScript',
  ),

  /// `int` (or `num`) `.hashCode` — and `Object.hash` / `identityHashCode` —
  /// are not stable across the VM, Wasm and JS runtimes.
  hashCodeNotPortable(
    'web_hash_code_not_portable',
    'Integer hash code is not stable across compilation targets',
  ),

  /// An integer that came from JSON, `int.parse`, or another external source
  /// flows into a platform-dependent operation. The magnitude is attacker
  /// controlled, which is exactly the exploit in the incident.
  untrustedMagnitude(
    'web_untrusted_integer_magnitude',
    'Attacker-controlled integer reaches a platform-dependent operation',
  ),

  /// A wide integer used as a `Map` key, `Set` member or identity token.
  /// Two distinct 64-bit ids can collapse to the same double on JS, defeating
  /// duplicate-order detection.
  integerKeyCollision(
    'web_integer_key_collision',
    'Distinct 64-bit integers can collide after JavaScript coercion',
  ),

  /// `num.toInt()` / `double.toInt()` on a value outside the exact range:
  /// the VM saturates while JS returns a non-integral double.
  doubleToIntDiverges(
    'web_double_to_int',
    'Converting a large double to int differs between VM and JS',
  );

  const FindingCode(this.id, this.problem);

  /// The stable diagnostic id, also usable as an `// ignore:` name.
  final String id;

  /// One-line human-readable problem template.
  final String problem;
}

/// A single reportable issue.
class Finding {
  Finding({
    required this.code,
    required this.severity,
    required this.offset,
    required this.length,
    required this.message,
    required this.fix,
    this.targets = const <Target>[],
    this.sample,
    this.trace = const <String>[],
    this.snippet,
  });

  final FindingCode code;
  final Severity severity;

  /// Offset in the analyzed file.
  final int offset;

  /// Length of the highlighted range.
  final int length;

  /// Full explanation, including the computed values when known.
  final String message;

  /// Concrete remediation, e.g. "Use Int64 (package:fixnum)".
  final String fix;

  /// Targets whose result differs from the reference (VM/Wasm) result.
  final List<Target> targets;

  /// Rendered per-target results, e.g. `{VM: 1099511627776, JS: 0}`.
  final Map<Target, String>? sample;

  /// Taint provenance, one entry per hop, when the value is external.
  final List<String> trace;

  /// The source text of the offending expression, for the report.
  final String? snippet;

  Finding copyWith({Severity? severity, String? message, String? fix}) =>
      Finding(
        code: code,
        severity: severity ?? this.severity,
        offset: offset,
        length: length,
        message: message ?? this.message,
        fix: fix ?? this.fix,
        targets: targets,
        sample: sample,
        trace: trace,
        snippet: snippet,
      );

  Map<String, Object?> toJson(String file) => <String, Object?>{
    'file': file,
    'line': _line,
    'column': _column,
    'offset': offset,
    'length': length,
    'code': code.id,
    'severity': severity.label,
    'message': message,
    'fix': fix,
    if (targets.isNotEmpty) 'targets': targets.map((t) => t.name).toList(),
    if (sample != null) 'sample': sample!.map((k, v) => MapEntry(k.name, v)),
    if (trace.isNotEmpty) 'trace': trace,
    if (snippet != null) 'snippet': snippet,
  };

  // Filled in by the report layer once line info is known; kept as plain
  // ints so `toJson` stays allocation-light.
  int _line = 0;
  int _column = 0;

  /// Attach 1-based line/column (used by the JSON/SARIF renderers).
  void setLocation(int line, int column) {
    _line = line;
    _column = column;
  }
}
