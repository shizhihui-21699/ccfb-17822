// Copyright 2026. All rights reserved.
//
// Value ranges and provenance for the integer flow analysis.
//
// The checker is an abstract interpreter: for every integer expression it
// computes a [IntRange] describing the values that expression can take, plus a
// [Provenance] recording where those values came from. A finding is only
// reported when the range (or the provenance) makes the JavaScript divergence
// reachable. This is what keeps the tool from crying wolf on the counters,
// indices, lengths and flags that dominate ordinary code.

/// The source of an integer's value, in increasing order of "cannot be
/// trusted". [untrusted] is what turns a merely-wide range into an incident.
enum Origin {
  /// A literal or a constant expression: exactly known.
  constant,

  /// A local counter/index/loop variable, or a value derived from one. Its
  /// magnitude is provably small.
  local,

  /// An `int` parameter (or field) with no constraint: its magnitude is
  /// unknown in the type system, so any 64-bit value may arrive. Not
  /// necessarily attacker controlled, but wide enough to diverge on JS.
  parameter,

  /// A value from `DateTime`, `Random`, timers, `.length`, etc. Width is
  /// engine-defined; these are not attacker controlled.
  engine,

  /// `int.parse` / `jsonDecode` / `as int` from `dynamic` / a parameter of a
  /// public entry point. Magnitude is chosen by the caller.
  untrusted,
}

/// Where an untrusted value entered the program, for the report's trace.
class TaintSource {
  const TaintSource({
    required this.origin,
    required this.description,
    required this.offset,
  });

  final Origin origin;

  /// e.g. `jsonDecode(...)['orderId']`, `int.parse(request.body)`.
  final String description;

  /// Offset of the expression that introduced the taint.
  final int offset;
}

/// An inclusive range of integers plus an origin and optional taint trail.
class IntRange {
  const IntRange(this.min, this.max, this.origin, {this.trace, this.exact});

  /// Exact value, when known.
  final int? exact;

  final int min;
  final int max;
  final Origin origin;

  /// Taint trail from the entry point to here, when [origin] is untrusted.
  final List<TaintSource>? trace;

  static const IntRange unknown =
      IntRange(-0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, Origin.engine);

  /// Attacker-controlled 64-bit value.
  const IntRange.untrusted()
    : min = -0x7FFFFFFFFFFFFFFF,
      max = 0x7FFFFFFFFFFFFFFF,
      origin = Origin.untrusted,
      trace = null,
      exact = null;

  /// A value that is a small local counter/index.
  const IntRange.local(int lo, int hi)
    : min = lo,
      max = hi,
      origin = Origin.local,
      trace = null,
      exact = null;

  factory IntRange.of(int value, {Origin origin = Origin.constant}) =>
      IntRange(value, value, origin, exact: value);

  /// A value whose magnitude is not known, but whose provenance is.
  ///
  /// The bounds cover the whole 64-bit int range; [isUnbounded] then means
  /// "we cannot prove anything about the magnitude", which lets the checker
  /// avoid claiming a specific range it does not actually know.
  const IntRange.unbounded(this.origin)
    : min = -0x7FFFFFFFFFFFFFFF,
      max = 0x7FFFFFFFFFFFFFFF,
      trace = null,
      exact = null;

  bool get isExact => exact != null;

  bool get isUntrusted => origin == Origin.untrusted;

  /// True when the bounds are the full int64 range, i.e. nothing is known
  /// about the magnitude (only about the provenance).
  bool get isUnbounded => exact == null && min <= -0x7FFFFFFFFFFFFFFF;

  bool get isSmall => min >= -0x100000 && max <= 0x100000;

  /// Whether every value is inside the 32-bit signed window.
  bool get fitsInInt32 => min >= -0x80000000 && max <= 0x7FFFFFFF;

  /// Whether every value is inside the unsigned 32-bit window.
  bool get fitsInUint32 => min >= 0 && max <= 0xFFFFFFFF;

  /// Whether every value is exactly representable as a JS double.
  bool get fitsInJsSafe => min >= -9007199254740991 && max <= 9007199254740991;

  IntRange withOrigin(Origin o) => IntRange(min, max, o, trace: trace, exact: exact);

  IntRange withTrace(List<TaintSource>? t) =>
      IntRange(min, max, origin, trace: t, exact: exact);

  /// Widen to untrusted, keeping the range.
  IntRange markUntrusted({TaintSource? source}) => IntRange(
    min,
    max,
    Origin.untrusted,
    exact: exact,
    trace: source == null
        ? trace
        : <TaintSource>[...?trace, source],
  );

  @override
  String toString() => exact != null
      ? 'exact($exact, ${origin.name})'
      : '[$min..$max, ${origin.name}]';

  /// The widest of two origins (untrusted dominates).
  static Origin mergeOrigin(Origin a, Origin b) =>
      a.index >= b.index ? a : b;
}

/// Result of evaluating an integer expression: the range, plus whether the
/// expression's operator itself is one whose JS behaviour differs.
class IntValue {
  const IntValue(this.range, {this.differsOnJs = false});

  final IntRange range;

  /// True when the *computed* result provably differs between VM and JS.
  final bool differsOnJs;

  static const IntValue unknown = IntValue(IntRange.unknown);
}

/// Utility predicates shared by the analysis.
class Ranges {
  /// Saturating add that never overflows the int64 domain used in the model.
  static IntRange add(IntRange a, IntRange b) {
    final lo = _sat(a.min + b.min);
    final hi = _sat(a.max + b.max);
    return IntRange(
      lo,
      hi,
      IntRange.mergeOrigin(a.origin, b.origin),
      trace: _mergeTrace(a, b),
    );
  }

  static IntRange mul(IntRange a, IntRange b) {
    final candidates = <int>[
      _sat(a.min * b.min),
      _sat(a.min * b.max),
      _sat(a.max * b.min),
      _sat(a.max * b.max),
    ];
    candidates.sort();
    return IntRange(
      candidates.first,
      candidates.last,
      IntRange.mergeOrigin(a.origin, b.origin),
      trace: _mergeTrace(a, b),
    );
  }

  static List<TaintSource>? _mergeTrace(IntRange a, IntRange b) {
    if (a.trace == null) return b.trace;
    if (b.trace == null) return a.trace;
    final combined = <TaintSource>[...a.trace!, ...b.trace!];
    // De-duplicate by offset so a long expression doesn't repeat the entry.
    final seen = <int>{};
    return [
      for (final t in combined)
        if (seen.add(t.offset)) t,
    ];
  }

  static int _sat(int v) {
    if (v > 0x7FFFFFFFFFFFFFFF) return 0x7FFFFFFFFFFFFFFF;
    if (v < -0x7FFFFFFFFFFFFFFF) return -0x7FFFFFFFFFFFFFFF;
    return v;
  }
}
