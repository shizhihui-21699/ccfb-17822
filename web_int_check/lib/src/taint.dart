import 'range.dart';

/// Where an integer value may have come from, in terms of web precision.
enum TaintSource {
  /// `dart:convert` `jsonDecode` / `JsonDecoder` (or a configured source).
  /// On JS every number in the payload is a JS `double`: values above 2^53
  /// are rounded before the program ever sees them.
  json,

  /// `int.parse` / `int.tryParse` with a non-constant argument. On JS the
  /// parsed value is rounded when it exceeds 2^53.
  parse,

  /// `num.toInt/round/floor/ceil/truncate` (and `double` equivalents).
  /// On JS the result is a rounded double above 2^53.
  numConversion,

  /// Explicitly marked web-unsafe by an `@webUnsafeInt` annotation.
  annotated,

  /// A configured additional source method.
  configured,
}

/// Abstract state attached to expressions. Taint is tracked independently of
/// whether the expression statically looks like an int, so that a
/// `jsonDecode(...) as Map` followed by `map['id'] as int` keeps its
/// untrusted provenance end to end.
class IntState {
  /// Mathematical range of the value. `null` means "not an int / no int
  /// information"; [IntRange.unknown] means "int but unbounded".
  final IntRange? range;

  /// Taint sources that can reach this value (empty == internally produced
  /// from known-safe operands).
  final Set<TaintSource> taints;

  /// True when every contributing element carries an `@webSafeInt`
  /// contract. Suppresses "cannot prove" infos (never hard warnings).
  final bool safe;

  const IntState(this.range, this.taints, {this.safe = false});

  static const IntState noInt = IntState(null, <TaintSource>{});
  static const IntState unboundedInt =
      IntState(IntRange.unknown, <TaintSource>{});

  bool get isInt => range != null;
  bool get isTainted => taints.isNotEmpty;

  IntState withRange(IntRange? r) => IntState(r, taints, safe: safe);

  static IntState merge(IntState a, IntState b) {
    // The `@webSafeInt` contract is a property of the element, not of any
    // one incoming value; a merge with an internally-produced (untainted)
    // state must not erase it. Taint, however, always wins.
    final taints = <TaintSource>{...a.taints, ...b.taints};
    final safe = (a.safe || b.safe) && taints.isEmpty;
    if (!a.isInt && !b.isInt) {
      return IntState(null, taints, safe: safe);
    }
    if (!a.isInt) {
      return IntState(b.range, taints, safe: safe);
    }
    if (!b.isInt) {
      return IntState(a.range, taints, safe: safe);
    }
    return IntState(IntRange.union(a.range, b.range), taints, safe: safe);
  }

  static IntState joinTaint(IntRange? range, Iterable<IntState> parts) {
    final taints = <TaintSource>{};
    var anySafe = false;
    var anyPart = false;
    for (final p in parts) {
      anyPart = true;
      taints.addAll(p.taints);
      if (p.safe) anySafe = true;
    }
    return IntState(range, taints,
        safe: anyPart && anySafe && taints.isEmpty);
  }

  @override
  String toString() => 'IntState($range, taint=$taints, safe=$safe)';
}
