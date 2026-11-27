import 'semantics.dart';

/// A mathematical integer interval, unbounded ends allowed.
///
/// Bounds use [BigInt] on purpose: products of two 64-bit-ranged operands
/// need more than 64 bits to stay exact, and source literals outside the
/// 64-bit range still parse.
class IntRange {
  /// Inclusive lower bound, or `null` when unbounded.
  final BigInt? lo;

  /// Inclusive upper bound, or `null` when unbounded.
  final BigInt? hi;

  const IntRange._(this.lo, this.hi);

  factory IntRange.exact(BigInt v) => IntRange._(v, v);

  /// Inclusive bounded range. Public for tests and custom transfer rules.
  factory IntRange.bounded(BigInt lo, BigInt hi) => IntRange._(lo, hi);

  static const IntRange unknown = IntRange._(null, null);

  bool get isExact => lo != null && lo == hi;
  BigInt? get exactValue => isExact ? lo : null;
  bool get isUnbounded => lo == null || hi == null;

  bool canExceedSafeInt() =>
      hi == null || hi! > BigInt.from(maxSafeInteger);
  bool canBeBelowNegativeSafeInt() =>
      lo == null || lo! < BigInt.from(-maxSafeInteger);
  bool canLeaveSafeRange() =>
      canExceedSafeInt() || canBeBelowNegativeSafeInt();
  bool canBeNegative() => lo == null || lo! < BigInt.zero;
  bool canBeNonPositive() => lo == null || lo! <= BigInt.zero;

  static IntRange? union(IntRange? a, IntRange? b) {
    if (a == null) return b;
    if (b == null) return a;
    final lo = (a.lo == null || b.lo == null)
        ? null
        : (a.lo! < b.lo! ? a.lo : b.lo);
    final hi = (a.hi == null || b.hi == null)
        ? null
        : (a.hi! > b.hi! ? a.hi : b.hi);
    return IntRange._(lo, hi);
  }

  static IntRange exactInt(int v) => IntRange.exact(BigInt.from(v));

  @override
  String toString() {
    final l = lo ?? '-inf';
    final h = hi ?? '+inf';
    return isExact ? '$l' : '[$l, $h]';
  }
}

/// Transfer functions for the integer interval abstract domain.
///
/// Every function returns `null` ("no int information", e.g. for a `double`
/// operand) rather than an unbounded range; unbounded-but-int is
/// [IntRange.unknown].
class RangeOps {
  static IntRange? binary(String op, IntRange? a, IntRange? b) {
    if (a == null || b == null) return null;
    switch (op) {
      case '+':
        return _arith(a, b, (x, y) => x + y);
      case '-':
        return _arith(a, b, (x, y) => x - y);
      case '*':
        return _mul(a, b);
      case '%':
      case 'remainder':
        return _modulo(a, b);
      case '~/':
        return _truncDiv(a, b);
      case '&':
        return _bitAnd(a, b);
      case '|':
        return _bitOr(a, b);
      case '^':
        return _bitXor(a, b);
      case '<<':
        return _shiftLeft(a, b);
      case '>>':
        return _shiftRight(a, b);
      case '>>>':
        return _unsignedShiftRight(a, b);
      default:
        return IntRange.unknown;
    }
  }

  static IntRange? unary(String op, IntRange? a) {
    if (a == null) return null;
    switch (op) {
      case '-':
        return IntRange._(a.hi == null ? null : -a.hi!,
            a.lo == null ? null : -a.lo!);
      case '~':
        // ~x == -x - 1
        final neg = unary('-', a)!;
        return IntRange._(
            neg.lo == null ? null : neg.lo! - BigInt.one,
            neg.hi == null ? null : neg.hi! - BigInt.one);
      case 'abs':
        if (!a.canBeNegative()) return a;
        if (a.lo == null || a.hi == null) return IntRange.unknown;
        final maxAbs = [a.lo!.abs(), a.hi!.abs()].reduce((x, y) => x > y ? x : y);
        return IntRange._(BigInt.zero, maxAbs);
      default:
        return IntRange.unknown;
    }
  }

  static IntRange _arith(IntRange a, IntRange b,
      BigInt Function(BigInt, BigInt) f) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    final corners = [
      f(a.lo!, b.lo!),
      f(a.lo!, b.hi!),
      f(a.hi!, b.lo!),
      f(a.hi!, b.hi!),
    ];
    return IntRange._(corners.reduce((x, y) => x < y ? x : y),
        corners.reduce((x, y) => x > y ? x : y));
  }

  static IntRange _mul(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    final corners = [
      a.lo! * b.lo!,
      a.lo! * b.hi!,
      a.hi! * b.lo!,
      a.hi! * b.hi!,
    ];
    return IntRange._(corners.reduce((x, y) => x < y ? x : y),
        corners.reduce((x, y) => x > y ? x : y));
  }

  static IntRange? _modulo(IntRange a, IntRange b) {
    // Result magnitude is bounded by the divisor's magnitude minus one.
    final bAbs = b.isExact
        ? b.exactValue!.abs()
        : (b.lo == null || b.hi == null ? null : _maxAbs(b.lo!, b.hi!));
    if (bAbs == null) return IntRange.unknown;
    if (bAbs == BigInt.zero) return IntRange.unknown;
    final m = bAbs - BigInt.one;
    // Dart `%` always returns a non-negative result; `remainder` can be
    // negative, but the magnitude bound is the same.
    return IntRange._(BigInt.zero, m);
  }

  static IntRange? _truncDiv(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    if (b.lo == BigInt.zero || b.hi == BigInt.zero) return IntRange.unknown;
    final corners = [
      _trunc(a.lo!, b.lo!),
      _trunc(a.lo!, b.hi!),
      _trunc(a.hi!, b.lo!),
      _trunc(a.hi!, b.hi!),
    ];
    return IntRange._(corners.reduce((x, y) => x < y ? x : y),
        corners.reduce((x, y) => x > y ? x : y));
  }

  static BigInt _trunc(BigInt x, BigInt y) {
    final r = x ~/ y;
    return (x.isNegative != y.isNegative && x != BigInt.zero) ? r : r;
  }

  static BigInt _maxAbs(BigInt x, BigInt y) {
    final ax = x.abs(), ay = y.abs();
    return ax > ay ? ax : ay;
  }

  /// Bit-width sufficient for the magnitude of [v] (0 -> 0, 1 -> 1, 2..3 -> 2…).
  static int _bitWidth(BigInt v) {
    v = v.abs();
    var w = 0;
    while (v > BigInt.zero) {
      w++;
      v >>= 1;
    }
    return w;
  }

  static BigInt _maskOfWidth(int w) =>
      w == 0 ? BigInt.zero : (BigInt.one << w) - BigInt.one;

  static BigInt _maskForValue(BigInt v) => _maskOfWidth(_bitWidth(v));

  static IntRange? _bitAnd(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    if (!a.canBeNegative() && !b.canBeNegative()) {
      final bound = _maskForValue(a.hi!.abs() < b.hi!.abs() ? a.hi! : b.hi!);
      return IntRange._(BigInt.zero, bound);
    }
    return IntRange.unknown;
  }

  static IntRange? _bitOr(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    if (!a.canBeNegative() && !b.canBeNegative()) {
      final w = _bitWidth(a.hi!) > _bitWidth(b.hi!) ? _bitWidth(a.hi!) : _bitWidth(b.hi!);
      return IntRange._(BigInt.zero, _maskOfWidth(w));
    }
    return IntRange.unknown;
  }

  static IntRange? _bitXor(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    if (!a.canBeNegative() && !b.canBeNegative()) {
      final w = _bitWidth(a.hi!) > _bitWidth(b.hi!) ? _bitWidth(a.hi!) : _bitWidth(b.hi!);
      return IntRange._(BigInt.zero, _maskOfWidth(w));
    }
    return IntRange.unknown;
  }

  static IntRange? _shiftLeft(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    BigInt sh(BigInt v, BigInt n) {
      if (n < BigInt.zero) throw StateError('negative shift');
      return v << n.toInt();
    }

    final corners = [
      sh(a.lo!, b.lo!),
      sh(a.lo!, b.hi!),
      sh(a.hi!, b.lo!),
      sh(a.hi!, b.hi!),
    ];
    return IntRange._(corners.reduce((x, y) => x < y ? x : y),
        corners.reduce((x, y) => x > y ? x : y));
  }

  static IntRange? _shiftRight(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    final nMax = b.hi!.toInt();
    if (nMax < 0) return IntRange.unknown;
    final srd = a.lo! >> nMax;
    final shi = a.hi! >> nMax;
    return IntRange._(srd < shi ? srd : shi, srd > shi ? srd : shi);
  }

  static IntRange? _unsignedShiftRight(IntRange a, IntRange b) {
    if (a.isUnbounded || b.isUnbounded) return IntRange.unknown;
    final nMax = b.hi!.toInt();
    if (nMax < 0) return IntRange.unknown;
    // Non-negative operands behave like the signed shift.
    if (!a.canBeNegative()) return _shiftRight(a, b);
    // Negative operand: result magnitude can reach the operand's bit width.
    return IntRange._(BigInt.zero, _maskOfWidth(_bitWidth(a.lo!.abs())));
  }

  /// Result range of [num.toInt]/[num.round]/… — precision loss on JS, so
  /// mark it unbounded and let taint carry the warning.
  static IntRange fromNumConversion() => IntRange.unknown;
}
