// Copyright 2026. All rights reserved.
//
// Exact per-target models of Dart's `int` operators.
//
// Everything here was validated against real builds of the same source on the
// Dart VM, `dart compile js` and `dart compile wasm`. The models are:
//
//   VM / Wasm : signed 64-bit two's complement, wrapping on overflow.
//               `<<`, `>>`, `>>>` use the low 6 bits conceptually but *saturate*
//               (a shift amount >= 64 behaves like shifting every bit out:
//               `1 << 64 == 0`, `-1 >> 64 == -1`, `-1 >>> 64 == 0`).
//               `%` is Euclidean (result is never negative).
//   JS        : every bitwise operator runs through ToInt32/ToUint32, so the
//               result always fits in 32 bits and is *non-negative* for
//               `&`, `|`, `^`, `~`, `<<`, `>>>`; `>>` on a negative receiver
//               sign-fills then coerces to unsigned, so it is non-negative too.
//               A shift amount > 31 yields 0. Arithmetic (+ - *) is IEEE-754
//               double arithmetic, exact only while |value| <= 2^53.

import 'model.dart';

/// 2^31.
final BigInt bigTwo31 = BigInt.one << 31;

/// 2^32.
final BigInt bigTwo32 = BigInt.one << 32;

/// 2^53, the largest exactly representable JavaScript integer magnitude + 1.
final BigInt bigTwo53 = BigInt.one << 53;

/// 2^63.
final BigInt bigTwo63 = BigInt.one << 63;

/// 2^64.
final BigInt bigTwo64 = BigInt.one << 64;

/// The largest integer a Dart `int` can hold.
final BigInt bigMaxInt64 = bigTwo63 - BigInt.one;

/// The smallest integer a Dart `int` can hold.
final BigInt bigMinInt64 = -bigTwo63;

/// Largest magnitude at which every integer is exactly representable as a JS
/// double.
final BigInt bigMaxSafeJs = bigTwo53 - BigInt.one;

/// Wrap an arbitrary precision integer into signed 64-bit range.
BigInt toInt64(BigInt value) {
  final wrapped = value & (bigTwo64 - BigInt.one);
  return wrapped >= bigTwo63 ? wrapped - bigTwo64 : wrapped;
}

/// Interpret the low 64 bits as an unsigned integer.
BigInt toUint64(BigInt value) => value & (bigTwo64 - BigInt.one);

/// Interpret the low 32 bits as a signed integer.
BigInt toInt32(BigInt value) {
  final low = value & (bigTwo32 - BigInt.one);
  return low >= bigTwo31 ? low - bigTwo32 : low;
}

/// Interpret the low 32 bits as an unsigned integer.
BigInt toUint32(BigInt value) => value & (bigTwo32 - BigInt.one);

/// Whether [value] is exactly representable as a JavaScript double, i.e.
/// whether `dart compile js` will accept it as an integer literal.
///
/// dart2js rejects a literal like `9007199254740993` at compile time with
/// "The integer literal ... can't be represented exactly in JavaScript", while
/// `9007199254740992` and `9007199254740994` are accepted (they round-trip
/// through a double exactly).
bool isExactlyRepresentableAsDouble(BigInt value) {
  final asDouble = value.toDouble();
  if (!asDouble.isFinite) return false;
  if (asDouble != asDouble.truncateToDouble()) return false;
  return BigInt.from(asDouble) == value;
}

/// Whether the integer [value] is within the JavaScript exact range.
bool isWithinJsExactRange(BigInt value) =>
    value >= -bigTwo53 && value <= bigTwo53;

/// Whether two VM results would be observed as equal on JS.
bool jsAgreesWithVm(double jsValue, BigInt vmValue) {
  if (!jsValue.isFinite) return false;
  if (jsValue != jsValue.truncateToDouble()) return false;
  return BigInt.from(jsValue) == vmValue;
}

/// Thrown when an operation has no defined value (division by zero, negative
/// shift amount). Both the VM and JS throw for these, so they are not
/// cross-platform divergences and callers should not report them.
class UndefinedIntegerOperation implements Exception {
  UndefinedIntegerOperation(this.reason);
  final String reason;
  @override
  String toString() => 'UndefinedIntegerOperation: $reason';
}

/// Evaluates an integer expression under one target's semantics.
///
/// VM and Wasm produce exact [BigInt]s; JS produces [double]s because that is
/// what a JS-hosted Dart `int` actually is.
class TargetEvaluator {
  const TargetEvaluator(this.target);

  final Target target;

  bool get isJs => target == Target.js;

  // ---------------------------------------------------------------------
  // Literals
  // ---------------------------------------------------------------------

  /// The value a literal takes on [target].
  ///
  /// On the VM/Wasm this is the mathematical value (the compiler rejects
  /// anything outside 64 bits). On JS the literal is rejected by the compiler
  /// if it is not exactly representable, so callers should check
  /// [isExactlyRepresentableAsDouble] first.
  Object literal(BigInt value) {
    if (isJs) return value.toDouble();
    return toInt64(value);
  }

  // ---------------------------------------------------------------------
  // Arithmetic
  // ---------------------------------------------------------------------

  Object add(Object a, Object b) => isJs ? _d(a) + _d(b) : toInt64(_b(a) + _b(b));

  Object subtract(Object a, Object b) =>
      isJs ? _d(a) - _d(b) : toInt64(_b(a) - _b(b));

  Object multiply(Object a, Object b) =>
      isJs ? _d(a) * _d(b) : toInt64(_b(a) * _b(b));

  Object negate(Object a) => isJs ? -_d(a) : toInt64(-_b(a));

  Object truncatingDivide(Object a, Object b) {
    if (isJs) return _jsTdiv(_d(a), _d(b));
    final bb = _b(b);
    if (bb == BigInt.zero) throw UndefinedIntegerOperation('division by zero');
    // BigInt.~/ truncates toward zero, matching Dart int.~/
    return toInt64(_b(a) ~/ bb);
  }

  Object modulo(Object a, Object b) {
    if (isJs) return _jsMod(_d(a), _d(b));
    final bb = _b(b);
    if (bb == BigInt.zero) throw UndefinedIntegerOperation('modulo by zero');
    // BigInt.% is Euclidean, matching Dart int.%:  -7 % 3 == 2, 7 % -3 == 1
    return toInt64(_b(a) % bb);
  }

  // ---------------------------------------------------------------------
  // Shifts
  // ---------------------------------------------------------------------

  Object shiftLeft(Object a, Object amount) {
    final sh = _b(amount);
    if (sh < BigInt.zero) throw UndefinedIntegerOperation('negative shift amount');
    if (isJs) {
      final d = _d(a);
      if (!d.isFinite) return 0.0;
      final n = _toShiftInt(sh);
      if (n > 31) return 0.0;
      // (a << n) >>> 0 : int32 shift then unsigned coercion.
      final shifted = toUint32(toInt32(_dToBigInt(d)) << n);
      return shifted.toDouble();
    }
    if (sh >= BigInt.from(64)) return BigInt.zero;
    return toInt64(_b(a) << sh.toInt());
  }

  Object shiftRight(Object a, Object amount) {
    final sh = _b(amount);
    if (sh < BigInt.zero) throw UndefinedIntegerOperation('negative shift amount');
    if (isJs) {
      final d = _d(a);
      if (!d.isFinite) return 0.0;
      final n = _toShiftInt(sh);
      final av = _dToBigInt(d);
      if (av > BigInt.zero) {
        if (n > 31) return 0.0;
        return (toUint32(av) >> n).toDouble();
      }
      // Negative receiver: arithmetic shift of the int32, then unsigned.
      final clamped = n > 31 ? 31 : n;
      final signed = toInt32(av) >> clamped;
      return toUint32(signed).toDouble();
    }
    if (sh >= BigInt.from(64)) return _b(a) < BigInt.zero ? -BigInt.one : BigInt.zero;
    final av = _b(a);
    // BigInt >> is an arithmetic shift, which is what the VM does.
    return toInt64(av >> sh.toInt());
  }

  Object unsignedShiftRight(Object a, Object amount) {
    final sh = _b(amount);
    if (sh < BigInt.zero) throw UndefinedIntegerOperation('negative shift amount');
    if (isJs) {
      final d = _d(a);
      if (!d.isFinite) return 0.0;
      final n = _toShiftInt(sh);
      if (n > 31) return 0.0;
      return (toUint32(_dToBigInt(d)) >> n).toDouble();
    }
    if (sh >= BigInt.from(64)) return BigInt.zero;
    return toInt64(toUint64(_b(a)) >> sh.toInt());
  }

  // ---------------------------------------------------------------------
  // Bitwise
  // ---------------------------------------------------------------------

  Object bitAnd(Object a, Object b) {
    if (isJs) {
      return toUint32(toInt32(_dToBigInt(_d(a))) & toInt32(_dToBigInt(_d(b))))
          .toDouble();
    }
    return toInt64(_b(a) & _b(b));
  }

  Object bitOr(Object a, Object b) {
    if (isJs) {
      return toUint32(toInt32(_dToBigInt(_d(a))) | toInt32(_dToBigInt(_d(b))))
          .toDouble();
    }
    return toInt64(_b(a) | _b(b));
  }

  Object bitXor(Object a, Object b) {
    if (isJs) {
      return toUint32(toInt32(_dToBigInt(_d(a))) ^ toInt32(_dToBigInt(_d(b))))
          .toDouble();
    }
    return toInt64(_b(a) ^ _b(b));
  }

  Object bitNot(Object a) {
    if (isJs) return toUint32(~toInt32(_dToBigInt(_d(a)))).toDouble();
    return toInt64(~_b(a));
  }

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------

  /// Render an evaluator value the way `print` would on this target.
  String render(Object value) {
    if (value is BigInt) return value.toString();
    final d = value as double;
    if (!d.isFinite || d != d.truncateToDouble()) return d.toString();
    // A JS `int` prints like an integer; mimic Dart's double->int formatting
    // for values inside the exact range and fall back to the double form.
    if (d.abs() <= 9007199254740992.0) {
      return BigInt.from(d).toString();
    }
    return d.toString();
  }

  // ---------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------

  BigInt _b(Object v) => v is BigInt ? v : _dToBigInt(v as double);

  double _d(Object v) => v is double ? v : (v as BigInt).toDouble();

  BigInt _dToBigInt(double d) {
    if (!d.isFinite) throw UndefinedIntegerOperation('non-finite value');
    return BigInt.from(d.truncateToDouble());
  }

  int _toShiftInt(BigInt amount) =>
      amount > BigInt.from(0x7FFFFFFF) ? 0x7FFFFFFF : amount.toInt();

  /// Mirrors `JSNumber.~/` in dart2js: a fast int32 path, otherwise truncation
  /// toward zero of the double quotient.
  ///
  /// The fast path is taken only when the dividend is in int32 range *and* the
  /// divisor is outside [-1, 1] — the dart2js source reads
  /// `other >= 1 || other < -1`, so division by exactly -1 deliberately falls
  /// through to the slow path.
  double _jsTdiv(double a, double b) {
    if (b == 0) throw UndefinedIntegerOperation('division by zero');
    final quotient = a / b;
    if (_isInt32D(a) && (b >= 1 || b < -1)) {
      // `(a / b) | 0` in JS: ToInt32 of the (already truncated) quotient.
      return toInt32(BigInt.from(quotient.truncate())).toDouble();
    }
    if (!quotient.isFinite) return quotient;
    return quotient.truncateToDouble();
  }

  /// Mirrors `JSNumber.%` (Euclidean) in dart2js.
  double _jsMod(double a, double b) {
    if (b == 0) throw UndefinedIntegerOperation('modulo by zero');
    final result = a.remainder(b);
    if (result == 0) return 0.0;
    if (result > 0) return result;
    return b < 0 ? result - b : result + b;
  }

  bool _isInt32D(double d) =>
      d.isFinite && d >= -2147483648.0 && d <= 2147483647.0;
}

/// 64-bit `dart:typed_data` constructors that throw `UnsupportedError` when
/// compiled with dart2js (they work on the VM and on Wasm). Verified against
/// real builds: "Uint64List not supported on the web".
const Set<String> unsupported64BitTypedData = {
  'Int64List',
  'Uint64List',
};

/// `ByteData` accessors that throw on dart2js:
/// "Int64 accessor not supported by dart2js".
const Set<String> unsupported64BitByteDataAccessors = {
  'getInt64',
  'setInt64',
  'getUint64',
  'setUint64',
};

/// Convenience: render a full per-target sample for a constant expression.
Map<Target, String>? renderConstantSample(BigInt? vmValue, double? jsValue) {
  if (vmValue == null && jsValue == null) return null;
  return <Target, String>{
    Target.vm: vmValue?.toString() ?? '?',
    Target.wasm: vmValue?.toString() ?? '?',
    Target.js: jsValue == null
        ? '?'
        : (jsValue.isFinite && jsValue == jsValue.truncateToDouble())
              ? (jsValue.abs() <= 9007199254740992.0
                    ? BigInt.from(jsValue).toString()
                    : jsValue.toString())
              : jsValue.toString(),
  };
}
