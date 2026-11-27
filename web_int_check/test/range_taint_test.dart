import 'package:test/test.dart';
import 'package:web_int_check/src/range.dart';
import 'package:web_int_check/src/semantics.dart';
import 'package:web_int_check/src/taint.dart';

void main() {
  group('IntRange', () {
    test('exact value round-trips', () {
      final r = IntRange.exact(BigInt.from(42));
      expect(r.isExact, isTrue);
      expect(r.exactValue, BigInt.from(42));
      expect(r.canLeaveSafeRange(), isFalse);
    });

    test('flags values beyond the JS safe integer', () {
      final safe = IntRange.exact(BigInt.from(maxSafeInteger));
      final unsafe = IntRange.exact(BigInt.from(firstUnsafeInteger + 1));
      expect(safe.canLeaveSafeRange(), isFalse);
      expect(unsafe.canLeaveSafeRange(), isTrue);
    });

    test('union widens both ends', () {
      final a = IntRange.exact(BigInt.from(1));
      final b = IntRange.exact(BigInt.from(10));
      final u = IntRange.union(a, b)!;
      expect(u.lo, BigInt.one);
      expect(u.hi, BigInt.from(10));
    });
  });

  group('RangeOps transfer functions', () {
    IntRange r(int lo, int hi) =>
        IntRange.bounded(BigInt.from(lo), BigInt.from(hi));

    test('addition bounds from corners', () {
      final out = RangeOps.binary('+', r(1, 10), r(2, 5))!;
      expect(out.lo, BigInt.from(3));
      expect(out.hi, BigInt.from(15));
    });

    test('multiplication keeps full (non-53-bit) precision', () {
      final out = RangeOps.binary('*', r(100000000, 100000000),
          r(100000000, 100000000))!;
      expect(out.exactValue, BigInt.parse('10000000000000000'));
      expect(out.canLeaveSafeRange(), isTrue);
    });

    test('AND with a small mask bounds the result to that mask', () {
      final out = RangeOps.binary('&', IntRange.unknown, r(0xFF, 0xFF));
      // Unbounded operand -> conservative unknown (not null); the
      // platform-independence guarantee is established in the rule layer
      // using the exact mask constant.
      expect(out, IntRange.unknown);
      final bounded = RangeOps.binary('&', r(0, 1000000), r(0xFF, 0xFF))!;
      expect(bounded.hi, BigInt.from(0xFF));
    });

    test('left shift widens the range', () {
      final out = RangeOps.binary('<<', r(1, 1), r(32, 32))!;
      expect(out.exactValue, BigInt.from(4294967296));
      expect(out.canLeaveSafeRange(), isFalse);
    });

    test('modulo is bounded by divisor magnitude', () {
      final out = RangeOps.binary('%', r(0, 1 << 40), r(7, 7))!;
      expect(out.lo, BigInt.zero);
      expect(out.hi, BigInt.from(6));
    });

    test('unary complement', () {
      final out = RangeOps.unary('~', r(0, 0))!;
      expect(out.exactValue, BigInt.from(-1));
    });
  });

  group('IntState taint', () {
    test('merge preserves taint from either side', () {
      final a = IntState(IntRange.unknown, const {TaintSource.json});
      final b = IntState.unboundedInt;
      final m = IntState.merge(a, b);
      expect(m.taints, contains(TaintSource.json));
    });

    test('safe contract survives a merge with clean internal state', () {
      final safe =
          IntState(IntRange.unknown, const {}, safe: true);
      final clean = IntState.unboundedInt;
      expect(IntState.merge(safe, clean).safe, isTrue);
      expect(IntState.merge(clean, safe).safe, isTrue);
    });

    test('taint always defeats the safe contract', () {
      final safe =
          IntState(IntRange.unknown, const {}, safe: true);
      final tainted =
          IntState(IntRange.unknown, const {TaintSource.json});
      expect(IntState.merge(safe, tainted).safe, isFalse);
      expect(IntState.merge(safe, tainted).isTainted, isTrue);
    });
  });

  group('semantics constants match the empirical probe', () {
    test('JS cliff values', () {
      expect(maxSafeInteger, 9007199254740991);
      expect(jsUint32Mask, 0xFFFFFFFF);
      expect(jsInt32Min, -2147483648);
      expect(jsShiftModulo, 32);
      expect(nativeShiftModulo, 64);
    });
  });
}
