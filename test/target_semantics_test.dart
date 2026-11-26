// Copyright 2026. All rights reserved.
//
// Semantics-model tests. These pin down the exact per-target behaviour that the
// whole checker rests on, using values read straight out of real VM and
// dart2js builds. If the model and these expectations ever disagree, the tool
// would be lying about the web target, so they are the most important tests.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:web_int_checker/src/model.dart';
import 'package:web_int_checker/src/target_semantics.dart';

void main() {
  const vm = TargetEvaluator(Target.vm);
  const wasm = TargetEvaluator(Target.wasm);
  const js = TargetEvaluator(Target.js);

  group('VM/Wasm 64-bit semantics', () {
    test('shifts saturate at 64 bits', () {
      expect(vm.shiftLeft(BigInt.one, BigInt.from(40)), BigInt.from(1 << 40));
      expect(vm.shiftLeft(BigInt.one, BigInt.from(64)), BigInt.zero);
      expect(vm.shiftLeft(BigInt.one, BigInt.from(63)), bigMinInt64);
      expect(vm.shiftRight(BigInt.from(-1), BigInt.from(64)), -BigInt.one);
      expect(vm.unsignedShiftRight(BigInt.from(-1), BigInt.from(63)),
          BigInt.one);
    });

    test('arithmetic wraps at 64 bits', () {
      expect(vm.add(bigMaxInt64, BigInt.one), bigMinInt64);
      expect(vm.multiply(BigInt.from(1 << 62), BigInt.from(4)), BigInt.zero);
    });

    test('modulo is Euclidean', () {
      expect(vm.modulo(BigInt.from(-7), BigInt.from(3)), BigInt.two);
      expect(vm.modulo(BigInt.from(7), BigInt.from(-3)), BigInt.one);
      expect(vm.truncatingDivide(BigInt.from(-7), BigInt.from(2)),
          BigInt.from(-3));
    });

    test('Wasm is identical to the VM', () {
      for (final a in [0, 1, -1, 1 << 40, -(1 << 53), 0x7FFFFFFFFFFFFFFF]) {
        for (final b in [1, 3, 31, 64]) {
          expect(wasm.shiftLeft(BigInt.from(a), BigInt.from(b)),
              vm.shiftLeft(BigInt.from(a), BigInt.from(b)));
          expect(wasm.bitXor(BigInt.from(a), BigInt.from(b)),
              vm.bitXor(BigInt.from(a), BigInt.from(b)));
        }
      }
    });
  });

  group('JS semantics', () {
    test('bitwise operators are 32-bit and unsigned', () {
      // 1 << 40 == 0 on JS.
      expect(js.shiftLeft(BigInt.one, BigInt.from(40)), 0.0);
      // -1 & 0xFF == 255 on both, but -1 ^ 0xFF differs.
      expect(js.bitAnd(BigInt.from(-1), BigInt.from(0xFF)), 255.0);
      expect(js.bitXor(BigInt.from(-1), BigInt.from(0xFF)), 4294967040.0);
      expect(js.bitNot(BigInt.from(5)), 4294967290.0);
      // ~0 == 0xFFFFFFFF, not -1.
      expect(js.bitNot(BigInt.zero), 4294967295.0);
    });

    test('>> on a negative receiver is sign-filled then made unsigned', () {
      expect(js.shiftRight(BigInt.from(-5), BigInt.one), 4294967293.0);
      expect(js.shiftRight(BigInt.from(-1), BigInt.one), 4294967295.0);
    });

    test('arithmetic is double arithmetic above 2^53', () {
      final big = BigInt.parse('9007199254740993');
      expect(js.add(big, BigInt.zero), 9007199254740992.0);
      expect(js.multiply(BigInt.parse('9007199254740993'), BigInt.one),
          9007199254740992.0);
      // Exact arithmetic below 2^53.
      expect(js.add(BigInt.from(1 << 40), BigInt.one), 1099511627777.0);
    });

    test('integer division matches dart2js, including -2^31 / -1', () {
      expect(js.truncatingDivide(BigInt.from(-2147483648), BigInt.from(-1)),
          2147483648.0);
      expect(js.truncatingDivide(BigInt.from(-7), BigInt.from(2)), -3.0);
      expect(js.modulo(BigInt.from(-7), BigInt.from(3)), 2.0);
    });
  });

  group('literal representability', () {
    test('accepts values that round-trip through a double', () {
      for (final v in [
        0,
        1,
        2147483647,
        2147483648,
        4294967296,
        9007199254740991,
        9007199254740992,
        9007199254740994,
        18014398509481984,
      ]) {
        expect(isExactlyRepresentableAsDouble(BigInt.from(v)), isTrue,
            reason: '$v should be accepted');
      }
    });

    test('rejects the values dart2js rejects', () {
      for (final v in [
        '9007199254740993',
        '9007199254740995',
        '9223372036854775807',
        '4611686018427387905',
      ]) {
        expect(isExactlyRepresentableAsDouble(BigInt.parse(v)), isFalse,
            reason: '$v should be rejected');
      }
    });

    test('the FNV offset basis is not representable', () {
      expect(
        isExactlyRepresentableAsDouble(BigInt.parse('0xcbf29ce484222325')),
        isFalse,
      );
    });
  });

  group('64-bit helpers', () {
    test('toInt64 wraps', () {
      expect(toInt64(bigTwo63), bigMinInt64);
      expect(toInt64(bigTwo64 + BigInt.one), BigInt.one);
    });

    test('toInt32/toUint32', () {
      expect(toInt32(BigInt.from(4294967295)), BigInt.from(-1));
      expect(toUint32(BigInt.from(-1)), BigInt.from(4294967295));
    });
  });

  test('ByteData Int64 accessors are unsupported on dart2js', () {
    // Documented here as a fact the checker relies on for its typed-data rule.
    expect(unsupported64BitByteDataAccessors, contains('getInt64'));
    // On the VM they work.
    final data = ByteData(8)..setInt64(0, 42);
    expect(data.getInt64(0), 42);
  });
}
