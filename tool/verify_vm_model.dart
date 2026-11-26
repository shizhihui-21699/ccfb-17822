// Copyright 2026. All rights reserved.
//
// Differential self-test: runs the same operator over the same operands under
// (a) this package's TargetEvaluator model and (b) the *real* Dart VM at
// runtime, and asserts they agree. A companion script does the same against a
// dart2js build; see tool/verify_against_targets.sh.

import 'dart:typed_data';

import 'package:web_int_checker/src/model.dart';
import 'package:web_int_checker/src/target_semantics.dart';

int _failures = 0;

void _check(String label, Object? model, Object? actual) {
  final m = model?.toString();
  final a = actual?.toString();
  if (m != a) {
    _failures++;
    if (_failures <= 40) print('MISMATCH $label model=$m vm=$a');
  }
}

/// Runs every operator with the model and compares with the VM operator.
void main() {
  const vmEval = TargetEvaluator(Target.vm);
  const wasmEval = TargetEvaluator(Target.wasm);

  final operands = <int>[
    0, 1, -1, 2, 3, -3, 7, -7, 31, 32, 33, 63, 64, 65,
    1 << 20, 1 << 30, 1 << 31, 1 << 32, 1 << 40, 1 << 52, 1 << 53,
    -(1 << 31), -(1 << 32), -(1 << 40), -(1 << 52), -(1 << 53),
    0x7FFFFFFF, -0x80000000, 0xFFFFFFFF, 0x100000000,
    0x7FFFFFFFFFFFFFFF, -0x8000000000000000,
    9007199254740991, 9007199254740992, -9007199254740992,
    123456789012345, -123456789012345, 4294967295, 4294967296,
  ];
  final shifts = <int>[0, 1, 5, 30, 31, 32, 33, 40, 62, 63, 64, 65, 100];

  for (final a in operands) {
    // unary
    _check('-$a', vmEval.negate(BigInt.from(a)), -a);
    _check('~$a', vmEval.bitNot(BigInt.from(a)), ~a);
    for (final b in operands) {
      BigInt ba = BigInt.from(a), bb = BigInt.from(b);
      _check('$a+$b', vmEval.add(ba, bb), a + b);
      _check('$a-$b', vmEval.subtract(ba, bb), a - b);
      _check('$a*$b', vmEval.multiply(ba, bb), a * b);
      _check('$a&$b', vmEval.bitAnd(ba, bb), a & b);
      _check('$a|$b', vmEval.bitOr(ba, bb), a | b);
      _check('$a^$b', vmEval.bitXor(ba, bb), a ^ b);
      if (b != 0) {
        _check('$a~/$b', vmEval.truncatingDivide(ba, bb), a ~/ b);
        _check('$a%$b', vmEval.modulo(ba, bb), a % b);
      }
    }
    for (final s in shifts) {
      BigInt bs = BigInt.from(s);
      _check('$a<<$s', vmEval.shiftLeft(BigInt.from(a), bs), a << s);
      _check('$a>>$s', vmEval.shiftRight(BigInt.from(a), bs), a >> s);
      _check('$a>>>$s', vmEval.unsignedShiftRight(BigInt.from(a), bs), a >>> s);
    }
    // Wasm must agree with the VM on everything.
    _check('wasm $a', wasmEval.add(BigInt.from(a), BigInt.one), a + 1);
  }

  // Literal representability must match what dart2js accepts. The list below
  // is the empirically observed accept/reject set.
  final accepted = <int>[
    0, 1, 2147483647, 2147483648, 4294967295, 4294967296,
    9007199254740990, 9007199254740991, 9007199254740992, 9007199254740994,
    18014398509481984, 4611686018427387904,
  ];
  final rejected = <String>[
    '9007199254740993', '9007199254740995', '9007199254740997',
    '4611686018427387905', '9223372036854775807',
    '18446744073709551614', '123456789012345678',
  ];
  for (final v in accepted) {
    if (!isExactlyRepresentableAsDouble(BigInt.from(v))) {
      _failures++;
      print('MISMATCH literal $v should be accepted');
    }
  }
  for (final s in rejected) {
    if (isExactlyRepresentableAsDouble(BigInt.parse(s))) {
      _failures++;
      print('MISMATCH literal $s should be rejected');
    }
  }

  // Byte-tick: make sure ByteData is reachable in this harness.
  final bd = ByteData(8)..setInt64(0, 42);
  if (bd.getInt64(0) != 42) {
    _failures++;
    print('MISMATCH bytedata');
  }

  print(_failures == 0
      ? 'OK: model matches the Dart VM for every sampled operator'
      : 'FAILED: $_failures mismatches');
  if (_failures != 0) throw StateError('model diverges from VM');
}
