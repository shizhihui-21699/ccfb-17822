/// Checker rule catalog. Rule semantics are backed by the empirical
/// three-target comparison in `example/semantics_probe.dart`.
enum CheckSeverity { error, warning, info, ignore }

class CheckRule {
  final String id;
  final String title;
  final CheckSeverity defaultSeverity;

  const CheckRule(this.id, this.title, this.defaultSeverity);

  static const literalUnrepresentable = CheckRule(
    'WEB_INT_001',
    'Integer literal cannot be represented exactly in JavaScript',
    CheckSeverity.error,
  );

  static const bitwiseTruncated = CheckRule(
    'WEB_INT_002',
    'Bitwise operation is truncated to 32 bits on the JS target',
    CheckSeverity.warning,
  );

  static const shiftCountSemantics = CheckRule(
    'WEB_INT_003',
    'Shift count/result differs between JS (mod 32) and VM/Wasm (mod 64)',
    CheckSeverity.warning,
  );

  static const arithmeticRounded = CheckRule(
    'WEB_INT_004',
    'Integer arithmetic can leave the 2^53 safe range and rounds on JS',
    CheckSeverity.warning,
  );

  static const jsonTaint = CheckRule(
    'WEB_INT_005',
    'JSON-derived number is a rounded double on JS: collisions and identity drift',
    CheckSeverity.warning,
  );

  static const parseRounded = CheckRule(
    'WEB_INT_006',
    'Parsed integer is rounded on JS when its magnitude exceeds 2^53',
    CheckSeverity.warning,
  );

  static const numConversion = CheckRule(
    'WEB_INT_007',
    'num.toInt()/round() loses precision above 2^53 on JS',
    CheckSeverity.warning,
  );

  static const hashIdentity = CheckRule(
    'WEB_INT_008',
    'Integer used as hash/map key/equality can collide after JS rounding',
    CheckSeverity.warning,
  );

  static const unprovenParameter = CheckRule(
    'WEB_INT_009',
    'Unbounded int parameter used in web-sensitive operation (add @webSafeInt to silence)',
    CheckSeverity.info,
  );

  static List<CheckRule> get all => const [
        literalUnrepresentable,
        bitwiseTruncated,
        arithmeticRounded,
        shiftCountSemantics,
        jsonTaint,
        parseRounded,
        numConversion,
        hashIdentity,
        unprovenParameter,
      ];
}

/// Human-readable remediation text attached to each finding. The [detail]
/// string describes the concrete observed values/range.
class Remediation {
  static String int64OrBigInt(String what, {required bool needsArbitrary}) {
    if (needsArbitrary) {
      return 'Replace $what with BigInt (or parse the payload as a String and '
          'use BigInt.parse). BigInt is exact on every target; note that '
          'BigInt has no bitwise-shortcut operators and must be converted '
          'explicitly with toInt().';
    }
    return 'Replace $what with package:fixnum Int64 (e.g. Int64.parseInt / '
        'Int64(high, low)); Int64 keeps full 64-bit semantics on JS. Use '
        'BigInt instead if values may exceed 2^63-1.';
  }

  static const jsonAdvice =
      'Have the server send 64-bit identifiers as JSON strings and parse with '
      'Int64.parseInt/BigInt.parse, or validate the numeric range against '
      '2^53 before use. Reject (do not truncate) out-of-range values so an '
      'attacker cannot forge colliding ids.';

  static const hashAdvice =
      'Do not use raw JSON numbers as map keys/ids on the web build: hash the '
      'canonical string form, or carry the id as Int64/BigInt end to end.';

  static const bitwiseAdvice =
      'On JS all operands of & | ^ ~ are coerced to signed 32-bit values. '
      'Move the checksum/hash into Int64 (or BigInt) arithmetic, or mask the '
      'inputs to 32 bits explicitly on every target so the result is '
      'platform-independent by construction.';

  static const shiftAdvice =
      'JS masks the shift count with 31 (count mod 32) and shifts within a '
      '32-bit body; VM/Wasm use mod 64. Use Int64.shiftLeft/shiftRight, or '
      'assert the count is < 32 and the value fits 32 bits on all targets.';

  static const arithmeticAdvice =
      'Perform this calculation in Int64/BigInt, or range-check the inputs '
      '(and intermediate products) against 2^53 and fail closed. Keeping the '
      'checksum in 64-bit types on all three targets makes client/server '
      'signatures agree.';
}
