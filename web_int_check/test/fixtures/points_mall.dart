// Fixture: shared business code of a points mall, compiled to both mobile
// and web. Vulnerable patterns are annotated with `VULN`, safe patterns
// with `SAFE`. The test suite asserts the exact rule ids fired per line.
library;

import 'dart:convert';

/// Annotation understood by the checker (name-based, no package needed).
class webSafeInt {
  const webSafeInt();
}

class webUnsafeInt {
  const webUnsafeInt();
}

// ---------------------------------------------------------------- VULN 001

// dart2js refuses to build this file because of the literal; the checker
// must flag it even without running a web compile.
const int legacyOrderEpoch = 9007199254740993; // VULN: WEB_INT_001

// ------------------------------------------------------------------ SAFE

const int pointsPerYuan = 100; // SAFE: small literal, no finding
const int flagMask = 0xFF; // SAFE: 8-bit mask

int discountedPrice(int priceCents, int couponCents) {
  // SAFE: ordinary small-money arithmetic must stay silent.
  final pay = priceCents - couponCents;
  return pay < 0 ? 0 : pay;
}

int loyaltyTier(int totalPoints) {
  // SAFE: small comparisons and arithmetic.
  if (totalPoints < 1000) return 1;
  if (totalPoints < 10000) return 2;
  return 3;
}

int parseSmallQuantity(String raw) {
  // SAFE: constant-string parse of a small value is fully knowable.
  return int.parse('42');
}

double moneyWithTax(double amount) {
  // SAFE: double arithmetic has identical IEEE semantics on all targets.
  return amount * 1.06 + 0.5;
}

int permissionFlags(int role) {
  // `& 0xFF` is provably platform-independent (low-8-bit masking); the `|`
  // reports WEB_INT_009 only because `role` itself is an unbounded parameter.
  return (role & flagMask) | (1 << 3); // VULN(soft): WEB_INT_009
}

// ---------------------------------------------------------------- VULN 005

class OrderPayload {
  final int orderId;
  final int points;
  OrderPayload(this.orderId, this.points);

  static OrderPayload fromJson(String body) {
    final data = jsonDecode(body) as Map<String, dynamic>;
    final id = data['orderId'] as int; // VULN: WEB_INT_005
    final pts = data['points'] as int; // VULN: WEB_INT_005
    return OrderPayload(id, pts);
  }
}

// ---------------------------------------------------------------- VULN 002

/// Tamper-proof checksum shared by client and server.
int orderChecksum(int orderId, int points, int salt) {
  // VULN: bitwise on unbounded parameter ints -> 002 (and 009).
  var mix = orderId ^ (points << 7); // VULN: WEB_INT_002 + WEB_INT_003
  mix = (mix + salt) & 0x7fffffff; // VULN: WEB_INT_002
  return mix;
}

int checksumFromPayload(String body) {
  final data = jsonDecode(body) as Map<String, dynamic>;
  final id = data['orderId'] as int; // VULN 005
  final pts = data['points'] as int; // VULN 005
  final mixed = id ^ (pts << 13); // VULN 002/003 on tainted values
  return ~mixed; // VULN 002: ~ differs (signed 32-bit on JS)
}

// ---------------------------------------------------------------- VULN 003

int buildBitMask(int bitIndex) {
  return 1 << bitIndex; // VULN: count unbounded -> WEB_INT_003/009
}

int rotateLeft(int value, int n) {
  final mod = n % 64; // VM/Wasm shift width; JS silently uses mod 32
  return value << mod; // VULN: WEB_INT_003
}

// ---------------------------------------------------------------- VULN 004

int redeemCost(int points, int multiplier) {
  // Unbounded product: only a soft info (strict mode), not a hard 004.
  return points * multiplier;
}

/// Proven overflow: both operands are known constants whose product leaves
/// the 2^53 safe range, so the divergence is statically certain (hard 004).
int provenOverflowProduct() {
  const bigBase = 100000000; // 10^8
  return bigBase * bigBase * bigBase; // 10^24 > 2^53 -> WEB_INT_004
}

int provenOverflowAdd() {
  const nearLimit = 9007199254740000; // below 2^53 itself...
  return nearLimit + 100000; // ...but the sum crosses it -> WEB_INT_004
}

int accumulatePoints(List<int> deltas) {
  var total = 0;
  for (final d in deltas) {
    total += d; // loop accumulation of parameter-sourced values
  }
  return total;
}

// ---------------------------------------------------------------- VULN 006

int parseExternalOrderId(String wire) {
  return int.parse(wire); // VULN: WEB_INT_006
}

int? tryParseExternal(String wire) => int.tryParse(wire); // VULN: WEB_INT_006

// ---------------------------------------------------------------- VULN 007

int normalizeAmount(num amount) {
  return amount.toInt(); // VULN: WEB_INT_007
}

// ---------------------------------------------------------------- VULN 008

class IdempotencyStore {
  final Map<int, String> _processed = {};

  bool markProcessed(int orderId, String token) {
    if (_processed.containsKey(orderId)) return true; // VULN: WEB_INT_008
    _processed[orderId] = token; // VULN: WEB_INT_008 (int map key write)
    return false;
  }

  bool sameOrder(int a, int b) => a == b; // VULN(soft): WEB_INT_009
}

int idHash(int orderId) => orderId.hashCode; // VULN(soft): WEB_INT_009

// ---------------------------------------------------------- SAFE (annotated)

int safeChecksum(@webSafeInt() int orderId, @webSafeInt() int points) {
  // SAFE: boundary contract says values fit the JS safe range.
  return (orderId ^ (points << 7)) & 0x7fffffff;
}

// -------------------------------------------------------- VULN (annotated)

int explicitUnsafe(@webUnsafeInt() int externalId) {
  // The annotated source is tainted; an unmasked bitwise op is a hard 002.
  return externalId ^ 0x12345678; // VULN: WEB_INT_002
}

// ------------------------------------------------------------------ SAFE

enum Status { pending, paid, refunded }

Status statusFromCode(int code) {
  // SAFE: tiny switch values.
  switch (code) {
    case 0:
      return Status.pending;
    case 1:
      return Status.paid;
    default:
      return Status.refunded;
  }
}

int indexOfTab(String name, List<String> tabs) {
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i] == name) return i; // SAFE: loop index, small int
  }
  return -1;
}

int sumCartQuantities(List<int> quantities) {
  var sum = 0;
  for (var i = 0; i < quantities.length; i++) {
    sum += quantities[i];
  }
  return sum;
}
