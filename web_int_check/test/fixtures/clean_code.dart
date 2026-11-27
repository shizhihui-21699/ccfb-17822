// A file that must produce ZERO findings: ordinary small-value business
// code, double math, loop indices and provably-masked bit operations.
library;

const int _mask31 = 0x7fffffff;

/// Boundary contract: values handed in are guaranteed within the JS safe
/// integer range and (for hashing) within 32 bits.
class webSafeInt {
  const webSafeInt();
}

int cartTotal(List<int> pricesCents) {
  var total = 0;
  for (var i = 0; i < pricesCents.length; i++) {
    total += pricesCents[i];
  }
  return total;
}

int applyCoupon(@webSafeInt() int priceCents, @webSafeInt() int couponCents) =>
    priceCents - couponCents;

double taxed(double price) => price * 1.06;

int stableHash31(@webSafeInt() int a, @webSafeInt() int b) {
  // Both masking forms are provably identical on VM, Wasm and JS.
  final mix = (a ^ (b << 5)) & _mask31;
  return mix & 0x7fffffff;
}

int smallShifts(@webSafeInt() int x) {
  // Constant count < 32, constant small body.
  final a = 1 << 10;
  final b = x & 0xffff;
  return a | b;
}

int parseKnown() => int.parse('12345');

Status parseStatus(int code) => switch (code) {
      0 => Status.pending,
      1 => Status.paid,
      _ => Status.refunded,
    };

enum Status { pending, paid, refunded }
