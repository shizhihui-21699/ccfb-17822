// Copyright 2026. All rights reserved.
//
// Reproduction of the reported incident, in the shape it had in production:
// one shared business-logic library, compiled both for mobile (VM) and for the
// web (dart2js). Every annotated spot is what web_int_checker reports.
//
// Run the checker on this file:
//   dart run web_int_checker:main examples/incident_repro.dart

import 'dart:convert';

// ---------------------------------------------------------------------------
// Untrusted data enters here.
// ---------------------------------------------------------------------------

class OrderRequest {
  final int orderId;
  final int points;
  final String cartSignature;

  const OrderRequest(this.orderId, this.points, this.cartSignature);

  /// The hostile payload arrives as JSON; `orderId` is a 64-bit integer chosen
  /// by the client, so it can exceed 2^53.
  factory OrderRequest.fromJson(Map<String, dynamic> json) {
    return OrderRequest(
      json['orderId'] as int, // taint: jsonDecode result, attacker controlled
      json['points'] as int, // taint: same
      json['cartSignature'] as String,
    );
  }
}

// ---------------------------------------------------------------------------
// The shared checksum: this is the code whose result must match the server.
// ---------------------------------------------------------------------------

int computeOrderChecksum(int orderId, int points) {
  // The classic djb2-style mixing used by the service.
  var hash = orderId; // 64-bit on VM, double on JS
  hash = (hash << 5) - hash + points; // shift is 32-bit on JS
  hash = hash & 0x7FFFFFFF; // bitwise is 32-bit on JS
  return hash;
}

/// A second, FNV-like checksum that uses a 64-bit constant.
int computeSignature(int orderId, int points) {
  const prime = 1099511628211;
  var h = 0xcbf29ce484222325; // 64-bit literal: rejected by dart2js
  h = (h ^ orderId) * prime;
  h = h ^ points;
  return h;
}

// ---------------------------------------------------------------------------
// Idempotency: duplicate order detection keyed by the raw 64-bit id.
// ---------------------------------------------------------------------------

class IdempotencyStore {
  final Set<int> _seen = <int>{};
  final Map<int, String> _results = <int, String>{};

  /// On the web two distinct 64-bit ids above 2^53 can hash to the same double,
  /// so the second order is silently treated as a duplicate of the first.
  bool alreadyProcessed(int orderId) => _seen.contains(orderId);

  void remember(int orderId, String result) {
    _seen.add(orderId);
    _results[orderId] = result; // integer key: collides above 2^53
  }
}

// ---------------------------------------------------------------------------
// Points conversion: money -> points, then points -> money.
// ---------------------------------------------------------------------------

class PointsCalculator {
  final int pointsPerYuanCents;

  const PointsCalculator(this.pointsPerYuanCents);

  /// `cents` is the order amount in cents; it is bounded in practice, but the
  /// multiplication is done with a client-supplied multiplier in one path.
  int pointsFor(int cents, int multiplier) {
    return cents * multiplier; // can exceed 2^53
  }

  /// Ratio calculation that is then truncated.
  int yuanCentsFor(int points) {
    return points ~/ pointsPerYuanCents;
  }
}

// ---------------------------------------------------------------------------
// A "signature" built on hashCode — never stable across runtimes.
// ---------------------------------------------------------------------------

int weakSignature(int orderId, int points) {
  return 'order-$orderId'.hashCode ^ points.hashCode;
}

// ---------------------------------------------------------------------------
// Demonstration entry point.
// ---------------------------------------------------------------------------

void main() {
  // What a hostile client sends. Both are legal JSON integers, and both are
  // exactly representable on the VM but not on JS.
  const hostileJson = '{"orderId": 9007199254740993, '
      '"points": 9007199254740993, "cartSignature": "x"}';
  final request =
      OrderRequest.fromJson(jsonDecode(hostileJson) as Map<String, dynamic>);

  final checksum = computeOrderChecksum(request.orderId, request.points);
  final signature = computeSignature(request.orderId, request.points);
  final weak = weakSignature(request.orderId, request.points);

  final store = IdempotencyStore();
  store.remember(request.orderId, 'processed');
  final secondOrderSameId = request.orderId + 1; // 2^53 + 2 on the VM

  const calculator = PointsCalculator(100);
  final points = calculator.pointsFor(123456789, request.points);

  print('orderId   = ${request.orderId}');
  print('checksum  = $checksum');
  print('signature = $signature');
  print('weak      = $weak');
  print('duplicate = ${store.alreadyProcessed(secondOrderSameId)}');
  print('points    = $points');
  print('cents     = ${calculator.yuanCentsFor(points)}');
}
