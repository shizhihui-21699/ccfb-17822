import 'dart:convert';

/// A very ordinary mobile+web client. The only cross-platform hazard is the
/// order id, which is wide on the server side.
class ApiClient {
  final String baseUrl;
  const ApiClient(this.baseUrl);

  OrderSummary parseOrder(String body) {
    final json = jsonDecode(body) as Map<String, dynamic>;
    return OrderSummary(
      orderId: json['orderId'] as int,
      itemCount: json['itemCount'] as int,
      totalCents: json['totalCents'] as int,
    );
  }
}

class OrderSummary {
  const OrderSummary({
    required this.orderId,
    required this.itemCount,
    required this.totalCents,
  });

  final int orderId;
  final int itemCount;
  final int totalCents;

  String get displayTotal => (totalCents / 100).toStringAsFixed(2);
  int get avgCents => itemCount == 0 ? 0 : totalCents ~/ itemCount;
}
