import 'api_client.dart';
import 'widgets.dart';

void main() {
  const client = ApiClient('https://example.test');
  final order = client.parseOrder(
    '{"orderId": 9007199254740993, "itemCount": 3, "totalCents": 5997}',
  );
  print(order.displayTotal);
  print(order.avgCents);
  print(progressPercent(3, 10));
  print(itemIndexForOffset(480, 120));
  print(scrollExtent(20, 120));
}
