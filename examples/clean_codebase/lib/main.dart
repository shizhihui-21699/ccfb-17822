import 'models/item.dart';
import 'src/cart.dart';
import 'src/formatting.dart';
import 'src/pagination.dart';

void main() {
  final cart = Cart();
  for (var i = 0; i < 5; i++) {
    cart.add(CartItem(id: i, priceCents: 1999 * (i + 1), quantity: i + 1));
  }
  print(formatYuan(cart.totalCents));
  print(formatYuan(cart.totalCents - 500));
  for (final page in pageNumbers(total: 137, perPage: 20)) {
    print('page $page');
  }
}
