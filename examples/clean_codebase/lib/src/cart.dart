import '../models/item.dart';

class Cart {
  final List<CartItem> _items = <CartItem>[];

  void add(CartItem item) => _items.add(item);

  void removeAt(int index) {
    if (index >= 0 && index < _items.length) _items.removeAt(index);
  }

  int get totalCents {
    var sum = 0;
    for (final item in _items) {
      sum += item.lineTotalCents;
    }
    return sum;
  }

  int get itemCount => _items.length;

  bool get isEmpty => _items.isEmpty;

  int get totalPoints {
    var points = 0;
    for (final item in _items) {
      points += item.pointsEarned;
    }
    return points;
  }

  /// Clamp a requested quantity into the allowed range.
  int clampQuantity(int requested, {int max = 99}) {
    return requested.clamp(1, max);
  }
}
