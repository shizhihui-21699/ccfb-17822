class CartItem {
  const CartItem({
    required this.id,
    required this.priceCents,
    required this.quantity,
  });

  final int id;
  final int priceCents;
  final int quantity;

  /// Line total. Bounded: prices and quantities come from a validated form.
  int get lineTotalCents => priceCents * quantity;

  int get pointsEarned => lineTotalCents ~/ 100;
}
