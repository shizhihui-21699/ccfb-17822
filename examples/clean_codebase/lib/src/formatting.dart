/// Money formatting: cents to a human string. All arithmetic here is bounded
/// by the number of digits displayed, so it stays far inside the safe range.
String formatYuan(int cents) {
  final sign = cents < 0 ? '-' : '';
  final abs = cents.abs();
  final yuan = abs ~/ 100;
  final fen = abs % 100;
  return '$sign$yuan.${fen.toString().padLeft(2, '0')}';
}

String formatPercent(int numerator, int denominator) {
  if (denominator == 0) return '0%';
  final basisPoints = (numerator * 10000) ~/ denominator;
  return '${basisPoints / 100}%';
}
