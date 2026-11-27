import 'dart:convert';
void main() {
  // collision: 2^53+1 vs 2^53+3 round to the same double
  var x = jsonDecode('9007199254740995');
  var y = jsonDecode('9007199254740997');
  print('C1 json collision x==y: ${x == y}');
  var m = <int, String>{};
  m[x as int] = 'a';
  m[y as int] = 'b';
  print('C2 map size: ${m.length}');
  // The casts are intentional: they mark where a JSON number crosses into
  // the int world (the exact boundary WEB_INT_005 reports on).
  // ignore: unnecessary_cast
  var set = <int>{x as int, y as int};
  print('C3 set size: ${set.length}');
  // shift masking on JS
  print('S1 1<<(32)   = ${1 << 32}');
  print('S2 1<<(33)   = ${1 << 33}');
  print('S3 1<<(64)   = ${1 << 64}');
  print('S4 1<<(65)   = ${1 << 65}');
  print('S5 (-1)>>0   = ${(-1) >> 0}');
  print('S6 (-1)>>32  = ${(-1) >> 32}');
  print('S7 1 >>> 32  = ${1 >>> 32}');
  print('S8 255 & (1<<40) = ${255 & (1 << 40)}');
  // int overflow wrap VM vs JS
  var max = int.parse('9223372036854775807');
  print('O1 max+1 = ${max + 1}');
  print('O2 max*2 = ${max * 2}');
}
