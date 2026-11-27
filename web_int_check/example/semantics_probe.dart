// Semantics probe: same Dart on VM / dart2js / dart2wasm (no >2^53 literals)
import 'dart:convert';

String show(Object? v) {
  if (v is double) return 'double($v)';
  return '${v.runtimeType}($v)';
}

void main() {
  var big = int.parse('9007199254740993'); // 2^53+1 at runtime
  print('1 runtime 2^53+1: ${show(big)}');

  var a = 900719925474099; // 2^53/10-ish, representable
  print('2 mul x10: ${show(a * 10)}');
  print('3 add:     ${show(9007199254740990 + 5)}');

  print('4 and:  ${show(big & 0xFFFFFFFF)}');
  print('5 or:   ${show(1 | (1 << 40))}');
  print('6 not:  ${show(~0)}');
  print('7 xor:  ${show(big ^ 0xFF)}');

  print('8 shl32:  ${show(1 << 32)}');
  print('9 shl63:  ${show(1 << 63)}');
  print('10 shl64: ${show(1 << 64)}');
  print('11 shr-1: ${show((-1) >> 1)}');
  print('12 shr32: ${show(0x100000000 >>> 8)}');

  int h = 900719925474099;
  print('13 hashmix: ${show((h ^ (h >>> 30)) & 0x3fffffff)}');

  var j = jsonDecode('{"orderId": 9007199254740993, "points": 12}');
  print('14 json id:    ${show(j['orderId'])}');
  print('15 json as int: ${show(j['orderId'] as int)}');
  print('16 json==parsed: ${j['orderId'] == big}');
  print('17 collision:  ${jsonDecode('9007199254740993') == jsonDecode('9007199254740995')}');
  print('18 parse:      ${show(int.parse('9007199254740993'))}');

  num n = 9007199254740993.0;
  print('19 num.toInt:  ${show(n.toInt())}');
  print('20 mod:        ${show(big % 7)}');

  var m = <int, String>{};
  m[jsonDecode('9007199254740993') as int] = 'a';
  m[jsonDecode('9007199254740995') as int] = 'b';
  print('21 map size (expect 2 VM): ${m.length}');

  print('22 abs: ${show((-big).abs())}');
}
