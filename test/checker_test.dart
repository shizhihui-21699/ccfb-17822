// Copyright 2026. All rights reserved.
//
// Behavioural tests for the checker: what it must find, and — just as
// importantly — what it must stay silent about.

import 'package:test/test.dart';
import 'package:web_int_checker/src/model.dart';

import 'harness.dart';

void main() {
  group('oversized literals', () {
    test('reports a literal dart2js cannot represent', () async {
      final findings = await analyzeSource('''
const int seed = 0xcbf29ce484222325;
void main() => print(seed);
''');
      expect(findings, hasLength(1));
      expect(findings.single.code, FindingCode.literalNotRepresentable);
      expect(findings.single.severity, Severity.error);
      expect(findings.single.line, 1);
    });

    test('does not report representable literals', () async {
      final findings = await analyzeSource('''
const int mask = 0x7FFFFFFF;
const int big = 9007199254740992; // 2^53, exactly representable
const int shift = 1 << 30;
void main() => print(mask + big + shift);
''');
      expect(findings, isEmpty);
    });

    test('reports a constant expression that folds differently', () async {
      final findings = await analyzeSource('''
const int bad = 9007199254740992 + 1;
void main() => print(bad);
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.constantFoldsDifferently),
      );
    });

    test('reports 1 << 40 as a differing constant', () async {
      final findings = await analyzeSource('''
const int window = 1 << 40;
void main() => print(window);
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.constantFoldsDifferently),
      );
    });
  });

  group('attacker-controlled input', () {
    test('reports a checksum over a JSON id', () async {
      final findings = await analyzeSource('''
import 'dart:convert';

class Order {
  final int id;
  Order(this.id);
  factory Order.fromJson(Map<String, dynamic> json) =>
      Order(json['id'] as int);
}

int checksum(int orderId) {
  var h = orderId;
  h = (h << 5) - h;
  return h & 0x7FFFFFFF;
}

void main() {
  final order = Order.fromJson(jsonDecode('{}') as Map<String, dynamic>);
  print(checksum(order.id));
}
''');
      final untrusted = findings
          .where((f) => f.severity == Severity.error)
          .map((f) => f.code)
          .toSet();
      expect(untrusted, contains(FindingCode.untrustedMagnitude));
    });

    test('reports int.parse flowing into arithmetic', () async {
      final findings = await analyzeSource('''
int points(String raw) {
  final value = int.parse(raw);
  return value * 1000;
}

void main() => print(points('12'));
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.untrustedMagnitude),
      );
    });

    test('reports an int map key that receives an untrusted id', () async {
      final findings = await analyzeSource('''
final Map<int, String> seen = <int, String>{};

void remember(int id, String value) {
  seen[id] = value;
}

void handle(String raw) => remember(int.parse(raw), 'x');
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.integerKeyCollision),
      );
    });
  });

  group('hash codes', () {
    test('reports int.hashCode', () async {
      final findings = await analyzeSource('''
void main() => print(42.hashCode);
''');
      expect(findings.map((f) => f.code), contains(FindingCode.hashCodeNotPortable));
    });

    test('reports Object.hash', () async {
      final findings = await analyzeSource('''
void main() => print(Object.hash(1, 2));
''');
      expect(findings.map((f) => f.code), contains(FindingCode.hashCodeNotPortable));
    });
  });

  group('genuinely wide, trusted code', () {
    test('reports a constant shift beyond 31 bits', () async {
      final findings = await analyzeSource('''
int widen(int x) => x << 40;
void main() => print(widen(1));
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.shiftTruncatesOnWeb),
      );
    });

    test('reports a constant bit mask outside int32', () async {
      final findings = await analyzeSource('''
int highBit(int x) => x & 0x100000000;
void main() => print(highBit(1));
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.bitwiseTruncatesOnWeb),
      );
    });
  });

  group('precision: ordinary code produces no findings', () {
    test('money arithmetic and formatting', () async {
      final findings = await analyzeSource('''
String formatYuan(int cents) {
  final sign = cents < 0 ? '-' : '';
  final abs = cents.abs();
  final yuan = abs ~/ 100;
  final fen = abs % 100;
  return '\$sign\$yuan.\${fen.toString().padLeft(2, '0')}';
}

int lineTotal(int priceCents, int quantity) => priceCents * quantity;

void main() => print(formatYuan(lineTotal(1999, 3)));
''');
      expect(findings, isEmpty);
    });

    test('feature bit flags', () async {
      final findings = await analyzeSource('''
const int featureA = 1 << 0;
const int featureB = 1 << 1;

bool isEnabled(int flags, int feature) => (flags & feature) != 0;
int enable(int flags, int feature) => flags | feature;
int disable(int flags, int feature) => flags & ~feature;

void main() {
  final flags = enable(0, featureA);
  print(isEnabled(flags, featureB));
  print(disable(flags, featureA));
}
''');
      expect(findings, isEmpty);
    });

    test('pagination and loop counters', () async {
      final findings = await analyzeSource('''
Iterable<int> pages({required int total, required int perPage}) sync* {
  if (perPage <= 0) return;
  final count = (total + perPage - 1) ~/ perPage;
  for (var page = 0; page < count; page++) {
    yield page;
  }
}

int offsetFor(int page, int perPage) => page * perPage;

void main() => print(pages(total: 137, perPage: 20).toList());
''');
      expect(findings, isEmpty);
    });

    test('small bounded shifts', () async {
      final findings = await analyzeSource('''
int encode(int value) => (value & 0xFF) << 8;
int decode(int encoded) => (encoded >> 8) & 0xFF;
void main() => print(decode(encode(200)));
''');
      expect(findings, isEmpty);
    });
  });

  group('named arguments and equality', () {
    test('taint follows a named constructor argument to its field', () async {
      final findings = await analyzeSource('''
import 'dart:convert';

class Summary {
  const Summary({required this.orderId, required this.count});
  final int orderId;
  final int count;
}

Summary parse(String body) {
  final json = jsonDecode(body) as Map<String, dynamic>;
  return Summary(orderId: json['id'] as int, count: json['n'] as int);
}

int ratio(Summary s) => s.orderId ~/ s.count;

void main() => print(ratio(parse('{}')));
''');
      expect(
        findings.map((f) => f.code),
        contains(FindingCode.untrustedMagnitude),
      );
    });

    test('comparing a wide value against zero is not reported', () async {
      final findings = await analyzeSource('''
int avg(int total, int count) {
  if (count == 0) return 0;
  return total ~/ count;
}

void main() => print(avg(10, 3));
''');
      expect(findings, isEmpty);
    });
  });

  group('fixes', () {
    test('Int64 and BigInt arithmetic is not reported', () async {
      // The recommended fix must itself be clean, or the advice is useless.
      final findings = await analyzeSources({
        'lib/main.dart': '''
import 'package:fixnum/fixnum.dart';

Int64 checksum(Int64 orderId, Int64 points) {
  var h = orderId;
  h = (h << 5) - h + points;
  return h & Int64.parseInt('9223372036854775807');
}

BigInt widen(BigInt x) => x * BigInt.two;

void main() => print(checksum(Int64.one, Int64.two));
''',
        'pubspec.yaml': '''
name: fixture
environment:
  sdk: ^3.9.0
dependencies:
  fixnum: ^1.1.0
''',
      });
      // `Int64.parseInt` is not an int.parse; `Int64(...)` values are portable.
      expect(
        findings.where((f) =>
            f.severity == Severity.error &&
            f.code == FindingCode.untrustedMagnitude),
        isEmpty,
      );
    });
  });
}
