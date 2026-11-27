import 'package:test/test.dart';
import 'package:web_int_check/web_int_check.dart';

import 'src/rule_expectations.dart' as expectations;

void main() {
  final mallPath = expectations.mallFixturePath;
  final cleanPath = expectations.cleanFixturePath;

  group('vulnerable points-mall fixture', () {
    late List<Finding> findings;

    setUpAll(() async {
      findings = await runWebIntCheck([mallPath]);
    });

    test('detects every rule family at least once', () {
      final ids = findings.map((f) => f.ruleId).toSet();
      for (final rule in CheckRule.all) {
        expect(ids, contains(rule.id),
            reason: '${rule.id} (${rule.title}) should fire');
      }
    });

    test('matches the per-line rule expectations exactly', () {
      final actual = <int, Set<String>>{};
      for (final f in findings) {
        actual.putIfAbsent(f.line, () => <String>{}).add(f.ruleId);
      }
      for (final entry in expectations.mallExpectations.entries) {
        expect(actual[entry.key], equals(entry.value),
            reason: 'line ${entry.key}');
      }
    });

    test('does not report any line that has no expectation', () {
      final expectedLines = expectations.mallExpectations.keys.toSet();
      final extra = findings
          .map((f) => f.line)
          .where((line) => !expectedLines.contains(line))
          .toSet();
      expect(extra, isEmpty, reason: 'unexpected findings on lines: $extra');
    });

    test('the over-2^53 literal is a build-breaking error', () {
      final literal = findings
          .where((f) => f.ruleId == CheckRule.literalUnrepresentable.id)
          .toList();
      expect(literal, hasLength(1));
      expect(literal.single.severity, CheckSeverity.error);
      expect(literal.single.line, 21);
    });

    test('JSON taint is tracked through as-casts and indexing', () {
      final json = findings
          .where((f) => f.ruleId == CheckRule.jsonTaint.id)
          .map((f) => f.line)
          .toSet();
      expect(json, containsAll(<int>{66, 67, 84, 85}));
    });

    test('every finding carries an actionable remediation', () {
      for (final f in findings) {
        expect(f.remediation.trim(), isNotEmpty,
            reason: '${f.ruleId} needs remediation text');
        expect(f.remediation, contains(RegExp(r'Int64|BigInt|2\^53|32 bit|string')),
            reason: '${f.ruleId} remediation should mention the fix shape');
      }
    });
  });

  group('clean fixture (false-positive control)', () {
    test('produces no findings at all', () async {
      final findings = await runWebIntCheck([cleanPath]);
      expect(findings, isEmpty,
          reason: 'ordinary small-value/masked code must stay silent:\n'
              '${findings.map((f) => '${f.line} ${f.ruleId}').join('\n')}');
    });

    test('double-only arithmetic never triggers integer rules', () async {
      final findings = await runWebIntCheck([cleanPath]);
      expect(
        findings.where((f) => f.message.contains('taxed')),
        isEmpty,
      );
    });
  });

  group('severity and exit-code contract', () {
    test('hard rules default to warning/error, never info', () async {
      final findings = await runWebIntCheck([mallPath]);
      const hard = {
        'WEB_INT_001',
        'WEB_INT_002',
        'WEB_INT_003',
        'WEB_INT_004',
        'WEB_INT_005',
        'WEB_INT_006',
        'WEB_INT_007',
        'WEB_INT_008',
      };
      for (final f in findings.where((f) => hard.contains(f.ruleId))) {
        expect(f.severity == CheckSeverity.warning ||
            f.severity == CheckSeverity.error, isTrue,
            reason: '${f.ruleId} must not be info');
      }
    });

    test('rule severity can be downgraded to ignore via config', () async {
      final config = CheckerConfig(severityOverrides: const {
        'WEB_INT_009': CheckSeverity.ignore,
      });
      final findings =
          await runWebIntCheck([mallPath], config: config);
      expect(findings.any((f) => f.ruleId == 'WEB_INT_009'), isFalse);
    });

    test('strict arithmetic config does not break safe-contract silence',
        () async {
      final config = CheckerConfig(strictArithmetic: true);
      final findings =
          await runWebIntCheck([cleanPath], config: config);
      // The clean fixture's arithmetic sits behind @webSafeInt contracts,
      // so strict mode must still leave it silent (strict only surfaces
      // *non-contracted* unbounded arithmetic).
      expect(findings, isEmpty);
    });

    test('strict arithmetic adds infos on non-contracted parameter math',
        () async {
      final relaxed = await runWebIntCheck([mallPath]);
      final strict = await runWebIntCheck([mallPath],
          config: CheckerConfig(strictArithmetic: true));
      expect(strict.length, greaterThan(relaxed.length));
      expect(
        strict.any((f) =>
            f.ruleId == 'WEB_INT_009' &&
            f.message.contains('strict mode')),
        isTrue,
      );
    });
  });

  group('JSON output shape', () {
    test('findings serialize to stable JSON fields', () async {
      final findings = await runWebIntCheck([mallPath]);
      for (final json in findings.map((f) => f.toJson())) {
        expect(json.keys,
            containsAll(['rule', 'severity', 'message', 'file', 'line',
                'column', 'remediation']));
        expect(json['line'], isA<int>());
        expect(json['column'], isA<int>());
      }
    });
  });
}
