// Copyright 2026. All rights reserved.
//
// Corpus regression tests.
//
// The example trees under `examples/` encode the product requirements:
//
//  * `incident_repro`  - the reported attack; must be reported as errors.
//  * `clean_codebase`  - ordinary business/UI code; must produce nothing.
//  * `bigints`         - genuinely 64-bit code; must be reported.
//  * `mixed_app`       - a realistic client; exactly one real finding.
//
// If the checker ever starts crying wolf or goes quiet on the incident, one of
// these fails. That is the whole point of the file.

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:web_int_checker/src/model.dart';
import 'package:web_int_checker/src/report.dart';
import 'package:web_int_checker/src/runner.dart';

/// Locates the repository root by walking up until `pubspec.yaml` is found.
String get _repoRoot {
  var dir = Directory.current;
  while (true) {
    if (File(p.join(dir.path, 'pubspec.yaml')).existsSync() &&
        Directory(p.join(dir.path, 'examples')).existsSync()) {
      return dir.path;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) {
      throw StateError('could not find repository root from ${Directory.current}');
    }
    dir = parent;
  }
}

Future<List<LocatedFinding>> _check(String relative) =>
    runChecker(RunConfig(paths: [p.join(_repoRoot, relative)]));

void main() {
  group('incident reproduction', () {
    late List<LocatedFinding> findings;
    setUpAll(() async {
      findings = await _check('examples/incident_repro.dart');
    });

    test('reports the attacker-controlled checksum as an error', () {
      final errors = findings
          .where((f) => f.finding.severity == Severity.error)
          .toList();
      expect(errors, isNotEmpty);
      expect(
        errors.map((f) => f.finding.code),
        contains(FindingCode.untrustedMagnitude),
      );
    });

    test('reports the unrepresentable 64-bit literal', () {
      expect(
        findings.map((f) => f.finding.code),
        contains(FindingCode.literalNotRepresentable),
      );
    });

    test('reports the integer-keyed idempotency store', () {
      expect(
        findings.map((f) => f.finding.code),
        contains(FindingCode.integerKeyCollision),
      );
    });

    test('does not flag the 31-bit final mask as the problem', () {
      // The `& 0x7FFFFFFF` is fine on its own; the error must be attributed to
      // the checksum arithmetic, not to the mask constant.
      final maskFindings = findings.where(
        (f) => f.finding.snippet == 'hash & 0x7FFFFFFF',
      );
      expect(maskFindings.length, lessThanOrEqualTo(1));
    });

    test('every error carries a fix and a taint trace', () {
      for (final f in findings) {
        if (f.finding.severity != Severity.error) continue;
        expect(f.finding.fix, isNotEmpty);
        if (f.finding.code == FindingCode.untrustedMagnitude) {
          expect(f.finding.trace, isNotEmpty,
              reason: 'an untrusted finding must explain where the value came from');
        }
      }
    });
  });

  group('clean codebase produces no findings', () {
    test('money, pagination, flags and loops are quiet', () async {
      final findings = await _check('examples/clean_codebase');
      expect(findings, isEmpty,
          reason: findings
              .map((LocatedFinding f) => '${f.file}:${f.line} ${f.finding.code.id}')
              .join('\n'));
    });
  });

  group('genuinely 64-bit code is reported', () {
    test('wide masks, shifts and constants', () async {
      final findings = await _check('examples/bigints');
      final codes = findings.map((f) => f.finding.code).toSet();
      expect(codes, contains(FindingCode.literalNotRepresentable));
      expect(codes, contains(FindingCode.shiftTruncatesOnWeb));
      expect(codes, contains(FindingCode.bitwiseTruncatesOnWeb));
    });
  });

  group('mixed client app', () {
    test('reports exactly the wide id path, nothing else', () async {
      final findings = await _check('examples/mixed_app');
      expect(findings, hasLength(1),
          reason: findings
              .map((LocatedFinding f) =>
                  '${f.line}:${f.finding.code.id} ${f.finding.snippet}')
              .join('\n'));
      final only = findings.single;
      expect(only.finding.code, FindingCode.untrustedMagnitude);
      expect(only.finding.snippet, contains('~/'));
    });
  });
}
