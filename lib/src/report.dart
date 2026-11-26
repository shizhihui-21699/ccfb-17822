// Copyright 2026. All rights reserved.
//
// Turns findings into human- and machine-readable output.

import 'dart:convert';
import 'dart:io';

import 'model.dart';

/// A finding together with the file and resolved location it belongs to.
class LocatedFinding {
  LocatedFinding({
    required this.file,
    required this.line,
    required this.column,
    required this.finding,
    this.sourceLine,
  });

  final String file;
  final int line;
  final int column;
  final Finding finding;
  final String? sourceLine;

  Map<String, Object?> toJson() => finding.toJson(file);

  /// Formats as `path:line:col: severity: message [code]`.
  String console() {
    final b = StringBuffer()
      ..write(file)
      ..write(':')
      ..write(line)
      ..write(':')
      ..write(column)
      ..write(': ')
      ..write(finding.severity.label)
      ..write(': ')
      ..write(finding.message)
      ..write(' [')
      ..write(finding.code.id)
      ..write(']');
    return b.toString();
  }
}

/// Renders a set of findings.
class Reporter {
  Reporter({required this.useColor, this.verbose = false});

  final bool useColor;
  final bool verbose;

  static const _red = '\x1B[31m';
  static const _yellow = '\x1B[33m';
  static const _blue = '\x1B[34m';
  static const _cyan = '\x1B[36m';
  static const _dim = '\x1B[2m';
  static const _bold = '\x1B[1m';
  static const _reset = '\x1B[0m';

  String _paint(String s, String color) => useColor ? '$color$s$_reset' : s;

  /// ANSI console report grouped by file, with the fix and per-target values.
  void console(List<LocatedFinding> findings, {String? summary}) {
    final byFile = <String, List<LocatedFinding>>{};
    for (final f in findings) {
      byFile.putIfAbsent(f.file, () => <LocatedFinding>[]).add(f);
    }
    final sortedFiles = byFile.keys.toList()..sort();
    for (final file in sortedFiles) {
      final list = byFile[file]!
        ..sort((a, b) => a.finding.offset.compareTo(b.finding.offset));
      stdout.writeln(_paint(file, _bold));
      for (final lf in list) {
        final f = lf.finding;
        final sev = switch (f.severity) {
          Severity.error => _paint('error', _red),
          Severity.warning => _paint('warning', _yellow),
          Severity.info => _paint('info', _blue),
        };
        stdout.writeln(
          '  ${lf.line.toString().padLeft(5)}:${lf.column.toString().padRight(4)} '
          '$sev  ${f.message}',
        );
        stdout.writeln('        ${_paint('[${f.code.id}]', _cyan)}');
        if (lf.sourceLine != null) {
          stdout.writeln('        ${_paint('│ ${lf.sourceLine!.trim()}', _dim)}');
        }
        final sample = f.sample;
        if (sample != null) {
          final pairs =
              sample.entries.map((e) => '${e.key.label}=${e.value}').join(', ');
          stdout.writeln('        ${_paint('targets: $pairs', _dim)}');
        }
        if (verbose && f.trace.isNotEmpty) {
          for (final hop in f.trace) {
            stdout.writeln('        ${_paint('taint: $hop', _dim)}');
          }
        }
        stdout.writeln('        ${_paint('fix: ${f.fix}', _dim)}');
      }
      stdout.writeln();
    }
    if (summary != null) stdout.writeln(summary);
  }

  /// JSON report. Stable schema for CI consumption.
  String json(List<LocatedFinding> findings, {Map<String, Object?>? meta}) {
    final payload = <String, Object?>{
      // ignore: use_null_aware_elements
      if (meta != null) 'meta': meta,
      'findings': [for (final f in findings) f.toJson()],
      'summary': _summaryMap(findings),
    };
    return const JsonEncoder.withIndent('  ').convert(payload);
  }

  /// SARIF 2.1.0, consumable by GitHub code scanning.
  String sarif(List<LocatedFinding> findings) {
    final rules = <String, Map<String, Object?>>{};
    for (final f in findings) {
      rules.putIfAbsent(
        f.finding.code.id,
        () => <String, Object?>{
          'id': f.finding.code.id,
          'name': f.finding.code.id,
          'shortDescription': {'text': f.finding.code.problem},
          'help': {'text': f.finding.code.problem},
          'properties': {'tags': ['web', 'integer', 'portability']},
        },
      );
    }
    final results = <Map<String, Object?>>[];
    for (final f in findings) {
      final finding = f.finding;
      results.add(<String, Object?>{
        'ruleId': finding.code.id,
        'level': switch (finding.severity) {
          Severity.error => 'error',
          Severity.warning => 'warning',
          Severity.info => 'note',
        },
        'message': {'text': '${finding.message}\n\nFix: ${finding.fix}'},
        'locations': [
          {
            'physicalLocation': {
              'artifactLocation': {'uri': f.file},
              'region': {
                'startLine': f.line,
                'startColumn': f.column,
                'endLine': f.line,
                'endColumn': f.column + finding.length,
              },
            },
          },
        ],
      });
    }
    final doc = <String, Object?>{
      r'$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
      'version': '2.1.0',
      'runs': [
        {
          'tool': {
            'driver': {
              'name': 'web_int_checker',
              'informationUri': 'https://github.com/example/web_int_checker',
              'rules': rules.values.toList(),
            },
          },
          'results': results,
        },
      ],
    };
    return const JsonEncoder.withIndent('  ').convert(doc);
  }

  Map<String, Object?> _summaryMap(List<LocatedFinding> findings) {
    final bySeverity = <String, int>{};
    for (final f in findings) {
      bySeverity.update(f.finding.severity.label, (v) => v + 1,
          ifAbsent: () => 1);
    }
    return <String, Object?>{
      'total': findings.length,
      'bySeverity': bySeverity,
    };
  }

  /// Human summary line used after the console report.
  String summaryLine(List<LocatedFinding> findings) {
    if (findings.isEmpty) return 'No cross-platform integer issues found.';
    var errors = 0, warnings = 0, infos = 0;
    for (final f in findings) {
      switch (f.finding.severity) {
        case Severity.error:
          errors++;
        case Severity.warning:
          warnings++;
        case Severity.info:
          infos++;
      }
    }
    final parts = <String>[
      if (errors > 0) '$errors error${errors == 1 ? '' : 's'}',
      if (warnings > 0) '$warnings warning${warnings == 1 ? '' : 's'}',
      if (infos > 0) '$infos info',
    ];
    return '${parts.join(', ')} found.';
  }
}
