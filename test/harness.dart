// Copyright 2026. All rights reserved.
//
// Test harness: analyzes an in-memory Dart source snippet with the real
// analyzer and returns the checker's findings.

import 'dart:io';

import 'package:analyzer/dart/analysis/analysis_context_collection.dart';
import 'package:analyzer/dart/analysis/results.dart';
import 'package:path/path.dart' as p;
import 'package:web_int_checker/src/analyzer.dart';
import 'package:web_int_checker/src/model.dart';
import 'package:web_int_checker/src/runner.dart';

/// One finding reduced to the fields tests assert on.
class TestFinding {
  TestFinding(this.code, this.severity, this.line, this.column, this.message);

  final FindingCode code;
  final Severity severity;
  final int line;
  final int column;
  final String message;

  @override
  String toString() => '${code.id} ${severity.label} $line:$column';
}

/// Creates a temporary package containing [files] and analyzes it.
///
/// A `pubspec.yaml` is written so the analyzer treats the sources as a real
/// package rather than a bare directory.
Future<List<TestFinding>> analyzeSources(
  Map<String, String> files, {
  AnalysisOptionsData options = const AnalysisOptionsData(),
  bool trustEntireLibrary = false,
}) async {
  final dir = Directory.systemTemp.createTempSync('wic_test_');
  try {
    File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
      'name: fixture\nenvironment:\n  sdk: ^3.9.0\n',
    );
    for (final entry in files.entries) {
      final file = File(p.join(dir.path, entry.key));
      file.parent.createSync(recursive: true);
      file.writeAsStringSync(entry.value);
    }

    final collection = AnalysisContextCollection(
      includedPaths: [dir.path],
    );
    final results = <TestFinding>[];
    try {
      for (final context in collection.contexts) {
        final session = context.currentSession;
        for (final path in context.contextRoot.analyzedFiles()) {
          if (!path.endsWith('.dart')) continue;
          if (path.endsWith('.g.dart')) continue;
          final resolved = await session.getResolvedUnit(path);
          if (resolved is! ResolvedUnitResult) continue;
          final located = analyzeResolvedUnit(
            resolved,
            options,
            trustEntireLibrary: trustEntireLibrary,
          );
          for (final lf in located) {
            results.add(
              TestFinding(
                lf.finding.code,
                lf.finding.severity,
                lf.line,
                lf.column,
                lf.finding.message,
              ),
            );
          }
        }
      }
    } finally {
      collection.dispose();
    }
    return results;
  } finally {
    dir.deleteSync(recursive: true);
  }
}

/// Convenience: analyze a single file.
Future<List<TestFinding>> analyzeSource(
  String source, {
  AnalysisOptionsData options = const AnalysisOptionsData(),
  bool trustEntireLibrary = false,
}) =>
    analyzeSources(
      {'lib/main.dart': source},
      options: options,
      trustEntireLibrary: trustEntireLibrary,
    );
