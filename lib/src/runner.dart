// Copyright 2026. All rights reserved.
//
// Drives the analyzer over a directory and collects findings.

import 'dart:convert';

import 'package:analyzer/dart/analysis/analysis_context_collection.dart';
import 'package:analyzer/dart/analysis/results.dart';
import 'package:path/path.dart' as p;

import 'analyzer.dart';
import 'report.dart';

/// Configuration for a run.
class RunConfig {
  const RunConfig({
    required this.paths,
    this.options = const AnalysisOptionsData(),
    this.sdkPath,
    this.excludeGlobs = const <String>[],
    this.includePaths = const <String>[],
  });

  final List<String> paths;
  final AnalysisOptionsData options;
  final String? sdkPath;
  final List<String> excludeGlobs;
  final List<String> includePaths;

  bool isExcluded(String absolutePath) {
    for (final glob in excludeGlobs) {
      final pattern = _globToRegExp(glob);
      if (pattern.hasMatch(absolutePath) ||
          pattern.hasMatch(p.basename(absolutePath))) {
        return true;
      }
    }
    return false;
  }

  static RegExp _globToRegExp(String glob) {
    final b = StringBuffer('^');
    for (var i = 0; i < glob.length; i++) {
      final c = glob[i];
      if (c == '*') {
        if (i + 1 < glob.length && glob[i + 1] == '*') {
          b.write('.*');
          i++;
        } else {
          b.write('[^/]*');
        }
      } else if (c == '?') {
        b.write('.');
      } else if (r'.+()[]{}^$|\'.contains(c)) {
        b.write(RegExp.escape(c));
      } else {
        b.write(c);
      }
    }
    b.write(r'$');
    return RegExp(b.toString());
  }
}

/// Runs the checker over [config] and returns located findings.
Future<List<LocatedFinding>> runChecker(RunConfig config) async {
  final normalized = <String>[
    for (final path in config.paths) p.normalize(p.absolute(path)),
  ];

  final collection = AnalysisContextCollection(
    includedPaths: normalized,
    sdkPath: config.sdkPath,
  );

  final results = <LocatedFinding>[];
  try {
    for (final context in collection.contexts) {
      final session = context.currentSession;
      final files = context.contextRoot.analyzedFiles().toList()..sort();
      for (final file in files) {
        if (!file.endsWith('.dart')) continue;
        if (config.isExcluded(file)) continue;
        final resolved = await session.getResolvedUnit(file);
        if (resolved is! ResolvedUnitResult) continue;
        results.addAll(analyzeResolvedUnit(resolved, config.options));
      }
    }
  } finally {
    collection.dispose();
  }

  results.sort((a, b) {
    final byFile = a.file.compareTo(b.file);
    if (byFile != 0) return byFile;
    return a.finding.offset.compareTo(b.finding.offset);
  });
  return results;
}

/// Analyzes a single resolved unit. Exposed for tests.
List<LocatedFinding> analyzeResolvedUnit(
  ResolvedUnitResult resolved,
  AnalysisOptionsData options, {
  bool trustEntireLibrary = false,
}) {
  final analyzer = UnitAnalyzer(
    unit: resolved.unit,
    content: resolved.content,
    typeProvider: resolved.typeProvider,
    options: options,
    trustEntireLibrary: trustEntireLibrary,
  );
  analyzer.analyze();

  final lineInfo = resolved.lineInfo;
  final lines = const LineSplitter().convert(resolved.content);
  final located = <LocatedFinding>[];
  for (final finding in analyzer.findings) {
    final location = lineInfo.getLocation(finding.offset);
    final line = location.lineNumber;
    finding.setLocation(line, location.columnNumber);
    String? sourceLine;
    if (line - 1 >= 0 && line - 1 < lines.length) {
      sourceLine = lines[line - 1];
    }
    located.add(
      LocatedFinding(
        file: resolved.path,
        line: line,
        column: location.columnNumber,
        finding: finding,
        sourceLine: sourceLine,
      ),
    );
  }
  return located;
}

