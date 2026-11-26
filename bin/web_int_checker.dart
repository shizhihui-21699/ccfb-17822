// Copyright 2026. All rights reserved.
//
// Command line interface for the cross-platform integer semantics checker.

import 'dart:io';

import 'package:args/args.dart';

import 'package:web_int_checker/src/analyzer.dart';
import 'package:web_int_checker/src/model.dart';
import 'package:web_int_checker/src/report.dart';
import 'package:web_int_checker/src/runner.dart';

const _version = '0.1.0';

Future<void> main(List<String> arguments) async {
  final exitCode = await _run(arguments);
  if (exitCode != 0) exit(exitCode);
}

Future<int> _run(List<String> arguments) async {
  final parser = ArgParser()
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show usage.')
    ..addFlag('version', negatable: false, help: 'Print the version.')
    ..addOption('format',
        abbr: 'f',
        defaultsTo: 'console',
        allowed: ['console', 'json', 'sarif'],
        help: 'Output format.')
    ..addOption('strictness',
        abbr: 's',
        defaultsTo: 'standard',
        allowed: ['minimal', 'standard', 'strict'],
        help: 'How aggressively to report.')
    ..addMultiOption('entry-point',
        help: 'Treat this function as attacker-facing (repeatable).',
        splitCommas: true)
    ..addMultiOption('trusted-parameter',
        help: 'Parameter to treat as trusted (repeatable).', splitCommas: true)
    ..addMultiOption('trusted-function',
        help: 'Function whose return value is trusted (repeatable).',
        splitCommas: true)
    ..addMultiOption('exclude',
        abbr: 'x',
        help: 'Glob of files to skip (repeatable).', splitCommas: true)
    ..addOption('sdk', help: 'Path to a Dart SDK (auto-detected by default).')
    ..addFlag('trust-library',
        negatable: false,
        help: 'Treat every int parameter in every library as attacker '
            'controlled (for shared business-logic packages).')
    ..addFlag('verbose',
        abbr: 'v', negatable: false, help: 'Show taint traces.')
    ..addFlag('no-color', negatable: false, help: 'Disable ANSI colours.')
    ..addFlag('fatal-warnings',
        negatable: false,
        help: 'Exit non-zero if any warning is found (errors always fail).')
    ..addFlag('fail-on-info',
        negatable: false, help: 'Exit non-zero if any finding is reported.');

  ArgResults args;
  try {
    args = parser.parse(arguments);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    stderr.writeln(parser.usage);
    return 64;
  }

  if (args['help'] as bool) {
    stdout.writeln(_usage(parser));
    return 0;
  }
  if (args['version'] as bool) {
    stdout.writeln('web_int_checker $_version');
    return 0;
  }

  final paths = args.rest.isEmpty ? <String>['.'] : args.rest;
  for (final path in paths) {
    if (!FileSystemEntity.isDirectorySync(path) &&
        !FileSystemEntity.isFileSync(path)) {
      stderr.writeln('No such file or directory: $path');
      return 66;
    }
  }

  final options = AnalysisOptionsData(
    strictness: Strictness.parse(args['strictness'] as String),
    entryPoints: _set(args['entry-point']),
    trustedParameters: _set(args['trusted-parameter']),
    trustedFunctions: _set(args['trusted-function']),
  );

  final config = RunConfig(
    paths: paths,
    options: options,
    sdkPath: args['sdk'] as String?,
    excludeGlobs: _set(args['exclude']).toList(),
  );

  final stopwatch = Stopwatch()..start();
  final List<LocatedFinding> findings;
  try {
    findings = await runChecker(config);
  } on FileSystemException catch (e) {
    stderr.writeln('Analysis failed: ${e.message}');
    return 74;
  }
  stopwatch.stop();

  final format = args['format'] as String;
  final reporter = Reporter(
    useColor: !(args['no-color'] as bool) && stdout.hasTerminal && format == 'console',
    verbose: args['verbose'] as bool,
  );

  switch (format) {
    case 'json':
      stdout.writeln(reporter.json(findings, meta: <String, Object?>{
        'version': _version,
        'strictness': options.strictness.name,
        'elapsedMs': stopwatch.elapsedMilliseconds,
      }));
    case 'sarif':
      stdout.writeln(reporter.sarif(findings));
    default:
      reporter.console(findings, summary: reporter.summaryLine(findings));
  }

  return _exitCode(findings, args);
}

int _exitCode(List<LocatedFinding> findings, ArgResults args) {
  if (args['fail-on-info'] as bool && findings.isNotEmpty) return 1;
  var hasError = false;
  var hasWarning = false;
  for (final f in findings) {
    if (f.finding.severity == Severity.error) hasError = true;
    if (f.finding.severity == Severity.warning) hasWarning = true;
  }
  if (hasError) return 1;
  if (hasWarning && (args['fatal-warnings'] as bool)) return 1;
  return 0;
}

Set<String> _set(Object? value) {
  final list = value as List<String>?;
  if (list == null) return const <String>{};
  return {
    for (final v in list)
      if (v.trim().isNotEmpty) v.trim(),
  };
}

String _usage(ArgParser parser) => '''
web_int_checker $_version
Finds Dart integer arithmetic whose result changes when compiled to JavaScript.

The same Dart source can be compiled for the VM/AOT (64-bit int), for Wasm
(64-bit int) and for JavaScript (int is a double: 53-bit precision, 32-bit
bitwise). This tool reports the operations whose result differs, and gives a
concrete Int64 / BigInt fix.

USAGE
  dart run web_int_checker [options] [paths...]

  With no paths, the current directory is analyzed.

EXAMPLES
  dart run web_int_checker lib
  dart run web_int_checker --format json lib > report.json
  dart run web_int_checker --strictness strict --format sarif .
  dart run web_int_checker --entry-point ValidateOrder --exclude '**/*.g.dart' lib

${parser.usage}
EXIT CODES
  0  no errors (warnings allowed unless --fatal-warnings)
  1  errors found, or warnings with --fatal-warnings
 64  usage error
 66  path not found
 74  analysis failure
''';
