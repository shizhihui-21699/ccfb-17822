import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:web_int_check/web_int_check.dart';

const _usage = '''
web_int_check — Dart integer-semantics checker for web targets

Usage: web_int_check [options] <paths...>

Options:
  --config=<file>   YAML config with a web_int_check: section
  --format=text     human-readable output (default)
  --format=json     machine-readable JSON array
  --fatal-severity=<sev>
                    exit non-zero when findings of this severity or higher
                    exist (error, warning, info); default: error
  -h, --help        show this help
''';

Future<void> main(List<String> argv) async {
  if (argv.contains('-h') || argv.contains('--help') || argv.isEmpty) {
    stdout.writeln(_usage);
    exit(argv.isEmpty ? 64 : 0);
  }

  var format = 'text';
  String? configPath;
  var fatal = CheckSeverity.error;
  final paths = <String>[];

  for (final arg in argv) {
    if (arg.startsWith('--format=')) {
      format = arg.substring('--format='.length);
    } else if (arg.startsWith('--config=')) {
      configPath = arg.substring('--config='.length);
    } else if (arg.startsWith('--fatal-severity=')) {
      final name = arg.substring('--fatal-severity='.length);
      fatal = CheckSeverity.values.asNameMap()[name] ?? CheckSeverity.error;
    } else if (arg.startsWith('-')) {
      stderr.writeln('Unknown option: $arg\n$_usage');
      exit(64);
    } else {
      paths.add(arg);
    }
  }

  final config = configPath != null
      ? CheckerConfig.loadFromFile(configPath)
      : _discoverConfig(paths);

  List<Finding> findings;
  try {
    findings = await runWebIntCheck(paths, config: config);
  } on FileSystemException catch (e) {
    stderr.writeln('error: ${e.message}: ${e.path}');
    exit(66);
  }

  switch (format) {
    case 'json':
      stdout.writeln(const JsonEncoder.withIndent('  ')
          .convert(findings.map((f) => f.toJson()).toList()));
      break;
    case 'text':
    default:
      if (findings.isEmpty) {
        stdout.writeln('No web integer-semantics issues found.');
      } else {
        for (final f in findings) {
          stdout.writeln(f.toConsoleText());
          if (f.codeSnippet != null) stdout.writeln('    | ${f.codeSnippet}');
          stdout.writeln('');
        }
        final counts = <CheckSeverity, int>{};
        for (final f in findings) {
          counts[f.severity] = (counts[f.severity] ?? 0) + 1;
        }
        stdout.writeln(counts.entries
            .map((e) => '${e.value} ${e.key.name}')
            .join(', '));
      }
  }

  final order = CheckSeverity.values.asNameMap();
  final fatalRank = order[fatal.name]!.index;
  final hasFatal = findings.any((f) => f.severity.index <= fatalRank);
  exit(hasFatal ? 1 : 0);
}

CheckerConfig _discoverConfig(List<String> paths) {
  for (final base in paths) {
    final dir = FileSystemEntity.isDirectorySync(base)
        ? base
        : p.dirname(File(base).absolute.path);
    final candidate = File(p.join(dir, 'web_int_check.yaml'));
    if (candidate.existsSync()) {
      return CheckerConfig.loadFromFile(candidate.path);
    }
    final pubCandidate = File(p.join(dir, 'pubspec.yaml'));
    if (pubCandidate.existsSync()) {
      return CheckerConfig.loadFromFile(pubCandidate.path);
    }
  }
  return CheckerConfig.defaults;
}
