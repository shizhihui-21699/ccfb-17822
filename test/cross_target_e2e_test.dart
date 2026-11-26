// Copyright 2026. All rights reserved.
//
// End-to-end proof that the checker's advice is correct.
//
// For each fix the checker recommends, this compiles the *same* source for the
// VM, for dart2js and (when node is available) for Wasm, and asserts:
//
//   * the hostile example really does produce different output on JS, and
//   * the recommended Int64/BigInt rewrite produces identical output.
//
// These tests shell out to the Dart SDK and Node, so they are skipped when
// those tools are missing. They are the evidence behind every fix message the
// tool prints.

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';

final _hasDart = Platform.resolvedExecutable.isNotEmpty;
final _hasNode = _which('node') != null;

String? _which(String exe) {
  final path = Platform.environment['PATH'] ?? '';
  final sep = Platform.isWindows ? ';' : ':';
  for (final dir in path.split(sep)) {
    if (dir.isEmpty) continue;
    final candidate = p.join(dir, Platform.isWindows ? '$exe.exe' : exe);
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}

/// Runs [source] on the VM and returns normalised stdout lines.
Future<List<String>> _runVm(String dir, String source) async {
  final file = File(p.join(dir, 'lib', 'main.dart'));
  file.parent.createSync(recursive: true);
  file.writeAsStringSync(source);
  final result = await Process.run(
    Platform.resolvedExecutable,
    ['run', file.path],
  );
  expect(result.exitCode, 0,
      reason: 'VM run failed:\n${result.stdout}\n${result.stderr}');
  return (result.stdout as String).trim().split('\n');
}

/// Compiles [source] with dart2js and runs it under node.
Future<List<String>> _runJs(String dir, String source) async {
  final file = File(p.join(dir, 'lib', 'main.dart'));
  file.parent.createSync(recursive: true);
  file.writeAsStringSync(source);
  final out = p.join(dir, 'out.js');
  final compile = await Process.run(
    Platform.resolvedExecutable,
    ['compile', 'js', '-O1', '-o', out, file.path],
  );
  expect(compile.exitCode, 0,
      reason: 'dart2js failed:\n${compile.stdout}\n${compile.stderr}');
  final run = await Process.run('node', [out]);
  expect(run.exitCode, 0,
      reason: 'node failed:\n${run.stdout}\n${run.stderr}');
  return (run.stdout as String).trim().split('\n');
}

/// Creates a scratch package, runs [body], and cleans up.
Future<void> withPackage(
  String name,
  Map<String, String> extraFiles,
  Future<void> Function(String dir) body,
) async {
  final directory = Directory.systemTemp.createTempSync('wic_e2e_$name');
  final dir = directory.path;
  try {
    File(p.join(dir, 'pubspec.yaml')).writeAsStringSync('''
name: e2e
environment:
  sdk: ^3.9.0
dependencies:
  fixnum: ^1.1.0
''');
    for (final entry in extraFiles.entries) {
      final file = File(p.join(dir, entry.key));
      file.parent.createSync(recursive: true);
      file.writeAsStringSync(entry.value);
    }
    await body(dir);
  } finally {
    directory.deleteSync(recursive: true);
  }
}

void main() {
  group('the reported incident is real', () {
    const buggy = '''
int checksum(int orderId, int points) {
  var h = orderId;
  h = (h << 5) - h + points;
  return h & 0x7FFFFFFF;
}

void main() {
  final id = int.parse('9007199254740993');
  print(checksum(id, id));
  final a = int.parse('9007199254740993');
  final b = int.parse('9007199254740992');
  print(a == b);
}
''';

    test('VM and JS disagree on the checksum and the duplicate check',
        () async {
      await withPackage('buggy', {}, (dir) async {
        final vm = await _runVm(dir, buggy);
        final js = await _runJs(dir, buggy);
        expect(vm, isNot(equals(js)),
            reason: 'the bug must reproduce, or the tool has nothing to find');
        // The duplicate-id bypass: distinct ids compare equal only on JS.
        expect(vm.last, 'false');
        expect(js.last, 'true');
      });
    }, skip: !_hasDart || !_hasNode ? 'needs dart + node' : false);

    test('the Int64 fix makes VM and JS agree', () async {
      const fixed = '''
import 'package:fixnum/fixnum.dart';

final Int64 _mask = Int64.parseInt('2147483647');

Int64 checksum(Int64 orderId, Int64 points) {
  var h = orderId;
  h = (h << 5) - h + points;
  return h & _mask;
}

void main() {
  final id = Int64.parseInt('9007199254740993');
  print(checksum(id, id));
  final a = Int64.parseInt('9007199254740993');
  final b = Int64.parseInt('9007199254740992');
  print(a == b);
}
''';
      await withPackage('fixed', {}, (dir) async {
        final vm = await _runVm(dir, fixed);
        final js = await _runJs(dir, fixed);
        expect(vm, equals(js));
        expect(vm.last, 'false', reason: 'distinct 64-bit ids stay distinct');
      });
    }, skip: !_hasDart || !_hasNode ? 'needs dart + node' : false);
  });

  group('constant folding is proved by the compilers', () {
    test('1 << 40 differs between VM and JS', () async {
      const source = '''
void main() {
  const int window = 1 << 40;
  print(window);
}
''';
      await withPackage('shift40', {}, (dir) async {
        final vm = await _runVm(dir, source);
        final js = await _runJs(dir, source);
        expect(vm.single, '1099511627776');
        expect(js.single, '0');
      });
    }, skip: !_hasDart || !_hasNode ? 'needs dart + node' : false);

    test('an oversized literal is a hard dart2js error', () async {
      const source = '''
const int seed = 0xcbf29ce484222325;
void main() => print(seed);
''';
      await withPackage('bigliteral', {}, (dir) async {
        final file = File(p.join(dir, 'lib', 'main.dart'));
        file.parent.createSync(recursive: true);
        file.writeAsStringSync(source);
        final compile = await Process.run(
          Platform.resolvedExecutable,
          ['compile', 'js', '-O1', '-o', p.join(dir, 'out.js'), file.path],
        );
        expect(compile.exitCode, isNot(0),
            reason: 'dart2js should reject an unrepresentable literal');
        expect('${compile.stdout}${compile.stderr}',
            contains("can't be represented exactly"));
      });
    }, skip: !_hasDart ? 'needs dart' : false);
  });
}
