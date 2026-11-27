/// Cross-platform integer semantics checker for Dart.
///
/// Use [runWebIntCheck] to analyze package directories or individual files.
/// The checker is built on `package:analyzer` and flags integer operations
/// whose results differ on the JavaScript (dart2js) target versus the native
/// VM and WebAssembly (dart2wasm, 64-bit) targets:
///
/// - unrepresentable integer literals (dart2js build breakers),
/// - 32-bit-truncated bitwise operations and shifts,
/// - arithmetic that can leave the 2^53 safe-integer range,
/// - numbers flowing in from `jsonDecode`, `int.parse`, `num.toInt`,
/// - integer hash/map-key/equality uses exposed to rounding collisions.
library web_int_check;

import 'src/config.dart';
import 'src/driver.dart';
import 'src/finding.dart';

export 'src/config.dart';
export 'src/finding.dart';
export 'src/rules.dart';
export 'src/semantics.dart';

/// Analyzes [paths] (files or directories) and returns all findings.
///
/// [config] controls rule severities, extra untrusted-source methods and
/// the recognized annotations. Paths are resolved against the current
/// working directory.
Future<List<Finding>> runWebIntCheck(
  List<String> paths, {
  CheckerConfig config = CheckerConfig.defaults,
}) async {
  final driver = CheckerDriver(config);
  return driver.analyzePaths(paths);
}
