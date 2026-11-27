import 'dart:io';

import 'package:yaml/yaml.dart';

import 'rules.dart';

/// Fully resolved checker configuration.
class CheckerConfig {
  /// Effective severity per rule id. Rules absent here use their default.
  final Map<String, CheckSeverity> severityOverrides;

  /// Fully qualified methods (`package:uri/foo.dart::ClassName.methodName`
  /// or bare `methodName`) whose int/dynamic results are treated as
  /// untrusted sources, like `jsonDecode`.
  final List<String> extraSourceMethods;

  /// Annotation simple names marking a parameter/field as known web-safe.
  final Set<String> safeAnnotations;

  /// Annotation simple names marking a parameter/field as web-unsafe.
  final Set<String> unsafeAnnotations;

  /// File path globs (relative names containing wildcards) to skip.
  final List<String> excludeGlobs;

  /// When false (default), plain arithmetic on unbounded, untainted ints
  /// (e.g. parameters of a small-money function) is silent. When true it is
  /// reported as WEB_INT_009 info. Bitwise/shift/hash "cannot prove" infos
  /// are always emitted because their semantics change at a hard cliff.
  final bool strictArithmetic;

  const CheckerConfig({
    this.severityOverrides = const {},
    this.extraSourceMethods = const [],
    this.safeAnnotations = const {'webSafeInt', 'safeInt'},
    this.unsafeAnnotations = const {'webUnsafeInt'},
    this.excludeGlobs = const [],
    this.strictArithmetic = false,
  });

  CheckSeverity severityOf(CheckRule rule) =>
      severityOverrides[rule.id] ?? rule.defaultSeverity;

  static const CheckerConfig defaults = CheckerConfig();

  /// Reads `web_int_check:` section from a pub-style YAML file. Missing file
  /// yields [defaults]; malformed YAML throws [FormatException].
  static CheckerConfig loadFromFile(String path) {
    final f = File(path);
    if (!f.existsSync()) return defaults;
    final doc = loadYaml(f.readAsStringSync());
    if (doc is! YamlMap) return defaults;
    final section = doc['web_int_check'];
    if (section is! YamlMap) return defaults;

    final overrides = <String, CheckSeverity>{};
    final rules = section['rules'];
    if (rules is YamlMap) {
      for (final e in rules.nodes.entries) {
        final name = e.key.toString();
        final raw = e.value.toString().toLowerCase();
        final sev = CheckSeverity.values.asNameMap()[raw];
        if (sev != null) overrides[name] = sev;
      }
    }

    List<String> asStringList(dynamic v) =>
        v is YamlList ? v.map((e) => e.toString()).toList() : const [];
    Set<String> asStringSet(dynamic v) => asStringList(v).toSet();

    return CheckerConfig(
      severityOverrides: overrides,
      extraSourceMethods: asStringList(section['extra_sources']),
      safeAnnotations: asStringSet(section['safe_annotations'])
        ..addAll(const {'webSafeInt', 'safeInt'}),
      unsafeAnnotations: asStringSet(section['unsafe_annotations'])
        ..addAll(const {'webUnsafeInt'}),
      excludeGlobs: asStringList(section['exclude']),
      strictArithmetic: section['strict_arithmetic'] == true,
    );
  }
}
