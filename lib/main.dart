// Copyright 2026. All rights reserved.
//
// Analyzer plugin entry point.
//
// Registering this plugin in `analysis_options.yaml`
//
//     plugins:
//       web_int_checker:
//         path: /path/to/web_int_checker
//         diagnostics:
//           web_integer_literal_not_representable: true
//           web_untrusted_integer_magnitude: true
//           ...
//
// makes `dart analyze`, `flutter analyze` and the IDE report the same
// cross-platform integer problems the CLI reports, inline on the source line.
//
// The plugin runs the *same* engine as the CLI (`lib/src/analyzer.dart`), so
// the two can never disagree about what is wrong.

import 'package:analysis_server_plugin/plugin.dart';
import 'package:analysis_server_plugin/registry.dart';
import 'package:analyzer/analysis_rule/analysis_rule.dart';
import 'package:analyzer/analysis_rule/rule_context.dart';
import 'package:analyzer/analysis_rule/rule_visitor_registry.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/error/error.dart';

import 'src/analyzer.dart';
import 'src/model.dart';

/// The plugin instance the analysis server loads.
final plugin = WebIntPlugin();

class WebIntPlugin extends Plugin {
  @override
  String get name => 'web_int_checker';

  @override
  void register(PluginRegistry registry) {
    for (final family in FindingFamily.values) {
      registry.registerLintRule(WebIntRule(family));
    }
  }
}

/// One rule per group of related finding codes.
class WebIntRule extends MultiAnalysisRule {
  WebIntRule(this.family)
      : super(name: family.ruleName, description: family.description);

  final FindingFamily family;

  static final Map<FindingCode, LintCode> _codes = {
    for (final code in FindingCode.values) code: LintCode(code.id, code.problem),
  };

  @override
  List<DiagnosticCode> get diagnosticCodes => [
    for (final code in family.codes) _codes[code]!,
  ];

  @override
  void registerNodeProcessors(
    RuleVisitorRegistry registry,
    RuleContext context,
  ) {
    registry.addCompilationUnit(this, _UnitVisitor(this, context));
  }

  /// Translate an engine finding from this rule's family into a diagnostic.
  void report(Finding finding) {
    // The message template has no placeholders, so no arguments are passed;
    // the full explanation (including the fix) rides on the problem text via
    // `LintCode.problemMessage`. The CLI report carries the detailed version.
    reportAtOffset(
      finding.offset,
      finding.length,
      diagnosticCode: _codes[finding.code]!,
    );
  }
}

/// Groups of finding codes, each registered as its own rule name.
enum FindingFamily {
  portability('web_integer_portability',
      'Integer results that change when compiled to JavaScript.', [
    FindingCode.arithmeticLosesPrecision,
    FindingCode.shiftTruncatesOnWeb,
    FindingCode.bitwiseTruncatesOnWeb,
  ]),
  literals('web_integer_constants',
      'Integer literals and constant expressions that differ on the web.', [
    FindingCode.literalNotRepresentable,
    FindingCode.constantFoldsDifferently,
  ]),
  hashes('web_integer_hashes',
      'Hash values that are not stable across the VM, Wasm and JS.', [
    FindingCode.hashCodeNotPortable,
  ]),
  untrusted('web_integer_untrusted',
      'Attacker-controlled integers reaching platform-dependent code.', [
    FindingCode.untrustedMagnitude,
    FindingCode.integerKeyCollision,
  ]),
  conversion('web_integer_conversion',
      'Numeric conversions that differ between the VM and JavaScript.', [
    FindingCode.doubleToIntDiverges,
  ]);

  const FindingFamily(this.ruleName, this.description, this.codes);

  final String ruleName;
  final String description;
  final List<FindingCode> codes;
}

/// Runs the shared engine once per compilation unit.
class _UnitVisitor extends SimpleAstVisitor<void> {
  _UnitVisitor(this.rule, this.context);

  final WebIntRule rule;
  final RuleContext context;

  @override
  void visitCompilationUnit(CompilationUnit node) {
    final unit = context.currentUnit;
    final content = unit?.content ?? _contentOf(node);
    final analyzer = UnitAnalyzer(
      unit: node,
      content: content,
    );
    analyzer.analyze();
    final familyCodes = rule.family.codes.toSet();
    final seen = <String>{};
    for (final finding in analyzer.findings) {
      if (!familyCodes.contains(finding.code)) continue;
      if (seen.add('${finding.offset}:${finding.code.id}')) {
        rule.report(finding);
      }
    }
  }

  /// Fallback text reconstruction when the context does not expose the buffer.
  String _contentOf(CompilationUnit node) {
    final b = StringBuffer();
    if (node.offset > 0) b.write(' ' * node.offset);
    b.write(node.toSource());
    return b.toString();
  }
}
