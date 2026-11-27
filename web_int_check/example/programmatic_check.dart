import 'package:web_int_check/web_int_check.dart';

/// Programmatic use of the checker (the CLI in bin/ wraps the same call).
Future<void> main() async {
  // Default configuration: hard findings for proven divergence and untrusted
  // data; info findings where web-safety cannot be proved.
  final findings = await runWebIntCheck(['lib/shared']);
  for (final f in findings) {
    // ignore: avoid_print
    print('${f.ruleId} ${f.filePath}:${f.line} — ${f.message}');
  }

  // Customize: treat extra methods as untrusted, make arithmetic strict.
  final configured = CheckerConfig(
    strictArithmetic: true,
    extraSourceMethods: const ['ApiClient.readNumber'],
    severityOverrides: const {
      'WEB_INT_009': CheckSeverity.warning,
    },
  );
  final more = await runWebIntCheck(['lib'], config: configured);
  // ignore: avoid_print
  print('strict findings: ${more.length}');
}
