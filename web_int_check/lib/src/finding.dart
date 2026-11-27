import 'rules.dart';

/// A single reported problem, mapped 1:1 to a source location.
class Finding {
  final String ruleId;
  final CheckSeverity severity;
  final String message;
  final String remediation;
  final String filePath;
  final int offset;
  final int line;
  final int column;
  final String? codeSnippet;

  const Finding({
    required this.ruleId,
    required this.severity,
    required this.message,
    required this.remediation,
    required this.filePath,
    required this.offset,
    required this.line,
    required this.column,
    this.codeSnippet,
  });

  Map<String, Object?> toJson() => {
        'rule': ruleId,
        'severity': severity.name,
        'message': message,
        'remediation': remediation,
        'file': filePath,
        'offset': offset,
        'line': line,
        'column': column,
        if (codeSnippet != null) 'snippet': codeSnippet,
      };

  String toConsoleText() {
    final loc = '$filePath:$line:$column';
    return '${severity.name.padRight(7)} $ruleId  $loc\n'
        '  $message\n  -> $remediation';
  }
}
