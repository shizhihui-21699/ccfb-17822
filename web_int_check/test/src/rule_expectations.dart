import 'package:path/path.dart' as p;

/// Paths and the exact expected findings for the checked-in fixtures.
/// Keeping the expectations here (rather than parsing comments) makes a
/// shifted line fail loudly instead of silently weakening the test.
String get mallFixturePath =>
    p.join('test', 'fixtures', 'points_mall.dart');
String get cleanFixturePath =>
    p.join('test', 'fixtures', 'clean_code.dart');

/// line -> set of rule ids that must fire on exactly that line.
const Map<int, Set<String>> mallExpectations = {
  21: {'WEB_INT_001'},
  // Unbounded parameter reaching a semantics cliff (soft, contractable).
  77: {'WEB_INT_009'},
  // JSON-derived numbers crossing into the int world.
  66: {'WEB_INT_005'},
  67: {'WEB_INT_005'},
  84: {'WEB_INT_005'},
  85: {'WEB_INT_005'},
  // Tainted checksum body: hard bitwise/shift divergence plus boundary.
  86: {'WEB_INT_002', 'WEB_INT_003', 'WEB_INT_005'},
  87: {'WEB_INT_002'},
  // Unbounded shift count.
  93: {'WEB_INT_009'},
  // Shift count reaching the mod-32 boundary.
  98: {'WEB_INT_003'},
  // Statically provable overflow of the 2^53 safe range.
  112: {'WEB_INT_004'},
  117: {'WEB_INT_004'},
  // Runtime string parsing.
  131: {'WEB_INT_006'},
  134: {'WEB_INT_006'},
  // num -> int conversion.
  139: {'WEB_INT_007'},
  // Idempotency store: lookup and map-key write on a large/untrusted int.
  148: {'WEB_INT_008'},
  149: {'WEB_INT_008'},
  // Explicitly @webUnsafeInt source feeding an unmasked bitwise op.
  169: {'WEB_INT_002'},
};
