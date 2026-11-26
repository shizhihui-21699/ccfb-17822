/// A Snowflake-style 64-bit id generator: the ids are legitimately wider than
/// 2^53, so every operation on them is a real portability bug even though no
/// attacker is involved.
class SnowflakeIds {
  static const int epochShift = 22;
  static const int nodeBits = 12;
  static const int sequenceBits = 10;

  int _sequence = 0;

  int next(int timestampMs, int nodeId) {
    _sequence = (_sequence + 1) & ((1 << sequenceBits) - 1);
    final id = (timestampMs << epochShift) |
        (nodeId << sequenceBits) |
        _sequence;
    return id;
  }

  /// Extracting the node back out of an id: a 64-bit mask and shift.
  int nodeOf(int id) => (id >> sequenceBits) & ((1 << nodeBits) - 1);

  int timestampOf(int id) => id >> epochShift;
}
