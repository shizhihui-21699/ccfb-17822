/// A checksum over a wide identifier: intentionally 64-bit.
const int _offsetBasis = 0xcbf29ce484222325;
const int _prime = 0x100000001b3;

int fnv1a(int value) {
  var hash = _offsetBasis;
  var remaining = value;
  while (remaining != 0) {
    hash = (hash ^ (remaining & 0xFF)) * _prime;
    remaining = remaining >> 8;
  }
  return hash;
}
