/// Functions that demonstrably operate on values above 2^53 where the caller
/// passes constants: the checker can prove the divergence.
int widen(int x) => x << 40;

int mix(int x) => (x * 0x100000000) + 1;

int highBitMask(int x) => x & 0x100000000;
