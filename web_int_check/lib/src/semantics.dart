/// Empirically verified integer semantics of the three Dart compilation
/// targets. Every number in this file was confirmed by running the same Dart
/// source on the VM, `dart compile js` (node) and `dart compile wasm`
/// (WasmGC in node). See `example/semantics_probe.dart`.
///
/// Summary of the probe results:
///
/// | construct                         | VM / Wasm (64-bit)      | dart2js (JS)              |
/// |-----------------------------------|-------------------------|---------------------------|
/// | literal > 2^53                    | exact int               | *compile error*           |
/// | runtime value > 2^53 (parse/JSON) | exact 64-bit int        | rounded double, `is int`  |
/// | `+ - * %` on >2^53 values         | exact/wrapping 64-bit   | IEEE-754 rounding         |
/// | `& | ^ ~`                         | full 64-bit             | operands & result on 32b  |
/// | `<< n` / `>> n` / `>>> n`         | shift count mod 64      | count mod 32, 32-bit body |
/// | `~0`                              | -1                      | 4294967295                |
/// | `(-1) >> 1`                       | -1                      | 4294967295                |
library;

/// 2^53: JavaScript `Number.MAX_SAFE_INTEGER`. Above this magnitude a JS
/// double cannot distinguish consecutive integers (ULP becomes >= 2).
const int maxSafeInteger = 9007199254740991;

/// 2^53 itself is exactly representable; the first unrepresentable positive
/// integer is 2^53 + 1.
const int firstUnsafeInteger = 9007199254740992;

/// 2^32 - 1: result width of every JS bitwise operator.
const int jsUint32Mask = 0xFFFFFFFF;

/// 2^31 - 1: largest positive value after JS signed-32-bit coercion.
const int jsInt32Max = 0x7FFFFFFF;

/// -(2^31): smallest value after JS signed-32-bit coercion.
const int jsInt32Min = -2147483648;

/// Shift counts on JS are taken modulo 32 (`x << 32` is `x << 0`).
const int jsShiftModulo = 32;

/// Shift counts on the VM/Wasm are taken modulo 64.
const int nativeShiftModulo = 64;
