# Integer semantics, target by target

This is the reference the checker is built from. Every row was verified by
compiling the same source three ways (`dart run`, `dart compile js`,
`dart compile wasm`) and comparing output; see `tool/verify_*_model.dart` and
`test/cross_target_e2e_test.dart`.

Let `MAX = 2^63-1`, `MIN = -2^63`, `SAFE = 2^53-1`.

## Representation

| | VM | Wasm | JS |
|---|---|---|---|
| type of `int` | boxed/unboxed 64-bit | 64-bit | `double` |
| exact integer range | `[MIN, MAX]` | `[MIN, MAX]` | `[-2^53, 2^53]` |
| literals outside range | compile error | compile error | compile error if not exactly a double |

## Operators

| expression | VM / Wasm | JS |
|---|---|---|
| `a + b`, `a - b`, `a * b` | wraps at 64 bits | IEEE-754 double; exact while the result is ≤ 2^53 |
| `-a` | wraps | double negation |
| `a ~/ b` | truncates toward zero | `(a/b)\|0` fast path inside int32, else truncates toward zero |
| `a % b` | Euclidean (`-7 % 3 == 2`) | Euclidean, matches the VM |
| `a << n` | 64-bit; `n >= 64` → `0` | `(ToInt32(a) << (n & 31)) >>> 0`; `n > 31` → `0` |
| `a >> n` | 64-bit arithmetic | `n > 31` → `0` if `a >= 0`; else `(ToInt32(a) >> min(n,31)) >>> 0` |
| `a >>> n` | 64-bit logical | `n > 31` → `0`; else `ToUint32(a) >>> n` |
| `a & b`, `a \| b`, `a ^ b` | 64-bit | `ToUint32(ToInt32(a) op ToInt32(b))` ∈ `[0, 2^32)` |
| `~a` | 64-bit | `ToUint32(~ToInt32(a))` ∈ `[0, 2^32)` |
| `a.toUnsigned(w)` | mask to `w` bits | `a & ((1<<w)-1)`, capped at 32 bits |
| `a.bitLength` | up to 64 | computed from a 32-bit window for big values |
| `a.hashCode` | VM hash | `0x1FFFFFFF & a`, else mantissa mix |
| negative shift amount | `ArgumentError` | `ArgumentError` |

## `dart:typed_data`

| | VM | Wasm | JS |
|---|---|---|---|
| `Int64List`, `Uint64List` | works | works | **`UnsupportedError`** |
| `ByteData.get/setInt64`, `get/setUint64` | works | works | **`UnsupportedError`** |
| `Uint32List`, `Int32List`, `Float64List` | works | works | works |

## What makes a finding provable

A divergence is reported as an **error** when it is provable for the values the
code can actually hold:

* the literal is outside the exactly-representable set (compile error on JS);
* a constant expression folds to different values (`1 << 40`, `2^53 + 1`);
* a shift amount is a constant outside `[0, 31]`;
* a bitwise operand is a constant outside int32 (`x & 0x100000000` is 0 on JS);
* the value is attacker controlled (its magnitude is chosen by the caller).

It is reported as a **warning** when it is provable for some inputs but not all
(a parameter whose range the checker could not bound, only at `--strictness
strict` for plain parameters).

It is **not reported** when the range is confined to where JS and the VM agree:
values inside int32 for bitwise/shift, inside 2^53 for arithmetic, and
non-negative operands for `>>`/`>>>`.
