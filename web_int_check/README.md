# web_int_check

A Dart static-analysis tool, built **on the official `package:analyzer`**,
that finds integer operations whose result changes when shared business code
is compiled to the web. It is built for the "same Dart runs on three targets"
problem:

| target | integer width | bitwise / shift | numbers above 2^53 |
|---|---|---|---|
| native VM / AOT | 64-bit | full 64-bit | exact `int` |
| **dart2wasm (WasmGC)** | **64-bit** | **full 64-bit** | exact `int` |
| **dart2js (JavaScript)** | `double`, 53-bit mantissa | operands/result coerced to **32-bit** | rounded |

The VM and dart2wasm agree. JavaScript is the outlier, and every rule in this
tool is backed by a three-target probe (`example/semantics_probe*.dart`), not
by assumption.

## The attack it addresses

A points-mall app shares order/points/checksum logic between mobile and web.
On the web build an attacker can submit order ids / point values above 2^53:

- the value is rounded on JS but exact on the server, so a tamper checksum
  computed client-side and server-side disagree;
- two distinct ids round to the same JS double (verified:
  `9007199254740995` and `9007199254740997` both become `9007199254740996`),
  so a `Map<int,…>` idempotency table collapses two orders into one key.

## Verified semantics (from the probes)

```
construct                  VM / Wasm            dart2js
-------------------------  -------------------  ---------------------------
literal > 2^53             exact int            COMPILE ERROR
runtime value > 2^53       exact int            rounded double (is int true)
& | ^ ~                    64-bit               signed 32-bit coercion
~0                         -1                   4294967295
(-1) >> 1                  -1                   4294967295
1 << 32                    4294967296           0   (count mod 32)
1 << 63                    -9223372036854775808 0
x % y on a >2^53 value     exact remainder      different rounded remainder
jsonDecode(big number)     exact int            rounded double
JSON id 2^53+3 vs 2^53+5   two map entries      ONE map entry (collision)
```

## Usage

```bash
dart pub get
dart run bin/web_int_check.dart lib/shared --format=text
dart run bin/web_int_check.dart lib --format=json --fatal-severity=warning
dart run bin/web_int_check.dart --config=example/web_int_check.yaml lib
```

Exit code is non-zero when a finding at `--fatal-severity` or higher exists
(default `error`), so it slots into CI.

## Rules

| id | severity | what it catches |
|---|---|---|
| `WEB_INT_001` | error | integer literal > 2^53-1 — dart2js refuses the build |
| `WEB_INT_002` | warning | bitwise op truncated to 32 bits on JS |
| `WEB_INT_003` | warning | shift count/body differs (mod 32 vs mod 64) |
| `WEB_INT_004` | warning | arithmetic whose range provably leaves 2^53 |
| `WEB_INT_005` | warning | JSON-derived number crossing into the `int` world |
| `WEB_INT_006` | warning | runtime `int.parse`/`tryParse` rounded above 2^53 |
| `WEB_INT_007` | warning | `num.toInt/round/floor/ceil/truncate` precision loss |
| `WEB_INT_008` | warning | int hash/map-key/equality exposed to rounding collisions |
| `WEB_INT_009` | info | web-safety cannot be *proved* for a semantics cliff |

## How it avoids false positives on normal code

The tool combines a **mathematical interval domain** (using `BigInt` so
intermediate products keep precision) with a **taint model** and an explicit
**boundary contract**. Reporting is three-tiered:

1. **Hard warning/error** — proven range overflow, untrusted (JSON/parse/num)
   data reaching a sensitive operation, or a build-breaking literal.
2. **Info (009)** — only at a true semantics *cliff* (bitwise, shift, hash)
   where the value range cannot be proved safe. Suppressible by contract.
3. **Silent** — ordinary small-value arithmetic on untainted ints, `double`
   math (identical IEEE semantics everywhere), and forms that are
   *provably platform-independent*, notably:
   - `x & m` with a non-negative constant mask `m <= 0xFFFFFFFF` (the low
     bits JS preserves are exactly the bits the mask keeps);
   - shifts with a constant count < 32 and an in-32-bit body;
   - anything whose operands are provably inside the 32-bit range.

### Boundary contracts

```dart
class webSafeInt { const webSafeInt(); }   // name-based, no package needed

int stableHash(@webSafeInt() int a, @webSafeInt() int b) =>
    (a ^ (b << 5)) & 0x7fffffff;           // no finding: contract accepted
```

`@webSafeInt` asserts the caller guarantees the JS safe range (and 32-bit
fit for hashing). `@webUnsafeInt` does the opposite and forces a finding.
Taint always defeats a safe contract — an annotated value fed JSON data is
still reported.

## Recommended fixes (emitted per finding)

- **ids / order numbers from the server:** send them as JSON **strings**,
  parse with `Int64.parseInt` (package:fixnum) or `BigInt.parse`; reject
  out-of-range numeric payloads rather than truncating.
- **checksums / hashes:** keep them in `Int64` (or `BigInt`) end to end on
  all three targets, or explicitly mask to 32 bits everywhere so the result
  is platform-independent by construction.
- **arithmetic that may exceed 2^53:** `Int64` for values within 64 bits,
  `BigInt` when they can exceed 2^63-1; otherwise range-check inputs and
  fail closed.
- **idempotency keys:** never key a map on a raw JSON number on the web;
  key on the canonical string form or an Int64/BigInt id.

## How it works

`lib/src` separates the concerns:

- `semantics.dart` — the empirically verified cliff constants;
- `range.dart` — `BigInt` interval domain and per-operator transfer functions;
- `taint.dart` — provenance (json / parse / num-conversion / annotated),
  plus the safe-contract flag;
- `visitor.dart` — flow-insensitive fixed-point dataflow over the resolved
  AST, including element summary iteration for loops and reassignments;
- `driver.dart` — analysis-context management, annotation resolution
  (works on both analyzer 6 and 7 element models) and rule decisions;
- `rules.dart` / `finding.dart` / `config.dart` — catalog, output, config.

## Tests

```bash
dart test
```

26 tests cover the interval/taint domains, the full rule catalog against a
vulnerable points-mall fixture, a clean fixture that must produce **zero**
findings (the false-positive control), config overrides and JSON output.
