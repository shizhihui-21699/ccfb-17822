# web_int_checker

Finds Dart integer arithmetic whose result changes when the same code is
compiled to JavaScript — shifts, bitwise operators, hashes, oversized literals,
and attacker-controlled magnitudes — and tells you how to fix each one with
`Int64` or `BigInt`.

```console
$ dart run web_int_checker lib
lib/src/order.dart
     41:10   error  Attacker-controlled value (from json['orderId'] reads a
                    field out of untrusted JSON) reaches
                    `(hash << 5) - hash + points`. Addition/subtraction is
                    exact on JS only while the result stays below 2^53; on the
                    VM it wraps at 64 bits.
        [web_untrusted_integer_magnitude]
        │ hash = (hash << 5) - hash + points;
        fix: Use `Int64` (package:fixnum) for 64-bit wrap-around semantics, or
             `BigInt` if values may exceed 64 bits.
```

---

## Why this exists

Dart has one source language but three integer models:

| target                | `int` representation              | shifts | bitwise ops | overflow |
|-----------------------|-----------------------------------|--------|-------------|----------|
| VM / AOT (mobile)     | signed 64-bit two's complement    | 64-bit | 64-bit      | wraps at 64 bits |
| `dart compile wasm`   | signed 64-bit two's complement    | 64-bit | 64-bit      | wraps at 64 bits |
| `dart compile js`     | IEEE-754 double (53-bit exact)    | **32-bit** | **32-bit** (`ToInt32`/`ToUint32`) | silently loses precision above 2^53 |

The same `int` expression is therefore three different functions. A checksum
written once and shared between a Flutter mobile build and a Flutter web build
can compute different values on the two platforms — and, worse, two distinct
64-bit identifiers can collapse to the same double on the web, which is how
duplicate-order detection gets bypassed.

`web_int_checker` is built on the official `package:analyzer`, so it sees
resolved types and can follow values across functions and constructor calls
instead of grepping for operators.

**Every semantic rule in this tool was validated against real compiler output**
— the VM, `dart compile js` and `dart compile wasm` — not assumed. See
[Verification](#verification).

---

## What it reports

| Code | Meaning | Typical fix |
|------|---------|-------------|
| `web_integer_literal_not_representable` | An integer literal `dart2js` cannot represent exactly. The web build **fails**. | `Int64.parseInt('…')` / `BigInt.parse('…')` |
| `web_integer_constant_differs` | A constant expression that folds to a different value on JS (`1 << 40`, `2^53 + 1`). | Same, or restructure to stay in range |
| `web_integer_arithmetic_loses_precision` | `+ - * ~/ %` where the result provably leaves the 53-bit exact range. | `Int64` for wrap-around, `BigInt` for unbounded |
| `web_shift_truncates` | Shifts that are 32-bit on JS, or that shift by more than 31. | `Int64` |
| `web_bitwise_truncates_32bit` | `& \| ^ ~` on values that are not confined to 32 bits. | `Int64` |
| `web_hash_code_not_portable` | `int.hashCode`, `Object.hash`, `bitLength` — different on every runtime. | Explicit checksum over canonical text, or `package:crypto` |
| `web_untrusted_integer_magnitude` | Attacker-controlled input reaches a platform-dependent operation. | `Int64`/`BigInt` **and** validate the input range |
| `web_integer_key_collision` | A wide integer used as a `Map` key, `Set` member or identity token. | Key by canonical string or `Int64` |
| `web_double_to_int` | `toInt()` on a value outside the exact range (VM saturates, JS does not). | Check magnitude first |

Each finding carries the concrete per-target values where they are known, e.g.

```
targets: VM=-3750763034362895579, Wasm=-3753034362895579, JS=compile error
```

---

## Install and run

```yaml
# pubspec.yaml
dev_dependencies:
  web_int_checker:
    path: ../web_int_checker   # or a git/pub dependency
```

```console
# whole package, human output
dart run web_int_checker lib

# machine output for CI
dart run web_int_checker --format json lib  > report.json
dart run web_int_checker --format sarif lib > report.sarif   # GitHub code scanning
```

Exit status is `1` when any **error** is found, `0` otherwise (warnings fail
only with `--fatal-warnings`, any finding fails with `--fail-on-info`).

### As an analyzer plugin

The same engine also runs inside `dart analyze` / `flutter analyze` / the IDE:

```yaml
# analysis_options.yaml (at the package root)
plugins:
  web_int_checker:
    path: ../web_int_checker
    diagnostics:
      web_integer_portability: true   # arithmetic, shifts, bitwise
      web_integer_constants: true     # literals and constant folding
      web_integer_hashes: true        # hashCode, Object.hash
      web_integer_untrusted: true     # attacker-controlled magnitudes
      web_integer_conversion: true    # double -> int
```

Findings then appear inline as required to be fixed, and can be suppressed the
usual way: `// ignore: web_untrusted_integer_magnitude`.

---

## Precise, not noisy

The hard requirement is that **normal small-number arithmetic must not be
reported**. The checker is an abstract interpreter over integer *ranges plus
provenance*, so it reports an operator only when the JavaScript result can
actually differ:

* A loop counter, an index, a `length`, a page number, money in cents, or a bit
  flag has a range the tool can reason about — no finding.
* A value that comes from `jsonDecode`, `int.parse`, `as int` on `dynamic`, or a
  parameter of a public entry point is **attacker controlled** — always a
  finding, at `error` severity, with a taint trace.
* A value whose magnitude is simply unknown (an ordinary `int` parameter) is a
  finding only at `--strictness strict`, because reporting every `int` would be
  useless on real business code.

This is the whole design: the incident's checksum is reported **because the id
came from JSON**, not because it contains a `<<`.

### Strictness

| Level | Reports |
|-------|---------|
| `minimal` | Only provable problems: unrepresentable literals, constants that fold differently, attacker-controlled values. |
| `standard` (default) | Adds provably-wide values (constant shifts > 31, constant masks > 32 bits, integer keys). |
| `strict` | Also reports bitwise/shift/hash on values of *unknown* magnitude. Use for shared business-logic packages. |

---

## The incident, end to end

`examples/incident_repro.dart` is the reported scenario: a points mall with a
shared checksum, an idempotency store keyed by the raw order id, and a points
conversion. Running the checker on it produces five `error`s. Compiling the
two versions and running them on the VM and on JS shows why:

```
                      VM                          JS
checksum             32                          0
distinct ids equal   false                       true     ← duplicate-order bypass
```

The recommended rewrite (`Int64.parseInt` constants, `Int64` arithmetic) is
verified to produce **identical** output on the VM, dart2js and Wasm. That
verification is a test (`test/cross_target_e2e_test.dart`), so the advice cannot
silently rot.

---

## Fixing findings

### Use `Int64` when the values are 64-bit by design

Checksums, snowflake ids, hashes and bitmasks are 64-bit on purpose. `Int64`
from [`package:fixnum`](https://pub.dev/packages/fixnum) has 64-bit `==`,
`hashCode`, shifts and bitwise operators on **every** target.

```dart
import 'package:fixnum/fixnum.dart';

// Wrap-around 64-bit arithmetic, identical on VM, Wasm and JS.
final Int64 _mask31 = Int64.parseInt('2147483647');
final Int64 _fnvOffset = Int64.parseInt('-3750763034362895579'); // 0xcbf29ce484222325

Int64 checksum(Int64 orderId, Int64 points) {
  var h = orderId;
  h = (h << 5) - h + points;
  return h & _mask31;
}
```

Two gotchas the checker's fixes call out explicitly:

* **`Int64(0xcbf29ce484222325)` does not compile for the web** either — the
  literal is still the problem. Use `Int64.parseInt('…')` (decimal or with
  `radix: 16`).
* `Int64` has no `>>>`; use `toUnsigned(64)` where the VM would use a logical
  shift.

### Use `BigInt` when the values may exceed 64 bits

```dart
BigInt widen(BigInt x) => x * BigInt.two;
```

`BigInt` is exact everywhere, but it allocates; prefer `Int64` for fixed-width
64-bit work.

### For ids used as keys

```dart
// Before: two distinct ids alias on the web.
final Map<int, String> seen = {};
seen[orderId] = result;

// After: the canonical text is the identity.
final Map<String, String> seen = {};
seen[orderId.toString()] = result;
```

---

## Three targets, three semantics

### `dart compile js`

`int` is a double. The consequences, confirmed against real dart2js output:

* **Bitwise** `& | ^ ~ << >> >>>` coerce through `ToInt32`/`ToUint32`. Results
  of `& | ^ ~ << >>>` are always non-negative and fit in 32 bits;
  `>>` on a negative receiver sign-fills and then becomes unsigned.
* **Shift amount > 31** returns `0` for `<<`/`>>>` (the amount is masked mod 32
  in JS terms); `>>` clamps.
* **`~/` and `%`** are exact while the operands are ≤ 2^53; `%` is Euclidean,
  which matches the VM.
* **Literals** above 2^53 that are not exactly representable are a **compile
  error**.
* **`hashCode`** of an `int` is `0x1FFFFFFF & value`; of an `int` above 2^31 it
  is a mantissa mix — different from the VM's hash.
* **`dart:typed_data`** `Int64List`, `Uint64List` and the 64-bit `ByteData`
  accessors throw `UnsupportedError`.

### `dart compile wasm`

Identical to the VM: signed 64-bit, wrapping, 64-bit shifts and bitwise. This is
why the tool emits only `js` as a diverging target — the common mistake is to
treat "web" as one runtime, when Wasm is not the problem.

### The VM / AOT

Signed 64-bit two's complement. `1 << 64 == 0`, `-1 >> 64 == -1`,
`-1 >>> 64 == 0`, and arithmetic wraps.

---

## Commands

```console
# Analyze everything under lib/
dart run web_int_checker lib

# Treat these functions as attacker-facing (their int params become untrusted)
dart run web_int_checker --entry-point ValidateOrder --entry-point SubmitCart lib

# Trust a parameter that the tool cannot tell is bounded
dart run web_int_checker --trusted-parameter clampQuantity lib

# Shared business-logic package: treat every int parameter as untrusted
dart run web_int_checker --trust-library lib

# Skip generated files, emit SARIF for GitHub code scanning
dart run web_int_checker --exclude '**/*.g.dart' --format sarif lib
```

Taint sources the tool recognises automatically:

* `jsonDecode(...)` and any value read out of a `Map<String, dynamic>` that
  came from it, including `json['id'] as int`
* `x as int` where `x` is `dynamic` or `Object?`
* `int.parse(...)` / `int.tryParse(...)`
* `int.fromEnvironment(...)`
* parameters of functions named `main`, `handle*`, `validate*`, `submit*`,
  `process*`, and parameters of `fromJson`-style constructors
* anything annotated `@untrusted` / `@userInput` / `@external`

Taint propagates through locals, fields, constructor initialisers, factory
constructors, collection elements and user-function calls, so a value that
enters via JSON and reaches a checksum four calls away is still caught.

---

## Verification

The semantic model is checked against the real compilers, not just asserted:

```console
dart run tool/verify_vm_model.dart    # model vs the running Dart VM
dart run tool/verify_js_model.dart    # model vs a real `dart compile js` build
dart test                             # unit + cross-target end-to-end tests
```

`tool/verify_js_model.dart` generates 13,611 sampled operations, compiles them
with dart2js, runs them under Node, and compares each result with the model.
`test/cross_target_e2e_test.dart` compiles the same source for the VM and JS and
asserts the bug reproduces and the recommended fix does not.

---

## CI example

```yaml
- name: Cross-platform integer check
  run: dart run web_int_checker --format sarif --exclude '**/*.g.dart' lib > web_int.sarif

- name: Upload results
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: web_int.sarif
```

---

## Design notes

* **One engine, two front ends.** The CLI (`bin/`) and the analyzer plugin
  (`lib/main.dart`) both call `UnitAnalyzer`; they cannot drift apart.
* **Abstract interpretation, not pattern matching.** Ranges let the tool stay
  quiet on bounded code; provenance (taint) lets it be loud on attacker input.
* **Constants are folded twice**, once exactly and once under the JS model, so
  `1 << 40` is reported as a fact rather than a guess.
* **Findings are de-duplicated** per node and per code, and only the outermost
  operator of a chain is reported, so one expression yields one finding.

The known limitation: without developer input the tool cannot know that an
`int` parameter is bounded. That is what `--trusted-parameter`,
`--entry-point` and `--trust-library` are for — and why unknown-magnitude
parameters are silent at the default strictness.
