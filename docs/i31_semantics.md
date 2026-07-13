# LOOM i31 integer semantics

Status: normative for the interpreter, portable Python backend, portable
JavaScript backend, WAT output, WebAssembly binary backend, checked `asm`
intrinsics, and ABI v1 host decoding.

## Domain

A LOOM integer is a signed i31 value:

- minimum: `-1073741824` (`-2^30`)
- maximum: `1073741823` (`2^30 - 1`)
- cardinality: `2147483648` (`2^31`)

Integer literals outside that range are rejected before execution. They are not
truncated, saturated, host-coerced, or backend-defined.

## Canonical wraparound

Every integer-producing arithmetic operation canonicalizes its result with the
same signed modulo-`2^31` rule:

```text
i31(n) = ((n - (-1073741824)) mod 2147483648) + (-1073741824)
```

This means:

- `1073741823 + 1` becomes `-1073741824`
- `-1073741824 - 1` becomes `1073741823`
- `1073741823 * 2` becomes `-2`
- `1073741823 * 1073741823` becomes `1`

The operation is deterministic and portable. No LOOM backend may use host
integer overflow, saturation, arbitrary precision leakage, or JavaScript
floating-point rounding as the user-visible integer semantics.

## Backend obligations

The interpreter and portable Python backend call the shared `_i31` rule after
integer arithmetic.

The portable JavaScript backend uses the same signed i31 projection for
addition and subtraction, and uses `Math.imul` for multiplication before the
projection so the result follows 32-bit integer arithmetic before returning to
the i31 domain.

The WebAssembly backend uses tagged `i32` values. Arithmetic must produce the
same signed i31 value observable from the interpreter:

- `+` and checked `asm wasm i31.add` lower tagged operands directly through
  `i32.add`.
- `-` and checked `asm wasm i31.sub` lower tagged operands directly through
  `i32.sub`.
- `*` and checked `asm wasm i31.mul` decode one tagged operand with
  arithmetic shift-right by one, multiply with `i32.mul`, and return a tagged
  i31 value.
- comparisons produce LOOM booleans as tagged i31 integers: `0` for false and
  `1` for true at the decoded language level.

## ABI v1 boundary

ABI v1 encodes signed i31 integer `n` as the even tagged `i32` value `n << 1`.
The low bit is `0`. Heap pointers have low bit `1`, so integers and pointers
cannot alias.

A host decodes an even tagged integer with arithmetic shift-right by one. ABI
metadata such as `loom_abi_version` is raw `i32`, not a tagged LOOM value.

Changing any of the domain, literal rejection rule, wraparound equation,
tagged encoding, or host decoding rule requires a new ABI version.

## Citadel pin

The citadel pins this contract with a cross-backend numeric oracle. The same
source program is executed through the interpreter, portable Python,
JavaScript, and WebAssembly paths, and must produce:

```text
{"add": -1073741824, "sub": 1073741823, "mul": -2, "wide": 1}
```

The checked `asm` tests also pin the WAT strategy for `i31.add`, `i31.sub`,
`i31.mul`, `i31.eq`, `i31.lt_s`, and `i31.gt_s`.
