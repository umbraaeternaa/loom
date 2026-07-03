# LOOM checked assembly envelope v0

Status: closed and executable for explicitly registered pure intrinsics only.

## Purpose

The `asm` surface is a future backend-owned escape hatch. It must not turn raw
text into authority that bypasses LOOM's effect checker, tagged-value ABI, or
cross-backend honesty. Version 0 therefore defines only a closed envelope:

```lisp
(asm wasm OPCODE ARG...)
```

The target and opcode are symbols, never quoted text. The opcode registry owns
arity, value types, effects, and lowering. Source code cannot self-declare those
properties.

Each registry entry is the implementation's single contract record:

- `inputs` and `result` describe the LOOM value boundary;
- `effects` is the checker-owned effect row;
- `portable_op` selects interpreter/Python/JavaScript semantics;
- `wasm_rhs` declares whether the second tagged operand stays boxed or must be
  decoded before the binary instruction;
- `wasm_result` declares whether the instruction already returns a tagged value
  or whether a raw result must be encoded for LOOM;
- `wasm_opcode` selects the binary instruction byte;
- `wat_opcode` selects the human-readable instruction.

## v0 registry

| Target | Opcode | Arguments | Result | Effects | Executable |
| --- | --- | ---: | --- | --- | --- |
| `wasm` | `i31.add` | 2 | tagged i31 | `Pure` | Yes |
| `wasm` | `i31.sub` | 2 | tagged i31 | `Pure` | Yes |
| `wasm` | `i31.mul` | 2 | tagged i31 | `Pure` | Yes |
| `wasm` | `i31.eq` | 2 | tagged boolean i31 | `Pure` | Yes |
| `wasm` | `i31.lt_s` | 2 | tagged boolean i31 | `Pure` | Yes |
| `wasm` | `i31.gt_s` | 2 | tagged boolean i31 | `Pure` | Yes |

`i31.add` evaluates both arguments, adds them with LOOM's signed i31
modulo-`2^31` wraparound, and returns one tagged i31. The interpreter and
portable Python/JavaScript backends emulate that exact contract; WASM lowers
the already-tagged operands to one `i32.add`, and WAT mirrors it visibly.

`i31.sub` follows the same value and effect contract, subtracting the second
argument from the first with identical modulo-`2^31` wraparound. WASM lowers
the tagged operands directly to `i32.sub`.

`i31.mul` first decodes the second tagged operand with an arithmetic right
shift, then multiplies it by the still-tagged first operand. This keeps exactly
one tag factor in the result: `(2a) * b = 2ab`.

`i31.eq` compares the tagged operands directly. WebAssembly returns raw `0` or
`1`, so the registered result strategy shifts it left and returns LOOM's tagged
boolean integer `0` or `2` at the binary boundary.

`i31.lt_s` compares tagged operands with signed `i32.lt_s`. Multiplying both i31
values by the positive tag factor preserves their signed order; the raw boolean
result is then encoded through the same registered result strategy as `i31.eq`.

`i31.gt_s` closes the signed comparison pair with `i32.gt_s`. It uses the same
order-preserving tagged operands and registered boolean result encoding.

## Rejection rules

The checker rejects:

- missing or quoted targets;
- targets other than `wasm`;
- missing, quoted, or unregistered opcodes;
- an argument count that differs from the registry;

Runtime and backend entry points independently validate the envelope as defense
in depth. No v0 form may inject raw WAT, WebAssembly bytes, imports, memory
access, control flow, or host calls.

## Gate for registry expansion

An opcode may become executable only after its tagged input/output semantics,
effect row, interpreter behavior, portable-backend behavior, WASM lowering,
WAT mirror, published bundle parity, and negative security cases are all pinned
by the citadel. Expanding an opcode's authority requires explicit review of the
WebAssembly ABI version.
