# LOOM checked assembly envelope v0

Status: reserved, validated, and deliberately non-executable.

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

## v0 registry

| Target | Opcode | Arguments | Result | Effects | Executable |
| --- | --- | ---: | --- | --- | --- |
| `wasm` | `i31.add` | 2 | tagged i31 | `Pure` | No |

`i31.add` is present only to pin validation and the shape of the future
registry. A correctly formed expression is still rejected as reserved.

## Rejection rules

The checker rejects:

- missing or quoted targets;
- targets other than `wasm`;
- missing, quoted, or unregistered opcodes;
- an argument count that differs from the registry;
- every otherwise valid v0 expression, because execution is not enabled yet.

Runtime and backend entry points fail closed as defense in depth. No v0 form
may inject raw WAT, WebAssembly bytes, imports, memory access, control flow, or
host calls.

## Gate for v1 execution

An opcode may become executable only after its tagged input/output semantics,
effect row, interpreter behavior, portable-backend behavior, WASM lowering,
WAT mirror, published bundle parity, and negative security cases are all pinned
by the citadel. Expanding an opcode's authority requires explicit review of the
WebAssembly ABI version.
