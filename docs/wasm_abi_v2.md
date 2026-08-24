# LOOM WebAssembly Tagged Value ABI v2

Status: implemented, normative, opt-in, and additive.

Tagged Value ABI v2 is emitted by `compile_wasm_v2` and identified by the
immutable exported raw global `loom_abi_version == 2`. ABI v1 remains the
default of `compile_wasm`, `emit_wat`, and `run_wasm`; existing v1 module bytes
and host contracts are unchanged.

ABI v2 exists to remove three v1 identity collisions that made a sound
Canonical ABI adapter impossible: integer zero versus false versus an empty
record, integer one versus true, and ordinary records versus closures.

## Public API

~~~python
wasm = loom.compile_wasm_v2(source)
wat = loom.emit_wat_v2(source)
value, output = loom.run_wasm_v2(source, call)

loom.verify_wasm_trust_receipt_abi_v2(source, wasm)
loom.verify_wasm_trust_receipt_v2_abi_v2(source, wasm)
loom.verify_wasm_source_equivalence_abi_v2(source, wasm)
loom.verify_wasm_component_bridge_v0_abi_v2(source, wasm)

loom.build_wit_component_boundary_v0(
    source, wasm, package, world, exports, abi_version=2,
)
~~~

Every verifier recompiles or reconstructs against ABI v2 explicitly. A v1
verifier rejects v2 bytes, and a v2 verifier rejects v1 bytes. The version is
part of receipt and bridge evidence rather than a host-side assumption.

## Value encoding

Every LOOM parameter and result is one tagged `i32`.

| Value | Encoding |
| --- | --- |
| Signed i31 integer `n` | `n << 1`; low bit is `0` |
| Boolean false | Reserved immediate `1` |
| Empty list | Reserved immediate `3` |
| Boolean true | Reserved immediate `5` |
| Empty record | Reserved immediate `7` |
| Heap pointer at address `p` | `p | 1`; valid pointers are at least `9` |

The signed i31 range and modulo-`2^31` arithmetic law are unchanged from ABI
v1. Compiler-generated comparison results use the boolean immediates. Numeric
operations and conditions normalize false to tagged integer zero and true to
tagged integer one before applying the existing LOOM computational semantics.
Identity functions and boundary transport do not normalize them, so their type
identity survives crossing the module boundary.

A host decoder must test even integers and the four reserved odd immediates
before treating any odd value as a pointer. It must reject an unrecognized odd
immediate below `9`.

## Heap differences from ABI v1

Kinds `1` through `6` retain their v1 layouts for lists, records, variants,
effect boxes, resources, and strings. Two details are versioned:

1. A kind-2 record chain terminates with the empty-record immediate `7`, not
   raw zero. The record value `7` represents the empty record without an
   allocation.
2. A closure uses a distinct kind-7 chain. Its cells have the same 16-byte
   field layout as record cells, but each cell's raw kind is `7`, and the chain
   terminates with the immediate `7`.

### Closure field, kind 7, 16 bytes

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `7` |
| 4 | Raw field ID |
| 8 | Tagged field value |
| 12 | Tagged next closure-field pointer or empty-record immediate `7` |

The first closure field is still module-local `code`; following fields are the
captured environment. A conforming boundary may identify and reject a closure
without confusing it with application data. Code and field IDs remain local to
one compilation and are not interchange IDs.

## Component Bridge v0 under ABI v2

The five `loom_component_*` exports and the fixed one-page heap policy remain
unchanged. Their validators use the selected profile:

- `loom_component_cons` accepts `3` as the empty-list tail;
- `loom_component_record` accepts `7` as the empty-record tail;
- false `1`, true `5`, and empty record `7` are valid tagged values;
- closure kind `7` is not accepted as Canonical JSON input data;
- malformed pointers, wrong tail kinds, cycles beyond 2048 cells, unknown
  kinds, and out-of-bounds objects fail closed.

This is value transport only. It grants no capability, invokes no LOOM export,
and does not authorize an action.

## Host decoding order

A conforming ABI v2 host must:

1. require `loom_abi_version == 2`;
2. decode even values as signed i31 integers;
3. decode `1`, `3`, `5`, and `7` as false, empty list, true, and empty record;
4. bounds-check every other odd value as a pointer at or above `9`;
5. decode only documented object kinds and require the profile-specific chain
   terminator;
6. keep the 2048-cell finite traversal guard;
7. reject closure, resource, or effect values when the target transport does
   not admit them.

## Compatibility and migration

ABI v2 is not a reinterpretation of v1 bytes. Hosts must dispatch by the
exported version and must never guess from a value. In particular, raw `1`,
`5`, and `7` have different meanings from v1, record chains have a different
terminator, and closure kind `7` does not exist in v1.

Migration is explicit: compile with `compile_wasm_v2`, verify with ABI v2
verifiers, and bind the WIT boundary with `abi_version=2`. Rollback is equally
explicit because the default v1 functions remain untouched. ABI v2 introduces
no new host import, ambient authority, `memory.grow`, or WASI capability.

## Non-claims

ABI v2 supplies collision-free value identity needed by a component adapter.
It is not itself a Component Model binary, Canonical ABI adapter, package
ecosystem, signature, proof of compiler soundness, or operator authorization.
Those layers require separate artifacts and gates.
