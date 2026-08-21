# LOOM Component Bridge Extension v0

Status: implemented additive extension for modules emitted by `compile_wasm`.
It is not a Component Model adapter, execution approval, signature, or source
capability grant.

## Purpose

LOOM ABI v1 uses tagged `i32` values and a private monotonic heap. A separate
component adapter cannot safely construct strings, lists, records, or variants
by writing that heap directly. Bridge v0 exposes five bounded constructors that
all use the compiler's existing `$reserve` allocator and object layouts:

```text
loom_component_alloc_bytes(raw-length) -> raw-pointer
loom_component_make_string(raw-pointer, raw-length) -> tagged-value
loom_component_cons(tagged-value, tagged-list-tail) -> tagged-value
loom_component_record(raw-field-id, tagged-value, tagged-record-tail) -> tagged-value
loom_component_variant(raw-tag-id, tagged-value) -> tagged-value
```

The helpers import or invoke no host authority. They trap on negative or
oversized lengths, heap exhaustion, a second pending byte allocation, a byte
range not issued by the same instance, malformed UTF-8, malformed tails,
unsupported tagged heap kinds, and unknown module-local field or tag IDs.
Effect boxes and resource markers are not accepted as component input values.
List and record tails are traversed completely, reject malformed links, and
trap after 2048 cells so a forged cycle cannot make validation unbounded.

`alloc_bytes` permits one pending range at a time. `make_string` requires that
exact pointer and length, validates strict RFC 3629 UTF-8, reserves the kind-6
header, increments `loom_heap_strings`, and only then publishes the tagged
object. Traps do not authorize fallback behavior.

## Exact evidence section

Every newly compiled module carries exactly one custom section named
`loom.component-bridge.v0`. Its canonical JSON payload uses schema
`loom-component-bridge/v0` and binds:

- the exact UTF-8 source SHA-256;
- the SHA-256 of deterministic core bytes with this bridge section omitted;
- ABI version and compiler profile;
- sorted name-to-ID field and variant-tag maps;
- exact bridge export signatures and fixed memory/string limits.

The omitted-section hash avoids a circular self-hash. A future adapter artifact
must bind the full final core-module hash externally.

`loom.verify_wasm_component_bridge_v0(source, wasm_bytes)` performs strict
single-section parsing, canonical JSON and closed-key checks, recomputes the
omitted-section binding, recompiles the source deterministically, and requires
byte identity. The result schema is
`loom-component-bridge-validation/v0`.

## Non-claims

Bridge v0 does not produce a WebAssembly Component, does not implement
Canonical ABI lowering, does not expose WASI, does not approve execution, and
does not make effectful or higher-order exports component-safe. Those remain
separate operator-gated work.
