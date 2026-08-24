# LOOM WIT Component Boundary v0

Status: implemented, normative, deterministic, content-addressed,
non-executable, and non-authorizing.

WIT Component Boundary v0 is the first explicit boundary between a checked LOOM
core WebAssembly module and the WebAssembly Component Model. It supports an
explicit LOOM WASM ABI profile while preserving ABI v1 unchanged. It does not relabel a tagged-`i32`
module as a component and does not claim that a Canonical ABI adapter exists.

## Public API

~~~python
loom.build_wit_component_boundary_v0(
    source, wasm_bytes, package, world, exports=None, abi_version=1,
)

loom.verify_wit_component_boundary_v0(
    boundary, source, wasm_bytes, package, world, exports=None, abi_version=1,
)
~~~

`abi_version` accepts the closed profiles `1` and `2`; every other value fails
closed. The builder returns `loom-wit-component-boundary-validation/v0`. A successful
result contains one `loom-wit-component-boundary/v0` artifact. The verifier
rebuilds that artifact from all exact inputs and compares it closed.

## Why this is a separate layer

LOOM WASM ABI v1 uses tagged `i32` values, module-local heap layouts, exported
linear memory, and eight `env` imports. Component functions instead cross a
shared-nothing boundary through Canonical ABI lift/lower adapters. Treating
those contracts as interchangeable would be unsound.

The Component Model defines WIT worlds as complete import/export descriptions
and Canonical ABI `lift`/`lower` operations as the bridge between component
functions and core functions. WASI 0.2 is the stable WASI release based on this
model. Boundary v0 follows that architecture while stopping before adapter or
component-binary construction:

- [WebAssembly Component Model WIT specification](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md)
- [WebAssembly Component Model Canonical ABI](https://github.com/WebAssembly/component-model/blob/main/design/mvp/CanonicalABI.md)
- [WASI 0.2](https://wasi.dev/releases/wasi-p2)

## Closed v0 projection

Boundary v0 exports checked top-level `defx` functions only when all of these
conditions hold:

1. the complete LOOM source passes the checker;
2. supplied WASM bytes are byte-identical to deterministic compiler output for
   the explicitly selected ABI profile;
3. both `loom.trust.v1` and `loom.trust.v2` receipts verify;
4. the selected function has no declared, performed, or required effect other
   than optional `Pure`;
5. every parameter is a plain value parameter, not higher-order or linear;
6. its name maps uniquely to a lowercase WIT kebab identifier;
7. package and world identities use the closed v0 grammar.

Effectful exports fail with `effectful-export-denied`. This is deliberate:
`IO`, `Net`, `Rand`, `Alloc`, and `FFI` must not silently become ambient WASI
authority. A later capability-projection contract must map each effect to exact
versioned WIT imports before those exports can cross the boundary.

## Generated WIT

For two Pure LOOM functions, v0 emits deterministic WIT of this shape:

~~~wit
package umbra:loom@0.1.0;

world verified-kernel {
  export inc-value: func(request: list<u8>) -> result<list<u8>, list<u8>>;
  export square: func(request: list<u8>) -> result<list<u8>, list<u8>>;
}
~~~

Exports are sorted by canonical WIT name. LOOM `_` maps to WIT `-`; ambiguous,
reserved, non-lowercase, duplicate, and colliding identifiers fail closed.

The byte payload contract is `loom-canonical-json-utf8/v0`, capped at 1 MiB:

- request: canonical UTF-8 JSON `{"args":[...]}`;
- success: canonical UTF-8 JSON `{"ok":VALUE}`;
- failure: canonical UTF-8 JSON
  `{"error":{"code":"...","message":"..."}}`.

Both WIT result branches are `list<u8>`: success and failure therefore use the
same canonical byte-envelope instead of giving the error branch an unrelated
host string encoding. Object keys use Unicode code-point order, whitespace is
forbidden, non-ASCII text is escaped, and numbers are signed i31 only. The v0
value domain is i31, boolean, string, list, record, and the explicit variant
shape `{"$variant":["TAG",VALUE]}`. Closures, resources, effect boxes, floats,
and null are rejected by the future adapter rather than guessed across the
boundary.

The transport is represented in WIT as `list<u8>` so it is a real Canonical
ABI value rather than a leaked LOOM heap pointer. Boundary v0 defines the
envelope contract but does not yet implement the adapter that validates,
decodes, invokes, and re-encodes it.

## Evidence object

The artifact content-addresses:

- exact UTF-8 source bytes;
- exact deterministic core-WASM bytes;
- LOOM WASM ABI version;
- the eight required ABI v1 adapter imports;
- exact generated WIT source and package/world identity;
- selected LOOM/WIT export names, arities, and Pure effect projection;
- the canonical JSON transport contract;
- lifecycle and capability-projection state.

`boundary_sha256` hashes canonical JSON for the complete object without that
field. Verification independently rebuilds the object and rejects both a hash
mismatch and any semantic mismatch.

## Honest lifecycle

Every valid v0 artifact carries:

~~~json
{
  "component_binary": "absent",
  "adapter": "required",
  "executable": false,
  "authorization": "none"
}
~~~

It therefore proves a stable, reviewable component boundary design for exact
LOOM bytes. It does not prove that a component can already be instantiated,
that WIT was packaged into a component binary, that WASI capabilities were
granted, that Canonical ABI lifting succeeded, or that any code executed.

## Additive executable boundary

[`Exact Component Adapter Artifact v0`](component_adapter_v0.md) now implements
the bounded JSON transport, bridges collision-free LOOM Tagged Value ABI v2 to
separate Canonical ABI memory, packages a real zero-import component binary,
and binds its bytes back to this boundary. Boundary v0 itself deliberately
continues to say `component_binary: absent`: it describes an exact requested
surface, while the additive artifact proves one implementation. Effect-to-WASI
projection remains a later explicit gate. Neither layer may mutate this v0
schema or infer authority from valid evidence.
