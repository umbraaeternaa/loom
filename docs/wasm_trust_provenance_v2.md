# LOOM WASM Trust/Provenance Receipt v2

Status: normative additive metadata contract for modules emitted by
`compile_wasm`.

## Purpose and compatibility

Receipt v2 extends the inspectable static trust layer with the role-policy forms
that influence checker decisions: `roles`, `sub`, and `needs`. It is emitted in
a WebAssembly custom section named `loom.trust.v2` beside `loom.trust.v1`.

Receipt v1 remains unchanged. Receipt v2 changes no WASM ABI v1 import, export,
tagged-value, heap, effect, or runtime-value contract. A consumer that only
understands v1 can continue to ignore the v2 custom section.

## Receipt schema

The payload is canonical UTF-8 JSON with sorted keys and compact separators:

```json
{
  "abi_version": 1,
  "checked": true,
  "forms": [],
  "runtime": "transparent-after-static-check",
  "schema": "loom-trust-provenance/v2",
  "source_sha256": "..."
}
```

`forms` is a source-order inventory. It contains every v1 form kind plus:

- `roles`, with the source-declared `required` role list;
- `sub`, with its `lower` and `higher` roles;
- `needs`, with its capability `effect` and required `role`.

Every form also carries its source span. `source_sha256` is the SHA-256 digest
of the exact UTF-8 source string supplied to `compile_wasm`.

## Boundary

- Receipt v2 is deterministic checker evidence, not a signature.
- It is not a proof certificate, operator approval, identity claim, capability
  grant, or runtime authorization input.
- Runtime values remain provenance-free in ABI v1; role-policy forms lower
  transparently after the static check.
- Custom sections are ignored by the WebAssembly core runtime.

The full WASM bytes, including both trust sections, are covered by the existing
artifact binding's `wasm_sha256`. Artifact binding still records the unchanged
v1 receipt digest for backward compatibility, while its builder and verifier
fail closed unless both receipt versions match the supplied source.

## Read-only verifier

`loom.verify_wasm_trust_receipt_v2(source, wasm_bytes)` returns a JSON-like
object with `valid`, `receipt`, and `findings`. It validates section framing,
rejects duplicate or malformed v2 sections, requires canonical JSON, reruns the
source checker, and compares the payload byte-for-byte with the expected v2
receipt. It does not execute the module.

`run_wasm` verifies both receipt v1 and receipt v2 before instantiation.
