# LOOM WASM Trust/Provenance Receipt v1

Status: normative metadata contract for modules emitted by `compile_wasm`.

## Purpose

LOOM checks `trust`, provenance, role, declassification, seam, recall, and FFI
forms before WebAssembly code generation. The value semantics of these forms
remain transparent after that static check. A generated module now carries the
checker-visible form inventory in a WebAssembly custom section named
`loom.trust.v1`.

The receipt makes the static trust layer inspectable by a host without putting
provenance tags into runtime values or adding a host authorization callback.

## Receipt schema

The custom-section payload is canonical UTF-8 JSON with sorted keys and compact
separators:

```json
{
  "abi_version": 1,
  "checked": true,
  "forms": [],
  "runtime": "transparent-after-static-check",
  "schema": "loom-trust-provenance/v1",
  "source_sha256": "..."
}
```

`forms` is a source-order inventory. Each entry has a `kind` and source span;
recognized kinds are `trust`, `prov`, `by`, `declassify`, `seam`, `seam1`,
`seamN`, `vouch`, `recall`, `repro`, and `ffi`. Relevant literal fields such as
trust spec, anchor, role, author, component, grant, quantum, and foreign name
are included when present.

`source_sha256` is the SHA-256 digest of the exact UTF-8 source string supplied
to `compile_wasm`. It binds the receipt to that source text, but it is not a
signature and does not establish publisher identity.

## Soundness and host boundary

- `checked: true` means this module was emitted only after the LOOM checker
  returned no diagnostics.
- The receipt is metadata, not a proof certificate, operator approval, or
  capability grant. Hosts must not authorize effects from its presence alone.
- Runtime values do not carry provenance tags in ABI v1. `prov`, `by`,
  `declassify`, and `trust` remain static semantics and lower transparently
  after checking.
- `ffi` results remain opaque for trust/provenance. A source-level seam or
  re-vouch is still required and is recorded only as checked metadata here.
- Custom sections are ignored by the WebAssembly core runtime. This addition
  changes no ABI v1 import, export, tagged-value, heap, or effect contract.

WAT output exposes the same boundary through a deterministic comment marker:
`custom section loom.trust.v1` and
`runtime=transparent-after-static-check`.

## Read-only verifier

The public API `loom.verify_wasm_trust_receipt(source, wasm_bytes)` returns a
JSON-like object with `valid`, `receipt`, and `findings`. It checks the WASM
header and section framing, rejects duplicate or malformed receipt sections,
requires canonical JSON, reruns the LOOM source checker, and compares the
receipt byte-for-byte with the expected receipt for that exact source.

`run_wasm` performs this verification before asking Node to instantiate the
module. The verifier does not execute the module and does not establish that a
producer owns the listed authors or that the WASM function body is equivalent
to the source. Those remain separate compiler, signing, and host-boundary
claims.

## Additive v2 compatibility

Receipt v1 remains unchanged. Current modules also carry a separate additive
[`loom.trust.v2` role-policy receipt](wasm_trust_provenance_v2.md) for the
checker-visible `roles`, `sub`, and `needs` clauses. Consumers may verify either
contract independently; the additional custom section changes no WASM ABI v1
runtime contract.
