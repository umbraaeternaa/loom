# LOOM Gate WASM artifact binding v1

Status: read-only, deterministic, advisory, and non-authorizing.

`loom.build_wasm_artifact_binding(manifest, source, wasm_bytes)` binds one
validated Gate manifest to one exact LOOM source string, one emitted WASM byte
sequence, and its `loom.trust.v1` receipt. The result schema is
`loom-gate-wasm-artifact-validation/v1`.

## Binding shape

```json
{
  "schema": "loom-gate-wasm-artifact/v1",
  "manifest_sha256": "...",
  "source_sha256": "...",
  "wasm_sha256": "...",
  "trust_receipt_sha256": "...",
  "wasm_abi_version": 1
}
```

The manifest digest is the existing canonical `manifest_sha256`. The source and
WASM digests are SHA-256 over the exact UTF-8 source bytes and exact WASM bytes.
The trust receipt digest is over canonical JSON for the verified
`loom.trust.v1` receipt. The ABI version is copied from that receipt.

`loom.verify_wasm_artifact_binding(binding, manifest, source, wasm_bytes)`
revalidates the manifest, trust receipt, all hashes, schema, and closed binding
fields. A changed source, binary, receipt, manifest, or binding is rejected.

## Boundary

- The binding is content-addressing, not a signature and not publisher identity.
- It does not execute WASM, read host state, claim an operator approval, or
  grant capabilities.
- It does not prove that arbitrary WASM function bodies are semantically
  equivalent to source; it proves only the declared source/receipt/binary/hash
  relationship.
- Existing closed Gate manifest v1/v2 schemas are unchanged. A future Gate
  workflow may require this binding as an explicit evidence or artifact lane.
- Operator signing remains a separate Gate approval contract and must not be
  replaced by this envelope.
