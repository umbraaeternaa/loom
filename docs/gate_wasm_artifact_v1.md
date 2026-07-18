# LOOM Gate WASM artifact binding and evidence v1

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

## Gate evidence and receipt v2

`loom.build_wasm_artifact_evidence(manifest, source, wasm_bytes)` rechecks the
binding and emits the closed `loom-gate-wasm-artifact-evidence/v1` envelope:

```json
{
  "schema": "loom-gate-wasm-artifact-evidence/v1",
  "kind": "wasm-artifact",
  "status": "pass",
  "manifest_sha256": "...",
  "binding": {"...": "..."},
  "binding_sha256": "..."
}
```

`loom.build_wasm_artifact_receipt(manifest, observation, source, wasm_bytes)`
keeps the existing `loom-gate-receipt/v1` contract unchanged and emits
`loom-gate-receipt/v2` only after the v1 observation receipt and the exact
source/WASM evidence both pass. `loom.verify_wasm_artifact_receipt(...)`
recomputes the complete result and rejects tampered evidence or receipt fields.

`loom.build_gate_workflow_v2(manifest)` exposes the explicit artifact lane and
places `artifact-evidence` before the final receipt step. The workflow is a
route, not an execution engine; the trusted host must supply the exact source
and WASM bytes to the v2 receipt API.

## Boundary

- The binding is content-addressing, not a signature and not publisher identity.
- It does not execute WASM, read host state, claim an operator approval, or
  grant capabilities.
- It does not prove that arbitrary WASM function bodies are semantically
  equivalent to source; it proves only the declared source/receipt/binary/hash
  relationship.
- Existing closed Gate manifest v1/v2 schemas are unchanged. A future Gate
  workflow may require this binding as an explicit evidence or artifact lane.
- Gate observation v1 and receipt v1 remain unchanged. The v2 artifact lane
  is a separate contract and does not turn self-reported string evidence into
  a binary proof.
- Operator signing remains a separate Gate approval contract and must not be
  replaced by this envelope.
