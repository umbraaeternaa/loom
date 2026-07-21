# LOOM Gate WASM Compiler Receipt v4 and Workflow v4

Status: normative, deterministic, advisory, and non-authorizing composition
contract with builder/verifier attribution.

## Purpose

Artifact Receipt v2 binds observation and exact artifact evidence. Compiler
Evidence v2 separately records the exact builder compiler and lets a verifier
compare its own exact compiler profile before source/artifact attribution.
Receipt v4 composes those contracts without changing Receipt v3 or any earlier
schema.

The public APIs are:

```python
loom.build_wasm_compiler_receipt_v4(
    manifest, observation, source, wasm_bytes, builder_components
)
loom.verify_wasm_compiler_receipt_v4(
    receipt, manifest, observation, source, wasm_bytes,
    builder_surface, builder_components, verifier_components
)
loom.build_gate_workflow_v4(manifest)
```

The builder surface is fixed by the implementation issuing the receipt. During
verification, builder surface and exact historical builder bytes are explicit
trusted-host inputs; verifier surface remains fixed by the running
implementation. Core LOOM performs no filesystem collection.

## Receipt and validation

The builder returns `loom-gate-receipt-v4-validation/v1`. A valid result
contains this closed `loom-gate-receipt/v4` object:

```json
{
  "schema": "loom-gate-receipt/v4",
  "advisory": true,
  "manifest_sha256": "...",
  "policy": "operator-codex-cloud/v1",
  "policy_decision": "operator-required",
  "agent": {"id": "codex", "role": "code"},
  "result": "completed",
  "repositories": [],
  "files_changed": [],
  "actions_observed": [],
  "evidence": [],
  "artifact_evidence": {"schema": "loom-gate-wasm-artifact-evidence/v1"},
  "compiler_evidence": {"schema": "loom-gate-wasm-compiler-evidence/v2"},
  "compiler_evidence_sha256": "...",
  "receipt_sha256": "..."
}
```

The immutable receipt stores builder facts only. Its validation result carries
`compiler_attribution` with builder/verifier surfaces, both profile hashes, and
relation `same`, `different`, or `unknown`. A future verifier identity is never
inserted into historical receipt content.

## Cross-links

The builder and verifier require:

```text
receipt.manifest_sha256 == artifact_evidence.manifest_sha256
receipt.manifest_sha256 == compiler_evidence.artifact_binding.manifest_sha256
compiler_evidence.artifact_binding == artifact_evidence.binding
compiler_evidence.artifact_binding_sha256 == artifact_evidence.binding_sha256
receipt.compiler_evidence_sha256 == compiler_evidence.evidence_sha256
compiler_evidence.builder_profile.wasm_abi_version == artifact_evidence.binding.wasm_abi_version
```

The complete canonical receipt is then bound by `receipt_sha256`.

## Fail-closed verification order

1. Validate the closed outer receipt, advisory flag, canonical data, and
   receipt hash.
2. Verify embedded Compiler Evidence v2 from exact builder/verifier inputs.
3. If valid profiles differ, stop with structured attribution and only
   `wasm-compiler-drift`; do not add source or generic receipt mismatch.
4. Only if profiles match, verify Artifact Evidence v1 and rebuild Artifact
   Receipt v2 from the exact observation, source, and WASM.
5. Require all cross-links and compare the complete expected v4 receipt.

Malformed receipt/evidence input reports structural findings before drift.
Drift retains precedence when the receipt is structurally valid even if the
supplied source, WASM, or observation also changed.

## Workflow v4

`loom.build_gate_workflow_v4(manifest)` returns
`loom-gate-workflow/v4` with exact builder and verifier component-input
requirements and the route:

```text
artifact-evidence -> compiler-evidence -> compiler-receipt -> finish
```

The compiler step uses `build_wasm_compiler_evidence_v2`; the receipt step uses
`build_wasm_compiler_receipt_v4`. For operator-required actions these remain
before `finish`. Accepted, rejected, and invalid manifests preserve existing
Gate routing behavior.

Workflow v4 is descriptive only. Initial v4 does not add a CLI command or
Playground route and does not collect components, execute WASM, invoke tools,
sign, approve, claim, or finalize an operator action.

## Boundary

- Receipt v4 is content-addressed evidence, not a signature, publisher
  identity, authorization, or proof of compiler correctness.
- Observation v1 remains host-supplied advisory evidence.
- Exact historical builder bytes must remain available out of band.
- A newer exact compiler profile rejects the historical receipt fail-closed;
  archival acceptance requires future hermetic or signed provenance, not a
  relaxed v4 mode.
- Receipt v1-v3, Workflow v1-v3, Source Equivalence v1, Compiler Evidence
  v1/v2, approvals, claims, executor lifecycle, trust receipts, and WASM ABI v1
  remain unchanged.
- Action Capsule, Approval v2, CLI/Playground v4 exposure, and signed
  in-toto/SLSA envelopes require separate explicit integration.
