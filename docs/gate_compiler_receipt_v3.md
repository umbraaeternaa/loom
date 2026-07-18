# LOOM Gate WASM Compiler Receipt v3

Status: normative, deterministic, advisory, and non-authorizing composition contract.

## Purpose

Receipt v2 binds a Gate observation to exact source and verified WASM artifact
bytes. Compiler Evidence v1 separately binds those bytes to the running
verifier's exact closed compiler surface. Receipt v3 composes both contracts so
one receipt cannot attribute an artifact to a different compiler or attribute
compiler evidence to a different artifact.

The public APIs are:

```python
loom.build_wasm_compiler_receipt(manifest, observation, source, wasm_bytes, components)
loom.verify_wasm_compiler_receipt(receipt, manifest, observation, source, wasm_bytes, components)
loom.build_gate_workflow_v3(manifest)
```

`components` remains explicit trusted-host input containing the exact bytes of
the compiler surface actually loaded. Core LOOM performs no filesystem
collection and callers cannot select a compiler surface different from the
running implementation.

## Receipt contract

The builder returns `loom-gate-receipt-v3-validation/v1`. A valid result
contains a closed `loom-gate-receipt/v3` object:

```json
{
  "schema": "loom-gate-receipt/v3",
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
  "compiler_evidence": {"schema": "loom-gate-wasm-compiler-evidence/v1"},
  "receipt_sha256": "..."
}
```

The builder first rebuilds Receipt v2 and Compiler Evidence v1 from all exact
inputs. It then requires both cross-links:

```text
compiler_evidence.artifact_binding == artifact_evidence.binding
compiler_evidence.artifact_binding_sha256 == artifact_evidence.binding_sha256
```

Only after those checks pass does it hash all canonical v3 fields into
`receipt_sha256`. The verifier rebuilds the complete expected receipt and
rejects unknown, missing, changed, or non-matching fields, including a receipt
whose outer hash was recomputed after nested evidence tampering.

## Workflow v3

`loom.build_gate_workflow_v3(manifest)` extends Workflow v2 with the compiler
surface fixed by the running implementation and the explicit route:

```text
artifact-evidence -> compiler-evidence -> compiler-receipt
```

For operator-required actions these steps remain before the existing `finish`
step. The workflow is descriptive only. It does not collect component bytes,
execute WASM, invoke tools, sign evidence, approve an action, or finalize an
operator claim.

## Boundary

- Receipt v3 is content-addressed evidence, not a signature or publisher identity.
- Compiler identity does not prove compiler correctness or formal soundness.
- Observation v1 remains an advisory input; trusted host collection and signed
  operator approval remain separate contracts.
- Existing manifest v1/v2, observation v1, receipt v1/v2, workflow v1/v2,
  approval, trust receipt, compiler profile, artifact, and WASM ABI schemas are
  unchanged.
- Playground issuance and a signed in-toto/SLSA envelope are outside this
  contract and require separate explicit integration.
