# LOOM Effectful Component Result Binding v0

Status: implemented, normative, host-only, terminal, signed-evidence-bound, and
non-authorizing.

Effectful Component Result Binding v0 closes the evidence gap between a
Component spawn and the ordinary Action Result/Attestation lifecycle. It does
not execute a process, consume a ledger row, or create authority. It verifies
three already completed artifacts and emits one content-addressed join:

1. `loom-effectful-component-host-execution/v0`;
2. `loom-action-capsule-result/v0`;
3. the externally signed DSSE `loom-action-result-attestation-predicate/v0`.

## Public API

```python
loom.build_effectful_component_result_binding_v0(
    host_execution,
    action_result,
    action_result_attestation,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key,
)

loom.validate_effectful_component_result_binding_v0(
    binding,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key,
)
```

Both operations are verification-only. They accept public keys, never private
signing material. The validator performs no process execution or filesystem IO.

## Closed chain

The builder independently invokes the existing validators for Host Execution,
Action Result, and Action Result Attestation. It then requires:

- byte-for-byte equality between the host record's nested Bounded Execution and
  the execution embedded in the terminal Action Result;
- equality of `action_execution_sha256` across both records;
- exact Approval, request, invocation binding, Claim, and Mediation links;
- equality between Component host status and terminal Action outcome;
- an Action Result that is exactly the Result inside the verified signed DSSE
  predicate, not merely a Result with a similar status;
- the trusted attester key identity and Gate Receipt v4 hash recovered from the
  verified attestation.

The resulting `loom-effectful-component-result-links/v0` object binds the
Effectful execution binding, Component spawn measurement, Component bytes,
private launch, Action execution, terminal outcome, Action Result, DSSE
envelope, Gate Receipt, operator Approval, and attester key.
It is embedded by the terminal
`loom-effectful-component-result-binding/v0` record together with all three
validated source artifacts.

## Tamper and resource resistance

The outer binding is canonical JSON and content-addressed with SHA-256. The
validator rebuilds the expected binding from independently validated nested
artifacts; recomputing only the outer hashes cannot substitute a Component,
execution, Result, receipt, or attestation. Replacing and fully rehashing the
DSSE envelope still fails signature verification.

The binding narrows the more general Action Attestation verifier to one closed
DSSE envelope, one trusted-key signature, and canonical standard Base64. This
prevents unsigned envelope extensions, signature ordering, or alternate Base64
spellings from creating multiple binding identities for the same signed bytes.

Before canonical serialization, the host-only module bounds JSON depth, node
count, cumulative text, and final byte size. Unknown or missing fields are
rejected. These limits keep an untrusted evidence object from turning pure
validation into an unbounded parser or hashing workload.

## Terminal semantics

The lifecycle is closed and exact:

```json
{
  "schema": "loom-effectful-component-result-lifecycle/v0",
  "terminal": true,
  "authorization": "none",
  "execution_repeated": false,
  "effectful_execution_closed": true,
  "signed_result_evidence": true,
  "remaining_evidence": []
}
```

`remaining_evidence: []` means that this record already embeds the signed
Action Result evidence and its Gate Receipt. It does not mean that the output is
semantically correct, safe, or endorsed. It proves which verified Component was
spawned, under which operator-authorized Action chain, what bounded process
outcome was observed, and which attester signed that exact terminal Result.

The API is absent from `docs/loom.py` and the Playground. Browser code has no
operator verification boundary, private Action ledger, host sandbox, or reason
to construct production execution receipts.

For portable authenticated export, the additive
[Effectful Component Execution Attestation v0](effectful_component_execution_attestation_v0.md)
signs this exact terminal binding as an external DSSE/in-toto Statement. The
binding remains complete without that optional export; the outer attestation
adds signer-authenticated distribution, not execution authority.
