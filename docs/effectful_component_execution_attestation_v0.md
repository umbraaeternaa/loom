# LOOM Effectful Component Execution Attestation v0

Status: implemented, normative, host-only, externally signed, terminal,
portable, and non-authorizing.

Effectful Component Execution Attestation v0 exports one complete terminal
Component execution chain as a signed DSSE/in-toto artifact. It signs the
already verified
[`loom-effectful-component-result-binding/v0`](effectful_component_result_binding_v0.md),
not a new description reconstructed from logs.

The transition performs no process execution, does not consume a ledger row,
and never receives private signing material.

## Public API

```python
loom.prepare_effectful_component_execution_attestation_v0(
    result_binding,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key,
    result_attester_public_key,
    execution_attester_public_key,
    attested_at_unix_ms,
)

loom.build_effectful_component_execution_attestation_v0(
    result_binding,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key,
    result_attester_public_key,
    execution_attester_public_key,
    attested_at_unix_ms,
    signature,
)

loom.verify_effectful_component_execution_attestation_v0(
    envelope,
    result_binding,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key,
    result_attester_public_key,
    execution_attester_public_key,
)
```

`prepare` returns canonical payload and DSSE PAE bytes. An external issuer signs
those exact bytes. `build` verifies that signature before constructing the
envelope. `verify` checks signature bytes before parsing the signed statement,
then independently rebuilds the expected statement from the supplied evidence.

## Signed subjects

The in-toto Statement uses:

```text
https://umbraaeternaa.github.io/loom/attestation/effectful-component-execution/v0
```

Its five subjects are exact SHA-256 identities for:

1. the terminal Effectful Component Result Binding;
2. the Component Host Execution record;
3. the Action Result;
4. the executed Component bytes;
5. Gate Receipt v4.

The `loom-effectful-component-execution-attestation-links/v0` predicate also
binds the private Component spawn measurement, launch, Action execution,
operator Approval, nested Action Result attestation, nested result-attester
key, and outer execution-attester key.

## Canonical DSSE boundary

The outer envelope is deliberately narrower than a general multisignature DSSE
container. It requires:

- exactly the fields `payloadType`, `payload`, and `signatures`;
- exactly one signature from the supplied trusted execution-attester key;
- canonical standard Base64 for payload and signature;
- strict duplicate-free canonical UTF-8 JSON;
- bounded payload bytes, signature bytes, JSON nodes, and JSON depth.

Unsigned envelope extensions, alternate Base64 spellings, malformed Unicode,
signature substitution, signed-but-rebound Result Binding content, and stale
external verification inputs all fail closed.

## Trust statement

The v0 lifecycle is honest about what the outer signature proves:

```json
{
  "schema": "loom-effectful-component-execution-attestation-lifecycle/v0",
  "terminal": true,
  "evidence": "signed-effectful-component-execution",
  "authorization": "none",
  "execution_repeated": false,
  "nested_signature_verified": true,
  "portable_verification": true,
  "independent_attester_claim": false,
  "slsa_level_claim": "none"
}
```

The result-attester and execution-attester keys may be the same. Therefore v0
does not claim independent quorum merely because two signature layers exist.
The outer signature authenticates the portable join; it does not certify
semantic correctness, safety of output, an organizational identity, or a SLSA
level.

This API is absent from `docs/loom.py` and the Playground. It belongs to the
trusted host evidence lane, while browser LOOM remains an execution and
inspection surface without operator key custody.
