# LOOM Portable Execution Evidence Bundle v0

Status: implemented, normative, host-only, terminal, portable, offline
verifiable, externally anchored, and non-authorizing.

Portable Execution Evidence Bundle v0 packages one already signed
[Effectful Component Execution Attestation v0](effectful_component_execution_attestation_v0.md)
with every exact public input needed to verify it on another machine. The
bundle carries the Result Binding, manifest, observation, source and WASM
bytes, compiler surfaces, and the three public keys used by the nested trust
chain.

It does not execute the program, repeat the Component launch, authorize an
action, or receive private signing material.

## Public API

```python
loom.build_effectful_component_execution_evidence_bundle_v0(
    envelope,
    result_binding,
    manifest, observation, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    approval_public_key,
    result_attester_public_key,
    execution_attester_public_key,
)

loom.verify_effectful_component_execution_evidence_bundle_v0(
    bundle,
    expected_execution_attester_key_sha256,
)
```

The builder first performs the full Execution Attestation verification. It
then encodes exact source, WASM, and compiler-component bytes using canonical
standard Base64, records their SHA-256 identities, closes every object schema,
and content-addresses the complete bundle as
`loom-effectful-component-execution-evidence-bundle/v0`.

## Offline CLI verifier

```console
loom execution-verify execution-bundle.json \
  --execution-key-sha256 EXPECTED_LOWERCASE_SHA256
```

Use `--format json` for a machine-readable verdict. The verifier accepts one
bundle file up to 64 MiB, rejects duplicate JSON keys and non-finite numbers,
decodes bounded canonical Base64, checks all byte hashes, and reruns the entire
nested verification chain. It performs no host execution and no network IO.

## External trust anchor

An embedded public key can prove that bundle contents are internally
consistent, but it cannot prove whose key it is. Verification therefore
requires an **external execution-attester key pin** obtained independently of
the bundle. The CLI refuses a missing, malformed, or mismatched pin.

The external pin is the SHA-256 identity returned by the verified Execution
Attestation contract. Rehashing altered bundle content cannot bypass the
signature or replace this external trust root.

## Lifecycle and non-claims

The closed lifecycle records:

```json
{
  "authorization": "none",
  "execution_repeated": false,
  "private_key_material": false,
  "embedded_key_identity_claim": false,
  "slsa_level_claim": "none"
}
```

The bundle proves a byte-exact, signature-checked evidence chain relative to
the externally pinned execution-attester key. It does not prove organizational
identity, semantic correctness of output, independent quorum, or a SLSA level.

This API and `execution-verify` are absent from `docs/loom.py` and the
Playground. They belong to the trusted host evidence lane; the browser bundle
does not receive operator keys or host-only terminal evidence.
