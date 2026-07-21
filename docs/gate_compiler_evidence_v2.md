# LOOM Gate WASM Compiler Evidence v2

Status: normative, deterministic, read-only, advisory, and non-authorizing
builder/verifier attribution contract.

## Purpose

Source Equivalence v1 intentionally recompiles with the compiler inside the
verifier trust boundary. Compiler Evidence v1 binds that current verifier to an
artifact, but a byte mismatch alone cannot distinguish artifact drift from an
honest change between the builder compiler and verifier compiler.

Compiler Evidence v2 is additive. It records the builder's exact Compiler
Profile v1 and requires verification to compare exact builder and verifier
profiles before invoking Source Equivalence v1. It does not change Source
Equivalence v1, Compiler Evidence v1, Receipt v3, or Workflow v3.

The public APIs are:

```python
loom.build_wasm_compiler_evidence_v2(
    manifest, source, wasm_bytes, builder_components
)
loom.verify_wasm_compiler_evidence_v2(
    evidence, manifest, source, wasm_bytes,
    builder_surface, builder_components, verifier_components
)
```

The builder surface is fixed by the implementation issuing evidence. The
verifier surface is fixed by the implementation checking evidence.
`builder_surface` is explicit trusted-host input so evidence cannot select its
own provenance identity. Both component maps contain exact bytes; core LOOM
performs no filesystem collection.

## Evidence and validation

The builder returns `loom-gate-wasm-compiler-evidence-validation/v2`. A valid
result contains this closed `loom-gate-wasm-compiler-evidence/v2` object:

```json
{
  "schema": "loom-gate-wasm-compiler-evidence/v2",
  "kind": "wasm-compiler",
  "status": "pass",
  "builder_surface": "modular-python",
  "builder_profile": {"schema": "loom-wasm-compiler-profile/v1"},
  "builder_profile_sha256": "...",
  "artifact_binding": {"schema": "loom-gate-wasm-artifact/v1"},
  "artifact_binding_sha256": "...",
  "builder_source_equivalence": {
    "schema": "loom-wasm-source-equivalence/v1",
    "valid": true
  },
  "evidence_sha256": "..."
}
```

Validation also returns a closed `attribution` object with builder/verifier
surface, both profile hashes, and relation `same`, `different`, or `unknown`.
Invalid evidence is returned as `null`; structured attribution remains
available for diagnosis without treating the invalid envelope as trusted.

## Fail-closed order

1. Validate the closed evidence shape, canonical data, and evidence hash.
2. Rebuild and verify the builder profile from trusted-host builder surface and
   exact historical builder component bytes.
3. Rebuild the verifier profile from the running implementation's fixed
   surface and exact verifier component bytes.
4. If valid profiles differ, return only `wasm-compiler-drift` for attribution;
   do not report `wasm-source-mismatch`.
5. Only if profiles are identical, rebuild Artifact Binding v1 and Source
   Equivalence v1. Changed source can fail the existing trust-receipt checks;
   a changed WASM body with intact valid receipts is reported as
   `wasm-source-mismatch`.
6. Require compiler/artifact ABI agreement and exact canonical v2 evidence.

Malformed evidence or profile input reports its structural finding before a
drift decision. A bare profile hash is never sufficient builder provenance.

## Surface identity

`modular-python` and `standalone-python` are different exact identities even
when they emit byte-identical WASM. Cross-surface verification therefore fails
with `wasm-compiler-drift`. Same-surface component-byte changes do the same.

## Boundary

- Verification recompiles only after exact profiles match; it never executes
  the supplied WASM.
- Exact component bytes provide content identity, not compiler correctness,
  Python loader provenance, publisher identity, or a signature.
- The trusted host must supply the exact bytes actually loaded and retain
  historical builder bytes out of band.
- Compiler Profile v1 does not identify the Python interpreter, standard
  library, native runtime, or a hermetic build container.
- Evidence grants no capability and does not replace operator approval.
- Receipt v3 and Workflow v3 continue to compose unchanged Compiler Evidence
  v1. Compiler Evidence v2 requires a future additive Receipt v4 / Workflow v4
  contract before composition.
- Existing Gate manifest, observation, artifact, receipt, workflow, approval,
  trust receipt, Source Equivalence v1, Compiler Evidence v1, and WASM ABI
  schemas remain unchanged.
