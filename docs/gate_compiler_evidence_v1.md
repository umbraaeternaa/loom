# LOOM Gate WASM Compiler Evidence v1

Status: normative read-only compiler-to-artifact evidence contract.

## Purpose

Source Equivalence v1 proves that exact WASM bytes are the deterministic output
of the compiler inside the verifier's trust boundary. Compiler Profile v1
identifies exact compiler component bytes. Compiler Evidence v1 binds those two
claims to the same Gate manifest and artifact without changing either contract.

The public APIs are:

```python
loom.build_wasm_compiler_evidence(manifest, source, wasm_bytes, components)
loom.verify_wasm_compiler_evidence(evidence, manifest, source, wasm_bytes, components)
```

`components` is supplied by a trusted host as the exact closed compiler surface.
The API performs no filesystem collection. The modular verifier can issue only
`modular-python` evidence. The standalone verifier can issue only
`standalone-python` evidence. A caller cannot select a different surface.

## Validation and evidence schemas

The result schema is
`loom-gate-wasm-compiler-evidence-validation/v1`. A valid result contains this
closed `loom-gate-wasm-compiler-evidence/v1` object:

```json
{
  "schema": "loom-gate-wasm-compiler-evidence/v1",
  "kind": "wasm-compiler",
  "status": "pass",
  "surface": "modular-python",
  "compiler_profile": {"schema": "loom-wasm-compiler-profile/v1"},
  "profile_sha256": "...",
  "artifact_binding": {"schema": "loom-gate-wasm-artifact/v1"},
  "artifact_binding_sha256": "...",
  "source_equivalence": {"schema": "loom-wasm-source-equivalence/v1", "valid": true},
  "evidence_sha256": "..."
}
```

The builder performs these checks in order:

1. Rebuild Compiler Profile v1 from the exact host-supplied component bytes and
   the surface fixed by the running implementation.
2. Rebuild Artifact Binding v1, which revalidates the manifest, both trust
   receipts, exact source and WASM bytes, and Source Equivalence v1.
3. Record Source Equivalence v1 explicitly and require compiler-profile ABI to
   equal artifact-binding ABI.
4. Hash canonical evidence fields into `evidence_sha256`.

The verifier rebuilds the complete expected evidence from all exact inputs. It
rejects unknown or missing fields, unsupported schema, surface substitution,
non-canonical data, evidence hash tampering, component drift, manifest drift,
source drift, and WASM drift.

## Surface identity

Behavioral parity does not make implementation identities interchangeable. The
modular and standalone compilers may emit byte-identical WASM while retaining
different exact profile hashes. Fixed-surface issuance prevents a modular
recompilation from being labeled as evidence for standalone compiler bytes, or
the reverse.

## Boundary

- The builder recompiles source for equivalence but does not execute the supplied WASM.
- Evidence is content addressing, not proof that the compiler is semantically
  correct or free of defects.
- The trusted host owns component collection and must supply the bytes of the
  implementation it actually loaded. This contract does not independently
  prove Python loader provenance.
- Evidence is not a signature, publisher identity, or operator approval.
- It grants no capability and does not infer identity from a Git revision.
- Receipt v3, workflow v3, and Playground integration are not part of v1.
- Existing Gate manifest, observation, artifact, receipt, workflow, approval,
  and WASM ABI schemas are unchanged.
