# LOOM WASM Compiler Profile v1

Status: normative host-built compiler identity contract.

## Purpose

Source Equivalence v1 proves that a WASM module is the complete deterministic
output of the compiler currently inside the verifier's trust boundary. Compiler
Profile v1 identifies the exact compiler bytes supplied by a trusted host.

The compiler does not self-attest. A host reads one closed implementation
surface and calls:

```python
loom.build_wasm_compiler_profile(surface, components)
loom.verify_wasm_compiler_profile(profile, surface, components)
```

`components` maps canonical component paths to exact `bytes` or `bytearray`
values. The standalone-safe API performs no filesystem access.

## Closed surfaces

`modular-python` requires exactly:

- `loom.py`
- `loom_parse.py`
- `loom_checker.py`
- `loom_bounds.py`
- `loom_recursion.py`
- `loom_frontend.py`
- `loom_wasm.py`

`standalone-python` requires exactly `docs/loom.py`. The two surfaces have
different exact fingerprints. Published-bundle parity establishes behavioral
alignment; it does not pretend that their implementation bytes are identical.

## Profile schema

The builder returns `loom-wasm-compiler-profile-validation/v1`. A valid result
contains this closed profile:

```json
{
  "schema": "loom-wasm-compiler-profile/v1",
  "compiler": "loom-wasm",
  "surface": "modular-python",
  "package_version": "0.1.0",
  "wasm_abi_version": 1,
  "components": [
    {"path": "loom.py", "byte_length": 0, "sha256": "..."}
  ],
  "profile_sha256": "..."
}
```

Components are emitted in canonical surface order. `profile_sha256` hashes the
canonical JSON profile before that field is added. Missing, extra, non-byte, or
changed components fail closed. The verifier also rejects unknown profile
fields, schema drift, self-hash tampering, and a profile built from different
component bytes.

## Host collector and packaging

The modular host collector is available without changing the public runtime:

```console
python3 -m loom_provenance --root . --surface modular-python
python3 -m loom_provenance --root . --surface standalone-python
```

`pyproject.toml` includes the complete modular compiler closure. The Citadel
builds a real wheel from an isolated temporary checkout and verifies that every
declared module is present in the archive. It then imports the compiler directly
from that wheel and compiles a real LOOM source to WASM.

## Boundary

- A profile is content identity, not a signature or publisher identity.
- It does not execute WASM, grant capabilities, or claim operator approval.
- Git revision is external observed evidence and is not inferred from component
  bytes.
- Profile v1 is implementation-level and artifact-independent. A future
  versioned Gate compiler-evidence contract may bind `profile_sha256` to one
  exact `wasm_sha256` and Source Equivalence result.
- Existing Gate schemas, trust receipts, and WASM ABI v1 are unchanged.
