# LOOM WASM Source Equivalence v1

Status: normative read-only verification contract.

## Purpose

Trust receipts bind static metadata to source, but metadata alone cannot prove
that a supplied WebAssembly function body was emitted from that source.
`loom.verify_wasm_source_equivalence(source, wasm_bytes)` closes that boundary
by recompiling the exact source with the current deterministic LOOM compiler
and comparing the complete WASM byte sequence.

The result has this stable JSON-like shape:

```json
{
  "schema": "loom-wasm-source-equivalence/v1",
  "valid": true,
  "source_sha256": "...",
  "expected_wasm_sha256": "...",
  "actual_wasm_sha256": "...",
  "findings": []
}
```

`valid` is true only when `compile_wasm(source)` succeeds and every emitted byte
matches `wasm_bytes`. The expected and actual SHA-256 fields make a mismatch
inspectable without returning another copy of the binary. Invalid source or
non-byte WASM input fails closed.

## Gate integration

`build_wasm_artifact_binding` and `verify_wasm_artifact_binding` first verify
the v1 and v2 trust receipts, then require Source Equivalence v1. A changed code
section with untouched valid receipts is rejected with `wasm-source-mismatch`.
Artifact binding, evidence, receipt, manifest, observation, workflow, and WASM
ABI schemas remain unchanged.

## Boundary

- Verification recompiles but does not execute the supplied module.
- A valid result proves byte identity with the output of the current LOOM
  compiler implementation for the exact source string.
- It does not prove that the compiler implementation is semantically correct,
  that a publisher owns an identity, or that an operator approved execution.
- Compiler-version or deterministic-code-generation changes may produce a new
  expected hash; verification is intentionally against the implementation in
  the verifier's trust boundary.
- The contract grants no capability and changes no WASM ABI v1 runtime value,
  import, export, heap, or effect rule.
