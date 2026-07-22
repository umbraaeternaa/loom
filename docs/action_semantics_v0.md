# LOOM Action Semantics v0

Status: normative, deterministic, pure, advisory, and non-authorizing semantic
binding contract.

## Purpose

Action Semantics v0 binds one exact checked LOOM entrypoint to one complete
Tool Binding v0 and builder-issued Compiler Evidence v2. It is the first
Action Capsule prerequisite that proves a semantic authority ceiling instead
of merely collecting hashes.

The public APIs are:

```python
loom.build_action_semantics_v0(
    manifest, tool_binding, tool_input, source, wasm_bytes,
    builder_components, entrypoint
)
loom.verify_action_semantics_v0(
    semantics, manifest, tool_binding, tool_input, source, wasm_bytes,
    builder_surface, builder_components, verifier_components, entrypoint
)
```

Core LOOM performs no filesystem collection, network access, tool or WASM
execution, signing, approval, claim, ledger write, or capability grant.

## Exact v0 profile

The manifest must be `loom-gate-manifest/v1`, normalize to exactly the
`process` action, and evaluate to `operator-required`.

Tool input is the closed portable JSON object:

```json
{"action":"process","manifest_sha256":"<exact manifest hash>"}
```

The complete supplied Tool Binding must verify as `local-process/v1`, authority
`urn:loom:host:operator-gate`, operation `process`, with its complete Interface
Binding, exact input hash, and exact process output contract.

The entire source profile is one top-level form:

```loom
(defx main (FFI!)
  (fn ()
    (seamN 1 (FFI)
      (ffi "operator-gate" "<tool-binding-sha256>"))))
```

Comments and whitespace may differ, but parsed structure is closed. V0 permits
no extra function, entrypoint argument, effect, expression, role clause,
handler, nested seam, recursion, `depthN`, dynamic component, or second FFI
call. The quoted FFI argument is the exact Tool Binding hash, not tool payload,
credential, token, or capability.

The accepted `loom-verdict/v1` must report exactly one function and:

```text
declared == performed == required == capabilities == [FFI]
```

The sole entrypoint-scoped source limit is one `FFI` request through
`seamN/v1`; both maximum and counted maximal-path quantity are exactly one.

## Validation and object

Both APIs return `loom-action-semantics-validation/v0`. Invalid results carry
`semantics: null`, structured findings, and diagnostic `compiler_attribution`.

A valid result contains this closed `loom-action-semantics/v0` object:

```json
{
  "schema": "loom-action-semantics/v0",
  "advisory": true,
  "manifest_sha256": "...",
  "policy": "operator-codex-cloud/v1",
  "policy_decision": "operator-required",
  "tool_binding": {"schema": "loom-tool-binding/v0"},
  "tool_binding_sha256": "...",
  "compiler_evidence": {"schema": "loom-gate-wasm-compiler-evidence/v2"},
  "compiler_evidence_sha256": "...",
  "artifact_binding_sha256": "...",
  "entrypoint": {
    "function": "main",
    "arguments": [],
    "arguments_sha256": "...",
    "reachable_functions": ["main"]
  },
  "checker_verdict": {"schema": "loom-verdict/v1"},
  "checker_verdict_sha256": "...",
  "effect_contract": {
    "declared": ["FFI"],
    "performed": ["FFI"],
    "required": ["FFI"],
    "capabilities": ["FFI"]
  },
  "source_limits": {
    "schema": "loom-action-source-limits/v0",
    "scope": "entrypoint-invocation",
    "effect_meters": [
      {"effect":"FFI","maximum":1,"counted_max_path":1,"mechanism":"seamN/v1"}
    ],
    "recursive_calls": null
  },
  "target_mediation": {
    "schema": "loom-action-target-mediation/v0",
    "profile": "local-process-ffi-binding/v0",
    "foreign_component": "operator-gate",
    "source_binding_literal": "...",
    "protocol": "local-process/v1",
    "authority": "urn:loom:host:operator-gate",
    "operation": "process",
    "input_sha256": "...",
    "output_contract_sha256": "..."
  },
  "semantics_sha256": "..."
}
```

`semantics_sha256` binds every preceding canonical field. Complete Tool
Binding, Compiler Evidence, and checker verdict objects are verified; their
hashes are cross-links, not substitutes for verification.

## Verification order

1. Validate the closed outer and nested shapes, advisory value, self-hashes,
   canonical data, and outer semantics hash.
2. Verify embedded Compiler Evidence v2 from exact builder/verifier component
   bytes.
3. If valid profiles differ, stop with only `wasm-compiler-drift`; do not add
   source, manifest, tool-input, semantic, or generic mismatch.
4. Only for matching profiles, rebuild manifest policy and verify exact Tool
   Binding/input.
5. Re-run the checker and exact single-main AST profile.
6. Require all manifest, tool, compiler, artifact, source, effect, meter,
   entrypoint, and target-mediation cross-links.
7. Rebuild and compare the complete expected semantics object.

Malformed immutable structure is reported before attribution. A bare compiler
profile hash or Tool Binding hash is never sufficient evidence.

## Boundary

- Action Semantics v0 is not an Action Capsule, signature, operator approval,
  execution claim, terminal result, or attached Compiler Receipt v4. Compiler
  Receipt v4 already exists as a separate stable evidence contract.
- `seamN 1` meters LOOM runtime FFI requests. It does not itself meter host
  process side effects; a future trusted-host mediation contract must charge
  before real invocation.
- The current process executor validates plans and attempts but executes no
  command.
- Exact historical builder bytes remain required out of band.
- Tool input is hashed rather than embedded; the exact v0 descriptor contains
  no credential.
- Action Capsule v0, Approval v2, host mediation/execution, terminal Result v0,
  CLI/Playground exposure, MCP/A2A/WASI adapters, and signed in-toto/SLSA
  envelopes require separate explicit contracts.
- Existing Gate, Tool/Interface Binding, Compiler Evidence v1/v2, Receipt and
  Workflow v1-v4, Approval v1, executor, trust receipt, and WASM ABI contracts
  remain unchanged.
