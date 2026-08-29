# LOOM Effectful Component Host Execution v0

Status: implemented, normative, host-only, one-use, snapshot-bound, sandboxed,
and terminal-result-producing.

Effectful Component Host Execution v0 is the first LOOM transition that runs a
verified Effectful Component through the operator-authorized Action lifecycle.
It does not infer authority from Component evidence. It requires the exact
short-lived Approval v2, Claim, Trusted Host Mediation, Execution Binding v0,
original compiler inputs, host values, runtime, Component bytes, mapping,
policy, export, and canonical request.

## Public API

```python
loom.execute_effectful_component_host_v0(
    execution_binding,
    artifact, component_bytes, mapping, host_policy,
    component_source, component_core_wasm, package, world,
    component_uri, component_request, export,
    approval, request, claim, mediation,
    manifest, tool_binding, tool_input, program_source, program_wasm,
    builder_surface, builder_components, verifier_components,
    entrypoint, invocation, environment_values, now_unix_ms,
    wasm_tools_executable=..., wasmtime_executable=..., exports=...,
)

loom.validate_effectful_component_host_execution_v0(execution)
```

The public executor loads only the configured operator verification key and
private Action ledger. Private signing material is neither accepted nor read.

## Spawn protocol

The transition is fail-closed and ordered:

1. Rebuild and cryptographically verify Approval v2 from every original
   compiler, Capsule, invocation, and Action input at the current time.
2. Recheck Claim and Mediation structure, hashes, timestamps, and exact private
   ledger rows.
3. Rebuild Effectful Component Execution Binding v0, including independent
   Component Adapter v1 verification through pinned wasm-tools and Wasmtime.
4. Probe the existing platform network sandbox and remeasure the Wasmtime
   executable, working directory, environment, and stdin.
5. Open the Component descriptor-relatively without following symlinks, require
   its bound identity and permissions, stream its exact bytes into a new `0400`
   private snapshot, and verify source/snapshot SHA-256 equality and stable
   source identity.
6. Atomically reserve the ready mediation once in `action_executions_v0`.
7. Launch the private runtime snapshot with the signed argv prefix and only the
   final signed Component path replaced by the private Component snapshot.
   Shell and network remain denied; timeout and output limits are inherited
   unchanged from Bounded Execution v0.
8. Finalize the ordinary Action execution ledger row and emit a self-contained,
   content-addressed host execution record. Temporary snapshots are removed by
   the host cleanup path.

## Evidence and continuation

The `loom-effectful-component-host-execution/v0` record embeds:

- the exact non-authorizing Execution Binding v0;
- source and private-snapshot Component identities, byte length, and hashes;
- the signed argv plus a content-addressed proof of the single path
  substitution;
- the complete `loom-action-bounded-execution/v0` record;
- a lifecycle requiring `loom-action-capsule-result/v0` next and explicitly
  retaining an `effectful_result_binding_required` obligation.

The embedded ordinary Action execution is intentionally compatible with the
existing Action Capsule Result and Result Attestation chain. The legacy Result
does not include the outer Effectful host execution hash by itself. The
implemented [Effectful Component Result Binding v0](effectful_component_result_binding_v0.md)
now verifies the host record, terminal Result, and signed DSSE attestation, then
content-addresses their exact shared execution and evidence links. A successful
process exit is not a new authorization and is not itself a trusted semantic
claim about the program output.

## Refusal surface

Execution is rejected before mediation consumption when Approval is invalid or
expired, any compiler/Action input drifts, the binding is malformed, Component
bytes or identity change, environment commitments differ, the private ledger
is absent or altered, the sandbox cannot prove enforcement, or a snapshot
cannot be created exactly. Replay reaches the unique mediation reservation and
is rejected. No browser fallback exists.

This API is deliberately absent from `docs/loom.py` and the Playground because
they have no operator key boundary, private ledger, descriptor-relative host
filesystem, process sandbox, or atomic one-use execution store.
