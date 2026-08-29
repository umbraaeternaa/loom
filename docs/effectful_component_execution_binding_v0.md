# LOOM Effectful Component Execution Binding v0

Status: implemented, normative, host-only, ledger-verified, resource-measuring,
and non-authorizing.

Effectful Component Execution Binding v0 joins one independently verified
Effectful Component Adapter v1 artifact to one existing Action Approval request,
Claim, and Trusted Host Mediation. It closes the identity gap without pretending
that evidence is permission or that a Component file measured now is immutable
until process launch.

## Public API

```python
loom.build_effectful_component_execution_binding_v0(
    artifact, component_bytes, mapping, host_policy,
    component_source, component_core_wasm, package, world,
    request, claim, mediation, environment_values,
    component_uri, component_request, export, observed_at_unix_ms,
    wasm_tools_executable=..., wasmtime_executable=..., exports=...,
)

loom.verify_effectful_component_execution_binding_v0(
    binding,
    artifact, component_bytes, mapping, host_policy,
    component_source, component_core_wasm, package, world,
    request, claim, mediation, environment_values,
    component_uri, component_request, export, observed_at_unix_ms,
    wasm_tools_executable=..., wasmtime_executable=..., exports=...,
)
```

Both calls are host-only. The builder reads the exact Component resource and
private Action ledger but does not update either. The verifier first rejects a
malformed or authority-bearing binding, then rebuilds the complete expected
binding from live host and compiler inputs.

## Approval-time precommitments

The exact Invocation Binding signed by Approval v2 must contain only these six
environment commitments:

- `LOOM_EFFECTFUL_ARTIFACT_SHA256`
- `LOOM_EFFECTFUL_COMPONENT_SHA256`
- `LOOM_EFFECTFUL_MAPPING_SHA256`
- `LOOM_EFFECTFUL_HOST_POLICY_SHA256`
- `LOOM_EFFECTFUL_EXPORT`
- `LOOM_EFFECTFUL_REQUEST_SHA256`

The supplied trusted-host values must reproduce every commitment exactly. The
adapter digest must equal the pinned Wasmtime executable independently accepted
by Effectful Component Adapter verification. `argv` must name the exact WIT
export, canonical JSON request bytes, and literal Component path. Shell and
network remain denied.

## Host and ledger proof

The Component URI uses the existing literal absolute-file profile. The binding
opens every path segment descriptor-relatively with no-follow flags, rejects a
symlink or group/world-writable resource, streams at most 16 MiB through SHA-256,
checks stable identity before and after reading, and requires byte identity with
the independently verified Component.

The request and mediation receive their existing pure structural verification.
The Claim hash and all Claim/Mediation/request cross-links are rebuilt. The
private SQLite ledger must contain byte-identical `claimed` and `ready` rows,
canonical schemas, and no trigger or view. This check is read-only: it does not
create an execution table, reserve the mediation, or change Claim state.

## Closed binding

The content-addressed binding carries exact artifact, Component resource,
mapping, policy, selected export, canonical request, pinned runtime,
environment commitments, Action cross-links, observation/expiry times, and a
fixed lifecycle. Its lifecycle is always:

```json
{
  "authorization": "none",
  "execution_authorized": false,
  "operator_approval_recheck_required": true,
  "component_remeasurement_required": true,
  "private_component_snapshot_required": true,
  "required_next": "loom-effectful-component-host-execution/v0"
}
```

## Host execution handoff

[Effectful Component Host Execution v0](effectful_component_host_execution_v0.md)
implements the required next transition. It treats this binding as evidence,
not permission: Approval v2 and every original compiler/Action input are
reverified again before the mediation can be consumed.

## Honest boundary

This contract proves that the operator-approved invocation had precommitted the
same identities later measured and independently verified. It does not consume
the mediation or invoke Wasmtime. The separate host executor reverifies
Approval v2 from every original compiler/Action input, remeasures both runtime
and Component at the spawn boundary, atomically reserves the ready mediation,
executes only private exact-byte snapshots under the existing sandbox, and
emits a host execution record whose nested Bounded Execution can enter the
existing terminal Result/Attestation chain. A later Effectful Result Binding is
still required to bind that legacy Result to the outer Component spawn record.

This module is deliberately absent from the standalone browser bundle and
Playground because browser loading has no private Action ledger or trusted host
filesystem boundary.
