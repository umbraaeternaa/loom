# LOOM Multi-Action Evidence Dataflow v0

Status: implemented, host-only, bounded, advisory, and non-authorizing.

Multi-Action Evidence Dataflow v0 closes one narrow gap between independently
authorized steps: it proves that a successful signed source Result describes
the same bytes that an exact target Invocation Binding already commits to as
stdin. The proof is digest equality. LOOM does not receive, store, parse,
transport, or execute those bytes.

## API

```python
declared = loom.build_multi_action_evidence_dataflow_v0(
    plan,
    [{
        "source_step_id": "produce",
        "source_channel": "stdout",
        "target_step_id": "consume",
    }],
    {"consume": consume_invocation_binding},
)
dataflow = declared["dataflow"]

loom.validate_multi_action_evidence_dataflow_v0(
    dataflow, plan, {"consume": consume_invocation_binding},
)

resolved = loom.resolve_multi_action_evidence_dataflow_v0(
    dataflow,
    plan,
    {"consume": consume_invocation_binding},
    dataflow["edges"][0]["edge_sha256"],
    produce_result,
    operator_public_key,
)

loom.verify_multi_action_evidence_dataflow_resolution_v0(
    resolved["resolution"],
    dataflow,
    plan,
    {"consume": consume_invocation_binding},
    operator_public_key,
)
```

All four calls are pure artifact operations. They perform no requested host
action and grant no authority.

## Closed declaration

The `loom-multi-action-evidence-dataflow/v0` declaration binds:

- the exact `loom-multi-action-plan/v0` hash;
- one direct dependency edge per target stdin;
- source step, Capsule, Result schema, and `stdout` or `stderr` channel;
- target step, Capsule, non-shareable approval boundary, Invocation Binding,
  exact invocation, stdin encoding, and stdin payload digest;
- a content hash for every edge and for the complete declaration.

Edges are sorted deterministically. There may be 1-64 edges. One source output
may fan out to several target steps, but one target stdin cannot accept several
sources. An edge must follow a direct dependency already present in the Plan;
the dataflow layer cannot add ordering or mutate the DAG.

Unknown fields, malformed identifiers, unsupported channels, extra or missing
target bindings, duplicate edges, multiple stdin sources, non-direct edges,
Capsule drift, Invocation Binding drift, and hash drift fail closed.

## Resolution

The `loom-multi-action-dataflow-resolution/v0` artifact is emitted only when:

1. the dataflow declaration and target Invocation Binding rebuild exactly;
2. the source is a valid signed `loom-action-capsule-result/v0`;
3. the Result belongs to the declared source Capsule;
4. the Result is terminal and successful (`completed`, exit code zero, no
   terminating signal);
5. the selected output descriptor SHA-256 equals the target stdin
   `payload_sha256`.

The resolution embeds the signed source Result, both payload digests, the
target binding identities, and an explicit equality proof. Verification
revalidates the signature and reconstructs the complete resolution from zero;
mere self-consistent rehashing cannot legitimize a modified artifact.

## Authority boundary

The declaration and resolution both state:

```text
authorization: none
host_actions_executed: false
host_byte_transport: false
approval_inheritance: forbidden
```

The source Approval authorizes only its own exact Invocation Binding. A valid
resolution does not approve the target. The target still requires its own
operator Approval, Claim, Host Mediation, Bounded Execution, and terminal
Result. The actual byte transport is an external host responsibility and must
independently prove that the transported bytes match the committed digest.

## Deliberate exclusions

V0 does not provide:

- a JSONPath, field projection, transform, merge, codec, or schema engine;
- byte storage, byte custody, pipes, files, network transfer, or IPC;
- a scheduler, retry loop, rollback, compensation, or dynamic graph mutation;
- approval inheritance, plan-wide authority, ambient capabilities, or key
  custody;
- proof that a host actually delivered the bytes to the target process.

The API is host-only and modular-only. It is absent from the standalone browser
Playground because the Playground intentionally exposes no host Action
lifecycle or operator-signing surface.
