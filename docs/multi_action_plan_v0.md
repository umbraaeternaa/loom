# LOOM Multi-Action Plan v0

Status: implemented host-only composition and terminal evidence contract.

Multi-Action Plan v0 composes existing `loom-action-capsule/v0` artifacts into
one bounded directed acyclic graph. It does not execute a scheduler and does
not turn several non-authorizing Capsules into ambient authority.

The contract exists for AI workflows whose real unit of work is a dependency
graph rather than one tool call. Each node preserves the complete Capsule
identity, declared effect row, and a distinct approval boundary. A plan is a
reviewable statement of intended order, not permission to perform that order.

## Public API

```python
plan_result = loom.build_multi_action_plan_v0([
    {"id": "compile", "depends_on": [], "capsule": compile_capsule},
    {"id": "test", "depends_on": ["compile"], "capsule": test_capsule},
    {"id": "publish", "depends_on": ["test"], "capsule": publish_capsule},
])

loom.validate_multi_action_plan_v0(plan_result["plan"])

receipt_result = loom.build_multi_action_receipt_v0(
    plan_result["plan"],
    {"compile": compile_result, "test": test_result, "publish": publish_result},
    operator_public_key,
)

loom.verify_multi_action_receipt_v0(
    receipt_result["receipt"], plan_result["plan"],
    {"compile": compile_result, "test": test_result, "publish": publish_result},
    operator_public_key,
)
```

The builder accepts 1 to 64 steps. IDs are NFC-normalized lowercase ASCII and
match `[a-z][a-z0-9-]{0,63}`. Each dependency list is unique and bounded to 64
entries. Unknown dependencies, self-dependencies, duplicate IDs, and cycles
fail closed.

## Plan contract

The successful builder returns `loom-multi-action-plan-validation/v0` with one
closed `loom-multi-action-plan/v0`:

```json
{
  "schema": "loom-multi-action-plan/v0",
  "advisory": true,
  "steps": [
    {
      "schema": "loom-multi-action-step/v0",
      "id": "compile",
      "depends_on": [],
      "capsule": {"schema": "loom-action-capsule/v0"},
      "capsule_sha256": "...",
      "declared_effects": ["FFI"],
      "approval_boundary": {
        "schema": "loom-multi-action-approval-boundary/v0",
        "mode": "per-step",
        "step_id": "compile",
        "capsule_sha256": "...",
        "approval_schema": "loom-action-capsule-approval/v2",
        "shareable": false,
        "boundary_sha256": "..."
      },
      "step_sha256": "..."
    }
  ],
  "roots": ["compile"],
  "terminals": ["publish"],
  "limits": {"schema": "loom-multi-action-limits/v0"},
  "execution_policy": {
    "schema": "loom-multi-action-execution-policy/v0",
    "mode": "not-executable",
    "dependency_policy": "all-success-before-start",
    "failure_policy": "skip-transitive-dependents",
    "effect_escalation": "forbidden",
    "approval_inheritance": "forbidden",
    "host_actions_executed": false
  },
  "lifecycle": {
    "schema": "loom-multi-action-lifecycle/v0",
    "authorization": "none",
    "approval_eligible": false,
    "per_step_approval_required": true,
    "aggregate_receipt_schema": "loom-multi-action-receipt/v0"
  },
  "plan_sha256": "..."
}
```

Steps are serialized by ID. Dependency traversal uses a deterministic
topological order with lexical tie-breaking. Reordering input specifications
therefore produces identical plan bytes, while reordering stored canonical
steps is rejected.

`declared_effects` is derived from the embedded Capsule. It cannot be narrowed,
broadened, or rewritten independently. Every approval boundary commits to both
the step ID and Capsule hash, is explicitly non-shareable, and requires the
existing exact Action Approval v2 path. No approval can be inherited from a
dependency or promoted to plan scope.

## Aggregate receipt

`build_multi_action_receipt_v0` performs no execution. It accepts already
terminal `loom-action-capsule-result/v0` artifacts and validates every embedded
operator signature and lifecycle through the existing Result validator.

For each unblocked step, exactly one terminal Result is required. Its embedded
Invocation Binding must reference that step's Capsule. Result hashes and
approval hashes cannot be reused across steps. A dependent Result is rejected
if it started before every direct dependency finalized.

A terminal Result is successful only when its status is `completed`, exit code
is zero, and no terminating signal exists. If a dependency is unsuccessful,
the dependent step must have no Result and is recorded as `skipped`. Supplying
a Result for a blocked step fails closed.

The resulting `loom-multi-action-receipt/v0` binds the plan hash, per-step
Capsule, approval boundary, approval and Result hashes, timings, status, and a
closed summary. `completed` means every step succeeded. Otherwise the decision
is `stopped`, with exact failed and skipped step IDs.

The receipt is terminal, replay-denied, grants `authorization: none`, and
allows no further execution. It records whether terminal host actions already
occurred; it cannot cause one.

## Refusal and non-claims

The plan and receipt reject unknown fields, hash drift, effect drift, shared
approvals, replayed Results, incomplete unblocked steps, dependency-order
violations, and any lifecycle that claims authorization.

V0 deliberately does not provide:

- a scheduler or host executor;
- plan-wide approval;
- implicit rollback or compensation;
- dynamic graph mutation;
- dataflow between step outputs and later inputs;
- parallel execution authority;
- a claim that a declared actor is cryptographically identified.

Those capabilities require new additive contracts. They must not be inferred
from a valid v0 plan or receipt. The module is host-only and absent from the
browser Playground.
