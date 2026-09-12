# LOOM Multi-Action Execution State Machine v0

Status: implemented, normative, deterministic, pure, replay-verifiable,
non-authorizing, and host-only.

Multi-Action Execution State Machine v0 turns one validated Multi-Action Plan
into a content-addressed execution history. It accepts only complete signed
Action Capsule Results, reconstructs their proved execution and finalization
transitions, and deterministically updates dependent steps. It performs no
host action and is not a live scheduler.

## Public API

~~~python
state_result = loom.build_multi_action_execution_state_v0(plan)

next_result = loom.ingest_multi_action_result_v0(
    state_result["state"],
    plan,
    "compile",
    compile_result,
    operator_public_key,
)

loom.verify_multi_action_execution_state_v0(
    next_result["state"], plan, operator_public_key,
)
~~~

All three calls are pure. They do not open the private Action ledger, read a
clock, invoke an executable, access a network, consume an Approval, or hold a
private key. Every successful envelope remains advisory with
`authorization: "none"`.

## Deterministic state

The initial state is derived from the exact `plan_sha256`. Root steps are
`ready`; every other step is `blocked` by its declared dependencies. A step
state binds its Capsule, non-shareable approval boundary, execution/result
hashes, times, and latest event hash. Canonical summary lists expose `ready`,
`running`, `completed`, `failed`, and `skipped` step identifiers.

The lifecycle is closed and includes:

~~~text
accepts: verified-action-result-only
host_actions_executed_by_state_machine: false
replay: denied
authorization: none
~~~

`running` is a proved historical transition derived from the embedded Bounded
Execution inside a complete Result. It is not a claim that this pure API can
observe an operating-system process in real time. Because Result ingestion is
atomic, a returned v0 state normally contains terminal, ready, blocked, or
skipped steps rather than a persistent running step.

## Result ingestion

One ready step may advance only when its complete
`loom-action-capsule-result/v0` passes the existing independent validator and
operator-signature check. The Result must bind the step's exact Capsule.
Result and Approval hashes may not be reused by another step. Every dependency
must already be completed, and the child execution time may not predate any
dependency finalization time.

A successful ingestion appends two evidence-linked events:

1. `execution-observed`: `ready -> running`, carrying the complete redacted
   Result and exact plan approval-boundary hash.
2. `result-finalized`: `running -> completed|failed`, linking the first event,
   execution hash, and Result hash.

After success, newly satisfied dependents move `blocked -> ready`. After
failure, every transitive dependent moves deterministically
`blocked -> skipped`. These dependency transitions are also events.

## Hash-chain replay

Each event commits to its index, transition, timestamp, evidence, and previous
event SHA-256. The state commits to the complete ordered event list and current
step projection. Verification extracts the embedded Results, validates them
again, rebuilds the initial state from the Plan, replays every transition, and
requires exact state equality. Recomputed outer hashes cannot hide event,
ordering, dependency, Result, Approval, or projection drift.
The closed 64-step profile admits at most 192 events; oversized histories fail
before replay.

## Honest boundary

This v0 contract records and verifies completed evidence. It does not choose
which tool to run, issue per-step Approvals, execute parallel work, stream live
status, bind outputs into later inputs, retry, compensate, roll back, or mutate
the Plan. Those require separate future scheduler and dataflow contracts.

The API remains absent from `docs/loom.py` and the browser Playground. Browser
code can execute ordinary LOOM programs but cannot acquire host orchestration
authority through this state format.
