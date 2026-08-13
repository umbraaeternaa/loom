# LOOM Action Capsule Result v0

Status: implemented, normative, terminal, content-addressed, stateful, one-use,
and non-authorizing.

Action Capsule Result v0 closes the exact host lifecycle begun by Action
Capsule v0. It does not execute a process. It consumes one already-terminal
Bounded Execution v0, verifies the complete signed chain at the time execution
began, atomically closes the private Claim, and emits one portable redacted
result.

## Public API

~~~python
loom.finalize_action_capsule_result_v0(
    approval,
    request,
    claim,
    mediation,
    execution,
    manifest,
    tool_binding,
    tool_input,
    source,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
    entrypoint,
    invocation,
    finalized_at_unix_ms,
)

loom.validate_action_capsule_result_v0(result, public_key_value)
~~~

The finalizer reads the pinned operator public key and private Action ledger.
The validator accepts the public key explicitly and performs no host IO.

## Self-contained evidence chain

`loom-action-capsule-result/v0` embeds the exact:

- Action Approval request, including Invocation Binding and Action Capsule;
- signed Action Approval v2;
- Capsule Claim v0;
- Trusted Host Mediation v0;
- Bounded Execution v0;
- derived `loom-action-terminal-outcome/v0`;
- terminal `loom-action-result-lifecycle/v0`.

Every embedded artifact retains its own digest. The Result repeats the request,
approval, claim, mediation, execution, and outcome digests as closed
cross-links, then hashes the complete Result as `result_sha256`. Unknown fields,
missing fields, non-canonical JSON values, broken nested hashes, changed
cross-links, and a signature from another key fail closed.

The verifier validates the operator signature against the execution start time,
not the later Result finalization time. An execution that began inside its
signed approval window may therefore finish and be recorded after that window
expires; an execution that began outside the window cannot be legitimized by a
later Result.

## Redacted terminal outcome

The outcome preserves only:

- terminal status and measured duration;
- exit code or terminating signal;
- stdout and stderr SHA-256 digests and byte counts;
- host remeasurement, sandbox, and process-attempt digests.

It contains no stdout, stderr, environment value, credential, stdin payload,
private key, or random executable snapshot path. The full embedded chain also
contains commitments rather than those raw values.

`completed` maps the private Claim to `completed`. `failed`, `timed-out`,
`output-limit-exceeded`, and `spawn-failed` map it to `failed` while preserving
the exact detailed status in the Result.

## Atomic closure

SQLite `BEGIN IMMEDIATE` verifies the exact canonical `action_claims_v0`,
`action_mediations_v0`, `action_executions_v0`, and `action_results_v0` table
schemas and rejects every trigger and view. It compares the complete private
Claim, Mediation, and terminal Execution rows with the embedded artifacts.

One transaction then:

1. changes the Claim from `claimed` to `completed` or `failed` exactly once;
2. inserts one Result row keyed by `execution_sha256` with unique attempt,
   mediation, claim, approval, outcome, and result digests;
3. commits both changes together.

Replay and concurrent finalization therefore cannot create two terminal
Results. A schema mismatch, substituted row, symlinked or weakly owned ledger,
trigger, view, failed constraint, or non-unique Claim transition rolls back the
transaction and returns `action-result-finalization-failed`.

## Terminal boundary

A valid Result returns:

~~~text
authorization: "none"
terminal: true
replay: "denied"
~~~

The lifecycle lists `loom-gate-receipt/v4` as remaining evidence, not as new
execution authority. Result v0 does not sign a supply-chain attestation, collect
Git or CI observation, grant ambient capabilities, rerun the process, or claim
filesystem confinement beyond the evidence already stated by Mediation and
Bounded Execution.

The standalone browser bundle exposes the same construction and validation
surface for parity. Browser/Pyodide cannot reach a successful Result through
the public lifecycle because its Bounded Execution stage fails closed without a
supported OS sandbox provider. The Playground does not execute this API.
