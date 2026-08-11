# LOOM Capsule Claim v0

Status: implemented, normative, atomic, one-use, exact-invocation-bound, and
non-executing.

Capsule Claim v0 is the state transition between a valid short-lived Action
Approval v2 and Trusted Host Mediation v0. It reserves one exact approval
in a private local ledger before any process may start. A successful claim
reports `authorization: "host-mediation-required"`; it is not permission for an
agent process to invoke the target directly.

## Public API

~~~python
loom.claim_action_capsule_approval_v0(
    approval,
    request,
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
    now_unix_ms,
)
~~~

The public API reads the pinned operator public key and uses the fixed private
Gate ledger. It first invokes the complete Action Approval v2 verifier, which
rebuilds the request and exact Invocation Binding from every supplied semantic,
compiler, artifact, tool, and invocation input. Invalid, expired, future,
rebound, wrongly signed, or differently keyed approvals never reach the ledger.

## Closed claim

The validation envelope is
`loom-action-capsule-claim-validation/v0`. A successful state transition has
`advisory: false` and contains one closed `loom-action-capsule-claim/v0`:

~~~json
{
  "schema": "loom-action-capsule-claim/v0",
  "approval_sha256": "<sha256>",
  "request_sha256": "<sha256>",
  "challenge_sha256": "<sha256>",
  "binding_sha256": "<sha256>",
  "capsule_sha256": "<sha256>",
  "invocation_sha256": "<sha256>",
  "claim_scope": "exact-invocation",
  "claimed_at_unix_ms": 1800000000001,
  "approval_expires_at_unix_ms": 1800000300000,
  "status": "claimed",
  "claim_sha256": "<sha256>"
}
~~~

`claim_sha256` covers every preceding field. Claim time is an explicit
trusted-host input and must still be inside the signed Approval v2 interval.
The claim carries no secret, credential, private key, raw environment value, or
executable payload.

## Atomic one-use reservation

The ledger transition uses SQLite `BEGIN IMMEDIATE` and a primary key on
`approval_sha256`. The implementation:

1. verifies Approval v2 and the complete exact invocation before opening the
   ledger;
2. requires a current-user-owned, non-symlink private parent and ledger;
3. fixes parent mode to `0700` and ledger mode to `0600`;
4. verifies the exact `action_claims_v0` table schema and rejects attached
   triggers or views;
5. refuses an existing approval row and inserts all claim cross-links in one
   transaction;
6. commits before returning the claim.

Concurrent attempts for the same approval serialize at the database write
boundary: exactly one may insert, and all others fail with
`action-claim-failed`. Invalid approvals do not create a ledger. A symlink,
group/world-writable file, non-canonical table, duplicate row, database error,
or failed constraint leaves no successful claim.

The Action Claim table is additive inside the existing private Gate database.
Legacy Gate Approval v1 claims, consumption, executor, and receipt tables and
schemas are unchanged; an Approval v2 cannot be consumed through the v1 API.

## Honest boundary

Claim v0 does not remeasure executable bytes or environment values, install
resource limits, obtain credentials, execute a process, update a claim to a
terminal state, collect observation, or issue an Action Capsule Result. Trusted
Host Mediation v0 now owns the first host measurement and one-use redacted
handoff. Bounded execution, terminal state transition, and Result v0 remain
separate.

The standalone browser bundle carries the same API and semantics for parity,
but imports SQLite only when claim is invoked. Browser/Pyodide loading and the
Playground remain non-authorizing and do not call this stateful API.
