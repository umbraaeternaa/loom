# LOOM Trusted Host Mediation v0

Status: implemented, normative, stateful, one-use, host-measuring, and
non-executing.

Trusted Host Mediation v0 is the state transition after Capsule Claim v0. It
re-verifies the complete Approval v2, Invocation Binding, and Claim; measures
the bound host resources; and atomically records one closed mediation handoff.
A successful result reports `authorization: "bounded-execution-required"`.
That value is a required next state, not permission for the caller or agent to
start a process directly.

## Public API

~~~python
loom.mediate_action_capsule_claim_v0(
    approval,
    request,
    claim,
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
    environment_values,
    now_unix_ms,
)

loom.validate_action_host_mediation_v0(mediation)
~~~

The public API reads the pinned operator public key and the fixed private Gate
ledger. `environment_values` is an exact name-to-string object supplied by the
trusted host. `now_unix_ms` is also explicit trusted-host input; the verifier
does not read a hidden wall clock.

`validate_action_host_mediation_v0` is a pure structural verifier for a closed
mediation artifact. It validates closure, canonical field profiles, cross-links,
and self-hashes without reading files, environment values, SQLite, or a clock.
It does not prove that previously measured host resources are still unchanged;
the bounded executor remains obligated to reopen and remeasure them at spawn.

## Real host measurement

Before touching mediation state, the implementation:

1. fully re-verifies Approval v2 against every semantic, compiler, artifact,
   tool, and invocation input;
2. verifies the closed Claim v0 body and hash against that approval and rejects
   a future claim or expired approval;
3. converts the bound executable and working-directory file URIs under the v0
   literal-path profile, rejecting percent-encoded bytes;
4. traverses every path component descriptor-relatively with `O_NOFOLLOW`,
   `O_DIRECTORY`, and `O_CLOEXEC`, so a symlink in the final component or any
   ancestor is refused;
5. streams at most 64 MiB of exact executable bytes through SHA-256, verifies a
   stable regular-file identity before and after the read, and rejects a
   group/world-writable executable;
6. verifies that the working directory is a non-symlink directory and is not
   group/world-writable;
7. requires exactly the committed environment names, NFC-normalizes each value,
   verifies every value commitment, and stores no raw value;
8. rebuilds canonical JSON UTF-8 stdin from the exact Tool Input and verifies
   its payload digest.

The host measurement records content hashes plus device, inode, owner, mode,
size, and modification-time identity for the opened executable and directory.
Device, inode, owner, and modification-time identifiers are decimal strings so
the JSON contract does not depend on JavaScript safe-integer limits.

## Closed mediation

The validation envelope is
`loom-action-host-mediation-validation/v0`. A successful
`loom-action-host-mediation/v0` cross-links the Claim, Approval, request,
Invocation Binding, Capsule, invocation, and one
`loom-action-host-measurement/v0`. It includes:

- `host_measurement_sha256` over the complete redacted measurement;
- explicit mediation and approval-expiry times;
- `status: "ready"`;
- `mediation_sha256` over the complete mediation body.

The measurement carries committed environment hashes, not values; canonical
stdin metadata, not payload bytes; executable identity and hash, not executable
bytes; and `credentials: "none"`.

## Atomic one-use ledger transition

Mediation requires the existing private Claim ledger. It never creates an
approval or claim. Inside SQLite `BEGIN IMMEDIATE`, it verifies:

- exact canonical `action_claims_v0` schema;
- exact canonical `action_mediations_v0` schema;
- absence of every trigger and view in the private action ledger;
- byte-for-byte equality between the supplied Claim and its `claimed` row.

`claim_sha256` is the mediation-table primary key. Concurrent attempts for one
Claim serialize at the write boundary: exactly one can become `ready`. Replay,
missing or terminal Claim rows, foreign schemas, injected triggers/views,
symlink ledgers, unsafe permissions, and changed ledger identity fail closed.

## Execution obligations and honest boundary

Mediation v0 performs no shell expansion, network access, credential lookup,
subprocess creation, process execution, claim finalization, observation, or
Action Capsule Result issuance. Its closed handoff requires the next bounded
executor to:

- reopen the executable without following symlinks;
- remeasure its bytes immediately before spawn;
- reverify the working-directory identity;
- supply the exact environment and canonical stdin;
- enforce the signed timeout;
- keep shell and network denied.

The mediation function closes its file descriptors before returning. Therefore
its measurement alone is not an atomic `exec` handoff and does not claim to
eliminate the post-measurement TOCTOU window. Bounded Execution v0 must repeat
the identity/content checks at the actual spawn boundary and atomically consume
the `ready` mediation before it may produce a process attempt.

The standalone browser bundle exposes the same API for parity but imports OS
and SQLite facilities only when mediation is invoked. Browser/Pyodide loading
and the Playground remain non-authorizing and do not call this host-only API.
