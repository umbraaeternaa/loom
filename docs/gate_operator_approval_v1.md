# LOOM Gate signed one-use operator approval v1

Status: manifest-bound capability contract with host-local replay protection.

`loom.build_approval_challenge(manifest, nonce)` accepts only a valid manifest
whose policy decision is `operator-required`. The host supplies a fresh 256-bit
nonce as 64 lowercase hexadecimal characters. The resulting
`loom-gate-approval-challenge/v1` binds the manifest SHA-256, policy, decision,
and nonce under its own `challenge_sha256`.

`loom.build_approval_request(manifest, challenge)` builds the closed
`loom-gate-approval-request/v1` envelope that crosses into an external issuer.
It contains the normalized manifest, the exact rebuilt challenge, all policy
reasons shown to the operator, and `request_sha256` over the complete preceding
body. A reordered equivalent manifest produces the same request; a changed
path, action, repository head, nonce, challenge hash, or policy reason cannot
silently preserve its identity. Invalid, rejected, or approval-free manifests
receive no request.

The issuer must display the request fields from this envelope before asking for
operator confirmation. The request is not an approval and carries no signing
authority; agents may construct it without gaining the ability to approve it.
Before display or signing, the issuer calls
`loom.validate_approval_request(request)`, which rejects unknown/missing fields
and rebuilds the manifest, challenge, policy reasons, and request hash. A
request that was mutated after construction therefore fails closed.

An operator issuer outside LOOM signs a closed
`loom-gate-operator-approval/v1` body with RSA-2048-or-stronger PKCS#1 v1.5 and
SHA-256. The body binds:

- `challenge_sha256` and `manifest_sha256`;
- `approver: operator` and `decision: approve`;
- the pinned public-key SHA-256;
- the signature over every preceding approval field.

LOOM deliberately contains no production signing or key-generation function.
The private key must remain in a separate operator-controlled issuer.

`loom.verify_operator_approval(...)` reads only the pinned public key at
`/Users/macbook/codex/Кодекс/gate/operator_public_key.json` and verifies the
complete binding. The API does not accept a caller-selected key.

`loom.consume_operator_approval(...)` then atomically inserts the approval hash
into the fixed SQLite ledger
`/Users/macbook/codex/Кодекс/gate/operator_approvals.sqlite3`. The SHA-256
primary key makes a second consumption fail closed, including concurrent
attempts. Neither production path accepts a caller-selected ledger.
The pinned key must be a regular non-symlink file and neither key nor ledger
may be group/world-writable; the ledger directory/file are forced to
`0700`/`0600` after creation.

The returned `operator-approval` evidence is suitable for a trusted Gate host.
Receipt v1 itself remains advisory and can still parse supplied evidence; a
dashboard or enforcement host must accept operator approval only after a
successful `consume_operator_approval` result, never directly from arbitrary
observation JSON.

`loom.build_consumed_receipt(manifest, observation, challenge, approval)` is
the safe integrated path. It rejects caller-supplied `operator-approval`,
verifies the signature, injects its own evidence, fully preflights receipt v1,
and only then atomically consumes the token. Invalid observations or missing
evidence do not create the ledger or spend the approval; a replay cannot return
a receipt.

## Pre-execution claim lifecycle

The integrated receipt path above is retained for compatibility, but a trusted
host that must stop an action before execution uses two phases:

1. `loom.claim_operator_approval(manifest, challenge, approval)` verifies the
   signature and atomically records a manifest/challenge-bound `claimed` row.
2. Only after that succeeds may the trusted host start the declared action.
3. `loom.finish_claimed_receipt(...)` preflights the terminal observation and
   atomically changes the same row to exactly `completed` or `failed`.

The claim has a canonical SHA-256 identity. A forged or rebound claim, an
approval already spent through the compatibility path, a second claim, and a
second finalization all fail closed. `blocked` is not a valid terminal state
after execution has been claimed: if the host attempted the action and it did
not complete, it must record `failed`.

This lifecycle closes the ordering gap in which an action could run before its
one-use approval was atomically reserved. It still does not by itself prevent a
host process from bypassing LOOM and invoking a tool directly; real enforcement
also requires an executor whose underlying credential or capability is not
available to the agent process.

The private-key issuer and operator UI are intentionally not provisioned by
Codex. Creating the key inside the agent that seeks approval would collapse the
trust boundary. Filesystem protection is still host-level policy, not a full OS
sandbox; later enforcement should isolate the issuer and ledger permissions.
