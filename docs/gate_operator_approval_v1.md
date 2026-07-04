# LOOM Gate signed one-use operator approval v1

Status: manifest-bound capability contract with host-local replay protection.

`loom.build_approval_challenge(manifest, nonce)` accepts only a valid manifest
whose policy decision is `operator-required`. The host supplies a fresh 256-bit
nonce as 64 lowercase hexadecimal characters. The resulting
`loom-gate-approval-challenge/v1` binds the manifest SHA-256, policy, decision,
and nonce under its own `challenge_sha256`.

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

The private-key issuer and operator UI are intentionally not provisioned by
Codex. Creating the key inside the agent that seeks approval would collapse the
trust boundary. Filesystem protection is still host-level policy, not a full OS
sandbox; later enforcement should isolate the issuer and ledger permissions.
