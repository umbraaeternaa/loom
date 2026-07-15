# LOOM Gate macOS native issuer contract

Status: normative contract for a macOS operator-presence issuer. This document
describes the boundary a native app must satisfy; it does not ship private
keys, provisioning profiles, certificates, or an enrolled operator identity.

## Role

The macOS native issuer is the operator-side signing tool for
`loom-gate-approval-request/v1`. It is not the requesting agent, not the
browser, not the dashboard, and not the trusted host executor.

Its only authority is to review one fixed pending request, ask for explicit
operator approval, ask macOS for user presence, and write one signed
`approval.json`.

## Required boundary

A production macOS issuer must:

- create or use a non-exported signing key owned by the operator-side app;
- protect signing with macOS user presence;
- use a stable code-signing identity, Team ID, bundle identifier, and exactly
  one private Keychain access group;
- verify its own signing and entitlement boundary before enrollment or signing;
- read only a fixed pending request inbox, not arbitrary request paths or stdin;
- reject extra command-line arguments for signing;
- validate the complete request, challenge, manifest hash, and request hash
  before showing the review UI;
- display the task summary, actions, write paths, policy reasons, request hash,
  manifest hash, and challenge hash before signing;
- refuse to overwrite an existing approval output;
- write only `approval.json` with private file permissions;
- export only the public verifier key to LOOM's pinned verifier path.

## Forbidden authority

The macOS issuer must not:

- expose, print, log, export, or copy the private key;
- accept a private key from Codex, Cloud Code, browser storage, dashboard state,
  shared memory, GitHub, CI, or a web page;
- accept a request body over stdin or a caller-selected path for signing;
- claim approvals, plan host actions, execute host actions, consume the ledger,
  or finalize receipts;
- let the dashboard approve by itself;
- let a copied request count as permission;
- let a signed approval count as execution.

## Dashboard launcher rule

A dashboard may launch the native issuer for review only if all of these are
true:

1. There is a valid pending request with no existing approval or receipt.
2. The issuer path is fixed and non-symlinked.
3. The app passes strict code-signature verification.
4. The bundle identifier, Team ID, application identifier, and sole Keychain
   access group match the pinned expected values.
5. The dashboard launches exactly the fixed issuer binary with the single
   `sign-pending` argument, without a shell.

Even then, the dashboard is only a launcher. Operator approval still happens in
the native app, and macOS user presence is still required before signing.

## Runtime health

Code signature validity is necessary but not sufficient. Before treating a
native issuer as production-ready, its non-signing self-test or status command
must also run successfully on the target host. If a signed app is valid on disk
but terminates before its self-test/status output, the issuer is not considered
runtime-healthy until diagnosed.

## LOOM side

LOOM verifies the result. It does not become the key owner.

After the issuer writes `approval.json`, the trusted host still must claim the
approval before action, build a bounded plan, validate the host attempt, and
finish once through the ledger; without that lifecycle, a signature is only a
signature, not completed execution.
