# LOOM Secret and Credential Safety Policy

Status: defensive design contract for future LOOM Gate and host-tool work.
This document does not grant any capability to collect, extract, or exfiltrate
secrets.

## Purpose

LOOM must treat secrets as a protected boundary, not as ordinary text.

The goal is to help users and agents prove that AI-written code does **not**
read or leak credentials, or to stop and require explicit operator approval
when a task genuinely needs access to a protected secret lane.

## Protected Data Classes

Future LOOM/Gate secret policy should classify at least these zones:

- `SecretRead`: reading secret-bearing files or stores.
- `CredentialAccess`: passwords, tokens, API keys, session cookies, browser
  cookies, SSH keys, `.env` files, keychains, and password managers.
- `WalletKey`: crypto wallet private keys, seed phrases, keystores, signing
  material, and hardware-wallet bridge data.
- `BankCredential`: bank login data, one-time codes, recovery phrases, payment
  credentials, and financial identity proofs.
- `SecretExfil`: any network, FFI, clipboard, file-write, log, or report path
  that could move protected material out of its allowed boundary.

These are defensive names. They exist to detect, block, require approval, and
write receipts. They are not instructions for harvesting secrets.

## Core Rules

- No ambient credential access. A task may not read secret-bearing paths merely
  because it can read the filesystem.
- No silent exfiltration. Secret-bearing data may not flow into `Net`, `FFI`,
  logs, reports, clipboard, generated code, or ordinary output without an
  explicit policy lane.
- Operator approval must be manifest-bound. If a legitimate task needs a
  protected secret lane, the approval must name the manifest, the path class,
  the requested action, and the exact evidence requirement.
- Prefer denial over ambiguity. Unknown secret-like paths or outputs should
  classify as `operator-required` or `reject`, never as autonomous `accept`.
- Receipts must not contain the secret. Evidence may state that a secret lane
  was used or blocked, but must not copy the secret value into the receipt.
- Agents may not self-vouch credential access. AI-generated code, manifests, or
  explanations are not sufficient proof that a secret read is safe.

## Gate Manifest v2 Secret Lane

`loom-gate-manifest/v2` adds a closed `secret_access` field such as:

```json
{
  "secret_access": [
    {
      "class": "CredentialAccess",
      "path": "/Users/example/project/.env",
      "mode": "read",
      "reason": "load local test API key for a signed operator-approved test"
    }
  ]
}
```

Policy rejects unknown classes, relative paths, ordinary non-secret paths, class
mismatches, and vague reasons. A declaration of ordinary `read_paths` must not implicitly grant `secret_access`. A declared `secret_access` lane is only a
manifest-bound request: it requires operator approval, and combining it with
outbound/reporting actions is still rejected as possible `SecretExfil`.

## Candidate Effect Model

Future language-level work may introduce effects such as:

- `Secret`
- `Credential`
- `Wallet`
- `SecretOut`

These effects should compose with existing `Net`, `IO`, `FFI`, and `Alloc`.
For example, `Secret + Net` is more dangerous than either alone and should be
treated as a possible exfiltration path unless explicitly reinterpreted,
blocked, or approved.

## Non-Goals

- No password harvesting.
- No bank, wallet, session, cookie, token, or seed-phrase collection tooling.
- No stealth credential discovery.
- No bypass of password managers, keychains, browsers, wallets, or banking
  systems.
- No receipt or dashboard view that prints raw secrets.

## Recommended Sequence

1. Document the defensive policy contract and pin it in the citadel.
2. Add Gate path classification for common secret-bearing paths as advisory
   `operator-required` or `reject`. Implemented in Gate policy v1 for
   declaration-only path classification; it does not read secret contents.
3. Add receipt/evidence wording that proves a secret lane was blocked or
   approved without revealing the secret. Implemented in Gate receipt v1 with
   `secret-lane` evidence and safe detail wording.
4. Add explicit `secret_access` declaration in `loom-gate-manifest/v2`.
   Implemented as a closed, denial-first manifest lane; it describes the
   requested secret class and reason but does not grant ambient host access.
5. Add VS Code/Playground diagnostics that explain why a task touched a
   protected lane.
6. Only after the host boundary exists, consider language-level `Secret` effects
   for source programs.
