# LOOM Gate real operator workflow

Status: human-facing production checklist for using LOOM Gate approvals without
turning the requesting agent, browser, dashboard, or trusted host into the
private-key owner.

This document is intentionally not a key generator. Real operator keys must be
created and stored by an operator-controlled tool or secret store outside the
LOOM repository. The reference scripts below show the handoff shape, not a
policy that the agent may own signing material.

## Trust boundary

- Operator: owns the private signing key and decides whether to approve.
- Browser or CLI: builds a manifest-bound approval request only.
- Native issuer: validates the request, shows the review surface, and writes
  only `approval.json`.
- Trusted host: verifies against the pinned public key, claims once, plans,
  validates the host attempt, and finishes once through the ledger.
- Codex, Cloud Code, dashboard, playground, and untrusted agents: must not read,
  copy, generate, escrow, upload, or persist the operator private key.

## One-time setup

1. Generate the real RSA signing key outside LOOM with an operator-controlled
   tool or secret store.
2. Export or derive only the public verifier fields:
   `algorithm`, `n`, and `e`.
3. Pin that public verifier key on the trusted host:

```console
python3 examples/pin_operator_public_key.py operator_public_key.json
```

The pinned verifier key is not a secret. The private key is still controlled by
the operator and must not be placed in the LOOM repo, browser downloads folder,
dashboard state, trusted-host ledger directory, shared memory, or agent bridge.

## Per-approval flow

1. Build the request:

```console
python3 loom.py gate-request manifest.json --nonce <64-hex> --format json > request-result.json
```

2. Give only the request envelope to the native issuer.
3. The native issuer validates the request and shows the review surface:

```console
python3 examples/native_issuer.py request.json operator_private_key.json approval.json
```

4. If the operator approves, the issuer writes only `approval.json`.
5. The trusted host claims before any bounded action:

```console
python3 loom.py gate-claim manifest.json challenge.json approval.json --format json > claim-result.json
```

6. The trusted host plans, validates the attempt envelope, and finishes:

```console
python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json > plan-result.json
python3 loom.py gate-process-attempt plan.json attempt.json --format json
python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json > receipt.json
```

## What never crosses the boundary

- The operator private key never enters Codex, Cloud Code, Gemini, the browser,
  the dashboard, GitHub, shared context files, or the approval ledger path.
- A copied request is not permission.
- A signed approval is not execution.
- A receipt is trusted only after claim, plan, attempt validation, and finish
  bind it to the fixed public key and one-use ledger.
- The demo private key in `examples/operator_handoff_cli.py` is public test
  material and must never be used for real approvals.

## Demo versus real workflow

Use `examples/operator_handoff_cli.py` to learn the full shape safely. It
redirects the pinned public key and ledger into a temporary workdir and uses a
public demo key. For real operation, keep the private key outside the repo and
run only the operator-controlled issuer against real requests.
