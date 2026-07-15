# LOOM Gate operator key storage model

Status: production boundary policy for where the real operator signing key may
live. This document does not generate, import, export, or migrate keys.

## Rule

The operator private signing key is an operator-controlled credential, not a
LOOM project file and not agent memory. LOOM may verify approvals against a
pinned public key, and a native issuer may produce `approval.json`, but the
private key must stay outside the repository, browser, dashboard, shared
context, bridge files, GitHub, and the trusted-host approval ledger.

## Accepted storage models

### A. External operator key file

This is the current reference shape for the example issuer:

- The key file is created outside the LOOM repository.
- The file is owned by the operator account and not shared with agents.
- The file is readable only by the local operator-controlled issuer process.
- The issuer writes only `approval.json`.
- The public verifier key is pinned separately with
  `examples/pin_operator_public_key.py`.

This model is acceptable for local testing and early production hardening when
the operator controls the machine and file permissions. It is not permission for
Codex, Cloud Code, Gemini, a browser, dashboard, or CI job to read the private
key.

### B. macOS Keychain or native presence wrapper

This is the preferred production direction for macOS:

- A native operator-side component owns the signing identity.
- The private key is not exported into JSON, logs, shell history, clipboard,
  browser storage, dashboard state, shared memory, or agent-readable files.
- Signing requires an explicit operator presence step.
- The component displays the same manifest-bound review surface as the
  reference issuer.
- The only output crossing back into LOOM is `approval.json`.

LOOM should treat this wrapper as a separate operator tool. The language, Gate,
dashboard, and agents verify the result; they do not become the key owner.

The normative wrapper boundary is pinned in
[`gate_macos_native_issuer_contract.md`](gate_macos_native_issuer_contract.md).
That contract requires stable signed app identity, exactly one private Keychain
access group, fixed inbox/outbox, no stdin/path signing, explicit operator
review, macOS user presence, dashboard-as-launcher only, and runtime
self-test/status health before production use.

## Forbidden storage models

- Private key committed to the LOOM repository.
- Private key placed in `docs/`, `examples/`, test fixtures, bridge files,
  shared memory, handoff journals, dashboard state, browser local storage, or
  GitHub secrets controlled by an agent workflow.
- Private key passed to Codex, Cloud Code, Gemini, untrusted agents, the
  playground, or a web page.
- Private key copied into the trusted-host ledger directory.
- Private key retained in logs, transcripts, screenshots, or generated reports.

## Consequence

A real approval is valid only when these boundaries hold:

1. The request is manifest-bound and challenge-bound.
2. The operator reviews it outside the requesting agent.
3. The private key stays under operator control.
4. The issuer writes only signed approval JSON.
5. The trusted host verifies against the pinned public key, claims once, plans,
   validates the attempt, and finishes once through the ledger.

If any step requires an agent, browser, dashboard, or repository file to possess
the private key, the workflow is not a real LOOM operator approval.
