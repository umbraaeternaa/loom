# LOOM Gate native issuer handoff

Status: operator-facing bridge from the browser playground to the real trusted host lifecycle.

The playground can build and copy a `loom-gate-approval-request/v1` JSON
envelope. That JSON is not an approval. It is evidence for an
operator-controlled issuer.

## Boundary

- Browser: builds the manifest-bound request and lets the operator copy it.
- Native issuer: validates the request, displays the exact fields, and signs
  the request hash only after operator presence.
- Trusted host: receives the signed approval, claims it before any action,
  builds a bounded plan, dry-runs the host attempt, and finishes exactly once.

The browser must not hold the private key, write the approval ledger, claim an
approval, run a host action, or finalize a receipt.

## Files

The handoff directory should contain:

```text
manifest.json
challenge.json
request.json
approval.json
claim.json
plan.json
attempt.json
receipt.json
```

`request.json` is the JSON copied from the playground or produced by
`gate-request`. `approval.json` is produced only by the native issuer.

## 1. Build or receive the request

From CLI:

```console
python3 loom.py gate-request manifest.json --nonce <64-hex> --format json > request-result.json
```

From the playground:

```text
Approval request -> Copy approval JSON -> request.json
```

Or use `Download approval JSON` to save the same envelope as a file.

The copied JSON contains both `manifest` and `challenge`. Save those exact
objects as `manifest.json` and `challenge.json` if the trusted host does not
already have them from the original workflow.

## 2. Native issuer validates and signs

Before signing, the issuer validates the copied envelope with
`loom.validate_approval_request(request)`. The issuer must show the operator at
least:

- policy decision;
- requested actions;
- manifest SHA-256;
- challenge SHA-256;
- request SHA-256;
- policy reasons.

Only the native issuer writes `approval.json`. Codex, the playground, and the
trusted host do not create the private signature.

The reference operator-side issuer is:

```console
python3 examples/native_issuer.py request.json operator_private_key.json approval.json
```

It validates the request with `loom.validate_approval_request(request)`, displays
the review surface, asks for explicit operator confirmation, and writes only the
signed `approval.json`. It does not claim an approval, write the ledger, plan,
execute, or finalize a receipt.

Before the trusted host can verify `approval.json`, pin the matching public key:

```console
python3 examples/pin_operator_public_key.py operator_public_key.json
```

The helper may read the reference private-key JSON too, but it writes only
`algorithm`, `n`, and `e` to LOOM's fixed verifier path.

## 3. Trusted host claims before action

```console
python3 loom.py gate-claim manifest.json challenge.json approval.json --format json > claim-result.json
```

Store the `claim` object as `claim.json`. If this step fails, the host must not
plan, dry-run, execute, or finish.

## 4. Plan, dry-run, finish

```console
python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json > plan-result.json
python3 loom.py gate-process-attempt plan.json attempt.json --format json
python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json > receipt.json
```

`attempt.json` is written by the trusted host after its bounded work. LOOM
validates the envelope and consumes the claim during finish. A second finish for
the same claim fails closed.

## Safety notes

- Do not paste a signed approval back into the playground as if the browser were
  the host.
- Do not let the agent that requests approval also control the issuer private
  key.
- Do not accept approval evidence that did not pass claim/finish through the
  fixed local ledger.
- Do not treat a copied request as permission. Permission begins only after issuer signing and successful trusted-host claim.

See also:

- `docs/gate_operator_approval_v1.md`
- `docs/gate_operator_real_workflow.md`
- `docs/gate_operator_key_storage.md`
- `docs/gate_macos_native_issuer_contract.md`
- `docs/gate_process_cli_lifecycle.md`
- `examples/process_lifecycle_cli.py`
- `examples/operator_handoff_cli.py` for a complete local demo transcript that
  redirects the pinned public key and ledger into a temporary workdir.
