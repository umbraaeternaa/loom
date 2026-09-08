# LOOM Evidence-fed Dogfooding v2

Status: implemented host-only advisory evidence runner.

Evidence-fed Dogfooding v2 makes LOOM judge one real development candidate
from reverified external facts. It keeps the bounded Pure v1 policy unchanged,
but derives its `(main 3)` input from three exact facts instead of accepting a
manual quorum number:

1. the observed Git head matches canonical GitHub `main`;
2. the canonical LOOM Citadel workflow and required verification steps passed
   for that exact head;
3. the operator signed the exact content-addressed review request with the
   public key pinned outside the request.

The runner pins the exact canonical policy source by SHA-256. Even a whitespace
change is refused before evidence collection, so a passing CI run cannot be
reused with a substituted policy.

## Commands

The first command recollects GitHub evidence and produces a closed
`loom-dogfood-review-request/v1` object:

```console
loom dogfood-review-request policy.loom manifest.json observation.json RUN_ID \
  --nonce HEX64 --format json
```

An external issuer signs the closed review body. LOOM never reads or stores the
operator private key. The signed object uses `loom-dogfood-review/v1` and binds
the request SHA-256, reviewer, decision and pinned public-key SHA-256.

The second command recollects the same external evidence, verifies the signed
review, runs the unchanged policy through all four backends, and emits a closed
`loom-dogfood-validation/v2` envelope with a content-addressed
`loom-dogfood-receipt/v2`:

```console
loom dogfood-v2 policy.loom manifest.json observation.json RUN_ID \
  request.json review.json --format json
```

## Public API

The host module exposes these exact calls:

```python
loom.build_dogfood_review_request_v1(source, manifest, observation, run_id, nonce)
loom.verify_dogfood_review_v1(request, review, source, manifest, observation, run_id, nonce)
loom.evaluate_dogfood_policy_v2(source, manifest, observation, run_id, request, review)
loom.verify_dogfood_policy_receipt_v2(receipt, source, manifest, observation, run_id, request, review)
```

Fresh verification rebuilds the request from the source, normalized Gate
manifest and observation, current GitHub API responses, exact workflow run and
operator signature. Unknown fields, missing fields, caller-supplied evidence,
non-read-only manifests, failed CI steps, changed heads, invalid signatures and
receipt drift are refused.

## Closed profile

The Gate identity is exactly `ci/trace`. Actions are exactly `read` and `test`,
with no write paths. Evidence is exactly `syntax`, `citadel`, `docs-parity`,
`fuzz` and `git-sync`. The observation must be completed, must contain no
caller evidence, and is bounded to 4096 changed paths. The request is bounded
to 1 MiB and requires a 64-character lowercase hexadecimal nonce.

The policy remains the finite first-order Pure profile from Dogfooding v1 and
must agree across the reference interpreter, generated Python, generated
JavaScript and generated WebAssembly. The derived provenance label is
`derived-from-reverified-ci-git-and-signed-review`; `manual_value_accepted` is
always false.

## Trust boundary and non-claims

Dogfooding v2 is advisory. It grants no authorization, consumes no Action
Approval, executes no requested host action and does not replace the four Gate
stages. A review signature proves control of the pinned operator key and binds
one exact request; it is not ambient authority.

The fixed GitHub API adapter and TLS connection are external oracles, not a
GitHub cryptographic attestation. The local LOOM compiler, runners, Gate
normalizers, CI adapter and pinned-key verifier remain in the trusted computing
base. Verification is intentionally freshness-bound to the currently published
canonical `main`; durable historical proof still requires independently signed
portable CI attestations. The browser bundle exposes none of these host-only
APIs.
