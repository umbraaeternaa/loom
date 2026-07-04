# LOOM Gate GitHub CI evidence adapter v1

Status: remote read-only evidence, canonical-LOOM-only, and non-enforcing.

`loom.collect_ci_evidence(manifest, observation, run_id)` reads the public
GitHub API at a fixed repository endpoint and binds one completed workflow run
to the observation's `after_head`.
The observed `after_head` must be the full 40-character commit SHA; abbreviated
prefixes are rejected at this remote trust boundary.
The observation `before_head` must also exactly equal the manifest
`expected_head`, so evidence cannot be rebound to a different starting state.

Version 1 accepts exactly `umbraaeternaa/loom`, workflow `LOOM Citadel`, job
`verify`, and these successful steps:

- `Compile Python sources` -> `syntax`;
- `Run citadel` -> `citadel`;
- `Verify published docs parity` -> `docs-parity`;
- `Run extended deterministic fuzz seeds` -> `fuzz`.

It also requires the public `main` branch SHA to match the observed head before
emitting `git-sync`. A wrong repository, workflow, SHA, branch, job, step,
status, or conclusion invalidates the entire collection; partial pass evidence
is never returned.

The adapter uses HTTPS GET only, a fixed `api.github.com` origin, exact-redirect
refusal, a five-second timeout, and a one-megabyte response limit. It executes
no repository code and accepts no caller-supplied URL, command, token, or shell
fragment. API/network/CORS failures fail closed.

TLS certificate and hostname verification are mandatory. The adapter uses the
platform trust store, with known system CA-bundle paths as a macOS framework-
Python fallback; it never provides an unverified mode.

This proves what the named public CI run reported for one commit. It is not a
GitHub attestation, a sandbox, or a proof that GitHub itself is trustworthy.
`operator-approval` remains outside this adapter until LOOM has a task-bound,
one-use approval capability rather than a reusable assertion.
