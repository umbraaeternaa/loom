# LOOM release readiness

Status: public release-readiness contract for the open LOOM language artifact.
This document says what a user can rely on today, what is intentionally
experimental, and what LOOM does not claim yet.

## Current public baseline

- Canonical self-verification: `PASS -- 494/494 citadel checks`.
- Published browser bundle parity is required before release:
  `python3 verify_docs_parity.py`.
- The public compatibility surface is `loom.py`; module boundaries are pinned in
  `docs/module_boundaries.md`.
- LOOM has no runtime dependency beyond Python 3 for its core tests.
- Installable checkout entry point: `python3 -m pip install .` provides the
  `loom` console command. The zero-install checkout entry points
  `python3 -m loom ...` and `python3 loom.py ...` remain supported.
- The first-run onboarding path is pinned in `docs/quickstart.md` and starts
  with `examples/first.loom`.
- CLI discovery is pinned through `loom --help`, `loom help`, and
  `loom help quickstart`.
- Bundled example discovery is pinned through `loom examples` and
  `loom examples --format json`.
- Lightweight checkout health is pinned through `loom doctor --dry-run` and
  `loom doctor --dry-run --format json`.

## Stable today

- Parser, checker, interpreter, and CLI facade.
- Static effect rows for `Pure`, `IO`, `Net`, `Alloc`, `FFI`, and `Rand`.
- Capability seams, effect handlers, `with` reinterpretation, linear resources,
  affine seams, required effects, records, variants, lists, closures, recursion,
  and first-class functions with row-polymorphic effects.
- Provenance, taint flow, `trust`, role quorum, role lattice, per-effect role
  binding, declassification, and policy-level `require` / `forbid`.
- Portable checked-code backends for Python and JavaScript.
- WebAssembly/WAT backend for the published supported surface, including
  tagged i31 integers, records, lists, variants/match, closures, core effect
  boxes/handlers, strings, FFI boundary, heap diagnostics, source labels, and
  the non-authorizing `loom.trust.v1` trust/provenance receipt plus additive
  `loom.trust.v2` role-policy evidence for `roles`, `sub`, and `needs`.
- Deterministic signed i31 semantics across interpreter, Python, JavaScript,
  WebAssembly, and WAT.
- LOOM Gate advisory contracts: manifest validation, policy decision,
  redacted diagnostics, observation, CI evidence, signed operator approval,
  claim/plan/attempt/finish lifecycle, secret-lane receipts, native issuer
  handoff contracts, and read-only WASM artifact binding.
- Gate artifact evidence v1 and receipt v2 can carry a reverified exact
  source/WASM binding without changing manifest v1/v2, observation v1, receipt
  v1, or operator approval semantics. Source Equivalence v1 requires complete
  byte identity with deterministic recompilation before artifact binding.
- Compiler Profile v1 content-addresses the exact closed modular or standalone
  compiler surface supplied by a trusted host. It remains artifact-independent
  and non-authorizing.
- Gate Compiler Evidence v1 binds that exact profile to Artifact Binding v1 and
  Source Equivalence v1 while fixing identity to the running implementation
  surface. Additive Compiler Evidence v2 compares exact trusted-host builder
  and verifier profiles before source equivalence, reporting compiler drift
  separately from downstream same-profile artifact validation. Compiler
  Receipt v4 composes builder evidence v2 with Artifact Receipt v2 and exposes
  a pure Workflow v4 API while leaving CLI/Playground integration deferred.
  Compiler Receipt v3 continues to compose unchanged v1 evidence with Receipt v2 and
  exposes Workflow v3 without changing earlier receipt or workflow schemas.
  `loom gate-workflow-v3` and the Playground expose this route without
  collecting components, signing, approving, or executing host actions.
- Interface and Tool Binding v0 deterministically pins the exact
  `local-process/v1` plan/attempt contract, operator-gate authority, `process`
  operation, and normalized portable JSON input. It is advisory and performs no
  execution, signing, approval, claim, delegation, or capability grant.
- Action Semantics v0 composes exactly one process-bound `main`, required `FFI`,
  `seamN 1`, a literal Tool Binding hash, checker verdict, and Compiler Evidence
  v2. It remains pure and advisory; it does not invoke the tool or grant
  authority.
- Action Capsule v0 deterministically composes the normalized manifest, exact
  Gate decision, declaration-only actor, complete Action Semantics, cross-linked
  hashes, fixed execution class, and fixed lifecycle. It remains pure,
  `concrete_invocation: unbound`, `authorization: none`, and
  `approval_eligible: false`.
- Exact Invocation Binding v0 rebuilds that Capsule and binds one concrete host
  adapter digest, executable file URI, argv, working directory, committed
  environment, canonical Tool Input stdin, timeout, and denied shell/network
  modes. It is pure and non-authorizing; `approval_eligible: true` means only
  that Approval v2 has an exact `binding_sha256` subject.
- Exact Action Approval v2 builds a closed human-review request and binds a
  short-lived operator RSA signature to the exact Invocation Binding, Capsule,
  executable, argv, cwd, committed environment, stdin, and timeout hashes. It
  explicitly returns `claim-required` and performs no execution or ledger write.
- Capsule Claim v0 re-verifies the complete Approval v2 and exact invocation,
  then atomically reserves `approval_sha256` once in a private, schema-checked
  SQLite ledger. Success returns `host-mediation-required`; it does not execute.
- Trusted Host Mediation v0 re-verifies Approval and Claim, traverses executable
  and cwd paths without following symlinks, streams and verifies executable
  bytes, checks the exact committed environment and canonical stdin, then
  atomically records one redacted `ready` handoff. Success returns
  `bounded-execution-required`; it still performs no subprocess execution.
- Bounded Execution v0 requires a verified macOS Seatbelt or Linux user/network
  namespace provider, remeasures exact executable bytes, and launches either a
  private snapshot or a fully checked root-owned immutable macOS path. It
  atomically reserves each mediation before spawn, replaces env/stdin exactly,
  enforces process-group timeout and a 1 MiB per-stream limit, persists only
  redacted terminal hashes, and exposes a pure closed-artifact validator.
  Success returns `terminal-result-required`.
- Deterministic property fuzz smoke is part of the citadel.

## Experimental or bounded

- LOOM is still a research kernel, not a package-manager ecosystem.
- Multi-action semantics and terminal Action Capsule Result v0 remain future
  contracts. Cross-platform sandbox providers beyond macOS Seatbelt and Linux
  user/network namespaces also remain future work. Compiler
  Receipt v4 is already stable evidence and is not embedded in the
  pre-execution Capsule because no execution observation exists yet.
- The Gate is a verification and lifecycle layer; it does not magically confine
  arbitrary external tools unless those tools are routed through the bounded
  host lifecycle.
- Native operator signing is intentionally outside the public language runtime.
  LOOM verifies the approval artifact and documents the required boundary; it
  does not ship private keys or production key ownership.
- Portable Meter Frame v1 is implemented by the reference interpreter, the
  generated Python and JavaScript backends, and WASM. The WASM frame propagates
  through named calls, closures/`applyN`, recursion, handlers, and FFI. The
  Checker Meter Summary v1 admits finite statically resolved calls, closures,
  higher-order applications, and handlers. Quantitative Recurrence Summary v1
  additionally admits certified single-spine recursion when the selected
  i31/list entry measure is a source literal. Branching, unknown-input,
  uncertified, and unresolved higher-order recursion remain fail-closed.
- Call Budget Frame v1 is implemented by the interpreter, generated Python and
  JavaScript, and WASM. `(depthN K ...)` charges named recursive SCC edges at
  runtime without claiming a termination proof or weakening `seamN` analysis.
  `(prove (descent NAME...))` separately requests a checker-issued recursive
  descent certificate; the directive erases before execution and changes no
  backend ABI.
- Proven Value Bounds v1 extends checker-only recurrence analysis through
  lexical `let`, safe pure i31/list expressions, and path refinement. It adds
  no trusted annotation, runtime machinery, or backend/ABI change; unknown
  values and possible i31 wraparound remain fail-closed.
- Contextual Value Bounds v2 carries proven intervals through direct named-call
  value parameters under a fixed context cap. Callable/HOF, effectful/FFI,
  recursive-context, and unsupported arguments remain fail-closed.
- WASM Trust/Provenance Receipt v1 emits checked static trust/provenance form
  metadata and a source digest in a custom section. Runtime values remain
  provenance-free in ABI v1; the receipt is not a signature, proof certificate,
  operator approval, or capability grant.
- WASM ABI v1 is stable for the documented surface. `seamN` lowers to an
  internal linked runtime meter without adding host ABI obligations, but
  host-visible quantity diagnostics and future heap growth remain experimental.
- Future incompatible changes to tagged values, stable effect IDs, host imports,
  or exported ABI metadata require a new ABI version.

## Release verification checklist

Run these before treating a public checkout as release-ready:

```console
python3 loom.py release-check
```

The command expands to the pinned public checklist:

```console
python3 run_tests.py
python3 verify_docs_parity.py
python3 fuzz_tests.py --cases 256 --seed 0xBADC0DE
python3 loom.py about --format json
```

Expected public markers:

- `run_tests.py` prints `PASS -- 494/494 citadel checks`.
- `verify_docs_parity.py` prints that the published bundle is standalone and
  citadel-green.
- `loom.py about --format json` reports `citadel_checks: 494`, the current
  WASM ABI version, and the supported backend list.
- An installed checkout exposes `loom` as the same CLI surface as
  `python3 loom.py`.

## Non-claims

- LOOM does not claim to replace Python, JavaScript, or WebAssembly.
- LOOM does not claim to inspect every real-world host action by itself.
- LOOM does not provide a mechanism to harvest passwords, keys, wallets,
  cookies, bank data, or hidden information.
- LOOM does not treat an AI-authored assertion, test, or proof as sufficient
  trust by itself.
- LOOM does not expose private operator key material through the repository,
  browser, dashboard, logs, examples, or shared context files.

## Public/private boundary

The public release artifact is the LOOM language, CLI, documentation,
playground, examples, and tests in this repository. Internal development
operations, private dashboards, private journals, and private automation used
by the maintainer are not part of the public release surface and are not
required to use LOOM.
