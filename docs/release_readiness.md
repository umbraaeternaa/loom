# LOOM release readiness

Status: public release-readiness contract for the open LOOM language artifact.
This document says what a user can rely on today, what is intentionally
experimental, and what LOOM does not claim yet.

## Current public baseline

- Canonical self-verification: `PASS -- 489/489 citadel checks`.
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
- Deterministic property fuzz smoke is part of the citadel.

## Experimental or bounded

- LOOM is still a research kernel, not a package-manager ecosystem.
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

- `run_tests.py` prints `PASS -- 489/489 citadel checks`.
- `verify_docs_parity.py` prints that the published bundle is standalone and
  citadel-green.
- `loom.py about --format json` reports `citadel_checks: 489`, the current
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
