# LOOM release readiness

Status: public release-readiness contract for the open LOOM language artifact.
This document says what a user can rely on today, what is intentionally
experimental, and what LOOM does not claim yet.

## Current public baseline

- Canonical self-verification: `PASS -- 433/433 citadel checks`.
- Published browser bundle parity is required before release:
  `python3 verify_docs_parity.py`.
- The public compatibility surface is `loom.py`; module boundaries are pinned in
  `docs/module_boundaries.md`.
- LOOM has no runtime dependency beyond Python 3 for its core tests.
- Installable checkout entry point: `python3 -m pip install .` provides the
  `loom` console command. The zero-install checkout entry points
  `python3 -m loom ...` and `python3 loom.py ...` remain supported.

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
  boxes/handlers, strings, FFI boundary, heap diagnostics, and source labels.
- Deterministic signed i31 semantics across interpreter, Python, JavaScript,
  WebAssembly, and WAT.
- LOOM Gate advisory contracts: manifest validation, policy decision,
  redacted diagnostics, observation, CI evidence, signed operator approval,
  claim/plan/attempt/finish lifecycle, secret-lane receipts, and native issuer
  handoff contracts.
- Deterministic property fuzz smoke is part of the citadel.

## Experimental or bounded

- LOOM is still a research kernel, not a package-manager ecosystem.
- The Gate is a verification and lifecycle layer; it does not magically confine
  arbitrary external tools unless those tools are routed through the bounded
  host lifecycle.
- Native operator signing is intentionally outside the public language runtime.
  LOOM verifies the approval artifact and documents the required boundary; it
  does not ship private keys or production key ownership.
- WASM ABI v1 is stable for the documented surface, but runtime quantity
  mediation for `seamN` counters is not yet an ABI-enforced runtime meter.
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

- `run_tests.py` prints `PASS -- 433/433 citadel checks`.
- `verify_docs_parity.py` prints that the published bundle is standalone and
  citadel-green.
- `loom.py about --format json` reports `citadel_checks: 433`, the current
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
