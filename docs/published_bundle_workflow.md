# Published Bundle Workflow

`docs/loom.py` is not just another copy of the kernel. It is the published
single-file browser bundle consumed by `docs/play.html` through:

```js
fetch("./loom.py")
```

That makes it a release artifact with different constraints from the modular
development core.

## Invariants

1. `docs/play.html` must keep loading only `./loom.py`.
2. `docs/loom.py` must remain a standalone single-file bundle.
3. Structural modularization in the development core must not mechanically
   overwrite `docs/loom.py`.
4. Semantic parity between the modular core and the published bundle must be
   proven explicitly before release.

## Required Verification

Run:

```console
python3 verify_docs_parity.py
```

This check enforces the published-bundle contract by:

1. verifying that `docs/play.html` still loads only `./loom.py`;
2. rejecting accidental browser-side fetches of development modules such as
   `loom_parse.py`, `loom_checker.py`, `loom_runtime.py`, `loom_codegen.py`,
   `loom_wasm.py`, or `loom_cli.py`;
3. loading `docs/loom.py` as the active `loom` module;
4. running the full citadel against that injected standalone bundle.

## Release Discipline

When the modular core evolves:

1. change the development modules first;
2. verify the modular core normally;
3. update `docs/loom.py` only as a reviewed published-bundle step;
4. run `python3 verify_docs_parity.py`;
5. ship only when both the modular core and the injected published bundle are green.

## Non-Goals

- Do not turn `docs/` into a multi-file browser import graph unless the
  playground loader is intentionally redesigned.
- Do not assume module extraction in the core automatically updates the
  published bundle safely.
