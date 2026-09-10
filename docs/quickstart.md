# LOOM quickstart

This is the shortest path from a fresh checkout to a verified LOOM program.

## 1. Run without installing

```console
python3 -m loom about --format json
python3 -m loom help quickstart
python3 -m loom examples
python3 -m loom doctor --dry-run
python3 -m loom check examples/first.loom
python3 -m loom run examples/first.loom
```

Expected result:

```console
OK
42
```

`examples/first.loom` is intentionally tiny:

```lisp
(defx main () (fn () 42))
```

The empty effect row `()` says that `main` is pure. The checker proves that
the program really performs no `IO`, `Net`, `FFI`, `Rand`, or allocation effect
before it runs.

## 2. Install the CLI

```console
python3 -m pip install .
loom about --format json
loom check examples/first.loom
loom run examples/first.loom
```

The installed `loom` command is the same public CLI surface as
`python3 loom.py`.

## 3. Run the release check

```console
loom release-check
```

That command runs the public verification checklist:

```console
python3 run_tests.py
python3 verify_docs_parity.py
python3 fuzz_tests.py --cases 256 --seed 0xBADC0DE
python3 loom.py about --format json
```

The expected public baseline is:

```console
PASS -- 515/515 citadel checks
```

The CLI help is also pinned:

```console
loom --help
loom help quickstart
loom examples
loom doctor --dry-run
```

To verify a terminal Component execution bundle offline, use an
execution-attester key SHA-256 pin obtained outside the bundle:

```console
loom execution-verify execution-bundle.json \
  --execution-key-sha256 EXPECTED_LOWERCASE_SHA256
```

To use LOOM itself as a bounded advisory judge for a local development
candidate, run the four-backend Dogfooding v1 policy:

```console
loom dogfood examples/dogfood_release_policy.loom "(main 3)"
```

The `3` is an operator-supplied, unverified quorum fact. The command proves the
Pure policy and requires exact interpreter/Python/JavaScript/WebAssembly
agreement; it does not verify the external fact or authorize a host action.

For an evidence-fed decision, first bind an exact canonical GitHub CI run into
a review request, have the external operator issuer sign that request, then run
Dogfooding v2:

```console
loom dogfood-review-request policy.loom manifest.json observation.json RUN_ID \
  --nonce HEX64 --format json
loom dogfood-v2 policy.loom manifest.json observation.json RUN_ID \
  request.json review.json --format json
```

This path derives the quorum from reverified Git, CI and pinned-key review
evidence. It remains advisory and performs no requested host action.

To compose several existing Action Capsules without granting plan-wide
authority, use the host-only Multi-Action API:

```python
plan = loom.build_multi_action_plan_v0([
    {"id": "compile", "depends_on": [], "capsule": compile_capsule},
    {"id": "test", "depends_on": ["compile"], "capsule": test_capsule},
])
```

Each step still requires its own Invocation Binding, operator Approval, Claim,
Mediation, Bounded Execution, and terminal Result. See
[`multi_action_plan_v0.md`](multi_action_plan_v0.md).

## 4. See the trust gate

```console
loom check examples/trust.loom
loom run examples/trust.loom
```

`examples/trust.loom` shows the core LOOM idea: AI-only trust is circular and
is refused unless independent non-AI anchors vouch for the value.

## 5. Try it in the browser

Open the playground:

```text
https://umbraaeternaa.github.io/loom/play.html
```

The playground runs in your browser tab. It can check code, run `main`, compile
to JavaScript, show WAT, and execute the published WebAssembly backend without
sending your program to a server.
