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
PASS -- 525/525 citadel checks
```

The portable Windows core harness can also be exercised without making a
Windows certification claim:

```console
python3 tools/windows_core_conformance.py --self-test
python3 tools/windows_component_conformance.py --self-test
python3 tools/windows_host_security_conformance.py --self-test
python3 tools/windows_bounded_execution_conformance.py --self-test
```

Only the pinned `verify-windows-core` CI job may emit the revision-bound
Windows Core Conformance v0 witness.

The second command runs the real Pure/effectful Component and reproducible
release path with local pinned tools. It is non-certifying outside the pinned
`verify-windows-component` job and emits no Windows witness.

The third command validates the closed Windows Host Security witness schema and
its tamper refusals on any platform. Only the pinned
`verify-windows-host-security` job builds and runs the native SID/DACL,
reparse-point, AppContainer, network-denial, and Job Object probe; portable
self-test mode is explicitly non-certifying.

The fourth command validates the additive Windows Approval-to-Result lifecycle,
native receipt schema, and tamper refusal without making a Windows
certification claim. Only `verify-windows-bounded-execution` builds the fixed
native adapter and emits the revision-bound integration witness.

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

After those independently authorized actions return signed terminal Results,
replay them into the plan's deterministic state:

```python
state = loom.build_multi_action_execution_state_v0(plan)["state"]
state = loom.ingest_multi_action_result_v0(
    state, plan, "compile", compile_result, operator_public_key,
)["state"]
loom.verify_multi_action_execution_state_v0(state, plan, operator_public_key)
```

To declare and resolve one evidence-bound output-to-input edge, provide the
target step's exact Invocation Binding:

```python
dataflow = loom.build_multi_action_evidence_dataflow_v0(
    plan,
    [{
        "source_step_id": "compile",
        "source_channel": "stdout",
        "target_step_id": "test",
    }],
    {"test": test_invocation_binding},
)["dataflow"]
resolution = loom.resolve_multi_action_evidence_dataflow_v0(
    dataflow, plan, {"test": test_invocation_binding},
    dataflow["edges"][0]["edge_sha256"], compile_result,
    operator_public_key,
)["resolution"]
```

This only proves digest equality between signed terminal evidence and the
already-bound target stdin. It neither transports the bytes nor authorizes or
executes the target action. See
[`multi_action_evidence_dataflow_v0.md`](multi_action_evidence_dataflow_v0.md).

To prove possession of the exact bytes committed by both sides without storing
the payload in the artifact:

```python
delivery = loom.build_multi_action_byte_delivery_evidence_v0(
    resolution, dataflow, plan, {"test": test_invocation_binding},
    delivered_bytes, operator_public_key,
)["evidence"]
loom.verify_multi_action_byte_delivery_evidence_v0(
    delivery, resolution, dataflow, plan,
    {"test": test_invocation_binding}, delivered_bytes,
    operator_public_key,
)
```

This detached byte witness proves exact digest and size equality. It still does
not transport bytes, authorize the target, or claim that a process consumed
them. See
[`multi_action_byte_delivery_evidence_v0.md`](multi_action_byte_delivery_evidence_v0.md).

This API verifies evidence and dependency transitions; it does not schedule or
execute a host action. See
[`multi_action_execution_state_v0.md`](multi_action_execution_state_v0.md).

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
