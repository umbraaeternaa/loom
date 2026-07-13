# LOOM Gate host executor shim v1

Status: bounded host contract; no command execution.

`loom.plan_claimed_execution(manifest, challenge, approval, claim, actions)`
builds a deterministic execution plan for a signed approval that has already
been claimed. The plan is not an executor process and does not run shell,
network, tools, or repository commands. It verifies the signed approval against
the pinned operator public key, checks that the claim matches the manifest and
challenge, and rejects actions that were not declared in the manifest.

The plan contains only bounded host-facing facts:

- manifest, challenge, approval, claim, and plan SHA-256 bindings;
- the exact actions allowed for this execution;
- declared read and write scopes;
- redacted secret-lane metadata, never raw secret paths or values;
- an explicit `no-shell/no-network-by-default` executor boundary.

`loom.finish_claimed_execution(...)` accepts that exact plan after the trusted
host has attempted the bounded action. It collects read-only observation facts,
validates that observed actions are within the plan, and finalizes the already
claimed approval through `loom.finish_claimed_receipt(...)`.

The same contract is exposed to trusted host scripts through CLI adapter steps:

```console
python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json
python3 loom.py gate-exec-finish manifest.json challenge.json approval.json claim.json plan.json completed actions.json evidence.json --format json
```

`actions.json` is a JSON array of observed actions, for example
`["process"]`. `evidence.json` is a JSON array of receipt evidence items. These
commands still do not run the action; they only bind the plan and finalize the
receipt around facts supplied or collected by the trusted host.

Trusted hosts that only need the common `process` action can use the narrower
Python wrapper:

```python
plan_result = loom.plan_process_execution(manifest, challenge, approval, claim)
receipt_result = loom.finish_process_execution(
    manifest, challenge, approval, claim, plan_result["plan"], "completed"
)
```

This wrapper deliberately does not accept a caller-supplied action list. It is
still a contract wrapper, not a command runner.
See `examples/process_lifecycle_host.py` for the full trusted-host callback
recipe.

Trusted host callbacks return a closed attempt object:

```json
{"schema": "loom-gate-host-attempt/v1", "result": "completed", "evidence": []}
```

`loom.validate_host_attempt(...)` accepts only the fields `schema`, `result`,
and `evidence`. Results are limited to `completed`, `failed`, or `blocked`.
Evidence items must use the existing closed LOOM Gate evidence taxonomy; unknown
kinds are rejected before finalization. `loom.finish_process_attempt(...)`
validates this object and then finalizes the process-only receipt.

The host-attempt schema can be checked from the CLI without executing or
finalizing anything:

```console
python3 loom.py gate-attempt attempt.json --format json
```

To dry-run the attempt against the concrete process-only plan before any
receipt finalization, use:

```console
python3 loom.py gate-process-attempt plan.json attempt.json --format json
```

This verifies the plan surface, the process-only action binding, the plan hash,
and the host-attempt envelope. It still does not execute the action or finalize
a receipt.

To finalize a trusted host's already-completed process attempt, use:

```console
python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json
```

This consumes the claimed approval through `loom.finish_process_attempt(...)`.
It still does not run the action; the trusted host supplies the closed attempt
object after doing its own bounded work.
See `examples/process_lifecycle_cli.py` for the complete CLI handoff recipe.

This shim closes a practical integration gap without giving an agent ambient
authority. The agent may request and inspect a plan; the trusted host remains
responsible for keeping underlying credentials, filesystem writes, network, and
tool execution outside the agent process.
