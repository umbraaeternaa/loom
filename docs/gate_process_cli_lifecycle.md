# LOOM Gate process CLI lifecycle

Status: transcript-style host handoff; no command execution.

This is the concrete CLI shape of the process-only host lifecycle:

```text
claim -> plan -> trusted host attempt -> dry-run attempt -> finish
```

The LOOM CLI steps only bind JSON facts. They do not run a shell, open the
network, read secrets, or execute the process action. The trusted host owns the
real work and writes a closed attempt object after that work is done.

## Files

A trusted host work directory contains handoff JSON files:

```text
manifest.json
challenge.json
approval.json
claim.json
plan.json
attempt.json
receipt.json
```

`manifest.json`, `challenge.json`, and `approval.json` are produced by the
normal Gate approval flow. The remaining files are produced by the lifecycle
below.

## 1. Claim the signed approval

```console
python3 loom.py gate-claim manifest.json challenge.json approval.json --format json > claim-result.json
```

The host stores the `claim` object from that result as `claim.json`. Claiming is
the point where the signed approval becomes reserved for this exact execution.

## 2. Build a process-only plan

```console
python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json > plan-result.json
```

The host stores the `plan` object from that result as `plan.json`. The plan is
bounded to:

- the manifest/challenge/approval/claim hashes;
- `actions_allowed: ["process"]`;
- declared read/write scopes;
- `no-shell/no-network-by-default`.

## 3. Trusted host writes the attempt

After doing its own bounded work outside the agent process, the trusted host
writes `attempt.json`:

```json
{"schema": "loom-gate-host-attempt/v1", "result": "completed", "evidence": []}
```

Allowed `result` values are `completed`, `failed`, and `blocked`. Evidence must
use the existing closed LOOM Gate evidence taxonomy.

## 4. Dry-run the attempt against the plan

```console
python3 loom.py gate-process-attempt plan.json attempt.json --format json
```

This validates the attempt envelope and the process-only plan binding without
finalizing anything.

## 5. Finish the process receipt

```console
python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json > receipt.json
```

This finalizes the already claimed approval through `loom.finish_process_attempt(...)`.
The command still does not execute the action. It only consumes the claim using
the supplied plan and attempt facts.

## One-use boundary

After `gate-process-finish` succeeds, the same claim cannot be finalized again.
A later `gate-exec-finish` or `gate-process-finish` for the same claim must
fail with an approval-finalization finding.

See `examples/process_lifecycle_cli.py` for a tested Python host recipe that
drives the same CLI lifecycle with temporary JSON files.
