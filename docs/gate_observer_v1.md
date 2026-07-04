# LOOM Gate read-only Git observer v1

Status: host-derived Git facts, advisory, and non-enforcing.

`loom.collect_observation(manifest, result, actions_observed, evidence)` reads
only repositories declared by a valid `loom-gate-manifest/v1`. It returns a
`loom-gate-observation-collection/v1` wrapper containing a normalized
`loom-gate-observation/v1` suitable for `loom.build_receipt(...)`.

The observer independently derives:

- the current Git `after_head`, while preserving the manifest `expected_head`
  as `before_head`;
- changed tracked paths since `expected_head` plus untracked paths;
- `git-clean` evidence, replacing any caller-supplied claim of that kind.

It rejects unavailable repositories, non-canonical or symlinked roots, unknown
expected commits, non-ancestor expected heads, Git read failures, non-UTF-8
paths, and paths that escape the declared repository root.

The implementation invokes Git with argument arrays, no shell, a five-second
timeout, `GIT_OPTIONAL_LOCKS=0`, and no network operation. It does not run the
task, tests, hooks, external diff drivers, or evidence producers; fsmonitor and
lazy object fetches are disabled, and it writes no receipt.

The honesty boundary remains explicit: `result`, `actions_observed`, and all
evidence other than `git-clean` are still supplied assertions. Browser/Pyodide
use fails closed because host Git is unavailable there. This is an observation
layer, not enforcement or sandboxing.
