# LOOM Gate advisory policy v1

Status: deterministic and non-enforcing.

`loom.evaluate_manifest(value)` first validates `loom-gate-manifest/v1`, then
classifies the declared task under policy `operator-codex-cloud/v1`.

Possible decisions are:

- `accept`: the declaration fits an autonomous lane;
- `operator-required`: the declaration is permitted only after a later
  manifest-bound operator approval;
- `reject`: the declaration is structurally invalid, crosses a hard role/path
  boundary, or omits evidence required for its requested actions.

`reject` always outranks `operator-required`, which outranks `accept`.

## Hard boundaries

- `/Users/macbook/Projects/argus/citadel` is frozen and read-only for every
  agent, including the operator identity in policy v1.
- Codex owns canonical `/Users/macbook/Projects/loom` code changes.
- Cloud Code owns organism operations under ARGUS/NOSTROMO, but not canonical
  LOOM.
- Auditor may read external audit targets and write only its report lane; it
  may never write the target.
- CI may read/test canonical LOOM but not mutate host source.
- Agent IDs must use their policy-owned role; a manifest cannot self-assign a
  more powerful role.

## Secret and credential path advisory rules

Policy v1 classifies common secret-bearing paths from the declaration only; it
does not read file contents. Reads of credential-like paths such as `.env*`,
`.ssh` keys, cloud credential stores, cookies, sessions, tokens, keychains,
password stores, wallet seeds, and keystores return `operator-required`.

A secret-like read combined with outbound or reporting actions (`network`,
`report`, `dashboard`, or `git-push`) is rejected as possible `SecretExfil`.
Writes or deletes targeting secret-like paths are rejected. This is a defensive
classification layer; it is not a capability to collect or print secrets.

Redacted diagnostics are available through `loom.build_gate_diagnostics(value)`
and `python3 loom.py gate manifest.json`. The diagnostics use
`loom-gate-diagnostics/v1` and expose only the secret class, manifest field, and
disposition (`approval-required` or `blocked`). They never echo the raw path or
secret value.

LOOM writes require `syntax`, `citadel`, `docs-parity`, and `git-clean`
evidence declarations. Writes under `docs/` also require `live-site`. Git push
requires `git-sync` and `operator-approval`; backup requires `backup`.

## Honesty boundary

Every result is `advisory: true`. Policy v1 classifies only the normalized
declaration. It does not read the current Git state, issue an approval token,
intercept commands, inspect actual changed files, or confine host tools.
