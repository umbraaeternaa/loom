# LOOM Bounded Execution v0

Status: implemented, normative, stateful, one-use, process-executing, and
fail-closed on missing network isolation.

Bounded Execution v0 is the only LOOM v0 transition that starts the exact
process approved by Action Approval v2 and measured by Trusted Host Mediation
v0. Success authorizes only the next lifecycle state:
`authorization: "terminal-result-required"`.

## Public API

~~~python
loom.execute_action_host_mediation_v0(
    approval,
    request,
    claim,
    mediation,
    manifest,
    tool_binding,
    tool_input,
    source,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
    entrypoint,
    invocation,
    environment_values,
    now_unix_ms,
)

loom.validate_action_bounded_execution_v0(execution)
~~~

The public function reads the pinned operator public key and fixed private
Action ledger. It re-verifies Approval v2, Claim v0, the complete Mediation v0
artifact, all cross-links, expiry, executable bytes, cwd identity, exact
environment commitments, and canonical stdin before reservation.

## Real network sandbox

The executor does not treat `shell=False` as network isolation. It requires a
working OS provider before it reserves the mediation:

- macOS (`darwin-seatbelt-network-deny/v0`): root-owned
  `/usr/bin/sandbox-exec` with the fixed Seatbelt profile
  `(version 1)(allow default)(deny network*)`;
- Linux (`linux-user-network-namespace/v0`): root-owned
  `unshare --user --map-root-user --net`, creating a separate user and network
  namespace.

The provider must be a regular root-owned file, must not be group/world
writable, is streamed through SHA-256, and is recorded in
`loom-action-network-sandbox/v0`. A separate `policy_sha256` binds the exact
fixed profile arguments, not merely the provider binary or a profile label. A
real provider capability probe must succeed.
Unsupported platforms, unavailable user namespaces, nested-sandbox refusal, or
provider failure return `action-bounded-execution-failed` before ledger
reservation and before target execution.

## Spawn-boundary remeasurement

The executor rebuilds the complete host measurement and requires byte-for-byte
equality with Mediation v0. It then reopens executable and cwd through the
descriptor-relative no-follow traversal and verifies their identities again.
It then selects one of two closed launch boundaries:

- `private-executable-snapshot` copies the exact open executable bytes into a
  random current-user-only directory beside the private ledger, sets mode
  `0500`, re-hashes the copy, and launches that path;
- `root-owned-immutable-path` is the macOS-compatible path for Apple platform
  binaries that AMFI refuses to run from a copied location. Every component
  from filesystem root through the final executable is reopened without
  following symlinks, required to be root-owned and not group/world-writable,
  and recorded as ordered path-custody evidence. The final launch identity must
  equal the mediated executable identity.

User-controlled executable paths never qualify for the immutable-path mode and
therefore use the private exact-byte snapshot. Snapshot residue is removed
after every terminal or failed attempt.

The cwd is reverified immediately before snapshot creation, but Python's
portable process API still accepts cwd by pathname rather than directory file
descriptor. Same-UID mutation of that path remains part of the trusted-host
boundary in v0 and is not claimed away.

## Atomic one-use execution

Before target spawn, SQLite `BEGIN IMMEDIATE` verifies exact canonical Claim,
Mediation, and `action_executions_v0` table schemas, rejects every trigger and
view, compares the complete private Claim and Mediation rows, and inserts one
`reserved` row keyed by `mediation_sha256`.

The reservation commits before spawn. Concurrent or replayed calls cannot
start a second process. A host crash may leave a `reserved` row; that is a
deliberate fail-closed terminal ambiguity and requires external reconciliation,
not automatic replay.

## Exact process boundary

The process receives:

- no shell expansion (`shell=False`);
- only the approved argv after the executable;
- a completely replaced environment containing exactly the NFC-normalized
  committed names and values, with no inherited variables;
- exact canonical JSON UTF-8 stdin;
- a new process group;
- the signed timeout;
- the verified OS network sandbox.

Timeout kills the complete process group. Stdout and stderr are drained
concurrently, never embedded in the result, and each is limited to 1 MiB. An
overflow kills the process group. The terminal statuses are `completed`,
`failed`, `timed-out`, `output-limit-exceeded`, and `spawn-failed`.

## Redacted attempt evidence

`loom-action-process-attempt/v0` stores only exit code or terminating signal,
duration, timeout, stream byte counts and SHA-256 digests, stdin digest,
sandbox digest, host remeasurement digest, and denied shell/network controls.
No stdout, stderr, environment value, credential, stdin payload, or random
snapshot pathname is returned or persisted.

The terminal attempt updates the already-reserved ledger row exactly once and
is wrapped by `loom-action-bounded-execution/v0`. Bounded Execution v0 does not
issue Action Capsule Result v0, sign an attestation, or claim filesystem
confinement beyond the explicit no-follow measurements and selected launch
boundary.
Terminal Result v0 remains the next contract.

`validate_action_bounded_execution_v0` performs no host IO. It validates the
closed execution, remeasurement, sandbox, path-custody, stream metadata, and
attempt shapes; recomputes every nested and outer hash; checks all cross-links;
and rejects non-canonical or tampered evidence without executing anything.

The standalone browser bundle exposes the same Python API for parity, but a
browser/Pyodide runtime has no supported OS sandbox provider and therefore
fails closed before reservation. The Playground does not invoke this API.
