# LOOM Windows Native Process Input Receipt v0

Status: additive, test-only, revision-bound native Windows evidence. It is
certified only when the exact revision passes the `windows-2025` bounded
execution lane, `verify-windows-bounded-execution`, and emits a valid witness.

Windows Native Process Input Receipt v0 proves parent-side native Windows pipe
acceptance for the exact stdin already bound by Action Approval, Claim,
Mediation, Bounded Execution, and the existing native receipt. It does not
prove process consumption, parsing, persistence, or semantic use of those
bytes.

## Unchanged contracts

The existing `loom-windows-action-bounded-execution/v0`,
`loom-windows-action-result/v0`, native receipt, and SQLite lifecycle ledger
remain byte-compatible. The new evidence is a separate
`loom-windows-process-input-receipt/v0` linked to the existing mediation,
execution, and native receipt hashes.

Its revision-bound CI envelope is
`loom-windows-process-input-receipt-ci-witness/v0`, uploaded independently as
`windows-native-process-input-receipt-v0`.

## Counted native boundary

The Windows certifier starts the fixed native adapter with an unbuffered
anonymous stdin pipe. CPython 3.12 on the native Windows runner delegates each
unbuffered pipe write to the Windows `WriteFile` path. The writer loops and
advances its SHA-256 state and byte count only after a positive returned write
count. It then closes the parent writer end.

A valid receipt requires:

- exact expected and written SHA-256 equality;
- exact expected and written byte-count equality;
- at least one positive write for non-empty stdin;
- `write_status: "complete"`;
- `writer_end_closed: true`;
- exact mediation, binding, execution, and native-receipt links;
- no embedded payload and `authorization: "none"`.

Partial, zero-progress, failed, timed-out, or broken-pipe observations cannot
produce a receipt. A spawn-failed execution cannot carry input-delivery
evidence.

## Native adversarial proof

The `/Brepro` adapter includes a dedicated `--close-stdin` adversarial mode.
It closes its inherited stdin handle without reading and exits. The Windows CI
runner sends a payload larger than the anonymous pipe capacity and requires a
partial or broken write rather than a false complete observation.

The portable verifier also rejects self-consistently rehashed byte-count drift,
execution rebinding, unknown-field or payload injection, and non-canonical
receipt hashes.

## Honest scope

The receipt proves only parent-side pipe acceptance. It does not prove process
consumption. It is test-only, grants no production authority, and does not
claim native operator presence. The standalone browser Playground cannot
create this host-only evidence.

Portable schema and adversarial validation:

```console
python3 tools/windows_bounded_execution_conformance.py --self-test
```

Certifying mode is restricted to the pinned GitHub Actions Windows runner and
must receive both output paths. Outside that environment it fails closed and
emits neither witness.
