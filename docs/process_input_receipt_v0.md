# LOOM Byte-Counted Process Input Receipt v0

Status: implemented, host-only, process-executing evidence, content-addressed,
non-authorizing, and fail-closed on partial stdin writes.

Process Input Receipt v0 closes one precise gap between Multi-Action Byte
Delivery Evidence v0 and Bounded Execution v0. The earlier detached evidence
proves that the verifier possessed one exact payload preimage. This receipt
proves that the bounded executor's parent-side stdin pipe accepted that exact
payload before the writer end was closed.

It does **not** claim that the child parsed, semantically used, persisted, or
acted on every byte. Those are application-protocol facts, not properties a
generic pipe writer can infer.

## Public API

~~~python
loom.execute_action_host_mediation_with_input_receipt_v0(
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

loom.validate_action_process_input_receipt_v0(receipt, execution)
~~~

The execution API preserves the existing `loom-action-bounded-execution/v0`
artifact and ledger. Its additive validation envelope is
`loom-action-process-input-receipt-validation/v0`. On success it carries both
the unchanged Execution and one `loom-action-process-input-receipt/v0`.

## Counted write boundary

The parent uses the unbuffered subprocess stdin pipe and loops until every
byte has been accepted by `write()`. Each positive returned byte count advances
the SHA-256 state over exactly that accepted slice. Zero, invalid, partial,
broken-pipe, or timed-out writer outcomes cannot produce a valid receipt and
force a previously unclassified successful process attempt to `failed`.

The observation records only:

- SHA-256 and size of the expected mediated stdin;
- SHA-256 and byte count actually accepted by the pipe writes;
- `write_status: "complete"`;
- `writer_end_closed: true`.

Raw stdin bytes and write errors are not persisted. A `spawn-failed` Execution
cannot carry this receipt because no child stdin pipe existed.

## Closed links

The receipt binds:

- `mediation_sha256` and `binding_sha256`;
- the unchanged `execution_sha256` and `attempt_sha256`;
- host-remeasured expected stdin digest and size;
- byte-counted written digest and size;
- the fixed parent stdin-pipe writer profile;
- `receipt_sha256` over the complete preceding body.

Independent validation first revalidates the complete Bounded Execution, then
requires exact link equality, exact expected/written digest and size equality,
a complete write, a closed writer end, the fixed lifecycle, and the canonical
outer hash. Unknown fields, self-consistently rehashed size drift, execution
rebinding, payload embedding, and non-canonical values fail closed.

## Lifecycle and non-claims

The lifecycle is fixed:

~~~text
authorization: none
host_action_executed: true
evidence_kind: byte-counted-stdin-pipe-write
payload_embedded: false
process_input_pipe_delivery: true
process_consumption_proven: false
required_next: loom-action-capsule-result/v0
~~~

The receipt grants no capability and does not replace Approval, Claim,
Mediation, Bounded Execution, or terminal Result. Version 0 is certified on the
POSIX Bounded Execution path. Windows native adapters and a live Multi-Action
scheduler require separate additive contracts and native CI evidence.

The standalone browser Playground does not invoke this host-only API and has
no supported OS process pipe or network-sandbox provider.
