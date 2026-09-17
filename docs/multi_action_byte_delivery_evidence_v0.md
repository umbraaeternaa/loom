# LOOM Multi-Action Byte Delivery Evidence v0

Status: implemented, host-only, bounded, advisory, non-authorizing, and
detached-payload.

Multi-Action Byte Delivery Evidence v0 binds one detached byte witness to the
complete signed Evidence Dataflow chain. It proves that the exact bytes held by
the caller are canonical JSON UTF-8, fit the 1 MiB bound, and have the same
SHA-256 and size as the signed source output and the target Invocation Binding
stdin commitment.

The artifact deliberately does not embed the payload. Verification requires the
same detached byte witness again. This provides exact replay without copying a
possibly sensitive payload into a long-lived evidence document.

## API

```python
delivery = loom.build_multi_action_byte_delivery_evidence_v0(
    resolution,
    dataflow,
    plan,
    {"consume": consume_invocation_binding},
    delivered_bytes,
    operator_public_key,
)["evidence"]

loom.verify_multi_action_byte_delivery_evidence_v0(
    delivery,
    resolution,
    dataflow,
    plan,
    {"consume": consume_invocation_binding},
    delivered_bytes,
    operator_public_key,
)
```

Both calls are pure artifact operations. They execute no action, open no file,
write no pipe, contact no network, and grant no authority.

## Closed evidence

The `loom-multi-action-byte-delivery-evidence/v0` artifact binds:

- the exact Dataflow Resolution, declaration, Plan, and edge hashes;
- the signed source Result hash and source step;
- the target step, Invocation Binding, invocation, and approval-boundary hashes;
- detached witness encoding, SHA-256, exact size, and the 1 MiB ceiling;
- explicit three-way source/target/witness digest equality;
- explicit source/witness size equality.

The raw payload is not present. The witness section states
`payload_embedded: false`; replay fails unless the verifier supplies the exact
bytes again. Wrong bytes, non-bytes values, malformed UTF-8, duplicate JSON
keys, non-canonical JSON, payloads larger than 1 MiB, source-size drift,
signature drift, chain drift, unknown fields, and self-consistently rehashed
tampering fail closed.

## What the proof means

The proof establishes a bounded byte handoff fact:

1. a successful signed source Result commits to digest and size;
2. a resolved direct dataflow edge commits to the same target stdin digest;
3. the verifier possessed one exact canonical byte sequence with that digest
   and size when it built or replayed the evidence.

This is stronger than digest-only Dataflow Resolution because the verifier must
possess the preimage bytes. It is intentionally weaker than an operating-system
claim that a child process consumed every byte. The current Bounded Execution
records the intended stdin digest, but its pipe writer does not yet issue a
byte-counted write receipt.

## Authority and custody boundary

The lifecycle states:

```text
authorization: none
host_actions_executed: false
host_byte_transport: false
process_delivery_proven: false
payload_embedded: false
byte_custody: external
byte_witness_required_for_replay: true
approval_inheritance: forbidden
```

The source Approval remains scoped to the source Invocation Binding. Delivery
evidence cannot authorize the target. The target still requires its own exact
Approval, Claim, Host Mediation, Bounded Execution, and terminal Result.

## Deliberate exclusions

V0 does not provide:

- payload storage, encryption, redaction, transport, pipe or file IO;
- proof that a process accepted or consumed every byte;
- a scheduler, retry, rollback, compensation, transform, merge, or codec;
- approval inheritance, ambient authority, private-key custody, or live host
  execution.

The next honest frontier is a byte-counted process-input receipt emitted by the
bounded host executor. Until that separate contract exists, callers must not
reinterpret this artifact as process-ingestion evidence.

The API is host-only and modular-only. It is absent from the standalone browser
Playground, which exposes neither the Action lifecycle nor operator signing.
