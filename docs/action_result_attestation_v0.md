# LOOM Action Result Attestation v0

Status: implemented, normative, signed, content-addressed, post-execution,
externally issued, and non-authorizing.

Action Result Attestation v0 binds one terminal Action Capsule Result v0 to the
exact Gate Compiler Receipt v4 and WASM artifact that describe the same action.
It uses an in-toto Statement v1 inside a DSSE envelope. It does not change,
replace, or authorize any earlier Action or Gate contract.

## Public API

~~~python
loom.prepare_action_result_attestation_v0(
    result, gate_receipt, manifest, observation, source, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key, attested_at_unix_ms,
)

loom.build_action_result_attestation_v0(
    result, gate_receipt, manifest, observation, source, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key, attested_at_unix_ms, signature,
)

loom.verify_action_result_attestation_v0(
    envelope, manifest, observation, source, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key,
)
~~~

`prepare_action_result_attestation_v0` returns the canonical Base64 payload,
the exact Base64 DSSE PAE signing bytes, their SHA-256 digest, and the expected
attester key digest. It never reads or receives a private key. An external
issuer signs those exact PAE bytes. `build_action_result_attestation_v0` verifies
the supplied RSA PKCS#1 v1.5 SHA-256 signature before constructing the envelope.

## Statement and envelope

The payload is a canonical UTF-8 JSON
[`https://in-toto.io/Statement/v1`](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with predicate type:

~~~text
https://umbraaeternaa.github.io/loom/attestation/action-result/v0
~~~

Its subjects bind exactly:

- `loom-action-result.json` by `result_sha256`;
- `loom-gate-receipt-v4.json` by `receipt_sha256`;
- `loom-program.wasm` by the verified WASM SHA-256 digest.

The predicate embeds the complete Result and Receipt, the attester identity,
the attestation time, a terminal non-authorizing lifecycle, and closed
cross-links for the manifest, Capsule, Invocation, Approval, Execution,
Outcome, Result, Receipt, artifact binding, and Compiler Evidence.

The envelope follows
[`DSSEv1`](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
and signs the exact PAE sequence for `application/vnd.in-toto+json`. Standard
and URL-safe Base64 are accepted. A signature `keyid` and unknown envelope
fields are untrusted routing hints; authorization never depends on them. With
multiple signatures, verification succeeds only when at least one signature
matches the explicitly supplied trusted attester public key.

## Fail-closed verification

Verification is ordered deliberately:

1. decode bounded payload and signature bytes;
2. verify the DSSE signature over the exact payload bytes;
3. parse that payload once;
4. reject duplicate keys, NaN or Infinity, excessive depth or node count, and
   every non-canonical JSON encoding;
5. revalidate the embedded terminal Result and complete Receipt v4;
6. rebuild and compare the exact expected Statement.

The Result status must match the Receipt result. The Receipt must observe
exactly the `process` action. Its manifest, Compiler Evidence v2, compiler
evidence digest, and artifact binding digest must match the embedded Action
Semantics exactly. The attestation timestamp cannot predate Result finalization.
Any mismatch fails closed with a structured finding.

## Trust boundary

A valid envelope means that the trusted attester key signed this exact
post-execution evidence composition. It does not mean:

- that the signature granted permission to execute;
- that LOOM accessed or protected the attester private key;
- that the process ran again during attestation;
- that a transparency log or trusted timestamp exists;
- that an in-toto layout, SLSA level, publisher identity, or third-party audit
  has been established.

The lifecycle remains `authorization: "none"`, `terminal: true`, and
`execution_repeated: false`. Approval v2 remains the only operator-signed
pre-execution authority in this chain.
