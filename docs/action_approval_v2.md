# LOOM Exact Action Approval v2

Status: implemented, normative, signed, short-lived, exact-invocation-bound,
and claim-required.

Action Approval v2 is the first operator-authority object in the Action Capsule
line. It signs the complete `loom-action-invocation-binding/v0` identity rather
than a manifest, command label, or free-form intent. The signed subject already
commits to the Capsule, compiler evidence, Tool Input, executable bytes, argv,
working directory, environment value commitments, canonical stdin, timeout,
and denied shell/network modes.

Approval alone does not start the process. A valid result reports
`authorization: "claim-required"`. Capsule Claim v0 is implemented separately
and must atomically reserve the one-use approval; trusted host mediation must
still remeasure host inputs before any invocation.

## Public API

~~~python
loom.build_action_approval_request_v2(binding, nonce)
loom.validate_action_approval_request_v2(request)

loom.verify_action_capsule_approval_v2(
    approval,
    request,
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
    now_unix_ms,
)
~~~

The builder and request validator are deterministic and pure. Verification is
deterministic for its explicit `now_unix_ms` input and reads only the pinned
operator public key. None of these APIs executes a process, reads an
environment value, claims or consumes an approval, writes a ledger, or exposes
a private key.

The verification envelope is
`loom-action-capsule-approval-validation/v2`. Its approval subject is exactly
`approval_subject: "binding_sha256"`; a valid but unclaimed signature reports
`authorization: "claim-required"`.

## Closed challenge and request

The host supplies a fresh 256-bit lowercase hexadecimal nonce. The resulting
`loom-action-approval-challenge/v2` binds:

- `binding_sha256`;
- `capsule_sha256`;
- `invocation_sha256`;
- the nonce;
- `challenge_sha256` over the complete preceding body.

The closed `loom-action-approval-request/v2` embeds the complete Invocation
Binding, challenge, deterministic human review surface, fixed lifecycle, and
`request_sha256`. The review surface uses
`loom-action-approval-review/v2` and displays agent/task declarations,
executable URI and digest, argv, cwd, environment names plus value hashes,
stdin hash, timeout, shell mode, and network mode. Raw environment values and
secrets never enter the request.

`validate_action_approval_request_v2` rejects unknown or missing fields and
rebuilds the complete request. A caller cannot alter the review text, hide an
argument, exchange an executable, or recompute only outer hashes while
preserving validity.

The request lifecycle is fixed:

~~~json
{
  "schema": "loom-action-approval-request-lifecycle/v2",
  "authorization": "none",
  "approval_subject": "binding_sha256",
  "approval_schema": "loom-action-capsule-approval/v2",
  "claim_required": true,
  "maximum_ttl_ms": 900000
}
~~~

## Signed approval

The external operator issuer validates the request, displays its review
surface, obtains explicit operator presence, and signs one closed
`loom-action-capsule-approval/v2` object with the existing pinned RSA
PKCS#1 v1.5 SHA-256 identity. The signature covers:

- request, challenge, binding, Capsule, and invocation hashes;
- `approval_scope: "exact-invocation"`;
- `approver: "operator"` and `decision: "approve"`;
- integer `issued_at_unix_ms` and `expires_at_unix_ms`;
- `claim_required: true` and the pinned key hash.

The validity interval must be positive and at most 900000 milliseconds. Boolean
timestamps, future-issued approvals, expired approvals, oversized windows,
unknown fields, wrong keys, and invalid signatures fail closed. Time is an
explicit trusted-host input; the verifier does not hide a wall-clock read.

The reference issuer supports both Gate Approval v1 and Action Approval v2:

~~~console
python3 examples/native_issuer.py request.json operator_private_key.json approval.json
~~~

For v2 it shows the exact invocation review and defaults to a five-minute TTL.
It writes only `approval.json`; the private key remains outside LOOM.

## Exact verification

Before checking the signature, the verifier validates the request and calls
`verify_action_invocation_binding_v0` with all external manifest, Tool Binding,
Tool Input, source, WASM, compiler, entrypoint, and invocation inputs. Therefore
even a structurally valid request for another invocation cannot be substituted.
The verifier then checks every signed cross-link, validity time, key identity,
and signature before returning the approval hash.

Approval v2 is additive. Existing Gate Approval v1, Gate claim/executor,
Action Capsule v0, Invocation Binding v0, Compiler Evidence, Receipt, Workflow,
CLI, Playground, MCP, A2A, WASI, and host-executor schemas are unchanged.
Capsule Claim v0 is implemented as a separate additive stateful contract.
Executable/environment remeasurement, host mediation, execution, and terminal
Action Capsule Result v0 remain separate future contracts.
