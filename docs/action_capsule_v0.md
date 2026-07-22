# LOOM Action Capsule v0

Status: implemented, normative, deterministic, pure, advisory, and non-authorizing.

Action Capsule v0 composes one normalized Gate manifest, its exact advisory
Gate decision, a declaration-only actor, and complete Action Semantics v0 into
one closed content-addressed object. It gives a verifier one immutable semantic
subject. It is not an approval, principal identity, capability, invocation,
claim, execution result, or receipt.

## Public API

~~~python
loom.build_action_capsule_v0(
    manifest,
    tool_binding,
    tool_input,
    source,
    wasm_bytes,
    builder_components,
    entrypoint,
)

loom.verify_action_capsule_v0(
    capsule,
    manifest,
    tool_binding,
    tool_input,
    source,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
    entrypoint,
)
~~~

Both functions are pure. They perform no filesystem collection, execute no
command, invoke no host callback, access no network, prompt for no credential,
write no ledger, and consume no approval.

The validation envelope uses schema
"loom-action-capsule-validation/v0". On failure, "capsule" is null. Compiler
attribution remains outside the immutable Capsule so verifier-local identity
cannot rewrite builder content.

## Closed Capsule

Every field below is required. Unknown fields are rejected.

~~~json
{
  "schema": "loom-action-capsule/v0",
  "advisory": true,
  "manifest": {"schema": "loom-gate-manifest/v1"},
  "manifest_sha256": "<sha256>",
  "gate_decision": {
    "schema": "loom-gate-decision/v1",
    "advisory": true,
    "policy": "operator-codex-cloud/v1",
    "manifest_sha256": "<sha256>",
    "decision": "operator-required",
    "reasons": [],
    "violations": []
  },
  "declared_actor": {
    "schema": "loom-action-actor-declaration/v0",
    "profile": "manifest-declared/v0",
    "id": "codex",
    "role": "code",
    "identity_assurance": "declaration-only"
  },
  "action_semantics": {"schema": "loom-action-semantics/v0"},
  "action_semantics_sha256": "<sha256>",
  "bindings": {
    "schema": "loom-action-capsule-bindings/v0",
    "tool_binding_sha256": "<sha256>",
    "compiler_evidence_sha256": "<sha256>",
    "artifact_binding_sha256": "<sha256>"
  },
  "execution_class": {
    "schema": "loom-action-execution-class/v0",
    "protocol": "local-process/v1",
    "authority": "urn:loom:host:operator-gate",
    "operation": "process",
    "foreign_component": "operator-gate",
    "maximum_ffi_requests": 1,
    "concrete_invocation": "unbound",
    "host_boundary": "no-shell/no-network-by-default"
  },
  "lifecycle": {
    "schema": "loom-action-capsule-lifecycle/v0",
    "authorization": "none",
    "approval_eligible": false,
    "required_before_authorization": [
      "loom-action-invocation-binding/v0",
      "loom-action-capsule-approval/v2",
      "loom-action-capsule-claim/v0",
      "loom-action-host-mediation/v0"
    ],
    "required_after_attempt": [
      "loom-action-capsule-result/v0",
      "loom-gate-receipt/v4"
    ]
  },
  "capsule_sha256": "<sha256>"
}
~~~

The displayed manifest and action_semantics values are abbreviated only in
this example. The actual object embeds each complete normalized closed object.

## Exact derivation

- manifest is exactly validate_manifest(manifest)["normalized_manifest"].
  Action Capsule v0 admits only loom-gate-manifest/v1 and exactly the process
  action.
- manifest_sha256 is the validator's canonical digest.
- gate_decision is the complete exact evaluate_manifest result. It must be
  operator-required, contain no violations, and reference the same manifest
  hash.
- declared_actor.id and declared_actor.role are copied from manifest.agent.
  identity_assurance: declaration-only explicitly makes no
  authenticated-principal claim.
- action_semantics is the complete result of build_action_semantics_v0. A
  caller cannot inject prebuilt semantics into the builder.
- All fields in bindings are exact cross-links to embedded Action Semantics.
- execution_class is derived from Tool Binding, Target Mediation, the checked
  seamN 1 meter, and the Interface Binding executor boundary.
- lifecycle is a fixed constant. It accepts no caller input.
- capsule_sha256 is SHA-256 over canonical JSON for every Capsule field except
  capsule_sha256 itself.

Reordered input manifest keys normalize to the same Capsule. Any meaningful
manifest, tool, input, source, WASM, compiler, actor, decision, binding,
execution-class, or lifecycle change either fails verification or produces a
different Capsule hash.

## Verification order

The verifier first rejects unknown, missing, malformed, non-canonical, or
incorrectly hashed immutable content. It validates the embedded normalized
manifest, Gate decision shape, complete Action Semantics structure, all
cross-links, fixed execution class, fixed lifecycle, and outer hash.

It then calls verify_action_semantics_v0 with the external manifest, Tool
Binding, Tool Input, source, WASM, builder surface/components, verifier
components, and entrypoint. A valid builder/verifier profile difference returns
only wasm-compiler-drift; it does not add source, manifest, tool-input,
semantic, Capsule, or generic mismatch findings. Same-profile mutations retain
the narrower nested semantic or compiler finding. Finally the verifier rebuilds
the complete expected Capsule and rejects any remaining difference as
action-capsule-mismatch.

## Authorization boundary

These values are normative and immutable:

- concrete_invocation: "unbound"
- authorization: "none"
- approval_eligible: false

Action Semantics v0 binds the normalized Tool Input
{"action":"process","manifest_sha256":"<exact-manifest-hash>"}. It does not bind
an executable, argv, cwd, environment, stdin, callback, concrete host payload,
or process result. Therefore Capsule v0 cannot identify what a host would
actually invoke and cannot be approved for execution.

Exact loom-action-invocation-binding/v0 must be designed and implemented before
Approval v2. Approval v2, claim, trusted host mediation, and terminal Action
Capsule Result v0 remain separate future contracts. Compiler Receipt v4 already
exists as stable evidence, but the pre-execution Capsule does not embed it
because no execution observation exists yet. Capsule v0 contains no nonce,
timestamp, expiry, signature, key, token, delegation, ambient authority,
approval, claim, ledger state, execution output, or freshness assertion.

Existing Gate, Interface/Tool Binding, Action Semantics, Compiler Evidence,
Receipt, Workflow, approval, and claim schemas remain unchanged. No CLI,
Playground, MCP, A2A, WASI, identity, or host-executor adapter is added by this
contract.
