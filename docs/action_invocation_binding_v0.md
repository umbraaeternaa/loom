# LOOM Exact Invocation Binding v0

Status: implemented, normative, deterministic, pure, advisory, and
non-authorizing.

Exact Invocation Binding v0 closes the gap between an Action Capsule and one
concrete local host invocation. It binds the complete Capsule, exact host
adapter identity, arguments, working directory, committed environment, stdin
payload, timeout, and denied shell/network modes into one content-addressed
approval subject. It does not approve or execute that subject.

## Public API

~~~python
loom.build_action_invocation_binding_v0(
    manifest,
    tool_binding,
    tool_input,
    source,
    wasm_bytes,
    builder_components,
    entrypoint,
    invocation,
)

loom.verify_action_invocation_binding_v0(
    binding,
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
)
~~~

Both functions are pure. They perform no filesystem lookup, executable
measurement, process creation, shell expansion, network access, environment
read, secret read, approval, claim, or host callback.

The validation envelope uses
`loom-action-invocation-binding-validation/v0`. On failure, `binding` is null.
Compiler attribution remains verifier-local and outside immutable binding
content.

## Invocation descriptor

The caller supplies one closed `loom-local-process-invocation/v0` descriptor:

~~~json
{
  "schema": "loom-local-process-invocation/v0",
  "protocol": "local-process/v1",
  "authority": "urn:loom:host:operator-gate",
  "operation": "process",
  "foreign_component": "operator-gate",
  "adapter": {
    "schema": "loom-host-adapter-identity/v0",
    "executable_uri": "file:///opt/loom/operator-gate",
    "artifact_sha256": "<sha256>",
    "entrypoint": "process"
  },
  "argv": ["process", "--canonical-json"],
  "working_directory_uri": "file:///workspace/loom",
  "environment": [
    {"name": "LOOM_MODE", "value_sha256": "<sha256>"}
  ],
  "stdin": {
    "schema": "loom-action-invocation-stdin/v0",
    "encoding": "canonical-json/utf-8",
    "payload_sha256": "<exact-tool-input-sha256>"
  },
  "timeout_ms": 30000,
  "shell": "denied",
  "network": "denied"
}
~~~

The executable and working directory are absolute file URIs. The v0 URI profile
rejects dot segments, empty interior segments, query strings, fragments, and
backslashes so two hosts cannot resolve the same signed text differently. The
adapter digest commits to exact executable bytes; a later trusted host must
measure those bytes before invocation. `argv` contains only arguments after
the executable and preserves order. Environment entries are sorted by
normalized name and contain value commitments, never raw values. A value
commitment is SHA-256 over the exact NFC-normalized UTF-8 environment value
that later host mediation must supply. Duplicate names, unknown fields, floats,
booleans used as integers, relative paths, NUL bytes, raw environment values,
and non-canonical stdin are rejected.

The stdin payload digest must equal the normalized Tool Binding input digest.
The only encoding is canonical JSON UTF-8. The timeout is an integer from 1 to
3600000 milliseconds. Shell and network remain denied in v0.

## Closed binding

Every field is required and unknown fields are rejected:

~~~json
{
  "schema": "loom-action-invocation-binding/v0",
  "advisory": true,
  "capsule": {"schema": "loom-action-capsule/v0"},
  "capsule_sha256": "<sha256>",
  "invocation": {
    "schema": "loom-local-process-invocation/v0",
    "invocation_sha256": "<sha256>"
  },
  "invocation_sha256": "<sha256>",
  "cross_links": {
    "schema": "loom-action-invocation-cross-links/v0",
    "capsule_sha256": "<sha256>",
    "tool_binding_sha256": "<sha256>",
    "input_sha256": "<sha256>",
    "adapter_artifact_sha256": "<sha256>"
  },
  "lifecycle": {
    "schema": "loom-action-invocation-lifecycle/v0",
    "authorization": "none",
    "approval_eligible": true,
    "approval_subject": "binding_sha256",
    "required_next": [
      "loom-action-capsule-approval/v2",
      "loom-action-capsule-claim/v0",
      "loom-action-host-mediation/v0"
    ]
  },
  "binding_sha256": "<sha256>"
}
~~~

The displayed Capsule and invocation are abbreviated. The actual binding
embeds both complete closed objects.

## Exact derivation and verification

The builder does not accept a prebuilt Capsule. It rebuilds Action Capsule v0
from the manifest, Tool Binding, Tool Input, source, WASM, compiler components,
and entrypoint. It then normalizes the invocation, binds its stdin to the exact
Tool Input digest, and creates all cross-links and hashes.

The verifier first validates closed structure, fixed class values, normalized
environment ordering, nested hashes, cross-links, lifecycle, and the outer
digest. It then verifies the embedded Capsule against every external compiler
and semantic input and rebuilds the complete expected Invocation Binding. An
attacker cannot change the executable digest, argv, cwd, environment
commitment, stdin, timeout, Capsule, or lifecycle and regain validity merely by
recomputing hashes.

Valid modular/standalone compiler differences retain the narrow
`wasm-compiler-drift` attribution. They do not become a generic invocation
mismatch.

## Authorization boundary

`approval_eligible: true` means only that Approval v2 now has an exact immutable
subject to sign. It does not mean approved or authorized. These values remain
normative:

- `authorization: "none"`
- `approval_subject: "binding_sha256"`
- `shell: "denied"`
- `network: "denied"`

Exact Action Approval v2 is implemented as a separate short-lived RSA signature
over this binding. Approval validation still returns `claim-required`; Capsule
Claim v0 then atomically reserves that exact approval. Trusted Host Mediation v0
remeasures executable bytes, cwd identity, environment commitments, and
canonical stdin without executing. Bounded process execution and terminal
Action Capsule Result v0 remain separate future contracts. The old Gate
approval/executor lifecycle remains unchanged and does not implicitly consume
this binding.

Existing Gate, Interface/Tool Binding, Action Semantics, Action Capsule,
Compiler Evidence, Receipt, Workflow, approval, claim, CLI, Playground, MCP,
A2A, WASI, and host-executor schemas remain unchanged.
