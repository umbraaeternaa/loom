# LOOM Interface and Tool Binding v0

Status: normative, deterministic, read-only, advisory, and non-authorizing.

Interface and Tool Binding v0 is the first pure Action Capsule primitive. It
content-addresses what a host interface means and what exact tool invocation is
being discussed. It does not execute that invocation and does not grant anyone
permission to execute it.

## Public API

The modular and standalone Python surfaces expose the same four functions:

```python
build_interface_binding(protocol)
verify_interface_binding(binding, protocol)
build_tool_binding(protocol, authority, operation, input_value)
verify_tool_binding(binding, protocol, authority, operation, input_value)
```

Each function returns a closed validation object. A successful build or verify
contains the canonical binding; a failed operation returns `binding: null` and
structured findings. No function performs host IO.

## Interface Binding v0

Schema: `loom-interface-binding/v0`.

The only protocol in v0 is `local-process/v1`. Its descriptor pins the exact
closed contracts already used by the Gate host boundary:

- plan: `loom-gate-execution-plan/v1` and its validation schema;
- attempt: `loom-gate-host-attempt/v1` and its validation schema;
- allowed attempt results: `blocked`, `completed`, and `failed`;
- action: `process` only;
- executor boundary: `no-shell/no-network-by-default`.

The descriptor is hashed as canonical JSON. Verification rebuilds the pinned
descriptor from the protocol name, so editing both the descriptor and its hash
does not create a valid alternative interface.

## Tool Binding v0

Schema: `loom-tool-binding/v0`.

A tool binding fixes all of the following in one canonical object:

- protocol and complete Interface Binding v0;
- authority: `urn:loom:host:operator-gate`;
- operation: `process`;
- normalized JSON input and its SHA-256 digest;
- normalized input and output-contract digests;
- the outer binding digest.

Verification rebuilds that complete object from the expected protocol,
authority, operation, and input. Recomputing hashes after changing any nested
contract therefore remains invalid.

## Portable JSON profile

Tool input is normalized before hashing. The v0 profile accepts only JSON null,
booleans, strings, integers, arrays, and objects. It additionally requires:

- NFC-normalized strings and object keys;
- no floating-point values;
- integers inside the JavaScript-safe range;
- maximum nesting depth 16;
- maximum 256 members per array or object;
- maximum 65536 UTF-8 bytes per string or key;
- no duplicate object keys after NFC normalization.

This profile makes modular Python, standalone Python, and future browser hosts
hash the same semantic input identically.

## Authority boundary

These bindings are advisory descriptions, not capabilities. They do not:

- execute a process or invoke any tool;
- sign an artifact or collect credentials;
- approve, claim, delegate, or attenuate authority;
- replace the operator Gate or the existing host lifecycle.

Action Capsule v0 and an additive Approval v2 that binds an exact capsule hash
remain outside this contract. They must be specified separately before a
binding can participate in an authorizing lifecycle.
