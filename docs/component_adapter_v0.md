# LOOM Exact Component Adapter Artifact v0

Status: implemented for the modular Python surface, deterministic,
content-addressed, executable under independent verification, zero-import,
one-shot, and non-authorizing.

Component Adapter Artifact v0 is the first real WebAssembly Component emitted
from a checked LOOM program. It is additive to WIT Component Boundary v0 and
requires a bridge-enabled LOOM Tagged Value ABI v2 core. It does not mutate the
boundary, make ABI v2 the default, or project any LOOM effect into WASI.
Its closed content object is `loom-component-adapter-artifact/v0`; build and
verification results use separate schemas and never substitute for that object.

## Public API

```python
loom.build_component_adapter_artifact_v0(
    boundary, source, core_wasm, package, world, exports=None,
    builder_executable=builder,
    wasm_tools_executable=wasm_tools,
)

loom.verify_component_adapter_artifact_v0(
    artifact, component_bytes, boundary, source, core_wasm,
    package, world, exports=None,
    wasm_tools_executable=wasm_tools,
    wasmtime_executable=wasmtime,
)
```

Both tool paths are explicit evidence inputs. The implementation accepts only
the pinned wasm-tools `1.257.1` and Wasmtime `48.0.0` binaries in the closed
macOS arm64 and Linux x86_64 executable-hash allowlist. Their official release
archive digests are pinned separately in CI before extraction. Absence,
replacement, version drift, platform drift, or hash drift fails closed.
The artifact records the build-platform wasm-tools identity; verification may
use the other supported platform identity from the same closed version/hash
allowlist and records that verifier identity separately. This keeps the
component artifact portable without treating unlike binaries as identical.
The repository-owned Rust assembler is locked by `Cargo.lock`; artifacts bind
its executable, source-tree, and lockfile hashes separately.
That binding identifies the exact executable used; v0 does not claim that the
binary hash alone formally proves a reproducible source-to-binary compilation.
CI pins Rust `1.93.0`. The additive
[Signed Reproducible Component Release Attestation v0](component_release_attestation_v0.md)
now performs two clean frozen source builds and binds their exact Component
outputs without changing this artifact schema.

## Component shape

The component embeds exactly three independently recoverable core modules:

1. `deny-env` supplies all eight structural LOOM `env` imports. Every function
   traps, so a Pure-export regression gains no ambient host capability.
2. `loom-core` is byte-identical to the accepted ABI v2 core and is located by
   SHA-256 rather than by module position.
3. `loom-adapter` owns 35 fixed pages of Canonical ABI memory with disjoint
   static, 1 MiB input, bounded scratch, and 1 MiB output regions; it imports only the
   internal LOOM namespace, and exports only the selected WIT functions plus
   required canonical realloc/post-return helpers inside the component.

The public component import set and WASI import set are both empty. The exact
WIT source remains in the `loom.component-adapter.v0` evidence section, while
wasm-tools independently extracts and verifies its semantic type graph.

## Transport

Each WIT export has this wire type:

```wit
func(request: list<u8>) -> result<list<u8>, list<u8>>
```

The adapter itself parses `loom-canonical-json-utf8/v0`; no host JSON parser is
imported. Accepted requests are exact `{"args":[...]}` bytes with no
whitespace. The value domain is signed i31, distinct booleans, strict UTF-8
strings encoded as canonical ASCII JSON escapes, lists, sorted known-field
records, and `{"$variant":["TAG",VALUE]}` with a known module-local tag.
Floats, `null`, NaN, duplicate/unsorted/unknown fields, unknown tags,
noncanonical escapes and numbers, malformed UTF-8, exports or requests above
the closed 32-argument limit, trailing
bytes, depth above 64, more than 2048 aggregate cells, and envelopes above
1 MiB are refused.

Input heap objects are constructed only through Component Bridge v0. Output
pointers, lengths, kinds, chains, UTF-8, field IDs, and tag IDs are checked
before canonical serialization. Closures, resources, and effect boxes do not
cross v0.

## Lifecycle and evidence

Each adapter instance is one-shot. The used flag is set before parsing; every
second call traps. A host must instantiate a fresh component for another
operation. The build artifact says
`instantiable: requires-runtime-verification`; only the verifier may report a
successful Wasmtime instantiation probe.

Verification independently:

- rebuilds Boundary v0 and Component Bridge v0 from exact source/core inputs;
- checks the closed artifact hash and all source/core/WIT/tool identities;
- validates the component with pinned wasm-tools;
- extracts the WIT JSON graph and requires zero component imports;
- unbundles exactly three core modules and matches the exact hash set;
- regenerates deny-env and adapter cores instead of trusting artifact claims;
- checks the exact canonical evidence custom-section bytes;
- invokes a noncanonical-envelope refusal probe through pinned Wasmtime with no
  WASI linker.

`authorization` is always `none`. A valid artifact or validation result proves
identity and behavior only; it is not an operator approval, Action Capsule,
Claim, mediation, execution permission, or capability grant.

## Deliberate boundary

Adapter v0 is host-only and modular-only because building and independently
verifying a Component requires filesystem/process oracles. The browser
standalone remains the ABI v1 Playground and does not pretend to provide this
API. Typed effect-to-WASI projection and the additive
[Effectful Component Adapter v1](effectful_component_adapter_v1.md) now exist
as separate contracts; this zero-import Pure adapter does not consume them.
Reusable instances, streaming values, and public LOOM resources require later
explicit contracts.
Signed release evidence is provided separately by Component Release
Attestation v0 and never changes this artifact's authorization.
