# LOOM Effectful Component Adapter v1

Status: implemented as a deterministic, content-addressed, host-only,
non-authorizing WebAssembly Component adapter for the closed `IO`, `Rand`, and
`Alloc` subset of Typed WASI Capability Mapping v0.

Effectful Component Adapter v1 turns an exact checked ABI v2 mapping into a
real Component. It does not broaden the mapping, infer ambient authority, or
turn evidence into permission. `Net` and `FFI` remain refused.

## Public API

```python
loom.prepare_effectful_component_host_policy_v1(mapping, policy_id)
loom.verify_effectful_component_host_policy_v1(policy, mapping, policy_id)

loom.build_effectful_component_adapter_v1(
    mapping, policy, source, wasm_bytes, package, world, exports=None,
    builder_executable=..., wasm_tools_executable=...,
)

loom.verify_effectful_component_adapter_v1(
    artifact, component_bytes, mapping, policy, source, wasm_bytes,
    package, world, exports=None,
    wasm_tools_executable=..., wasmtime_executable=...,
)
```

The `prepare` call returns a validation envelope; its `policy` field is the
exact object supplied to the builder after `valid` is true.

The artifact schema is `loom-effectful-component-adapter/v1`; build and
verification results use `loom-effectful-component-adapter-build/v1` and
`loom-effectful-component-adapter-validation/v1`. The exact evidence custom
section is `loom.effectful-component-adapter.v1`.

## Closed lowering

- `IO/print` serializes the checked LOOM value as canonical JSON, obtains
  `wasi:cli/stdout@0.2.8`, calls
  `wasi:io/streams.output-stream.blocking-write-and-flush`, and drops the
  output-stream resource before returning.
- The nominal `wasi:io/error@0.2.8` interface is imported because the streams
  resource contract uses its error resource. It exposes no callable operation.
- `Rand/rand` calls `wasi:random/random.get-random-u64` and maps the result to
  the nonnegative i31 range by the exact `u64 modulo 1073741824` rule.
- `Alloc/alloc` stays inside the bounded LOOM reserve path and adds no Component
  import.

The public import set is exactly the sorted union in the accepted mapping.
There is no stdin, stderr, environment, filesystem, clock, network, or generic
foreign import. The generated host policy binds this exact import set and
explicitly records `ambient_authority: false` and `authorization: none`.

## Component shape

The Component embeds exactly four independently recoverable core modules:

1. canonical memory owns 35 fixed pages and never grows;
2. effect environment owns bounded handler/capability stacks and the print log;
3. linked LOOM core is recompiled under `typed-wasi-effect-lowering/v1`;
4. the adapter performs strict canonical JSON lift/lower and WIT export glue.

Every instance is one-shot. Requests are bounded by 1 MiB, 32 arguments, depth
64, and 2048 aggregate cells. The transport is
`loom-canonical-json-utf8/v0`. A fresh instance is required for another call.

## Independent verification

The verifier rebuilds the Typed WASI mapping, host policy, ABI v2 bridge,
effect-linked core, canonical-memory core, effect-environment core, and adapter
core from exact inputs. It then:

- validates the Component with pinned wasm-tools;
- extracts the semantic WIT graph and requires the exact interfaces,
  functions, types, exports, and no extra imports;
- unbundles exactly four core modules and compares their regenerated hashes;
- checks exact custom-section evidence bytes;
- binds source, original core, linked core, mapping, policy, WIT, builder source
  tree, Cargo lockfile, wasm-tools, and final Component bytes;
- uses pinned Wasmtime to link the exact imports and prove rejection of a
  noncanonical envelope.

Citadel additionally invokes real `IO`, `Rand`, and `Alloc` fixtures through
Wasmtime. It checks stdout output and resource completion, random range, bounded
allocation, deterministic builds, toolchain absence, and policy/artifact/binary
tampering.

## Authority boundary

A valid policy, artifact, or verification result proves identity and bounded
behavior only. It is not operator approval, an Action Capsule, a Claim, host
mediation, execution authorization, or a capability grant. Runtime deployment
must still bind the verified Component and policy into the separate operator
Gate lifecycle.

[Effectful Component Execution Binding v0](effectful_component_execution_binding_v0.md)
now implements that non-authorizing bridge through exact precommitments and a
claimed/mediated lifecycle. It deliberately stops before process launch.

This API remains host-only and modular-only because it requires filesystem and
process oracles. It is deliberately absent from `docs/loom.py` and the browser
Playground.
