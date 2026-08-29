# LOOM module boundaries

Status: production-readiness contract for keeping `loom.py` as a stable public
facade while implementation code continues moving into focused modules.

## Public facade

`loom.py` remains the compatibility surface imported by users, the playground,
Gate clients, tests, and published docs. Public functions exposed there should
delegate into extracted modules rather than re-growing independent copies of
the same behavior.

## Extracted modules

Current stable boundaries:

| Module | Boundary |
| --- | --- |
| `loom_parse.py` | tokenization, parsing, and source spans |
| `loom_checker.py` | static effect/trust/capability checking |
| `loom_bounds.py` | conservative i31/list bounds and contextual specialization |
| `loom_frontend.py` | shared parser/checker/backend adapter contracts and ASM registry |
| `loom_runtime.py` | interpreter runtime and capability contexts |
| `loom_codegen.py` | portable Python and JavaScript backends |
| `loom_wasm.py` | WebAssembly/WAT backend and ABI runtime |
| `loom_component.py` | deterministic WIT component-boundary projection and verification |
| `loom_wasi_capabilities.py` | host-only Typed WASI effect projection and exact mapping verification |
| `loom_recursion.py` | shared named-call graph, recursive-SCC edges, static descent certificates, and quantitative recurrence metadata |
| `loom_provenance.py` | host-built content-addressed compiler profiles and closed surface collection |
| `loom_cli.py` | CLI and machine-readable verdict surface |
| `loom_gate.py` | Gate manifest, policy, diagnostics, and advisory receipt logic |
| `loom_observer.py` | read-only Git observation collection |
| `loom_evidence.py` | CI evidence collection |
| `loom_approval.py` | signed one-use operator approval lifecycle |
| `loom_executor.py` | claimed execution and process-attempt lifecycle |
| `loom_effectful_execution.py` | exact Effectful Component resource-to-claimed-lifecycle binding |

## Gate boundary rule

Gate behavior must have one implementation truth in `loom_gate.py`. The public
facade in `loom.py` may expose:

- `validate_manifest`
- `evaluate_manifest`
- `build_gate_diagnostics`
- `build_receipt`

but those functions must delegate to the extracted Gate module and preserve the
same stable schemas:

- `loom-gate-manifest-validation/v1`
- `loom-gate-decision/v1`
- `loom-gate-diagnostics/v1`
- `loom-gate-receipt-validation/v1`
- `loom-gate-receipt/v1`

The standalone browser bundle in `docs/loom.py` may inline the same stable
facade so it can run without development-only module imports in Pyodide.

A future migration may split Gate further, but it must keep the public facade
stable and pin the new boundary before deleting the old one.

## WASM compiler state boundary

The WebAssembly backend must keep all program-specific compiler state inside a
fresh per-compilation context. Closure tables, top-level function maps, helper
function indexes, apply-dispatch indexes, tag IDs, field IDs, resource IDs,
foreign IDs, string layouts, heap offsets, and source-span maps are local to one
compiled module.

Development `loom.py` may keep one stable frontend adapter for calls into
`loom_wasm.py`, but it must not own mutable `_WASM_*` compiler tables. The
standalone browser bundle in `docs/loom.py` may inline the same implementation,
but it must preserve the same per-compilation isolation rule.

This boundary is part of production-readiness: separate builds, parallel builds,
and repeated browser playground runs must not inherit closure/layout state from
an earlier program.

## Component boundary rule

`loom_wasm.py` owns Component Bridge Extension v0 because its five reserved
constructors share the backend's private `$reserve` allocator, object layouts,
module-local field/tag IDs, and diagnostic counters. Every compile emits one
exact `loom.component-bridge.v0` section. The public verifier is exposed only
through the stable `loom.py` facade. ABI v1 modular and standalone compilers
and verifiers remain byte-identical. Tagged Value ABI v2 is currently an
explicit modular-only profile; the standalone browser bundle must report only
ABI v1 until v2 is deliberately published there.

`loom_component.py` may consume the public parser/checker and deterministic WASM
facades, but it must not modify supplied core-WASM bytes. WIT Component Boundary
v0 is a content-addressed description of Pure exports, exact WIT, transport,
lifecycle state, and the selected ABI v1/v2 profile. It is not a component
binary and grants no WASI capability.

The standalone browser bundle may inline the same implementation, but modular
and standalone builders/verifiers must produce byte-identical boundary objects
for identical source, WASM, package, world, and export inputs.

`loom_wasi_capabilities.py` owns Typed WASI Capability Mapping v0. It consumes
only checked ABI v2 source/core identity and emits a content-addressed,
non-executable WIT import projection. It must minimize imports, pin the exact
WASI release/spec sources, reject unmapped effects, grant no authority, and
remain excluded from the ABI v1 browser standalone profile.

`loom_component_adapter.py` owns Exact Component Adapter Artifact v0. It may
invoke only explicitly supplied, hash-pinned builder, wasm-tools, and Wasmtime
executables. It generates a separate Canonical ABI memory, embeds the exact ABI
v2 core unchanged, and independently re-extracts all embedded modules and WIT.
It must expose no WASI/component import, mutate no Boundary v0 artifact, infer
no authority, or silently fall back when its external oracle is absent. This
host-only module is deliberately excluded from the standalone browser bundle.

The same module owns Effectful Component Adapter v1 as an additive contract. It
must consume an exactly reverified Typed WASI mapping and separately verified
host policy, embed exactly four regenerated core modules, import no interface
beyond the mapping, and lower only `IO`, `Rand`, and `Alloc`. Its repository
owned Rust builder lives under `tools/loom-effectful-component-builder` and is
source-tree/Cargo-lock pinned. `Net`, `FFI`, ambient authority, authorization,
fallback tools, and browser publication remain forbidden.

`loom_effectful_execution.py` owns the additive bridge from that verified
Effectful Component to Action Claim/Mediation state. It must independently
reverify the Component, require operator-signed environment commitments for
artifact/component/mapping/policy/export/request identities, measure the exact
Component URI without following symlinks, and prove matching private ledger
rows without consuming them. It grants no authority and must require a later
executor to reverify Approval v2, remeasure the Component, and launch only an
exact private snapshot.

`loom_component_release.py` owns Signed Reproducible Component Release
Attestation v0. It may run exact offline Cargo builds, inspect locked registry
sources, invoke the Component builder/verifier, and verify an external DSSE
signature. It must not hold a private key, grant authorization, or enter the
browser standalone bundle.

## Citadel pin

The citadel pins this contract by checking that development `loom.py` is backed
by the extracted `loom_gate` module and that facade calls match direct module
calls for manifest validation, policy evaluation, redacted diagnostics, and
receipt building. It also checks that the standalone browser bundle preserves
the same public schemas without importing development-only modules. The WASM
pin also checks that compiler contexts remain isolated across parallel builds
and that legacy module-global `_WASM_*` compiler tables do not return.
