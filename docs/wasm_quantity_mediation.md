# LOOM WASM Quantity Mediation Roadmap

Status: design contract for future LOOM WebAssembly runtime work. This
document does not change ABI v1 by itself.

## Current Truth

LOOM has two different quantity stories today:

- Source quantities: `seamN K` is enforced by the LOOM checker before code
  generation. The accepted source program is the authority for the quantum.
- Runtime heap quantities: generated WASM exports `loom_heap_limit` and
  `loom_heap_used`; `$reserve` increments the used counter for each successful
  heap allocation.

ABI v1 now has an internal compiler-emitted direct-effect counter for `seamN`.
Generated WASM still contains capability presence gates through `push_caps` and
`has_cap`; additionally, direct `IO`, `Net`, `Rand`, and `Alloc` effect
boundaries inside a metered seam decrement a local runtime counter before the
effect becomes visible. This does not add imports, exports, globals, object
layouts, or host obligations.

That internal meter is not yet a full ABI-enforced quantity mediation layer for
closures, recursion, effect handlers, or future heap growth.

## Rule Before Growth

Do not add `memory.grow` until heap growth is explicitly metered by LOOM.

Do not add runtime `seamN` counters independently from heap metering unless
the interaction between both meters is specified and tested.
Capability-use quantity and heap-byte quantity are one runtime-mediation family:
both must be deterministic, host-visible, and fail-closed.

## Candidate Runtime Contract

A future runtime quantity contract should provide:

- A scoped capability meter frame pushed when entering a metered seam.
- One counter per stable effect ID named by that seam.
- Decrement-or-trap behavior at every runtime effect boundary.
- Deterministic handling for closures, recursion, handlers, and `applyN`
  dispatchers.
- Host-visible exports or diagnostics for the active quantity state.
- A heap budget contract where `$reserve(size)` checks and records bytes before
  object stores, and any future grow path is charged before memory expands.

The trap point must be before the effect or allocation becomes externally
visible.

## ABI Impact

Adding runtime capability-use counters changes the module boundary if it adds
new imports, exports, globals, object layouts, or host obligations. In that
case, LOOM must either:

- keep ABI v1 unchanged and expose the meter only as an internal codegen
  strategy with no new host contract, or
- define ABI v2 with a new normative document and explicit host rejection for
  unknown versions.

## Non-Goals

- No unmetered `memory.grow`.
- No hidden host-side quantum enforcement that is absent from WAT/binary
  structure.
- No claim that a WASM artifact self-enforces `seamN K` until the runtime meter
  exists and is pinned by tests.

## Recommended Sequence

1. Keep ABI v1 honest: source-checked quantities, internal direct-effect
   `seamN` lowering, and heap-used diagnostics.
2. Add human-facing diagnostics that explain which heap object families reserve
   bytes.
3. Extend the internal runtime meter behind tests until closures, recursion,
   handlers, and heap bytes compose.
4. Only after capability-use and heap-byte meters compose, consider metered
   `memory.grow`.
