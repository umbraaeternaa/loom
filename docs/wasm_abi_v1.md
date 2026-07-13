# LOOM WebAssembly ABI v1

Status: normative for modules emitted by `compile_wasm`.

The binary module exports the immutable raw `i32` global
`loom_abi_version`. A v1 host must require its value to be exactly `1`
before calling a LOOM function or decoding linear memory.

## Value encoding

Every LOOM function parameter and result uses one tagged `i32` value.

| Value | Encoding |
| --- | --- |
| Signed i31 integer `n` | `n << 1`; low bit is `0` |
| Boolean false / true | Encoded integers `0` / `2` |
| Heap pointer at address `p` | `p | 1`; low bit is `1` |
| Empty list | Reserved immediate `3` |

The integer domain is `-1073741824..1073741823`. Literals outside this
range are rejected. Arithmetic wraps modulo `2^31`, then is interpreted as
a signed i31 value. A host decodes an even value with arithmetic shift
right by one. The normative cross-backend integer law is specified in
[`i31_semantics.md`](i31_semantics.md).

Heap pointers are never confused with integers. To obtain the aligned
memory address, clear the pointer's low bit (`value & -2`). Valid v1 heap
pointers are at least `9`; `3` is never a heap address.

## Module boundary

Every binary module exports:

- `memory`: linear memory, currently exactly one initial 64 KiB page in
  generated modules.
- `loom_abi_version`: immutable raw `i32`, currently `1`.
- `loom_heap_limit`: immutable raw `i32`, currently `65536` for the fixed-page
  heap policy.
- `loom_heap_used`: mutable raw `i32`; runtime `$reserve` increments it by
  each successful heap allocation size.
- `loom_heap_static_used`: immutable raw `i32`; bytes occupied by static
  string/data heap objects before runtime allocation begins.
- `loom_heap_records`, `loom_heap_lists`, `loom_heap_variants`,
  `loom_heap_effects`, `loom_heap_resources`: mutable raw `i32` diagnostic
  counters incremented when the corresponding runtime heap object family is
  successfully reserved.
- One function for each top-level `defx`, with signature `(i32*) -> i32`.

Arguments and results of exported LOOM functions are tagged values. The
ABI version and metadata IDs are raw integers, not tagged values.

Every binary module imports these functions from module `env`:

| Import | Signature | Contract |
| --- | --- | --- |
| `push_handler` | `(raw_effect_id, tagged_handler) -> i32` | Push handler; return value is ignored |
| `pop_handler` | `(raw_effect_id) -> i32` | Pop handler; return value is ignored |
| `current_handler` | `(raw_effect_id) -> tagged_handler_or_0` | Return current closure or raw sentinel `0` |
| `host_print` | `(tagged_value) -> tagged_value` | Emit decoded value and return the original tagged value |

Effect IDs are stable in ABI v1:

| Effect | Raw ID |
| --- | ---: |
| `IO` | 0 |
| `Net` | 1 |
| `Rand` | 2 |
| `Alloc` | 3 |

## Linear-memory objects

The bump allocator starts at byte offset `8`. All addresses are
4-byte-aligned. Object words are little-endian `i32`. The pointer returned
to LOOM is the object's base address with its low bit set.

### List cell, kind 1, 12 bytes

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `1` |
| 4 | Tagged element value |
| 8 | Tagged next list pointer or empty-list immediate `3` |

### Record field, kind 2, 16 bytes

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `2` |
| 4 | Raw field ID |
| 8 | Tagged field value |
| 12 | Tagged next record-field pointer or raw terminator `0` |

A record is a linked chain in source field order. Field IDs are local to
the compiled module. They must not be persisted or compared across modules.

### Variant, kind 3, 12 bytes

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `3` |
| 4 | Raw variant tag ID |
| 8 | Tagged payload |

Variant tag IDs are local to the compiled module and are not stable across
separate compilations.

### Effect box, kind 4, 12 bytes

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `4` |
| 4 | Stable raw effect ID |
| 8 | Tagged payload |

### Static string, kind 6, 12 bytes plus immutable bytes

String literals are emitted as immutable static data, not allocated at
runtime. The string object has kind `6`:

| Offset | Word |
| ---: | --- |
| 0 | Raw kind `6` |
| 4 | Raw byte length |
| 8 | Raw byte address |

The byte payload is UTF-8 data stored in a separate passive-at-load data
segment. Source-level string values cross the WASM boundary by returning a
tagged pointer to this object. Hosts decode kind `6` by reading exactly the
declared byte length from the raw byte address and interpreting those bytes
as UTF-8. The bytes are immutable for LOOM code; v1 exposes no string
mutation or concatenation operation.

## Closure convention

A closure is represented by a kind-2 record chain:

- Field ID `0` (`code`) contains the tagged local code ID.
- Field IDs `1..N` (`e0..eN`) contain tagged captured values.

Code IDs and capture-field IDs are module-local. Generated `applyN`
dispatchers read the closure record and call the matching internal function.
The closure convention is part of ABI v1, but its module-local IDs are not
an interchange format.

## Host decoding

A conforming host decoder must:

1. Verify `loom_abi_version == 1`.
2. Decode even values as signed i31 integers.
3. Decode `3` as the empty list.
4. For other odd values, clear bit zero, bounds-check memory, read the kind,
   and decode only the matching layout.
5. Reject invalid pointers, unknown kinds, malformed chains, and out-of-bounds
   objects. It must not guess an object type from payload shape.

Hosts need the compiler-produced field-ID and variant-tag maps to recover
source names. Those maps describe one module and are not stable ABI IDs.

## Compiler state isolation

ABI v1 metadata IDs are per-module products of a single compilation. Closure
code IDs, helper indexes, apply-dispatch indexes, field IDs, variant-tag IDs,
resource IDs, foreign IDs, string-layout addresses, heap offsets, and source-span
maps must not be stored in mutable module-global compiler tables and reused by a
later compilation.

A conforming compiler may expose a stable frontend adapter, but every call to
`compile_wasm` or `emit_wat` must build a fresh program context. Parallel builds
of unrelated programs must produce the same bytes and WAT as isolated sequential
builds, with no closure/layout state inherited across modules.

## Failure and resource behavior

- Unsupported LOOM forms fail during compilation with `LoomError`.
- An unmatched variant arm emits a WebAssembly trap.
- Metered source seams such as `seamN K` are enforced by the LOOM source
  checker before code generation. In ABI v1, generated WASM carries capability
  presence only (`push_caps` / `has_cap`); the numeric quantum `K` is not a
  runtime counter in the binary artifact.
- The current allocator does not grow memory. Generated modules declare one 64 KiB page
  and contain no `memory.grow` path. Before each runtime heap
  allocation, `$reserve` checks `hp + size <= loom_heap_limit` and also
  sanity-checks `hp + size <= memory.size() << 16`; successful reserves
  increment `loom_heap_used` by `size`, then the allocating helper increments
  its object-family diagnostic counter. Exhausting the exported memory traps
  before any object-family counter, object header, or payload store changes.
- The current direct host-call interface accepts integer arguments only.
- String literals are supported at the value boundary as immutable static
  kind-6 heap objects. General runtime string allocation and string
  operations are not part of ABI v1.

## Compatibility policy

ABI version `1` must change if any tagged-value encoding, stable effect ID,
heap kind, object offset, import signature, closure convention, or i31
domain/wraparound/host-decoding rule changes. Adding a source-language form
without changing those contracts does not by itself require a new ABI version.

Hosts must reject unknown ABI versions. A future incompatible layout must
use a new integer version and a separate normative document.
