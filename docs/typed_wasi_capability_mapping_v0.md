# LOOM Typed WASI Capability Mapping v0

Status: implemented as a deterministic, content-addressed, host-only,
non-executable and non-authorizing projection contract.

Typed WASI Capability Mapping v0 is the first explicit bridge from checked LOOM
effect rows to versioned WebAssembly Component Model imports. It does not modify
WIT Component Boundary v0, Component Adapter Artifact v0, or the ABI v2 core. It
does not build an effectful Component. It proves what an eventual adapter would
have to import and how each supported operation must cross that boundary.

## Public API

```python
loom.build_typed_wasi_capability_mapping_v0(
    source, wasm_bytes, package, world, exports=None,
)

loom.verify_typed_wasi_capability_mapping_v0(
    mapping, source, wasm_bytes, package, world, exports=None,
)
```

The result schema is
`loom-typed-wasi-capability-mapping-validation/v0`. A successful result carries
one `loom-typed-wasi-capability-mapping/v0` object. The verifier rebuilds that
object from all exact inputs and rejects hash, source, core, export, WIT,
version, operation or policy drift.

Its closed capability table is identified separately as
`loom-wasi-effect-projection/v0`, so consumers cannot confuse projection policy
with the enclosing source/core evidence envelope.

## Required compiler evidence

The builder accepts only:

1. source that parses and passes the LOOM checker;
2. core bytes that are byte-identical to deterministic Tagged Value ABI v2
   compilation of that source;
3. core bytes whose `loom.trust.v1` and `loom.trust.v2` receipts both verify;
4. selected top-level functions with plain value parameters and arity at most
   32;
5. a lowercase versioned WIT package and unambiguous lowercase WIT world/export
   identifiers;
6. at least one selected non-Pure effect.

All-Pure selections fail with `empty-capability-projection`; they belong to WIT
Component Boundary v0. Higher-order and linear parameters remain fail-closed.

## Closed effect table

v0 has three supported effects and two deliberate refusals.

### `IO` / `print`

Exact imports:

```text
wasi:cli/stdout@0.2.8
wasi:io/error@0.2.8
wasi:io/streams@0.2.8
```

Required calls:

```text
wasi:cli/stdout.get-stdout
wasi:io/streams.output-stream.blocking-write-and-flush
```

The adapter must encode the LOOM value as canonical JSON bytes, obtain stdout
for that effect, perform a blocking write and flush, and drop the stream handle
before return. It may not infer stdin, stderr, filesystem access or a terminal.

### `Rand` / `rand`

Exact import and call:

```text
wasi:random/random@0.2.8
wasi:random/random.get-random-u64
```

The `u64` result maps to the nonnegative LOOM i31 range by
`u64 modulo 1073741824`. This is unbiased because `2^30` divides `2^64`.
No clock, environment or deterministic fallback may substitute for the random
interface.

### `Alloc` / `alloc`

`Alloc` maps to the existing internal `loom.$reserve` path. It adds no WIT
import and grants no host authority. Fixed-page checked reserve remains in
force and `memory.grow` remains forbidden.

### Refused in v0

`Net` fails with `unmapped-wasi-effect`: the current LOOM operation does not
specify HTTP versus sockets, DNS, endpoint policy or connection-resource
lifecycle. Mapping it to a broad WASI network world would manufacture ambient
authority.

`FFI` also fails with `unmapped-wasi-effect`: arbitrary foreign component names
are not a portable WASI operation and must receive a separate typed component
contract.

Handled or reinterpreted effects that do not escape a selected function's
checked row require no host import. Transitive effects do escape and therefore
appear in that export's projection.

## Generated WIT

Imports are the sorted union required by selected exports. They are never the
whole WASI command world. For one export using `IO`, `Rand` and `Alloc`, v0
emits:

```wit
package umbra:loom@0.4.0;

world typed-wasi {
  import wasi:cli/stdout@0.2.8;
  import wasi:io/error@0.2.8;
  import wasi:io/streams@0.2.8;
  import wasi:random/random@0.2.8;

  export act: func(request: list<u8>) -> result<list<u8>, list<u8>>;
}
```

The export transport remains `loom-canonical-json-utf8/v0`, capped at 1 MiB.
The generated WIT source and each selected export's declared, performed,
required and projected effects are content-addressed.

## Immutable WASI specification pins

The mapping identifies WASI release `0.2.8` and pins SHA-256 for the tagged
official WIT inputs:

- `WebAssembly/wasi-cli` `v0.2.8`: `wit/command.wit` and `wit/stdio.wit`;
- `WebAssembly/wasi-io` `v0.2.8`: `wit/error.wit` and `wit/streams.wit`;
- `WebAssembly/wasi-random` `v0.2.8`: `wit/random.wit`.

These pins identify the reviewed interface text. They are not package
signatures and do not prove a host implements those interfaces honestly.

## Lifecycle and authority

Every valid mapping carries:

```json
{
  "component_binary": "absent",
  "effect_adapter": "required",
  "executable": false,
  "authorization": "none",
  "host_policy_binding": "required-before-instantiation"
}
```

`ambient_authority` is always false. Valid evidence does not instantiate a
component, grant an import, satisfy an operator gate or authorize execution.
Effectful Component Adapter v1 now binds this exact mapping, lowers each
accepted operation, proves no extra imports, and binds a separate host policy.
That artifact remains non-authorizing and still requires the operator Gate
before a deployment may execute it.

## Honest next boundary

The implemented [Effectful Component Adapter v1](effectful_component_adapter_v1.md)
consumes this table without broadening it. The next step is to bind verified
effectful artifacts into the existing claimed-execution lifecycle. `Net` and
`FFI` stay closed until their own typed semantics exist.
