# LOOM Call Budget Frame v1

## Contract

Evaluating `(depthN K BODY...)` pushes one invocation-scoped call-budget frame
with `K` remaining units. `K` must be an integer in `0..1023`.

One unit is charged before every direct named call edge whose caller and callee
belong to the same recursive strongly connected component. This includes direct
and mutual recursion. Entering the outermost function does not consume a unit.

All active call-budget frames are checked before any frame is decremented. If
one has no remaining units, execution traps before entering the recursive
callee. Otherwise every active frame is decremented once. Frames are restored
when their dynamic scope exits.

## Boundary

`depthN` is runtime enforcement, not an assertion that the compiler trusts. It
bounds named recursive call edges executed inside its dynamic scope; it does
not prove that a program terminates, bound non-recursive work, or turn an
unresolved higher-order cycle into a statically known call graph.

Call budgets and effect meters are independent:

- `depthN` charges named recursive call edges.
- `seamN` charges effect requests.
- A call may charge both resources before its eventual effect request.
- `depthN` does not make an otherwise unbounded Checker Meter Summary finite.

## Backend parity

The interpreter and generated Python/JavaScript use invocation-local frame and
named-call stacks. WASM uses a private compiler-emitted linked frame propagated
through generated functions. The linked frame is not imported, exported, or
part of the public host ABI.

WASM allocates each dynamic call-budget frame from its fixed linear-memory heap.
`memory.grow` remains disabled, so runtime bookkeeping cannot bypass the heap
limit.
