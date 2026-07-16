# LOOM Portable Meter Frame v1

Status: normative reference semantics.

## Frame Entry

Evaluating `seamN K (E...) BODY...` pushes one invocation-scoped meter frame
and the matching capability frame. `K` must be a non-negative integer. The
meter frame contains one counter initialized to `K` for every named effect
except `Pure`.

Both frames unwind when the body returns or raises. Calls, closures,
higher-order calls, recursion, and handlers execute under the active frames;
they do not receive fresh counters unless they enter another `seamN`.

## Atomic Effect Charge

Each logical effect request charges every active frame that names its effect.
The runtime first checks all matching counters. If any counter is zero, it
traps before changing any counter and before the handler, foreign call, output,
allocation, or other visible effect. Otherwise, all matching counters decrement
exactly once. Nested frames therefore charge both their inner and outer scopes.

The reference scope covers `IO`, `Net`, `Alloc`, `Rand`, and `FFI`. Runtime
metering for typed resource use remains pending and must be specified before it
is claimed.

## Handlers

`handle E` and `with E` charge the original effect request before discharge or
reinterpretation. Effects performed by a handler body are separate requests and
are charged under the frames active when those effects occur.

## Backend And Checker Status

- The reference interpreter implements Meter Frame v1.
- The Python and JavaScript generated backends are pending.
- WASM implements direct scoped effects; indirect calls, closures, `applyN`,
  recursion, and handler parity are pending.
- The production checker remains fail-closed for indirect metered paths until
  every execution backend implements this contract.

Meter Frame v1 changes no WASM ABI v1 imports, exports, object layouts, or host
obligations. Host-visible meter state or diagnostics require a separate ABI
decision.
