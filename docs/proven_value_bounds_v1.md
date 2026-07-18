# LOOM Proven Value Bounds v1

Status: normative static-checker contract.

## Contract

Proven Value Bounds v1 derives a conservative abstract value environment for
the existing quantitative recurrence summary. It adds no source annotation and
does not change runtime evaluation. A bound is used only when the checker can
prove it from the current lexical expression and path.

The abstract domain is:

- `("i31", lower, upper)` for signed LOOM i31 integers;
- `("list", lower, upper)` for immutable list lengths;
- unknown, represented by no bound.

The checker propagates bounds through lexical `let` bindings, exact integer and
list literals, pure `+`, binary `-`, `*`, `list`, `cons`, `tail`, and `empty`.
Conditional paths refine direct integer comparisons against literals and join
reachable branch results with a conservative interval hull. Lexical shadowing
removes the outer fact before the new binding is analyzed.

For recurrence quantity, only the proven upper bound is consumed:

- i31 upper value becomes `max(0, upper - FLOOR + 1)`;
- list upper length becomes the initial rank.

The resulting rank is still solved by Quantitative Recurrence Summary v1 and
all meter arithmetic still saturates at the existing `1024` sentinel.

## i31 soundness

Exact constant arithmetic is evaluated with LOOM's canonical signed i31
wraparound. Non-exact arithmetic is accepted only when every possible result
stays inside the i31 range; a possible overflow or wraparound makes the result
unknown. Bounds analysis never evaluates effectful, foreign, random, or
unresolved higher-order expressions.

## Fail-closed boundary

The bound remains unknown for unsupported forms, effect/FFI results, unresolved
higher-order values, wrapper calls without contextual specialization, unsafe
shadowing, path/context explosion, possible i31 wraparound, and rank or meter
counts reaching `1024`. Unknown values preserve the existing unbounded meter
diagnostic and remain fail-closed. No runtime counter, backend lowering, public WASM ABI change, or
trusted user assertion is introduced.

Version 1 is intentionally intraprocedural. Context-sensitive wrapper and
function-parameter specialization require a separately bounded memoization and
recursion contract and are deferred to a future version.
