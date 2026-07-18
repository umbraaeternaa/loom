# LOOM Contextual Value Bounds v2

Status: normative static-checker contract.

## Contract

Contextual Value Bounds v2 extends Proven Value Bounds v1 across direct calls
to named functions with value parameters. At the call site, each value
argument is analyzed in the caller's abstract environment. The callee's value
parameters are shadowed and rebound to those proven facts before its body is
meter-analyzed.

This permits finite quantitative recurrence summaries through bounded named
wrappers, for example:

```loom
(prove (descent hit))
(defx hit (Net)
  (fn (n)
    (if (< n 1) 0
        (let (x (net n)) (hit (- n 1))))))
(defx wrap (Net) (fn (n) (hit n)))
(defx main (Net) (fn () (seamN 2 (Net) (wrap 2))))
```

The same abstract interval rules from v1 continue through aliases, pure
arithmetic, branch joins, and list operations. Only the proven upper bound is
used by the recurrence solver.

## Deliberate boundary

v2 specializes direct named value parameters only. It does not specialize:

- callable parameters, closures, or unresolved higher-order dispatch;
- effectful, foreign, random, or otherwise unknown arguments;
- recursive contexts or arbitrary interprocedural fixpoints;
- `with`/resource recurrence re-scoping;
- contexts beyond the fixed direct-call depth cap.

When a context is unknown or exceeds the cap, the meter summary remains
unbounded and the checker rejects an insufficient `seamN` contract. Callable
effect summaries remain in their separate `cenv`; value bounds never create an
effect capability.

No source annotation, runtime counter, backend change, public WASM ABI change,
or user-trusted assertion is introduced. This is checker metadata only and
erases before execution.
