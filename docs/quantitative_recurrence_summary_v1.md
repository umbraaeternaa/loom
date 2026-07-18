# LOOM Quantitative Recurrence Summary v1

Status: normative static-checker contract.

## Contract

Quantitative Recurrence Summary v1 adds no source annotation. It is available
only for a named recursive SCC that already has a successful
`(prove (descent NAME...))` certificate.

The checker may refine a recursive Checker Meter Summary from unbounded to a
finite upper bound only when all of these conditions hold:

- every function in the SCC makes at most one intra-SCC call along any
  evaluation path (a **single spine**);
- all decreasing edges use one measure domain, either guarded i31 subtraction
  or guarded list-tail descent;
- the entry call supplies the selected measure as an integer literal or a
  source list literal;
- local effect paths are finitely resolvable by Checker Meter Summary v1;
- the computed quantity remains below the `1024` saturation sentinel.

For an i31 entry literal `N`, the initial rank is conservatively
`max(0, N - FLOOR + 1)`, where `FLOOR` is the smallest proven lower bound on a
strict numeric call edge. For a list literal, the initial rank is its source
length. Every strict edge consumes at least one rank unit. Weak edges keep the
rank, but the descent certificate has already proved that their graph is
acyclic.

For each effect, the checker solves the finite maximal-path recurrence:

```text
Q(function, rank) = max(
  terminal-path local quantity,
  recursive-path local quantity + Q(callee, next-rank)
)
```

All additions saturate at `1024`. The result is an upper bound; it need not be
the smallest possible bound.

## Example

```loom
(prove (descent hit))
(defx hit (Net)
  (fn (n)
    (if (< n 1)
        0
        (let (x (net n))
          (hit (- n 1))))))

(defx main (Net)
  (fn () (seamN 2 (Net) (hit 2))))
```

The descent proof establishes a single guarded i31 spine. The literal entry
measure is `2`, so the checker proves at most two `Net` requests. `seamN 2`
accepts; `seamN 1` rejects with a finite count of two.

## Fail-closed boundary

The recursive summary remains unbounded when any of these is present:

- no checked descent certificate;
- an unknown or computed entry measure;
- two recursive calls on one path, including Fibonacci-style branching;
- mixed or unknown measure domains;
- unresolved higher-order dispatch or recursive function escape;
- recursion crossing `with` or typed-resource quantity re-scoping;
- an input rank or accumulated effect count reaching the saturation sentinel.

Effect requests hidden by `with` or another effect-row discharge still count at
runtime. Unsupported recursive discharge shapes therefore saturate rather than
using the function's outward effect row as a quantity summary.

## Non-claims

This contract does not prove asymptotic complexity for arbitrary recursion. It
does not infer bounds from runtime values, solve branching recurrences, add a
runtime counter, remove `depthN`, or weaken `seamN`.

The summary is checker metadata and erases before execution. It changes no
interpreter behavior, generated Python or JavaScript signature, WASM import or
export, public object layout, or host ABI obligation.
