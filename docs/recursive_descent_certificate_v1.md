# LOOM Recursive Descent Certificate v1

## Contract

The top-level directive `(prove (descent NAME...))` requests a static proof for
the named function or functions. A request is not an assertion: the checker
accepts it only after constructing a recursive-descent certificate for the
entire named-call strongly connected component (SCC) containing each target.

The checker selects one value parameter as the measure for every function in
the SCC. Each direct named call inside that SCC must relate the caller's
measure to the callee's measure as either:

- **weak:** the same parameter, or a `tail` of it without a proven nonempty
  guard;
- **strict:** one or more `tail` operations under the false branch of
  `(empty PARAM)`, or `(- PARAM K)` for a positive integer `K` under a path
  guard that proves a safe i31 lower bound with no wraparound.

The weak-edge subgraph must be acyclic. Equivalently, every recursive cycle
must contain at least one strict descent. This covers direct recursion and
mutual recursion without requiring every edge in a cycle to decrease.

For example:

```loom
(prove (descent suml))
(defx suml ()
  (fn (xs)
    (if (empty xs)
        0
        (+ (head xs) (suml (tail xs))))))
```

## Fail-closed boundary

The checker refuses a certificate when:

- an SCC function escapes direct named-call position;
- recursive dispatch is hidden in a closure or unresolved higher-order call;
- a call grows or replaces the selected measure;
- a cycle contains only weak edges;
- numeric descent can wrap around the signed i31 range;
- no common measure assignment is found, or the bounded measure search would
  exceed 4096 assignments.

An equality guard such as `(if (= n 0) ... (f (- n 1)))` is insufficient for a
universal proof: a negative initial `n` can continue downward until i31
wraparound. A lower-bound guard such as `(if (< n 1) BASE (f (- n 1)))` proves
the subtraction safe.

## Meaning and non-claims

The certificate proves that the named recursive SCC cannot produce an
infinite sequence of its direct named recursive calls, assuming evaluation
reaches those calls and invoked primitives or external operations return. It
does not claim that FFI, network operations, handlers, or unresolved
higher-order code terminate.

The certificate is independent of both runtime resource frames:

- `depthN` dynamically limits recursive SCC edges even for uncertified code;
- `seamN` limits effect requests;
- a descent certificate does not remove either frame and does not turn a
  recursive Meter Summary into a fixed finite quantity for unknown input.

Proof directives are checker metadata and erase before execution. They add no
runtime operation, host import, public WASM export, or ABI obligation.
