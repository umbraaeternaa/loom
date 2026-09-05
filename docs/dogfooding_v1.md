# LOOM Dogfooding v1

Status: implemented host-only advisory policy runner.

Dogfooding v1 is the first development path where LOOM is used as an actual
decision tool for work on LOOM. It is deliberately narrower than the language
runtime and separate from Action Capsule execution.

```console
loom dogfood examples/dogfood_release_policy.loom "(main 3)"
```

The command accepts only when one Pure LOOM policy produces the exact i31
integer `1` with no output and the complete observable result agrees across:

1. the reference interpreter;
2. generated Python;
3. generated JavaScript executed by Node;
4. generated WebAssembly executed by Node.

The result is a closed `loom-dogfood-validation/v1` envelope carrying a
content-addressed `loom-dogfood-receipt/v1`. The receipt binds the exact source,
canonical call, four backend observables, agreement digest, decision and honest
lifecycle limits.

The public `loom.verify_dogfood_policy_receipt_v1(receipt, source, call)` API
re-executes the same bounded policy on all four backends and requires exact
receipt equality. Unknown fields, removed fields and any changed observation
are refused.

## Closed execution profile

Dogfooding v1 permits exactly one top-level form: a function definition named
`main`, with zero or one signed i31 literal input. Every function must have an
empty effect row. Extra top-level expressions, nested functions, recursion and
parameter-dispatched calls are rejected before execution. Source is bounded to
256 KiB and the call to 4 KiB.

Those restrictions make the policy finite and prevent Dogfooding v1 from
becoming another general host executor. JavaScript and WebAssembly require a
real local Node runtime; absence or failure is a refusal, never a skipped vote.

The policy result has two meanings:

- integer `1`: `decision: accept`;
- integer `0`: `decision: refuse`.

Every other result shape, any emitted output, backend disagreement or backend
failure invalidates the run and produces no receipt.

## Trust boundary

Call arguments have the fixed provenance label
`operator-supplied-unverified`. LOOM proves the policy, effect boundary and
cross-backend decision; it does not prove that an input fact is true.
Role tags declared with `(by ...)` are checker-visible statements in the policy
source, not signatures, actor identities or evidence that those actors actually
performed the named roles.

The local compiler and four runner adapters remain in the trusted computing
base. The receipt is content-addressed but unsigned. It is advisory, grants no
authorization and executes no requested host action. The Pure policy is
statically forbidden from requesting network access. Dogfooding v1 does not
replace Gate approval, signed execution evidence or an independent attester.

The next additive step is Evidence-fed Dogfooding v2: replace manually supplied
input facts with exact, externally anchored test, Git and review receipts while
keeping the LOOM policy itself unchanged.
