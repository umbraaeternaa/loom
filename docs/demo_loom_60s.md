# LOOM in 60 seconds

> A tiny effect-typed language exploring a trust layer for AI-written code.
> One idea: an effect/capability row that is, at the same time, the AI-reasoning signature,
> the honest contract, and the enforced sandbox boundary.

This is the fastest way to understand what LOOM is for:

1. An AI writes code.
2. LOOM checks what that code is allowed to do.
3. If the code lies, the checker refuses it.
4. If the code is honest, the runtime can still keep foreign power fenced by a seam.

Everything below is meant to be read alongside the live playground:

- [Playground](https://umbraaeternaa.github.io/loom/play.html)
- [Source](https://github.com/umbraaeternaa/loom)

## Act 1 — the row is a signature

```lisp
(defx fetch (Net) (fn (u) (let (r (net u)) (print u))))
```

This program claims `Net`, but the body also performs `IO`. The checker rejects the lie:

```text
REJECTED — fetch: performs undeclared ['IO'] (declared ['Net'])
```

## Act 2 — the row is a contract

```lisp
(defx fetch (Net IO) (fn (u) (let (r (net u)) (print u))))
```

Now the same body must admit what it really does. The behavior is no longer hidden.

## Act 3 — the row is a boundary

```lisp
(defx fetch () (fn (u) (seam (Pure) (ffi "logger" u))))
(defx fetch (IO) (fn (u) (seam (IO) (ffi "logger" u))))
```

The same foreign call behaves differently depending on the row. Under `(seam (Pure) ..)` the
capability is not granted, so the attempted effect cannot escape. Under `(seam (IO) ..)` it can.

## Why this matters

The signature, the contract, and the sandbox are the same checked object. That is the bet:
trust AI-written code by making the boundary machine-checkable, not by reading every line and hoping.

## Try it

Use the playground for the fastest read, or the CLI if you want the capability surface on real code:

```console
python3 loom.py check examples/demo.loom
python3 loom.py run examples/demo.loom
python3 loom.py audit examples/demo.loom
```
