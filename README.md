# LOOM

**A tiny effect-typed language exploring a trust layer for AI-written code.**

In a world where code is increasingly written by AI, you often cannot trust the *author*.
So LOOM makes what code is *allowed to do* **machine-checkable**, and refuses to run anything
that lies about it. Every function must declare its **effects**; the checker proves the
declaration is honest before a single line runs.

> The slogan: **AI proposes, the compiler disposes.**

LOOM is a ~150-line s-expression language: a parser, a **static effect checker**, and an
interpreter. It is a research kernel — small on purpose — and it is **self-verified by 80
checks** that the language can only ever grow *greener* (every new feature must keep them all
passing).

```console
$ python3 run_tests.py
...
PASS — 80/80 citadel checks
```

## The idea in one screen

Every function carries an **effect row** drawn from `{Pure, IO, Net, Alloc, FFI}`, and the
**superset rule** holds: a function's *declared* effects must be a superset of what it
*actually does*. You may over-declare (be pessimistic); you may never under-declare (lie).

```lisp
(defx greet (IO) (fn (n) (print n)))     ; honest: declares IO, does IO        -> accepted
(defx sneaky () (fn (n) (print n)))      ; lies: declares nothing, does IO     -> REJECTED
```

The lie is caught transitively, through calls, branches, bindings, and recursion — not just
in straight-line code:

```lisp
(defx log (IO) (fn (m) (print m)))
(defx bad ()   (fn ()  (log "hi")))      ; bad calls log (IO) but declares pure -> REJECTED
```

### Boundaries: seams and handlers

A **seam** makes a foreign/opaque boundary's cost explicit (and is checked against what it wraps):

```lisp
(defx fetch (Net) (fn (u) (seam (Net) (net u))))     ; the boundary declares its real cost
```

A **handler** does the opposite — it *discharges* an effect locally, or **reinterprets** it:

```lisp
;; `with` reinterprets an effect: route Net to a pure mock => the whole thing is provably Pure
(defx realwork (Net) (fn (x) (net x)))
(defx mock     ()    (fn (x) (* x 2)))
(defx tested   ()    (fn (x) (with Net mock (realwork x))))   ; tested is PURE — and it's honest at runtime:
                                                              ; `net` is actually routed to the mock, not faked
```

This is the demo that motivates the whole project: **take code that touches the network,
swap what `Net` *means*, and the type system proves the original effect is contained.**

### Effects flow through abstraction

First-class functions are **effect-polymorphic**: a lowercase token is an effect *variable*,
instantiated at each call site by the actual function argument's effect. One higher-order
function propagates whatever effect its argument has — and you cannot smuggle an effect past
the caller's declaration.

```lisp
(defx ap (e) (fn ((f e) x) (f x)))       ; ap's effect = whatever f does
;; (ap a-pure-fn ..)   keeps the caller pure
;; (ap an-IO-fn ..)    forces the caller to declare IO

;; map/fold are not built in — they are DEFINED in LOOM, and the effect flows through iteration:
(defx map (e) (fn ((f e) xs)
  (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs))))))
```

## What's inside

Effect rows + superset rule · checked seams · effect handlers (`handle` discharges,
`with` reinterprets) · **capability seams for effect-opaque FFI** · **affine (use-once) seams** + **linear resources** (use-exactly-once, whole-program via a use-count lattice) · `if` / `let` · recursion ·
pure list primitives · first-class functions with row-polymorphism · anonymous lambdas &
closures · and a hard soundness rule: **an unverifiable call is rejected, never assumed
pure**. The static checker's vocabulary is kept identical to the interpreter's, so nothing
type-checks that can't actually run.

**Capability seams** are how LOOM stays sound across a boundary it cannot see into. An opaque
foreign call `(ffi name arg..)` has **no ambient authority** — un-wrapped, it is *refused*. A
seam is the only thing that grants it authority, and the seam's declared row **is** exactly the
authority handed across. The runtime enforces it: `(seam (Pure) (ffi untrusted))` makes the
foreign code's IO/Net **physically impossible**, not merely undeclared. Soundness stops resting
on trusting an annotation — *no capability granted ⇒ no effect possible*.

- [`loom.py`](loom.py) — parser, effect checker, interpreter.
- [`run_tests.py`](run_tests.py) — the self-verifying suite: it accepts honest programs,
  rejects every flavor of lie, and runs real programs.

## Run it

```console
python3 run_tests.py
```

No dependencies — pure Python 3.

## Honest status & prior art

This is **alpha** — a v0 research kernel, deliberately tiny. It is grown incrementally; every
feature is added only with an adversarial test and must keep all checks green.

The individual building blocks are **not new**: effect rows, algebraic effect handlers, and
capability-style reasoning come from prior work like Koka, Eff, Unison, and OCaml 5's effects.
LOOM does not claim to invent them — that's *why* the kernel fits in ~150 lines. What it
explores is the **synthesis and framing**: one legible signature channel, checked at a trusted
gate, as a **trust layer for AI-generated code**, with *reinterpreting handlers* as the
primitive for containing untrusted effects. Feedback and criticism are very welcome —
especially where the model is wrong.

## About

Built solo, in the open, from Ukraine 🇺🇦, by **Volodymyr Natoptanyi** (`umbraaeternaa`).
Part of a line of sovereign, local-first security & AI work — see also
[CHIMERA](https://github.com/umbraaeternaa/macbastion).

If this direction resonates, a ⭐ helps it reach more people. Feedback, issues, and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
