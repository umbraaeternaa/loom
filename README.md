# LOOM

**A tiny effect-typed language exploring a trust layer for AI-written code.**

In a world where code is increasingly written by AI, you often cannot trust the *author*.
So LOOM makes what code is *allowed to do* **machine-checkable**, and refuses to run anything
that lies about it. Every function must declare its **effects**; the checker proves the
declaration is honest before a single line runs.

> The slogan: **AI proposes, the compiler disposes.**

[![Live site](https://img.shields.io/badge/%F0%9F%8C%90_Live_site-Visit-39d6c8?style=for-the-badge)](https://umbraaeternaa.github.io/loom/) &nbsp; [![Donate · Monobank](https://img.shields.io/badge/%E2%98%95_Donate-Monobank_jar-FFC400?style=for-the-badge)](https://send.monobank.ua/jar/AHaziFXjYX) &nbsp; built solo, in the open, from Ukraine 🇺🇦 — [support it](#support-this-work)

🌐 **[Visit the live site → umbraaeternaa.github.io/loom »](https://umbraaeternaa.github.io/loom/)** &nbsp;·&nbsp; 🎬 **[Watch — LOOM in 30 seconds »](media/LOOM_intro.mp4)**

LOOM is a small (~1900-line) s-expression language: a parser, a **static effect checker**, an
interpreter, and **backends that compile checked code to Python and JavaScript** (plus a tagged-value **WebAssembly** runtime with a human-readable **WAT/assembler** view). It is a research
kernel — small on purpose — and it is **self-verified by 353 checks** that the language can only ever
grow *greener* (every new feature must keep them all passing).

```console
$ python3 run_tests.py
...
PASS — 363/363 citadel checks
```

## The idea in one screen

Every function carries an **effect row** drawn from `{Pure, IO, Net, Alloc, FFI, Rand}`, and the
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
`with` reinterprets) · **capability seams for effect-opaque FFI** · **affine (use-once) seams** + **linear resources** + **linear params** (use-exactly-once, carried across call boundaries) · typed resources can also carry an effect — open-once, use performs it, close-once · records (product data) · sum types + pattern matching · **required effects** (`E!`) — a function must *actually perform* a declared effect, not merely be permitted to (a do-nothing stub that lies about intent is rejected; a resource-tied floor forces the effect through the intended resource) · **provenance + a `trust` gate** — tag who authored a value (`(prov human e)`), and `(trust N e)` refuses a value trusted only by itself, demanding ≥ N *independent* (non-`ai`) anchors — a defense against **circular trust** (an AI authoring the code, the spec it's judged by, *and* the proof) · **role quorum** (`(by role who e)` + `(trust (roles code spec proof) e)`) — a *count* of anchors can't tell that they all played the same part, so the gate can demand that the **roles that matter are covered by distinct authors**: every required role needs a non-`ai` author *and* no single author may own them all (one person who wrote the code, the spec, *and* the proof is self-certifying → rejected) · **a role lattice** (`(sub LOW HIGH)`) — roles can be ranked, so a *stronger* check stands in for a weaker requirement (an `auditor` covers a required `reviewer`), strictly one-directional and never bypassing the distinct-author rule · **provenance-gated capabilities** — a capability seam can carry that quorum (`(seam (Net) (roles code review) …)`), so the dangerous authority itself (`Net`/`IO`/`FFI`) is **granted only to independently-vouched code**; trust stops being a side-channel and becomes a *condition on the capability*, proven before the effect can happen · **per-effect role binding** (`(needs Net review)`, `(needs FFI audit)`) — different dangers demand different vouchers, so a *specific* effect's grant can require a *specific* role, not one blanket quorum · **a program-wide trust policy** (`(rank LOW HIGH)`, `(require EFF role)` at top level) — declare the role lattice and the per-effect mandates **once** for a whole program and every gate inherits them, so trust becomes a property of the codebase rather than a pattern repeated at each seam (the mandate also takes a *number* — `(require Net 2)` means any grant of `Net` needs ≥ 2 distinct independent authors) · **negative policy** (`(forbid EFF)`) — the dual of `require`: ban an effect program-wide so it may never *escape* into any function's row; you either don't perform it or **discharge it locally** (with a handler), and the checker proves which — together `require`/`forbid` are a small policy language, positive and negative, settled before anything runs · **provenance taint** — provenance *flows*: a value derived from a `(prov P …)` value (bound to a name in an outer `let`, computed with, trusted later) still carries `P` when it reaches a gate, so provenance is what a value is **made of**, not where the anchor was typed (cross-statement and sound — derived-from-tainted stays tainted, shadowing-safe) · **exclusive-bearer resources** — inside a typed resource the effect has *no ambient bearer but the handle*: a stray ambient op that doesn't go through `(use r)` is a decoupling cheat, now refused (the "use that *is* the effect") · **capability confinement by author** (`(author name role who)` + `(confine EFF role)`) — the *composition graph*, not just an SBOM: when a program pulls in many third-party functions, a confined effect may be **wielded** only by code whose author is independently cleared (the op site, not a mere router) — least-privilege at the edge · **declassify** (`(declassify role e)`) — the principled escape hatch for taint: a non-`ai` role can *launder* a value's provenance (drop the `ai` taint, add its own vouch) so a human takes responsibility for an AI-derived value after review, while `ai` itself may never declassify · `if` / `let` · recursion ·
pure list primitives · first-class functions with row-polymorphism · anonymous lambdas &
closures · a BACKEND that compiles checked code to portable source — one verified program — even one with sum types, pattern matching, or effects (I/O · net · alloc · rand) — runs on both Python AND JavaScript with identical output (9 cross-checked programs; same pattern -> C/WASM) · and a hard soundness rule: **an unverifiable call is rejected, never assumed
pure**. The static checker's vocabulary is kept identical to the interpreter's, so nothing
type-checks that can't actually run.

**Capability seams** are how LOOM stays sound across a boundary it cannot see into. An opaque
foreign call `(ffi name arg..)` has **no ambient authority** — un-wrapped, it is *refused*. A
seam is the only thing that grants it authority, and the seam's declared row **is** exactly the
authority handed across. The runtime enforces it: `(seam (Pure) (ffi untrusted))` makes the
foreign code's IO/Net **physically impossible**, not merely undeclared. Soundness stops resting
on trusting an annotation — *no capability granted ⇒ no effect possible*.

- [`loom.py`](loom.py) — parser, effect checker, interpreter, and stable backend facade.
- [`loom_codegen.py`](loom_codegen.py) — isolated portable Python/JavaScript generators.
- [`loom_wasm.py`](loom_wasm.py) — isolated WebAssembly/WAT compiler and ABI runtime.
- [`run_tests.py`](run_tests.py) — the self-verifying suite: it accepts honest programs,
  rejects every flavor of lie, and runs real programs.

## Run it

```console
python3 run_tests.py
```

No dependencies — pure Python 3.

## Property fuzzing

LOOM includes a deterministic, dependency-free property fuzzer. It checks parser failure safety,
effect honesty, policy-state isolation, an independent i31 arithmetic oracle, structured tagged values,
and differential execution across the interpreter, generated Python, JavaScript, and WebAssembly.

```console
python3 fuzz_tests.py                                  # stable default seed
python3 fuzz_tests.py --cases 256 --seed 0xBADC0DE    # reproducible extended run
python3 fuzz_tests.py --cases 256 --no-node           # parser/checker/Python plus JS/WASM compilation
```

Every failure prints its seed and the divergent generated expression. The default fuzz smoke is also
part of `run_tests.py`; GitHub Actions runs the full citadel and three extended seeds on every push and pull request.

## Published docs parity

`docs/loom.py` is a published single-file browser bundle, not just another copy
of the modular core. The live playground still loads only `./loom.py`, so
published-bundle parity is verified separately:

```console
python3 verify_docs_parity.py
```

The workflow and invariants are documented in
[docs/published_bundle_workflow.md](docs/published_bundle_workflow.md).

## Use it as a tool

LOOM ships a small CLI — write a `.loom` file and run it:

```console
python3 loom.py check examples/demo.loom            # prove every effect is honest (else REJECTED)
python3 loom.py run   examples/demo.loom            # => [1, 4, 9, 16, 25]
python3 loom.py build examples/demo.loom --target js   # compile the checked program to JavaScript
python3 loom.py audit examples/demo.loom            # show declared-vs-performed capability surface
```

The same verified program runs in the interpreter, compiles to **Python** and **JavaScript**,
and lowers tagged values, closures, structured data, and effects to **WebAssembly** — one checked source, many platforms. LOOM integers have one portable contract on every backend: signed i31 values (`-2^30..2^30-1`) with deterministic modulo-`2^31` wraparound; out-of-range literals are rejected before execution.

The binary boundary is versioned and documented in the normative [LOOM WebAssembly ABI v1](docs/wasm_abi_v1.md); generated modules export `loom_abi_version = 1`, and hosts reject unknown versions.
Binary and WAT compilation use isolated per-program contexts, so closure, helper, tag, and field layouts cannot leak between concurrent builds.

## Try it in 60 seconds

If you want the fastest external read of what LOOM is for, start here:

- The machine-checked 60-second story is [here](docs/demo_loom_60s.md).
- The live playground at [umbraaeternaa.github.io/loom/play.html](https://umbraaeternaa.github.io/loom/play.html) if you want to paste code and see the checker react.
- [`loom audit`](#use-it-as-a-tool) if you want a CLI view of declared-vs-performed capability surface on real code.

That is the shortest path from "what is this" to "I can see the row, the lie, and the boundary."

## The whole idea in one program

[`examples/flagship.loom`](examples/flagship.loom) runs an **untrusted** step (think: code an AI
or a third party wrote) through a **capability sandbox** that makes its I/O *physically impossible*,
across a **linear resource** that must be opened and closed exactly once, and returns a **typed
result** — and the checker *proves* it is all safe before it runs:

```console
python3 loom.py check examples/flagship.loom   # the compiler proves it is safe
python3 loom.py run   examples/flagship.loom   # => 42  (the untrusted step emitted nothing — sandboxed)
```

## The trust gate, runnable

[`examples/trust.loom`](examples/trust.loom) shows the **circular-trust defense** in action. An AI-authored
value `(prov ai 42)` cannot vouch for itself — `(trust …)` *refuses* it until it carries **independent**
anchors. `(trust 2 …)` demands at least **2 distinct non-`ai` sources** (here a human ratification *and* a
real-execution trace):

```console
python3 loom.py run examples/trust.loom   # => 42  (refused outright without independent anchors)
```

## The role quorum, runnable

[`examples/roles.loom`](examples/roles.loom) goes one step further than a count. The threat the project
is named for is one author writing the **code**, the **spec** it's judged by, *and* the **proof** — so the
gate can demand those roles be covered by *different* people. `(by role who e)` records who performed a
role; `(trust (roles code proof) e)` accepts only if every role has a non-`ai` author **and** no single
author owns them all:

```console
python3 loom.py run examples/roles.loom   # => 42  (code ratified by a human, proof an independent trace)
# one author for both roles, or an ai-only role, is REJECTED before it can run
```

Roles can also be **ranked**: `(trust (roles code reviewer) (sub reviewer auditor) …)` declares that an
`auditor` outranks a `reviewer`, so a stronger check satisfies a weaker requirement — one-directional,
and rank never lets a single author stand in for two independent roles.

## Provenance-gated capabilities, runnable

[`examples/gated.loom`](examples/gated.loom) is where the two halves of the language meet. Provenance
stops being a side-channel and becomes a **condition on the capability itself**: a seam grants `Net`
to its body *only if* that body carries the role quorum. Network authority is handed exclusively to
code that has been independently vouched — and the checker proves it before anything runs.

```console
python3 loom.py run examples/gated.loom   # => '<net https://example>'  (Net granted: code by a human, reviewed by alice)
# ai-only, a single author, or a missing role => the capability is DENIED at check, before the call happens
```

A grant can also be **per-effect**: [`examples/needs.loom`](examples/needs.loom) binds each effect to the
role that must vouch for *it* — the network call needs a `review`, the logging needs an `audit` — so
different dangers demand different, appropriate vouchers rather than one blanket quorum.

```console
python3 loom.py run examples/needs.loom    # => 'shipped'  (Net needs review, IO needs audit — both vouched, non-ai)
```

And the policy can be set **once for the whole program**: [`examples/policy.loom`](examples/policy.loom)
declares `(rank review audit)` and `(require Net review)` at the top, and every seam inherits them — so
trust is a property of the codebase, not boilerplate at each gate.

```console
python3 loom.py run examples/policy.loom    # => '<net https://api>'  (an audit satisfies the program-wide review mandate)
```

And the dual — a flat ban: [`examples/forbid.loom`](examples/forbid.loom) declares `(forbid Net)`, yet
the code still "does network" — because it is *provably reinterpreted to a pure mock*, the effect never
escapes, so it is allowed. Let real `Net` leak and the program is rejected before it runs.

```console
python3 loom.py run examples/forbid.loom    # => 'payload'  (Net is forbidden, but here it is discharged to a mock)
```

Provenance also **flows through data, across statements**: [`examples/taint.loom`](examples/taint.loom)
binds a reviewed-then-audited value in outer `let`s and trusts it *later* — and `(trust 2 …)` still sees
both anchors, because the value carries the provenance it was made from wherever it travels.

```console
python3 loom.py run examples/taint.loom     # => 41  (the bound value still carries {human, audit} at the gate)
```

## Honest status & prior art

This is **alpha** — a v0 research kernel, deliberately tiny. It is grown incrementally; every
feature is added only with an adversarial test and must keep all checks green.

The individual building blocks are **not new**: effect rows, algebraic effect handlers, and
capability-style reasoning come from prior work like Koka, Eff, Unison, and OCaml 5's effects.
LOOM does not claim to invent them — that's *why* the kernel still fits in ~600 lines. What it
explores is the **synthesis and framing**: one legible signature channel, checked at a trusted
gate, as a **trust layer for AI-generated code**, with *reinterpreting handlers* as the
primitive for containing untrusted effects. Feedback and criticism are very welcome —
especially where the model is wrong.

## Support this work

LOOM is built **solo, in the open, from Ukraine 🇺🇦** — no company and no funding behind it,
just one person trying to make AI-written code something you can actually trust. If that
resonates and you'd like to help it keep growing, a small donation goes a long way.

[![Donate · Monobank](https://img.shields.io/badge/%E2%98%95_Donate-Monobank_jar-FFC400?style=for-the-badge)](https://send.monobank.ua/jar/AHaziFXjYX)

Or scan the jar:

<img src="monobank_qr.png" alt="Monobank donation jar — send.monobank.ua/jar/AHaziFXjYX" width="190">

**🎬 The mission in 30 seconds** — plays right here · ▶ [watch with sound](media/LOOM_intro.mp4):

![LOOM — 30-second intro](media/LOOM_intro.gif)

You can also use the **Sponsor** button at the top of the repo (same Monobank jar), and a
**⭐ Star** helps just as much — it brings more eyes to the project. Thank you. 🙏

## About

Built solo, in the open, from Ukraine 🇺🇦, by **Volodymyr Natoptanyi** (`umbraaeternaa`).
Part of a line of sovereign, local-first security & AI work — see also
[CHIMERA](https://github.com/umbraaeternaa/macbastion).

If this direction resonates, a ⭐ helps it reach more people. Feedback, issues, and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
