#!/usr/bin/env python3
# ARGUS/plt CITADEL test suite — the growing, self-verifying proof that LOOM's design holds.
# The organism appends new CASES here every cycle; the language only grows if ALL stay green.
import sys
import subprocess
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import loom as _loom
from loom import parse, check, run_call, compile_py, run_compiled, run_js, compile_js, compile_wasm, run_wasm, emit_wat, LoomError, _WASM_ABI_VERSION

# (name, source, should_be_accepted)
CASES = [
    ("pure square",          "(defx square () (fn (x) (* x x)))", True),
    ("i31 min literal",      "(defx f () (fn () -1073741824))", True),
    ("i31 max literal",      "(defx f () (fn () 1073741823))", True),
    ("i31 below min refused", "(defx f () (fn () -1073741825))", False),
    ("i31 above max refused", "(defx f () (fn () 1073741824))", False),
    ("honest IO",            '(defx greet (IO) (fn (n) (print n)))', True),
    ("lying: hidden IO",     '(defx sneaky () (fn (n) (print n)))', False),
    ("transitive honest",    '(defx log (IO) (fn (m) (print m))) (defx run (IO) (fn () (log "hi")))', True),
    ("transitive lie",       '(defx log (IO) (fn (m) (print m))) (defx bad () (fn () (log "hi")))', False),
    ("seam honest",          '(defx fetch (Net) (fn (u) (seam (Net) (net u))))', True),
    ("seam under-declared",  '(defx fetch2 (Net) (fn (u) (seam (Pure) (net u))))', False),
    ("unknown effect",       "(defx weird (Magic) (fn (x) x))", False),
    # --- grown 2026-06-21: Alloc / FFI / over-declaration / multi-effect rows / seam-through-call ---
    ("alloc honest",         "(defx makebuf (Alloc) (fn (n) (alloc n)))", True),
    ("alloc lie: hidden",    "(defx leakbuf () (fn (n) (alloc n)))", False),
    ("over-declared ok",     '(defx careful (IO Net) (fn (n) (print n)))', True),
    ("multi-effect honest",  '(defx sync (IO Net) (fn (u) (print (net u))))', True),
    ("multi-effect under",   '(defx sync2 (IO) (fn (u) (print (net u))))', False),
    ("seam thru call ok",    '(defx raw (Net) (fn (u) (net u))) (defx wrap (Net) (fn (u) (seam (Net) (raw u))))', True),
    ("FFI boundary honest",  "(defx ccall (FFI) (fn (x) (seam (FFI) x)))", True),
    # --- hardened 2026-06-22: the gate must REFUSE an unverifiable call, not assume it pure ---
    ("unresolved call",      "(defx evil () (fn (x) (ghost x)))", False),
    # --- grown 2026-06-22: effect HANDLERS — discharge an effect so it does not escape (dual of seam) ---
    ("handle discharges IO", "(defx quiet () (fn (x) (handle (IO) (print x))))", True),
    ("handle only what named","(defx leak () (fn (x) (handle (Net) (print x))))", False),
    ("handle unknown effect", "(defx wat (IO) (fn (x) (handle (Magic) (print x))))", False),
    # --- grown 2026-06-22: control flow — if (effect = union of branches) + let (local binding) ---
    ("if both branches pure", "(defx mx () (fn (a b) (if (> a b) a b)))", True),
    ("if branch leaks effect","(defx pick () (fn (c) (if c (print 1) 0)))", False),
    ("if effect declared",    "(defx pick2 (IO) (fn (c) (if c (print 1) 0)))", True),
    ("let pure binding",      "(defx dbl () (fn (x) (let (y (+ x x)) y)))", True),
    ("let binds an effect",   "(defx li () (fn (x) (let (y (print x)) y)))", False),
    # --- grown 2026-06-22: recursion — effect row flows through self-calls (free from the fixpoint) ---
    ("recursion: factorial",  "(defx fact () (fn (n) (if (< n 2) 1 (* n (fact (- n 1))))))", True),
    ("recursion carries eff", "(defx cd () (fn (n) (if (< n 1) 0 (let (z (print n)) (cd (- n 1))))))", False),
    ("recursion eff declared","(defx cd (IO) (fn (n) (if (< n 1) 0 (let (z (print n)) (cd (- n 1))))))", True),
    # --- grown 2026-06-22: first-class functions + EFFECT POLYMORPHISM (lowercase `e` = effect variable) ---
    ("HOF declares effect var","(defx ap (e) (fn ((f e) x) (f x)))", True),
    ("HOF body must declare e","(defx ap () (fn ((f e) x) (f x)))", False),
    ("poly pure use stays pure","(defx sq () (fn (x) (* x x))) (defx ap (e) (fn ((f e) x) (f x))) (defx usep () (fn (x) (ap sq x)))", True),
    ("poly: IO must surface","(defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x))) (defx bad () (fn (x) (ap lg x)))", False),
    ("poly: IO declared honest","(defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x))) (defx good (IO) (fn (x) (ap lg x)))", True),
    # --- grown 2026-06-22: ROW-POLYMORPHISM — multiple effect vars, known+var rows, threading thru nested HOFs ---
    ("row-poly: compose 2 vars","(defx sq () (fn (x) (* x x))) (defx lg (IO) (fn (x) (print x))) (defx comp (e r) (fn ((f e) (g r) x) (f (g x)))) (defx u (IO) (fn (x) (comp lg sq x)))", True),
    ("row-poly: compose smuggle","(defx sq () (fn (x) (* x x))) (defx lg (IO) (fn (x) (print x))) (defx comp (e r) (fn ((f e) (g r) x) (f (g x)))) (defx bad () (fn (x) (comp lg sq x)))", False),
    ("row-poly: own + arg effect","(defx nt (Net) (fn (x) (net x))) (defx logged (IO e) (fn ((f e) x) (let (z (print x)) (f x)))) (defx u2 () (fn (x) (logged nt x)))", False),
    ("row-poly: threads thru HOF","(defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x))) (defx ap2 (e) (fn ((f e) x) (ap f x))) (defx u4 (IO) (fn (x) (ap2 lg x)))", True),
    ("row-poly: thread smuggle","(defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x))) (defx ap2 (e) (fn ((f e) x) (ap f x))) (defx u5 () (fn (x) (ap2 lg x)))", False),
    # --- grown 2026-06-22: ANONYMOUS LAMBDAS / CLOSURES — inline (fn ..) values; latent effect = body's effect ---
    ("lambda arg, pure","(defx ap (e) (fn ((f e) x) (f x))) (defx u () (fn (x) (ap (fn (y) (* y y)) x)))", True),
    ("lambda arg, IO surfaces","(defx ap (e) (fn ((f e) x) (f x))) (defx u2 () (fn (x) (ap (fn (y) (print y)) x)))", False),
    ("let-bound lambda runs","(defx u4 () (fn (x) (let (g (fn (y) (* y y))) (g x))))", True),
    ("let-bound IO lambda surfaces","(defx u5 () (fn (x) (let (g (fn (y) (print y))) (g x))))", False),
    ("lambda internal seam-lie","(defx ap (e) (fn ((f e) x) (f x))) (defx u6 (IO) (fn (x) (ap (fn (y) (seam (Pure) (print y))) x)))", False),
    # --- grown 2026-06-22: REINTERPRETING HANDLERS — (with E hfn body..) trades E for the handler's own effect ---
    ("with: mock Net -> pure","(defx realwork (Net) (fn (x) (net x))) (defx mock () (fn (x) (* x 2))) (defx tested () (fn (x) (with Net mock (realwork x))))", True),
    ("with: unmocked Net surfaces","(defx realwork (Net) (fn (x) (net x))) (defx bad () (fn (x) (realwork x)))", False),
    ("with: trades Net for IO","(defx realwork (Net) (fn (x) (net x))) (defx lgm (IO) (fn (x) (print x))) (defx traded () (fn (x) (with Net lgm (realwork x))))", False),
    ("with: trade declared","(defx realwork (Net) (fn (x) (net x))) (defx lgm (IO) (fn (x) (print x))) (defx traded (IO) (fn (x) (with Net lgm (realwork x))))", True),
    ("with: unknown effect","(defx mock () (fn (x) x)) (defx bad2 () (fn (x) (with Magic mock x)))", False),
    # --- grown 2026-06-22: DATA / LISTS (pure primitives) + map/fold DEFINED in LOOM (effect-poly over iteration) ---
    ("list fold sum (pure)","(defx suml () (fn (xs) (if (empty xs) 0 (+ (head xs) (suml (tail xs))))))", True),
    ("map over list, pure","(defx sq () (fn (x) (* x x))) (defx map (e) (fn ((f e) xs) (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs)))))) (defx demo () (fn () (map sq (list 1 2 3))))", True),
    ("map propagates IO","(defx lg (IO) (fn (x) (print x))) (defx map (e) (fn ((f e) xs) (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs)))))) (defx dio () (fn () (map lg (list 1 2 3))))", False),
    ("map IO declared","(defx lg (IO) (fn (x) (print x))) (defx map (e) (fn ((f e) xs) (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs)))))) (defx dio (IO) (fn () (map lg (list 1 2 3))))", True),
    # --- grown 2026-06-22: CAPABILITY SEAMS for effect-opaque FFI (no ambient authority; the grant IS the contract) ---
    ("ffi has no ambient authority", '(defx raw () (fn (x) (ffi "logger" x)))', False),       # opaque foreign call un-seamed -> REFUSED
    ("ffi under capability seam",    '(defx fa (IO) (fn (x) (seam (IO) (ffi "logger" x))))', True),   # granted IO, declared IO
    ("ffi sandboxed to pure",        '(defx fb () (fn (x) (seam (Pure) (ffi "logger" x))))', True),    # grant nothing -> provably pure
    ("ffi grant must surface",       '(defx fc () (fn (x) (seam (IO) (ffi "logger" x))))', False),     # grant IO but hide it -> REFUSED
    # --- grown 2026-06-23: AFFINE / USE-ONCE seams (signals: Okosa2/ion-lang "move-only ownership";
    #     hyperpolymath/affinescript "affine-typed, the effect row is the abstraction"). Probe: can linearity
    #     ride on the FLAT-SET row without forcing a multiset / breaking superset inference? (seam1 = grant once) ---
    ("affine seam: one use ok",   '(defx f1 (Net) (fn (u) (seam1 (Net) (net u))))', True),               # use granted cap once
    ("affine seam: reuse refused",'(defx f2 (Net) (fn (u) (seam1 (Net) (let (a (net u)) (net u)))))', False),  # 2nd use = move-after-move
    ("affine: if-branches not double",'(defx f3 (Net) (fn (u c) (seam1 (Net) (if c (net u) (net u)))))', True),  # one branch runs -> single use
    ("plain seam still reuses",   '(defx f4 (Net) (fn (u) (seam (Net) (let (a (net u)) (net u)))))', True),    # non-linear row UNTOUCHED
    # --- hardened 2026-06-23: a linear cap used INDIRECTLY (through a call / recursion) is uncountable -> REFUSE ---
    ("affine: indirect via callee refused", '(defx hit (Net) (fn (u) (net u))) (defx f5 (Net) (fn (u) (seam1 (Net) (hit u) (hit u))))', False),
    ("affine: indirect via recursion refused", '(defx lp (Net) (fn (n) (if (< n 1) 0 (let (z (net n)) (lp (- n 1)))))) (defx f6 (Net) (fn (n) (seam1 (Net) (lp n))))', False),
    ("affine: single direct use still ok", '(defx pure1 () (fn (x) (* x x))) (defx f7 (Net) (fn (u) (seam1 (Net) (let (a (pure1 u)) (net a)))))', True),
    # --- grown 2026-06-23: USE-COUNT LATTICE (0/1/many) through the fixpoint — whole-program affine tracking, precise ---
    ("affine: single call use ok", '(defx hit (Net) (fn (u) (net u))) (defx f8 (Net) (fn (u) (seam1 (Net) (hit u))))', True),       # callee uses Net once -> total 1 -> OK (precision: not over-rejected)
    ("affine: if-branch calls not summed", '(defx hit (Net) (fn (u) (net u))) (defx f9 (Net) (fn (u c) (seam1 (Net) (if c (hit u) (hit u)))))', True),  # one branch runs -> 1
    # --- grown 2026-06-23: LINEAR RESOURCES — (resource r body) must use r EXACTLY once (open -> use once -> close) ---
    ("linear resource: used once ok", '(defx r1 () (fn () (resource r (use r))))', True),
    ("linear resource: never used = leak", '(defx r2 () (fn () (resource r 0)))', False),
    ("linear resource: used twice", '(defx r3 () (fn () (resource r (let (a (use r)) (use r)))))', False),
    ("linear resource: if-branch single use ok", '(defx r4 () (fn (c) (resource r (if c (use r) (use r)))))', True),
    # --- grown 2026-06-23: LINEAR PARAMS — (lin r) carries a linear resource ACROSS a call (open here -> close there) ---
    ("linear param: used once ok", '(defx u1 () (fn ((lin r)) (use r)))', True),
    ("linear param: never used = leak", '(defx u2 () (fn ((lin r)) 0))', False),
    ("linear param: used twice", '(defx u3 () (fn ((lin r)) (let (a (use r)) (use r))))', False),
    ("resource crosses call boundary ok", '(defx u1 () (fn ((lin r)) (use r))) (defx top1 () (fn () (resource res (u1 res))))', True),
    ("resource passed twice across calls", '(defx u1 () (fn ((lin r)) (use r))) (defx top2 () (fn () (resource res (let (a (u1 res)) (u1 res)))))', False),
    # --- grown 2026-06-23: TYPED EFFECTFUL RESOURCES — (resource (r E..) ..): linear use-once AND its use performs E ---
    ("typed resource: effect declared ok", '(defx tr1 (Net) (fn () (resource (r Net) (use r))))', True),
    ("typed resource: effect must surface", '(defx tr2 () (fn () (resource (r Net) (use r))))', False),
    ("typed resource: two effects ok", '(defx tr3 (IO Net) (fn () (resource (r IO Net) (use r))))', True),
    ("typed resource: unknown effect", '(defx tr4 (Magic) (fn () (resource (r Magic) (use r))))', False),
    ("typed resource: linear + effect (leak)", '(defx tr5 (Net) (fn () (resource (r Net) 0)))', False),
    # --- grown 2026-06-23: RECORDS — (record (k v)..) product data; building performs field effects, (get r k) access ---
    ("record: build + get pure", '(defx rc1 () (fn () (get (record (a 1) (b 2)) a)))', True),
    ("record: field effect surfaces", '(defx rc2 () (fn (u) (record (a (net u)) (b 2))))', False),
    ("record: field effect declared ok", '(defx rc3 (Net) (fn (u) (record (a (net u)) (b 2))))', True),
    # --- grown 2026-06-23: SUM TYPES + PATTERN MATCH — (variant Tag v) + (match e (pat body)..); arm effects = union ---
    ("variant + match value", '(defx m1 () (fn () (match (variant Some 5) ((Some x) x) ((None) 0))))', True),
    ("match nullary arm", '(defx m2 () (fn () (match (variant None 0) ((Some x) x) ((None) 7))))', True),
    ("match arm effect surfaces", '(defx m3 () (fn (e) (match e ((Some x) (print x)) ((None) 0))))', False),
    ("match arm effect declared ok", '(defx m4 (IO) (fn (e) (match e ((Some x) (print x)) ((None) 0))))', True),
    # --- grown 2026-06-23: TWO-SIDED ROW / REQUIRED effects `E!` — the row as a D7 SYNTHESIS CONTRACT, not just a
    #     capability ceiling. Signals: srtdog64/PergyraLang "intent-oriented... compile-time verified contracts";
    #     Aabody509/spec-compiler "human intent -> governed specification"; grioghar/sigil "requires/ensures".
    #     Probe: does the SAME flat-set row survive being two-sided (floor MUST-perform <= actual <= ceiling MAY-perform)
    #     so an AI's do-nothing stub is REJECTED — WITHOUT forcing a separate value-contract (Z3 ensures) mechanism? ---
    ("required: honest fetch performs Net", '(defx fetch (Net!) (fn (u) (net u)))', True),
    ("required: empty stub refused (D7)",   '(defx fetch (Net!) (fn (u) u))', False),    # type-checks under plain (Net); FAILS the intent
    ("permitted (no !) stub still ok",      '(defx maybe (Net) (fn (u) u))', True),      # backward compat: ceiling-only row untouched
    ("required: ceiling still enforced",    '(defx f (IO!) (fn (x) (net x)))', False),   # over-ceiling Net AND misses required IO
    ("required: multi must all surface",    '(defx sync (IO! Net!) (fn (u) (print (net u))))', True),
    ("required: multi under-performs",      '(defx sync2 (IO! Net!) (fn (u) (print u)))', False),  # IO done; Net required but absent
    ("required: discharged eff fails floor",'(defx q (IO!) (fn (x) (handle (IO) (print x))))', False),  # handled away -> not performed
    # --- grown 2026-06-24: RESOURCE-TIED FLOOR — pushing the D7 contract from "an effect happened" toward "the RIGHT
    #     effect happened" (signals: grioghar/sigil "Z3 requires/ENSURES — result relates to args"; promise-language
    #     "explicit ownership + zero hidden effects"; Aabody509/spec-compiler "human intent -> governed specification").
    #     The row can't see VALUES, but it CAN see resource IDENTITY: tie the required floor `E!` to a TYPED LINEAR
    #     resource of effect E, so the floor cannot be discharged while the intended resource sits unused (= leak).
    #     This answers the 2026-06-23 open question with NO new mechanism (floor + typed resource, already in LOOM). ---
    ("flat floor: stray Net cheats (D7 hole)",   '(defx fetch (Net!) (fn (u) (net "evil")))', True),   # honest limit: Net! only asks SOME net happen; the arg u is ignored, yet it type-checks
    ("resource-tied floor: must consume r",      '(defx fetch (Net!) (fn () (resource (r Net) (use r))))', True),  # the plug: the only way to discharge Net! is to USE r -> the effect is forced through the intended resource
    ("resource-tied floor: r ignored -> reject", '(defx fetch (Net!) (fn () (resource (r Net) (net "evil"))))', False),  # the cheat is caught: floor IS satisfied by stray net, yet REJECTED — r (the contract's resource) was never consumed
    # --- grown 2026-06-24 (pass 2): EXCLUSIVE-BEARER resource — inside (resource (r E..) ..) the effect E has NO ambient
    #     bearer but r; a stray ambient op of E (not via (use r)) is the decoupling cheat, now REFUSED — the
    #     "use-that-IS-the-net": linearity is unsatisfiable except BY performing E through r. ---
    ("exclusive: decoupling cheat refused", '(defx fetch (Net!) (fn () (resource (r Net) (let (a (use r)) (net "evil")))))', False),  # use r clears linearity; stray ambient net does the real work -> REFUSED
    ("exclusive: declared seam re-grant ok", '(defx fetch (Net!) (fn () (resource (r Net) (let (a (use r)) (seam (Net) (net "evil"))))))', True),  # exclusivity bans INVISIBLE decoupling, not a declared (seam ..) re-grant
    # --- flagship 2026-06-23: untrusted code sandboxed (capability seam) + linear resource + typed result, all PROVEN ---
    ("flagship: sandboxed + linear + typed", '(defx untrusted () (fn (x) (seam (Pure) (ffi "logger" x)))) (defx process () (fn (item) (resource conn (let (r (use conn)) (variant Ok (untrusted item)))))) (defx main () (fn () (match (process 42) ((Ok v) v) ((Err e) 0))))', True),
    # --- grown 2026-06-24: D9 PROVENANCE + the `trust` gate — defend CIRCULAR trust (the AI authoring the very criterion
    #     it is judged by). (prov P e) tags WHO authored a value; (trust e) demands an INDEPENDENT anchor (any provenance
    #     != 'ai'), else REJECTED. A channel SEPARATE from effects. Signals: KBSpec / CNnotator / CertiGC (the spec,
    #     the annotations, and the proof are ALL AI-generated too -> the gate was gameable by construction). ---
    ("trust: human anchor ok",        '(defx f () (fn () (trust (prov human 1))))', True),
    ("trust: purely-AI refused",      '(defx f () (fn () (trust (prov ai 1))))', False),               # circular: AI authored the value it gates
    ("trust: AI + human anchor ok",   '(defx f () (fn () (trust (prov ai (prov human 1)))))', True),    # one independent anchor is enough
    ("trust: real-trace anchor ok",   '(defx f () (fn () (trust (prov trace 1))))', True),
    ("trust: unprovenanced refused",  '(defx f () (fn () (trust 1)))', False),                          # no anchor at all = unanchored trust
    ("prov tag alone is free",        '(defx f () (fn () (prov ai 1)))', True),                         # tagging never bites; only `trust` gates
    ("trust: effects still flow",     '(defx f (Net) (fn (u) (trust (prov human (net u)))))', True),    # provenance is orthogonal to effects
    ("trust: under-declared effect still caught", '(defx f () (fn (u) (trust (prov human (net u)))))', False),  # human-anchored, yet Net undeclared -> REJECTED
    # --- grown 2026-06-24: D9.1 — independence as a QUANTITY. (trust N e) demands >= N DISTINCT independent anchors
    #     (provenance != 'ai'); N defaults to 1 (the D9 binary form). Answers NOSTROMO's open question: independence is a
    #     checkable NUMBER, not a binary. Provenance is a SET -> repeating a source does NOT count (needs real corroboration). ---
    ("trust N=2: two distinct anchors ok", '(defx f () (fn () (trust 2 (prov human (prov audit 1)))))', True),
    ("trust N=2: only one anchor refused",  '(defx f () (fn () (trust 2 (prov human 1))))', False),
    ("trust N=2: ai does not count",        '(defx f () (fn () (trust 2 (prov human (prov ai 1)))))', False),       # {human,ai}-ai = 1 < 2
    ("trust N=2: same source twice = 1",    '(defx f () (fn () (trust 2 (prov human (prov human 1)))))', False),    # set: distinct sources only
    ("trust N=3: three distinct ok",        '(defx f () (fn () (trust 3 (prov human (prov audit (prov trace 1))))))', True),
    ("trust N=1 explicit (backward-compat)",'(defx f () (fn () (trust 1 (prov human 1))))', True),
    # --- grown 2026-06-24: Rand — NONDETERMINISM as a tracked effect (randomness / wall-clock). Fresh axis: "what is
    #     AI code allowed to do" must cover hidden entropy. Mirrors net/alloc — superset rule, seams, handlers, `with`. ---
    ("rand: honest declares Rand",      '(defx f (Rand) (fn () (rand)))', True),
    ("rand: undeclared is the lie",     '(defx f () (fn () (rand)))', False),
    ("rand: over-declare is fine",      '(defx f (Rand) (fn (x) x))', True),
    ("rand: Pure seam sandboxes it",    '(defx f () (fn () (seam (Pure) (rand))))', False),     # seam wraps Rand but grants Pure
    ("rand: handle discharges it",      '(defx f () (fn () (handle (Rand) (rand))))', True),
    ("rand: with reinterprets to pure", '(defx rr (Rand) (fn () (rand))) (defx mk () (fn () 4)) (defx t () (fn () (with Rand mk (rr))))', True),
    ("rand: flows through a call",      '(defx g (Rand) (fn () (rand))) (defx h () (fn () (g)))', False),  # h calls g (Rand) yet declares Pure
    # --- grown 2026-06-27 (frontier pass 10): repro — a SCOPED, non-launderable REPRODUCIBILITY region.
    #     Tamper-evident (signed) != falsifiable (re-derivable): a Rand draw on a recorded/gated path is a HIDDEN
    #     INPUT that breaks re-derivation. `forbid`/`seal Rand` are GLOBAL; a bare `handle (Rand)` launders (op still
    #     fires); `repro` scopes the bound to ONE path and is non-launderable (the determinism dual of `seam`). ---
    ("repro: pure region accepts",          '(defx f () (fn (x) (repro (* x x))))', True),
    ("repro: Rand op on path refused",      '(defx f (Rand) (fn () (repro (rand))))', False),
    ("repro: Rand via call refused",        '(defx g (Rand) (fn () (rand))) (defx f (Rand) (fn () (repro (g))))', False),
    ("repro: handle CANNOT launder Rand",   '(defx f () (fn () (repro (handle (Rand) (rand)))))', False),
    ("repro: with-det reinterpret ok",      '(defx rr (Rand) (fn () (rand))) (defx mk () (fn () 4)) (defx f () (fn () (repro (with Rand mk (rr)))))', True),
    ("repro: non-Rand effects pass through",'(defx f (IO) (fn (x) (repro (print x))))', True),
    ("repro: scoped — Rand fine OUTSIDE",   '(defx f (Rand) (fn (x) (let (a (rand)) (repro (* x x)))))', True),
    ("repro: Rand nested in if refused",    '(defx f (Rand) (fn (c) (repro (if c (rand) 0))))', False),
    # --- grown 2026-06-24: D10 — independence by ROLES. (by ROLE WHO e) tags who performed a role; (trust (r..) e) demands
    #     each required role be covered by a non-ai author AND >= 2 DISTINCT authors total — defends CIRCULAR trust where one
    #     author owns code+spec+proof. A count of anchors (D9.1) can't see role distribution; this can.
    ("D10 roles: two roles two authors ok", '(defx f () (fn () (trust (roles code proof) (by code human (by proof trace 1)))))', True),
    ("D10 roles: a role only by ai refused", '(defx f () (fn () (trust (roles code proof) (by code ai (by proof trace 1)))))', False),    # code covered only by ai -> not covered
    ("D10 roles: single author all roles refused", '(defx f () (fn () (trust (roles code proof) (by code human (by proof human 1)))))', False),  # one author owns code+proof -> self-certifying
    ("D10 roles: missing role refused", '(defx f () (fn () (trust (roles code spec proof) (by code human (by proof trace 1)))))', False),   # spec role absent
    ("D10 roles: three roles three authors ok", '(defx f () (fn () (trust (roles code spec proof) (by code human (by spec audit (by proof trace 1))))))', True),
    ("D10: by-tag alone is free",       '(defx f () (fn () (by code human 1)))', True),                       # tagging never bites; only trust gates
    ("D10 roles: effects still flow",   '(defx f (Net) (fn (u) (trust (roles code proof) (by code human (by proof trace (net u))))))', True),     # role gate orthogonal to effects
    ("D10 roles: under-declared effect still caught", '(defx f () (fn (u) (trust (roles code proof) (by code human (by proof trace (net u))))))', False),  # Net undeclared -> REJECTED
    ("D10: by-author feeds the count form", '(defx f () (fn () (trust 2 (by code human (by proof trace 1)))))', True),   # by-authors are anchors for D9.1 too
    # --- grown 2026-06-24: D11 — roles as a LATTICE. (sub LOW HIGH) declares HIGH outranks LOW; a higher role STANDS IN FOR a
    #     lower required role. Strict direction (stronger checker covers weaker requirement, never reverse) + rank never bypasses
    #     the distinct-author rule. No (sub ..) => exact-name match = pure D10.
    ("D11 sub: auditor fills reviewer ok", '(defx f () (fn () (trust (roles code reviewer) (sub reviewer auditor) (by code human (by auditor alice 1)))))', True),
    ("D11 sub: wrong direction refused",   '(defx f () (fn () (trust (roles code auditor) (sub reviewer auditor) (by code human (by reviewer alice 1)))))', False),  # reviewer !>= auditor
    ("D11 sub: transitive subsumption ok", '(defx f () (fn () (trust (roles code reviewer) (sub reviewer auditor) (sub auditor board) (by code human (by board alice 1)))))', True),
    ("D11 sub: rank != independence",      '(defx f () (fn () (trust (roles code reviewer) (sub reviewer auditor) (by code alice (by auditor alice 1)))))', False),  # one author both -> circular
    ("D11: no sub => exact match only",    '(defx f () (fn () (trust (roles code reviewer) (by code human (by auditor alice 1)))))', False),  # auditor doesn't match reviewer w/o declared sub
    # --- grown 2026-06-24: D12 — provenance-GATED effects. A capability seam may carry a (roles ..) clause: the dangerous
    #     effect (Net/IO/FFI) is GRANTED only to independently-vouched code (same D10+D11 quorum over the seam body). This
    #     unifies the two axes — trust stops being a side-channel and becomes a CONDITION ON THE CAPABILITY ITSELF.
    ("D12: Net granted to vouched code",   '(defx f (Net) (fn (u) (seam (Net) (roles code review) (by code human (by review alice (net u))))))', True),
    ("D12: Net denied to ai-only code",    '(defx f (Net) (fn (u) (seam (Net) (roles code review) (by code ai (by review ai (net u))))))', False),   # capability needs non-ai roles
    ("D12: Net denied to single author",   '(defx f (Net) (fn (u) (seam (Net) (roles code review) (by code alice (by review alice (net u))))))', False),  # one author -> not independent
    ("D12: seam grant honors subsumption", '(defx f (Net) (fn (u) (seam (Net) (roles code review) (sub review auditor) (by code human (by auditor alice (net u))))))', True),   # auditor fills review
    ("D12: roles clause is opt-in (one author insufficient)", '(defx f (Net) (fn (u) (seam (Net) (roles code) (by code human (net u)))))', False),  # 1 author < 2 even though real
    # --- grown 2026-06-24: D13 — PER-EFFECT role binding. (needs EFF role) on a seam: that specific effect is granted only if
    #     the body carries the named role (non-ai, with D11 subsumption). Different dangers want different vouchers — Net wants
    #     a reviewer, FFI wants an auditor. Makes the D12 grant PRECISE, not a blanket quorum.
    ("D13 needs: Net+review satisfied",    '(defx f (Net) (fn (u) (seam (Net) (needs Net review) (by review alice (net u)))))', True),
    ("D13 needs: role absent denied",      '(defx f (Net) (fn (u) (seam (Net) (needs Net review) (by code alice (net u)))))', False),    # review role not present
    ("D13 needs: ai role denied",          '(defx f (Net) (fn (u) (seam (Net) (needs Net review) (by review ai (net u)))))', False),      # ai never vouches
    ("D13 needs: per-effect precision ok", '(defx f (Net IO) (fn (u) (seam (Net IO) (needs Net review) (needs IO audit) (by review alice (by audit bob (let (x (net u)) (print x)))))))', True),
    ("D13 needs: wrong role for effect",   '(defx f (Net) (fn (u) (seam (Net) (needs Net review) (by audit bob (net u)))))', False),    # audit present but Net needs review
    ("D13 needs: ungranted effect named",  '(defx f (Net) (fn (u) (seam (Net) (needs IO audit) (by audit bob (net u)))))', False),       # IO not granted by this seam
    ("D13 needs: honors subsumption",      '(defx f (Net) (fn (u) (seam (Net) (needs Net review) (sub review auditor) (by auditor alice (net u)))))', True),  # auditor fills review
    # --- grown 2026-06-24: D14 — the tokenizer now strips `;`-to-EOL COMMENTS (never inside a string literal). Before this,
    #     parens in a comment parsed as real forms and broke a check; comments are now genuinely inert.
    ("D14 comment: parens in inline comment ignored", '(defx f (IO) (fn (x)\n  ; danger (net x) (ffi y) mentioned here\n  (print x)))', True),  # would have slurped (net x)/(ffi y) before
    ("D14 comment: does NOT mask a real lie", '(defx f () (fn (x) (print x))) ; trailing (print x) is just a comment\n', False),   # f really does IO, declares none -> still REJECTED
    ("D14 comment: semicolon inside a string is not a comment", '(defx f (IO) (fn () (print "a;b")))', True),   # the ';' lives in the string, not a comment
    # --- grown 2026-06-24: D15 — program-wide trust POLICY declared once at top level. (rank LOW HIGH) is a global subsumption
    #     edge merged into every gate; (require EFF role) mandates that every seam granting EFF carries that role. The policy is
    #     reset per program (never leaks). Trust stops being a repeated per-gate pattern and becomes a property of the codebase.
    ("D15 rank: global rank fills a lower requirement", '(rank reviewer auditor) (defx f () (fn () (trust (roles code reviewer) (by code human (by auditor alice 1)))))', True),
    ("D15 rank: does NOT leak to a program without it", '(defx f () (fn () (trust (roles code reviewer) (by code human (by auditor alice 1)))))', False),  # no (rank) here -> auditor != reviewer
    ("D15 require: mandates a vouch on the effect", '(require Net review) (defx f (Net) (fn (u) (seam (Net) (by review alice (net u)))))', True),
    ("D15 require: rejects an un-vouched grant", '(require Net review) (defx f (Net) (fn (u) (seam (Net) (net u))))', False),   # Net granted, no review anchor -> policy violation
    ("D15 require: does NOT leak (plain seam ok)", '(defx f (Net) (fn (u) (seam (Net) (net u))))', True),   # no policy -> ordinary capability seam
    ("D15: require honors global rank", '(rank review audit) (require Net review) (defx f (Net) (fn (u) (seam (Net) (by audit bob (net u)))))', True),  # audit subsumes review
    # --- grown 2026-06-24: D16 — NEGATIVE policy. (forbid EFF) at top level bans an effect program-wide: it may not ESCAPE into
    #     ANY function's effect row. Discharge it locally (with/handle) or don't perform it. The dual of (require ..) — together
    #     they are the full policy language (positive + negative), proven before run.
    ("D16 forbid: bans the effect",        '(forbid Net) (defx f (Net) (fn (u) (net u)))', False),
    ("D16 forbid: locally-discharged is allowed", '(forbid Net) (defx mock () (fn (x) x)) (defx t () (fn (u) (with Net mock (net u))))', True),   # Net reinterpreted -> never escapes
    ("D16 forbid: does NOT leak",          '(defx f (Net) (fn (u) (net u)))', True),   # no (forbid) -> Net is fine
    ("D16 forbid: catches a declared+granted effect", '(forbid FFI) (defx f (FFI) (fn (x) (seam (FFI) (ffi "x" x))))', False),  # FFI declared+granted, ceiling ok -> forbid bans it
    ("D16 forbid: leaves other effects alone", '(forbid FFI) (defx f (IO) (fn (x) (print x)))', True),   # IO != FFI
    # --- grown 2026-06-24: D17 — (require EFF N) with an INTEGER: every seam granting EFF must carry >= N DISTINCT independent
    #     (non-ai) authors (merges D15 policy with D9.1 counting). The number form lives alongside the role form (require EFF role).
    ("D17 require N: two authors meets N=2", '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (by review alice (net u))))))', True),
    ("D17 require N: one author fails N=2",  '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (net u)))))', False),
    ("D17 require N: ai does not count",     '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (by x ai (net u))))))', False),  # {human,ai}-ai = 1 < 2
    ("D17 require N: does NOT leak",         '(defx f (Net) (fn (u) (seam (Net) (by code human (net u)))))', True),   # no policy -> a single author is fine
    ("D17 require N: prov anchors count too",'(require Net 2) (defx f (Net) (fn (u) (seam (Net) (prov human (prov audit (net u))))))', True),  # prov + prov = 2 distinct
    # --- grown 2026-06-24: D18 — TAINT. Provenance now FLOWS through `let` bindings and computation: a value derived from a
    #     (prov P ..) still carries P when it reaches a gate. Provenance stops being syntactic (the literal anchor position) and
    #     becomes semantic (what the value is actually made of). Sound over-approximation: deriving from tainted data stays tainted.
    ("D18 taint: flows through let",        '(defx f () (fn () (trust 2 (let (a (prov human 1)) (let (b (prov audit a)) b)))))', True),  # b carries {human,audit}
    ("D18 taint: flows through computation",'(defx f () (fn (x) (trust (let (y (prov human x)) (+ y 1)))))', True),   # (+ y 1) carries human
    ("D18 taint: faithful, does not fabricate", '(defx f () (fn () (trust 2 (let (a (prov human 1)) a))))', False),   # only {human} = 1 < 2; taint flows, never invents
    ("D18 taint: roles flow through let",   '(defx f () (fn () (trust (roles code review) (let (x (by code human 1)) (by review alice x)))))', True),  # x carries (code,human)
    ("D18 taint: ai taint still refused",   '(defx f () (fn () (trust (let (y (prov ai 1)) y))))', False),   # y carries {ai}; ai never anchors -> refused
    # --- grown 2026-06-24: D19 — CROSS-STATEMENT taint. A `let` OUTSIDE the gate now flows its provenance INTO the gate: the
    #     checker threads a taint env (_TAINT_PROV/_TAINT_ROLE) through infer, updated at every `let` (scoped, shadowing-safe).
    #     This is the pattern that actually matters: bind an authored value, THEN trust a use of it later in scope.
    ("D19 cross-stmt: let outside trust flows in", '(defx f () (fn () (let (y (prov human 5)) (trust y))))', True),
    ("D19 cross-stmt: ai bound then trusted refused", '(defx f () (fn () (let (y (prov ai 5)) (trust y))))', False),
    ("D19 cross-stmt: count across two lets", '(defx f () (fn () (let (a (prov human 1)) (let (b (prov audit 2)) (trust 2 (+ a b))))))', True),
    ("D19 cross-stmt: roles flow across lets", '(defx f () (fn () (let (x (by code human 1)) (trust (roles code review) (by review alice x)))))', True),
    ("D19 cross-stmt: shadowing hides outer taint", '(defx f () (fn () (let (y (prov human 1)) (let (y 5) (trust y)))))', False),  # inner y is untainted -> refused (no leak)
    # --- grown 2026-06-24: D20 — capability CONFINEMENT by author (the COMPOSITION GRAPH, not just an SBOM). (author NAME role WHO)
    #     attributes a defx; (confine EFF role) lets a confined effect be WIELDED (performed DIRECTLY) only by a cleared author. ---
    ("D20 confine: cleared author may wield Net", '(confine Net trusted) (author send trusted dev) (defx send (Net) (fn (u) (seam (Net) (net u))))', True),
    ("D20 confine: unattributed wielder refused", '(confine Net trusted) (author send trusted dev) (defx send (Net) (fn (u) (seam (Net) (net u)))) (defx leak (Net) (fn (u) (seam (Net) (net u))))', False),
    ("D20 confine: ai-authored wielder refused", '(confine Net trusted) (author leak trusted ai) (defx leak (Net) (fn (u) (seam (Net) (net u))))', False),
    ("D20 confine: wrong role refused", '(confine Net trusted) (author leak other mallory) (defx leak (Net) (fn (u) (seam (Net) (net u))))', False),
    ("D20 confine: honors global rank", '(rank trusted root) (confine Net trusted) (author send root dev) (defx send (Net) (fn (u) (seam (Net) (net u))))', True),
    ("D20 confine: router need not be cleared, only the wielder", '(confine Net trusted) (author hit trusted dev) (defx hit (Net) (fn (u) (net u))) (defx route (Net) (fn (u) (seam (Net) (hit u))))', True),
    ("D20 confine: does NOT leak (no policy)", '(defx leak (Net) (fn (u) (seam (Net) (net u))))', True),
    ("D20 confine: discharged effect not wielded", '(confine Net trusted) (defx mock () (fn (x) x)) (defx t () (fn (u) (with Net mock (net u))))', True),
    # --- grown 2026-06-25: D21 — (declassify ROLE e): the principled ESCAPE HATCH for provenance taint (D18/D19). A non-ai
    #     ROLE explicitly LAUNDERS the taint (drops the `ai` provenance, adds ROLE's vouch) so a human can take responsibility
    #     for an ai-derived value; ai itself may NOT declassify (the core anti-circularity rule). Provenance-only, additive. ---
    ("D21 declassify: human launders ai -> trusts", '(defx f () (fn () (trust (declassify human (prov ai 5)))))', True),
    ("D21 declassify: ai cannot launder", '(defx f () (fn () (trust (declassify ai (prov human 5)))))', False),
    ("D21 declassify: laundered value flows through let", '(defx f () (fn () (let (y (declassify human (prov ai 1))) (trust y))))', True),
    ("D21 declassify: ai-declassify through let refused", '(defx f () (fn () (let (y (declassify ai (prov human 1))) (trust y))))', False),
    ("D21 declassify: effects still pass through", '(defx f (Net) (fn () (declassify human (net 1))))', True),
    ("D21 declassify: one declassifier is not 2 anchors", '(defx f () (fn () (trust 2 (declassify human (prov ai 5)))))', False),
    # --- grown 2026-06-25: D22 -- (seal EFF): COMPLETE-MEDIATION policy. (forbid EFF) bans EFF from a function's ROW but
    #     ALLOWS discharging it locally (with/handle); yet `handle` of a non-IO effect is a STATIC-ONLY drop -- at runtime
    #     the op still FIRES (handle truly captures only IO). That is the unfireable-kernel / escapable-system gap in LOOM's
    #     own terms. (seal EFF) refuses the silent drop: a sealed effect may NOT be handled away -- it stays in the
    #     accountable row, or is genuinely reinterpreted by `with`. Opt-in, additive (no existing program carries (seal ..)).
    ("D22 seal: handle-discharge of sealed Net refused", '(seal Net) (defx f () (fn (u) (handle (Net) (net u))))', False),
    ("D22 seal: effect kept in the row is fine",         '(seal Net) (defx f (Net) (fn (u) (net u)))', True),
    ("D22 seal: `with` reinterpretation still allowed",  '(seal Net) (defx mock () (fn (x) x)) (defx t () (fn (u) (with Net mock (net u))))', True),
    ("D22 seal: targets only the sealed effect",         '(seal IO) (defx f (Net) (fn (u) (handle (Net) (net u))))', True),
    ("D22 seal: overrides default handle leniency (Rand)",'(seal Rand) (defx f () (fn () (handle (Rand) (rand))))', False),
    ("D22 seal: nested handle of sealed effect caught",  '(seal Net) (defx f (IO) (fn (u) (handle (IO) (let (z (handle (Net) (net u))) (print u)))))', False),
    ("D22 seal: does NOT leak (no policy)",              '(defx f () (fn (u) (handle (Net) (net u))))', True),
    # --- grown 2026-06-25 (pass 2): D22 — INTERPROCEDURAL provenance taint. Provenance now flows through a
    #     function CALL: a (trust raw-param) inside a callee DEFERS its anchor obligation to each call site,
    #     where the actual argument's provenance discharges it (the natural completion of D18 intra-expr +
    #     D19 cross-let + D21 declassify). Count-form only; an obligation-bearing fn may NOT be passed as a
    #     value (the obligation would escape discharge via an indirect call) — fail-closed (ai never sneaks). ---
    ("D22 interproc: human arg flows through call", '(defx g () (fn (x) (trust x))) (defx top () (fn () (g (prov human 5))))', True),
    ("D22 interproc: ai arg refused", '(defx g () (fn (x) (trust x))) (defx top () (fn () (g (prov ai 5))))', False),
    ("D22 interproc: unprovenanced arg refused", '(defx g () (fn (x) (trust x))) (defx top () (fn () (g 5)))', False),
    ("D22 interproc: callee alone (uncalled) is not a lie", '(defx g () (fn (x) (trust x)))', True),
    ("D22 interproc: N=2 two distinct anchors through call", '(defx g () (fn (x) (trust 2 x))) (defx top () (fn () (g (prov human (prov audit 5)))))', True),
    ("D22 interproc: N=2 one anchor refused", '(defx g () (fn (x) (trust 2 x))) (defx top () (fn () (g (prov human 5))))', False),
    ("D22 interproc: N=2 same source twice refused", '(defx g () (fn (x) (trust 2 x))) (defx top () (fn () (g (prov human (prov human 5)))))', False),
    ("D22 interproc: cross-stmt let then call flows", '(defx g () (fn (x) (trust x))) (defx top () (fn () (let (v (prov human 5)) (g v))))', True),
    ("D22 interproc: obligation-fn passed as value refused", '(defx g () (fn (x) (trust x))) (defx ap (e) (fn ((f e) y) (f y))) (defx top () (fn () (ap g (prov human 5))))', False),
    ("D22 interproc: effects still flow through the call", '(defx g (Net) (fn (x) (trust (prov human (net x))))) (defx top (Net) (fn () (g 5)))', True),
    ("D22 interproc: shadowed param not deferred (no leak)", '(defx g () (fn (y) (let (y 5) (trust y)))) (defx top () (fn () (g (prov human 1))))', False),
    # --- grown 2026-06-25 (pass 2): D23 - NEGATIVE TRUST POLICY (forbid declassify). The trust-layer twin of D16
    #     (forbid EFF): a top-level (forbid declassify) bans the D21 laundering hatch program-wide, so NO ai-derived
    #     value can be rubber-stamped into trust anywhere - the poisoned-playbook antidote as a one-line guarantee.
    #     Detected syntactically (declassify performs no effect row to match against). ---
    ("D23 forbid declassify: laundering banned", '(forbid declassify) (defx f () (fn () (trust (declassify human (prov ai 5)))))', False),
    ("D23 forbid declassify: clean program still ok", '(forbid declassify) (defx f () (fn () (trust (prov human 5))))', True),
    ("D23 declassify w/o the policy still ok (D21 intact)", '(defx f () (fn () (trust (declassify human (prov ai 5)))))', True),
    ("D23 forbid declassify: caught nested in a let", '(forbid declassify) (defx f () (fn () (let (y (declassify human (prov ai 1))) (trust y))))', False),
    ("D23 forbid declassify: caught inside a seam body", '(forbid declassify) (defx f (IO) (fn (x) (seam (IO) (declassify human (print x)))))', False),
    ("D23 forbid declassify: caught inside a match arm", '(forbid declassify) (defx f () (fn (e) (match e ((Some x) (declassify human x)) ((None) 0))))', False),
    ("D23 forbid Net does NOT ban declassify", '(forbid Net) (defx f () (fn () (trust (declassify human (prov ai 5)))))', True),
    # --- grown 2026-06-26: D24 -- PROVENANCE DOES NOT SURVIVE PERSISTENCE. (recall e) models a value crossing a memory/RAG
    #     store->recall boundary ACROSS TICKS; provenance is a static layer that does NOT serialize, so recall STRIPS all
    #     inner anchors and marks the value ai-tainted (the fail-closed DUAL of D21 declassify). Defends MEMORY POISONING:
    #     untrusted text persisted on tick 1 -> read back as 'trusted ground truth' on tick 2. Re-trust needs a LIVE vouch
    #     applied AFTER recall (outside it); a vouch placed INSIDE recall did not survive serialization. ---
    ("D24 recall: raw recalled value is untrusted", '(defx f () (fn () (trust 1 (recall 5))))', False),
    ("D24 recall: inner human vouch does NOT survive persistence", '(defx f () (fn () (trust 1 (recall (prov human 5)))))', False),
    ("D24 recall: inner role vouch does NOT survive persistence", '(defx f () (fn () (trust (roles code proof) (recall (by code human (by proof trace 5))))))', False),
    ("D24 recall: LIVE re-vouch after recall is honored", '(defx f () (fn () (trust 1 (prov human (recall 5)))))', True),
    ("D24 recall: persistence cannot launder an ai origin to trusted", '(defx f () (fn () (trust 1 (recall (prov ai 5)))))', False),
    ("D24 recall: effects still pass through a recall", '(defx f (Net) (fn (u) (recall (net u))))', True),
    ("D24 recall: bare recall tag never bites without a trust gate", '(defx f () (fn () (recall 5)))', True),
    ("D24 recall: two live re-vouchers satisfy N=2 after recall", '(defx f () (fn () (trust 2 (prov human (prov audit (recall 5))))))', True),
    # --- grown 2026-06-26: D25 — MULTI-HOP interprocedural provenance. A relay top -> mid -> g, where mid passes
    #     its OWN raw param into g's trusted slot, now ACCEPTS when the ROOT caller supplies the anchor: a callee's
    #     obligation PROPAGATES to the caller's param via the monotone preq fixpoint (like the effect row), and the
    #     discharge DEFERS at the relay (our own raw param -> obligation rides up). Fail-closed everywhere else.
    ("D25 multi-hop: 2-hop relay accepts human", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (mid (prov human 5))))', True),
    ("D25 multi-hop: 2-hop relay ai refused", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (mid (prov ai 5))))', False),
    ("D25 multi-hop: 2-hop relay unprovenanced refused", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (mid 5)))', False),
    ("D25 multi-hop: 3-hop relay accepts", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx mid2 () (fn (x) (mid x))) (defx top () (fn () (mid2 (prov human 5))))', True),
    ("D25 multi-hop: relay defined but uncalled is not a lie", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x)))', True),
    ("D25 multi-hop: N=2 relay two anchors accepts", '(defx g () (fn (x) (trust 2 x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (mid (prov human (prov audit 5)))))', True),
    ("D25 multi-hop: N=2 relay one anchor refused", '(defx g () (fn (x) (trust 2 x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (mid (prov human 5))))', False),
    ("D25 multi-hop: caller supplies anchor via cross-stmt let", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx top () (fn () (let (v (prov human 5)) (mid v))))', True),
    ("D25 multi-hop: relay fn used as value refused", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (g x))) (defx ap (e) (fn ((f e) y) (f y))) (defx top () (fn () (ap mid (prov human 5))))', False),
    ("D25 multi-hop: relay of ai-shadowed param refused", '(defx g () (fn (x) (trust x))) (defx mid () (fn (x) (let (x (prov ai 9)) (g x)))) (defx top () (fn () (mid (prov human 5))))', False),
    ("D25 multi-hop: obligation tracks the right param position", '(defx g () (fn (x) (trust x))) (defx mid () (fn (a b) (g b))) (defx top () (fn () (mid (prov human 1) 5)))', False),
    # --- grown 2026-06-26 (pass 2): D26 — provenance does NOT survive an opaque FFI boundary. The same (ffi ..) that
    #     has no ambient EFFECT-authority (it must be seam-granted) also has no DATA-authority: whatever opaque foreign
    #     code returns cannot carry the host's vouch, so prov_of/roles_of STRIP all anchors at an ffi node and mark it
    #     ai-tainted — the exact dual of D24 recall (persistence boundary), now at the INTEROP boundary. Re-trust needs a
    #     LIVE host re-vouch placed OUTSIDE the ffi, or an explicit (declassify ..). Fail-closed everywhere else.
    ("D26 ffi: input vouch does NOT survive a foreign call", '(defx f () (fn () (trust (seam (Pure) (ffi "x" (prov human 5))))))', False),
    ("D26 ffi: live re-vouch AFTER the foreign call is honored", '(defx f () (fn () (trust (prov human (seam (Pure) (ffi "x" 5))))))', True),
    ("D26 ffi: laundered value blocked even through a let", '(defx f () (fn () (let (y (seam (Pure) (ffi "x" (prov human 5)))) (trust y))))', False),
    ("D26 ffi: foreign result cannot launder an ai origin", '(defx f () (fn () (trust (seam (Pure) (ffi "x" (prov ai 5))))))', False),
    ("D26 ffi: N=2 not met by foreign-stripped anchors", '(defx f () (fn () (trust 2 (seam (Pure) (ffi "x" (prov human (prov audit 5)))))))', False),
    ("D26 ffi: role vouch does NOT survive a foreign call", '(defx f () (fn () (trust (roles code proof) (seam (Pure) (ffi "x" (by code human (by proof trace 5)))))))', False),
    ("D26 ffi: two live re-vouchers satisfy N=2 after a foreign call", '(defx f () (fn () (trust 2 (prov human (prov audit (seam (Pure) (ffi "x" 5)))))))', True),
    ("D26 ffi: effects still flow through a foreign call (orthogonal)", '(defx f (IO) (fn (x) (seam (IO) (ffi "logger" x))))', True),
    ("D26 ffi: bare ffi tag without a trust gate never bites", '(defx f () (fn (x) (seam (Pure) (ffi "x" (prov human x)))))', True),
    # --- grown 2026-06-26 (pass 9): D27 — METERED capabilities (seamN K). seam1 (D23) is the quantum=1 meter; the
    #     {0,1,'M'} use-count lattice collapses every count >= 2, so at-most-N (N>=2) is unrepresentable: a legit 2-use
    #     task must over-grant (seam, UNBOUNDED) or under-grant (seam1). (seamN K (E..) ... body) bounds each granted
    #     effect to K uses via an exact saturating count, delegating EVERY seam gate (no bypass); an effect reaching the
    #     meter via a call/recursion/reinterpret/discharge saturates to overflow (fail-closed). Signals: otari (budget
    #     enforcement), tokenomics (per-token metering), Agent Zero (unbounded ambient). ---
    ("D27 metered: under quantum ok",        '(defx f (Net) (fn (u) (seamN 2 (Net) (net u) (net u))))', True),
    ("D27 metered: over quantum refused",    '(defx f (Net) (fn (u) (seamN 1 (Net) (net u) (net u))))', False),
    ("D27 metered: K=1 is seam1 (at most once)", '(defx f (Net) (fn (u) (seamN 1 (Net) (net u))))', True),
    ("D27 metered: exactly K accepts",       '(defx f (Net) (fn (u) (seamN 3 (Net) (net u) (net u) (net u))))', True),
    ("D27 metered: K+1 refused",             '(defx f (Net) (fn (u) (seamN 2 (Net) (net u) (net u) (net u))))', False),
    ("D27 metered: if-branches not summed",  '(defx f (Net) (fn (u c) (seamN 1 (Net) (if c (net u) (net u)))))', True),
    ("D27 metered: effect via a call is fail-closed", '(defx hit (Net) (fn (u) (net u))) (defx f (Net) (fn (u) (seamN 5 (Net) (hit u))))', False),
    ("D27 metered: under-declared row still caught", '(defx f (Net) (fn (u) (seamN 2 (Pure) (net u))))', False),
    ("D27 metered: per-effect quantum holds", '(defx f (Net IO) (fn (u) (seamN 2 (Net IO) (net u) (net u) (print u))))', True),
    ("D27 metered: nested seam cannot launder amplification", '(defx f (Net) (fn (u) (seamN 1 (Net) (seam (Net) (net u) (net u)))))', False),
    # --- grown 2026-06-26 (pass 3): D27 — GRADED foreign trust via component-bound ATTESTATION. D26 strips ALL foreign
    #     output to ai (binary). A seam clause (vouch ROLE WHO COMP) lets a NON-AI authority WHO sign a SPECIFIC foreign
    #     component COMP, so (ffi COMP ..) directly in that seam body carries WHO's anchor instead of the strip — making
    #     trusted-FFI graded (audited vs arbitrary). Sound AS AN ATTESTATION (the checker enforces non-ai authorship +
    #     EXACT component-name match), not a verification. The dual of D21 declassify, bound to component IDENTITY (which
    #     declassify/prov/by cannot express). Signals: julelang/jule (first-class C/C++ interop + compile-time caps),
    #     carbon-lang (C++ interop), lantos1618/zen-holotype (one mechanism — the seam now also carries data-attestation).
    ("D27 vouch: auditor signs the component -> trusted", '(defx f () (fn (x) (trust (seam (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', True),
    ("D27 vouch: names a DIFFERENT component -> stripped", '(defx f () (fn (x) (trust (seam (Pure) (vouch auditor alice "other") (ffi "lib" x)))))', False),
    ("D27 vouch: ai cannot self-vouch (fail-closed)", '(defx f () (fn (x) (trust (seam (Pure) (vouch auditor ai "lib") (ffi "lib" x)))))', False),
    ("D27 vouch: no vouch -> D26 strip still stands", '(defx f () (fn () (trust (seam (Pure) (ffi "x" (prov human 5))))))', False),
    ("D27 vouch: effects still flow alongside the attestation", '(defx f (Net) (fn (x) (trust (seam (Net) (vouch auditor alice "lib") (ffi "lib" x)))))', True),
    ("D27 vouch: one vouch is ONE anchor, not N=2", '(defx f () (fn (x) (trust 2 (seam (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', False),
    ("D27 vouch: two distinct vouchers meet N=2", '(defx f () (fn (x) (trust 2 (seam (Pure) (vouch auditor alice "lib") (vouch sig bob "lib") (ffi "lib" x)))))', True),
    ("D27 vouch: role-quorum met by two component auditors", '(defx f () (fn (x) (trust (roles code proof) (seam (Pure) (vouch code alice "lib") (vouch proof bob "lib") (ffi "lib" x)))))', True),
    ("D27 vouch: nested (non-direct) ffi not covered -> stripped", '(defx f () (fn (x) (trust (seam (Pure) (vouch auditor alice "lib") (let (y (ffi "lib" x)) y)))))', False),
    # --- grown 2026-06-27: D28 -- METERED attestation. seamN (the D27 metered seam) carried effect-grant + use-quantum but
    #     DROPPED the (vouch ..) attestation a plain seam honors (prov_of/roles_of had no seamN case), so a metered+vouched
    #     foreign call was over-rejected. Now seamN honors the SAME direct-body component attestation as seam/seam1 -- the one
    #     seam carries grant + meter + attestation together. Direct-body ONLY (Horn B): a vouch does NOT reach an ffi nested
    #     under computation (mirrors the line above). Signals: julelang/jule (compile-time capabilities), zen-holotype (imports+checks=one fits()). ---
    ("D28 metered vouch: auditor signs a metered component -> trusted", '(defx f () (fn (x) (trust (seamN 2 (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', True),
    ("D28 metered vouch: different component -> stripped", '(defx f () (fn (x) (trust (seamN 2 (Pure) (vouch auditor alice "other") (ffi "lib" x)))))', False),
    ("D28 metered vouch: ai cannot self-vouch a metered component", '(defx f () (fn (x) (trust (seamN 2 (Pure) (vouch auditor ai "lib") (ffi "lib" x)))))', False),
    ("D28 metered vouch: nested (non-direct) ffi still stripped (Horn B)", '(defx f () (fn (x) (trust (seamN 2 (Pure) (vouch auditor alice "lib") (let (y (ffi "lib" x)) y)))))', False),
    ("D28 metered vouch: two distinct vouchers meet N=2", '(defx f () (fn (x) (trust 2 (seamN 2 (Pure) (vouch auditor alice "lib") (vouch sig bob "lib") (ffi "lib" x)))))', True),
    ("D28 metered vouch: role-quorum met by two metered-component auditors", '(defx f () (fn (x) (trust (roles code proof) (seamN 2 (Pure) (vouch code alice "lib") (vouch proof bob "lib") (ffi "lib" x)))))', True),
    ("D28 metered vouch: meter still bites alongside attestation", '(defx f (Net) (fn (x) (trust (seamN 1 (Net) (vouch auditor alice "lib") (net x) (net x) (ffi "lib" x)))))', False),
    ("D28 metered vouch: one voucher does not meet N=2", '(defx f () (fn (x) (trust 2 (seamN 2 (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', False),
    # --- grown 2026-06-26 (pass 3): D27 -- the ShareLock INTERPROCEDURAL split. The GRANT (a (seam E)
    #     that performs E) and the LAUNDER (a (handle E) that drops E from the row) are split across
    #     TWO functions; each passes its local ceiling check, yet the composition performs E and the
    #     ENTRY function declares Pure. PINS: (a) without the handle the effect-CLOSURE surfaces (the
    #     fixpoint is a JOINT judge -- no effect fires that no defx declares), (b) the residual is the
    #     entry row only, (c) (seal E) catches the laundering handle in whichever function holds it. ---
    ("D27 split-launder: handle outside a granting seam hides Net (the gap)", '(defx leak (Net) (fn () (seam (Net) (net 1)))) (defx hideit () (fn () (handle (Net) (leak))))', True),
    ("D27 split-launder: (seal Net) rejects it across the call boundary", '(seal Net) (defx leak (Net) (fn () (seam (Net) (net 1)))) (defx hideit () (fn () (handle (Net) (leak))))', False),
    ("D27 split-launder: without the handle, Net closure surfaces (joint judge)", '(defx leak (Net) (fn () (seam (Net) (net 1)))) (defx hideit () (fn () (leak)))', False),
    ("D27 split-launder: honest declaration of the routed effect is fine", '(defx leak (Net) (fn () (seam (Net) (net 1)))) (defx route (Net) (fn () (leak)))', True),
    ("D27 split-launder: IO variant accepts statically too (runtime-sound: handle captures IO)", '(defx leakio (IO) (fn () (seam (IO) (print 1)))) (defx hideio () (fn () (handle (IO) (leakio))))', True),
    ("D27 split-launder: (seal IO) also rejects the IO laundering", '(seal IO) (defx leakio (IO) (fn () (seam (IO) (print 1)))) (defx hideio () (fn () (handle (IO) (leakio))))', False),
    # --- grown 2026-06-26 (growth pass #7): D26 RE-VOUCH BOUNDARY -- pin the EXACT line between a host
    #     re-vouch that SURVIVES the foreign boundary and a vouch on the foreign INPUT that is STRIPPED.
    #     The D26 cases above pin 'prov OUTSIDE the seam' (accept) and 'prov as the ffi INPUT' (reject);
    #     these pin the SHARP middle: a vouch ABOVE the ffi node (host owns the RESULT) survives across
    #     prov/by/declassify; the ai-declassify guard holds at the ffi; and an N=2 gate cannot be PADDED
    #     with a foreign-stripped anchor. loom.py UNTOUCHED -- guards D26 (the live-playground headline). ---
    ("D26 boundary: prov ABOVE the ffi (inside the seam) survives", '(defx f () (fn () (trust (seam (Pure) (prov human (ffi "x" 5))))))', True),
    ("D26 boundary: declassify of a foreign result re-trusts (non-ai owns it)", '(defx f () (fn () (trust (declassify auditor (seam (Pure) (ffi "x" 5))))))', True),
    ("D26 boundary: ai cannot declassify its own foreign result", '(defx f () (fn () (trust (declassify ai (seam (Pure) (ffi "x" 5))))))', False),
    ("D26 boundary: (by ROLE WHO ..) re-vouch above the ffi survives", '(defx f () (fn () (trust (by code human (seam (Pure) (ffi "x" 5))))))', True),
    ("D26 boundary: by-form vouch on the foreign INPUT is stripped (through a let)", '(defx f () (fn () (let (y (seam (Pure) (ffi "x" (by code human 5)))) (trust y))))', False),
    ("D26 boundary: declassify placed BETWEEN seam and ffi re-trusts the result", '(defx f () (fn () (trust (seam (Pure) (declassify auditor (ffi "x" 5))))))', True),
    ("D26 boundary: N=2 cannot be padded by a foreign-stripped anchor", '(defx f () (fn () (trust 2 (prov human (seam (Pure) (ffi "x" (prov audit 5)))))))', False),
    # --- grown 2026-06-27: D27 -- the ShareLock PROVENANCE split (answering D26 p3's deferred quorum question).
    #     EFFECTS ride the fixpoint (joint judge); PROVENANCE does NOT -- prov_of/roles_of and both quorum checks
    #     (require-N count, (roles ..) quorum) are SYNTACTIC over the SEAM BODY and never recurse into a callee.
    #     So a 2nd author SCATTERED into a CALLEE is invisible: the split rejects EXACTLY like the 1-author control
    #     (fail-closed -- under-count, never launder UP). The one true multi-anchor forgery is the SINGLE-FUNCTION
    #     declassify double-tag (no split); (forbid declassify) closes it and it cannot cross a frame. loom.py
    #     UNTOUCHED -- this PINS the fail-closed invariant so a future 'propagate provenance through calls' feature
    #     (which would reopen cross-frame sum-laundering) is caught RED. ---
    ("D27 quorum-split: require-N two authors in the seam body ok", '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (by review alice (net u))))))', True),
    ("D27 quorum-split: require-N 2nd author in a CALLEE does not count (fail-closed)", '(require Net 2) (defx vouch () (fn () (by review alice 1))) (defx f (Net) (fn (u) (seam (Net) (by code human (net (vouch))))))', False),
    ("D27 quorum-split: require-N one author refused (control)", '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (net u)))))', False),
    ("D27 quorum-split: roles two authors in the seam body ok", '(defx f (Net) (fn (u) (seam (Net) (roles code review) (by code human (by review alice (net u))))))', True),
    ("D27 quorum-split: roles 2nd author in a CALLEE does not count (fail-closed)", '(defx vouch () (fn () (by review alice 1))) (defx f (Net) (fn (u) (seam (Net) (roles code review) (by code human (net (vouch))))))', False),
    ("D27 quorum-split: roles one author refused (control)", '(defx f (Net) (fn (u) (seam (Net) (roles code review) (by code human (net u)))))', False),
    ("D27 quorum-split: single-fn double-declassify forges 2 anchors (no split needed)", '(defx f () (fn () (trust 2 (declassify alice (declassify bob (prov ai 5))))))', True),
    ("D27 quorum-split: (forbid declassify) closes the double-declassify forgery", '(forbid declassify) (defx f () (fn () (trust 2 (declassify alice (declassify bob (prov ai 5))))))', False),
    ("D27 quorum-split: declassify forgery hidden in a callee cannot cross the frame", '(defx launder () (fn () (declassify alice (declassify bob (prov ai 5))))) (defx f () (fn () (trust 2 (launder))))', False),
]


def _capture9_program():
    body = "((fn (x) (+ x " + " ".join(f"a{i}" for i in range(1, 10)) + ")) 10)"
    for i in range(9, 0, -1):
        body = f"(let (a{i} {i}) {body})"
    return f"(defx t () (fn () {body}))"


CAPTURE9_PROGRAM = _capture9_program()


def main():
    ok = 0
    for name, src, accept in CASES:
        _, errs = check(parse(src))
        got = (len(errs) == 0)
        good = (got == accept); ok += good
        why = f"  [{errs[0]}]" if errs else ""
        print(f"  {'ok  ' if good else 'FAIL'} {name:22} expect={'accept' if accept else 'reject':6} got={'accept' if got else 'reject'}{why}")
    try:                                               # seamN should explain direct overflow differently from fail-closed opaque overflow
        _, direct_errs = check(parse('(defx f (Net) (fn (u) (seamN 1 (Net) (net u) (net u))))'))
        _, opaque_errs = check(parse('(defx hit (Net) (fn (u) (net u))) (defx f (Net) (fn (u) (seamN 5 (Net) (hit u))))'))
        direct_ok = bool(direct_errs) and "counted 2 direct use(s) in the seam body" in direct_errs[0]
        opaque_ok = bool(opaque_errs) and "meter became opaque via call/recursion/higher-order" in opaque_errs[0]
        meter_diag_ok = direct_ok and opaque_ok
        ok += meter_diag_ok
        print(f"  {'ok  ' if meter_diag_ok else 'FAIL'} checker: seamN diagnostics stay specific")
    except Exception as e:
        print(f"  FAIL seamN diagnostics: {e}")
    try:                                               # every check owns its policy/resource/taint context
        from concurrent.futures import ThreadPoolExecutor
        isolation_programs = [
            '(rank reviewer auditor) (defx f () (fn () (trust (roles code reviewer) (by code human (by auditor alice 1)))))',
            '(defx f () (fn () (trust (roles code reviewer) (by code human (by auditor alice 1)))))',
            '(forbid Net) (defx f (Net) (fn (u) (net u)))',
            '(defx f (Net) (fn (u) (net u)))',
            '(require Net 2) (defx f (Net) (fn (u) (seam (Net) (by code human (net u)))))',
            '(defx f () (fn () (let (v (prov ai 5)) (trust v))))',
        ]
        expected = [not bool(check(parse(p))[1]) for p in isolation_programs]
        def check_isolated(i):
            p = isolation_programs[i % len(isolation_programs)]
            return i % len(isolation_programs), not bool(check(parse(p))[1])
        with ThreadPoolExecutor(max_workers=8) as pool:
            isolated = list(pool.map(check_isolated, range(64)))
        legacy = ("_POLICY", "_RENV", "_TAINT_PROV", "_TAINT_ROLE")
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        boundary_ok = is_browser_bundle or getattr(_loom, "_loom_checker", None).__name__ == "loom_checker"
        checker_context_ok = (
            boundary_ok
            and not any(hasattr(_loom, name) for name in legacy)
            and all(got == expected[i] for i, got in isolated)
        )
        ok += checker_context_ok
        print(f"  {'ok  ' if checker_context_ok else 'FAIL'} checker: module boundary + isolated contexts (64 parallel checks)")
    except Exception as e:
        print(f"  FAIL checker context isolation: {e}")
    try:                                               # parser stays deterministic and modular under concurrent use
        from concurrent.futures import ThreadPoolExecutor
        parser_sources = [
            '(defx f () (fn () 1))',
            '(defx f () (fn () "a;b")) ; trailing comment',
            '(defx f () (fn () (list 1 (record (a 2)))))',
        ]
        expected = [parse(src) for src in parser_sources]
        def parse_isolated(i):
            src = parser_sources[i % len(parser_sources)]
            return i % len(parser_sources), parse(src)
        with ThreadPoolExecutor(max_workers=8) as pool:
            isolated = list(pool.map(parse_isolated, range(64)))
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        boundary_ok = is_browser_bundle or getattr(_loom, "_loom_parse", None).__name__ == "loom_parse"
        parser_ok = boundary_ok and all(got == expected[i] for i, got in isolated)
        ok += parser_ok
        print(f"  {'ok  ' if parser_ok else 'FAIL'} parser: module boundary + isolated parses (64 parallel reads)")
    except Exception as e:
        print(f"  FAIL parser module boundary: {e}")
    try:                                               # every runtime call owns its capability stack
        from concurrent.futures import ThreadPoolExecutor
        runtime_programs = [
            ('(defx fa (IO) (fn (x) (seam (IO) (ffi "logger" x))))', "(fa 7)"),
            ('(defx fb () (fn (x) (seam (Pure) (ffi "logger" x))))', "(fb 7)"),
            ('(defx fc (IO) (fn (x) (let (y (seam (Pure) (ffi "logger" x))) (seam (IO) (ffi "logger" y)))))', "(fc 7)"),
        ]
        expected = [run_call(program, call) for program, call in runtime_programs]
        def run_isolated(i):
            program, call = runtime_programs[i % len(runtime_programs)]
            return i % len(runtime_programs), run_call(program, call)
        with ThreadPoolExecutor(max_workers=8) as pool:
            isolated = list(pool.map(run_isolated, range(64)))
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        boundary_ok = is_browser_bundle or getattr(_loom, "_loom_runtime", None).__name__ == "loom_runtime"
        runtime_context_ok = (
            boundary_ok
            and
            not hasattr(_loom, "_CAPS")
            and all(got == expected[i] for i, got in isolated)
        )
        ok += runtime_context_ok
        print(f"  {'ok  ' if runtime_context_ok else 'FAIL'} runtime: module boundary + isolated capability contexts (64 parallel calls)")
    except Exception as e:
        print(f"  FAIL runtime capability isolation: {e}")
    try:                                               # runtime facade must stay a thin wrapper over the extracted module
        runtime_program = '(defx rt () (fn (x) (if (> x 0) (+ x 1) x)))'
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        if is_browser_bundle:
            runtime_facade_ok = True                   # published Pyodide artifact is intentionally one self-contained file
        else:
            impl = getattr(_loom, "_loom_runtime", None)
            frontend = getattr(_loom, "_RUNTIME_FRONTEND", None)
            runtime_facade_ok = (
                getattr(impl, "__name__", None) == "loom_runtime"
                and run_call(runtime_program, "(rt 4)") == impl.run_call(runtime_program, "(rt 4)", frontend)
                and getattr(_loom, "Closure", None) is getattr(impl, "Closure", None)
            )
        ok += runtime_facade_ok
        print(f"  {'ok  ' if runtime_facade_ok else 'FAIL'} runtime: stable module facade")
    except Exception as e:
        print(f"  FAIL runtime module facade: {e}")
    try:                                               # runtime smoke: an honest program actually RUNS
        val, _ = run_call('(defx square () (fn (x) (* x x)))', "(square 7)")
        run_ok = (val == 49); ok += run_ok
        print(f"  {'ok  ' if run_ok else 'FAIL'} runtime (square 7) = {val}")
    except LoomError as e:
        print(f"  FAIL runtime: {e}")
    try:                                               # runtime smoke: an Alloc program actually RUNS
        val2, _ = run_call('(defx makebuf (Alloc) (fn (n) (alloc n)))', "(makebuf 3)")
        run_ok2 = (val2 == [0, 1, 2]); ok += run_ok2
        print(f"  {'ok  ' if run_ok2 else 'FAIL'} runtime (makebuf 3) = {val2}")
    except LoomError as e:
        print(f"  FAIL runtime alloc: {e}")
    try:                                               # backend frontier: wasm alloc list decoding mirrors the interpreter
        wval2, _ = run_wasm('(defx makebuf (Alloc) (fn (n) (alloc n)))', "(makebuf 3)")
        w_ok2 = (wval2 == [0, 1, 2]); ok += w_ok2
        print(f"  {'ok  ' if w_ok2 else 'FAIL'} backend(WASM): alloc (makebuf 3) = {wval2}")
    except LoomError as e:
        print(f"  FAIL backend(WASM) alloc: {e}")
    try:                                               # tagged runtime: structured values cross the WASM host boundary exactly
        wr, _ = run_wasm('(defx r () (fn () (record (a 1) (b 2))))', "(r)")
        wv, _ = run_wasm('(defx v () (fn () (variant Some 5)))', "(v)")
        wn, _ = run_wasm('(defx n () (fn () (record (xs (list 4 5)) (v (variant Ok 7)))))', "(n)")
        w_struct = (wr == {"a": 1, "b": 2} and wv == ("Some", 5) and wn == {"xs": [4, 5], "v": ("Ok", 7)})
        ok += w_struct
        print(f"  {'ok  ' if w_struct else 'FAIL'} backend(WASM): tagged record/variant round-trip")
    except LoomError as e:
        print(f"  FAIL backend(WASM) structured values: {e}")
    try:                                               # even immediates cannot alias odd tagged heap pointers
        wa, _ = run_wasm('(defx alias () (fn () (let (x (list 1 2)) 9)))', "(alias)")
        w_alias = (wa == 9); ok += w_alias
        print(f"  {'ok  ' if w_alias else 'FAIL'} backend(WASM): integer/pointer anti-alias => {wa}")
    except LoomError as e:
        print(f"  FAIL backend(WASM) anti-alias: {e}")
    try:                                               # string literals must fail closed on the WASM value boundary, explicitly rather than as fake free vars
        pstr = '(defx t (IO) (fn () (print "x;y")))'
        denied = False
        try:
            compile_wasm(pstr)
        except LoomError as e:
            denied = "string literals are not yet supported at the WASM value boundary" in str(e)
        wat_denied = False
        try:
            emit_wat(pstr)
        except LoomError as e:
            wat_denied = "string literals are not yet supported at the WASM value boundary" in str(e)
        w_string_boundary = denied and wat_denied; ok += w_string_boundary
        print(f"  {'ok  ' if w_string_boundary else 'FAIL'} backend(WASM): string literal boundary stays explicit")
    except Exception as e:
        print(f"  FAIL backend(WASM) string boundary: {e}")
    try:                                               # i31 overflow semantics must match on every execution backend
        import shutil as _num_sh
        pnum = '(defx bounds () (fn () (record (add (+ 1073741823 1)) (sub (- -1073741824 1)) (mul (* 1073741823 2)) (wide (* 1073741823 1073741823)))))'
        expected_num = {"add": -1073741824, "sub": 1073741823, "mul": -2, "wide": 1}
        iv, _ = run_call(pnum, "(bounds)"); pv, _ = run_compiled(pnum, "(bounds)")
        numeric_values = [iv, pv]
        if _num_sh.which("node"):
            jv, _ = run_js(pnum, "(bounds)"); wv_num, _ = run_wasm(pnum, "(bounds)")
            numeric_values += [jv, wv_num]
        numeric_ok = all(v == expected_num for v in numeric_values); ok += numeric_ok
        print(f"  {'ok  ' if numeric_ok else 'FAIL'} numeric i31: cross-backend wraparound => {numeric_values}")
    except Exception as e:
        print(f"  FAIL numeric i31: {e}")
    try:                                               # runtime: handled IO is CAPTURED — never reaches output
        v3, out3 = run_call('(defx quiet () (fn (x) (handle (IO) (print x))))', "(quiet 42)")
        run_ok3 = (v3 == 42 and out3 == []); ok += run_ok3
        print(f"  {'ok  ' if run_ok3 else 'FAIL'} runtime (quiet 42) = {v3}, emitted-to-output={out3}")
    except LoomError as e:
        print(f"  FAIL runtime handle: {e}")
    try:                                               # runtime: if + let actually compute
        v4, _ = run_call('(defx mx () (fn (a b) (if (> a b) a b)))', "(mx 3 7)")
        v5, _ = run_call('(defx dbl () (fn (x) (let (y (+ x x)) y)))', "(dbl 5)")
        r45 = (v4 == 7 and v5 == 10); ok += r45
        print(f"  {'ok  ' if r45 else 'FAIL'} runtime (mx 3 7)={v4}  (dbl 5)={v5}")
    except LoomError as e:
        print(f"  FAIL runtime if/let: {e}")
    try:                                               # runtime: recursion actually computes
        v6, _ = run_call('(defx fact () (fn (n) (if (< n 2) 1 (* n (fact (- n 1))))))', "(fact 5)")
        v7, _ = run_call('(defx sumto () (fn (n) (if (< n 1) 0 (+ n (sumto (- n 1))))))', "(sumto 5)")
        r67 = (v6 == 120 and v7 == 15); ok += r67
        print(f"  {'ok  ' if r67 else 'FAIL'} runtime (fact 5)={v6}  (sumto 5)={v7}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime recursion: {e}")
    try:                                               # runtime: ONE higher-order fn, pure vs IO arg
        P = '(defx sq () (fn (x) (* x x))) (defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x)))'
        v8, o8 = run_call(P + ' (defx usep () (fn (x) (ap sq x)))', "(usep 5)")
        v9, o9 = run_call(P + ' (defx good (IO) (fn (x) (ap lg x)))', "(good 7)")
        r89 = (v8 == 25 and o8 == [] and v9 == 7 and o9 == ["7"]); ok += r89
        print(f"  {'ok  ' if r89 else 'FAIL'} runtime HOF: (usep 5)={v8} out={o8} | (good 7)={v9} out={o9}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime HOF: {e}")
    try:                                               # runtime: IO propagates through TWO nested higher-order fns
        P2 = '(defx lg (IO) (fn (x) (print x))) (defx ap (e) (fn ((f e) x) (f x))) (defx ap2 (e) (fn ((f e) x) (ap f x)))'
        v10, o10 = run_call(P2 + ' (defx u4 (IO) (fn (x) (ap2 lg x)))', "(u4 9)")
        r10 = (v10 == 9 and o10 == ["9"]); ok += r10
        print(f"  {'ok  ' if r10 else 'FAIL'} runtime row-poly: (u4 9)={v10} out={o10} (IO thru 2 nested HOFs)")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime row-poly: {e}")
    try:                                               # runtime: inline lambdas + closures actually run
        AP = '(defx ap (e) (fn ((f e) x) (f x)))'
        v11, o11 = run_call(AP + ' (defx u () (fn (x) (ap (fn (y) (* y y)) x)))', "(u 5)")
        v12, _   = run_call('(defx u4 () (fn (x) (let (g (fn (y) (* y y))) (g x))))', "(u4 6)")
        v13, o13 = run_call(AP + ' (defx u3 (IO) (fn (x) (ap (fn (y) (print y)) x)))', "(u3 7)")
        r11 = (v11 == 25 and o11 == [] and v12 == 36 and v13 == 7 and o13 == ["7"]); ok += r11
        print(f"  {'ok  ' if r11 else 'FAIL'} runtime lambdas: (u 5)={v11} | (u4 6)={v12} | (u3 7)={v13} out={o13}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime lambda: {e}")
    try:                                               # runtime: `with` reinterprets the effect's operation
        RW = '(defx realwork (Net) (fn (x) (net x)))'
        v14, o14 = run_call(RW + ' (defx mock () (fn (x) (* x 2))) (defx tested () (fn (x) (with Net mock (realwork x))))', "(tested 5)")
        v15, o15 = run_call(RW + ' (defx lgm (IO) (fn (x) (print x))) (defx traded (IO) (fn (x) (with Net lgm (realwork x))))', "(traded 7)")
        r14 = (v14 == 10 and o14 == [] and v15 == 7 and o15 == ["7"]); ok += r14
        print(f"  {'ok  ' if r14 else 'FAIL'} runtime with: Net mocked->pure (tested 5)={v14} out={o14} | Net->IO (traded 7)={v15} out={o15}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime with: {e}")
    try:                                               # runtime: lists + map/fold DEFINED in loom actually compute
        MAP = '(defx map (e) (fn ((f e) xs) (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs))))))'
        v16, _   = run_call('(defx suml () (fn (xs) (if (empty xs) 0 (+ (head xs) (suml (tail xs))))))', "(suml (list 1 2 3 4))")
        v17, _   = run_call('(defx sq () (fn (x) (* x x))) ' + MAP + ' (defx demo () (fn () (map sq (list 1 2 3))))', "(demo)")
        v18, o18 = run_call('(defx lg (IO) (fn (x) (print x))) ' + MAP + ' (defx dio (IO) (fn () (map lg (list 1 2 3))))', "(dio)")
        r16 = (v16 == 10 and v17 == [1, 4, 9] and o18 == ["1", "2", "3"]); ok += r16
        print(f"  {'ok  ' if r16 else 'FAIL'} runtime lists: (suml 1..4)={v16} | map sq=>{v17} | map lg emits {o18}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime lists: {e}")
    try:                                               # runtime: the SAME opaque foreign call, bounded by its seam's grant
        v19, o19 = run_call('(defx fa (IO) (fn (x) (seam (IO) (ffi "logger" x))))', "(fa 7)")
        v20, o20 = run_call('(defx fb () (fn (x) (seam (Pure) (ffi "logger" x))))', "(fb 7)")
        v21a, o21a = run_call('(defx fv () (fn (x) (trust (seam (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', "(fv 7)")
        v21b, o21b = run_call('(defx fm () (fn (x) (trust (seamN 2 (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', "(fm 7)")
        denied_unknown = False
        try:
            run_call('(defx fu (IO) (fn (x) (seam (IO) (ffi "ghost" x))))', "(fu 7)")
        except LoomError:
            denied_unknown = True
        r19 = (v19 == 7 and o19 == ["foreign:7"] and v20 == 7 and o20 == [] and v21a == 7 and o21a == [] and v21b == 7 and o21b == [] and denied_unknown); ok += r19
        print(f"  {'ok  ' if r19 else 'FAIL'} runtime ffi: logger={o19} | pure={o20} | vouched lib={v21a} | metered lib={v21b}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime ffi: {e}")
    try:                                               # runtime: a linear resource program actually runs
        v21, _ = run_call('(defx r1 () (fn () (resource r (use r))))', "(r1)")
        r21 = (v21 == "<used:r>"); ok += r21
        print(f"  {'ok  ' if r21 else 'FAIL'} runtime linear resource: (r1) = {v21}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime resource: {e}")
    try:                                               # runtime: a resource passed across a call boundary runs
        v22, _ = run_call('(defx u1 () (fn ((lin r)) (use r))) (defx top1 () (fn () (resource res (u1 res))))', "(top1)")
        r22 = (v22 == "<used:r>"); ok += r22
        print(f"  {'ok  ' if r22 else 'FAIL'} runtime linear param: (top1) = {v22}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime linear param: {e}")
    try:                                               # runtime: a typed effectful resource runs (use performs + consumes)
        v23, _ = run_call('(defx tr1 (Net) (fn () (resource (r Net) (use r))))', "(tr1)")
        r23 = (v23 == "<used:r>"); ok += r23
        print(f"  {'ok  ' if r23 else 'FAIL'} runtime typed resource: (tr1) = {v23}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime typed resource: {e}")
    try:                                               # runtime: capability seams narrow ambient authority when they grant less than ambient
        denied = False
        try:
            run_call('(defx bad () (fn (u) (seam (Pure) (handle (Net) (net u)))))', "(bad 5)")
        except LoomError:
            denied = True
        ok += denied
        print(f"  {'ok  ' if denied else 'FAIL'} runtime seam gate: Pure seam blocks Net")
    except Exception as e:
        print(f"  FAIL runtime seam gate: {e}")
    try:                                               # runtime: records build + field access
        v24, _ = run_call('(defx rc1 () (fn () (get (record (a 1) (b 2)) a)))', "(rc1)")
        v25, _ = run_call('(defx rcb () (fn () (get (record (a 10) (b 20)) b)))', "(rcb)")
        r24 = (v24 == 1 and v25 == 20); ok += r24
        print(f"  {'ok  ' if r24 else 'FAIL'} runtime records: (get a)={v24} (get b)={v25}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime records: {e}")
    try:                                               # BACKEND: compiled (Python codegen) must match the interpreter
        MAP = '(defx sq () (fn (x) (* x x))) (defx map (e) (fn ((f e) xs) (if (empty xs) (list) (cons (f (head xs)) (map f (tail xs))))))'
        pairs = [('(defx sq () (fn (x) (* x x)))', "(sq 9)"),
                 ('(defx fact () (fn (n) (if (< n 2) 1 (* n (fact (- n 1))))))', "(fact 6)"),
                 (MAP + ' (defx demo () (fn () (map sq (list 1 2 3 4))))', "(demo)"),
                 ('(defx g () (fn () (get (record (a 10) (b 20)) b)))', "(g)"),
                 ('(defx mk () (fn (x) (variant Ok x))) (defx main () (fn () (match (mk 7) ((Ok v) (+ v 1)) ((Err e) 0))))', "(main)"),  # SUM TYPE: variant+match compiles to BOTH Py and JS, each == interpreter (=> 8)
                 ('(defx t (IO) (fn () (print "x;y")))', "(t)"),                                         # string literal survives codegen quoting; quoted semicolon stays data, not syntax
                 ('(defx t (Net) (fn () (net "u")))', "(t)"),                                            # string literal payload survives effect boxing on portable backends
                 ('(defx f (Net) (fn () (seam (Net) (net 1))))', "(f)"),                       # EFFECT op net -> "<net 1>" on interp/Py/JS
                 ('(defx f (Alloc) (fn () (head (seam (Alloc) (alloc 3)))))', "(f)"),           # EFFECT op alloc -> [0,1,2], head => 0
                 ('(defx fa (IO) (fn (x) (seam (IO) (ffi "logger" x))))', "(fa 5)"),            # FFI codegen: seam GRANTS IO -> foreign emits "foreign:5"; interp==Py==Node
                 ('(defx fb () (fn (x) (seam (Pure) (ffi "logger" x))))', "(fb 5)"),             # FFI codegen FLAGSHIP: seam grants NOTHING -> foreign I/O SANDBOXED to silence on every backend
                 ('(defx fv () (fn (x) (trust (seam (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', "(fv 5)"),  # attested opaque foreign component: accepted statically, pure at runtime, identity payload everywhere
                 ('(defx fm () (fn (x) (trust (seamN 2 (Pure) (vouch auditor alice "lib") (ffi "lib" x)))))', "(fm 5)"),  # metered attested opaque foreign component keeps the same backend/runtime value path
                 ('(defx f (Rand) (fn () (seam (Rand) (rand))))', "(f)"),                       # EFFECT op rand -> "<rand>"
                 ('(defx f () (fn () (handle (IO) (print 5))))', "(f)"),                        # HANDLE discharges IO -> value 5, output SUPPRESSED []
                 ('(defx mock () (fn (u) u)) (defx f () (fn () (with Net mock (net 5))))', "(f)"),  # WITH reinterprets Net via a pure mock -> (net 5) routes to mock => 5, no net
                 ('(defx g (IO) (fn (x) (print x)))', "(g 7)")]   # EFFECTFUL: prints 7, returns 7 (value AND output must match)
        allok = True
        for prog, call in pairs:
            cval, cout = run_compiled(prog, call); ival, iout = run_call(prog, call)
            if (cval, cout) != (ival, iout): allok = False; print(f"  FAIL codegen: {call} compiled=({cval},{cout}) interp=({ival},{iout})")
        ok += allok
        print(f"  {'ok  ' if allok else 'FAIL'} backend: compiled Python == interpreter, value+output ({len(pairs)} programs)")
    except Exception as e:
        print(f"  FAIL backend: {e}")
    try:                                               # SECOND TARGET (JS): Node output must match the interpreter
        import shutil
        for prog, call in pairs:                       # same 4 programs compile to valid JS source
            assert isinstance(compile_js(prog), str) and compile_js(prog)
        if shutil.which("node"):
            jok = True
            for prog, call in pairs:
                jval, jout = run_js(prog, call); ival, iout = run_call(prog, call)
                if (jval, jout) != (ival, iout): jok = False; print(f"  FAIL js: {call} node=({jval},{jout}) interp=({ival},{iout})")
            ok += jok
            print(f"  {'ok  ' if jok else 'FAIL'} backend(JS): Node value+output == interpreter ({len(pairs)} programs)")
        else:
            ok += 1; print("  ok   backend(JS): compile_js emits source (node absent -> exec check skipped)")
    except Exception as e:
        print(f"  FAIL backend(JS): {e}")
    try:                                               # Python/JS generators live behind a stable facade in development builds
        codegen_program = '(defx t () (fn () (record (n (+ 2 3)) (v (variant Ok 7)))))'
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        if is_browser_bundle:
            codegen_boundary_ok = True                 # published Pyodide artifact is intentionally one self-contained file
        else:
            impl = getattr(_loom, "_loom_codegen", None)
            frontend = getattr(_loom, "_CODEGEN_FRONTEND", None)
            codegen_boundary_ok = (
                getattr(impl, "__name__", None) == "loom_codegen"
                and compile_py(codegen_program) == impl.compile_py(codegen_program, frontend)
                and compile_js(codegen_program) == impl.compile_js(codegen_program, frontend)
            )
        ok += codegen_boundary_ok
        print(f"  {'ok  ' if codegen_boundary_ok else 'FAIL'} backend(Python/JS): stable module boundary")
    except Exception as e:
        print(f"  FAIL backend(Python/JS) module boundary: {e}")
    try:                                               # modular backends share one narrow frontend contract without re-coupling to loom.py
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        if is_browser_bundle:
            shared_frontend_ok = True                  # published Pyodide artifact is intentionally one self-contained file
        else:
            import loom_frontend as _loom_frontend
            shared_frontend_ok = (
                isinstance(getattr(_loom, "_CODEGEN_FRONTEND", None), _loom_frontend.CodegenFrontend)
                and isinstance(getattr(_loom, "_WASM_FRONTEND", None), _loom_frontend.WasmFrontend)
                and getattr(getattr(_loom, "_loom_codegen", None), "Frontend").__mro__[1] is _loom_frontend.CodegenFrontend
                and getattr(getattr(_loom, "_loom_wasm", None), "Frontend").__mro__[1] is _loom_frontend.WasmFrontend
            )
        ok += shared_frontend_ok
        print(f"  {'ok  ' if shared_frontend_ok else 'FAIL'} backend(frontend): shared backend contract")
    except Exception as e:
        print(f"  FAIL backend(frontend) contract: {e}")
    try:                                               # THIRD TARGET (WASM): real wasm bytes via node's WebAssembly == interpreter (integer core)
        import shutil as _sh
        wpairs = [('(defx main () (fn () (+ 2 (* 3 4))))', "(main)"),                                   # arithmetic -> 14
                  ('(defx mx () (fn (a b) (if (> a b) a b)))', "(mx 3 7)"),                              # comparison + if -> 7
                  ('(defx fib () (fn (n) (if (< n 2) n (+ (fib (- n 1)) (fib (- n 2))))))', "(fib 10)"),  # recursion -> 55
                  ('(defx fac () (fn (n) (if (< n 1) 1 (* n (fac (- n 1))))))', "(fac 6)"),               # recursion -> 720
                  ('(defx sq () (fn (x) (let (y (* x x)) (+ y y)))) (defx main () (fn () (sq 5)))', "(main)"),  # VALUE RUNTIME: let/local -> 50
                  ('(defx sm () (fn (xs) (if (empty xs) 0 (+ (head xs) (sm (tail xs)))))) (defx main () (fn () (sm (list 1 2 3 4 5))))', "(main)"),  # integer LIST sum in linear memory -> 15
                  ('(defx ln () (fn (xs) (if (empty xs) 0 (+ 1 (ln (tail xs)))))) (defx main () (fn () (ln (list 7 8 9))))', "(main)"),  # integer LIST length -> 3
                  ('(defx mk () (fn (x) (variant Ok x))) (defx un () (fn (r) (match r ((Ok v) (+ v 1)) ((Err e) 0)))) (defx main () (fn () (un (mk 7))))', "(main)"),  # SUM TYPE: variant + match -> 8
                  ('(defx main () (fn () (match (variant Some 5) ((Some x) x) ((None) 0))))', "(main)"),  # match picks the Some arm + binds the payload -> 5
                  ('(defx rg () (fn () (get (record (a 10) (b 20)) b)))', "(rg)"),                      # record build + get -> 20
                  ('(defx t () (fn () (trust 1 (by reviewer ada (declassify reviewer (prov ai (recall (repro 9))))))))', "(t)")]  # transparent trust/provenance/persistence wrappers -> 9
        for prog, call in wpairs:                       # every program emits a valid wasm module (magic header)
            assert compile_wasm(prog)[:4] == b"\x00asm"
        assert _WASM_ABI_VERSION == 1 and b"loom_abi_version" in compile_wasm(wpairs[0][0])  # ABI v1 is machine-readable
        assert emit_wat(wpairs[2][0]).startswith("(module") and "i32.lt_s" in emit_wat(wpairs[2][0])   # WAT 'assembler' is emitted
        assert '(export "loom_abi_version"' in emit_wat(wpairs[0][0])  # WAT mirrors the binary ABI version export
        assert "call $cons" in emit_wat(wpairs[5][0])   # the list value-runtime ($cons heap) shows up in the WAT too
        assert "call $rec" in emit_wat(wpairs[9][0]) and "call $get" in emit_wat(wpairs[9][0])   # record helpers show up in the WAT too
        assert "tag Some" in emit_wat(wpairs[8][0]) and "call $variant" in emit_wat(wpairs[8][0])  # explicit variant helper in WAT
        wat_io = emit_wat('(defx t (IO) (fn () (print 7)))')
        wat_ffi = emit_wat('(defx t (IO) (fn (x) (seam (IO) (ffi "logger" x))))')
        wat_lib_ffi = emit_wat('(defx t () (fn (x) (seam (Pure) (ffi "lib" x))))')
        wat_with = emit_wat('(defx h () (fn (x) (* x 2))) (defx t () (fn () (with IO h (print 5))))')
        wat_with_local = emit_wat('(defx t () (fn () (let (h (fn (x) (* x 2))) (with IO h (print 5)))))')
        wat_closure = emit_wat('(defx ap (e) (fn ((f e) x) (f x))) (defx u () (fn (x) (ap (fn (y) (* y y)) x)))')
        wat_apply2 = emit_wat('(defx t () (fn () (let (f (fn (a b) (+ a b))) (f 3 4))))')
        wat_capture9 = emit_wat(CAPTURE9_PROGRAM)
        wat_trust_stack = emit_wat(wpairs[10][0])
        wat_topdef_value = emit_wat('(defx inc () (fn (x) (+ x 1))) (defx ap () (fn ((f) x) (f x))) (defx t () (fn () (ap inc 4)))')
        assert 'import "env" "host_print"' in wat_io and "call $host_print" in wat_io   # WAT mirrors host-print import for IO
        assert 'import "env" "host_ffi"' in wat_ffi and "call $host_ffi" in wat_ffi   # WAT mirrors the foreign boundary import too
        assert 'call $host_ffi' in wat_lib_ffi and 'foreign lib' in wat_lib_ffi   # opaque lib component lowers through the same WASM foreign boundary
        assert "call $apply1" in wat_with and "func $h" in wat_with   # WAT mirrors top-level with IO handler dispatch via closure apply
        assert "call $apply1" in wat_with_local and "func $lam0" in wat_with_local   # WAT mirrors local closure-valued handler dispatch
        assert "call $apply1" in wat_closure and "func $lam0" in wat_closure   # WAT mirrors closure literals + dispatcher
        assert "call $apply2" in wat_apply2 and "func $lam0" in wat_apply2   # WAT mirrors 2-arg closure application
        assert "func $lam0" in wat_capture9 and "call $apply1" in wat_capture9   # WAT mirrors closures with >8 captured values
        assert wat_trust_stack.startswith("(module") and "i32.const 18" in wat_trust_stack   # transparent trust/prov wrappers compile through WAT too
        assert "local.get $inc" not in wat_topdef_value and "call $rec" in wat_topdef_value   # WAT mirrors top-level function values as closure records, not fake locals
        if _sh.which("node"):
            wok = True
            for prog, call in wpairs:
                wval, _ = run_wasm(prog, call); ival, _ = run_call(prog, call)
                if wval != ival: wok = False; print(f"  FAIL wasm: {call} wasm={wval} interp={ival}")
            ok += wok
            print(f"  {'ok  ' if wok else 'FAIL'} backend(WASM): node WebAssembly value == interpreter ({len(wpairs)} programs)")
        else:
            ok += 1; print("  ok   backend(WASM): compile_wasm emits a valid module (node absent -> exec check skipped)")
    except Exception as e:
        print(f"  FAIL backend(WASM): {e}")
    try:                                               # compiler contexts must not leak closure/layout state across invocations
        from concurrent.futures import ThreadPoolExecutor
        context_programs = [
            '(defx a () (fn () (let (f (fn (x) (+ x 1))) (f 9))))',
            '(defx b () (fn () (record (alpha (variant Left 3)) (beta (list 4 5)))))',
        ]
        expected = [(compile_wasm(p), emit_wat(p)) for p in context_programs]
        def compile_isolated(i):
            p = context_programs[i % len(context_programs)]
            return i % len(context_programs), compile_wasm(p), emit_wat(p)
        with ThreadPoolExecutor(max_workers=4) as pool:
            isolated = list(pool.map(compile_isolated, range(32)))
        legacy = ("_WASM_TOPDEFS", "_WASM_CLOSURES", "_WASM_CLOSURE_BY_ID",
                  "_WASM_APPLY_IDS", "_WASM_APPLY1_ID", "_WASM_ALLOC_ID", "_WASM_VARIANT_ID")
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        boundary_ok = is_browser_bundle or getattr(_loom, "_loom_wasm", None).__name__ == "loom_wasm"
        context_ok = (boundary_ok and not any(hasattr(_loom, name) for name in legacy) and
                      all((wasm, wat) == expected[i] for i, wasm, wat in isolated))
        ok += context_ok
        print(f"  {'ok  ' if context_ok else 'FAIL'} backend(WASM): module boundary + isolated contexts (32 parallel builds)")
    except Exception as e:
        print(f"  FAIL backend(WASM) context isolation: {e}")
    try:                                               # closure frontier: multi-arg lambda capture + application survives wasm
        prog = '(defx t () (fn () (let (f (fn (a b) (+ a b))) (f 3 4))))'
        wv, _ = run_wasm(prog, "(t)")
        rv, _ = run_call(prog, "(t)")
        r_wasm_closure = (wv == 7 and rv == 7)
        ok += r_wasm_closure
        print(f"  {'ok  ' if r_wasm_closure else 'FAIL'} backend(WASM): closures capture + apply2 => {wv} / {rv}")
    except Exception as e:
        print(f"  FAIL backend(WASM) closures: {e}")
    try:                                               # closure frontier: capture count no longer capped at 8
        prog = CAPTURE9_PROGRAM
        wv, _ = run_wasm(prog, "(t)")
        rv, _ = run_call(prog, "(t)")
        r_capture9 = (wv == 55 and rv == 55)
        ok += r_capture9
        print(f"  {'ok  ' if r_capture9 else 'FAIL'} backend(WASM): closures capture 9 values => {wv} / {rv}")
    except Exception as e:
        print(f"  FAIL backend(WASM) capture9: {e}")
    try:                                               # effect frontier: IO print import + handle(IO) discharge survive wasm
        p1 = '(defx t (IO) (fn () (print 7)))'
        p2 = '(defx t () (fn () (handle (IO) (print 5))))'
        v31, o31 = run_wasm(p1, "(t)")
        v32, o32 = run_wasm(p2, "(t)")
        r31 = (v31 == 7 and o31 == ["7"] and v32 == 5 and o32 == [])
        ok += r31
        print(f"  {'ok  ' if r31 else 'FAIL'} backend(WASM): IO print + handle => ({v31}, {o31}) / ({v32}, {o32})")
    except Exception as e:
        print(f"  FAIL backend(WASM) effects: {e}")
    try:                                               # transparent wrappers must preserve sequencing around handled effects in wasm too
        prog = '(defx t () (fn () (handle (IO) (trust (prov human (print 5) 7)))))'
        wv, wo = run_wasm(prog, "(t)")
        rv, ro = run_call(prog, "(t)")
        r_trust_seq = ((wv, wo) == (rv, ro) == (7, []))
        ok += r_trust_seq
        print(f"  {'ok  ' if r_trust_seq else 'FAIL'} backend(WASM): transparent trust/prov sequencing => ({wv}, {wo}) / ({rv}, {ro})")
    except Exception as e:
        print(f"  FAIL backend(WASM) transparent wrappers: {e}")
    try:                                               # effect frontier: IO `with` reinterprets print through a handler closure
        prog = '(defx h () (fn (x) (* x 2))) (defx t () (fn () (with IO h (print 5))))'
        v33, o33 = run_wasm(prog, "(t)")
        rv33, ro33 = run_call(prog, "(t)")
        r33 = (v33 == 10 and o33 == [] and rv33 == 10 and ro33 == [])
        ok += r33
        print(f"  {'ok  ' if r33 else 'FAIL'} backend(WASM): IO with handler => ({v33}, {o33}) / ({rv33}, {ro33})")
    except Exception as e:
        print(f"  FAIL backend(WASM) with: {e}")
    try:                                               # runtime frontier: boxed Rand survives a non-IO handle in WASM/WAT
        p_box = '(defx t () (fn () (handle (Rand) (rand))))'
        v31, o31 = run_wasm(p_box, "(t)")
        rv31, ro31 = run_call(p_box, "(t)")
        r31 = (v31 == ("Rand", 0) and o31 == [] and rv31 == ("Rand", 0) and ro31 == [])
        ok += r31
        print(f"  {'ok  ' if r31 else 'FAIL'} backend(WASM): Rand handle boxes to {v31}")
    except Exception as e:
        print(f"  FAIL backend(WASM) handle-box: {e}")
    try:                                               # runtime frontier: Rand with-handler reinterprets to a pure result
        p_with = '(defx mk () (fn () 4)) (defx t () (fn () (with Rand mk (rand))))'
        v32, o32 = run_wasm(p_with, "(t)")
        rv32, ro32 = run_call(p_with, "(t)")
        r32 = (v32 == 4 and o32 == [] and rv32 == 4 and ro32 == [])
        ok += r32
        print(f"  {'ok  ' if r32 else 'FAIL'} backend(WASM): Rand with reinterprets to {v32}")
    except Exception as e:
        print(f"  FAIL backend(WASM) with-box: {e}")
    try:                                               # runtime frontier: Net with-handler now runs on WASM too
        p_net = '(defx realwork (Net) (fn (x) (net x))) (defx mock () (fn (x) (* x 2))) (defx tested () (fn (x) (with Net mock (realwork x))))'
        v33, o33 = run_wasm(p_net, "(tested 5)")
        rv33, ro33 = run_call(p_net, "(tested 5)")
        r33 = (v33 == 10 and o33 == [] and rv33 == 10 and ro33 == [])
        ok += r33
        print(f"  {'ok  ' if r33 else 'FAIL'} backend(WASM): Net with handler => {v33}")
    except Exception as e:
        print(f"  FAIL backend(WASM) net-with: {e}")
    try:                                               # runtime frontier: capability seams survive lowering in WASM
        p_seam = '(defx f (Net) (fn (u) (seam (Net) (net u))))'
        v34, o34 = run_wasm(p_seam, "(f 5)")
        rv34, ro34 = run_call(p_seam, "(f 5)")
        r34 = (v34 == ("Net", 5) and o34 == [] and rv34 == ("Net", 5) and ro34 == [])
        ok += r34
        print(f"  {'ok  ' if r34 else 'FAIL'} backend(WASM): seam-granted Net => {v34}")
    except Exception as e:
        print(f"  FAIL backend(WASM) seam: {e}")
    try:                                               # runtime frontier: resource/use keeps the interpreter-visible marker in WASM
        p_res = '(defx r1 () (fn () (resource r (use r)))) (defx tr1 (Net) (fn () (resource (r Net) (use r))))'
        v35, o35 = run_wasm(p_res, "(r1)")
        v36, o36 = run_wasm(p_res, "(tr1)")
        rv35, ro35 = run_call(p_res, "(r1)")
        rv36, ro36 = run_call(p_res, "(tr1)")
        r35 = (v35 == "<used:r>" and o35 == [] and v36 == "<used:r>" and o36 == [] and rv35 == "<used:r>" and ro35 == [] and rv36 == "<used:r>" and ro36 == [])
        ok += r35
        print(f"  {'ok  ' if r35 else 'FAIL'} backend(WASM): resource/use marker => {v35} / {v36}")
    except Exception as e:
        print(f"  FAIL backend(WASM) resource: {e}")
    try:                                               # runtime frontier: a Pure seam cannot wield Net on WASM either
        denied = False
        try:
            run_wasm('(defx bad () (fn (u) (seam (Pure) (handle (Net) (net u)))))', "(bad 5)")
        except LoomError:
            denied = True
        ok += denied
        print(f"  {'ok  ' if denied else 'FAIL'} backend(WASM): Pure seam blocks Net")
    except Exception as e:
        print(f"  FAIL backend(WASM) seam gate: {e}")
    try:                                               # runtime frontier: ffi parity now reaches WASM too, including handled-IO silence
        p_io = '(defx fa (IO) (fn (x) (seam (IO) (ffi "logger" x))))'
        p_pure = '(defx fb () (fn (x) (seam (Pure) (ffi "logger" x))))'
        p_handled = '(defx fh () (fn (x) (handle (IO) (seam (IO) (ffi "logger" x)))))'
        p_lib = '(defx fv () (fn (x) (seam (Pure) (ffi "lib" x))))'
        p_metered_lib = '(defx fm () (fn (x) (seamN 2 (Pure) (ffi "lib" x))))'
        w37, o37 = run_wasm(p_io, "(fa 7)")
        w38, o38 = run_wasm(p_pure, "(fb 7)")
        w39, o39 = run_wasm(p_handled, "(fh 7)")
        w40, o40 = run_wasm(p_lib, "(fv 7)")
        w41, o41 = run_wasm(p_metered_lib, "(fm 7)")
        r37, i37 = run_call(p_io, "(fa 7)")
        r38, i38 = run_call(p_pure, "(fb 7)")
        r39, i39 = run_call(p_handled, "(fh 7)")
        r40, i40 = run_call(p_lib, "(fv 7)")
        r41, i41 = run_call(p_metered_lib, "(fm 7)")
        denied_unknown = False
        try:
            run_wasm('(defx fu (IO) (fn (x) (seam (IO) (ffi "ghost" x))))', "(fu 7)")
        except LoomError:
            denied_unknown = True
        ffi_wasm_ok = ((w37, o37) == (r37, i37) and (w38, o38) == (r38, i38) and (w39, o39) == (r39, i39)
                       and (w40, o40) == (r40, i40) and (w41, o41) == (r41, i41) and denied_unknown)
        ok += ffi_wasm_ok
        print(f"  {'ok  ' if ffi_wasm_ok else 'FAIL'} backend(WASM): ffi logger/lib parity => ({w37}, {o37}) / ({w38}, {o38}) / handled {o39} / lib {w40} / metered-lib {w41}")
    except Exception as e:
        print(f"  FAIL backend(WASM) ffi: {e}")
    try:                                               # runtime: variant + match extracts the payload / picks the arm
        v26, _ = run_call('(defx m1 () (fn () (match (variant Some 5) ((Some x) x) ((None) 0))))', "(m1)")
        v27, _ = run_call('(defx m2 () (fn () (match (variant None 0) ((Some x) x) ((None) 7))))', "(m2)")
        r26 = (v26 == 5 and v27 == 7); ok += r26
        print(f"  {'ok  ' if r26 else 'FAIL'} runtime match: (Some 5)={v26} (None)={v27}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime match: {e}")
    try:                                               # FLAGSHIP: it runs to 42 AND the untrusted step emits nothing (sandboxed)
        FLAG = '(defx untrusted () (fn (x) (seam (Pure) (ffi "logger" x)))) (defx process () (fn (item) (resource conn (let (r (use conn)) (variant Ok (untrusted item)))))) (defx main () (fn () (match (process 42) ((Ok v) v) ((Err e) 0))))'
        v28, o28 = run_call(FLAG, "(main)")
        r28 = (v28 == 42 and o28 == []); ok += r28   # empty output => the untrusted ffi was physically sandboxed
        print(f"  {'ok  ' if r28 else 'FAIL'} flagship: (main)={v28}, untrusted output={o28} (sandboxed)")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL flagship: {e}")
    try:                                               # runtime: prov/trust are TRANSPARENT — the trust gate is a STATIC check
        v29, _ = run_call('(defx t1 () (fn () (trust (prov human 5))))', "(t1)")
        v30, _ = run_call('(defx t2 () (fn () (prov ai 7)))', "(t2)")
        r29 = (v29 == 5 and v30 == 7); ok += r29
        print(f"  {'ok  ' if r29 else 'FAIL'} runtime prov/trust: (trust (prov human 5))={v29} | (prov ai 7)={v30}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime prov/trust: {e}")
    try:                                               # runtime: Rand op runs; `with` reinterprets nondeterminism to a pure mock
        vr1, _ = run_call('(defx rr (Rand) (fn () (rand)))', "(rr)")
        vr2, _ = run_call('(defx rr (Rand) (fn () (rand))) (defx mk () (fn () 4)) (defx t () (fn () (with Rand mk (rr))))', "(t)")
        rr1 = (vr1 == ("Rand", 0) and vr2 == 4); ok += rr1
        print(f"  {'ok  ' if rr1 else 'FAIL'} runtime Rand: (rr)={vr1} | with-mock (t)={vr2}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime Rand: {e}")
    try:                                               # runtime: D10 `by` / role-trust are TRANSPARENT — the gate is static
        vd1, _ = run_call('(defx t () (fn () (trust (roles code proof) (by code human (by proof trace 9)))))', "(t)")
        vd2, _ = run_call('(defx t () (fn () (by code human 7)))', "(t)")
        rd1 = (vd1 == 9 and vd2 == 7); ok += rd1
        print(f"  {'ok  ' if rd1 else 'FAIL'} runtime D10 roles: (trust (code proof) ..)={vd1} | (by code human 7)={vd2}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D10 roles: {e}")
    try:                                               # runtime: D11 (sub ..) clause is TRANSPARENT — subsumption is a static check
        ve1, _ = run_call('(defx t () (fn () (trust (roles code reviewer) (sub reviewer auditor) (by code human (by auditor alice 5)))))', "(t)")
        re1 = (ve1 == 5); ok += re1
        print(f"  {'ok  ' if re1 else 'FAIL'} runtime D11 lattice: (trust (roles ..) (sub ..) ..)={ve1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D11 lattice: {e}")
    try:                                               # runtime: D12 (roles ..) on a seam is TRANSPARENT — the grant gate is static
        vg1, _ = run_call('(defx t () (fn () (seam (Pure) (roles code review) (by code human (by review alice 7)))))', "(t)")
        rg1 = (vg1 == 7); ok += rg1
        print(f"  {'ok  ' if rg1 else 'FAIL'} runtime D12 gated seam: (seam (Pure) (roles ..) ..)={vg1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D12 gated seam: {e}")
    try:                                               # runtime: D13 (needs ..) is TRANSPARENT — per-effect binding is a static check
        vn1, _ = run_call('(defx t (Net) (fn () (seam (Net) (needs Net review) (by review alice (net "u")))))', "(t)")
        rn1 = (vn1 == ("Net", "u")); ok += rn1
        print(f"  {'ok  ' if rn1 else 'FAIL'} runtime D13 needs: (seam (Net) (needs Net review) ..)={vn1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D13 needs: {e}")
    try:                                               # runtime: a ';' inside a string SURVIVES; a commented program still runs
        vc1, _ = run_call('(defx t (IO) (fn () (print "x;y")))', "(t)")
        vc2, _ = run_call('(defx t () (fn () 42)) ; a comment with (parens) and ; semicolons\n', "(t)")
        rc1 = (vc1 == "x;y" and vc2 == 42); ok += rc1
        print(f"  {'ok  ' if rc1 else 'FAIL'} runtime D14 comments: string ';' kept={vc1} | commented run={vc2}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D14 comments: {e}")
    try:                                               # runtime: D15 policy forms are STATIC — inert at runtime, program runs normally
        vp1, _ = run_call('(rank reviewer auditor) (require Net review) (defx t () (fn () 42))', "(t)")
        rp1 = (vp1 == 42); ok += rp1
        print(f"  {'ok  ' if rp1 else 'FAIL'} runtime D15 policy: program with (rank)/(require) runs => {vp1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D15 policy: {e}")
    try:                                               # runtime: (forbid ..) is STATIC — a program that respects it runs normally
        vf1, _ = run_call('(forbid FFI) (defx t () (fn () 7))', "(t)")
        rf1 = (vf1 == 7); ok += rf1
        print(f"  {'ok  ' if rf1 else 'FAIL'} runtime D16 forbid: program with (forbid FFI) runs => {vf1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D16 forbid: {e}")
    try:                                               # runtime: D17 (require EFF N) is STATIC — a grant that meets it runs
        vq1, _ = run_call('(require Net 2) (defx t (Net) (fn () (seam (Net) (by a x (by b y (net "z"))))))', "(t)")
        rq1 = (vq1 == ("Net", "z")); ok += rq1
        print(f"  {'ok  ' if rq1 else 'FAIL'} runtime D17 require-N: grant with 2 authors runs => {vq1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D17 require-N: {e}")
    try:                                               # runtime: D18 taint is STATIC — let/prov are transparent, value flows out
        vt1, _ = run_call('(defx t () (fn () (trust (let (y (prov human 5)) y))))', "(t)")
        rt1 = (vt1 == 5); ok += rt1
        print(f"  {'ok  ' if rt1 else 'FAIL'} runtime D18 taint: (trust (let (y (prov human 5)) y)) => {vt1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D18 taint: {e}")
    try:                                               # runtime: D19 cross-statement taint is STATIC — let/prov transparent at runtime
        vx1, _ = run_call('(defx t () (fn () (let (y (prov human 9)) (trust y))))', "(t)")
        rx1 = (vx1 == 9); ok += rx1
        print(f"  {'ok  ' if rx1 else 'FAIL'} runtime D19 cross-stmt: (let (y (prov human 9)) (trust y)) => {vx1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D19 cross-stmt: {e}")
    try:                                               # runtime: D20 confine/author are STATIC — inert at runtime
        vy1, _ = run_call('(confine Net trusted) (author t trusted dev) (defx t () (fn () 42))', "(t)")
        ry1 = (vy1 == 42); ok += ry1
        print(f"  {'ok  ' if ry1 else 'FAIL'} runtime D20 confine: program with (confine)/(author) runs => {vy1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D20 confine: {e}")
    try:                                               # runtime: D21 declassify is STATIC — value/provenance-transparent at runtime
        vz1, _ = run_call('(defx t () (fn () (declassify human 42)))', "(t)")
        rz1 = (vz1 == 42); ok += rz1
        print(f"  {'ok  ' if rz1 else 'FAIL'} runtime D21 declassify: (declassify human 42) => {vz1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D21 declassify: {e}")
    try:                                               # runtime: D24 recall is value/taint-transparent at runtime
        vr1, _ = run_call('(defx t () (fn () (recall 42)))', "(t)")
        rr1 = (vr1 == 42); ok += rr1
        print(f"  {'ok  ' if rr1 else 'FAIL'} runtime D24 recall: (recall 42) => {vr1}")
    except (LoomError, RecursionError) as e:
        print(f"  FAIL runtime D24 recall: {e}")
    try:                                               # CLI: audit should surface clean code and fail closed on a lie
        with tempfile.TemporaryDirectory() as td:
            clean = Path(td) / "clean.loom"
            liar = Path(td) / "liar.loom"
            clean.write_text('(defx pure () (fn (x) (* x x)))\n')
            liar.write_text('(defx sneaky () (fn (x) (print x)))\n')
            loom = Path(__file__).with_name("loom.py")
            a1 = subprocess.run([sys.executable, str(loom), "audit", str(clean)], capture_output=True, text=True)
            a2 = subprocess.run([sys.executable, str(loom), "audit", str(liar)], capture_output=True, text=True)
            r30 = (a1.returncode == 0 and "LOOM AUDIT" in a1.stdout and "[clean ] pure" in a1.stdout and
                   a2.returncode == 1 and "FINDINGS" in a2.stdout and "sneaky" in a2.stdout)
            ok += r30
            print(f"  {'ok  ' if r30 else 'FAIL'} cli audit: clean surfaces clean, liar returns findings")
    except Exception as e:
        print(f"  FAIL cli audit: {e}")
    try:                                               # CLI: check should summarize scoped findings, not dump a flat list
        with tempfile.TemporaryDirectory() as td:
            liar = Path(td) / "liar.loom"
            liar.write_text('(defx sneaky () (fn (x) (print x)))\n')
            loom = Path(__file__).with_name("loom.py")
            c1 = subprocess.run([sys.executable, str(loom), "check", str(liar)], capture_output=True, text=True)
            r31 = (c1.returncode == 1
                   and "REJECTED — 1 finding(s) across 1 scope(s)" in c1.stdout
                   and "[sneaky] 1 finding(s)" in c1.stdout)
            ok += r31
            print(f"  {'ok  ' if r31 else 'FAIL'} cli check: scoped rejection summary")
    except Exception as e:
        print(f"  FAIL cli check summary: {e}")
    try:                                               # CLI lives behind a stable facade in development builds
        import io, contextlib
        is_browser_bundle = Path(_loom.__file__).parent.name == "docs"
        if is_browser_bundle:
            cli_boundary_ok = True                     # published Pyodide artifact is intentionally one self-contained file
        else:
            impl = getattr(_loom, "_loom_cli", None)
            frontend = getattr(_loom, "_CLI_FRONTEND", None)
            with tempfile.TemporaryDirectory() as td:
                sample = Path(td) / "sample.loom"
                sample.write_text('(defx pure () (fn (x) (* x x)))\n')
                left = io.StringIO()
                right = io.StringIO()
                with contextlib.redirect_stdout(left):
                    left_code = _loom._cli(["check", str(sample)])
                with contextlib.redirect_stdout(right):
                    right_code = impl.cli(["check", str(sample)], frontend)
            cli_boundary_ok = (
                getattr(impl, "__name__", None) == "loom_cli"
                and left_code == right_code == 0
                and left.getvalue() == right.getvalue()
            )
        ok += cli_boundary_ok
        print(f"  {'ok  ' if cli_boundary_ok else 'FAIL'} cli: stable module facade")
    except Exception as e:
        print(f"  FAIL cli module facade: {e}")
    try:                                               # published browser bundle discipline is explicit, not tribal knowledge
        play = Path(__file__).with_name("docs").joinpath("play.html").read_text()
        workflow = Path(__file__).with_name("docs").joinpath("published_bundle_workflow.md").read_text()
        docs_discipline_ok = (
            'fetch("./loom.py")' in play
            and 'id="bWasm"' in play
            and "loom.compile_wasm(" in play
            and "WebAssembly.instantiate(" in play
            and '"findingsByFn"' in play
            and '"globalFindings"' in play
            and all(name not in play for name in (
                "loom_parse.py",
                "loom_checker.py",
                "loom_runtime.py",
                "loom_codegen.py",
                "loom_wasm.py",
                "loom_cli.py",
            ))
            and "verify_docs_parity.py" in workflow
            and "docs/loom.py" in workflow
            and Path(__file__).with_name("verify_docs_parity.py").exists()
        )
        ok += docs_discipline_ok
        print(f"  {'ok  ' if docs_discipline_ok else 'FAIL'} docs: published bundle workflow pinned")
    except Exception as e:
        print(f"  FAIL docs workflow pin: {e}")
    try:                                               # deterministic property fuzz is part of the citadel, not an optional side script
        fuzz = Path(__file__).with_name("fuzz_tests.py")
        fr = subprocess.run([sys.executable, str(fuzz), "--cases", "64", "--seed", "0xC17ADE1"], capture_output=True, text=True)
        fuzz_ok = (fr.returncode == 0 and "PASS property fuzz" in fr.stdout); ok += fuzz_ok
        print(f"  {'ok  ' if fuzz_ok else 'FAIL'} property fuzz: parser/checker/interpreter/Python/JS/WASM")
        if not fuzz_ok: print("       " + (fr.stdout.strip() or fr.stderr.strip())[:500])
    except Exception as e:
        print(f"  FAIL property fuzz: {e}")
    total = len(CASES) + 66   # runtime/backend smokes, including parser/checker/runtime/backend isolation, seamN diagnostics, cli proof-surface, string-literal backend guards, runtime/cli facades, docs workflow pin, shared backend contracts, deterministic property fuzz, and the WASM seam/resource frontier
    passed = (ok == total)
    print(f"{'PASS' if passed else 'FAIL'} — {ok}/{total} citadel checks")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
