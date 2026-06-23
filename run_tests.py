#!/usr/bin/env python3
# ARGUS/plt CITADEL test suite — the growing, self-verifying proof that LOOM's design holds.
# The organism appends new CASES here every cycle; the language only grows if ALL stay green.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from loom import parse, check, run_call, LoomError

# (name, source, should_be_accepted)
CASES = [
    ("pure square",          "(defx square () (fn (x) (* x x)))", True),
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
]


def main():
    ok = 0
    for name, src, accept in CASES:
        _, errs = check(parse(src))
        got = (len(errs) == 0)
        good = (got == accept); ok += good
        why = f"  [{errs[0]}]" if errs else ""
        print(f"  {'ok  ' if good else 'FAIL'} {name:22} expect={'accept' if accept else 'reject':6} got={'accept' if got else 'reject'}{why}")
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
        r19 = (v19 == 7 and o19 == ["foreign:7"] and v20 == 7 and o20 == []); ok += r19
        print(f"  {'ok  ' if r19 else 'FAIL'} runtime ffi: IO-granted emits {o19} | sandboxed-to-pure emits {o20}")
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
    total = len(CASES) + 13
    print(f"{'PASS' if ok == total else 'FAIL'} — {ok}/{total} citadel checks")


main()
