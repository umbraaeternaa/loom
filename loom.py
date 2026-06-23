#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
import re

EFFECTS = {"Pure", "IO", "Net", "Alloc", "FFI"}
# checker vocab MUST stay == interpreter (ev) vocab — no form the checker knows that the runtime can't run.
BUILTIN_EFF = {"print": {"IO"}, "net": {"Net"}, "alloc": {"Alloc"}}
PURE_OPS = {"+", "-", "*", "=", "<", ">",          # pure ops the interpreter runs; legitimate heads, zero effect
            "list", "cons", "head", "tail", "empty"}  # pure list primitives (map/fold are then DEFINABLE in LOOM)
OP = {"IO": "print", "Net": "net", "Alloc": "alloc"}   # which builtin operation a `with`-handler reinterprets
_CAPS = []                                              # runtime capability stack: each seam pushes the authority it grants
def _cap_ok(eff): return (not _CAPS) or (eff in _CAPS[-1])  # top-level host is unrestricted; a seam SANDBOXES its body
def _foreign_logger(args, out):                        # opaque foreign code that WANTS IO; emits ONLY if IO was granted
    if _cap_ok("IO"): out.append("foreign:" + str(args[0]))
    return args[0]
FOREIGN = {"logger": _foreign_logger}                  # registry of effect-opaque foreign functions reached via (ffi ..)


def plin(p): return p[1] if (isinstance(p, list) and len(p) >= 2 and p[0] == "lin") else None   # (lin r) = LINEAR param
def pname(p):                                                    # a param is `name` (value) · `(name eff..)` (fn) · `(lin r)` (linear)
    if isinstance(p, list): return p[1] if p and p[0] == "lin" else p[0]
    return p
def platent(p):                                                 # fn-param's latent effects; None for value / linear params
    if isinstance(p, list) and p and p[0] == "lin": return None
    return set(p[1:]) if isinstance(p, list) else None
def is_var(e): return isinstance(e, str) and e not in EFFECTS and e[:1].islower()  # lowercase token = effect variable
def is_fn_expr(e, fns, penv):                                    # does this expression denote a function?
    return (isinstance(e, list) and len(e) > 0 and e[0] == "fn") or (isinstance(e, str) and (e in fns or e in penv))


def tokenize(s): return re.findall(r'"[^"]*"|[()]|[^\s()]+', s)


def _read(t):
    x = t.pop(0)
    if x == "(":
        l = []
        while t[0] != ")": l.append(_read(t))
        t.pop(0); return l
    if x.startswith('"'): return x[1:-1]
    try: return int(x)
    except ValueError: return x


def parse(s):
    t = tokenize(s); out = []
    while t: out.append(_read(t))
    return out


class LoomError(Exception): pass


class Closure:                                          # an inline lambda evaluated as a VALUE — captures its env
    __slots__ = ("params", "body", "env")
    def __init__(self, params, body, env): self.params, self.body, self.env = params, body, env


def latent_of(arg, fns, penv, errs):
    """Latent effect-set of a function passed as a value: a named fn, a passed-through fn param, or an inline lambda."""
    if isinstance(arg, str):
        if arg in fns: return fns[arg]["eff"]
        if arg in penv: return penv[arg]
        return set()                                    # not a function value -> contributes no latent effect
    if isinstance(arg, list) and arg and arg[0] == "fn":   # inline lambda -> latent = the effect of its body
        lpenv = {**penv, **{pname(p): platent(p) for p in arg[1] if platent(p) is not None}}
        e = set()
        for b in arg[2:]: e |= infer(b, fns, errs, lpenv)
        return e
    return set()


# use-count lattice for AFFINE (use-once) seams: 0 (unused) < 1 (once) < "M" (many). add saturates; lub picks the higher.
def _uadd(a, b): return b if a == 0 else a if b == 0 else "M"          # 1+1, 1+M, M+x -> M (>=2 uses = many)
def _ulub(a, b): o = {0: 0, 1: 1, "M": 2}; return a if o[a] >= o[b] else b   # for if-branches: only one runs
_OPEFF = {op: E for E, op in OP.items()}                              # reverse of OP: net->Net, print->IO, alloc->Alloc


def _ucount(node, fns, penv):
    """Abstract use-count {effect: 0/1/'M'} performed along ONE path — threaded through the fixpoint via fns[h]['uc'],
    so reuse via a CALLEE or RECURSION (not just a direct op) reaches 'many'. The basis of sound move-only tracking."""
    out = {}
    def add(dd):
        for e, c in dd.items(): out[e] = _uadd(out.get(e, 0), c)
    if not isinstance(node, list) or not node: return out
    h = node[0]
    if h == "fn": return out                            # a lambda literal is latent (counted when called)
    if h == "use": return {node[1]: 1}                  # consume a LINEAR resource once (keyed by its name)
    if h == "resource":                                 # (resource r body..) — r is scoped; count then drop at the edge
        for x in node[2:]: add(_ucount(x, fns, penv))
        out.pop(node[1], None); return out
    if h == "if":
        add(_ucount(node[1], fns, penv))                # the condition always runs
        tc, ec = _ucount(node[2], fns, penv), _ucount(node[3], fns, penv)
        for e in set(tc) | set(ec): out[e] = _uadd(out.get(e, 0), _ulub(tc.get(e, 0), ec.get(e, 0)))
        return out
    if h == "let":
        add(_ucount(node[1][1], fns, penv))
        for x in node[2:]: add(_ucount(x, fns, penv))
        return out
    if h in ("seam", "seam1"):                          # a grant is pass-through for counting (the check happens AT seam1)
        for x in node[2:]: add(_ucount(x, fns, penv))
        return out
    if h == "handle":                                   # handled effects discharged locally -> 0 uses escape upward
        for x in node[2:]: add(_ucount(x, fns, penv))
        for e in set(node[1]): out[e] = 0
        return out
    if h == "with":                                     # reinterpreted effect discharged upward (handler effect: v0 skip)
        for x in node[3:]: add(_ucount(x, fns, penv))
        out[node[1]] = 0
        return out
    for a in node[1:]: add(_ucount(a, fns, penv))       # operands
    if h in _OPEFF: out[_OPEFF[h]] = _uadd(out.get(_OPEFF[h], 0), 1)   # a direct effectful op = one use
    elif h == "ffi": out["FFI"] = _uadd(out.get("FFI", 0), 1)
    elif h in fns:
        for e, c in fns[h].get("uc", {}).items():
            if e in EFFECTS: out[e] = _uadd(out.get(e, 0), c)   # propagate EFFECT counts; resource counts stay local
        for idx in fns[h].get("lin", set()):            # passing a resource to a callee's LINEAR param consumes it once
            if idx < len(node)-1 and isinstance(node[idx+1], str):
                out[node[idx+1]] = _uadd(out.get(node[idx+1], 0), 1)
    elif penv and h in penv:
        for e in penv[h]:
            if not is_var(e): out[e] = "M"              # through a fn-param: unknown multiplicity -> conservatively many
    return out


def instantiate(callee, args, fns, penv, errs):
    """Callee's effect row with its effect VARIABLES replaced by the actual function arguments' latent effects."""
    subst = {}
    for i, p in enumerate(callee["params"]):
        lat = platent(p)
        if lat is not None and i < len(args):           # functional param -> bind its var(s) to the arg's latent
            for v in lat:
                if is_var(v): subst[v] = subst.get(v, set()) | latent_of(args[i], fns, penv, errs)
    out = set()
    for t in callee["eff"]:
        out |= subst[t] if (is_var(t) and t in subst) else {t}
    return out


def infer(node, fns, errs, penv=None):
    """Effect row a node performs (transitively). penv = {param: latent-effect-set} for function-typed names in scope."""
    penv = penv or {}
    if not isinstance(node, list) or not node: return set()
    h = node[0]
    if h == "fn": return set()                          # DEFINING a lambda performs nothing (its cost is at the call)
    if h == "ffi":                                      # (ffi name arg..) — effect-OPAQUE foreign call; '?' = unbounded
        eff = set()                                     # foreign authority. Only a SEAM (the FFI contract) may cover it,
        for a in node[2:]: eff |= infer(a, fns, errs, penv)  # so the seam's granted row IS the capability handed across.
        return eff | {"?"}
    if h == "seam" or h == "seam1":                     # (seam (E..) expr..) — CHECKED boundary == CAPABILITY GRANT;
        decl = set(node[1]) - {"Pure"}                  # (seam1 ..) = LINEAR/AFFINE grant: each cap usable AT MOST ONCE.
        inner = set()                                   # the row it declares is exactly the authority handed to the body
        for x in node[2:]: inner |= infer(x, fns, errs, penv)  # (incl. opaque foreign code). 'Pure' = the EMPTY grant.
        inner.discard("?")                              # the seam is WHERE you take responsibility for opaque foreign code
        if inner - decl:
            errs.append(f"seam under-declares: wraps {sorted(inner)} but contract says {sorted(decl)}")
        if h == "seam1":                                # affinity rides AS A PER-SEAM MULTIPLICITY — the row stays a flat
            uc = {}                                     # idempotent SET (superset inference untouched); we additionally
            for x in node[2:]:                          # carry a use-count LATTICE (0/1/many) that flows THROUGH calls
                for e, c in _ucount(x, fns, penv).items(): uc[e] = _uadd(uc.get(e, 0), c)   # + recursion (whole-program)
            for E in sorted(decl):
                if uc.get(E, 0) == "M":
                    errs.append(f"linear capability {E} used more than once (incl. via a call or recursion)")
        return decl
    if h == "handle":                                   # (handle (E..) expr..) — DISCHARGE effects E locally (drop)
        hdl = set(node[1])
        bad = {e for e in hdl if e not in EFFECTS and not is_var(e)}
        if bad: errs.append(f"handle of unknown effect {sorted(bad)}")
        inner = set()
        for x in node[2:]: inner |= infer(x, fns, errs, penv)
        return inner - hdl                              # dual of seam: handled effects are subtracted, not added
    if h == "with":                                     # (with E hfn body..) — REINTERPRET E via hfn: E -> hfn's effect
        E = node[1]
        if E not in EFFECTS and not is_var(E):
            errs.append(f"with of unknown effect ['{E}']")
        hlat = latent_of(node[2], fns, penv, errs)      # the handler PROVIDES E; its OWN effects take E's place
        inner = set()
        for x in node[3:]: inner |= infer(x, fns, errs, penv)
        return (inner - {E}) | hlat
    if h == "use": return set()                         # consume a linear resource — pure; the discipline is the count
    if h == "resource":                                 # (resource r body..) — body must use r EXACTLY once (linear)
        r = node[1]; eff = set()
        for x in node[2:]: eff |= infer(x, fns, errs, penv)
        uc = {}
        for x in node[2:]:
            for e, c in _ucount(x, fns, penv).items(): uc[e] = _uadd(uc.get(e, 0), c)
        cnt = uc.get(r, 0)
        if cnt == 0: errs.append(f"linear resource {r} never used (must be used exactly once)")
        elif cnt == "M": errs.append(f"linear resource {r} used more than once")
        return eff
    if h == "if":                                       # (if cond then else) — SOUND: union of all branches
        return infer(node[1], fns, errs, penv) | infer(node[2], fns, errs, penv) | infer(node[3], fns, errs, penv)
    if h == "let":                                      # (let (name val) body..) — bind a local, then run body
        name, val = node[1][0], node[1][1]
        eff = infer(val, fns, errs, penv)               # the bound value's OWN effects (defining a lambda = none)
        bp = {**penv, name: latent_of(val, fns, penv, errs)} if is_fn_expr(val, fns, penv) else penv
        for x in node[2:]: eff |= infer(x, fns, errs, bp)   # a let-bound function becomes callable in the body
        return eff
    eff = set()
    for a in node[1:]: eff |= infer(a, fns, errs, penv)
    if h in BUILTIN_EFF: eff |= BUILTIN_EFF[h]
    elif h in penv: eff |= penv[h]                      # applying a function-typed name in scope -> its latent effect
    elif h in fns: eff |= instantiate(fns[h], node[1:], fns, penv, errs)  # callee row, effect-vars instantiated
    elif h not in PURE_OPS:                             # unknown head -> REFUSE to verify (never assume pure)
        errs.append(f"unresolved call: '{h}' is not a known function or builtin")
    return eff


def check(program):
    """Returns (fns, errors). errors empty == program type/effect-checks (is accepted)."""
    fns = {}
    for top in program:
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]
            penv = {pname(p): platent(p) for p in fn[1] if platent(p) is not None}
            lin = {idx for idx, p in enumerate(fn[1]) if plin(p)}   # positions of LINEAR params (carry a resource in)
            fns[top[1]] = {"decl": set(top[2]), "fn": fn, "params": fn[1], "penv": penv, "lin": lin, "eff": set(), "uc": {}}
    for _ in range(len(fns) + 2):                       # fixpoint over callee effects + use-counts (both monotone)
        for i in fns.values():
            body = i["fn"][2:]; tmp = []
            i["eff"] = set().union(*[infer(b, fns, tmp, i["penv"]) for b in body]) if body else set()
            uc = {}                                     # per-function use-count {effect: 0/1/'M'} for affine tracking
            for b in body:
                for e, c in _ucount(b, fns, i["penv"]).items(): uc[e] = _uadd(uc.get(e, 0), c)
            i["uc"] = uc
    errors = []
    for n, i in fns.items():
        for b in i["fn"][2:]: infer(b, fns, errors, i["penv"])   # collect seam/handle/with/lambda/unresolved violations
        eff = i["eff"]
        if "?" in eff:                                  # an opaque foreign 'ffi' that no seam ever granted authority to
            errors.append(f"{n}: foreign 'ffi' call has no capability seam (wrap it: (seam (..) ...))")
            eff = eff - {"?"}
        if eff - i["decl"]:
            errors.append(f"{n}: performs undeclared {sorted(eff - i['decl'])} (declared {sorted(i['decl'])})")
        unknown = {e for e in i["decl"] if e not in EFFECTS and not is_var(e)}  # vars ok; uppercase unknowns are not
        if unknown:
            errors.append(f"{n}: unknown effect {sorted(unknown)}")
        for p in i["params"]:                           # LINEAR params must be used EXACTLY once in the body
            rn = plin(p)
            if rn:
                cnt = i["uc"].get(rn, 0)
                if cnt == 0: errors.append(f"{n}: linear param {rn} never used (must be used exactly once)")
                elif cnt == "M": errors.append(f"{n}: linear param {rn} used more than once")
    return fns, errors


def call_fn(val, args, fns, out, handlers):
    """Apply a function VALUE (a Closure or a named-fn string) to already-evaluated args."""
    if isinstance(val, Closure):
        loc = {**val.env, **dict(zip([pname(p) for p in val.params], args))}; body = val.body
    elif isinstance(val, str) and val in fns:
        fn = fns[val]["fn"]; loc = dict(zip([pname(p) for p in fn[1]], args)); body = fn[2:]
    else:
        raise LoomError(f"not a function: {val}")
    r = None
    for b in body: r = ev(b, loc, fns, out, handlers)
    return r


def ev(node, env, fns, out, handlers=None):
    handlers = handlers or {}
    if isinstance(node, int): return node
    if isinstance(node, str): return env.get(node, node)
    h = node[0]
    if h == "fn": return Closure(node[1], node[2:], env)   # a lambda literal evaluates to a closure over env
    if h == "seam" or h == "seam1":                     # narrow runtime authority to exactly the granted row, then run
        _CAPS.append(set(node[1]) - {"Pure"})
        try:
            r = None
            for x in node[2:]: r = ev(x, env, fns, out, handlers)
        finally:
            _CAPS.pop()
        return r
    if h == "ffi":                                      # foreign call: run the registered fn under the current grant
        f = FOREIGN.get(node[1])
        if f is None: raise LoomError(f"unknown foreign fn: {node[1]}")
        return f([ev(x, env, fns, out, handlers) for x in node[2:]], out)
    if h == "handle":                                   # honest discharge: handled IO captured locally, never emitted
        sink = [] if "IO" in set(node[1]) else out
        r = None
        for x in node[2:]: r = ev(x, env, fns, sink, handlers)
        return r
    if h == "with":                                     # reinterpret op of E via hfn, within body
        op = OP.get(node[1])
        hf = ev(node[2], env, fns, out, handlers)       # the handler (a closure or a named fn)
        nh = {**handlers, op: hf} if op else handlers
        r = None
        for x in node[3:]: r = ev(x, env, fns, out, nh)
        return r
    if h == "use": return f"<used:{node[1]}>"           # consume the linear resource (runtime token)
    if h == "resource":
        r = None
        for x in node[2:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "if":
        c = ev(node[1], env, fns, out, handlers)
        live = (c != 0) if isinstance(c, int) else bool(c)
        return ev(node[2] if live else node[3], env, fns, out, handlers)
    if h == "let":
        loc = {**env, node[1][0]: ev(node[1][1], env, fns, out, handlers)}
        r = None
        for x in node[2:]: r = ev(x, loc, fns, out, handlers)
        return r
    a = [ev(x, env, fns, out, handlers) for x in node[1:]]
    if h == "+": return sum(a)
    if h == "-": return a[0] - a[1]
    if h == "*":
        r = 1
        for x in a: r *= x
        return r
    if h == "=": return 1 if a[0] == a[1] else 0
    if h == "<": return 1 if a[0] < a[1] else 0
    if h == ">": return 1 if a[0] > a[1] else 0
    if h == "list": return list(a)                      # pure list primitives
    if h == "cons": return [a[0]] + a[1]
    if h == "head": return a[0][0]
    if h == "tail": return a[0][1:]
    if h == "empty": return 1 if len(a[0]) == 0 else 0
    if h in OP.values() and h in handlers:              # a reinterpreted operation -> route to its handler fn
        return call_fn(handlers[h], a, fns, out, {k: v for k, v in handlers.items() if k != h})  # no self-recursion
    if h == "print":
        if not _cap_ok("IO"): raise LoomError("capability denied: IO not granted by enclosing seam")
        out.append(str(a[0])); return a[0]
    if h == "net":
        if not _cap_ok("Net"): raise LoomError("capability denied: Net not granted by enclosing seam")
        return f"<net {a[0]}>"
    if h == "alloc":
        if not _cap_ok("Alloc"): raise LoomError("capability denied: Alloc not granted by enclosing seam")
        return list(range(a[0])) if a else []
    fv = None                                           # resolve the head to a function: name, var->name, or closure
    if isinstance(h, str):
        if h in fns: fv = fns[h]
        else:
            g = env.get(h)
            if isinstance(g, str) and g in fns: fv = fns[g]
            elif isinstance(g, Closure): fv = g
    elif isinstance(h, list):                           # ((fn ..) args) — apply the result of an expression
        hv = ev(h, env, fns, out, handlers)
        fv = hv if isinstance(hv, Closure) else (fns[hv] if isinstance(hv, str) and hv in fns else None)
    if isinstance(fv, Closure):
        loc = {**fv.env, **dict(zip([pname(p) for p in fv.params], a))}; r = None
        for b in fv.body: r = ev(b, loc, fns, out, handlers)
        return r
    if isinstance(fv, dict):
        fn = fv["fn"]; loc = {**env, **dict(zip([pname(p) for p in fn[1]], a))}; r = None
        for b in fn[2:]: r = ev(b, loc, fns, out, handlers)
        return r
    raise LoomError(f"unknown form: {h}")


def run_call(program_src, call_src):
    """Static-check a program, then evaluate one call against it. Rejects if it fails the effect checker."""
    fns, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    _CAPS.clear()
    out = []
    return ev(parse(call_src)[0], {}, fns, out), out
