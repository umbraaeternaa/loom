#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + REQUIRED effects `E!` (two-sided row:
# floor MUST-perform <= actual <= ceiling MAY-perform -> the row IS the D7 synthesis contract) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
import re

EFFECTS = {"Pure", "IO", "Net", "Alloc", "FFI", "Rand"}   # Rand = nondeterminism (randomness / wall-clock)
# checker vocab MUST stay == interpreter (ev) vocab — no form the checker knows that the runtime can't run.
BUILTIN_EFF = {"print": {"IO"}, "net": {"Net"}, "alloc": {"Alloc"}, "rand": {"Rand"}}
PURE_OPS = {"+", "-", "*", "=", "<", ">",          # pure ops the interpreter runs; legitimate heads, zero effect
            "list", "cons", "head", "tail", "empty"}  # pure list primitives (map/fold are then DEFINABLE in LOOM)
OP = {"IO": "print", "Net": "net", "Alloc": "alloc", "Rand": "rand"}   # which builtin operation a `with`-handler reinterprets
_CAPS = []                                              # runtime capability stack: each seam pushes the authority it grants
def _cap_ok(eff): return (not _CAPS) or (eff in _CAPS[-1])  # top-level host is unrestricted; a seam SANDBOXES its body
_POLICY = {"rank": {}, "require": {}, "forbid": set(), "author": {}, "confine": []}   # D15/D16 + D20: author[NAME]={(role,who)..}; confine=[(EFF,role)..]; program-wide trust policy (STATIC): (rank LOW HIGH) global subsumption;
#   require[EFF] = {role..} every seam granting EFF must vouch; forbid = {EFF..} the effect may not escape any function's row. check() RESETS it.
_RENV = []                                              # static stack of {resource-name: effect-set} for typed resources
_MISS = object()                                        # sentinel for scoped save/restore
_TAINT_PROV = {}                                        # D19 cross-statement TAINT: var -> provenance set (built by `let` in infer,
_TAINT_ROLE = {}                                        #   read by the gates) so a (let (y (prov ai ..)) ..) flows into a trust LATER in scope
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


def tokenize(s):
    # strip `;`-to-end-of-line comments FIRST, but never inside a string literal: the alternation matches a whole
    # "..." first (kept verbatim, so a ';' within it survives), otherwise a comment (dropped).
    s = re.sub(r'"[^"]*"|;[^\n]*', lambda m: m.group(0) if m.group(0)[:1] == '"' else '', s)
    return re.findall(r'"[^"]*"|[()]|[^\s()]+', s)


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
        rname = node[1][0] if isinstance(node[1], list) else node[1]
        out.pop(rname, None); return out
    if h == "record":
        for fld in node[1:]:
            if isinstance(fld, list) and len(fld) >= 2: add(_ucount(fld[1], fns, penv))
        return out
    if h == "get": return _ucount(node[1], fns, penv)
    if h == "variant": return _ucount(node[2], fns, penv)
    if h == "match":                                    # scrutinee runs + exactly ONE arm -> lub over arms (like if)
        add(_ucount(node[1], fns, penv))
        acs = [_ucount(arm[1], fns, penv) for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2]
        for e in set().union(*[set(c) for c in acs]) if acs else set():
            m = 0
            for c in acs: m = _ulub(m, c.get(e, 0))
            out[e] = _uadd(out.get(e, 0), m)
        return out
    if h == "if":
        add(_ucount(node[1], fns, penv))                # the condition always runs
        tc, ec = _ucount(node[2], fns, penv), _ucount(node[3], fns, penv)
        for e in set(tc) | set(ec): out[e] = _uadd(out.get(e, 0), _ulub(tc.get(e, 0), ec.get(e, 0)))
        return out
    if h == "let":
        add(_ucount(node[1][1], fns, penv))
        for x in node[2:]: add(_ucount(x, fns, penv))
        return out
    if h == 'seamN': return _ucount(['seam'] + node[2:], fns, penv)   # D27 metered grant: pass-through for use-counting, like a seam
    if h in ("seam", "seam1"):                          # a grant is pass-through for counting (the check happens AT seam1)
        for x in _roleclauses(node[2:])[3]: add(_ucount(x, fns, penv))   # skip D12/D13 (roles..)/(sub..)/(needs..) clauses
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


_NCAP = 1024                                                         # D27 meter ceiling: counts saturate here (>> any lawful quantum); recursion/overflow reach it
def _nadd(a, b): return min(a + b, _NCAP)
def _ncount(node, fns, penv):                                        # D27 EXACT use-count {effect:int}, saturating -- numeric refinement of _ucount (whose {0,1,'M'} collapses every count >= 2)
    out = {}                                                         # conservative: a call/recursion/unknown higher-order use -> _NCAP (fail-closed); if/match branches take MAX (one runs)
    def add(dd):
        for e, c in dd.items(): out[e] = _nadd(out.get(e, 0), c)
    if not isinstance(node, list) or not node: return out
    h = node[0]
    if h == 'fn': return out
    if h == 'seamN': return _ncount(['seam'] + node[2:], fns, penv)
    if h in ('seam', 'seam1'):
        for x in _roleclauses(node[2:])[3]: add(_ncount(x, fns, penv))
        return out
    if h == 'if':
        add(_ncount(node[1], fns, penv))
        tc, ec = _ncount(node[2], fns, penv), _ncount(node[3], fns, penv)
        for e in set(tc) | set(ec): out[e] = _nadd(out.get(e, 0), max(tc.get(e, 0), ec.get(e, 0)))
        return out
    if h == 'match':
        add(_ncount(node[1], fns, penv))
        arms = [_ncount(a[1], fns, penv) for a in node[2:] if isinstance(a, list) and len(a) >= 2]
        for e in set().union(*[set(c) for c in arms]) if arms else set():
            out[e] = _nadd(out.get(e, 0), max(c.get(e, 0) for c in arms))
        return out
    if h == 'let':
        add(_ncount(node[1][1], fns, penv))
        for x in node[2:]: add(_ncount(x, fns, penv))
        return out
    if h == 'resource':
        spec = node[1]; rname, reffs = (spec[0], set(spec[1:])) if isinstance(spec, list) else (spec, set())
        for x in node[2:]: add(_ncount(x, fns, penv))
        uses = out.pop(rname, 0)
        for E in reffs & EFFECTS: out[E] = _nadd(out.get(E, 0), uses)
        return out
    if h == 'use': return {node[1]: 1}
    for a in node[1:]: add(_ncount(a, fns, penv))
    if h in _OPEFF: out[_OPEFF[h]] = _nadd(out.get(_OPEFF[h], 0), 1)
    elif h == 'ffi': out['FFI'] = _nadd(out.get('FFI', 0), 1)
    elif h in fns:
        for e in fns[h].get('eff', set()) & EFFECTS: out[e] = _NCAP
    elif penv and h in penv:
        for e in penv[h]:
            if not is_var(e): out[e] = _NCAP
    return out


def _ambient_op_of(node, effs):
    """Direct ambient builtin ops (net/print/alloc/rand) of an effect in `effs` reachable from `node`
    WITHOUT crossing a re-scoping boundary (seam/seam1/handle/with) or a nested resource, skipping
    `use` (the sanctioned bearer path) and `fn` (latent). Enforces resource EXCLUSIVITY: inside
    (resource (r E..) ..) the effect E has no ambient bearer but r."""
    found = set()
    if not isinstance(node, list) or not node: return found
    h = node[0]
    if h in ("seam", "seam1", "seamN", "handle", "with", "resource", "fn", "use"): return found
    for a in node[1:]: found |= _ambient_op_of(a, effs)
    if h in BUILTIN_EFF: found |= (BUILTIN_EFF[h] & effs)
    return found


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


def prov_of(node, penv=None):
    """Provenance set under a node — who authored the values. D18 TAINT: provenance FLOWS through `let` bindings and
    computation, so a value DERIVED from (prov P ..) still carries P. (prov P x) injects P; (by ROLE WHO x) injects WHO;
    a bound variable carries the provenance of what it was bound to; everything else unions its children. 'ai' never anchors."""
    penv = penv or {}
    if isinstance(node, str): return set(penv.get(node, ()))   # a variable reference carries its bound provenance (taint)
    if not isinstance(node, list) or not node: return set()
    if node[0] == "prov":
        s = {node[1]}
        for x in node[2:]: s |= prov_of(x, penv)
        return s
    if node[0] == "by":                                  # D10: (by ROLE WHO x) — WHO is also an independent anchor
        s = {node[2]}
        for x in node[3:]: s |= prov_of(x, penv)
        return s
    if node[0] == "recall":  # D24: persistence strips in-program provenance (store->recall across ticks)
        return {"ai"}  # drop ALL inner anchors, mark ai-tainted -> untrusted-by-default (fail-closed dual of declassify)
    if node[0] == "ffi":  # D26: opaque FOREIGN code cannot be vouched for -> its RESULT strips provenance (dual of recall,
        return {"ai"}     #   at the interop/FFI boundary): the seam vouches what foreign code is GRANTED, never what it DID
    if node[0] in ("seam", "seam1"):  # D27: a (vouch ROLE WHO COMP) seam clause names a non-ai authority WHO that SIGNS a
        vmap = {}; sbody = []         #   specific foreign component COMP, so (ffi COMP ..) DIRECTLY in this seam body carries
        for x in node[2:]:            #   WHO's anchor instead of the D26 strip -> graded (audited vs unaudited) trusted-FFI.
            if isinstance(x, list) and x and x[0] == "vouch" and len(x) >= 4: vmap.setdefault(x[3], set()).add(x[2])
            elif isinstance(x, list) and x and x[0] in ("roles", "sub", "needs"): pass
            else: sbody.append(x)
        s = set()
        for x in sbody:
            if isinstance(x, list) and len(x) > 1 and x[0] == "ffi" and x[1] in vmap: s |= vmap[x[1]]
            else: s |= prov_of(x, penv)
        return s
    if node[0] == "declassify":                          # D21: (declassify ROLE e) — a non-ai ROLE LAUNDERS the taint:
        inner = set()                                    # drop the `ai` provenance and add ROLE's vouch (ai-declassify caught in infer)
        for x in node[2:]: inner |= prov_of(x, penv)
        return (inner - {"ai"}) | {node[1]}
    if node[0] == "let":                                 # D18: (let (name E) BODY..) — name carries E's provenance INTO the body
        np = dict(penv); np[node[1][0]] = prov_of(node[1][1], penv)
        s = set()
        for b in node[2:]: s |= prov_of(b, np)
        return s
    s = set()
    for a in node[1:]: s |= prov_of(a, penv)
    return s

def roles_of(node, penv=None):
    """Role->author pairs under a node (D10). D18 TAINT: flows through `let` and computation, like prov_of."""
    penv = penv or {}
    if isinstance(node, str): return set(penv.get(node, ()))
    if not isinstance(node, list) or not node: return set()
    if node[0] == "by":
        s = {(node[1], node[2])}
        for x in node[3:]: s |= roles_of(x, penv)
        return s
    if node[0] == "recall":  # D24: no role vouch survives a persistence boundary -> recalled data carries NO role
        return set()
    if node[0] == "ffi":  # D26: no role vouch survives the FOREIGN boundary either -> ffi result carries NO role
        return set()
    if node[0] in ("seam", "seam1"):  # D27: a (vouch ROLE WHO COMP) clause re-grants (ROLE, WHO) to (ffi COMP ..) in body
        vmap = {}; sbody = []
        for x in node[2:]:
            if isinstance(x, list) and x and x[0] == "vouch" and len(x) >= 4: vmap.setdefault(x[3], set()).add((x[1], x[2]))
            elif isinstance(x, list) and x and x[0] in ("roles", "sub", "needs"): pass
            else: sbody.append(x)
        s = set()
        for x in sbody:
            if isinstance(x, list) and len(x) > 1 and x[0] == "ffi" and x[1] in vmap: s |= vmap[x[1]]
            else: s |= roles_of(x, penv)
        return s
    if node[0] == "let":
        np = dict(penv); np[node[1][0]] = roles_of(node[1][1], penv)
        s = set()
        for b in node[2:]: s |= roles_of(b, np)
        return s
    s = set()
    for a in node[1:]: s |= roles_of(a, penv)
    return s

def _prov_reqs(body, params, fns=None):
    """D22: per-PARAMETER provenance obligations inferred from a fn body. A (trust [N] p) whose body is a
    RAW parameter p (count-form only — roles-form stays fail-closed) requires every CALLER to pass an
    argument carrying >= N independent (non-ai) anchors. Returns {param: need}; discharged at call sites."""
    req = {}
    def walk(n):
        if not isinstance(n, list) or not n: return
        if n[0] == "trust":
            spec = n[1] if len(n) > 1 else None
            if isinstance(spec, int): need, tb = spec, n[2:]
            elif isinstance(spec, list): need, tb = None, []          # roles-form: not deferred (fail-closed)
            else: need, tb = 1, n[1:]
            if need is not None and len(tb) == 1 and isinstance(tb[0], str) and tb[0] in params:
                req[tb[0]] = max(req.get(tb[0], 0), need)
        elif fns and isinstance(n[0], str) and n[0] in fns:           # D25: inherit a callee's obligation when we pass our
            callee = fns[n[0]]; pn = [pname(p) for p in callee["params"]]   #   OWN raw param into its trusted slot (multi-hop relay)
            for pp, cneed in callee.get("preq", {}).items():
                cix = pn.index(pp)
                if cix + 1 < len(n) and isinstance(n[cix+1], str) and n[cix+1] in params:
                    req[n[cix+1]] = max(req.get(n[cix+1], 0), cneed)
        for c in n[1:]: walk(c)
    for b in body: walk(b)
    return req

def _value_uses(node, obligated):
    """D22 soundness: names in `obligated` (fns carrying a provenance obligation) used as a VALUE — ANY
    position but a direct-call head. Such a use (passed as an arg / returned) would escape call-site
    discharge via an indirect call, so it is REFUSED. A direct-call head is exempt (it is discharged)."""
    if isinstance(node, str): return {node} if node in obligated else set()
    bad = set()
    if not isinstance(node, list) or not node: return bad
    for c in node[1:]: bad |= _value_uses(c, obligated)
    if isinstance(node[0], list): bad |= _value_uses(node[0], obligated)
    return bad

def _quorum_check(roles_req, up, body, penv=None):
    """D10 role quorum + D11 lattice over `body`. up[LOW]={HIGH..}: a HIGHer role stands in for a LOWer requirement.
    Returns (missing_roles, satisfying_authors): a required role is covered by a non-ai anchor at that role OR any role
    that transitively subsumes it; authors are the non-ai authors that cover the required roles (>= 2 means independent).
    penv = D19 cross-statement taint env (var -> role-pairs), forwarded to roles_of."""
    def fillers(r):                                        # r plus every role transitively above it (iterative, no recursion)
        seen = {r}; stk = [r]
        while stk:
            for hi in up.get(stk.pop(), ()):
                if hi not in seen: seen.add(hi); stk.append(hi)
        return seen
    pairs = {(rr, w) for x in body for (rr, w) in roles_of(x, penv) if w != "ai"}   # 'ai' never anchors a role
    covered = set(); authors = set()
    for req in roles_req:
        fr = fillers(req)
        for (ar, w) in pairs:
            if ar in fr: covered.add(req); authors.add(w)
    return roles_req - covered, authors

def _roleclauses(tail):
    """Parse leading trust/grant clauses off a tail, then the body. Shared by `trust` and `seam` (D10/D11/D12/D13):
      (roles r..)        — the role quorum (D10/D11)
      (sub LOW HIGH)     — a lattice edge: HIGH outranks / subsumes LOW (D11)
      (needs EFF role)   — bind a specific effect's grant to a specific role (D13)
    Returns (role_spec | None, subsumption up-map, needs=[(EFF, role)..], body)."""
    role_spec = None; up = {}; needs = []; rest = list(tail)
    while rest and isinstance(rest[0], list) and len(rest[0]) > 0:
        c = rest[0]; head = c[0]
        if head == "roles": role_spec = c
        elif head == "sub" and len(c) >= 3: up.setdefault(c[1], set()).add(c[2])
        elif head == "needs" and len(c) >= 3: needs.append((c[1], c[2]))
        elif head == "vouch": pass                        # D27: foreign-component attestation (consumed by prov_of/roles_of)
        else: break                                       # first non-clause element => the body starts here
        rest = rest[1:]
    return role_spec, up, needs, rest

def _with_policy_rank(up):
    """D15: fold the program-wide (rank LOW HIGH) edges into a gate's local subsumption map (purely additive)."""
    if not _POLICY["rank"]: return up
    m = {k: set(v) for k, v in up.items()}
    for lo, his in _POLICY["rank"].items(): m.setdefault(lo, set()).update(his)
    return m

def _direct_effects(node):
    """D20: effects a node performs DIRECTLY via its OWN ops (net/print/alloc/rand/ffi, a typed resource) — NOT via
    callees. The author of the defx containing these WIELDS the capability; a mere router (a call) wields nothing."""
    out = set()
    if not isinstance(node, list) or not node: return out
    h = node[0]
    if h in BUILTIN_EFF: out |= BUILTIN_EFF[h]
    elif h == "ffi": out.add("FFI")
    elif h == "resource" and isinstance(node[1], list): out |= (set(node[1][1:]) & EFFECTS)   # typed resource (r E..)
    for a in node[1:]: out |= _direct_effects(a)
    return out

def _author_covers(pairs, role, up):
    """D20: does some NON-AI author at `role` (or a role that subsumes it via D11/D15) appear in `pairs`?"""
    seen = {role}; stk = [role]
    while stk:
        for hi in up.get(stk.pop(), ()):
            if hi not in seen: seen.add(hi); stk.append(hi)
    return any(r in seen and w != "ai" for (r, w) in pairs)

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
    if h == "seam" or h == "seam1":                     # (seam (E..) (roles ..)? (sub ..)* expr..) — CHECKED boundary == GRANT
        decl = set(node[1]) - {"Pure"}                  # (seam1 ..) = LINEAR/AFFINE grant: each cap usable AT MOST ONCE.
        role_spec, up, needs, body = _roleclauses(node[2:])  # D12 (roles ..) GATES the grant on a quorum; D13 (needs EFF role) binds per-effect
        up = _with_policy_rank(up)                       # D15: program-wide (rank ..) edges apply to this gate too
        inner = set()                                   # the row it declares is exactly the authority handed to the body
        for x in body: inner |= infer(x, fns, errs, penv)  # (incl. opaque foreign code). 'Pure' = the EMPTY grant.
        inner.discard("?")                              # the seam is WHERE you take responsibility for opaque foreign code
        if inner - decl:
            errs.append(f"seam under-declares: wraps {sorted(inner)} but contract says {sorted(decl)}")
        if role_spec is not None:                       # D12: grant the dangerous effect ONLY to independently-vouched code
            missing, authors = _quorum_check(set(role_spec[1:]), up, body, _TAINT_ROLE)
            if missing:
                errs.append(f"seam grant denied: capability {sorted(decl)} requires role(s) {sorted(missing)} — not independently vouched (need a non-ai author, or a subsuming role)")
            elif len(authors) < 2:
                errs.append(f"seam grant denied: capability {sorted(decl)} vouched by a single author {sorted(authors)} — needs >= 2 independent authors")
        for (eff, role) in needs:                       # D13: a SPECIFIC effect is granted only if its OWN role vouches for it
            if eff not in decl:
                errs.append(f"seam: (needs {eff} {role}) names {eff}, not granted by this seam {sorted(decl)}")
            elif _quorum_check({role}, up, body, _TAINT_ROLE)[0]:    # missing non-empty => role not covered (by a non-ai author or a subsuming role)
                errs.append(f"seam grant denied: effect {eff} requires role '{role}' — not vouched by a non-ai author (or a subsuming role)")
        for eff in sorted(decl):                        # D15/D17: program-wide (require EFF spec) per granted effect
            for spec in sorted(_POLICY["require"].get(eff, ()), key=str):
                if isinstance(spec, int):               # D17: the grant needs >= N DISTINCT independent (non-ai) authors
                    independent = {p for x in body for p in prov_of(x, _TAINT_PROV)} - {"ai"}
                    if len(independent) < spec:
                        errs.append(f"policy: effect {eff} requires >= {spec} independent authors (program-wide (require {eff} {spec})), got {len(independent)} {sorted(independent) or '(none)'}")
                elif _quorum_check({spec}, up, body, _TAINT_ROLE)[0]:  # D15: a SPECIFIC role must be covered (subsumption applies)
                    errs.append(f"policy: effect {eff} requires role '{spec}' (program-wide (require {eff} {spec})) — not vouched by a non-ai author")
        if h == "seam1":                                # affinity rides AS A PER-SEAM MULTIPLICITY — the row stays a flat
            uc = {}                                     # idempotent SET (superset inference untouched); we additionally
            for x in body:                              # carry a use-count LATTICE (0/1/many) that flows THROUGH calls
                for e, c in _ucount(x, fns, penv).items(): uc[e] = _uadd(uc.get(e, 0), c)   # + recursion (whole-program)
            for E in sorted(decl):
                if uc.get(E, 0) == "M":
                    errs.append(f"linear capability {E} used more than once (incl. via a call or recursion)")
        return decl
    if h == 'seamN':                                    # (seamN K (E..) ... body) -- D27 METERED grant: seam gates + at-most-K uses per granted effect
        K = node[1] if isinstance(node[1], int) else -1
        decl = infer(['seam'] + node[2:], fns, errs, penv)
        body = _roleclauses(node[3:])[3]
        opaque = any(_has_head(x, 'with') or _has_head(x, 'handle') for x in body)
        nc = {}
        for x in body:
            for e, c in _ncount(x, fns, penv).items(): nc[e] = _nadd(nc.get(e, 0), c)
        for E in sorted(decl):
            got = _NCAP if opaque else nc.get(E, 0)
            if K < 0 or K >= _NCAP or got > K:
                errs.append('metered capability ' + str(E) + ' used more than its quantum ' + str(K) + ' (got ' + (str(got) if got < _NCAP else 'unbounded/opaque') + '; a call/recursion/reinterpret/discharge or unknown higher-order use counts as overflow -- fail-closed)')
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
    if h == "use":                                      # consume a linear resource; its USE performs the resource's effect
        for frame in reversed(_RENV):                   # (a typed resource unifies linear use-once WITH an effect)
            if node[1] in frame: return set(frame[node[1]])
        return set()
    if h == "resource":                                 # (resource r body) or (resource (r E..) body): LINEAR + effect E
        spec = node[1]
        rname, reffs = (spec[0], set(spec[1:])) if isinstance(spec, list) else (spec, set())
        bad = {e for e in reffs if e not in EFFECTS and not is_var(e)}
        if bad: errs.append(f"resource {rname} declares unknown effect {sorted(bad)}")
        if reffs:                                       # EXCLUSIVITY: inside a typed resource, E has NO ambient bearer
            amb = set()                                 # but r. A stray ambient op of E (not via (use r)) decouples
            for x in node[2:]: amb |= _ambient_op_of(x, reffs)   # "consumed r" from "performed E" — refuse it.
            if amb:
                errs.append(f"resource {rname}: effect(s) {sorted(amb)} performed ambiently inside its scope — "
                            f"route through (use {rname}); the resource is E's sole bearer "
                            f"(a declared (seam ..) re-grant is allowed)")
        _RENV.append({rname: reffs})                    # in scope, (use rname) performs reffs
        try:
            eff = set()
            for x in node[2:]: eff |= infer(x, fns, errs, penv)
        finally:
            _RENV.pop()
        uc = {}
        for x in node[2:]:
            for e, c in _ucount(x, fns, penv).items(): uc[e] = _uadd(uc.get(e, 0), c)
        cnt = uc.get(rname, 0)
        if cnt == 0: errs.append(f"linear resource {rname} never used (must be used exactly once)")
        elif cnt == "M": errs.append(f"linear resource {rname} used more than once")
        return eff                                       # the resource's effect ESCAPES (using it really performs it)
    if h == "record":                                   # (record (k v)..) — a product value; BUILDING performs field effects
        eff = set()
        for fld in node[1:]:
            if isinstance(fld, list) and len(fld) >= 2: eff |= infer(fld[1], fns, errs, penv)
        return eff
    if h == "get": return infer(node[1], fns, errs, penv)   # (get r k) — field access is pure; effects come from r
    if h == "variant": return infer(node[2], fns, errs, penv)   # (variant Tag payload) — building performs payload effects
    if h == "match":                                    # (match e (pat body)..) — SOUND: union of all arm bodies
        eff = infer(node[1], fns, errs, penv)
        for arm in node[2:]:
            if isinstance(arm, list) and len(arm) >= 2: eff |= infer(arm[1], fns, errs, penv)
        return eff
    if h == "if":                                       # (if cond then else) — SOUND: union of all branches
        return infer(node[1], fns, errs, penv) | infer(node[2], fns, errs, penv) | infer(node[3], fns, errs, penv)
    if h == "let":                                      # (let (name val) body..) — bind a local, then run body
        name, val = node[1][0], node[1][1]
        eff = infer(val, fns, errs, penv)               # the bound value's OWN effects (defining a lambda = none)
        bp = {**penv, name: latent_of(val, fns, penv, errs)} if is_fn_expr(val, fns, penv) else penv
        sp = _TAINT_PROV.get(name, _MISS); sr = _TAINT_ROLE.get(name, _MISS)   # D19: bind name's provenance for the body's scope
        _TAINT_PROV[name] = prov_of(val, _TAINT_PROV); _TAINT_ROLE[name] = roles_of(val, _TAINT_ROLE)   # (chained lets resolve)
        try:
            for x in node[2:]: eff |= infer(x, fns, errs, bp)   # a let-bound function becomes callable; the gate sees the taint
        finally:                                        # restore (shadowing-safe), so the binding never leaks past its scope
            (_TAINT_PROV.__setitem__(name, sp) if sp is not _MISS else _TAINT_PROV.pop(name, None))
            (_TAINT_ROLE.__setitem__(name, sr) if sr is not _MISS else _TAINT_ROLE.pop(name, None))
        return eff
    if h == "prov":                                     # (prov P expr) — tag PROVENANCE P (who authored it); a channel
        eff = set()                                     # SEPARATE from effects: prov flows up, effects pass through unchanged
        for x in node[2:]: eff |= infer(x, fns, errs, penv)
        return eff
    if h == "by":                                       # (by ROLE WHO expr) — role-tagged provenance; effects pass through
        eff = set()
        for x in node[3:]: eff |= infer(x, fns, errs, penv)
        return eff
    if h == "recall":  # D24: e crossed a persistence boundary; effects flow, provenance does not (see prov_of/roles_of)
        eff = set()
        for x in node[1:]: eff |= infer(x, fns, errs, penv)
        return eff
    if h == "declassify":                               # (declassify ROLE e) — D21: a non-ai ROLE launders provenance taint
        if node[1] == "ai":                             # CORE anti-circularity rule: ai may not declassify its own output
            errs.append("declassify: 'ai' cannot declassify provenance — only a non-ai role may take responsibility")
        eff = set()
        for x in node[2:]: eff |= infer(x, fns, errs, penv)
        return eff
    if h == "trust":                                    # (trust SPEC? expr) — D9/D10 GATE vs CIRCULAR / under-corroborated trust
        spec = node[1] if len(node) > 1 else None
        is_roles = isinstance(spec, list) and len(spec) > 0 and spec[0] == "roles"
        if is_roles:                                     # D10 ROLE-QUORUM + D11 role LATTICE: (trust (roles ..) (sub LOW HIGH).. e)
            _, up, _, body = _roleclauses(node[1:])       # node[1] IS the (roles ..) spec — consume it + any (sub LOW HIGH) clauses
            roles_req = set(spec[1:])                     # up[LOW] = {HIGH..}: a higher role can STAND IN FOR a lower one (D11)
            missing, authors = _quorum_check(roles_req, _with_policy_rank(up), body, _TAINT_ROLE)   # D15: ranks; D19: taint env
            if missing:
                errs.append(f"trust gate (roles): role(s) {sorted(missing)} not independently covered (need a non-ai author, or a role that subsumes it) — self-certified")
            elif len(authors) < 2:
                errs.append(f"trust gate (roles): required roles satisfied by a single author {sorted(authors)} — circular trust (one author owns code+spec+proof)")
        else:                                            # D9 COUNT form: (trust [N] e) — value must carry >= N DISTINCT
            has_n = isinstance(spec, int)                #                 INDEPENDENT anchors (provenance != 'ai'); N defaults 1
            need = spec if has_n else 1
            body = node[2:] if has_n else node[1:]       # independence is a QUANTITY = count of distinct non-ai sources;
            independent = {p for x in body for p in prov_of(x, _TAINT_PROV)} - {"ai"} # SET; D19: taint env so bound vars carry prov
            p0 = body[0] if len(body) == 1 else None     # D22: (trust [N] raw-param) DEFERS to the call site, where
            deferred = isinstance(p0, str) and p0 in _POLICY.get("params", set()) and p0 not in _TAINT_PROV  # the arg's provenance discharges it; only a RAW param (untainted + unshadowed) defers
            if len(independent) < need and not deferred:
                errs.append(f"trust gate: need >= {need} independent anchor(s), got {len(independent)} {sorted(independent) or '(none)'} — value too self-referential / under-corroborated")
        eff = set()
        for x in body: eff |= infer(x, fns, errs, penv)
        return eff
    eff = set()
    for a in node[1:]: eff |= infer(a, fns, errs, penv)
    if h in BUILTIN_EFF: eff |= BUILTIN_EFF[h]
    elif h in penv: eff |= penv[h]                      # applying a function-typed name in scope -> its latent effect
    elif h in fns:
        eff |= instantiate(fns[h], node[1:], fns, penv, errs)            # callee row, effect-vars instantiated
        pn = [pname(p) for p in fns[h]["params"]]                        # D22: DISCHARGE the callee's provenance obligations —
        for pp, need in fns[h].get("preq", {}).items():                  #   the arg bound to a trusted param must carry the anchors
            ix = pn.index(pp)
            arg = node[ix+1] if ix + 1 < len(node) else None
            if isinstance(arg, str) and arg in _POLICY.get("params", set()) and arg not in _TAINT_PROV:
                continue                                             # D25: arg is OUR OWN raw param -> obligation rides up via our preq (deferred to callers)
            anchors = (prov_of(arg, _TAINT_PROV) - {"ai"}) if arg is not None else set()
            if len(anchors) < need:
                errs.append(f"call to {h}: arg for trusted param '{pp}' carries {len(anchors)} independent anchor(s) {sorted(anchors) or '(none)'}, needs >= {need} — provenance does not flow through (or is too self-referential)")
    elif h not in PURE_OPS:                             # unknown head -> REFUSE to verify (never assume pure)
        errs.append(f"unresolved call: '{h}' is not a known function or builtin")
    return eff


def _sealed_discharges(node, sealed):
    """D22: sealed effects DISCHARGED by a `handle` anywhere under `node`. (handle (E..) ..) drops E from the static
    row, but for a non-IO effect the runtime op still FIRES (handle truly captures only IO) -- a static-only drop, the
    escapable-kernel gap; a (seal EFF) policy refuses it so the effect stays accountable (in the row, or via `with`)."""
    out = set()
    if not isinstance(node, list) or not node: return out
    if node[0] == "handle": out |= (set(node[1]) & sealed)
    for a in node[1:]: out |= _sealed_discharges(a, sealed)
    return out


def _has_head(node, head):
    """D23: does a node-tree contain a form whose HEAD == `head`? Recurses into operands AND a
    list-valued head (e.g. ((fn ..) args)). Used by the negative TRUST policy (forbid declassify):
    the laundering hatch is banned SYNTACTICALLY (it performs no effect row to match against)."""
    if not isinstance(node, list) or not node: return False
    if node[0] == head: return True
    if isinstance(node[0], list) and _has_head(node[0], head): return True
    return any(_has_head(c, head) for c in node[1:])


def check(program):
    """Returns (fns, errors). errors empty == program type/effect-checks (is accepted)."""
    _POLICY["rank"] = {}; _POLICY["require"] = {}; _POLICY["forbid"] = set(); _POLICY["author"] = {}; _POLICY["confine"] = []; _POLICY["seal"] = set()   # D15/D16/D20/D22: RESET policy first (never leaks between programs)
    _TAINT_PROV.clear(); _TAINT_ROLE.clear()             # D19: RESET cross-statement taint env
    for top in program:                                  # collect (rank LOW HIGH) / (require EFF role) / (forbid EFF) BEFORE inference
        if isinstance(top, list) and len(top) >= 3 and top[0] == "rank":
            _POLICY["rank"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "require":
            _POLICY["require"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "forbid":
            _POLICY["forbid"].add(top[1])
        elif isinstance(top, list) and len(top) >= 4 and top[0] == "author":   # D20: (author NAME role WHO)
            _POLICY["author"].setdefault(top[1], set()).add((top[2], top[3]))
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "confine":   # D20: (confine EFF role)
            _POLICY["confine"].append((top[1], top[2]))
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "seal":   # D22: (seal EFF) -- complete-mediation: refuse a static-only discharge
            _POLICY["seal"].add(top[1])
    fns = {}
    for top in program:
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]
            penv = {pname(p): platent(p) for p in fn[1] if platent(p) is not None}
            lin = {idx for idx, p in enumerate(fn[1]) if plin(p)}   # positions of LINEAR params (carry a resource in)
            raw = top[2]                                            # declared row; a trailing '!' marks a REQUIRED effect
            decl = {(e[:-1] if isinstance(e, str) and e.endswith("!") else e) for e in raw}    # CEILING: may perform ⊆ decl
            req = {e[:-1] for e in raw if isinstance(e, str) and e.endswith("!") and e[:-1] in EFFECTS and e[:-1] != "Pure"}  # FLOOR: MUST perform
            fns[top[1]] = {"decl": decl, "req": req, "fn": fn, "params": fn[1], "penv": penv, "lin": lin, "eff": set(), "uc": {}}
    for _ in range(len(fns) + 2):                       # fixpoint over callee effects + use-counts (both monotone)
        for i in fns.values():
            body = i["fn"][2:]; tmp = []
            i["eff"] = set().union(*[infer(b, fns, tmp, i["penv"]) for b in body]) if body else set()
            uc = {}                                     # per-function use-count {effect: 0/1/'M'} for affine tracking
            for b in body:
                for e, c in _ucount(b, fns, i["penv"]).items(): uc[e] = _uadd(uc.get(e, 0), c)
            i["uc"] = uc
    for i in fns.values(): i["preq"] = {}               # D25: per-param provenance obligations to a FIXPOINT so they
    for _ in range(len(fns) + 2):                       # PROPAGATE through calls (monotone — demand flows toward callers)
        for n, i in fns.items():
            i["preq"] = _prov_reqs(i["fn"][2:], {pname(p) for p in i["params"]}, fns)
    _obl = {n for n, i in fns.items() if i["preq"]}     # obligation-bearing fns: may ONLY be called directly (else refused)
    errors = []
    for n, i in fns.items():
        _POLICY["params"] = {pname(p) for p in i["params"]}     # D22: params of THIS fn -> a (trust raw-param) defers to its callers
        for b in i["fn"][2:]: infer(b, fns, errors, i["penv"])   # collect seam/handle/with/lambda/unresolved violations + discharge obligations
        for b in i["fn"][2:]:                           # D22 soundness: an obligation-bearing fn used as a VALUE escapes discharge
            for nm in _value_uses(b, _obl): errors.append(f"{n}: '{nm}' carries a provenance obligation {sorted(fns[nm]['preq'])} and is used as a value — call it directly so it is discharged at the call site")
        eff = i["eff"]
        if "?" in eff:                                  # an opaque foreign 'ffi' that no seam ever granted authority to
            errors.append(f"{n}: foreign 'ffi' call has no capability seam (wrap it: (seam (..) ...))")
            eff = eff - {"?"}
        if eff - i["decl"]:                                 # CEILING: a capability you may not exceed (upper bound)
            errors.append(f"{n}: performs undeclared {sorted(eff - i['decl'])} (declared {sorted(i['decl'])})")
        banned = eff & _POLICY["forbid"]                    # D16: a program-wide (forbid EFF) — the effect must NOT escape into
        if banned:                                          # any function's row (discharge it locally with with/handle, or don't)
            errors.append(f"{n}: performs {sorted(banned)} — forbidden program-wide (forbid {sorted(banned)[0]}); discharge it locally or remove it")
        missing = i["req"] - eff                            # FLOOR: a REQUIRED effect (E!) must ACTUALLY be performed —
        if missing:                                         # the row is now the D7 SYNTHESIS CONTRACT: a do-nothing stub
            errors.append(f"{n}: contract requires {sorted(missing)} but body never performs it (stub does not satisfy intent)")
        unknown = {e for e in i["decl"] if e not in EFFECTS and not is_var(e)}  # vars ok; uppercase unknowns are not
        if unknown:
            errors.append(f"{n}: unknown effect {sorted(unknown)}")
        for p in i["params"]:                           # LINEAR params must be used EXACTLY once in the body
            rn = plin(p)
            if rn:
                cnt = i["uc"].get(rn, 0)
                if cnt == 0: errors.append(f"{n}: linear param {rn} never used (must be used exactly once)")
                elif cnt == "M": errors.append(f"{n}: linear param {rn} used more than once")
    if _POLICY["confine"]:                              # D20: capability CONFINEMENT by author — the COMPOSITION GRAPH
        up = _with_policy_rank({})                      # program-wide (rank ..) edges apply to clearance subsumption too
        for eff, role in _POLICY["confine"]:
            for n_, i in fns.items():
                if eff in i["eff"] and eff in _direct_effects(i["fn"]):   # this defx WIELDS the confined effect directly
                    if not _author_covers(_POLICY["author"].get(n_, {("ai", "ai")}), role, up):
                        errors.append(f"{n_}: wields confined effect {eff} but is not authored by a cleared '{role}' "
                                      f"(program-wide (confine {eff} {role})) — uncleared component in the capability graph")
    if _POLICY["seal"]:                                 # D22: COMPLETE MEDIATION -- a sealed effect may not be silently
        for n_, i in fns.items():                       # dropped by `handle` (a static-only discharge that still FIRES at
            bad = _sealed_discharges(i["fn"], _POLICY["seal"])   # runtime for a non-IO effect -- the unfireable-kernel gap)
            if bad:
                errors.append(f"{n_}: discharges sealed effect(s) {sorted(bad)} via handle "
                    f"(program-wide (seal {sorted(bad)[0]})) -- a sealed effect may not be dropped to nothing; "
                    f"keep it in the accountable row or genuinely reinterpret it with `with`")
    if "declassify" in _POLICY["forbid"]:               # D23: NEGATIVE trust policy -- (forbid declassify) bans the D21
        for n_, i in fns.items():                       # laundering hatch program-wide. A high-assurance codebase can
            if any(_has_head(b, "declassify") for b in i["fn"][2:]):   # guarantee NO ai-derived value is rubber-stamped
                errors.append(f"{n_}: uses (declassify ..) but it is forbidden program-wide (forbid declassify) -- no ai-derived value may be laundered into trust; remove the declassify or lift the policy")
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
    if h == 'seamN': return ev(['seam'] + node[2:], env, fns, out, handlers)   # D27 meter runs as a seam (cap stack); the quantum is a static check
    if h == "seam" or h == "seam1":                     # narrow runtime authority to exactly the granted row, then run
        _CAPS.append(set(node[1]) - {"Pure"})
        try:
            r = None
            for x in _roleclauses(node[2:])[3]: r = ev(x, env, fns, out, handlers)   # skip D12/D13 (roles..)/(sub..)/(needs..) clauses
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
    if h == "prov":                                     # provenance tag — runtime-transparent (the trust gate is static)
        r = None
        for x in node[2:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "by":                                       # role-tagged provenance — runtime-transparent (static gate)
        r = None
        for x in node[3:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "recall":  # D24: persistence boundary -- runtime-transparent (taint is a static layer)
        r = None
        for x in node[1:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "declassify":                               # declassification — runtime-transparent (provenance is a static layer)
        r = None
        for x in node[2:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "trust":                                    # trust gate — runtime-transparent (already checked at check-time)
        spec = node[1] if len(node) > 1 else None        # skip the SPEC arg (N or (roles ..)) + any (sub ..) clauses; eval body
        if isinstance(spec, int):
            body = node[2:]
        elif isinstance(spec, list) and len(spec) > 0 and spec[0] == "roles":
            body = node[2:]
            while body and isinstance(body[0], list) and len(body[0]) >= 3 and body[0][0] == "sub": body = body[1:]
        else:
            body = node[1:]
        r = None
        for x in body: r = ev(x, env, fns, out, handlers)
        return r
    if h == "record":                                   # build a product value (a dict of field -> value)
        return {fld[0]: ev(fld[1], env, fns, out, handlers) for fld in node[1:] if isinstance(fld, list) and len(fld) >= 2}
    if h == "get":
        rec = ev(node[1], env, fns, out, handlers)
        return rec[node[2]] if isinstance(rec, dict) and node[2] in rec else None
    if h == "variant": return (node[1], ev(node[2], env, fns, out, handlers))   # tagged value (Tag, payload)
    if h == "match":
        tag, val = ev(node[1], env, fns, out, handlers)
        for arm in node[2:]:
            pat, body = arm[0], arm[1]
            if pat[0] == tag:
                loc = ({**env, pat[1]: val} if len(pat) >= 2 else env)
                return ev(body, loc, fns, out, handlers)
        raise LoomError(f"no match arm for tag {tag!r}")
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
    if h == "rand":                                     # nondeterminism: only if Rand is granted by the enclosing seam
        if not _cap_ok("Rand"): raise LoomError("capability denied: Rand not granted by enclosing seam")
        return "<rand>"                                 # deterministic placeholder — the point is effect-tracking, not real RNG
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


# ---- BACKEND: compile CHECKED LOOM to portable target source (v0 target = Python; same emit pattern -> JS/C/WASM).
# "AI proposes -> the compiler DISPOSES -> and EMITS verified code that runs anywhere." Covers the computational core.
def _emit(node):
    if isinstance(node, int): return str(node)
    if isinstance(node, str): return node                              # variable / symbol
    h = node[0]
    if h == "+": return "(" + "+".join(_emit(a) for a in node[1:]) + ")"
    if h == "-": return f"({_emit(node[1])}-{_emit(node[2])})"
    if h == "*": return "(" + "*".join(_emit(a) for a in node[1:]) + ")"
    if h == "=": return f"(1 if ({_emit(node[1])}=={_emit(node[2])}) else 0)"
    if h == "<": return f"(1 if ({_emit(node[1])}<{_emit(node[2])}) else 0)"
    if h == ">": return f"(1 if ({_emit(node[1])}>{_emit(node[2])}) else 0)"
    if h == "if": return f"({_emit(node[2])} if ({_emit(node[1])}!=0) else {_emit(node[3])})"
    if h == "let": return f"(lambda {node[1][0]}: {_emit(node[2:][-1])})({_emit(node[1][1])})"
    if h == "list": return "[" + ",".join(_emit(a) for a in node[1:]) + "]"
    if h == "cons": return f"([{_emit(node[1])}]+{_emit(node[2])})"
    if h == "head": return f"({_emit(node[1])}[0])"
    if h == "tail": return f"({_emit(node[1])}[1:])"
    if h == "empty": return f"(1 if len({_emit(node[1])})==0 else 0)"
    if h == "record": return "{" + ",".join(f"{fld[0]!r}:{_emit(fld[1])}" for fld in node[1:] if isinstance(fld, list)) + "}"
    if h == "get": return f"({_emit(node[1])}[{node[2]!r}])"
    if h == "fn": return f"(lambda {','.join(pname(p) for p in node[1])}: {_emit(node[2:][-1])})"
    if h == 'seamN': return _emit(['seam'] + node[2:])   # D27 meter compiles as a seam (the quantum is a static-only check)
    if h in ("seam", "seam1"): return f"_seam({sorted(set(node[1])-{'Pure'})!r}, lambda: {_emit(node[2:][-1])})"   # seam SANDBOXES the body: push its granted row so foreign/ffi code is cap-gated exactly like the interpreter
    if h in ("resource", "prov", "declassify"): return _emit(node[2:][-1])   # value-transparent (effects/prov are static layers)
    if h == "by": return _emit(node[3:][-1])                           # value-transparent (role tag is a static layer)
    if h == "recall": return _emit(node[1:][-1])  # value-transparent (persistence taint is a static layer)
    if h == "trust": return _emit(node[1:][-1])                        # value-transparent (the trust gate is a static check)
    if h == "use": return "'<used>'"
    if h == "print": return f"_p({_emit(node[1])})"                     # IO: print AND return the value (as the interpreter)
    if h == "variant": return f"({node[1]!r},{_emit(node[2])})"           # tagged value (Tag, payload) — mirrors the interpreter tuple
    if h == "match":                                                      # dispatch on tag; bind payload; mirror the interpreter
        chain = "_nm(_sc[0])"
        for arm in reversed(node[2:]):
            pat = arm[0]; b = _emit(arm[1])
            hit = f"(lambda {pat[1]}: {b})(_sc[1])" if len(pat) >= 2 else b
            chain = f"({hit} if _sc[0]=={pat[0]!r} else {chain})"
        return f"(lambda _sc: {chain})({_emit(node[1])})"
    if h == "net": return f"_net({_emit(node[1])})"                       # effect OP -> prelude that mirrors the interpreter
    if h == "alloc": return f"_alloc({_emit(node[1])})" if len(node) > 1 else "[]"
    if h == "rand": return "_rand()"
    if h == "handle": return f"_handle(lambda: {_emit(node[2:][-1])})" if "IO" in node[1] else _emit(node[2:][-1])
    if h == "with":
        op = OP.get(node[1])
        return f"_with({op!r}, {_emit(node[2])}, lambda: {_emit(node[3:][-1])})" if op else _emit(node[3:][-1])
    if h == "ffi": return f"_ffi({node[1]!r}, [{','.join(_emit(a) for a in node[2:])}])"   # foreign call via the emitted registry; cap-gated to mirror the interpreter
    return f"{h}(" + ",".join(_emit(a) for a in node[1:]) + ")"          # call: a user fn, or a closure-valued name

def compile_py(program_src):
    """Compile a CHECKED LOOM program to portable Python source (one def per defx). Rejects if it fails the checker."""
    fns, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    lines = ["_sd = [0]", "_h = {}",
             "def _route(name, args, default):\n    if name in _h:\n        f = _h.pop(name)\n        try: return f(*args)\n        finally: _h[name] = f\n    return default()",
             "def _with(name, hf, thunk):\n    had = name in _h; prev = _h.get(name)\n    _h[name] = hf\n    try: return thunk()\n    finally:\n        if had: _h[name] = prev\n        else: _h.pop(name, None)",
             "def _p(x): return _route('print', (x,), lambda: (print(x) if _sd[0]==0 else None) or x)",
             "def _handle(t):\n    _sd[0]+=1\n    try: return t()\n    finally: _sd[0]-=1",
             "def _nm(t):\n    raise Exception('no match arm for '+str(t))",
             "def _net(u): return _route('net', (u,), lambda: '<net '+str(u)+'>')",
             "def _alloc(n): return _route('alloc', (n,), lambda: list(range(n)))",
             "def _rand(): return _route('rand', (), lambda: '<rand>')",
             "_caps = []",
             "def _cap_ok(e): return (not _caps) or (e in _caps[-1])",
             "def _seam(row, thunk): _caps.append(set(row)); _r = thunk(); _caps.pop(); return _r",
             "_FOREIGN = {'logger': (lambda a: (a[0], print('foreign:'+str(a[0])) if (_cap_ok('IO') and _sd[0]==0) else None)[0])}",
             "def _ffi(name, args): return _FOREIGN[name](args)"]   # FFI codegen: cap stack (seam SANDBOX) + foreign registry -> ffi mirrors the interpreter (foreign I/O fires only if its seam granted it)
    for top in parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(pname(p) for p in fn[1]); body = _emit(fn[2:][-1]) if fn[2:] else "None"
            lines.append(f"def {top[1]}({ps}): return {body}")
    return "\n".join(lines)

def run_compiled(program_src, call_src):
    """Compile to Python, run it; return (value, output-lines) — proof the emitted code MATCHES the interpreter."""
    import io, contextlib
    ns = {}; exec(compile_py(program_src), ns); buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        val = eval(_emit(parse(call_src)[0]), ns)
    return val, buf.getvalue().splitlines()


# ---- SECOND TARGET: JavaScript. Same emit pattern -> a DIFFERENT platform (browser / Node / any OS) => cross-platform. ----
def _emit_js(node):
    if isinstance(node, int): return str(node)
    if isinstance(node, str): return node
    h = node[0]
    if h == "+": return "(" + "+".join(_emit_js(a) for a in node[1:]) + ")"
    if h == "-": return f"({_emit_js(node[1])}-{_emit_js(node[2])})"
    if h == "*": return "(" + "*".join(_emit_js(a) for a in node[1:]) + ")"
    if h == "=": return f"(({_emit_js(node[1])}==={_emit_js(node[2])})?1:0)"
    if h == "<": return f"(({_emit_js(node[1])}<{_emit_js(node[2])})?1:0)"
    if h == ">": return f"(({_emit_js(node[1])}>{_emit_js(node[2])})?1:0)"
    if h == "if": return f"(({_emit_js(node[1])}!==0)?{_emit_js(node[2])}:{_emit_js(node[3])})"
    if h == "let": return f"(({node[1][0]})=>{_emit_js(node[2:][-1])})({_emit_js(node[1][1])})"
    if h == "list": return "[" + ",".join(_emit_js(a) for a in node[1:]) + "]"
    if h == "cons": return f"([{_emit_js(node[1])}].concat({_emit_js(node[2])}))"
    if h == "head": return f"({_emit_js(node[1])}[0])"
    if h == "tail": return f"({_emit_js(node[1])}.slice(1))"
    if h == "empty": return f"(({_emit_js(node[1])}.length===0)?1:0)"
    if h == "record": return "({" + ",".join(f"{fld[0]!r}:{_emit_js(fld[1])}" for fld in node[1:] if isinstance(fld, list)) + "})"
    if h == "get": return f"({_emit_js(node[1])}[{node[2]!r}])"
    if h == "fn": return f"(({','.join(pname(p) for p in node[1])})=>{_emit_js(node[2:][-1])})"
    if h == 'seamN': return _emit_js(['seam'] + node[2:])   # D27 meter compiles as a seam (JS)
    if h in ("seam", "seam1"): return f"_seam({sorted(set(node[1])-{'Pure'})!r}, ()=>({_emit_js(node[2:][-1])}))"   # seam SANDBOXES the body (JS): cap-gate foreign code like the interpreter
    if h in ("resource", "prov", "declassify"): return _emit_js(node[2:][-1])
    if h == "by": return _emit_js(node[3:][-1])
    if h == "recall": return _emit_js(node[1:][-1])  # value-transparent (persistence taint is a static layer)
    if h == "trust": return _emit_js(node[1:][-1])
    if h == "use": return "'<used>'"
    if h == "print": return f"_p({_emit_js(node[1])})"                  # IO: print AND return the value
    if h == "variant": return f"([{node[1]!r},{_emit_js(node[2])}])"      # tagged value [Tag, payload]
    if h == "match":
        chain = "_nm(_sc[0])"
        for arm in reversed(node[2:]):
            pat = arm[0]; b = _emit_js(arm[1])
            hit = f"((({pat[1]})=>{b})(_sc[1]))" if len(pat) >= 2 else b
            chain = f"((_sc[0]==={pat[0]!r})?{hit}:{chain})"
        return f"((_sc)=>{chain})({_emit_js(node[1])})"
    if h == "net": return f"_net({_emit_js(node[1])})"
    if h == "alloc": return f"_alloc({_emit_js(node[1])})" if len(node) > 1 else "[]"
    if h == "rand": return "_rand()"
    if h == "handle": return f"_handle(()=>({_emit_js(node[2:][-1])}))" if "IO" in node[1] else _emit_js(node[2:][-1])
    if h == "with":
        op = OP.get(node[1])
        return f"_with({op!r}, {_emit_js(node[2])}, ()=>({_emit_js(node[3:][-1])}))" if op else _emit_js(node[3:][-1])
    if h == "ffi": return f"_ffi({node[1]!r}, [{','.join(_emit_js(a) for a in node[2:])}])"   # foreign call via the emitted registry (JS); cap-gated to mirror the interpreter
    return f"{h}(" + ",".join(_emit_js(a) for a in node[1:]) + ")"

def compile_js(program_src):
    """Compile a CHECKED LOOM program to portable JavaScript source (one function per defx)."""
    fns, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    lines = ["let _sd=0; let _h={};",
             "function _route(name,args,d){ if(name in _h){ let f=_h[name]; delete _h[name]; try{ return f(...args); } finally{ _h[name]=f; } } return d(); }",
             "function _with(name,hf,thunk){ let had=(name in _h), prev=_h[name]; _h[name]=hf; try{ return thunk(); } finally{ if(had) _h[name]=prev; else delete _h[name]; } }",
             "function _p(x){ return _route('print',[x], ()=>{ if(_sd===0) console.log(x); return x; }); }",
             "function _handle(t){ _sd++; try{ return t(); } finally{ _sd--; } }",
             "function _nm(t){ throw new Error('no match arm for '+t); }",
             "function _net(u){ return _route('net',[u], ()=>'<net '+u+'>'); }", "function _alloc(n){ return _route('alloc',[n], ()=>Array.from({length:n},(_,i)=>i)); }", "function _rand(){ return _route('rand',[], ()=>'<rand>'); }",
             "let _caps=[];",
             "function _cap_ok(e){ return (_caps.length===0)||_caps[_caps.length-1].has(e); }",
             "function _seam(row,thunk){ _caps.push(new Set(row)); let _r=thunk(); _caps.pop(); return _r; }",
             "const _FOREIGN={ logger:(a)=>{ if(_cap_ok('IO')&&_sd===0) console.log('foreign:'+String(a[0])); return a[0]; } };",
             "function _ffi(name,args){ return _FOREIGN[name](args); }"]  # FFI codegen (JS): cap stack + foreign registry -> ffi mirrors the interpreter
    for top in parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(pname(p) for p in fn[1]); body = _emit_js(fn[2:][-1]) if fn[2:] else "null"
            lines.append(f"function {top[1]}({ps}){{ return {body}; }}")
    return "\n".join(lines)

def run_js(program_src, call_src):
    """Compile to JS, run through Node; return (value, output-lines) — proof the JS target matches the interpreter. Needs node."""
    import subprocess, json as _json
    js = compile_js(program_src) + "\nconsole.log('__R__'+JSON.stringify(" + _emit_js(parse(call_src)[0]) + "))"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=15)
    if r.returncode != 0: raise LoomError("node: " + r.stderr.strip()[:200])
    lines = r.stdout.splitlines(); val = None; out = []
    for ln in lines:
        if ln.startswith("__R__"): val = _json.loads(ln[5:])
        else: out.append(ln)
    return val, out


# ---- THIRD TARGET: WebAssembly. The integer computational core compiles to REAL wasm bytes (run via node's built-in
#      WebAssembly, ZERO deps) + a human-readable WAT "assembler". interp==Py==JS==WASM. Honest scope: the integer core
#      only (+ - * / = < > / if / first-order calls + recursion); closures/lists/types/effects need a value runtime in
#      linear memory -> the next frontier. Forms outside the core fail-closed (LoomError), never emit wrong code. ----
def _leb_u(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7; o.append(b | (0x80 if n else 0))
        if not n: return bytes(o)

def _leb_s(n):
    o = bytearray(); more = True
    while more:
        b = n & 0x7f; n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)): more = False
        else: b |= 0x80
        o.append(b)
    return bytes(o)

_WBIN = {"+": 0x6a, "-": 0x6b, "*": 0x6c}; _WCMP = {"=": 0x46, "<": 0x48, ">": 0x4a}   # i32 add/sub/mul + eq/lt_s/gt_s

def _emit_wasm(node, lmap, fmap, cons_i, tags, si):        # body bytes; lmap: name->local idx; cons_i: $cons idx; tags: tag->id; si: scrutinee local
    if isinstance(node, int): return b"\x41" + _leb_s(node)            # i32.const
    if isinstance(node, str):
        if node not in lmap: raise LoomError("wasm: free variable " + node)
        return b"\x20" + _leb_u(lmap[node])                            # local.get (param / let / match-bound)
    h = node[0]
    if h in ("+", "*"):
        out = _emit_wasm(node[1], lmap, fmap, cons_i, tags, si)
        for a in node[2:]: out += _emit_wasm(a, lmap, fmap, cons_i, tags, si) + bytes([_WBIN[h]])
        return out
    if h == "-": return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + _emit_wasm(node[2], lmap, fmap, cons_i, tags, si) + b"\x6b"
    if h in _WCMP: return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + _emit_wasm(node[2], lmap, fmap, cons_i, tags, si) + bytes([_WCMP[h]])
    if h == "if":                                                       # if (result i32) THEN else ELSE end
        return (_emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + b"\x04\x7f" + _emit_wasm(node[2], lmap, fmap, cons_i, tags, si)
                + b"\x05" + _emit_wasm(node[3], lmap, fmap, cons_i, tags, si) + b"\x0b")
    if h == "let":                                                      # (let (name val) body..) -> val; local.set name; body
        out = _emit_wasm(node[1][1], lmap, fmap, cons_i, tags, si) + b"\x21" + _leb_u(lmap[node[1][0]])
        for b in node[2:]: out += _emit_wasm(b, lmap, fmap, cons_i, tags, si)
        return out
    if h == "list":                                                     # (list a b ..) -> cons(a, cons(b, .. nil))
        if len(node) == 1: return b"\x41\x00"                           # nil = 0
        out = b"".join(_emit_wasm(a, lmap, fmap, cons_i, tags, si) for a in node[1:]) + b"\x41\x00"
        return out + b"".join(b"\x10" + _leb_u(cons_i) for _ in node[1:])   # fold to the right via $cons
    if h == "cons": return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + _emit_wasm(node[2], lmap, fmap, cons_i, tags, si) + b"\x10" + _leb_u(cons_i)
    if h == "head": return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + b"\x28\x02\x00"    # i32.load  (cell value / tag)
    if h == "tail": return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + b"\x28\x02\x04"    # i32.load offset 4 (next / payload)
    if h == "empty": return _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + b"\x45"           # i32.eqz   (ptr == nil)
    if h == "variant":                                                  # (variant Tag e) -> cons(tag_id, payload) -> cell [tag|payload]
        return b"\x41" + _leb_s(tags[node[1]]) + _emit_wasm(node[2], lmap, fmap, cons_i, tags, si) + b"\x10" + _leb_u(cons_i)
    if h == "match":                                                    # scrut->$s; chain: load tag; ==TAG; if (bind payload) body else .. unreachable
        out = _emit_wasm(node[1], lmap, fmap, cons_i, tags, si) + b"\x21" + _leb_u(si)
        def _arms(a):
            if not a: return b"\x00"                                    # unreachable — no arm matched (the interpreter likewise errors)
            pat, body = a[0][0], a[0][1]
            chk = b"\x20" + _leb_u(si) + b"\x28\x02\x00" + b"\x41" + _leb_s(tags[pat[0]]) + b"\x46"   # $s.tag == TAG
            bind = (b"\x20" + _leb_u(si) + b"\x28\x02\x04" + b"\x21" + _leb_u(lmap[pat[1]])) if len(pat) >= 2 else b""
            return chk + b"\x04\x7f" + bind + _emit_wasm(body, lmap, fmap, cons_i, tags, si) + b"\x05" + _arms(a[1:]) + b"\x0b"
        return out + _arms(node[2:])
    if h in fmap:                                                       # call $fn  (first-order / recursive)
        return b"".join(_emit_wasm(a, lmap, fmap, cons_i, tags, si) for a in node[1:]) + b"\x10" + _leb_u(fmap[h])
    raise LoomError("wasm: form not yet in the WASM backend: " + str(h))

def _wasm_defxs(program_src):
    return [t for t in parse(program_src) if isinstance(t, list) and t and t[0] == "defx"]

def _wasm_locals(node, names, flags):                      # collect let-names + match pattern-vars; flags['match']=True needs a scrutinee temp
    if not isinstance(node, list): return
    if node and node[0] == "let":
        names.append(node[1][0]); _wasm_locals(node[1][1], names, flags)
        for b in node[2:]: _wasm_locals(b, names, flags)
    elif node and node[0] == "match":
        flags["match"] = True; _wasm_locals(node[1], names, flags)
        for arm in node[2:]:
            if len(arm[0]) >= 2: names.append(arm[0][1])               # the pattern's bound variable
            _wasm_locals(arm[1], names, flags)
    else:
        for a in node: _wasm_locals(a, names, flags)

def _wasm_tags(program_src):                               # program-wide tag -> integer id (variant + match tags share one numbering)
    tags = {}
    def w(n):
        if not isinstance(n, list): return
        if n and n[0] == "variant":
            tags.setdefault(n[1], len(tags))
            for a in n[2:]: w(a)
        elif n and n[0] == "match":
            w(n[1])
            for arm in n[2:]:
                tags.setdefault(arm[0][0], len(tags)); w(arm[1])
        else:
            for a in n: w(a)
    for t in _wasm_defxs(program_src): w(t[3])
    return tags

def compile_wasm(program_src):
    """Compile a CHECKED LOOM program (integers + let + integer lists) to a real WebAssembly module (bytes). Rejects if it fails the checker.
    VALUE RUNTIME: a linear-memory heap (global $hp bump pointer) + a $cons helper allocates [value|next] cells; lists are linked
    in memory (head/tail = i32.load, empty = i32.eqz, nil = 0). Honest scope: ints + let + integer lists + sum types (variant/match); records/closures/
    effects still need more runtime (next frontier) and stay fail-closed until then."""
    _, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    ds = _wasm_defxs(program_src); fmap = {t[1]: i for i, t in enumerate(ds)}; cons_i = len(ds)   # $cons is the LAST function
    tags = _wasm_tags(program_src)                          # program-wide tag -> id (for variant/match)
    funcs = []                                              # (arity, n_locals, code)
    for t in ds:
        fn = t[3]; params = [pname(p) for p in fn[1]]; names = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, names, flags)
        seen = list(dict.fromkeys(names))                   # unique let-names + match-vars -> local slots after the params
        lmap = {p: i for i, p in enumerate(params)}
        for j, nm in enumerate(seen): lmap[nm] = len(params) + j
        si = len(params) + len(seen)                        # one shared scrutinee temp per function (used by match)
        nloc = len(seen) + (1 if flags["match"] else 0)
        funcs.append((len(params), nloc, _emit_wasm(fn[2:][-1] if fn[2:] else 0, lmap, fmap, cons_i, tags, si) + b"\x0b"))
    cons_code = (b"\x23\x00\x21\x02" b"\x23\x00\x41\x08\x6a\x24\x00"             # $t = $hp ; $hp += 8
                 b"\x20\x02\x20\x00\x36\x02\x00" b"\x20\x02\x20\x01\x36\x02\x04"  # mem[t] = v ; mem[t+4] = rest
                 b"\x20\x02\x0b")                                                 # return $t
    def _sec(sid, c): return bytes([sid]) + _leb_u(len(c)) + c
    ar = sorted({a for a, _, _ in funcs} | {2}); ti = {a: i for i, a in enumerate(ar)}   # arity-2 type covers $cons
    tc = _leb_u(len(ar)) + b"".join(b"\x60" + _leb_u(a) + b"\x7f" * a + b"\x01\x7f" for a in ar)   # type: (i32*)->i32
    fc = _leb_u(len(funcs) + 1) + b"".join(_leb_u(ti[a]) for a, _, _ in funcs) + _leb_u(ti[2])     # +$cons
    mc = _leb_u(1) + b"\x00" + _leb_u(1)                    # 1 memory, min 1 page (64 KiB heap)
    gc = _leb_u(1) + b"\x7f\x01\x41\x08\x0b"                # 1 mutable i32 global $hp = 8 (offset 0 reserved as nil)
    ec = _leb_u(len(funcs))
    for i, t in enumerate(ds):
        nb = t[1].encode(); ec += _leb_u(len(nb)) + nb + b"\x00" + _leb_u(i)                        # export func
    cc = _leb_u(len(funcs) + 1)
    for _, nloc, code in funcs:
        loc = (_leb_u(1) + _leb_u(nloc) + b"\x7f") if nloc else _leb_u(0)                           # let-locals (i32)
        e = loc + code; cc += _leb_u(len(e)) + e
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + cons_code; cc += _leb_u(len(e)) + e                     # $cons: 1 local ($t)
    return (b"\x00asm\x01\x00\x00\x00" + _sec(1, tc) + _sec(3, fc) + _sec(5, mc)
            + _sec(6, gc) + _sec(7, ec) + _sec(10, cc))

def emit_wat(program_src):
    """Human-readable WebAssembly Text (the 'assembler') for what compile_wasm encodes to bytes:
    the integer core + let + integer lists + sum types (variant/match) on a linear-memory heap."""
    _, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    ds = _wasm_defxs(program_src); fmap = {t[1]: i for i, t in enumerate(ds)}; tags = _wasm_tags(program_src); uses_heap = [False]
    _OP = {"+": "i32.add", "-": "i32.sub", "*": "i32.mul", "=": "i32.eq", "<": "i32.lt_s", ">": "i32.gt_s"}
    def w(node, ind):
        if isinstance(node, int): return [ind + "i32.const " + str(node)]
        if isinstance(node, str): return [ind + "local.get $" + node]
        h = node[0]
        if h in ("+", "*"):
            o = w(node[1], ind)
            for a in node[2:]: o += w(a, ind) + [ind + _OP[h]]
            return o
        if h in ("-", "=", "<", ">"): return w(node[1], ind) + w(node[2], ind) + [ind + _OP[h]]
        if h == "if":
            return (w(node[1], ind) + [ind + "if (result i32)"] + w(node[2], ind + "  ")
                    + [ind + "else"] + w(node[3], ind + "  ") + [ind + "end"])
        if h == "let":
            o = w(node[1][1], ind) + [ind + "local.set $" + node[1][0]]
            for b in node[2:]: o += w(b, ind)
            return o
        if h == "list":
            uses_heap[0] = True; o = []
            for a in node[1:]: o += w(a, ind)
            return o + [ind + "i32.const 0"] + [ind + "call $cons" for _ in node[1:]]
        if h == "cons": uses_heap[0] = True; return w(node[1], ind) + w(node[2], ind) + [ind + "call $cons"]
        if h == "head": uses_heap[0] = True; return w(node[1], ind) + [ind + "i32.load"]
        if h == "tail": uses_heap[0] = True; return w(node[1], ind) + [ind + "i32.load offset=4"]
        if h == "empty": return w(node[1], ind) + [ind + "i32.eqz"]
        if h == "variant":
            uses_heap[0] = True
            return [ind + "i32.const " + str(tags[node[1]]) + "  ;; tag " + node[1]] + w(node[2], ind) + [ind + "call $cons"]
        if h == "match":
            uses_heap[0] = True; o = w(node[1], ind) + [ind + "local.set $s"]
            def arms(a, ii):
                if not a: return [ii + "unreachable"]
                pat, body = a[0][0], a[0][1]
                ln = [ii + "local.get $s", ii + "i32.load", ii + "i32.const " + str(tags[pat[0]]) + "  ;; tag " + pat[0], ii + "i32.eq", ii + "if (result i32)"]
                if len(pat) >= 2: ln += [ii + "  local.get $s", ii + "  i32.load offset=4", ii + "  local.set $" + pat[1]]
                return ln + w(body, ii + "  ") + [ii + "else"] + arms(a[1:], ii + "  ") + [ii + "end"]
            return o + arms(node[2:], ind)
        if h in fmap:
            o = []
            for a in node[1:]: o += w(a, ind)
            return o + [ind + "call $" + h]
        raise LoomError("wat: form not yet in the WASM backend: " + str(h))
    bodies = []
    for t in ds:
        fn = t[3]; pn = [pname(p) for p in fn[1]]; sig = " ".join("(param $" + p + " i32)" for p in pn)
        nm = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, nm, flags)
        locs = " ".join("(local $" + x + " i32)" for x in dict.fromkeys(nm))
        if flags["match"]: locs = (locs + " " if locs else "") + "(local $s i32)"
        head = "  (func $" + t[1] + ((" " + sig) if sig else "") + " (result i32)" + ((" " + locs) if locs else "")
        bodies.append([head] + w(fn[2:][-1] if fn[2:] else 0, "    ")
                      + ["  )", '  (export "' + t[1] + '" (func $' + t[1] + "))"])
    lines = ["(module"]
    if uses_heap[0]:
        lines += ["  (memory 1)", "  (global $hp (mut i32) (i32.const 8))",
                  "  (func $cons (param $v i32) (param $rest i32) (result i32) (local $t i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 8  i32.add  global.set $hp",
                  "    local.get $t  local.get $v  i32.store",
                  "    local.get $t  local.get $rest  i32.store offset=4",
                  "    local.get $t)"]
    for b in bodies: lines += b
    return "\n".join(lines + [")"])

def run_wasm(program_src, call_src):
    """Compile to wasm bytes, run via node's built-in WebAssembly; return (value, []) — proof wasm == interpreter. Needs node."""
    import subprocess
    c = parse(call_src)[0]                                  # call site = (NAME int-args...) for the integer core
    name = c[0] if isinstance(c, list) else c
    args = c[1:] if isinstance(c, list) else []
    arr = ",".join(str(b) for b in compile_wasm(program_src))
    js = ("WebAssembly.instantiate(new Uint8Array([" + arr + "]))"
          ".then(m=>console.log(m.instance.exports[" + repr(name) + "](" + ",".join(str(a) for a in args) + ")))"
          ".catch(e=>{console.error(String(e));process.exit(1)})")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=15)
    if r.returncode != 0: raise LoomError("node-wasm: " + r.stderr.strip()[:200])
    return int(r.stdout.strip()), []


# ---- CLI: turn the kernel into a usable TOOL. `python3 loom.py <check|run|build> file.loom [call] [--target py|js|wat]` ----
def _cli(argv):
    flags, pos, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--target" and i + 1 < len(argv): flags["target"] = argv[i+1]; i += 2
        elif a.startswith("--target="): flags["target"] = a.split("=", 1)[1]; i += 1
        else: pos.append(a); i += 1
    if len(pos) < 2:
        print("usage: python3 loom.py <check|run|build> FILE [call] [--target py|js]"); return 2
    cmd, path = pos[0], pos[1]; call = pos[2] if len(pos) > 2 else "(main)"
    try: src = open(path).read()
    except OSError as e: print("cannot read file: " + str(e)); return 2
    if cmd == "check":
        _, errs = check(parse(src))
        if errs:
            print("REJECTED:"); [print("  - " + e) for e in errs]; return 1
        print(f"OK — checked, all effects honest"); return 0
    if cmd == "run":
        try: val, out = run_call(src, call)
        except LoomError as e: print("REJECTED: " + str(e)); return 1
        for line in out: print(line)
        print("=> " + repr(val)); return 0
    if cmd == "build":
        tgt = flags.get("target", "py")
        try: print(emit_wat(src) if tgt == "wat" else (compile_js(src) if tgt == "js" else compile_py(src)))
        except LoomError as e: print("REJECTED: " + str(e)); return 1
        return 0
    print("unknown command: " + cmd); return 2

if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
