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


def _ambient_op_of(node, effs):
    """Direct ambient builtin ops (net/print/alloc/rand) of an effect in `effs` reachable from `node`
    WITHOUT crossing a re-scoping boundary (seam/seam1/handle/with) or a nested resource, skipping
    `use` (the sanctioned bearer path) and `fn` (latent). Enforces resource EXCLUSIVITY: inside
    (resource (r E..) ..) the effect E has no ambient bearer but r."""
    found = set()
    if not isinstance(node, list) or not node: return found
    h = node[0]
    if h in ("seam", "seam1", "handle", "with", "resource", "fn", "use"): return found
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
    if node[0] == "let":
        np = dict(penv); np[node[1][0]] = roles_of(node[1][1], penv)
        s = set()
        for b in node[2:]: s |= roles_of(b, np)
        return s
    s = set()
    for a in node[1:]: s |= roles_of(a, penv)
    return s

def _prov_reqs(body, params):
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
            anchors = (prov_of(node[ix+1], _TAINT_PROV) - {"ai"}) if ix + 1 < len(node) else set()
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
    for n, i in fns.items():                            # D22: infer each fn's per-param provenance obligations (count-form)
        i["preq"] = _prov_reqs(i["fn"][2:], {pname(p) for p in i["params"]})
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
    if h in ("seam", "seam1", "resource", "prov", "declassify"): return _emit(node[2:][-1])   # value-transparent (effects/prov are static layers)
    if h == "by": return _emit(node[3:][-1])                           # value-transparent (role tag is a static layer)
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
    if h == "ffi":
        raise LoomError(f"codegen v0 does not cover '{h}' yet")
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
             "def _rand(): return _route('rand', (), lambda: '<rand>')"]   # sink + handler-map (_with reinterpret) + no-match + effect ops
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
    if h in ("seam", "seam1", "resource", "prov", "declassify"): return _emit_js(node[2:][-1])
    if h == "by": return _emit_js(node[3:][-1])
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
    if h == "ffi":
        raise LoomError(f"JS codegen v0 does not cover '{h}' yet")
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
             "function _net(u){ return _route('net',[u], ()=>'<net '+u+'>'); }", "function _alloc(n){ return _route('alloc',[n], ()=>Array.from({length:n},(_,i)=>i)); }", "function _rand(){ return _route('rand',[], ()=>'<rand>'); }"]  # sink + handler-map + no-match + effect ops
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


# ---- CLI: turn the kernel into a usable TOOL. `python3 loom.py <check|run|build> file.loom [call] [--target py|js]` ----
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
        try: print(compile_js(src) if tgt == "js" else compile_py(src))
        except LoomError as e: print("REJECTED: " + str(e)); return 1
        return 0
    print("unknown command: " + cmd); return 2

if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
