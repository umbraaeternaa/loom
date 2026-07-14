#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + REQUIRED effects `E!` (two-sided row:
# floor MUST-perform <= actual <= ceiling MAY-perform -> the row IS the D7 synthesis contract) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
import hashlib
import hmac
import json
import os
import re
import unicodedata
from contextvars import ContextVar
from pathlib import Path

EFFECTS = {"Pure", "IO", "Net", "Alloc", "FFI", "Rand"}   # Rand = nondeterminism (randomness / wall-clock)
# checker vocab MUST stay == interpreter (ev) vocab — no form the checker knows that the runtime can't run.
BUILTIN_EFF = {"print": {"IO"}, "net": {"Net"}, "alloc": {"Alloc"}, "rand": {"Rand"}}
PURE_OPS = {"+", "-", "*", "=", "<", ">",          # pure ops the interpreter runs; legitimate heads, zero effect
            "list", "cons", "head", "tail", "empty"}  # pure list primitives (map/fold are then DEFINABLE in LOOM)
OP = {"IO": "print", "Net": "net", "Alloc": "alloc", "Rand": "rand"}   # which builtin operation a `with`-handler reinterprets
_MISS = object()                                        # sentinel for scoped save/restore


class _RuntimeState:
    """Mutable runtime capability state scoped to one run_call() invocation."""
    __slots__ = ("caps",)

    def __init__(self):
        self.caps = []


class _CheckerState:
    """Mutable checker state scoped to one check() invocation."""
    __slots__ = ("policy", "renv", "taint_prov", "taint_role")

    def __init__(self):
        self.policy = {
            "rank": {}, "require": {}, "forbid": set(), "author": {},
            "confine": [], "seal": set(), "params": set(),
        }
        self.renv = []
        self.taint_prov = {}
        self.taint_role = {}


_CHECKER_STATE = ContextVar("loom_checker_state", default=None)
_RUNTIME_STATE = ContextVar("loom_runtime_state", default=None)


def _runtime_state():
    state = _RUNTIME_STATE.get()
    if state is None:
        state = _RuntimeState()
        _RUNTIME_STATE.set(state)
    return state


def _checker_state():
    state = _CHECKER_STATE.get()
    if state is None:
        state = _CheckerState()
        _CHECKER_STATE.set(state)
    return state
def _cap_ok(eff):
    caps = _runtime_state().caps
    return (not caps) or (eff in caps[-1])              # top-level host is unrestricted; a seam SANDBOXES its body
def _foreign_logger(args, out):                        # opaque foreign code that WANTS IO; emits ONLY if IO was granted
    if _cap_ok("IO"): out.append("foreign:" + str(args[0]))
    return args[0]
def _foreign_opaque(args, out):                        # opaque foreign component used to exercise attested ffi paths
    return args[0] if args else 0
FOREIGN = {
    "logger": _foreign_logger,
    "lib": _foreign_opaque,
    "x": _foreign_opaque,
    "other": _foreign_opaque,
}                  # registry of effect-opaque foreign functions reached via (ffi ..)
INT_BITS = 31
INT_MIN = -(1 << (INT_BITS - 1))
INT_MAX = (1 << (INT_BITS - 1)) - 1
_INT_MOD = 1 << INT_BITS
ASM_INTRINSICS = {
    ("wasm", "i31.add"): {
        "inputs": ("i31", "i31"),
        "result": "i31",
        "effects": frozenset(),
        "portable_op": "add",
        "wasm_rhs": "tagged",
        "wasm_result": "tagged",
        "wasm_opcode": 0x6A,
        "wat_opcode": "i32.add",
    },
    ("wasm", "i31.sub"): {
        "inputs": ("i31", "i31"),
        "result": "i31",
        "effects": frozenset(),
        "portable_op": "sub",
        "wasm_rhs": "tagged",
        "wasm_result": "tagged",
        "wasm_opcode": 0x6B,
        "wat_opcode": "i32.sub",
    },
    ("wasm", "i31.mul"): {
        "inputs": ("i31", "i31"),
        "result": "i31",
        "effects": frozenset(),
        "portable_op": "mul",
        "wasm_rhs": "unbox_i31",
        "wasm_result": "tagged",
        "wasm_opcode": 0x6C,
        "wat_opcode": "i32.mul",
    },
    ("wasm", "i31.eq"): {
        "inputs": ("i31", "i31"),
        "result": "bool-i31",
        "effects": frozenset(),
        "portable_op": "eq",
        "wasm_rhs": "tagged",
        "wasm_result": "tag_i31",
        "wasm_opcode": 0x46,
        "wat_opcode": "i32.eq",
    },
    ("wasm", "i31.lt_s"): {
        "inputs": ("i31", "i31"),
        "result": "bool-i31",
        "effects": frozenset(),
        "portable_op": "lt_s",
        "wasm_rhs": "tagged",
        "wasm_result": "tag_i31",
        "wasm_opcode": 0x48,
        "wat_opcode": "i32.lt_s",
    },
    ("wasm", "i31.gt_s"): {
        "inputs": ("i31", "i31"),
        "result": "bool-i31",
        "effects": frozenset(),
        "portable_op": "gt_s",
        "wasm_rhs": "tagged",
        "wasm_result": "tag_i31",
        "wasm_opcode": 0x4A,
        "wat_opcode": "i32.gt_s",
    },
}
ASM_TARGETS = frozenset(target for target, _ in ASM_INTRINSICS)


def asm_metadata(node):
    """Return registry-owned metadata for a structurally valid asm form."""
    return ASM_INTRINSICS[(str(node[1]), str(node[2]))]


def asm_validation_error(node):
    """Return a diagnostic for an invalid asm-v0 envelope, otherwise None."""
    if len(node) < 2 or not isinstance(node[1], str) or type(node[1]) is str:
        return "asm: expected target symbol; v0 syntax is (asm wasm OPCODE ARG...)"
    target = str(node[1])
    if target not in ASM_TARGETS:
        return f"asm: unsupported target '{target}'; v0 permits only wasm"
    if len(node) < 3 or not isinstance(node[2], str) or type(node[2]) is str:
        return "asm: expected opcode symbol after target"
    opcode = str(node[2])
    spec = ASM_INTRINSICS.get((target, opcode))
    if spec is None:
        return f"asm: unsupported wasm opcode '{opcode}' in v0"
    got = len(node) - 3
    arity = len(spec["inputs"])
    if got != arity:
        return f"asm: wasm opcode '{opcode}' expects {arity} argument(s), got {got}"
    return None


def _i31(n):
    """Canonical signed i31 wraparound shared by every LOOM execution backend."""
    return ((n - INT_MIN) % _INT_MOD) + INT_MIN


def _int_literal_errors(nodes):
    errors = []
    def walk(node):
        if isinstance(node, int):
            if node < INT_MIN or node > INT_MAX:
                errors.append(f"integer literal {node} outside LOOM i31 range [{INT_MIN}, {INT_MAX}]")
        elif isinstance(node, list):
            for item in node: walk(item)
    for node in nodes: walk(node)
    return errors


def _check_call_literals(call_ast):
    errors = _int_literal_errors(call_ast)
    if errors: raise LoomError("; ".join(errors))


class Symbol(str): pass


def plin(p): return p[1] if (isinstance(p, list) and len(p) >= 2 and p[0] == "lin") else None   # (lin r) = LINEAR param
def pname(p):                                                    # a param is `name` (value) · `(name eff..)` (fn) · `(lin r)` (linear)
    if isinstance(p, list): return p[1] if p and p[0] == "lin" else p[0]
    return p
def platent(p):                                                 # fn-param's latent effects; None for value / linear params
    if isinstance(p, list) and p and p[0] == "lin": return None
    return set(p[1:]) if isinstance(p, list) else None
def _is_symbol(node): return isinstance(node, str) and type(node) is not str
def is_var(e): return _is_symbol(e) and e not in EFFECTS and e[:1].islower()  # lowercase token = effect variable
def is_fn_expr(e, fns, penv):                                    # does this expression denote a function?
    return (isinstance(e, list) and len(e) > 0 and e[0] == "fn") or (_is_symbol(e) and (e in fns or e in penv))


def tokenize_spans(s):
    spans = []
    i = 0
    line = 1
    column = 1
    n = len(s)
    def advance(ch):
        nonlocal line, column
        if ch == "\n":
            line += 1
            column = 1
        else:
            column += 1
    while i < n:
        ch = s[i]
        if ch.isspace():
            advance(ch); i += 1; continue
        if ch == ";":
            while i < n and s[i] != "\n":
                advance(s[i]); i += 1
            continue
        start = i; start_line = line; start_column = column
        if ch in "()":
            tok = ch; advance(ch); i += 1
        elif ch == '"':
            i += 1; advance(ch)
            while i < n:
                c = s[i]
                i += 1; advance(c)
                if c == '"':
                    break
            tok = s[start:i]
        else:
            while i < n and (not s[i].isspace()) and s[i] not in "();":
                advance(s[i]); i += 1
            tok = s[start:i]
        spans.append({"token": tok, "line": start_line, "column": start_column, "offset": start, "end_offset": i})
    return spans


def tokenize(s):
    return [span["token"] for span in tokenize_spans(s)]


def _atom_value(x):
    if x.startswith('"'): return x[1:-1]
    try: return int(x)
    except ValueError: return Symbol(x)


def _read(t):
    if not t:
        raise LoomError("unexpected end of input")
    x = t.pop(0)
    if x == ")":
        raise LoomError("unexpected ')'")
    if x == "(":
        l = []
        while True:
            if not t:
                raise LoomError("unclosed '('")
            if t[0] == ")":
                t.pop(0); return l
            l.append(_read(t))
    return _atom_value(x)


def _span_payload(start, end):
    return {
        "line": start["line"],
        "column": start["column"],
        "offset": start["offset"],
        "end_offset": end["end_offset"],
    }


def _read_span(spans, index):
    if index >= len(spans):
        raise LoomError("unexpected end of input")
    head = spans[index]
    x = head["token"]
    if x == ")":
        raise LoomError("unexpected ')'")
    if x == "(":
        values = []
        children = []
        index += 1
        while True:
            if index >= len(spans):
                raise LoomError("unclosed '('")
            if spans[index]["token"] == ")":
                close = spans[index]
                return {"value": values, "span": _span_payload(head, close), "children": children}, index + 1
            child, index = _read_span(spans, index)
            values.append(child["value"])
            children.append(child)
    return {"value": _atom_value(x), "span": _span_payload(head, head), "children": []}, index + 1


def parse(s):
    t = tokenize(s); out = []
    while t: out.append(_read(t))
    return out


def parse_spans(s):
    spans = tokenize_spans(s)
    out = []
    index = 0
    while index < len(spans):
        item, index = _read_span(spans, index)
        out.append(item)
    return out


class LoomError(Exception): pass


class Closure:                                          # an inline lambda evaluated as a VALUE — captures its env
    __slots__ = ("params", "body", "env")
    def __init__(self, params, body, env): self.params, self.body, self.env = params, body, env


def latent_of(arg, fns, penv, errs):
    """Latent effect-set of a function passed as a value: a named fn, a passed-through fn param, or an inline lambda."""
    if _is_symbol(arg):
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
    if isinstance(h, list):
        add(_ucount(h, fns, penv))
        for a in node[1:]: add(_ucount(a, fns, penv))
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
    if isinstance(h, list):
        add(_ncount(h, fns, penv))
        for a in node[1:]: add(_ncount(a, fns, penv))
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
    if _is_symbol(node): return set(penv.get(node, ()))   # a variable reference carries its bound provenance (taint)
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
    if node[0] in ("seam", "seam1", "seamN"):  # D27/D28: a (vouch ROLE WHO COMP) seam clause names a non-ai authority WHO that SIGNS a
        vmap = {}; sbody = []         #   specific foreign COMP, so (ffi COMP ..) DIRECTLY in this (incl. METERED seamN) seam body
        for x in (node[3:] if node[0] == "seamN" else node[2:]):   # carries WHO's anchor instead of the D26 strip -- D28 metered attestation
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
    if _is_symbol(node): return set(penv.get(node, ()))
    if not isinstance(node, list) or not node: return set()
    if node[0] == "by":
        s = {(node[1], node[2])}
        for x in node[3:]: s |= roles_of(x, penv)
        return s
    if node[0] == "recall":  # D24: no role vouch survives a persistence boundary -> recalled data carries NO role
        return set()
    if node[0] == "ffi":  # D26: no role vouch survives the FOREIGN boundary either -> ffi result carries NO role
        return set()
    if node[0] in ("seam", "seam1", "seamN"):  # D27/D28: (vouch ROLE WHO COMP) re-grants (ROLE, WHO) to (ffi COMP ..) in body (incl. metered seamN)
        vmap = {}; sbody = []
        for x in (node[3:] if node[0] == "seamN" else node[2:]):
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
            if need is not None and len(tb) == 1 and _is_symbol(tb[0]) and tb[0] in params:
                req[tb[0]] = max(req.get(tb[0], 0), need)
        elif fns and _is_symbol(n[0]) and n[0] in fns:           # D25: inherit a callee's obligation when we pass our
            callee = fns[n[0]]; pn = [pname(p) for p in callee["params"]]   #   OWN raw param into its trusted slot (multi-hop relay)
            for pp, cneed in callee.get("preq", {}).items():
                cix = pn.index(pp)
                if cix + 1 < len(n) and _is_symbol(n[cix+1]) and n[cix+1] in params:
                    req[n[cix+1]] = max(req.get(n[cix+1], 0), cneed)
        for c in n[1:]: walk(c)
    for b in body: walk(b)
    return req

def _value_uses(node, obligated):
    """D22 soundness: names in `obligated` (fns carrying a provenance obligation) used as a VALUE — ANY
    position but a direct-call head. Such a use (passed as an arg / returned) would escape call-site
    discharge via an indirect call, so it is REFUSED. A direct-call head is exempt (it is discharged)."""
    if _is_symbol(node): return {node} if node in obligated else set()
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
    if not _checker_state().policy["rank"]: return up
    m = {k: set(v) for k, v in up.items()}
    for lo, his in _checker_state().policy["rank"].items(): m.setdefault(lo, set()).update(his)
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
            missing, authors = _quorum_check(set(role_spec[1:]), up, body, _checker_state().taint_role)
            if missing:
                errs.append(f"seam grant denied: capability {sorted(decl)} requires role(s) {sorted(missing)} — not independently vouched (need a non-ai author, or a subsuming role)")
            elif len(authors) < 2:
                errs.append(f"seam grant denied: capability {sorted(decl)} vouched by a single author {sorted(authors)} — needs >= 2 independent authors")
        for (eff, role) in needs:                       # D13: a SPECIFIC effect is granted only if its OWN role vouches for it
            if eff not in decl:
                errs.append(f"seam: (needs {eff} {role}) names {eff}, not granted by this seam {sorted(decl)}")
            elif _quorum_check({role}, up, body, _checker_state().taint_role)[0]:    # missing non-empty => role not covered (by a non-ai author or a subsuming role)
                errs.append(f"seam grant denied: effect {eff} requires role '{role}' — not vouched by a non-ai author (or a subsuming role)")
        for eff in sorted(decl):                        # D15/D17: program-wide (require EFF spec) per granted effect
            for spec in sorted(_checker_state().policy["require"].get(eff, ()), key=str):
                if isinstance(spec, int):               # D17: the grant needs >= N DISTINCT independent (non-ai) authors
                    independent = {p for x in body for p in prov_of(x, _checker_state().taint_prov)} - {"ai"}
                    if len(independent) < spec:
                        errs.append(f"policy: effect {eff} requires >= {spec} independent authors (program-wide (require {eff} {spec})), got {len(independent)} {sorted(independent) or '(none)'}")
                elif _quorum_check({spec}, up, body, _checker_state().taint_role)[0]:  # D15: a SPECIFIC role must be covered (subsumption applies)
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
            direct_count = nc.get(E, 0)
            got = _NCAP if opaque else direct_count
            if K < 0 or K >= _NCAP or got > K:
                errs.append(_meter_error(E, K, direct_count, body, fns, penv))
        return decl
    if h == "repro":                                    # (repro body..) -- pass-10 REPRODUCIBILITY region: this path must be
        inner = set()                                   # re-DERIVABLE, not merely signed. No nondeterministic Rand may influence it;
        for x in node[1:]: inner |= infer(x, fns, errs, penv)   # a handle CANNOT launder Rand to satisfy repro (the runtime op still
        laundered = set()                               # fires -- the seal lesson), so we re-add any Rand an inner handle dropped;
        for x in node[1:]: laundered |= _sealed_discharges(x, {"Rand"})   # a (with Rand det-fn) IS reproducible (allowed).
        nd = (inner | laundered) & {"Rand"}
        if nd:
            errs.append(f"repro region performs nondeterministic {sorted(nd)} -- not reproducible/falsifiable (a Rand draw is a hidden input: capture it, remove it, or reinterpret it with `with`)")
        return inner
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
        for frame in reversed(_checker_state().renv):                   # (a typed resource unifies linear use-once WITH an effect)
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
        _checker_state().renv.append({rname: reffs})                    # in scope, (use rname) performs reffs
        try:
            eff = set()
            for x in node[2:]: eff |= infer(x, fns, errs, penv)
        finally:
            _checker_state().renv.pop()
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
        sp = _checker_state().taint_prov.get(name, _MISS); sr = _checker_state().taint_role.get(name, _MISS)   # D19: bind name's provenance for the body's scope
        _checker_state().taint_prov[name] = prov_of(val, _checker_state().taint_prov); _checker_state().taint_role[name] = roles_of(val, _checker_state().taint_role)   # (chained lets resolve)
        try:
            for x in node[2:]: eff |= infer(x, fns, errs, bp)   # a let-bound function becomes callable; the gate sees the taint
        finally:                                        # restore (shadowing-safe), so the binding never leaks past its scope
            (_checker_state().taint_prov.__setitem__(name, sp) if sp is not _MISS else _checker_state().taint_prov.pop(name, None))
            (_checker_state().taint_role.__setitem__(name, sr) if sr is not _MISS else _checker_state().taint_role.pop(name, None))
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
    if isinstance(h, list):                             # direct application of an inline closure / callable expression
        eff = latent_of(h, fns, penv, errs)
        for a in node[1:]: eff |= infer(a, fns, errs, penv)
        return eff
    if h == "trust":                                    # (trust SPEC? expr) — D9/D10 GATE vs CIRCULAR / under-corroborated trust
        spec = node[1] if len(node) > 1 else None
        is_roles = isinstance(spec, list) and len(spec) > 0 and spec[0] == "roles"
        if is_roles:                                     # D10 ROLE-QUORUM + D11 role LATTICE: (trust (roles ..) (sub LOW HIGH).. e)
            _, up, _, body = _roleclauses(node[1:])       # node[1] IS the (roles ..) spec — consume it + any (sub LOW HIGH) clauses
            roles_req = set(spec[1:])                     # up[LOW] = {HIGH..}: a higher role can STAND IN FOR a lower one (D11)
            missing, authors = _quorum_check(roles_req, _with_policy_rank(up), body, _checker_state().taint_role)   # D15: ranks; D19: taint env
            if missing:
                errs.append(f"trust gate (roles): role(s) {sorted(missing)} not independently covered (need a non-ai author, or a role that subsumes it) — self-certified")
            elif len(authors) < 2:
                errs.append(f"trust gate (roles): required roles satisfied by a single author {sorted(authors)} — circular trust (one author owns code+spec+proof)")
        else:                                            # D9 COUNT form: (trust [N] e) — value must carry >= N DISTINCT
            has_n = isinstance(spec, int)                #                 INDEPENDENT anchors (provenance != 'ai'); N defaults 1
            need = spec if has_n else 1
            body = node[2:] if has_n else node[1:]       # independence is a QUANTITY = count of distinct non-ai sources;
            independent = {p for x in body for p in prov_of(x, _checker_state().taint_prov)} - {"ai"} # SET; D19: taint env so bound vars carry prov
            p0 = body[0] if len(body) == 1 else None     # D22: (trust [N] raw-param) DEFERS to the call site, where
            deferred = _is_symbol(p0) and p0 in _checker_state().policy.get("params", set()) and p0 not in _checker_state().taint_prov  # the arg's provenance discharges it; only a RAW param (untainted + unshadowed) defers
            if len(independent) < need and not deferred:
                errs.append(f"trust gate: need >= {need} independent anchor(s), got {len(independent)} {sorted(independent) or '(none)'} — value too self-referential / under-corroborated")
        eff = set()
        for x in body: eff |= infer(x, fns, errs, penv)
        return eff
    if h == "asm":
        error = asm_validation_error(node)
        if error:
            errs.append(error)
            return set()
        spec = asm_metadata(node)
        eff = set()
        for x in node[3:]: eff |= infer(x, fns, errs, penv)
        eff |= set(spec["effects"])
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
            if _is_symbol(arg) and arg in _checker_state().policy.get("params", set()) and arg not in _checker_state().taint_prov:
                continue                                             # D25: arg is OUR OWN raw param -> obligation rides up via our preq (deferred to callers)
            anchors = (prov_of(arg, _checker_state().taint_prov) - {"ai"}) if arg is not None else set()
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


def _meter_error(E, K, direct_count, body, fns, penv):
    if K < 0 or K >= _NCAP:
        return f"metered capability {E} has invalid quantum {K} (expected 0..{_NCAP - 1})"
    opaque = []
    if any(_has_head(x, "with") for x in body): opaque.append("with")
    if any(_has_head(x, "handle") for x in body): opaque.append("handle")
    if any(_ncount(x, fns, penv).get(E, 0) >= _NCAP for x in body): opaque.append("call/recursion/higher-order")
    if opaque:
        counted = f"counted {direct_count} direct use(s); " if direct_count else ""
        return f"metered capability {E} used more than its quantum {K} ({counted}meter became opaque via {', '.join(opaque)}; fail-closed)"
    return f"metered capability {E} used more than its quantum {K} (counted {direct_count} direct use(s) in the seam body)"


def _check_program(program):
    """Returns (fns, errors). errors empty == program type/effect-checks (is accepted)."""
    _checker_state().policy["rank"] = {}; _checker_state().policy["require"] = {}; _checker_state().policy["forbid"] = set(); _checker_state().policy["author"] = {}; _checker_state().policy["confine"] = []; _checker_state().policy["seal"] = set()   # D15/D16/D20/D22: RESET policy first (never leaks between programs)
    _checker_state().taint_prov.clear(); _checker_state().taint_role.clear()             # D19: RESET cross-statement taint env
    for top in program:                                  # collect (rank LOW HIGH) / (require EFF role) / (forbid EFF) BEFORE inference
        if isinstance(top, list) and len(top) >= 3 and top[0] == "rank":
            _checker_state().policy["rank"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "require":
            _checker_state().policy["require"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "forbid":
            _checker_state().policy["forbid"].add(top[1])
        elif isinstance(top, list) and len(top) >= 4 and top[0] == "author":   # D20: (author NAME role WHO)
            _checker_state().policy["author"].setdefault(top[1], set()).add((top[2], top[3]))
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "confine":   # D20: (confine EFF role)
            _checker_state().policy["confine"].append((top[1], top[2]))
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "seal":   # D22: (seal EFF) -- complete-mediation: refuse a static-only discharge
            _checker_state().policy["seal"].add(top[1])
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
    errors = _int_literal_errors(program)
    for n, i in fns.items():
        _checker_state().policy["params"] = {pname(p) for p in i["params"]}     # D22: params of THIS fn -> a (trust raw-param) defers to its callers
        for b in i["fn"][2:]: infer(b, fns, errors, i["penv"])   # collect seam/handle/with/lambda/unresolved violations + discharge obligations
        for b in i["fn"][2:]:                           # D22 soundness: an obligation-bearing fn used as a VALUE escapes discharge
            for nm in _value_uses(b, _obl): errors.append(f"{n}: '{nm}' carries a provenance obligation {sorted(fns[nm]['preq'])} and is used as a value — call it directly so it is discharged at the call site")
        eff = i["eff"]
        if "?" in eff:                                  # an opaque foreign 'ffi' that no seam ever granted authority to
            errors.append(f"{n}: foreign 'ffi' call has no capability seam (wrap it: (seam (..) ...))")
            eff = eff - {"?"}
        if eff - i["decl"]:                                 # CEILING: a capability you may not exceed (upper bound)
            errors.append(f"{n}: performs undeclared {sorted(eff - i['decl'])} (declared {sorted(i['decl'])})")
        banned = eff & _checker_state().policy["forbid"]                    # D16: a program-wide (forbid EFF) — the effect must NOT escape into
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
    if _checker_state().policy["confine"]:                              # D20: capability CONFINEMENT by author — the COMPOSITION GRAPH
        up = _with_policy_rank({})                      # program-wide (rank ..) edges apply to clearance subsumption too
        for eff, role in _checker_state().policy["confine"]:
            for n_, i in fns.items():
                if eff in i["eff"] and eff in _direct_effects(i["fn"]):   # this defx WIELDS the confined effect directly
                    if not _author_covers(_checker_state().policy["author"].get(n_, {("ai", "ai")}), role, up):
                        errors.append(f"{n_}: wields confined effect {eff} but is not authored by a cleared '{role}' "
                                      f"(program-wide (confine {eff} {role})) — uncleared component in the capability graph")
    if _checker_state().policy["seal"]:                                 # D22: COMPLETE MEDIATION -- a sealed effect may not be silently
        for n_, i in fns.items():                       # dropped by `handle` (a static-only discharge that still FIRES at
            bad = _sealed_discharges(i["fn"], _checker_state().policy["seal"])   # runtime for a non-IO effect -- the unfireable-kernel gap)
            if bad:
                errors.append(f"{n_}: discharges sealed effect(s) {sorted(bad)} via handle "
                    f"(program-wide (seal {sorted(bad)[0]})) -- a sealed effect may not be dropped to nothing; "
                    f"keep it in the accountable row or genuinely reinterpret it with `with`")
    if "declassify" in _checker_state().policy["forbid"]:               # D23: NEGATIVE trust policy -- (forbid declassify) bans the D21
        for n_, i in fns.items():                       # laundering hatch program-wide. A high-assurance codebase can
            if any(_has_head(b, "declassify") for b in i["fn"][2:]):   # guarantee NO ai-derived value is rubber-stamped
                errors.append(f"{n_}: uses (declassify ..) but it is forbidden program-wide (forbid declassify) -- no ai-derived value may be laundered into trust; remove the declassify or lift the policy")
    return fns, errors


def check(program):
    """Check one program with policy, resource, and taint state isolated from every other invocation."""
    token = _CHECKER_STATE.set(_CheckerState())
    try:
        return _check_program(program)
    finally:
        _CHECKER_STATE.reset(token)


def call_fn(val, args, fns, out, handlers):
    """Apply a function VALUE (a Closure or a named-fn string) to already-evaluated args."""
    if isinstance(val, Closure):
        loc = {**val.env, **dict(zip([pname(p) for p in val.params], args))}; body = val.body
    elif _is_symbol(val) and val in fns:
        fn = fns[val]["fn"]; loc = dict(zip([pname(p) for p in fn[1]], args)); body = fn[2:]
    else:
        raise LoomError(f"not a function: {val}")
    r = None
    for b in body: r = ev(b, loc, fns, out, handlers)
    return r


def ev(node, env, fns, out, handlers=None):
    handlers = handlers or {}
    if isinstance(node, int): return node
    if _is_symbol(node): return env.get(node, node)
    if type(node) is str: return node
    h = node[0]
    if h == "fn": return Closure(node[1], node[2:], env)   # a lambda literal evaluates to a closure over env
    if h == 'seamN': return ev(['seam'] + node[2:], env, fns, out, handlers)   # D27 meter runs as a seam (cap stack); the quantum is a static check
    if h == 'repro':                                    # pass-10 reproducibility region: value-transparent at runtime (a static-only assertion)
        r = None
        for x in node[1:]: r = ev(x, env, fns, out, handlers)
        return r
    if h == "seam" or h == "seam1":                     # narrow runtime authority to exactly the granted row, then run
        caps = _runtime_state().caps
        caps.append(set(node[1]) - {"Pure"})
        try:
            r = None
            for x in _roleclauses(node[2:])[3]: r = ev(x, env, fns, out, handlers)   # skip D12/D13 (roles..)/(sub..)/(needs..) clauses
        finally:
            caps.pop()
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
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise LoomError(error)
        spec = asm_metadata(node)
        args = [ev(x, env, fns, out, handlers) for x in node[3:]]
        if spec["portable_op"] == "add": return _i31(args[0] + args[1])
        if spec["portable_op"] == "sub": return _i31(args[0] - args[1])
        if spec["portable_op"] == "mul": return _i31(args[0] * args[1])
        if spec["portable_op"] == "eq": return 1 if args[0] == args[1] else 0
        if spec["portable_op"] == "lt_s": return 1 if args[0] < args[1] else 0
        if spec["portable_op"] == "gt_s": return 1 if args[0] > args[1] else 0
        raise LoomError("asm: registered intrinsic has no runtime lowering")
    a = [ev(x, env, fns, out, handlers) for x in node[1:]]
    if h == "+": return _i31(sum(a))
    if h == "-": return _i31(a[0] - a[1])
    if h == "*":
        r = 1
        for x in a: r = _i31(r * x)
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
        return ("Net", a[0])
    if h == "alloc":
        if not _cap_ok("Alloc"): raise LoomError("capability denied: Alloc not granted by enclosing seam")
        return list(range(a[0])) if a else []
    if h == "rand":                                     # nondeterminism: only if Rand is granted by the enclosing seam
        if not _cap_ok("Rand"): raise LoomError("capability denied: Rand not granted by enclosing seam")
        return ("Rand", 0)                              # deterministic opaque value — the point is effect-tracking, not real RNG
    fv = None                                           # resolve the head to a function: name, var->name, or closure
    if _is_symbol(h):
        if h in fns: fv = fns[h]
        else:
            g = env.get(h)
            if _is_symbol(g) and g in fns: fv = fns[g]
            elif isinstance(g, Closure): fv = g
    elif isinstance(h, list):                           # ((fn ..) args) — apply the result of an expression
        hv = ev(h, env, fns, out, handlers)
        fv = hv if isinstance(hv, Closure) else (fns[hv] if _is_symbol(hv) and hv in fns else None)
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
    token = _RUNTIME_STATE.set(_RuntimeState())
    try:
        out = []
        call_ast = parse(call_src); _check_call_literals(call_ast)
        return ev(call_ast[0], {}, fns, out), out
    finally:
        _RUNTIME_STATE.reset(token)


# ---- BACKEND: compile CHECKED LOOM to portable target source (v0 target = Python; same emit pattern -> JS/C/WASM).
# "AI proposes -> the compiler DISPOSES -> and EMITS verified code that runs anywhere." Covers the computational core.
def _emit(node):
    if isinstance(node, int): return str(node)
    if type(node) is str: return repr(node)                            # string literal
    if _is_symbol(node): return node                                   # variable / symbol
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise LoomError(error)
        spec = asm_metadata(node)
        if spec["portable_op"] == "add": return f"_i31({_emit(node[3])}+{_emit(node[4])})"
        if spec["portable_op"] == "sub": return f"_i31({_emit(node[3])}-{_emit(node[4])})"
        if spec["portable_op"] == "mul": return f"_i31({_emit(node[3])}*{_emit(node[4])})"
        if spec["portable_op"] == "eq": return f"(1 if ({_emit(node[3])}=={_emit(node[4])}) else 0)"
        if spec["portable_op"] == "lt_s": return f"(1 if ({_emit(node[3])}<{_emit(node[4])}) else 0)"
        if spec["portable_op"] == "gt_s": return f"(1 if ({_emit(node[3])}>{_emit(node[4])}) else 0)"
        raise LoomError("asm: registered intrinsic has no Python lowering")
    if h == "+": return "_i31(" + "+".join(_emit(a) for a in node[1:]) + ")"
    if h == "-": return f"_i31(({_emit(node[1])})-({_emit(node[2])}))"
    if h == "*": return "_i31(" + "*".join(_emit(a) for a in node[1:]) + ")"
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
    if h == "repro": return _emit(node[1:][-1])  # value-transparent (reproducibility is a static-only assertion)
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
    lines = ["_sd = [0]", "_h = {}", f"_INT_MIN={INT_MIN}; _INT_MOD={_INT_MOD}",
             "def _i31(n): return ((n-_INT_MIN)%_INT_MOD)+_INT_MIN",
             "def _route(name, args, default):\n    if name in _h:\n        f = _h.pop(name)\n        try: return f(*args)\n        finally: _h[name] = f\n    return default()",
             "def _with(name, hf, thunk):\n    had = name in _h; prev = _h.get(name)\n    _h[name] = hf\n    try: return thunk()\n    finally:\n        if had: _h[name] = prev\n        else: _h.pop(name, None)",
             "def _p(x): return _route('print', (x,), lambda: (print(x) if _sd[0]==0 else None) or x)",
             "def _handle(t):\n    _sd[0]+=1\n    try: return t()\n    finally: _sd[0]-=1",
             "def _nm(t):\n    raise Exception('no match arm for '+str(t))",
             "def _net(u): return _route('net', (u,), lambda: ('Net', u))",
             "def _alloc(n): return _route('alloc', (n,), lambda: list(range(n)))",
             "def _rand(): return _route('rand', (), lambda: ('Rand', 0))",
             "_caps = []",
             "def _cap_ok(e): return (not _caps) or (e in _caps[-1])",
             "def _seam(row, thunk): _caps.append(set(row)); _r = thunk(); _caps.pop(); return _r",
             "_FOREIGN = {'logger': (lambda a: (a[0], print('foreign:'+str(a[0])) if (_cap_ok('IO') and _sd[0]==0) else None)[0]), 'lib': (lambda a: a[0] if a else 0), 'x': (lambda a: a[0] if a else 0), 'other': (lambda a: a[0] if a else 0)}",
             "def _ffi(name, args): return _FOREIGN[name](args)"]   # FFI codegen: cap stack (seam SANDBOX) + foreign registry -> ffi mirrors the interpreter (foreign I/O fires only if its seam granted it)
    for top in parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(pname(p) for p in fn[1]); body = _emit(fn[2:][-1]) if fn[2:] else "None"
            lines.append(f"def {top[1]}({ps}): return {body}")
    return "\n".join(lines)

def run_compiled(program_src, call_src):
    """Compile to Python, run it; return (value, output-lines) — proof the emitted code MATCHES the interpreter."""
    import io, contextlib
    call_ast = parse(call_src); _check_call_literals(call_ast)
    ns = {}; exec(compile_py(program_src), ns); buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        val = eval(_emit(call_ast[0]), ns)
    return val, buf.getvalue().splitlines()


# ---- SECOND TARGET: JavaScript. Same emit pattern -> a DIFFERENT platform (browser / Node / any OS) => cross-platform. ----
def _emit_js(node):
    if isinstance(node, int): return str(node)
    if type(node) is str: return repr(node)
    if _is_symbol(node): return node
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise LoomError(error)
        spec = asm_metadata(node)
        if spec["portable_op"] == "add": return f"_i31({_emit_js(node[3])}+{_emit_js(node[4])})"
        if spec["portable_op"] == "sub": return f"_i31({_emit_js(node[3])}-{_emit_js(node[4])})"
        if spec["portable_op"] == "mul": return f"_imul({_emit_js(node[3])},{_emit_js(node[4])})"
        if spec["portable_op"] == "eq": return f"(({_emit_js(node[3])}==={_emit_js(node[4])})?1:0)"
        if spec["portable_op"] == "lt_s": return f"(({_emit_js(node[3])}<{_emit_js(node[4])})?1:0)"
        if spec["portable_op"] == "gt_s": return f"(({_emit_js(node[3])}>{_emit_js(node[4])})?1:0)"
        raise LoomError("asm: registered intrinsic has no JavaScript lowering")
    if h == "+": return "_i31(" + "+".join(_emit_js(a) for a in node[1:]) + ")"
    if h == "-": return f"_i31(({_emit_js(node[1])})-({_emit_js(node[2])}))"
    if h == "*":
        out = _emit_js(node[1])
        for arg in node[2:]: out = f"_imul({out},{_emit_js(arg)})"
        return out
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
    if h == "repro": return _emit_js(node[1:][-1])  # value-transparent (reproducibility is a static-only assertion)
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
             "function _i31(n){ return (n<<1)>>1; }",
             "function _imul(a,b){ return _i31(Math.imul(a,b)); }",
             "function _route(name,args,d){ if(name in _h){ let f=_h[name]; delete _h[name]; try{ return f(...args); } finally{ _h[name]=f; } } return d(); }",
             "function _with(name,hf,thunk){ let had=(name in _h), prev=_h[name]; _h[name]=hf; try{ return thunk(); } finally{ if(had) _h[name]=prev; else delete _h[name]; } }",
             "function _p(x){ return _route('print',[x], ()=>{ if(_sd===0) console.log(x); return x; }); }",
             "function _handle(t){ _sd++; try{ return t(); } finally{ _sd--; } }",
             "function _nm(t){ throw new Error('no match arm for '+t); }",
             "function _net(u){ return _route('net',[u], ()=>['Net',u]); }", "function _alloc(n){ return _route('alloc',[n], ()=>Array.from({length:n},(_,i)=>i)); }", "function _rand(){ return _route('rand',[], ()=>['Rand',0]); }",
             "let _caps=[];",
             "function _cap_ok(e){ return (_caps.length===0)||_caps[_caps.length-1].has(e); }",
             "function _seam(row,thunk){ _caps.push(new Set(row)); let _r=thunk(); _caps.pop(); return _r; }",
             "const _FOREIGN={ logger:(a)=>{ if(_cap_ok('IO')&&_sd===0) console.log('foreign:'+String(a[0])); return a[0]; }, lib:(a)=>a.length?a[0]:0, x:(a)=>a.length?a[0]:0, other:(a)=>a.length?a[0]:0 };",
             "function _ffi(name,args){ return _FOREIGN[name](args); }"]  # FFI codegen (JS): cap stack + foreign registry -> ffi mirrors the interpreter
    for top in parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(pname(p) for p in fn[1]); body = _emit_js(fn[2:][-1]) if fn[2:] else "null"
            lines.append(f"function {top[1]}({ps}){{ return {body}; }}")
    return "\n".join(lines)

def run_js(program_src, call_src):
    """Compile to JS, run through Node; return (value, output-lines) — proof the JS target matches the interpreter. Needs node."""
    import subprocess, json as _json
    def _norm(v):
        if isinstance(v, dict):
            return {k: _norm(x) for k, x in v.items()}
        if isinstance(v, list):
            vv = [_norm(x) for x in v]
            return tuple(vv) if len(vv) == 2 and isinstance(vv[0], str) and vv[0][:1].isupper() else vv
        return v
    call_ast = parse(call_src); _check_call_literals(call_ast)
    js = compile_js(program_src) + "\nconsole.log('__R__'+JSON.stringify(" + _emit_js(call_ast[0]) + "))"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=15)
    if r.returncode != 0: raise LoomError("node: " + r.stderr.strip()[:200])
    lines = r.stdout.splitlines(); val = None; out = []
    for ln in lines:
        if ln.startswith("__R__"): val = _norm(_json.loads(ln[5:]))
        else: out.append(ln)
    return val, out


# ---- THIRD TARGET: WebAssembly. Checked LOOM compiles to real wasm bytes (Node WebAssembly, zero dependencies) plus
#      a human-readable WAT "assembler". Tagged i32 values separate immediate integers from heap pointers; heap kinds
#      cover lists, records, variants, closures, and effect boxes. Unsupported forms fail closed with LoomError. ----
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
_WASM_IMPORTS = 8
_WASM_I_PUSH = 0
_WASM_I_POP = 1
_WASM_I_CURRENT = 2
_WASM_I_PRINT = 3
_WASM_I_PUSH_CAPS = 4
_WASM_I_POP_CAPS = 5
_WASM_I_HAS_CAP = 6
_WASM_I_FFI = 7
_WASM_ABI_VERSION = 1
EFFECT_IDS = {"IO": 0, "Net": 1, "Rand": 2, "Alloc": 3}
_WASM_NIL = 3
_WASM_K_LIST = 1
_WASM_K_RECORD = 2
_WASM_K_VARIANT = 3
_WASM_K_EFFECT = 4
_WASM_K_RESOURCE = 5
_WASM_K_STRING = 6

def _wasm_const(n):
    return b"\x41" + _leb_s(n)

def _wasm_int(n):
    return _wasm_const(n << 1)

def _wasm_i32(n):
    return int(n).to_bytes(4, "little", signed=True)

def _wat_bytes(bs):
    return '"' + "".join(f"\\{b:02x}" for b in bs) + '"'

def _wasm_unptr():
    return _wasm_const(-2) + b"\x71"                    # tagged pointer -> aligned heap address

def _wasm_capmask(effs):
    mask = 0
    for eff in set(effs) - {"Pure"}:
        if eff in EFFECT_IDS:
            mask |= 1 << EFFECT_IDS[eff]
    return mask

def _wasm_require_cap(effid):
    return b"\x41" + _leb_s(effid) + b"\x10" + _leb_u(_WASM_I_HAS_CAP) + b"\x45\x04\x40\x00\x0b"

def _wasm_transparent_body(node):
    head = node[0]
    if head in ("resource", "prov", "declassify"):
        return node[2:]
    if head == "by":
        return node[3:]
    if head in ("recall", "repro"):
        return node[1:]
    if head == "trust":
        spec = node[1] if len(node) > 1 else None
        if isinstance(spec, int):
            return node[2:]
        if isinstance(spec, list) and spec and spec[0] == "roles":
            body = node[2:]
            while body and isinstance(body[0], list) and len(body[0]) >= 3 and body[0][0] == "sub":
                body = body[1:]
            return body
        return node[1:]
    return None

def _emit_wasm_seq(ctx, nodes, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env=None, handled_effs=None, with_handlers=None):
    out = b""
    for i, child in enumerate(nodes):
        out += _emit_wasm(ctx, child, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        if i + 1 < len(nodes):
            out += b"\x1a"
    return out

def _emit_wasm(ctx, node, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env=None, handled_effs=None, with_handlers=None):        # body bytes; lmap: name->local idx; helpers: cons/rec/get; tags/fields: ids; si: scrutinee local
    callable_env = callable_env or set()
    handled_effs = handled_effs or set()
    with_handlers = with_handlers or {}
    if isinstance(node, int): return _wasm_int(node)                    # immediate integer: n << 1, low bit clear
    if _is_symbol(node):
        if node in lmap: return b"\x20" + _leb_u(lmap[node])            # local.get (param / let / match-bound)
        if node in ctx.topdefs:
            spec = ctx.topdefs[node]
            return _emit_wasm(ctx, ["record", ["code", spec["id"]]], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        raise LoomError("wasm: free variable " + node)
    if type(node) is str:
        return _wasm_const(ctx.string_layout[node]["tagged"])
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise LoomError(error)
        spec = asm_metadata(node)
        rhs = _emit_wasm(ctx, node[4], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        if spec["wasm_rhs"] == "unbox_i31": rhs += _wasm_const(1) + b"\x75"
        out = (_emit_wasm(ctx, node[3], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
               + rhs + bytes([spec["wasm_opcode"]]))
        if spec["wasm_result"] == "tag_i31": out += _wasm_const(1) + b"\x74"
        return out
    if isinstance(h, list):                                             # ((fn ..) args) — compute head, then apply as a closure
        arity = len(node[1:])
        apply_id = ctx.apply_ids.get(arity)
        if apply_id is None:
            raise LoomError("wasm closures currently support this arity only when an apply helper exists")
        out = _emit_wasm(ctx, h, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        for a in node[1:]:
            out += _emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x10" + _leb_u(apply_id + _WASM_IMPORTS)
    if h == "fn":
        spec = ctx.closures.get(id(node))
        if spec is None: raise LoomError("wasm: missing closure spec")
        caps = spec["captures"]
        rec = [["code", spec["id"]]] + [[f"e{i}", caps[i]] for i in range(len(caps))]
        return _emit_wasm(ctx, ["record"] + rec, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
    if h in ("+", "*"):
        out = _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        for a in node[2:]:
            out += _emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
            if h == "*": out += _wasm_const(1) + b"\x75"              # unbox rhs: (2a * b) = 2(ab)
            out += bytes([_WBIN[h]])
        return out
    if h == "-": return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x6b"
    if h in _WCMP: return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + bytes([_WCMP[h]]) + _wasm_const(1) + b"\x74"
    if h == "if":                                                       # if (result i32) THEN else ELSE end
        return (_emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x04\x7f" + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
                + b"\x05" + _emit_wasm(ctx, node[3], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x0b")
    if h == "let":                                                      # (let (name val) body..) -> val; local.set name; body
        out = _emit_wasm(ctx, node[1][1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x21" + _leb_u(lmap[node[1][0]])
        ncall = set(callable_env)
        if _wasm_is_closure_expr(ctx, node[1][1], callable_env): ncall.add(node[1][0])
        for b in node[2:]: out += _emit_wasm(ctx, b, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, ncall, handled_effs, with_handlers)
        return out
    if h == "seamN":
        return _emit_wasm(ctx, ["seam"] + node[2:], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
    if h in ("seam", "seam1"):
        body = _roleclauses(node[2:])[3]
        out = b"\x41" + _leb_s(_wasm_capmask(node[1])) + b"\x10" + _leb_u(_WASM_I_PUSH_CAPS) + b"\x1a"
        for b in body:
            out += _emit_wasm(ctx, b, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x10" + _leb_u(_WASM_I_POP_CAPS) + b"\x1a"
    if h == "handle":
        body_eff = set(node[1]) & {"IO"}
        nh = set(handled_effs) | body_eff
        out = b""
        for b in node[2:]:
            out += _emit_wasm(ctx, b, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, nh, with_handlers)
        return out
    if h == "with":
        if node[1] not in OP:
            raise LoomError("wasm: with currently supports builtin effects only")
        effid = EFFECT_IDS[node[1]]
        out = b"\x41" + _leb_s(effid) + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(_WASM_I_PUSH) + b"\x1a"
        for b in node[3:]:
            out += _emit_wasm(ctx, b, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x41" + _leb_s(effid) + b"\x10" + _leb_u(_WASM_I_POP) + b"\x1a"
    if h == "print":
        apply1_id = ctx.apply_ids.get(1, ctx.apply1_id)
        if "IO" in with_handlers:
            return _emit_wasm(ctx, with_handlers["IO"], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS)
        out = _wasm_require_cap(EFFECT_IDS["IO"]) + b"\x41" + _leb_s(EFFECT_IDS["IO"]) + b"\x10" + _leb_u(_WASM_I_CURRENT) + b"\x22" + _leb_u(lmap["hd"]) + b"\x45\x04\x7f"
        out += _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        out += b"\x10" + _leb_u(_WASM_I_PRINT) + b"\x05" + b"\x20" + _leb_u(lmap["hd"]) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS) + b"\x0b"
        if "IO" in handled_effs:
            return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out
    if h == "net":
        apply1_id = ctx.apply_ids.get(1, ctx.apply1_id)
        if "Net" in with_handlers:
            return _emit_wasm(ctx, with_handlers["Net"], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS)
        out = _wasm_require_cap(EFFECT_IDS["Net"]) + b"\x41" + _leb_s(EFFECT_IDS["Net"]) + b"\x10" + _leb_u(_WASM_I_CURRENT) + b"\x22" + _leb_u(lmap["hd"]) + b"\x45\x04\x7f"
        out += b"\x41" + _leb_s(EFFECT_IDS["Net"]) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(cons_i + 1 + _WASM_IMPORTS)
        out += b"\x05" + b"\x20" + _leb_u(lmap["hd"]) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS) + b"\x0b"
        return out
    if h == "rand":
        apply0_id = ctx.apply_ids.get(0)
        if apply0_id is None:
            raise LoomError("wasm: missing arity-0 apply helper")
        if "Rand" in with_handlers:
            return _emit_wasm(ctx, with_handlers["Rand"], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply0_id + _WASM_IMPORTS)
        out = _wasm_require_cap(EFFECT_IDS["Rand"]) + b"\x41" + _leb_s(EFFECT_IDS["Rand"]) + b"\x10" + _leb_u(_WASM_I_CURRENT) + b"\x22" + _leb_u(lmap["hd"]) + b"\x45\x04\x7f"
        out += b"\x41" + _leb_s(EFFECT_IDS["Rand"]) + b"\x41\x00" + b"\x10" + _leb_u(cons_i + 1 + _WASM_IMPORTS)
        out += b"\x05" + b"\x20" + _leb_u(lmap["hd"]) + b"\x10" + _leb_u(apply0_id + _WASM_IMPORTS) + b"\x0b"
        return out
    if h == "alloc":
        apply1_id = ctx.apply_ids.get(1, ctx.apply1_id)
        if "Alloc" in with_handlers:
            return _emit_wasm(ctx, with_handlers["Alloc"], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[1] if len(node) > 1 else 0, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS)
        out = _wasm_require_cap(EFFECT_IDS["Alloc"]) + b"\x41" + _leb_s(EFFECT_IDS["Alloc"]) + b"\x10" + _leb_u(_WASM_I_CURRENT) + b"\x22" + _leb_u(lmap["hd"]) + b"\x45\x04\x7f"
        if len(node) == 1:
            out += _wasm_const(_WASM_NIL)
        else:
            out += (_emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
                    + _wasm_int(0)
                    + b"\x10" + _leb_u(ctx.alloc_id + _WASM_IMPORTS))
        if len(node) == 1:
            out += b"\x05" + b"\x20" + _leb_u(lmap["hd"]) + b"\x41\x00" + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS) + b"\x0b"
        else:
            out += b"\x05" + b"\x20" + _leb_u(lmap["hd"]) + _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(apply1_id + _WASM_IMPORTS) + b"\x0b"
        return out
    transparent_body = _wasm_transparent_body(node)
    if transparent_body is not None:
        return _emit_wasm_seq(ctx, transparent_body, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
    if h == "ffi":
        if type(node[1]) is not str:
            raise LoomError("wasm: ffi name must be a string literal")
        return (_wasm_const(ctx.foreigns[node[1]])
                + _emit_wasm(ctx, ["list"] + node[2:], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
                + _wasm_const(1 if "IO" in handled_effs else 0)
                + b"\x10" + _leb_u(_WASM_I_FFI))
    if h == "use":
        return _wasm_const(ctx.resources[node[1]]) + b"\x10" + _leb_u(ctx.resource_use_id + _WASM_IMPORTS)
    if h == "record":
        if len(node) == 1: return b"\x41\x00"
        items = [fld for fld in node[1:] if isinstance(fld, list) and len(fld) >= 2]
        out = b"\x41\x00"
        for fld in reversed(items):
            out = out + b"\x41" + _leb_s(fields[fld[0]]) + _emit_wasm(ctx, fld[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(rec_i + _WASM_IMPORTS)
        return out
    if h == "get":
        return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x41" + _leb_s(fields[node[2]]) + b"\x10" + _leb_u(get_i + _WASM_IMPORTS)
    if h == "list":                                                     # (list a b ..) -> cons(a, cons(b, .. nil))
        if len(node) == 1: return _wasm_const(_WASM_NIL)
        out = b"".join(_emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) for a in node[1:]) + _wasm_const(_WASM_NIL)
        return out + b"".join(b"\x10" + _leb_u(cons_i + _WASM_IMPORTS) for _ in node[1:])   # fold to the right via $cons
    if h == "cons": return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(cons_i + _WASM_IMPORTS)
    if h == "head": return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _wasm_unptr() + b"\x28\x02\x04"
    if h == "tail": return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _wasm_unptr() + b"\x28\x02\x08"
    if h == "empty": return _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + _wasm_const(_WASM_NIL) + b"\x46" + _wasm_const(1) + b"\x74"
    if h == "variant":
        return _wasm_const(tags[node[1]]) + _emit_wasm(ctx, node[2], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x10" + _leb_u(ctx.variant_id + _WASM_IMPORTS)
    if h == "match":                                                    # scrut->$s; chain: load tag; ==TAG; if (bind payload) body else .. unreachable
        out = _emit_wasm(ctx, node[1], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x21" + _leb_u(si)
        def _arms(a):
            if not a: return b"\x00"                                    # unreachable — no arm matched (the interpreter likewise errors)
            pat, body = a[0][0], a[0][1]
            chk = b"\x20" + _leb_u(si) + _wasm_unptr() + b"\x28\x02\x04" + _wasm_const(tags[pat[0]]) + b"\x46"
            bind = (b"\x20" + _leb_u(si) + _wasm_unptr() + b"\x28\x02\x08" + b"\x21" + _leb_u(lmap[pat[1]])) if len(pat) >= 2 else b""
            return chk + b"\x04\x7f" + bind + _emit_wasm(ctx, body, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) + b"\x05" + _arms(a[1:]) + b"\x0b"
        return out + _arms(node[2:])
    if h in callable_env and h in lmap:                                 # callable local/param -> closure record in a local
        arity = len(node[1:])
        apply_id = ctx.apply_ids.get(arity)
        if apply_id is None:
            raise LoomError("wasm closures currently support this arity only when an apply helper exists")
        out = b"\x20" + _leb_u(lmap[h])
        for a in node[1:]:
            out += _emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x10" + _leb_u(apply_id + _WASM_IMPORTS)
    if h in fmap:                                                       # call $fn  (first-order / recursive)
        return b"".join(_emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) for a in node[1:]) + b"\x10" + _leb_u(fmap[h] + _WASM_IMPORTS)
    raise LoomError("wasm: form not yet in the WASM backend: " + str(h))

def _wasm_defxs(program_src):
    return [t for t in parse(program_src) if isinstance(t, list) and t and t[0] == "defx"]

def _wasm_topdefs(program_src):
    return {t[1]: i for i, t in enumerate(_wasm_defxs(program_src))}

def _wasm_collect_closures(program_src):
    """Collect lambda literals for the WASM closure runtime.
    A lambda captures the current lexical scope by value (all currently-bound locals in scope order)."""
    ds = _wasm_defxs(program_src)
    top = {t[1] for t in ds}
    specs = {}
    order = []

    def _is_closure_expr(node, callable_env):
        if _is_symbol(node):
            return node in callable_env or node in top
        if not isinstance(node, list) or not node:
            return False
        h = node[0]
        if h == "fn":
            return True
        if h == "let":
            return _is_closure_expr(node[1][1], callable_env) or _is_closure_expr(node[2], callable_env) if len(node) > 2 else _is_closure_expr(node[1][1], callable_env)
        if h == "if":
            return _is_closure_expr(node[2], callable_env) and _is_closure_expr(node[3], callable_env)
        if h == "match":
            return all(_is_closure_expr(a[1], callable_env) for a in node[2:] if isinstance(a, list) and len(a) >= 2)
        return False

    def walk(node, scope_names, callable_env):
        if not isinstance(node, list) or not node:
            return
        if isinstance(node[0], list):                      # inline closure in head position: visit the callee expression too
            walk(node[0], scope_names, callable_env)
        h = node[0]
        if h == "fn":
            params = [pname(p) for p in node[1]]
            sid = len(ds) + len(order)
            spec = {
                "id": sid,
                "name": f"lam{len(order)}",
                "node": node,
                "arity": len(params),
                "captures": list(scope_names),
                "scope": list(scope_names),
                "callable": set(callable_env),
            }
            specs[id(node)] = spec
            order.append(spec)
            new_callable = set(callable_env)
            if platent(node[1][0]) is not None if node[1] else False:
                new_callable.add(params[0])
            walk_body(node[2:], scope_names + params, new_callable)
            return
        if h == "let" and len(node) >= 3:
            walk(node[1][1], scope_names, callable_env)
            is_closure = _is_closure_expr(node[1][1], callable_env)
            new_callable = set(callable_env)
            if is_closure:
                new_callable.add(node[1][0])
            walk_body(node[2:], scope_names + [node[1][0]], new_callable)
            return
        if h == "match":
            walk(node[1], scope_names, callable_env)
            for arm in node[2:]:
                if isinstance(arm, list) and len(arm) >= 2:
                    patscope = list(scope_names)
                    if len(arm[0]) >= 2:
                        patscope.append(arm[0][1])
                    walk(arm[1], patscope, callable_env)
            return
        if h == "if":
            walk(node[1], scope_names, callable_env); walk(node[2], scope_names, callable_env); walk(node[3], scope_names, callable_env); return
        if h == "record":
            for fld in node[1:]:
                if isinstance(fld, list) and len(fld) >= 2: walk(fld[1], scope_names, callable_env)
            return
        if h == "variant":
            walk(node[2], scope_names, callable_env); return
        if h == "resource":
            for x in node[2:]: walk(x, scope_names, callable_env)
            return
        if h in ("seam", "seam1", "seamN", "handle", "with", "trust", "prov", "by", "recall", "declassify", "repro"):
            for x in node[1:]: walk(x, scope_names, callable_env)
            return
        for a in node[1:]:
            walk(a, scope_names, callable_env)

    def walk_body(body, scope_names, callable_env):
        for b in body:
            walk(b, scope_names, callable_env)

    for t in ds:
        fn = t[3]
        params = [pname(p) for p in fn[1]]
        callable_env = {pname(p) for p in fn[1] if platent(p) is not None}
        walk_body(fn[2:], params, callable_env)
    return ds, top, specs, order

def _wasm_is_closure_expr(ctx, node, callable_env):
    if _is_symbol(node):
        return node in callable_env or node in ctx.topdefs
    if not isinstance(node, list) or not node:
        return False
    h = node[0]
    if h == "fn":
        return True
    if h == "let":
        return _wasm_is_closure_expr(ctx, node[1][1], callable_env) or (len(node) > 2 and _wasm_is_closure_expr(ctx, node[2], callable_env))
    if h == "if":
        return _wasm_is_closure_expr(ctx, node[2], callable_env) and _wasm_is_closure_expr(ctx, node[3], callable_env)
    if h == "match":
        return all(_wasm_is_closure_expr(ctx, a[1], callable_env) for a in node[2:] if isinstance(a, list) and len(a) >= 2)
    return False

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
        if n and n[0] == "net":
            tags.setdefault("Net", len(tags))
            for a in n[1:]: w(a)
            return
        if n and n[0] == "rand":
            tags.setdefault("Rand", len(tags))
            for a in n[1:]: w(a)
            return
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

def _wasm_fields(program_src, capture_slots=8):            # program-wide field -> integer id (records + get share one numbering)
    fields = {"code": 0}
    for i in range(capture_slots):
        fields[f"e{i}"] = len(fields)
    def w(n):
        if not isinstance(n, list): return
        if n and n[0] == "record":
            for fld in n[1:]:
                if isinstance(fld, list) and len(fld) >= 2:
                    fields.setdefault(fld[0], len(fields))
                    w(fld[1])
        elif n and n[0] == "get":
            if len(n) >= 3 and isinstance(n[2], str): fields.setdefault(n[2], len(fields))
            w(n[1])
        else:
            for a in n: w(a)
    for t in _wasm_defxs(program_src): w(t[3])
    return fields

def _wasm_resources(program_src):
    resources = {}
    def w(n):
        if not isinstance(n, list) or not n:
            return
        if n[0] == "resource":
            spec = n[1]
            name = spec[0] if isinstance(spec, list) else spec
            resources.setdefault(name, len(resources))
            for item in n[2:]:
                w(item)
            return
        if n[0] == "use" and len(n) >= 2 and _is_symbol(n[1]):
            resources.setdefault(n[1], len(resources))
            return
        for a in n:
            w(a)
    for t in _wasm_defxs(program_src):
        w(t[3])
    return resources

def _wasm_foreigns(program_src):
    foreigns = {}
    def w(n):
        if not isinstance(n, list) or not n:
            return
        if n[0] == "ffi" and len(n) >= 2 and type(n[1]) is str:
            foreigns.setdefault(n[1], len(foreigns))
        for a in n[1:]:
            w(a)
    for t in _wasm_defxs(program_src):
        w(t[3])
    return foreigns

def _wasm_strings(program_src):
    strings = {}
    def w(n):
        if type(n) is str:
            strings.setdefault(n, len(strings))
            return
        if not isinstance(n, list):
            return
        for a in n:
            w(a)
    for t in _wasm_defxs(program_src):
        w(t[3])
    return list(strings.keys())

def _wasm_string_layout(strings):
    layout = {}
    hp = 8
    for s in strings:
        raw = s.encode("utf-8")
        obj = hp
        data = obj + 12
        hp = data + len(raw)
        if hp & 3:
            hp += 4 - (hp & 3)
        layout[s] = {"obj": obj, "data": data, "bytes": raw, "tagged": obj | 1}
    return layout, hp


def _wasm_source_maps(program_src, defs):
    node_path_by_id = {}
    span_by_path = {}
    def_paths = {}

    def walk_value(node, path):
        if isinstance(node, list) and path is not None:
            node_path_by_id[id(node)] = path
            for i, child in enumerate(node):
                walk_value(child, path + (i,))

    def walk_span(node, path):
        span_by_path[path] = node["span"]
        for i, child in enumerate(node["children"]):
            walk_span(child, path + (i,))

    for i, node in enumerate(parse_spans(program_src)):
        if isinstance(node["value"], list) and len(node["value"]) >= 2 and node["value"][0] == "defx":
            def_paths[node["value"][1]] = (i,)
        walk_span(node, (i,))
    for node in defs:
        walk_value(node, def_paths.get(node[1]))
    return node_path_by_id, span_by_path


def _wat_at(ctx, path):
    span = ctx.span_by_path.get(path) if path is not None else None
    return "" if span is None else " at " + str(span["line"]) + ":" + str(span["column"])


class _WasmContext:
    """All program-specific WASM state, isolated per compilation."""
    __slots__ = ("defs", "top", "closures", "closure_by_id", "order", "topdefs",
                 "helper_base", "apply_arities", "apply_ids", "apply1_id",
                 "variant_id", "alloc_id", "resource_use_id", "tags", "fields", "resources", "foreigns",
                 "strings", "string_layout", "hp_init", "node_path_by_id", "span_by_path")

    def __init__(self, program_src):
        self.defs, self.top, self.closures, self.order = _wasm_collect_closures(program_src)
        self.closure_by_id = {spec["id"]: spec for spec in self.order}
        self.topdefs = {
            t[1]: {"id": i, "arity": len(t[3][1]), "name": t[1]}
            for i, t in enumerate(self.defs)
        }
        self.helper_base = len(self.defs) + len(self.order)
        self.apply_arities = sorted(
            {0, 1}
            | {len(t[3][1]) for t in self.defs}
            | {spec["arity"] for spec in self.order}
        )
        self.apply_ids = {
            arity: self.helper_base + 8 + i
            for i, arity in enumerate(self.apply_arities)
        }
        self.apply1_id = self.apply_ids.get(1, self.helper_base + 8)
        self.variant_id = self.helper_base + 4
        self.alloc_id = self.helper_base + 5
        self.resource_use_id = self.helper_base + 6
        self.tags = _wasm_tags(program_src)
        capture_slots = max([8] + [len(spec["captures"]) for spec in self.order])
        self.fields = _wasm_fields(program_src, capture_slots)
        self.resources = _wasm_resources(program_src)
        self.foreigns = _wasm_foreigns(program_src)
        self.strings = _wasm_strings(program_src)
        self.string_layout, self.hp_init = _wasm_string_layout(self.strings)
        self.node_path_by_id, self.span_by_path = _wasm_source_maps(program_src, self.defs)

def compile_wasm(program_src):
    """Compile checked LOOM to a real WebAssembly module.
    Integers use even immediates; odd values are typed heap pointers, so host decoding never guesses from pointer shape."""
    _, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    ctx = _WasmContext(program_src)
    if ctx.hp_init > 65536:
        raise LoomError("wasm heap: static data exceeds the fixed 64 KiB memory page")
    ds, order = ctx.defs, ctx.order
    helper_base, apply_arities = ctx.helper_base, ctx.apply_arities
    fmap = {t[1]: i for i, t in enumerate(ds)}; rec_i = helper_base; get_i = helper_base + 1; cons_i = helper_base + 2
    reserve_i = helper_base + 7
    tags, fields = ctx.tags, ctx.fields
    funcs = []                                              # (name, arity, n_locals, code, params)
    for t in ds:
        fn = t[3]; params = [pname(p) for p in fn[1]]; names = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, names, flags)
        seen = list(dict.fromkeys(["hd"] + names))         # handler temp + unique let-names + match-vars -> local slots after the params
        lmap = {p: i for i, p in enumerate(params)}
        for j, nm in enumerate(seen): lmap[nm] = len(params) + j
        si = len(params) + len(seen)                        # one shared scrutinee temp per function (used by match)
        nloc = len(seen) + (1 if flags["match"] else 0)
        funcs.append((t[1], len(params), nloc, _emit_wasm(ctx, fn[2:][-1] if fn[2:] else 0, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, set(pname(p) for p in fn[1] if platent(p) is not None), None, None) + b"\x0b", params))
    lambda_funcs = []
    for spec in order:
        fn = spec["node"]; params = spec["captures"] + [pname(p) for p in fn[1]]
        names = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, names, flags)
        seen = list(dict.fromkeys(["hd"] + names))
        lmap = {p: i for i, p in enumerate(params)}
        for j, nm in enumerate(seen): lmap[nm] = len(params) + j
        si = len(params) + len(seen)
        nloc = len(seen) + (1 if flags["match"] else 0)
        lambda_callable = set(spec["callable"]) | {pname(p) for p in fn[1] if platent(p) is not None}
        lambda_funcs.append((spec["name"], len(params), nloc, _emit_wasm(ctx, fn[2:][-1] if fn[2:] else 0, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, lambda_callable, None, None) + b"\x0b", params, spec))
    heap_static_g, heap_record_g, heap_list_g = 4, 5, 6
    heap_variant_g, heap_effect_g, heap_resource_g = 7, 8, 9
    def _bump_global(g): return b"\x23" + _leb_u(g) + _wasm_const(1) + b"\x6a\x24" + _leb_u(g)
    rec_code = (_wasm_const(16) + b"\x10" + _leb_u(reserve_i + _WASM_IMPORTS) + b"\x21\x03"  # $t = reserve(16)
                + _bump_global(heap_record_g) +
                b"\x20\x03" + _wasm_const(_WASM_K_RECORD) + b"\x36\x02\x00" # kind
                b"\x20\x03\x20\x01\x36\x02\x04"                              # field-id
                b"\x20\x03\x20\x02\x36\x02\x08"                              # value
                b"\x20\x03\x20\x00\x36\x02\x0c"                              # next
                b"\x20\x03" + _wasm_const(1) + b"\x72\x0b")                  # return tagged pointer
    get_code = (b"\x20\x00"                                                  # if rec == 0 -> 0
                b"\x45"
                b"\x04\x7f"                                                  # if (result i32)
                b"\x41\x00"
                b"\x05"
                b"\x20\x00" + _wasm_unptr() + b"\x28\x02\x04"                # load field-id
                b"\x20\x01"
                b"\x46"
                b"\x04\x7f"
                b"\x20\x00" + _wasm_unptr() + b"\x28\x02\x08"                # hit -> load value
                b"\x05"
                b"\x20\x00" + _wasm_unptr() + b"\x28\x02\x0c"                # miss -> follow next and recurse
                b"\x20\x01"
                b"\x10" + _leb_u(get_i + _WASM_IMPORTS) +
                b"\x0b"
                b"\x0b"
                b"\x0b")
    cons_code = (_wasm_const(12) + b"\x10" + _leb_u(reserve_i + _WASM_IMPORTS) + b"\x21\x02"
                 + _bump_global(heap_list_g) +
                 b"\x20\x02" + _wasm_const(_WASM_K_LIST) + b"\x36\x02\x00"
                 b"\x20\x02\x20\x00\x36\x02\x04" b"\x20\x02\x20\x01\x36\x02\x08"
                 b"\x20\x02" + _wasm_const(1) + b"\x72\x0b")
    effbox_code = (_wasm_const(12) + b"\x10" + _leb_u(reserve_i + _WASM_IMPORTS) + b"\x21\x02"
                   + _bump_global(heap_effect_g) +
                   b"\x20\x02" + _wasm_const(_WASM_K_EFFECT) + b"\x36\x02\x00"
                   b"\x20\x02\x20\x00\x36\x02\x04"
                   b"\x20\x02\x20\x01\x36\x02\x08"
                   b"\x20\x02" + _wasm_const(1) + b"\x72\x0b")
    variant_code = (_wasm_const(12) + b"\x10" + _leb_u(reserve_i + _WASM_IMPORTS) + b"\x21\x02"
                    + _bump_global(heap_variant_g) +
                    b"\x20\x02" + _wasm_const(_WASM_K_VARIANT) + b"\x36\x02\x00"
                    b"\x20\x02\x20\x00\x36\x02\x04"
                    b"\x20\x02\x20\x01\x36\x02\x08"
                    b"\x20\x02" + _wasm_const(1) + b"\x72\x0b")
    def _apply_cases(cases, arity):
        code = b"\x41\x00"
        for spec in reversed(cases):
            if spec.get("kind") == "top":
                cap_fields = []
            else:
                cap_fields = [f"e{i}" for i in range(len(spec["captures"]))]
            case = (b"\x20\x00" + _wasm_const(fields["code"]) + b"\x10" + _leb_u(get_i + _WASM_IMPORTS) + _wasm_int(spec["id"]) + b"\x46" + b"\x04\x7f")
            for fld in cap_fields:
                case += b"\x20\x00" + b"\x41" + _leb_s(fields[fld]) + b"\x10" + _leb_u(get_i + _WASM_IMPORTS)
            for i in range(arity):
                case += b"\x20" + _leb_u(1 + i)
            case += b"\x10" + _leb_u(spec["id"] + _WASM_IMPORTS) + b"\x05" + code + b"\x0b"
            code = case
        return code
    def _sec(sid, c): return bytes([sid]) + _leb_u(len(c)) + c
    ar = sorted(set(apply_arities) | {a for _, a, _, _, _ in funcs} | {a for _, a, _, _, _, _ in lambda_funcs} | {2, 3})  # add helper arities
    ti = {a: i for i, a in enumerate(ar)}   # arity-2 type covers $cons/get; arity-3 covers $rec
    tc = _leb_u(len(ar)) + b"".join(b"\x60" + _leb_u(a) + b"\x7f" * a + b"\x01\x7f" for a in ar)   # type: (i32*)->i32
    fc = _leb_u(len(funcs) + len(lambda_funcs) + 8 + len(apply_arities)) + b"".join(_leb_u(ti[a]) for _, a, _, _, _ in funcs) + b"".join(_leb_u(ti[a]) for _, a, _, _, _, _ in lambda_funcs) + _leb_u(ti[3]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[1]) + _leb_u(ti[1]) + b"".join(_leb_u(ti[arity + 1]) for arity in apply_arities)
    mc = _leb_u(1) + b"\x00" + _leb_u(1)                    # 1 memory, min 1 page (64 KiB heap)
    gc = (_leb_u(10)
          + b"\x7f\x01" + _wasm_const(ctx.hp_init) + b"\x0b"                       # mutable i32 $hp = static-data end
          + b"\x7f\x00" + _wasm_const(_WASM_ABI_VERSION) + b"\x0b"                  # immutable raw ABI version
          + b"\x7f\x00" + _wasm_const(65536) + b"\x0b"                              # immutable raw heap limit
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b"                                  # mutable raw heap bytes reserved at runtime
          + b"\x7f\x00" + _wasm_const(max(0, ctx.hp_init - 8)) + b"\x0b"             # immutable static string/data bytes
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b"                                  # mutable record object count
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b"                                  # mutable list object count
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b"                                  # mutable variant object count
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b"                                  # mutable effect-box object count
          + b"\x7f\x01" + _wasm_const(0) + b"\x0b")                                 # mutable resource-use object count
    ic = (_leb_u(8)
          + _leb_u(len("env")) + b"env" + _leb_u(len("push_handler")) + b"push_handler" + b"\x00" + _leb_u(ti[2])
          + _leb_u(len("env")) + b"env" + _leb_u(len("pop_handler")) + b"pop_handler" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("current_handler")) + b"current_handler" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("host_print")) + b"host_print" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("push_caps")) + b"push_caps" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("pop_caps")) + b"pop_caps" + b"\x00" + _leb_u(ti[0])
          + _leb_u(len("env")) + b"env" + _leb_u(len("has_cap")) + b"has_cap" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("host_ffi")) + b"host_ffi" + b"\x00" + _leb_u(ti[3]))
    ec = _leb_u(len(funcs) + 10)
    ec += _leb_u(len("memory")) + b"memory" + b"\x02" + _leb_u(0)                  # export linear memory for the heap-backed runtime
    abi_name = b"loom_abi_version"
    ec += _leb_u(len(abi_name)) + abi_name + b"\x03" + _leb_u(1)                    # export immutable global 1
    heap_limit_name = b"loom_heap_limit"
    ec += _leb_u(len(heap_limit_name)) + heap_limit_name + b"\x03" + _leb_u(2)       # export immutable global 2
    heap_used_name = b"loom_heap_used"
    ec += _leb_u(len(heap_used_name)) + heap_used_name + b"\x03" + _leb_u(3)         # export mutable global 3
    for name, index in (
        (b"loom_heap_static_used", heap_static_g),
        (b"loom_heap_records", heap_record_g),
        (b"loom_heap_lists", heap_list_g),
        (b"loom_heap_variants", heap_variant_g),
        (b"loom_heap_effects", heap_effect_g),
        (b"loom_heap_resources", heap_resource_g),
    ):
        ec += _leb_u(len(name)) + name + b"\x03" + _leb_u(index)
    for i, t in enumerate(ds):
        nb = t[1].encode(); ec += _leb_u(len(nb)) + nb + b"\x00" + _leb_u(i + _WASM_IMPORTS)         # export func
    cc = _leb_u(len(funcs) + len(lambda_funcs) + 8 + len(apply_arities))
    for _, _, nloc, code, _ in funcs:
        loc = (_leb_u(1) + _leb_u(nloc) + b"\x7f") if nloc else _leb_u(0)                           # let-locals (i32)
        e = loc + code; cc += _leb_u(len(e)) + e
    for _, _, nloc, code, _, _ in lambda_funcs:
        loc = (_leb_u(1) + _leb_u(nloc) + b"\x7f") if nloc else _leb_u(0)
        e = loc + code; cc += _leb_u(len(e)) + e
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + rec_code; cc += _leb_u(len(e)) + e                     # $rec: 1 local ($t)
    e = _leb_u(0) + get_code; cc += _leb_u(len(e)) + e                                              # $get: no locals
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + cons_code; cc += _leb_u(len(e)) + e                     # $cons: 1 local ($t)
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + effbox_code; cc += _leb_u(len(e)) + e                  # $effbox: 1 local ($t)
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + variant_code; cc += _leb_u(len(e)) + e                 # $variant: 1 local ($t)
    alloc_code = (b"\x20\x01"                                                    # if i == n -> nil
                  b"\x20\x00" b"\x46"
                  b"\x04\x7f"
                  + _wasm_const(_WASM_NIL) +
                  b"\x05"
                  b"\x20\x01"                                                    # else cons(i, alloc(n, i+1))
                  b"\x20\x00"
                  b"\x20\x01"
                  + _wasm_int(1) +
                  b"\x6a"
                  b"\x10" + _leb_u(helper_base + 5 + _WASM_IMPORTS) +            # call $alloc
                  b"\x10" + _leb_u(cons_i + _WASM_IMPORTS) +
                  b"\x0b"
                  b"\x0b")
    e = (_leb_u(1) + _leb_u(2) + b"\x7f") + alloc_code; cc += _leb_u(len(e)) + e                # $alloc: 2 locals ($n,$i)
    resource_use_code = (_wasm_const(8) + b"\x10" + _leb_u(reserve_i + _WASM_IMPORTS) + b"\x21\x01"
                         + _bump_global(heap_resource_g) +
                         b"\x20\x01" + _wasm_const(_WASM_K_RESOURCE) + b"\x36\x02\x00"
                         b"\x20\x01\x20\x00\x36\x02\x04"
                         b"\x20\x01" + _wasm_const(1) + b"\x72\x0b")
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + resource_use_code; cc += _leb_u(len(e)) + e
    reserve_code = (b"\x23\x00\x21\x01"                                  # $t = $hp
                    b"\x23\x00\x20\x00\x6a\x22\x02"                      # $new = $hp + size
                    b"\x23\x02\x4b"                                      # $new > $heap_limit
                    b"\x04\x40\x00\x0b"                                  # if true: unreachable
                    b"\x20\x02\x3f\x00\x41\x10\x74\x4b"                  # $new > memory.size() << 16
                    b"\x04\x40\x00\x0b"                                  # if true: unreachable
                    b"\x23\x03\x20\x00\x6a\x24\x03"                      # $heap_used += size
                    b"\x20\x02\x24\x00"                                  # $hp = $new
                    b"\x20\x01\x0b")                                      # return $t
    e = (_leb_u(1) + _leb_u(2) + b"\x7f") + reserve_code; cc += _leb_u(len(e)) + e
    for arity in apply_arities:
        apply_code = _apply_cases(
            [{"id": i, "name": t[1], "captures": [], "arity": len(t[3][1]), "kind": "top"} for i, t in enumerate(ds) if len(t[3][1]) == arity] +
            [spec for spec in order if spec["arity"] == arity],
            arity,
        )
        e = _leb_u(0) + apply_code + b"\x0b"
        cc += _leb_u(len(e)) + e
    dc = None
    if ctx.string_layout:
        def _seg(addr, payload):
            return b"\x00" + _wasm_const(addr) + b"\x0b" + _leb_u(len(payload)) + payload
        segs = []
        for spec in ctx.string_layout.values():
            segs.append(_seg(spec["obj"], _wasm_i32(_WASM_K_STRING) + _wasm_i32(len(spec["bytes"])) + _wasm_i32(spec["data"])))
            if spec["bytes"]:
                segs.append(_seg(spec["data"], spec["bytes"]))
        dc = _leb_u(len(segs)) + b"".join(segs)
    return (b"\x00asm\x01\x00\x00\x00" + _sec(1, tc) + _sec(2, ic) + _sec(3, fc) + _sec(5, mc)
            + _sec(6, gc) + _sec(7, ec) + _sec(10, cc) + (_sec(11, dc) if dc is not None else b""))

def emit_wat(program_src):
    """Human-readable WebAssembly Text (the 'assembler') for what compile_wasm encodes to bytes:
    tagged integers plus typed list/record/variant/closure/effect objects on a linear-memory heap."""
    _, errs = check(parse(program_src))
    if errs: raise LoomError("; ".join(errs))
    ctx = _WasmContext(program_src)
    if ctx.hp_init > 65536:
        raise LoomError("wasm heap: static data exceeds the fixed 64 KiB memory page")
    ds, order = ctx.defs, ctx.order
    helper_base, apply_arities = ctx.helper_base, ctx.apply_arities
    fmap = {t[1]: i for i, t in enumerate(ds)}; tags, fields = ctx.tags, ctx.fields; uses_heap = [False]; uses_print = [False]
    _OP = {"+": "i32.add", "-": "i32.sub", "*": "i32.mul", "=": "i32.eq", "<": "i32.lt_s", ">": "i32.gt_s"}
    def w(node, ind, handled_effs=None, with_handlers=None, callable_env=None, path=None):
        handled_effs = handled_effs or set()
        with_handlers = with_handlers or {}
        callable_env = callable_env or set()
        if path is None and isinstance(node, list):
            path = ctx.node_path_by_id.get(id(node))
        def child_path(i):
            return path + (i,) if path is not None else None
        def seq(nodes):
            out = []
            for i, child in enumerate(nodes):
                out += w(child, ind, handled_effs, with_handlers, callable_env)
                if i + 1 < len(nodes):
                    out += [ind + "drop"]
            return out
        if isinstance(node, int): return [ind + "i32.const " + str(node << 1) + "  ;; int " + str(node)]
        if _is_symbol(node):
            if node in ctx.topdefs:
                spec = ctx.topdefs[node]
                return w(["record", ["code", spec["id"]]], ind, handled_effs, with_handlers, callable_env)
            return [ind + "local.get $" + node]
        if type(node) is str:
            uses_heap[0] = True
            return [ind + "i32.const " + str(ctx.string_layout[node]["tagged"]) + "  ;; alloc static string literal" + _wat_at(ctx, path)]
        h = node[0]
        if h == "asm":
            error = asm_validation_error(node)
            if error: raise LoomError(error)
            spec = asm_metadata(node)
            rhs = w(node[4], ind, handled_effs, with_handlers, callable_env, child_path(4))
            if spec["wasm_rhs"] == "unbox_i31": rhs += [ind + "i32.const 1", ind + "i32.shr_s"]
            out = (w(node[3], ind, handled_effs, with_handlers, callable_env, child_path(3))
                   + rhs + [ind + spec["wat_opcode"] + "  ;; checked asm " + str(node[1]) + " " + str(node[2])])
            if spec["wasm_result"] == "tag_i31": out += [ind + "i32.const 1", ind + "i32.shl"]
            return out
        if h == "fn":
            spec = ctx.closures.get(id(node))
            if spec is None: raise LoomError("wat: missing closure spec")
            uses_heap[0] = True
            rec = [["code", spec["id"]]] + [[f"e{i}", cap] for i, cap in enumerate(spec["captures"])]
            return w(["record"] + rec, ind, handled_effs, with_handlers, callable_env)
        if h in ("+", "*"):
            o = w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1))
            for i, a in enumerate(node[2:], 2):
                o += w(a, ind, handled_effs, with_handlers, callable_env, child_path(i))
                if h == "*": o += [ind + "i32.const 1", ind + "i32.shr_s"]
                o += [ind + _OP[h]]
            return o
        if h == "-": return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + w(node[2], ind, handled_effs, with_handlers, callable_env, child_path(2)) + [ind + _OP[h]]
        if h in ("=", "<", ">"): return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + w(node[2], ind, handled_effs, with_handlers, callable_env, child_path(2)) + [ind + _OP[h], ind + "i32.const 1", ind + "i32.shl"]
        if h == "if":
            return (w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "if (result i32)"] + w(node[2], ind + "  ", handled_effs, with_handlers, callable_env, child_path(2))
                    + [ind + "else"] + w(node[3], ind + "  ", handled_effs, with_handlers, callable_env, child_path(3)) + [ind + "end"])
        if h == "let":
            bind_path = child_path(1)
            val_path = bind_path + (1,) if bind_path is not None else None
            o = w(node[1][1], ind, handled_effs, with_handlers, callable_env, val_path) + [ind + "local.set $" + node[1][0]]
            ncall = set(callable_env)
            if _wasm_is_closure_expr(ctx, node[1][1], callable_env):
                ncall.add(node[1][0])
            for i, b in enumerate(node[2:], 2): o += w(b, ind, handled_effs, with_handlers, ncall, child_path(i))
            return o
        if h == "seamN":
            return w(["seam"] + node[2:], ind, handled_effs, with_handlers, callable_env)
        if h in ("seam", "seam1"):
            body = _roleclauses(node[2:])[3]
            o = [ind + "i32.const " + str(_wasm_capmask(node[1])), ind + "call $push_caps", ind + "drop"]
            for b in body:
                o += w(b, ind, handled_effs, with_handlers, callable_env)
            return o + [ind + "call $pop_caps", ind + "drop"]
        if h == "handle":
            nh = set(handled_effs) | {"IO"}
            o = []
            for i, b in enumerate(node[2:], 2): o += w(b, ind, nh, with_handlers, callable_env, child_path(i))
            return o
        if h == "with":
            if node[1] not in OP:
                raise LoomError("wat: with currently supports builtin effects only")
            nh = dict(with_handlers); nh[node[1]] = node[2]
            o = []
            for i, b in enumerate(node[3:], 3): o += w(b, ind, handled_effs, nh, callable_env, child_path(i))
            return o
        if h == "print":
            uses_print[0] = True
            if "IO" in with_handlers:
                return w(with_handlers["IO"], ind, handled_effs, with_handlers, callable_env) + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "call $apply1"]
            cap = [ind + "i32.const 0  ;; effect IO", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end"]
            if "IO" in handled_effs:
                return cap + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1))
            return cap + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "call $host_print"]
        if h == "net":
            uses_heap[0] = True
            if "Net" in with_handlers:
                return w(with_handlers["Net"], ind, handled_effs, with_handlers, callable_env) + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "call $apply1"]
            return [ind + "i32.const 1  ;; effect Net", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const 1  ;; effect Net"] + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "call $effbox  ;; alloc effect box from net" + _wat_at(ctx, path)]
        if h == "rand":
            uses_heap[0] = True
            if "Rand" in with_handlers:
                return w(with_handlers["Rand"], ind, handled_effs, with_handlers, callable_env) + [ind + "call $apply0"]
            return [ind + "i32.const 2  ;; effect Rand", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const 2  ;; effect Rand", ind + "i32.const 0"] + [ind + "call $effbox  ;; alloc effect box from rand" + _wat_at(ctx, path)]
        if h == "alloc":
            uses_heap[0] = True
            if "Alloc" in with_handlers:
                return w(with_handlers["Alloc"], ind, handled_effs, with_handlers, callable_env) + w(node[1] if len(node) > 1 else 0, ind, handled_effs, with_handlers, callable_env, child_path(1) if len(node) > 1 else None) + [ind + "call $apply1"]
            if len(node) == 1:
                return [ind + "i32.const 3  ;; effect Alloc", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const " + str(_WASM_NIL)]
            return [ind + "i32.const 3  ;; effect Alloc", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end"] + w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "i32.const 0", ind + "call $alloc  ;; alloc list cells from alloc" + _wat_at(ctx, path)]
        transparent_body = _wasm_transparent_body(node)
        if transparent_body is not None:
            return seq(transparent_body)
        if h == "ffi":
            if type(node[1]) is not str:
                raise LoomError("wat: ffi name must be a string literal")
            uses_heap[0] = True
            return ([ind + "i32.const " + str(ctx.foreigns[node[1]]) + "  ;; foreign " + node[1]]
                    + w(["list"] + node[2:], ind, handled_effs, with_handlers, callable_env)
                    + [ind + "i32.const " + ("1" if "IO" in handled_effs else "0"),
                       ind + "call $host_ffi"])
        if h == "use":
            uses_heap[0] = True
            return [ind + "i32.const " + str(ctx.resources[node[1]]) + "  ;; resource " + node[1], ind + "call $resuse  ;; alloc resource-use marker" + _wat_at(ctx, path)]
        if h == "record":
            uses_heap[0] = True
            items = [fld for fld in node[1:] if isinstance(fld, list) and len(fld) >= 2]
            out = [ind + "i32.const 0"]
            for fld in reversed(items):
                fld_path = ctx.node_path_by_id.get(id(fld))
                val_path = fld_path + (1,) if fld_path is not None else None
                out = out + [ind + "i32.const " + str(fields[fld[0]]) + "  ;; field " + str(fld[0])] + w(fld[1], ind, handled_effs, with_handlers, callable_env, val_path) + [ind + "call $rec  ;; alloc record field " + str(fld[0]) + _wat_at(ctx, fld_path)]
            return out
        if h == "get":
            uses_heap[0] = True
            return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "i32.const " + str(fields[node[2]])] + [ind + "call $get"]
        if h == "list":
            uses_heap[0] = True; o = []
            for i, a in enumerate(node[1:], 1): o += w(a, ind, handled_effs, with_handlers, callable_env, child_path(i))
            return o + [ind + "i32.const " + str(_WASM_NIL)] + [ind + "call $cons  ;; alloc list cell" + _wat_at(ctx, path) for _ in node[1:]]
        if h == "cons": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + w(node[2], ind, handled_effs, with_handlers, callable_env, child_path(2)) + [ind + "call $cons  ;; alloc cons cell" + _wat_at(ctx, path)]
        if h == "head": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "i32.const -2", ind + "i32.and", ind + "i32.load offset=4"]
        if h == "tail": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "i32.const -2", ind + "i32.and", ind + "i32.load offset=8"]
        if h == "empty": return w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "i32.const " + str(_WASM_NIL), ind + "i32.eq", ind + "i32.const 1", ind + "i32.shl"]
        if h == "variant":
            uses_heap[0] = True
            return [ind + "i32.const " + str(tags[node[1]]) + "  ;; tag " + node[1]] + w(node[2], ind, handled_effs, with_handlers, callable_env, child_path(2)) + [ind + "call $variant  ;; alloc variant " + node[1] + _wat_at(ctx, path)]
        if h == "match":
            uses_heap[0] = True; o = w(node[1], ind, handled_effs, with_handlers, callable_env, child_path(1)) + [ind + "local.set $s"]
            def arms(a, ii):
                if not a: return [ii + "unreachable"]
                pat, body = a[0][0], a[0][1]
                ln = [ii + "local.get $s", ii + "i32.const -2", ii + "i32.and", ii + "i32.load offset=4", ii + "i32.const " + str(tags[pat[0]]) + "  ;; tag " + pat[0], ii + "i32.eq", ii + "if (result i32)"]
                if len(pat) >= 2: ln += [ii + "  local.get $s", ii + "  i32.const -2", ii + "  i32.and", ii + "  i32.load offset=8", ii + "  local.set $" + pat[1]]
                return ln + w(body, ii + "  ", handled_effs, with_handlers, callable_env) + [ii + "else"] + arms(a[1:], ii + "  ") + [ii + "end"]
            return o + arms(node[2:], ind)
        if isinstance(h, list):
            arity = len(node[1:])
            if arity not in ctx.apply_ids:
                raise LoomError("wat closures currently support this arity only when an apply helper exists")
            out = w(h, ind, handled_effs, with_handlers, callable_env, child_path(0))
            for i, a in enumerate(node[1:], 1):
                out += w(a, ind, handled_effs, with_handlers, callable_env, child_path(i))
            return out + [ind + "call $apply" + str(arity)]
        if h in callable_env:
            arity = len(node[1:])
            if arity not in ctx.apply_ids:
                raise LoomError("wat closures currently support this arity only when an apply helper exists")
            out = [ind + "local.get $" + h]
            for i, a in enumerate(node[1:], 1):
                out += w(a, ind, handled_effs, with_handlers, callable_env, child_path(i))
            return out + [ind + "call $apply" + str(arity)]
        if h in fmap:
            o = []
            for i, a in enumerate(node[1:], 1): o += w(a, ind, handled_effs, with_handlers, callable_env, child_path(i))
            return o + [ind + "call $" + h]
        raise LoomError("wat: form not yet in the WASM backend: " + str(h))
    bodies = []
    for t in ds:
        fn = t[3]; pn = [pname(p) for p in fn[1]]; sig = " ".join("(param $" + p + " i32)" for p in pn)
        nm = ["hd"]; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, nm, flags)
        locs = " ".join("(local $" + x + " i32)" for x in dict.fromkeys(nm))
        if flags["match"]: locs = (locs + " " if locs else "") + "(local $s i32)"
        head = "  (func $" + t[1] + ((" " + sig) if sig else "") + " (result i32)" + ((" " + locs) if locs else "")
        callable_env = set(pname(p) for p in fn[1] if platent(p) is not None)
        bodies.append([head] + w(fn[2:][-1] if fn[2:] else 0, "    ", None, None, callable_env)
                      + ["  )", '  (export "' + t[1] + '" (func $' + t[1] + "))"])
    for spec in order:
        fn = spec["node"]; params = spec["captures"] + [pname(p) for p in fn[1]]; sig = " ".join("(param $" + p + " i32)" for p in params)
        nm = ["hd"]; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, nm, flags)
        locs = " ".join("(local $" + x + " i32)" for x in dict.fromkeys(nm))
        if flags["match"]: locs = (locs + " " if locs else "") + "(local $s i32)"
        head = "  (func $" + spec["name"] + ((" " + sig) if sig else "") + " (result i32)" + ((" " + locs) if locs else "")
        lambda_callable = set(spec["callable"]) | {pname(p) for p in fn[1] if platent(p) is not None}
        bodies.append([head] + w(fn[2:][-1] if fn[2:] else 0, "    ", None, None, lambda_callable) + ["  )"])
    lines = ["(module", "  (global $loom_abi_version i32 (i32.const " + str(_WASM_ABI_VERSION) + "))",
             "  (global $loom_heap_limit i32 (i32.const 65536))",
             "  (global $loom_heap_used (mut i32) (i32.const 0))",
             "  (global $loom_heap_static_used i32 (i32.const " + str(max(0, ctx.hp_init - 8)) + "))",
             "  (global $loom_heap_records (mut i32) (i32.const 0))",
             "  (global $loom_heap_lists (mut i32) (i32.const 0))",
             "  (global $loom_heap_variants (mut i32) (i32.const 0))",
             "  (global $loom_heap_effects (mut i32) (i32.const 0))",
             "  (global $loom_heap_resources (mut i32) (i32.const 0))",
             '  (export "loom_abi_version" (global $loom_abi_version))',
             '  (export "loom_heap_limit" (global $loom_heap_limit))',
             '  (export "loom_heap_used" (global $loom_heap_used))',
             '  (export "loom_heap_static_used" (global $loom_heap_static_used))',
             '  (export "loom_heap_records" (global $loom_heap_records))',
             '  (export "loom_heap_lists" (global $loom_heap_lists))',
             '  (export "loom_heap_variants" (global $loom_heap_variants))',
             '  (export "loom_heap_effects" (global $loom_heap_effects))',
             '  (export "loom_heap_resources" (global $loom_heap_resources))']
    if uses_heap[0]:
        lines += ["  (memory 1)", '  (export "memory" (memory 0))', "  (global $hp (mut i32) (i32.const " + str(ctx.hp_init) + "))",
                  "  (func $reserve (param $size i32) (result i32) (local $t i32) (local $new i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  local.get $size  i32.add  local.tee $new",
                  "    global.get $loom_heap_limit  i32.gt_u",
                  "    if",
                  "      unreachable",
                  "    end",
                  "    local.get $new",
                  "    memory.size  i32.const 16  i32.shl  i32.gt_u",
                  "    if",
                  "      unreachable",
                  "    end",
                  "    global.get $loom_heap_used  local.get $size  i32.add  global.set $loom_heap_used",
                  "    local.get $new  global.set $hp",
                  "    local.get $t)",
                  "  (func $rec (param $next i32) (param $fid i32) (param $val i32) (result i32) (local $t i32)",
                  "    i32.const 16  call $reserve  local.set $t",
                  "    global.get $loom_heap_records  i32.const 1  i32.add  global.set $loom_heap_records",
                  "    local.get $t  i32.const 2  i32.store  ;; record kind",
                  "    local.get $t  local.get $fid  i32.store offset=4",
                  "    local.get $t  local.get $val  i32.store offset=8",
                  "    local.get $t  local.get $next  i32.store offset=12",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $get (param $rec i32) (param $fid i32) (result i32)",
                  "    local.get $rec",
                  "    i32.eqz",
                  "    if (result i32)",
                  "      i32.const 0",
                  "    else",
                  "      local.get $rec",
                  "      i32.const -2  i32.and  i32.load offset=4",
                  "      local.get $fid",
                  "      i32.eq",
                  "      if (result i32)",
                  "        local.get $rec",
                  "        i32.const -2  i32.and  i32.load offset=8",
                  "      else",
                  "        local.get $rec",
                  "        i32.const -2  i32.and  i32.load offset=12",
                  "        local.get $fid",
                  "        call $get",
                  "      end",
                  "    end)",
                  "  (func $cons (param $v i32) (param $rest i32) (result i32) (local $t i32)",
                  "    i32.const 12  call $reserve  local.set $t",
                  "    global.get $loom_heap_lists  i32.const 1  i32.add  global.set $loom_heap_lists",
                  "    local.get $t  i32.const 1  i32.store  ;; list kind",
                  "    local.get $t  local.get $v  i32.store offset=4",
                  "    local.get $t  local.get $rest  i32.store offset=8",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $effbox (param $eff i32) (param $payload i32) (result i32) (local $t i32)",
                  "    i32.const 12  call $reserve  local.set $t",
                  "    global.get $loom_heap_effects  i32.const 1  i32.add  global.set $loom_heap_effects",
                  "    local.get $t  i32.const 4  i32.store  ;; effect kind",
                  "    local.get $t  local.get $eff  i32.store offset=4",
                  "    local.get $t  local.get $payload  i32.store offset=8",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $variant (param $tag i32) (param $payload i32) (result i32) (local $t i32)",
                  "    i32.const 12  call $reserve  local.set $t",
                  "    global.get $loom_heap_variants  i32.const 1  i32.add  global.set $loom_heap_variants",
                  "    local.get $t  i32.const 3  i32.store  ;; variant kind",
                  "    local.get $t  local.get $tag  i32.store offset=4",
                  "    local.get $t  local.get $payload  i32.store offset=8",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $alloc (param $n i32) (param $i i32) (result i32) (local $t i32)",
                  "    local.get $i",
                  "    local.get $n",
                  "    i32.eq",
                  "    if (result i32)",
                  "      i32.const 3  ;; nil",
                  "    else",
                  "      local.get $i",
                  "      local.get $n",
                  "      local.get $i",
                  "      i32.const 2  ;; encoded int 1",
                  "      i32.add",
                  "      call $alloc",
                  "      call $cons",
                  "    end)"]
        lines += ["  (func $resuse (param $rid i32) (result i32) (local $t i32)",
                  "    i32.const 8  call $reserve  local.set $t",
                  "    global.get $loom_heap_resources  i32.const 1  i32.add  global.set $loom_heap_resources",
                  "    local.get $t  i32.const 5  i32.store  ;; resource-use kind",
                  "    local.get $t  local.get $rid  i32.store offset=4",
                  "    local.get $t  i32.const 1  i32.or)"]
        for spec in ctx.string_layout.values():
            lines += ["  ;; alloc static string object"]
            lines += ['  (data (i32.const ' + str(spec["obj"]) + ") " + _wat_bytes(_wasm_i32(_WASM_K_STRING) + _wasm_i32(len(spec["bytes"])) + _wasm_i32(spec["data"])) + ")"]
            if spec["bytes"]:
                lines += ['  (data (i32.const ' + str(spec["data"]) + ") " + _wat_bytes(spec["bytes"]) + ")"]
    lines += ['  (import "env" "push_handler" (func $push_handler (param i32 i32) (result i32)))',
              '  (import "env" "pop_handler" (func $pop_handler (param i32) (result i32)))',
              '  (import "env" "current_handler" (func $current_handler (param i32) (result i32)))',
              '  (import "env" "host_print" (func $host_print (param i32) (result i32)))',
              '  (import "env" "push_caps" (func $push_caps (param i32) (result i32)))',
              '  (import "env" "pop_caps" (func $pop_caps (result i32)))',
              '  (import "env" "has_cap" (func $has_cap (param i32) (result i32)))',
              '  (import "env" "host_ffi" (func $host_ffi (param i32 i32 i32) (result i32)))']
    if order:
        def _apply_cases(cases, indent, arity):
            if not cases: return [indent + "unreachable"]
            spec = cases[0]
            out = [indent + "local.get $cl", indent + "i32.const " + str(fields["code"]), indent + "call $get",
                   indent + "i32.const " + str(spec["id"] << 1), indent + "i32.eq", indent + "if (result i32)"]
            for i, _cap in enumerate(spec["captures"]):
                out += [indent + "  local.get $cl", indent + "  i32.const " + str(fields[f"e{i}"]), indent + "  call $get"]
            for i in range(arity):
                out += [indent + "  local.get $a" + str(i)]
            out += [indent + "  call $" + spec["name"], indent + "else"] + _apply_cases(cases[1:], indent + "  ", arity) + [indent + "end"]
            return out
        for arity in apply_arities:
            apply_lines = ["  (func $apply" + str(arity) + " (param $cl i32)" + "".join(" (param $a" + str(i) + " i32)" for i in range(arity)) + " (result i32)"]
            apply_cases = [{"id": i, "name": t[1], "captures": [], "kind": "top"} for i, t in enumerate(ds) if len(t[3][1]) == arity] + [spec for spec in order if spec["arity"] == arity]
            apply_lines += _apply_cases(apply_cases, "    ", arity) + ["  )"]
            lines += apply_lines
    for b in bodies: lines += b
    return "\n".join(lines + [")"])

def run_wasm(program_src, call_src):
    """Compile to wasm bytes, run via node's built-in WebAssembly, and decode the observable result. Needs node."""
    import subprocess, json as _json
    def _norm(v):
        if isinstance(v, dict):
            return {k: _norm(x) for k, x in v.items()}
        if isinstance(v, list):
            vv = [_norm(x) for x in v]
            return tuple(vv) if len(vv) == 2 and isinstance(vv[0], str) and vv[0][:1].isupper() else vv
        return v
    c = parse(call_src)[0]                                  # call site = (NAME int-args...) for the integer core
    _check_call_literals([c])
    name = c[0] if isinstance(c, list) else c
    args = c[1:] if isinstance(c, list) else []
    if not all(isinstance(a, int) for a in args):
        raise LoomError("node-wasm: call arguments must currently be integers")
    _, _, _, closure_order = _wasm_collect_closures(program_src)
    capture_slots = max([8] + [len(spec["captures"]) for spec in closure_order])
    tags_json = _json.dumps({str(v): k for k, v in _wasm_tags(program_src).items()})
    fields_json = _json.dumps({str(v): k for k, v in _wasm_fields(program_src, capture_slots).items()})
    resources_json = _json.dumps({str(v): k for k, v in _wasm_resources(program_src).items()})
    foreigns_json = _json.dumps({str(v): k for k, v in _wasm_foreigns(program_src).items()})
    arr = ",".join(str(b) for b in compile_wasm(program_src))
    js = ("const __out=[]; const __hs=[[],[],[],[]]; const __caps=[]; let __mem=null; const __rd=(p)=>__mem.getInt32(p,true); const __td=new TextDecoder();"
          "const __tags=" + tags_json + "; const __fields=" + fields_json + "; const __resources=" + resources_json + "; const __foreigns=" + foreigns_json + ";"
          "let __dec=(v)=>((Number.isInteger(v)&&(v&1)===0)?(v>>1):v);"
          "const __push=(e,h)=>{ __hs[e|0].push(h|0); return 0; };"
          "const __pop=(e)=>{ __hs[e|0].pop(); return 0; };"
          "const __cur=(e)=>{ const s=__hs[e|0]; return s.length ? s[s.length-1] : 0; };"
          "const __push_caps=(m)=>{ __caps.push(m|0); return 0; };"
          "const __pop_caps=()=>{ __caps.pop(); return 0; };"
          "const __has_cap=(e)=>{ if(!__caps.length) return 1; const m=__caps[__caps.length-1]|0; return ((m >>> (e|0)) & 1) ? 1 : 0; };"
          "const __eff_name=(k)=>({0:'IO',1:'Net',2:'Rand',3:'Alloc'}[k]??k);"
          "const __ffi=(id,args,silent)=>{ const name=__foreigns[String(id)]??String(id); if(name==='logger'){ const argv=__dec(args); const raw0=(args===3)?0:__rd((args&-2)+4); if(__has_cap(0) && !silent) __out.push('foreign:'+String(argv[0])); return raw0|0; } if(name==='lib'||name==='x'||name==='other') return (args===3)?0:__rd((args&-2)+4); throw new Error('unknown foreign fn: '+name); };"
          "const __imports={env:{push_handler:__push,pop_handler:__pop,current_handler:__cur,host_print:(x)=>{__out.push(String(__dec(x)));return x|0;},push_caps:__push_caps,pop_caps:__pop_caps,has_cap:__has_cap,host_ffi:(id,args,silent)=>__ffi(id|0,args|0,silent|0)}};"
          "WebAssembly.instantiate(new Uint8Array([" + arr + "]), __imports)"
          ".then(m=>{__mem=m.instance.exports.memory ? new DataView(m.instance.exports.memory.buffer) : null;"
          "const __abi=m.instance.exports.loom_abi_version;if(!__abi||__abi.value!==" + str(_WASM_ABI_VERSION) + ")throw new Error('unsupported LOOM WASM ABI');"
          "const __raw=(v)=>v&-2; const __valid=(p,n)=>p>=8&&p+n<=__mem.byteLength;"
          "__dec=(v)=>{"
          "if(!Number.isInteger(v)) return v; if((v&1)===0) return v>>1; if(v===3) return [];"
          "const p=__raw(v); if(!__valid(p,12)) throw new Error('invalid tagged pointer '+v); const k=__rd(p);"
          "if(k===1){const xs=[];let q=v,n=0;while(q!==3){const r=__raw(q);if((q&1)!==1||!__valid(r,12)||__rd(r)!==1||n++>2048)throw new Error('invalid list');xs.push(__dec(__rd(r+4)));q=__rd(r+8);}return xs;}"
          "if(k===2){const o={};let q=v,n=0;while(q!==0){const r=__raw(q);if((q&1)!==1||!__valid(r,16)||__rd(r)!==2||n++>2048)throw new Error('invalid record');const f=__rd(r+4);o[__fields[f]??String(f)]=__dec(__rd(r+8));q=__rd(r+12);}return o;}"
          "if(k===3){const t=__rd(p+4);return [__tags[t]??String(t),__dec(__rd(p+8))];}"
          "if(k===4)return [__eff_name(__rd(p+4)),__dec(__rd(p+8))];"
          "if(k===5)return '<used:' + (__resources[__rd(p+4)]??String(__rd(p+4))) + '>';"
          "if(k===6){const n=__rd(p+4),d=__rd(p+8);return __td.decode(new Uint8Array(__mem.buffer,d,n));}"
          "throw new Error('unknown heap kind '+k);};"
          "const __v=__dec(m.instance.exports[" + repr(name) + "](" + ",".join(str(a << 1) for a in args) + "));"
          "console.log('__VAL__'+JSON.stringify(__v));console.log('__OUT__'+JSON.stringify(__out));})"
          ".catch(e=>{console.error(String(e));process.exit(1)})")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=15)
    if r.returncode != 0: raise LoomError("node-wasm: " + r.stderr.strip()[:200])
    val = None; out = []
    for ln in r.stdout.strip().splitlines():
        if ln.startswith("__VAL__"): val = _norm(_json.loads(ln[7:]))
        elif ln.startswith("__OUT__"): out = _json.loads(ln[7:])
    if val is None: raise LoomError("node-wasm: missing result")
    return val, out


# ---- LOOM Gate phase 1: deterministic advisory manifests (standalone bundle mirror). ----
GATE_MANIFEST_SCHEMA = "loom-gate-manifest/v1"
GATE_MANIFEST_SCHEMA_V2 = "loom-gate-manifest/v2"
GATE_MANIFEST_SCHEMAS = {GATE_MANIFEST_SCHEMA, GATE_MANIFEST_SCHEMA_V2}
GATE_VALIDATION_SCHEMA = "loom-gate-manifest-validation/v1"
GATE_DECISION_SCHEMA = "loom-gate-decision/v1"
GATE_OBSERVATION_SCHEMA = "loom-gate-observation/v1"
GATE_RECEIPT_SCHEMA = "loom-gate-receipt/v1"
GATE_RECEIPT_VALIDATION_SCHEMA = "loom-gate-receipt-validation/v1"
GATE_DIAGNOSTICS_SCHEMA = "loom-gate-diagnostics/v1"
GATE_COLLECTION_SCHEMA = "loom-gate-observation-collection/v1"
GATE_EVIDENCE_COLLECTION_SCHEMA = "loom-gate-evidence-collection/v1"
GATE_POLICY_ID = "operator-codex-cloud/v1"
GATE_AGENTS = {"codex", "cloud-code", "auditor", "argus", "nostromo", "ci", "operator"}
GATE_ROLES = {"code", "organism", "audit", "night", "trace", "operator"}
GATE_ACTIONS = {"read", "write", "test", "process", "network", "git-commit", "git-push", "delete", "backup", "memory-write", "dashboard", "report", "audit"}
GATE_EVIDENCE = {"syntax", "citadel", "docs-parity", "fuzz", "git-clean", "git-sync", "live-site", "backup", "operator-approval", "audit", "secret-lane"}
_GATE_KEYS = {"schema", "agent", "task", "repositories", "read_paths", "write_paths", "actions", "evidence_required"}
_GATE_KEYS_V2 = _GATE_KEYS | {"secret_access"}
_GATE_OBS_KEYS = {"schema", "result", "repositories", "files_changed", "actions_observed", "evidence"}
_GATE_RESULTS = {"completed", "failed", "blocked"}; _GATE_EVIDENCE_STATUS = {"pass", "fail", "not-run"}
_GATE_ROLES_BY_AGENT = {"codex": "code", "cloud-code": "organism", "auditor": "audit", "argus": "organism", "nostromo": "night", "ci": "trace", "operator": "operator"}
_GATE_LOOM = "/Users/macbook/Projects/loom"; _GATE_ARGUS = "/Users/macbook/Projects/argus"; _GATE_NOSTROMO = "/Users/macbook/Projects/nostromo"
_GATE_MEMORY = "/Users/macbook/codex/Кодекс"; _GATE_FROZEN = "/Users/macbook/Projects/argus/citadel"; _GATE_AUDIT = "/Users/macbook/Projects/audit-targets"
_GATE_SECRET_SEGMENTS = {".aws", ".azure", ".config/gcloud", ".docker", ".gnupg", ".kube", ".ssh", ".1password", "keychain", "keychains", "password-store"}
_GATE_CREDENTIAL_FILES = {".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json", "hosts.yml", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
_GATE_CREDENTIAL_TOKENS = ("api_key", "apikey", "auth_token", "cookie", "password", "session", "token")
_GATE_WALLET_TOKENS = ("keystore", "mnemonic", "privatekey", "private_key", "seed", "wallet")
_GATE_BANK_TOKENS = ("bank", "card", "payment")
_GATE_SECRET_EVIDENCE_PREFIXES = ("secret lane approved:", "secret lane blocked:")
_GATE_SECRET_ACCESS_CLASSES = {"SecretRead", "CredentialAccess", "WalletKey", "BankCredential"}
_GATE_SECRET_ACCESS_MODES = {"read"}


def _gate_finding(path, code, message): return {"path": path, "code": code, "message": message}


def _gate_text(value, path, findings):
    if not isinstance(value, str):
        findings.append(_gate_finding(path, "expected-string", "expected a string")); return None
    value = unicodedata.normalize("NFC", value)
    if not value.strip():
        findings.append(_gate_finding(path, "empty-string", "value must not be empty")); return None
    return value


def _gate_object(value, path, required, findings):
    if not isinstance(value, dict):
        findings.append(_gate_finding(path, "expected-object", "expected an object")); return False
    for key in sorted(set(value) - set(required)): findings.append(_gate_finding(f"{path}.{key}", "unknown-field", f"unknown field '{key}'"))
    for key in sorted(set(required) - set(value)): findings.append(_gate_finding(f"{path}.{key}", "missing-field", f"missing required field '{key}'"))
    return set(value) == set(required)


def _gate_enum_list(value, path, allowed, findings):
    if not isinstance(value, list):
        findings.append(_gate_finding(path, "expected-array", "expected an array")); return None
    normalized = []
    for index, item in enumerate(value):
        item = _gate_text(item, f"{path}[{index}]", findings)
        if item is None: continue
        if item not in allowed: findings.append(_gate_finding(f"{path}[{index}]", "unknown-value", f"unknown value '{item}'"))
        normalized.append(item)
    for item in sorted({item for item in normalized if normalized.count(item) > 1}):
        findings.append(_gate_finding(path, "duplicate-value", f"duplicate value '{item}'"))
    return sorted(set(normalized))


def _gate_path_list(value, path, findings):
    if not isinstance(value, list):
        findings.append(_gate_finding(path, "expected-array", "expected an array")); return None
    normalized = []
    for index, item in enumerate(value):
        item = _gate_text(item, f"{path}[{index}]", findings)
        if item is None: continue
        parts = item.split("/")
        if not item.startswith("/"): findings.append(_gate_finding(f"{path}[{index}]", "path-not-absolute", "path must be absolute"))
        elif ".." in parts or "~" in parts: findings.append(_gate_finding(f"{path}[{index}]", "unsafe-path", "path must not contain '..' or '~'"))
        else:
            canonical = "/" + "/".join(part for part in parts if part)
            normalized.append(canonical or "/")
    for item in sorted({item for item in normalized if normalized.count(item) > 1}):
        findings.append(_gate_finding(path, "duplicate-path", f"duplicate path '{item}'"))
    return sorted(set(normalized))


def _gate_secret_access_list(value, path, findings):
    if not isinstance(value, list):
        findings.append(_gate_finding(path, "expected-array", "expected an array")); return None
    normalized = []
    for index, item in enumerate(value):
        base = f"{path}[{index}]"
        if not _gate_object(item, base, {"class", "path", "mode", "reason"}, findings): continue
        secret_class = _gate_text(item["class"], base + ".class", findings)
        mode = _gate_text(item["mode"], base + ".mode", findings)
        reason = _gate_text(item["reason"], base + ".reason", findings)
        paths = _gate_path_list([item["path"]], base + ".path", findings)
        lane_path = paths[0] if paths else None
        if secret_class is not None and secret_class not in _GATE_SECRET_ACCESS_CLASSES: findings.append(_gate_finding(base + ".class", "unknown-secret-class", f"unknown secret class '{secret_class}'"))
        if mode is not None and mode not in _GATE_SECRET_ACCESS_MODES: findings.append(_gate_finding(base + ".mode", "unknown-secret-mode", f"unknown secret access mode '{mode}'"))
        if reason is not None:
            if len(reason.split()) < 4: findings.append(_gate_finding(base + ".reason", "vague-secret-reason", "secret access reason must be specific"))
            if "=" in reason: findings.append(_gate_finding(base + ".reason", "unsafe-secret-reason", "secret access reason must not contain secret assignments"))
        inferred = _gate_secret_class(lane_path) if lane_path else None
        if lane_path and inferred is None: findings.append(_gate_finding(base + ".path", "secret-path-not-classified", "secret_access path must be classified as secret-like"))
        elif secret_class and inferred and secret_class not in {inferred, "SecretRead"}: findings.append(_gate_finding(base + ".class", "secret-class-mismatch", f"declared class '{secret_class}' does not match path class '{inferred}'"))
        normalized.append({"class": secret_class, "path": lane_path, "mode": mode, "reason": reason})
    keys = [(item["class"], item["path"], item["mode"]) for item in normalized]
    for key in sorted({key for key in keys if keys.count(key) > 1}): findings.append(_gate_finding(path, "duplicate-secret-access", f"duplicate secret access lane '{key[0]} {key[2]} {key[1]}'"))
    return sorted(normalized, key=lambda item: (item["path"] or "", item["class"] or "", item["mode"] or ""))


def _gate_result(normalized, findings, digest=None):
    return {"schema": GATE_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "manifest_sha256": digest, "normalized_manifest": normalized, "findings": findings}


def validate_manifest(manifest):
    findings = []
    if not isinstance(manifest, dict):
        findings.append(_gate_finding("$", "expected-object", "manifest must be an object")); return _gate_result(None, findings)
    schema = _gate_text(manifest.get("schema"), "schema", findings)
    keys = _GATE_KEYS_V2 if schema == GATE_MANIFEST_SCHEMA_V2 else _GATE_KEYS
    for key in sorted(set(manifest) - keys): findings.append(_gate_finding(key, "unknown-field", f"unknown field '{key}'"))
    for key in sorted(keys - set(manifest)): findings.append(_gate_finding(key, "missing-field", f"missing required field '{key}'"))
    normalized = {}
    if schema is not None and schema not in GATE_MANIFEST_SCHEMAS: findings.append(_gate_finding("schema", "unsupported-schema", f"expected one of {sorted(GATE_MANIFEST_SCHEMAS)}"))
    normalized["schema"] = schema
    agent = manifest.get("agent")
    if _gate_object(agent, "agent", {"id", "role"}, findings):
        agent_id = _gate_text(agent["id"], "agent.id", findings); role = _gate_text(agent["role"], "agent.role", findings)
        if agent_id is not None and agent_id not in GATE_AGENTS: findings.append(_gate_finding("agent.id", "unknown-agent", f"unknown agent '{agent_id}'"))
        if role is not None and role not in GATE_ROLES: findings.append(_gate_finding("agent.role", "unknown-role", f"unknown role '{role}'"))
        normalized["agent"] = {"id": agent_id, "role": role}
    task = manifest.get("task")
    if _gate_object(task, "task", {"summary", "intent"}, findings):
        normalized["task"] = {"summary": _gate_text(task["summary"], "task.summary", findings), "intent": _gate_text(task["intent"], "task.intent", findings)}
    repositories = manifest.get("repositories"); normalized_repositories = []
    if not isinstance(repositories, list): findings.append(_gate_finding("repositories", "expected-array", "expected an array"))
    else:
        for index, repository in enumerate(repositories):
            base = f"repositories[{index}]"
            if not _gate_object(repository, base, {"root", "expected_head", "require_clean"}, findings): continue
            roots = _gate_path_list([repository["root"]], base + ".root", findings)
            head = _gate_text(repository["expected_head"], base + ".expected_head", findings); clean = repository["require_clean"]
            if head is not None and re.fullmatch(r"[0-9a-f]{7,40}", head) is None: findings.append(_gate_finding(base + ".expected_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            if not isinstance(clean, bool): findings.append(_gate_finding(base + ".require_clean", "expected-boolean", "expected true or false"))
            normalized_repositories.append({"root": roots[0] if roots else None, "expected_head": head, "require_clean": clean if isinstance(clean, bool) else None})
        roots = [item["root"] for item in normalized_repositories if item["root"] is not None]
        for root in sorted({root for root in roots if roots.count(root) > 1}): findings.append(_gate_finding("repositories", "duplicate-repository", f"duplicate repository root '{root}'"))
    normalized["repositories"] = sorted(normalized_repositories, key=lambda item: item["root"] or "")
    normalized["read_paths"] = _gate_path_list(manifest.get("read_paths"), "read_paths", findings)
    normalized["write_paths"] = _gate_path_list(manifest.get("write_paths"), "write_paths", findings)
    normalized["actions"] = _gate_enum_list(manifest.get("actions"), "actions", GATE_ACTIONS, findings)
    normalized["evidence_required"] = _gate_enum_list(manifest.get("evidence_required"), "evidence_required", GATE_EVIDENCE, findings)
    if schema == GATE_MANIFEST_SCHEMA_V2: normalized["secret_access"] = _gate_secret_access_list(manifest.get("secret_access"), "secret_access", findings)
    if findings: return _gate_result(None, findings)
    canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _gate_result(normalized, [], hashlib.sha256(canonical.encode("utf-8")).hexdigest())


def _gate_under(path, root): return path == root or path.startswith(root + "/")


def _gate_zone(path):
    if _gate_under(path, _GATE_FROZEN): return "frozen"
    if _gate_under(path, _GATE_LOOM): return "loom"
    if _gate_under(path, _GATE_ARGUS): return "argus"
    if _gate_under(path, _GATE_NOSTROMO): return "nostromo"
    if _gate_under(path, _GATE_MEMORY): return "memory"
    if _gate_under(path, _GATE_AUDIT): return "audit-target"
    return "external"


def _gate_secret_class(path):
    lowered = path.lower(); parts = [part for part in lowered.split("/") if part]; base = parts[-1] if parts else ""
    if base.startswith(".env"): return "CredentialAccess"
    pairs = {"/".join(parts[index:index + 2]) for index in range(max(0, len(parts) - 1))}
    if any(segment in _GATE_SECRET_SEGMENTS for segment in parts) or any(pair in _GATE_SECRET_SEGMENTS for pair in pairs): return "CredentialAccess"
    if base in _GATE_CREDENTIAL_FILES or any(token in base for token in _GATE_CREDENTIAL_TOKENS): return "CredentialAccess"
    if any(token in lowered for token in _GATE_WALLET_TOKENS): return "WalletKey"
    if any(token in lowered for token in _GATE_BANK_TOKENS): return "BankCredential"
    return None


def _gate_issue(code, message, path="$"): return {"path": path, "code": code, "message": message}


def _gate_autonomous_write(agent, path, actions):
    if agent == "cloud-code":
        if _gate_under(path, _GATE_MEMORY) and "memory-write" in actions: return True
        if _gate_under(path, _GATE_ARGUS + "/reports") and "report" in actions: return True
        if _gate_under(path, _GATE_ARGUS + "/state") and actions & {"report", "dashboard", "backup"}: return True
        if _gate_under(path, _GATE_NOSTROMO + "/reports") and "report" in actions: return True
    if agent == "auditor": return _gate_under(path, _GATE_ARGUS + "/reports/auditor") and "report" in actions
    if agent == "argus":
        roots = (_GATE_ARGUS + "/reports", _GATE_ARGUS + "/state", _GATE_ARGUS + "/design", _GATE_ARGUS + "/experiments")
        return any(_gate_under(path, root) for root in roots) and bool(actions & {"report", "audit", "dashboard", "test"})
    if agent == "nostromo": return _gate_under(path, _GATE_NOSTROMO + "/reports") and "report" in actions
    return False


def _gate_unique(items):
    keyed = {(item["path"], item["code"], item["message"]): item for item in items}
    return [keyed[key] for key in sorted(keyed)]


def _gate_decision(decision, digest, reasons, violations):
    return {"schema": GATE_DECISION_SCHEMA, "decision": decision, "advisory": True, "manifest_sha256": digest, "policy": GATE_POLICY_ID, "reasons": _gate_unique(reasons), "violations": _gate_unique(violations)}


def _gate_secret_issue_class(code, message):
    if code == "secret-exfil-forbidden": return "SecretExfil"
    match = re.search(r"\(([^()]+)\)\s*$", message)
    return match.group(1) if match else "SecretRead"


def _gate_secret_issue_disposition(code):
    return "approval-required" if code in {"secret-read-operator-required", "secret-access-operator-required"} else "blocked"


def build_gate_diagnostics(manifest):
    decision = evaluate_manifest(manifest); lanes = []
    for item in decision["reasons"] + decision["violations"]:
        code = item["code"]
        if not code.startswith("secret-"): continue
        lanes.append({"field": item["path"], "code": code, "class": _gate_secret_issue_class(code, item["message"]), "disposition": _gate_secret_issue_disposition(code)})
    return {"schema": GATE_DIAGNOSTICS_SCHEMA, "advisory": True, "decision": decision["decision"], "policy": decision["policy"], "manifest_sha256": decision["manifest_sha256"], "secret_lane_count": len(lanes), "secret_lanes": sorted(lanes, key=lambda item: (item["field"], item["disposition"] != "approval-required", item["code"]))}


def _gate_has_secret_issue(decision):
    return any(item["code"].startswith("secret-") for item in decision["reasons"] + decision["violations"])


def _gate_validate_secret_evidence_detail(detail, path, findings):
    lowered = detail.lower()
    if not lowered.startswith(_GATE_SECRET_EVIDENCE_PREFIXES): findings.append(_gate_finding(path, "unsafe-secret-evidence", "secret-lane evidence must start with 'secret lane approved:' or 'secret lane blocked:'"))
    if "/" in detail or "\\" in detail or "=" in detail: findings.append(_gate_finding(path, "unsafe-secret-evidence", "secret-lane evidence must not contain raw paths or secret assignments"))


def evaluate_manifest(manifest):
    validation = validate_manifest(manifest)
    if not validation["valid"]: return _gate_decision("reject", None, [], validation["findings"])
    normalized = validation["normalized_manifest"]; digest = validation["manifest_sha256"]
    agent = normalized["agent"]["id"]; role = normalized["agent"]["role"]; actions = set(normalized["actions"]); evidence = set(normalized["evidence_required"])
    reasons, violations = [], []
    expected = _GATE_ROLES_BY_AGENT[agent]
    if role != expected: violations.append(_gate_issue("role-mismatch", f"agent '{agent}' must use role '{expected}', not '{role}'", "agent.role"))
    allowed = {
        "codex": {"read", "write", "test", "process", "network", "git-commit", "git-push", "delete", "memory-write", "report", "audit"},
        "cloud-code": {"read", "write", "test", "process", "network", "git-commit", "git-push", "delete", "backup", "memory-write", "dashboard", "report", "audit"},
        "auditor": {"read", "network", "report", "audit"},
        "argus": {"read", "write", "test", "process", "network", "dashboard", "report", "audit"},
        "nostromo": {"read", "write", "process", "network", "backup", "report"},
        "ci": {"read", "test", "report"}, "operator": set(GATE_ACTIONS),
    }[agent]
    for action in sorted(actions - allowed): violations.append(_gate_issue("action-forbidden", f"agent '{agent}' may not request action '{action}'", "actions"))
    if actions & {"write", "delete", "memory-write"} and not normalized["write_paths"]: violations.append(_gate_issue("missing-write-scope", "mutating action requires at least one write path", "write_paths"))
    secret_reads = []
    for index, path in enumerate(normalized["read_paths"]):
        secret = _gate_secret_class(path)
        if secret is None: continue
        where = f"read_paths[{index}]"; secret_reads.append((path, secret, where))
        reasons.append(_gate_issue("secret-read-operator-required", f"secret-like read path requires manifest-bound operator approval ({secret})", where))
    for index, lane in enumerate(normalized.get("secret_access", [])):
        secret_reads.append((lane["path"], lane["class"], f"secret_access[{index}]"))
        reasons.append(_gate_issue("secret-access-operator-required", f"declared secret_access lane requires manifest-bound operator approval ({lane['class']})", f"secret_access[{index}]"))
    for index, path in enumerate(normalized["write_paths"]):
        zone = _gate_zone(path); where = f"write_paths[{index}]"
        secret = _gate_secret_class(path)
        if secret is not None:
            violations.append(_gate_issue("secret-write-forbidden", f"secret-like write/delete path is rejected by Gate policy ({secret})", where)); continue
        if zone == "frozen": violations.append(_gate_issue("frozen-zone", "the frozen ARGUS citadel is read-only for every agent", where)); continue
        if agent == "operator": continue
        if agent == "codex":
            if zone not in {"loom", "memory"}: violations.append(_gate_issue("write-zone-forbidden", f"Codex may not write zone '{zone}'", where))
            else: reasons.append(_gate_issue("operator-gate", f"Codex write to {zone} requires operator approval", where))
        elif agent in {"cloud-code", "argus", "nostromo", "auditor"}:
            owned = zone in ({"argus", "nostromo", "memory"} if agent == "cloud-code" else ({"argus"} if agent in {"argus", "auditor"} else {"nostromo"}))
            if not owned or zone == "audit-target": violations.append(_gate_issue("write-zone-forbidden", f"agent '{agent}' may not write zone '{zone}'", where))
            elif not _gate_autonomous_write(agent, path, actions): reasons.append(_gate_issue("operator-gate", f"agent '{agent}' write outside its autonomous report/state lane requires operator approval", where))
        else: violations.append(_gate_issue("write-zone-forbidden", f"agent '{agent}' may not write host files", where))
    if agent == "ci":
        for index, path in enumerate(normalized["read_paths"]):
            if _gate_zone(path) != "loom": violations.append(_gate_issue("read-zone-forbidden", "CI may read only the canonical LOOM zone", f"read_paths[{index}]"))
    git_actions = actions & {"git-commit", "git-push"}
    if git_actions and not normalized["repositories"]: violations.append(_gate_issue("missing-repository", "Git action requires a declared repository", "repositories"))
    for index, repository in enumerate(normalized["repositories"]):
        if not git_actions: break
        zone = _gate_zone(repository["root"]); owner = "codex" if zone == "loom" else ("cloud-code" if zone in {"argus", "nostromo"} else None)
        if agent != "operator" and owner != agent: violations.append(_gate_issue("git-zone-forbidden", f"agent '{agent}' may not perform Git actions in zone '{zone}'", f"repositories[{index}].root"))
    gated = {"codex": {"write", "memory-write", "process", "network", "git-commit", "git-push", "delete"}, "cloud-code": {"process", "git-commit", "git-push", "delete"}, "auditor": {"network"}, "argus": {"process"}, "nostromo": {"process"}, "ci": set(), "operator": set()}[agent]
    for action in sorted(actions & gated): reasons.append(_gate_issue("operator-gate", f"action '{action}' requires operator approval", "actions"))
    if secret_reads and actions & {"network", "report", "dashboard", "git-push"}:
        for _, secret, where in secret_reads:
            violations.append(_gate_issue("secret-exfil-forbidden", f"secret-like read combined with outbound/reporting action is rejected by Gate policy ({secret})", where))
    required = set(); loom_writes = [path for path in normalized["write_paths"] if _gate_zone(path) == "loom"]
    if loom_writes: required |= {"syntax", "citadel", "docs-parity", "git-clean"}
    if any(_gate_under(path, _GATE_LOOM + "/docs") for path in loom_writes): required.add("live-site")
    if "git-push" in actions: required |= {"git-sync", "operator-approval"}
    if "backup" in actions: required.add("backup")
    for item in sorted(required - evidence): violations.append(_gate_issue("missing-evidence", f"action set requires evidence '{item}'", "evidence_required"))
    reasons = _gate_unique(reasons); violations = _gate_unique(violations)
    return _gate_decision("reject" if violations else ("operator-required" if reasons else "accept"), digest, reasons, violations)


def _gate_validate_observation(observation):
    findings = []
    if not isinstance(observation, dict): return None, [_gate_finding("observation", "expected-object", "observation must be an object")]
    for key in sorted(set(observation) - _GATE_OBS_KEYS): findings.append(_gate_finding(key, "unknown-field", f"unknown observation field '{key}'"))
    for key in sorted(_GATE_OBS_KEYS - set(observation)): findings.append(_gate_finding(key, "missing-field", f"missing required observation field '{key}'"))
    normalized = {}; schema = _gate_text(observation.get("schema"), "schema", findings)
    if schema is not None and schema != GATE_OBSERVATION_SCHEMA: findings.append(_gate_finding("schema", "unsupported-schema", f"expected '{GATE_OBSERVATION_SCHEMA}'"))
    normalized["schema"] = schema; result = _gate_text(observation.get("result"), "result", findings)
    if result is not None and result not in _GATE_RESULTS: findings.append(_gate_finding("result", "unknown-result", f"unknown result '{result}'"))
    normalized["result"] = result
    normalized["files_changed"] = _gate_path_list(observation.get("files_changed"), "files_changed", findings)
    normalized["actions_observed"] = _gate_enum_list(observation.get("actions_observed"), "actions_observed", GATE_ACTIONS, findings)
    repositories = observation.get("repositories"); normalized_repositories = []
    if not isinstance(repositories, list): findings.append(_gate_finding("repositories", "expected-array", "expected an array"))
    else:
        for index, repository in enumerate(repositories):
            base = f"repositories[{index}]"
            if not _gate_object(repository, base, {"root", "before_head", "after_head"}, findings): continue
            roots = _gate_path_list([repository["root"]], base + ".root", findings)
            before = _gate_text(repository["before_head"], base + ".before_head", findings); after = _gate_text(repository["after_head"], base + ".after_head", findings)
            if before is not None and re.fullmatch(r"[0-9a-f]{7,40}", before) is None: findings.append(_gate_finding(base + ".before_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            if after is not None and re.fullmatch(r"[0-9a-f]{7,40}", after) is None: findings.append(_gate_finding(base + ".after_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            normalized_repositories.append({"root": roots[0] if roots else None, "before_head": before, "after_head": after})
        roots = [item["root"] for item in normalized_repositories if item["root"] is not None]
        for root in sorted({root for root in roots if roots.count(root) > 1}): findings.append(_gate_finding("repositories", "duplicate-repository", f"duplicate observation repository '{root}'"))
    normalized["repositories"] = sorted(normalized_repositories, key=lambda item: item["root"] or "")
    evidence = observation.get("evidence"); normalized_evidence = []
    if not isinstance(evidence, list): findings.append(_gate_finding("evidence", "expected-array", "expected an array"))
    else:
        for index, item in enumerate(evidence):
            base = f"evidence[{index}]"
            if not _gate_object(item, base, {"kind", "status", "detail"}, findings): continue
            kind = _gate_text(item["kind"], base + ".kind", findings); status = _gate_text(item["status"], base + ".status", findings); detail = _gate_text(item["detail"], base + ".detail", findings)
            if kind is not None and kind not in GATE_EVIDENCE: findings.append(_gate_finding(base + ".kind", "unknown-evidence", f"unknown evidence '{kind}'"))
            if status is not None and status not in _GATE_EVIDENCE_STATUS: findings.append(_gate_finding(base + ".status", "unknown-evidence-status", f"unknown evidence status '{status}'"))
            if kind == "secret-lane" and detail is not None: _gate_validate_secret_evidence_detail(detail, base + ".detail", findings)
            normalized_evidence.append({"kind": kind, "status": status, "detail": detail})
        kinds = [item["kind"] for item in normalized_evidence if item["kind"] is not None]
        for kind in sorted({kind for kind in kinds if kinds.count(kind) > 1}): findings.append(_gate_finding("evidence", "duplicate-evidence", f"duplicate evidence '{kind}'"))
    normalized["evidence"] = sorted(normalized_evidence, key=lambda item: item["kind"] or "")
    return (None if findings else normalized), findings


def _gate_receipt_result(receipt, findings):
    return {"schema": GATE_RECEIPT_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "receipt": receipt, "findings": _gate_unique(findings)}


def build_receipt(manifest, observation):
    validation = validate_manifest(manifest); observed, findings = _gate_validate_observation(observation)
    if not validation["valid"]: findings = list(validation["findings"]) + findings
    if findings: return _gate_receipt_result(None, findings)
    normalized = validation["normalized_manifest"]; decision = evaluate_manifest(normalized); result = observed["result"]; findings = []
    if decision["decision"] == "reject" and result == "completed": findings.append(_gate_finding("result", "rejected-task-completed", "a policy-rejected task cannot produce a completed receipt"))
    declared = set(normalized["actions"])
    for action in sorted(set(observed["actions_observed"]) - declared): findings.append(_gate_finding("actions_observed", "undeclared-action", f"observed action '{action}' was not declared"))
    for index, path in enumerate(observed["files_changed"]):
        if not any(_gate_under(path, scope) for scope in normalized["write_paths"]): findings.append(_gate_finding(f"files_changed[{index}]", "changed-file-outside-scope", f"changed file '{path}' was not declared by the manifest"))
    expected = {item["root"]: item for item in normalized["repositories"]}; actual = {item["root"]: item for item in observed["repositories"]}
    for root in sorted(set(expected) - set(actual)): findings.append(_gate_finding("repositories", "missing-repository-observation", f"missing observation for repository '{root}'"))
    for root in sorted(set(actual) - set(expected)): findings.append(_gate_finding("repositories", "unexpected-repository", f"unexpected observation repository '{root}'"))
    for root in sorted(set(expected) & set(actual)):
        if actual[root]["before_head"] != expected[root]["expected_head"]: findings.append(_gate_finding("repositories", "stale-before-head", f"repository '{root}' before_head does not match manifest expected_head"))
    if result == "completed" and "git-commit" in observed["actions_observed"] and not any(item["before_head"] != item["after_head"] for item in observed["repositories"]): findings.append(_gate_finding("repositories", "commit-without-new-head", "completed git-commit must change at least one repository head"))
    evidence = {item["kind"]: item for item in observed["evidence"]}
    if result == "completed":
        required = set(normalized["evidence_required"])
        if decision["decision"] == "operator-required": required.add("operator-approval")
        if _gate_has_secret_issue(decision): required.add("secret-lane")
        for kind in sorted(required):
            item = evidence.get(kind)
            if item is None: findings.append(_gate_finding("evidence", "missing-evidence", f"missing required evidence '{kind}'"))
            elif item["status"] != "pass": findings.append(_gate_finding("evidence", "failed-evidence", f"required evidence '{kind}' has status '{item['status']}'"))
    elif _gate_has_secret_issue(decision):
        item = evidence.get("secret-lane")
        if item is None: findings.append(_gate_finding("evidence", "missing-evidence", "missing required evidence 'secret-lane'"))
        elif item["status"] != "pass": findings.append(_gate_finding("evidence", "failed-evidence", f"required evidence 'secret-lane' has status '{item['status']}'"))
    if findings: return _gate_receipt_result(None, findings)
    body = {"schema": GATE_RECEIPT_SCHEMA, "advisory": True, "manifest_sha256": validation["manifest_sha256"], "policy": decision["policy"], "policy_decision": decision["decision"], "agent": normalized["agent"], "result": result, "repositories": observed["repositories"], "files_changed": observed["files_changed"], "actions_observed": observed["actions_observed"], "evidence": observed["evidence"]}
    body["receipt_sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _gate_receipt_result(body, [])


def _gate_collection_result(observation, findings):
    return {"schema": GATE_COLLECTION_SCHEMA, "valid": not findings, "advisory": True, "read_only": True, "observation": observation if not findings else None, "findings": _gate_unique(findings)}


def _gate_git(root, *args):
    try:
        import subprocess
    except ImportError as error:
        return None, f"git unavailable in this Python runtime: {error}"
    env = os.environ.copy(); env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C"})
    try:
        proc = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", root, *args], capture_output=True, env=env, timeout=5)
    except FileNotFoundError:
        return None, "git executable not found"
    except (subprocess.TimeoutExpired, OSError) as error:
        return None, f"git command unavailable: {error}"
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        return None, detail or f"git exited with status {proc.returncode}"
    return proc.stdout, None


def _gate_decode_paths(data, root, path, findings):
    values = []
    for raw in data.split(b"\0"):
        if not raw: continue
        try: relative = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            findings.append(_gate_finding(path, "non-utf8-git-path", "Git path is not valid UTF-8")); continue
        absolute = str((Path(root) / relative).resolve(strict=False))
        if not _gate_under(absolute, root):
            findings.append(_gate_finding(path, "changed-path-outside-repository", f"Git reported path outside repository '{root}'")); continue
        values.append(absolute)
    return values


def collect_observation(manifest, result, actions_observed, evidence):
    """Collect read-only Git facts; fail closed where host Git is unavailable."""
    validation = validate_manifest(manifest)
    if not validation["valid"]: return _gate_collection_result(None, validation["findings"])
    normalized = validation["normalized_manifest"]; findings = []; repositories = []; changed_files = []; clean = True
    for index, repository in enumerate(normalized["repositories"]):
        root = repository["root"]; base = f"repositories[{index}]"; declared = Path(root)
        if not declared.is_absolute() or not declared.is_dir():
            findings.append(_gate_finding(base + ".root", "repository-unavailable", f"repository root is not an available directory '{root}'")); continue
        top_raw, error = _gate_git(root, "rev-parse", "--show-toplevel")
        if error: findings.append(_gate_finding(base + ".root", "git-read-failed", error)); continue
        top = top_raw.decode("utf-8", "replace").strip()
        if top != root or str(declared.resolve()) != root:
            findings.append(_gate_finding(base + ".root", "repository-root-mismatch", f"declared root '{root}' does not match canonical Git root '{top}'")); continue
        expected = repository["expected_head"]
        expected_raw, error = _gate_git(root, "rev-parse", "--verify", expected + "^{commit}")
        if error: findings.append(_gate_finding(base + ".expected_head", "expected-head-unavailable", error)); continue
        expected_full = expected_raw.decode("ascii", "replace").strip()
        head_raw, error = _gate_git(root, "rev-parse", "--verify", "HEAD^{commit}")
        if error: findings.append(_gate_finding(base + ".root", "head-unavailable", error)); continue
        head_full = head_raw.decode("ascii", "replace").strip()
        _, ancestor_error = _gate_git(root, "merge-base", "--is-ancestor", expected_full, head_full)
        if ancestor_error: findings.append(_gate_finding(base + ".expected_head", "expected-head-not-ancestor", "manifest expected_head is not an ancestor of current HEAD")); continue
        short_raw, error = _gate_git(root, "rev-parse", f"--short={len(expected)}", head_full)
        if error: findings.append(_gate_finding(base + ".root", "head-unavailable", error)); continue
        diff_raw, error = _gate_git(root, "diff", "--no-ext-diff", "--name-only", "-z", expected_full, "--")
        if error: findings.append(_gate_finding(base + ".root", "git-diff-failed", error)); continue
        untracked_raw, error = _gate_git(root, "ls-files", "--others", "--exclude-standard", "-z")
        if error: findings.append(_gate_finding(base + ".root", "git-status-failed", error)); continue
        status_raw, error = _gate_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        if error: findings.append(_gate_finding(base + ".root", "git-status-failed", error)); continue
        changed_files.extend(_gate_decode_paths(diff_raw, root, base, findings)); changed_files.extend(_gate_decode_paths(untracked_raw, root, base, findings))
        repo_clean = not bool(status_raw); clean = clean and repo_clean
        repositories.append({"root": root, "before_head": expected, "after_head": short_raw.decode("ascii", "replace").strip()})
    supplied = [item for item in evidence if not (isinstance(item, dict) and item.get("kind") == "git-clean")] if isinstance(evidence, list) else evidence
    if isinstance(supplied, list):
        supplied = list(supplied) + [{"kind": "git-clean", "status": "pass" if clean and not findings else "fail", "detail": "all declared repositories clean" if clean and not findings else "one or more declared repositories dirty or unreadable"}]
    observation = {"schema": GATE_OBSERVATION_SCHEMA, "result": result, "repositories": repositories, "files_changed": sorted(set(changed_files)), "actions_observed": actions_observed, "evidence": supplied}
    observed, observed_findings = _gate_validate_observation(observation); findings.extend(observed_findings)
    return _gate_collection_result(observed, findings)


_GATE_CI_API = "https://api.github.com/repos/umbraaeternaa/loom"
_GATE_CI_STEPS = {"Compile Python sources": "syntax", "Run citadel": "citadel", "Verify published docs parity": "docs-parity", "Run extended deterministic fuzz seeds": "fuzz"}
_GATE_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_GATE_CA_BUNDLES = (Path("/etc/ssl/cert.pem"), Path("/opt/homebrew/etc/openssl@3/cert.pem"), Path("/usr/local/etc/openssl@3/cert.pem"))


def _gate_evidence_result(evidence, findings):
    return {"schema": GATE_EVIDENCE_COLLECTION_SCHEMA, "valid": not findings, "advisory": True, "read_only": True, "evidence": evidence if not findings else None, "findings": _gate_unique(findings)}


def _gate_fetch_json(path):
    try:
        import ssl
        from urllib.error import HTTPError, URLError
        from urllib.request import Request, urlopen
    except ImportError as error:
        raise ValueError(f"GitHub API unavailable in this Python runtime: {error}") from error
    url = _GATE_CI_API + path
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "loom-gate-evidence-v1", "X-GitHub-Api-Version": "2022-11-28"})
    ca_bundle = next((path for path in _GATE_CA_BUNDLES if path.is_file()), None); context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    try:
        with urlopen(request, timeout=5, context=context) as response:
            if response.geturl() != url: raise ValueError("GitHub API redirect refused")
            payload = response.read(1_000_001)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        raise ValueError(f"GitHub API read failed: {error}") from error
    if len(payload) > 1_000_000: raise ValueError("GitHub API response exceeds size limit")
    try: value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise ValueError(f"GitHub API returned invalid JSON: {error}") from error
    if not isinstance(value, dict): raise ValueError("GitHub API response must be an object")
    return value


def collect_ci_evidence(manifest, observation, run_id):
    validation = validate_manifest(manifest); observed, observed_findings = _gate_validate_observation(observation)
    findings = list(validation["findings"]) + observed_findings
    if isinstance(run_id, bool) or not isinstance(run_id, (int, str)) or not str(run_id).isdigit() or int(run_id) <= 0: findings.append(_gate_finding("run_id", "invalid-run-id", "run_id must be a positive decimal integer"))
    if findings: return _gate_evidence_result(None, findings)
    normalized = validation["normalized_manifest"]; roots = {item["root"] for item in normalized["repositories"]}; observed_repos = {item["root"]: item for item in observed["repositories"]}
    if roots != {_GATE_LOOM}: findings.append(_gate_finding("repositories", "unsupported-ci-repository", "CI evidence v1 supports exactly the canonical LOOM repository"))
    if set(observed_repos) != roots: findings.append(_gate_finding("observation.repositories", "repository-mismatch", "observation repositories must exactly match the manifest"))
    expected_repos = {item["root"]: item for item in normalized["repositories"]}
    for root in sorted(set(observed_repos) & set(expected_repos)):
        if observed_repos[root]["before_head"] != expected_repos[root]["expected_head"]: findings.append(_gate_finding("observation.repositories.before_head", "stale-before-head", "observation before_head does not match manifest expected_head"))
    if findings: return _gate_evidence_result(None, findings)
    after_head = observed_repos[_GATE_LOOM]["after_head"]
    if len(after_head) != 40: return _gate_evidence_result(None, [_gate_finding("observation.repositories.after_head", "full-head-required", "CI evidence requires a full 40-character observed after_head")])
    run_id = int(run_id)
    try:
        run = _gate_fetch_json(f"/actions/runs/{run_id}"); jobs = _gate_fetch_json(f"/actions/runs/{run_id}/jobs?per_page=100"); branch = _gate_fetch_json("/branches/main")
    except ValueError as error: return _gate_evidence_result(None, [_gate_finding("github", "github-api-failed", str(error))])
    repository = run.get("repository"); head_sha = run.get("head_sha")
    if not isinstance(repository, dict) or repository.get("full_name") != "umbraaeternaa/loom": findings.append(_gate_finding("github.run.repository", "repository-mismatch", "workflow run does not belong to canonical LOOM"))
    if run.get("name") != "LOOM Citadel": findings.append(_gate_finding("github.run.name", "workflow-mismatch", "expected workflow 'LOOM Citadel'"))
    if run.get("status") != "completed" or run.get("conclusion") != "success": findings.append(_gate_finding("github.run", "workflow-not-successful", "workflow run must be completed with success"))
    if not isinstance(head_sha, str) or not _GATE_FULL_SHA.fullmatch(head_sha) or not head_sha.startswith(after_head): findings.append(_gate_finding("github.run.head_sha", "head-mismatch", "workflow head_sha does not match observed after_head"))
    commit = branch.get("commit"); branch_sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(branch_sha, str) or not _GATE_FULL_SHA.fullmatch(branch_sha) or not branch_sha.startswith(after_head): findings.append(_gate_finding("github.branch.main", "git-sync-failed", "origin main does not match observed after_head"))
    job_list = jobs.get("jobs"); verify_jobs = [job for job in job_list if isinstance(job, dict) and job.get("name") == "verify"] if isinstance(job_list, list) else []
    verify_job = verify_jobs[0] if len(verify_jobs) == 1 else None
    if verify_job is None: findings.append(_gate_finding("github.jobs", "verify-job-missing", "expected exactly one verify job"))
    elif verify_job.get("status") != "completed" or verify_job.get("conclusion") != "success": findings.append(_gate_finding("github.jobs.verify", "verify-job-not-successful", "verify job must be completed with success"))
    steps = {step.get("name"): step for step in verify_job.get("steps", []) if isinstance(step, dict) and isinstance(step.get("name"), str)} if verify_job else {}
    for name in sorted(_GATE_CI_STEPS):
        step = steps.get(name)
        if step is None or step.get("status") != "completed" or step.get("conclusion") != "success": findings.append(_gate_finding("github.jobs.verify.steps", "required-step-not-successful", f"required step '{name}' must complete successfully"))
    if findings: return _gate_evidence_result(None, findings)
    evidence = [{"kind": kind, "status": "pass", "detail": f"GitHub Actions run {run_id}: {name} passed at {head_sha}"} for name, kind in sorted(_GATE_CI_STEPS.items(), key=lambda item: item[1])]
    evidence.append({"kind": "git-sync", "status": "pass", "detail": f"GitHub main matches {head_sha}"})
    return _gate_evidence_result(sorted(evidence, key=lambda item: item["kind"]), [])


GATE_CHALLENGE_SCHEMA = "loom-gate-approval-challenge/v1"; GATE_CHALLENGE_VALIDATION_SCHEMA = "loom-gate-approval-challenge-validation/v1"
GATE_REQUEST_SCHEMA = "loom-gate-approval-request/v1"; GATE_REQUEST_VALIDATION_SCHEMA = "loom-gate-approval-request-validation/v1"
GATE_APPROVAL_SCHEMA = "loom-gate-operator-approval/v1"; GATE_APPROVAL_VALIDATION_SCHEMA = "loom-gate-operator-approval-validation/v1"
GATE_CLAIM_SCHEMA = "loom-gate-approval-claim/v1"; GATE_CLAIM_VALIDATION_SCHEMA = "loom-gate-approval-claim-validation/v1"
_GATE_APPROVAL_ALGORITHM = "rsa-pkcs1v15-sha256"; _GATE_NONCE = re.compile(r"^[0-9a-f]{64}$"); _GATE_HEX = re.compile(r"^[0-9a-f]+$")
_GATE_KEY_PATH = Path(_GATE_MEMORY) / "gate" / "operator_public_key.json"; _GATE_LEDGER_PATH = Path(_GATE_MEMORY) / "gate" / "operator_approvals.sqlite3"
_GATE_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _gate_canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
def _gate_challenge_result(challenge, findings): return {"schema": GATE_CHALLENGE_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "challenge": challenge if not findings else None, "findings": _gate_unique(findings)}
def _gate_request_result(request, findings): return {"schema": GATE_REQUEST_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "request": request if not findings else None, "findings": _gate_unique(findings)}
def _gate_approval_result(evidence, approval_sha, findings): return {"schema": GATE_APPROVAL_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "evidence": evidence if not findings else None, "approval_sha256": approval_sha if not findings else None, "findings": _gate_unique(findings)}
def _gate_claim_result(claim, findings): return {"schema": GATE_CLAIM_VALIDATION_SCHEMA, "valid": not findings, "advisory": False, "claim": claim if not findings else None, "findings": _gate_unique(findings)}


def build_approval_challenge(manifest, nonce):
    validation = validate_manifest(manifest); findings = list(validation["findings"])
    if not isinstance(nonce, str) or not _GATE_NONCE.fullmatch(nonce): findings.append(_gate_finding("nonce", "invalid-nonce", "nonce must be 64 lowercase hexadecimal characters"))
    decision = evaluate_manifest(manifest)
    if validation["valid"] and decision["decision"] != "operator-required": findings.append(_gate_finding("manifest", "approval-not-required", "manifest policy decision must be operator-required"))
    if findings: return _gate_challenge_result(None, findings)
    body = {"schema": GATE_CHALLENGE_SCHEMA, "manifest_sha256": validation["manifest_sha256"], "policy": decision["policy"], "policy_decision": decision["decision"], "nonce": nonce}
    body["challenge_sha256"] = hashlib.sha256(_gate_canonical(body).encode()).hexdigest()
    return _gate_challenge_result(body, [])


def build_approval_request(manifest, challenge):
    validation = validate_manifest(manifest); findings = list(validation["findings"]); decision = evaluate_manifest(manifest)
    if validation["valid"] and decision["decision"] != "operator-required": findings.append(_gate_finding("manifest", "approval-not-required", "manifest policy decision must be operator-required"))
    if not isinstance(challenge, dict): findings.append(_gate_finding("challenge", "expected-object", "challenge must be an object"))
    elif validation["valid"]:
        rebuilt = build_approval_challenge(manifest, challenge.get("nonce"))
        if not rebuilt["valid"]: findings.extend(rebuilt["findings"])
        elif challenge != rebuilt["challenge"]: findings.append(_gate_finding("challenge", "challenge-mismatch", "challenge does not match manifest and nonce"))
    if findings: return _gate_request_result(None, findings)
    body = {"schema": GATE_REQUEST_SCHEMA, "manifest": validation["normalized_manifest"], "challenge": challenge, "policy_reasons": decision["reasons"]}
    body["request_sha256"] = hashlib.sha256(_gate_canonical(body).encode()).hexdigest()
    return _gate_request_result(body, [])


def validate_approval_request(request):
    if not isinstance(request, dict): return _gate_request_result(None, [_gate_finding("request", "expected-object", "approval request must be an object")])
    required = {"schema", "manifest", "challenge", "policy_reasons", "request_sha256"}; findings = []
    for field in sorted(set(request) - required): findings.append(_gate_finding("request." + field, "unknown-field", f"unknown approval request field '{field}'"))
    for field in sorted(required - set(request)): findings.append(_gate_finding("request." + field, "missing-field", f"missing approval request field '{field}'"))
    if findings: return _gate_request_result(None, findings)
    rebuilt = build_approval_request(request["manifest"], request["challenge"])
    if not rebuilt["valid"]: return _gate_request_result(None, rebuilt["findings"])
    if request != rebuilt["request"]: return _gate_request_result(None, [_gate_finding("request", "request-mismatch", "approval request does not match its manifest, challenge, policy, and hash")])
    return rebuilt


def _gate_validate_public_key(value):
    findings = []; required = {"algorithm", "n", "e"}
    if not isinstance(value, dict): return None, [_gate_finding("public_key", "expected-object", "operator public key must be an object")]
    for key in sorted(set(value) - required): findings.append(_gate_finding("public_key." + key, "unknown-field", f"unknown public key field '{key}'"))
    for key in sorted(required - set(value)): findings.append(_gate_finding("public_key." + key, "missing-field", f"missing public key field '{key}'"))
    algorithm = value.get("algorithm"); n_hex = value.get("n"); exponent = value.get("e")
    if algorithm != _GATE_APPROVAL_ALGORITHM: findings.append(_gate_finding("public_key.algorithm", "unsupported-algorithm", f"expected '{_GATE_APPROVAL_ALGORITHM}'"))
    if not isinstance(n_hex, str) or not _GATE_HEX.fullmatch(n_hex) or n_hex.startswith("0"): findings.append(_gate_finding("public_key.n", "invalid-modulus", "RSA modulus must be canonical lowercase hexadecimal")); modulus = None
    else: modulus = int(n_hex, 16)
    if modulus is not None and (not (2048 <= modulus.bit_length() <= 4096) or modulus % 2 == 0): findings.append(_gate_finding("public_key.n", "unsafe-modulus", "RSA modulus must be odd and 2048-4096 bits"))
    if exponent != 65537: findings.append(_gate_finding("public_key.e", "unsafe-exponent", "RSA exponent must be 65537"))
    normalized = {"algorithm": algorithm, "n": n_hex, "e": exponent}
    return (None if findings else normalized), findings


def _gate_rsa_verify(message, signature_hex, key):
    if not isinstance(signature_hex, str) or not _GATE_HEX.fullmatch(signature_hex) or len(signature_hex) % 2: return False
    modulus = int(key["n"], 16); size = (modulus.bit_length() + 7) // 8; signature = bytes.fromhex(signature_hex)
    if len(signature) != size: return False
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus: return False
    digest_info = _GATE_DIGEST_INFO + hashlib.sha256(message).digest(); padding = size - len(digest_info) - 3
    if padding < 8: return False
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    return hmac.compare_digest(pow(signature_int, key["e"], modulus).to_bytes(size, "big"), expected)


def _gate_verify_approval(manifest, challenge, approval, public_key_value):
    key, findings = _gate_validate_public_key(public_key_value)
    if not isinstance(challenge, dict): findings.append(_gate_finding("challenge", "expected-object", "challenge must be an object"))
    if not isinstance(approval, dict): findings.append(_gate_finding("approval", "expected-object", "approval must be an object"))
    if findings: return _gate_approval_result(None, None, findings)
    rebuilt = build_approval_challenge(manifest, challenge.get("nonce"))
    if not rebuilt["valid"]: findings.extend(rebuilt["findings"])
    elif challenge != rebuilt["challenge"]: findings.append(_gate_finding("challenge", "challenge-mismatch", "challenge does not match manifest and nonce"))
    required = {"schema", "challenge_sha256", "manifest_sha256", "approver", "decision", "key_sha256", "signature"}
    for field in sorted(set(approval) - required): findings.append(_gate_finding("approval." + field, "unknown-field", f"unknown approval field '{field}'"))
    for field in sorted(required - set(approval)): findings.append(_gate_finding("approval." + field, "missing-field", f"missing approval field '{field}'"))
    if findings: return _gate_approval_result(None, None, findings)
    if approval["schema"] != GATE_APPROVAL_SCHEMA: findings.append(_gate_finding("approval.schema", "unsupported-schema", f"expected '{GATE_APPROVAL_SCHEMA}'"))
    if approval["challenge_sha256"] != challenge.get("challenge_sha256"): findings.append(_gate_finding("approval.challenge_sha256", "challenge-mismatch", "approval is bound to a different challenge"))
    if approval["manifest_sha256"] != challenge.get("manifest_sha256"): findings.append(_gate_finding("approval.manifest_sha256", "manifest-mismatch", "approval is bound to a different manifest"))
    if approval["approver"] != "operator": findings.append(_gate_finding("approval.approver", "invalid-approver", "approver must be 'operator'"))
    if approval["decision"] != "approve": findings.append(_gate_finding("approval.decision", "not-approved", "operator decision must be 'approve'"))
    key_sha = hashlib.sha256(_gate_canonical(key).encode()).hexdigest()
    if approval["key_sha256"] != key_sha: findings.append(_gate_finding("approval.key_sha256", "key-mismatch", "approval is signed by a different key"))
    signed = {field: approval[field] for field in sorted(required - {"signature"})}
    if not _gate_rsa_verify(_gate_canonical(signed).encode(), approval["signature"], key): findings.append(_gate_finding("approval.signature", "invalid-signature", "operator approval signature is invalid"))
    if findings: return _gate_approval_result(None, None, findings)
    approval_sha = hashlib.sha256(_gate_canonical(approval).encode()).hexdigest()
    return _gate_approval_result([{"kind": "operator-approval", "status": "pass", "detail": f"signed one-use operator approval {approval_sha}"}], approval_sha, [])


def _gate_load_operator_key():
    try:
        import stat
        if _GATE_KEY_PATH.is_symlink() or not _GATE_KEY_PATH.is_file(): raise ValueError("operator public key path must be a regular non-symlink file")
        if _GATE_KEY_PATH.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("operator public key must not be group/world-writable")
        return json.loads(_GATE_KEY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error: raise ValueError(f"operator public key unavailable: {error}") from error


def verify_operator_approval(manifest, challenge, approval):
    try: key = _gate_load_operator_key()
    except ValueError as error: return _gate_approval_result(None, None, [_gate_finding("public_key", "public-key-unavailable", str(error))])
    return _gate_verify_approval(manifest, challenge, approval, key)


def _gate_consume_once(approval_sha, ledger_path):
    try:
        import sqlite3
        import stat
    except ImportError as error:
        raise ValueError(f"approval ledger unavailable in this Python runtime: {error}") from error
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger_path.parent.chmod(0o700)
    if ledger_path.is_symlink(): raise ValueError("approval ledger path must not be a symlink")
    if ledger_path.exists() and ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
    try:
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
        try:
            ledger_path.chmod(0o600)
            connection.execute("PRAGMA trusted_schema=OFF"); connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS spent (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64))")
            connection.execute("CREATE TABLE IF NOT EXISTS claims (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256)=64), claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), status TEXT NOT NULL CHECK(status IN ('claimed','completed','failed')))")
            if connection.execute("SELECT 1 FROM claims WHERE approval_sha256=?", (approval_sha,)).fetchone(): connection.execute("ROLLBACK"); raise ValueError("operator approval was already claimed")
            try: connection.execute("INSERT INTO spent(approval_sha256) VALUES (?)", (approval_sha,))
            except sqlite3.IntegrityError as error: connection.execute("ROLLBACK"); raise ValueError("operator approval was already consumed") from error
            connection.execute("COMMIT")
        finally: connection.close()
    except sqlite3.Error as error:
        raise ValueError(f"approval ledger failed: {error}") from error


def consume_operator_approval(manifest, challenge, approval):
    verified = verify_operator_approval(manifest, challenge, approval)
    if not verified["valid"]: return verified
    try: _gate_consume_once(verified["approval_sha256"], _GATE_LEDGER_PATH)
    except (OSError, ValueError) as error: return _gate_approval_result(None, None, [_gate_finding("ledger", "approval-consume-failed", str(error))])
    return verified


def _gate_claim_once(verified, challenge, ledger_path):
    try:
        import sqlite3
        import stat
    except ImportError as error: raise ValueError(f"approval ledger unavailable in this Python runtime: {error}") from error
    approval_sha = verified["approval_sha256"]
    body = {"schema": GATE_CLAIM_SCHEMA, "approval_sha256": approval_sha, "manifest_sha256": challenge["manifest_sha256"], "challenge_sha256": challenge["challenge_sha256"], "status": "claimed"}
    body["claim_sha256"] = hashlib.sha256(_gate_canonical(body).encode("utf-8")).hexdigest()
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True); ledger_path.parent.chmod(0o700)
    if ledger_path.is_symlink(): raise ValueError("approval ledger path must not be a symlink")
    if ledger_path.exists() and ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
    try:
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
        try:
            ledger_path.chmod(0o600); connection.execute("PRAGMA trusted_schema=OFF"); connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS spent (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64))")
            connection.execute("CREATE TABLE IF NOT EXISTS claims (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256)=64), claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), status TEXT NOT NULL CHECK(status IN ('claimed','completed','failed')))")
            if connection.execute("SELECT 1 FROM spent WHERE approval_sha256=?", (approval_sha,)).fetchone(): connection.execute("ROLLBACK"); raise ValueError("operator approval was already consumed")
            try: connection.execute("INSERT INTO claims VALUES (?,?,?,?,?)", (approval_sha, body["manifest_sha256"], body["challenge_sha256"], body["claim_sha256"], "claimed"))
            except sqlite3.IntegrityError as error: connection.execute("ROLLBACK"); raise ValueError("operator approval was already claimed") from error
            connection.execute("COMMIT")
        finally: connection.close()
    except sqlite3.Error as error: raise ValueError(f"approval ledger failed: {error}") from error
    return body


def _gate_claim_operator_approval(manifest, challenge, approval, public_key, ledger_path):
    verified = _gate_verify_approval(manifest, challenge, approval, public_key)
    if not verified["valid"]: return _gate_claim_result(None, verified["findings"])
    try: claim = _gate_claim_once(verified, challenge, ledger_path)
    except (OSError, ValueError) as error: return _gate_claim_result(None, [_gate_finding("ledger", "approval-claim-failed", str(error))])
    return _gate_claim_result(claim, [])


def claim_operator_approval(manifest, challenge, approval):
    try: key = _gate_load_operator_key()
    except ValueError as error: return _gate_claim_result(None, [_gate_finding("public_key", "public-key-unavailable", str(error))])
    return _gate_claim_operator_approval(manifest, challenge, approval, key, _GATE_LEDGER_PATH)


def _gate_finish_claimed_receipt(manifest, observation, challenge, approval, claim, public_key, ledger_path):
    observed, findings = _gate_validate_observation(observation)
    if findings: return _gate_receipt_result(None, findings)
    if observed["result"] not in {"completed", "failed"}: return _gate_receipt_result(None, [_gate_finding("result", "terminal-result-required", "claimed execution must finish as completed or failed")])
    if any(item["kind"] == "operator-approval" for item in observed["evidence"]): return _gate_receipt_result(None, [_gate_finding("evidence", "supplied-operator-approval", "operator approval evidence must come from the claimed execution")])
    verified = _gate_verify_approval(manifest, challenge, approval, public_key)
    if not verified["valid"]: return _gate_receipt_result(None, verified["findings"])
    expected = {"schema": GATE_CLAIM_SCHEMA, "approval_sha256": verified["approval_sha256"], "manifest_sha256": challenge["manifest_sha256"], "challenge_sha256": challenge["challenge_sha256"], "status": "claimed"}
    expected["claim_sha256"] = hashlib.sha256(_gate_canonical(expected).encode("utf-8")).hexdigest()
    if claim != expected: return _gate_receipt_result(None, [_gate_finding("claim", "claim-mismatch", "claim does not match the signed manifest and challenge")])
    prepared = dict(observed); prepared["evidence"] = sorted(observed["evidence"] + verified["evidence"], key=lambda item: item["kind"])
    preflight = build_receipt(manifest, prepared)
    if not preflight["valid"]: return preflight
    connection = None
    try:
        import sqlite3
        import stat
    except ImportError as error:
        return _gate_receipt_result(None, [_gate_finding("ledger", "approval-finalize-failed", f"approval ledger unavailable in this Python runtime: {error}")])
    try:
        if ledger_path.is_symlink() or not ledger_path.is_file(): raise ValueError("approval ledger must be a regular non-symlink file")
        if ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None); connection.execute("PRAGMA trusted_schema=OFF"); connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT manifest_sha256, challenge_sha256, claim_sha256, status FROM claims WHERE approval_sha256=?", (verified["approval_sha256"],)).fetchone()
        wanted = (expected["manifest_sha256"], expected["challenge_sha256"], expected["claim_sha256"], "claimed")
        if row != wanted: connection.execute("ROLLBACK"); raise ValueError("approval claim is absent, mismatched, or already finished")
        connection.execute("UPDATE claims SET status=? WHERE approval_sha256=? AND status='claimed'", (observed["result"], verified["approval_sha256"])); connection.execute("COMMIT")
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction: connection.execute("ROLLBACK")
        return _gate_receipt_result(None, [_gate_finding("ledger", "approval-finalize-failed", str(error))])
    finally:
        if connection is not None: connection.close()
    return preflight


def finish_claimed_receipt(manifest, observation, challenge, approval, claim):
    try: key = _gate_load_operator_key()
    except ValueError as error: return _gate_receipt_result(None, [_gate_finding("public_key", "public-key-unavailable", str(error))])
    return _gate_finish_claimed_receipt(manifest, observation, challenge, approval, claim, key, _GATE_LEDGER_PATH)


def _gate_build_consumed_receipt(manifest, observation, challenge, approval, public_key, ledger_path):
    observed, findings = _gate_validate_observation(observation)
    if findings: return _gate_receipt_result(None, findings)
    if observed["result"] != "completed": return _gate_receipt_result(None, [_gate_finding("result", "completed-required", "signed approval consumption requires a completed observation")])
    if any(item["kind"] == "operator-approval" for item in observed["evidence"]): return _gate_receipt_result(None, [_gate_finding("evidence", "supplied-operator-approval", "operator approval evidence must come from signed one-use consumption")])
    verified = _gate_verify_approval(manifest, challenge, approval, public_key)
    if not verified["valid"]: return _gate_receipt_result(None, verified["findings"])
    prepared = dict(observed); prepared["evidence"] = sorted(observed["evidence"] + verified["evidence"], key=lambda item: item["kind"])
    preflight = build_receipt(manifest, prepared)
    if not preflight["valid"]: return preflight
    try: _gate_consume_once(verified["approval_sha256"], ledger_path)
    except (OSError, ValueError) as error: return _gate_receipt_result(None, [_gate_finding("ledger", "approval-consume-failed", str(error))])
    return preflight


def build_consumed_receipt(manifest, observation, challenge, approval):
    try: key = _gate_load_operator_key()
    except ValueError as error: return _gate_receipt_result(None, [_gate_finding("public_key", "public-key-unavailable", str(error))])
    return _gate_build_consumed_receipt(manifest, observation, challenge, approval, key, _GATE_LEDGER_PATH)


# ---- CLI + structured verdict: one checker truth for humans, Gate clients, and receipts. ----
def _partition_findings(fns, errs):
    ftab, globals_ = {}, []
    for error in errs:
        key = error.split(": ", 1)[0]
        if key in fns: ftab.setdefault(key, []).append(error)
        else: globals_.append(error)
    return ftab, globals_


def build_verdict(src):
    try:
        fns, errs = check(parse(src))
    except LoomError as error:
        fns, errs = {}, ["parse: " + str(error)]
    ftab, globals_ = _partition_findings(fns, errs)
    sensitive = {"Net", "IO", "FFI", "Alloc", "Rand"}
    functions = []
    for name, info in fns.items():
        declared = set(info["decl"]); performed = set(info["eff"]) - {"?"}
        mine = ftab.get(name, [])
        lies = bool(mine) or bool(performed - declared) or ("?" in info["eff"]) or bool(set(info.get("req", set())) - performed)
        caps = sorted(performed & sensitive)
        functions.append({
            "name": name,
            "declared_effects": sorted(declared),
            "performed_effects": sorted(performed),
            "required_effects": sorted(info.get("req", set())),
            "capabilities": caps,
            "status": "lie" if lies else ("review" if caps else "clean"),
            "findings": list(mine),
        })
    return {
        "schema": "loom-verdict/v1",
        "verdict": "reject" if errs else "accept",
        "advisory": True,
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "function_count": len(functions),
        "functions": functions,
        "global_findings": list(globals_),
        "finding_count": len(errs),
    }


def _emit_verdict_json(verdict):
    print(json.dumps(verdict, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def build_about():
    return {
        "schema": "loom-about/v1",
        "language": "LOOM",
        "citadel_checks": 421,
        "wasm_abi_version": _WASM_ABI_VERSION,
        "i31_bits": INT_BITS,
        "backends": ["interpreter", "python", "javascript", "webassembly", "wat"],
        "commands": ["about", "check", "run", "build", "audit", "source-map", "gate", "gate-workflow"],
    }


def _about(output_format="text"):
    about = build_about()
    if output_format == "json":
        _emit_verdict_json(about)
        return 0
    print("LOOM — trust layer for AI-written code")
    print(f"citadel: {about['citadel_checks']} self-verifying checks")
    print(f"WASM ABI: v{about['wasm_abi_version']}")
    print(f"i31: {about['i31_bits']} bit signed wraparound")
    print("backends: " + ", ".join(about["backends"]))
    return 0


def build_gate_workflow(manifest):
    validation = validate_manifest(manifest)
    workflow = {
        "schema": "loom-gate-workflow/v1",
        "valid": validation["valid"],
        "advisory": False,
        "manifest_sha256": validation.get("manifest_sha256"),
        "decision": None,
        "task_summary": None,
        "agent": None,
        "actions": [],
        "steps": [],
        "findings": list(validation["findings"]),
    }
    if not validation["valid"]:
        workflow["steps"] = [{"id": "fix-manifest", "kind": "operator", "description": "Fix the manifest until LOOM Gate validation accepts it."}]
        return workflow
    normalized = validation["normalized_manifest"]
    decision = evaluate_manifest(normalized)
    diagnostics = build_gate_diagnostics(normalized)
    workflow.update({
        "decision": decision["decision"],
        "task_summary": normalized["task"]["summary"],
        "agent": normalized["agent"],
        "actions": list(normalized["actions"]),
        "findings": list(decision["violations"]),
    })
    if decision["decision"] == "reject":
        workflow["steps"] = [{"id": "fix-policy", "kind": "operator", "description": "Resolve policy violations before requesting approval or execution."}]
        return workflow
    if decision["decision"] == "accept":
        workflow["steps"] = [{"id": "collect-observation", "kind": "trusted-host", "description": "Run only the manifest-declared action, then collect observation evidence."}]
        return workflow
    workflow["steps"] = [
        {"id": "approval-request", "kind": "operator", "description": "Build a nonce-bound approval request for the operator issuer.", "command": "python3 loom.py gate-request manifest.json --nonce <64-hex> --format json"},
        {"id": "claim", "kind": "trusted-host", "description": "Claim the signed approval before any bounded host action starts.", "command": "python3 loom.py gate-claim manifest.json challenge.json approval.json --format json"},
        {"id": "plan", "kind": "trusted-host", "description": "Build the bounded execution plan for the declared process action.", "command": "python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json"},
        {"id": "attempt-dry-run", "kind": "trusted-host", "description": "Validate the trusted host attempt envelope against the plan without finalizing.", "command": "python3 loom.py gate-process-attempt plan.json attempt.json --format json"},
        {"id": "finish", "kind": "trusted-host", "description": "Finalize the claimed approval exactly once from the validated process attempt.", "command": "python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json"},
    ]
    if diagnostics["secret_lanes"]:
        workflow["steps"].insert(1, {"id": "secret-lane-review", "kind": "operator", "description": "Review redacted secret-lane diagnostics; raw secret paths or values must stay hidden."})
    return workflow


def allocation_source_map_lines(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    if not rows:
        return ["allocation source map: no heap allocation sites"]
    return ["allocation source map"] + [f"  {line}:{column}  {label}" for line, column, label in rows]


def allocation_source_map_entries(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    return [{"line": line, "column": column, "label": label} for line, column, label in rows]


def build_source_map_verdict(src):
    try:
        allocations = allocation_source_map_entries(emit_wat(src))
    except LoomError as error:
        return {
            "schema": "loom-source-map/v1",
            "verdict": "reject",
            "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
            "allocation_count": 0,
            "allocations": [],
            "error": str(error),
        }
    return {
        "schema": "loom-source-map/v1",
        "verdict": "accept",
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "allocation_count": len(allocations),
        "allocations": allocations,
    }


def _cli(argv):

    flags, pos, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--target" and i + 1 < len(argv): flags["target"] = argv[i+1]; i += 2
        elif a.startswith("--target="): flags["target"] = a.split("=", 1)[1]; i += 1
        elif a == "--format" and i + 1 < len(argv): flags["format"] = argv[i+1]; i += 2
        elif a.startswith("--format="): flags["format"] = a.split("=", 1)[1]; i += 1
        else: pos.append(a); i += 1
    if len(pos) < 1:
        print("usage: python3 loom.py <about|check|run|build|audit|source-map|gate|gate-workflow> FILE [call] [--target py|js|wat] [--format text|json]"); return 2
    cmd = pos[0]
    output_format = flags.get("format", "text")
    if output_format not in ("text", "json"):
        print("unsupported format: " + output_format); return 2
    if cmd == "about":
        return _about(output_format)
    if len(pos) < 2:
        print("usage: python3 loom.py <about|check|run|build|audit|source-map|gate|gate-workflow> FILE [call] [--target py|js|wat] [--format text|json]"); return 2
    path = pos[1]; call = pos[2] if len(pos) > 2 else "(main)"
    try: src = open(path).read()
    except OSError as e: print("cannot read file: " + str(e)); return 2
    if cmd == "check":
        verdict = build_verdict(src)
        if output_format == "json":
            _emit_verdict_json(verdict); return 1 if verdict["verdict"] == "reject" else 0
        if verdict["verdict"] == "accept":
            print(f"OK — checked, all effects honest ({verdict['function_count']} function(s))"); return 0
        touched = sum(bool(item["findings"]) for item in verdict["functions"]) + (1 if verdict["global_findings"] else 0)
        print(f"REJECTED — {verdict['finding_count']} finding(s) across {touched} scope(s)")
        for item in verdict["functions"]:
            if not item["findings"]: continue
            print(f"  [{item['name']}] {len(item['findings'])} finding(s)")
            for error in item["findings"]: print("    - " + error)
        if verdict["global_findings"]:
            print(f"  [global] {len(verdict['global_findings'])} finding(s)")
            for error in verdict["global_findings"]: print("    - " + error)
        return 1
    if cmd == "gate":
        try: manifest = json.loads(src)
        except json.JSONDecodeError as e: print("invalid Gate manifest JSON: " + str(e)); return 2
        diagnostics = build_gate_diagnostics(manifest)
        if output_format == "json":
            _emit_verdict_json(diagnostics); return 1 if diagnostics["decision"] == "reject" else 0
        print("LOOM GATE - redacted advisory manifest diagnostics")
        print("decision: " + diagnostics["decision"])
        if diagnostics["secret_lanes"]:
            print("secret lanes:")
            for item in diagnostics["secret_lanes"]: print(f"  [{item['disposition']}] {item['class']} at {item['field']} ({item['code']})")
        else: print("secret lanes: none")
        return 1 if diagnostics["decision"] == "reject" else 0
    if cmd == "gate-workflow":
        try: manifest = json.loads(src)
        except json.JSONDecodeError as e: print("invalid Gate manifest JSON: " + str(e)); return 2
        workflow = build_gate_workflow(manifest)
        if output_format == "json":
            _emit_verdict_json(workflow); return 0 if workflow["valid"] and workflow["decision"] != "reject" else 1
        print("LOOM GATE WORKFLOW - bounded AI action route")
        print("decision: " + str(workflow["decision"]))
        if workflow["agent"]: print("agent: " + workflow["agent"]["id"] + " (" + workflow["agent"]["role"] + ")")
        if workflow["task_summary"]: print("task: " + workflow["task_summary"])
        if workflow["actions"]: print("requested actions: " + ", ".join(workflow["actions"]))
        step_ids = [step["id"] for step in workflow["steps"]]
        if not workflow["valid"]:
            print("allowed now: fix the manifest only")
            print("blocked until valid: approval, claim, plan, execution, finish")
            print("next safe step: " + workflow["steps"][0]["id"])
        elif workflow["decision"] == "reject":
            print("allowed now: fix policy violations only")
            print("blocked until policy accepts: approval, claim, plan, execution, finish")
            print("next safe step: " + workflow["steps"][0]["id"])
        elif workflow["decision"] == "accept":
            print("allowed now: manifest-declared action only")
            print("blocked always: anything outside declared actions and paths")
            print("next safe step: " + workflow["steps"][0]["id"])
        else:
            print("allowed now: operator approval request only")
            print("blocked until approval: " + ", ".join(step_ids[1:]))
            print("next safe step: " + workflow["steps"][0]["id"])
        print("safety: this command explains the route; it does not execute shell/network/tools")
        for step in workflow["steps"]:
            print(f"  {step['id']}: {step['description']}")
            if "command" in step: print("    " + step["command"])
        return 0 if workflow["valid"] and workflow["decision"] != "reject" else 1
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
    if cmd == "source-map":
        if output_format == "json":
            verdict = build_source_map_verdict(src)
            _emit_verdict_json(verdict); return 1 if verdict["verdict"] == "reject" else 0
        try: lines = allocation_source_map_lines(emit_wat(src))
        except LoomError as e: print("REJECTED: " + str(e)); return 1
        for line in lines: print(line)
        return 0
    if cmd == "audit":                                  # DISTRIBUTION: surface the capability surface of AI-written code
        verdict = build_verdict(src)
        if output_format == "json":
            _emit_verdict_json(verdict); return 1 if verdict["verdict"] == "reject" else 0
        print("LOOM AUDIT - capability surface of AI-written code (DECLARED vs actually PERFORMED)")
        for item in verdict["functions"]:
            tag = {"lie": "LIE   ", "review": "REVIEW", "clean": "clean "}[item["status"]]
            d = " ".join(item["declared_effects"]) or "Pure"; a = " ".join(item["performed_effects"]) or "Pure"
            extra = ("  <- holds: " + ", ".join(item["capabilities"])) if (item["capabilities"] and item["status"] != "lie") else ""
            print(f"  [{tag}] {item['name']}: declared ({d}) | performs ({a}){extra}")
            for error in item["findings"]: print("           ! " + error)
        if verdict["finding_count"]:
            print(f"-- FINDINGS ({verdict['finding_count']}), every violation verbatim:")
            for item in verdict["functions"]:
                for error in item["findings"]: print("   ! " + error)
            for error in verdict["global_findings"]: print("   ! " + error)
            if verdict["global_findings"]:
                print("-- global findings:")
                for error in verdict["global_findings"]: print("   ! " + error)
        else:
            print("-- no violations; review every non-Pure capability above")
        return 1 if verdict["verdict"] == "reject" else 0
    print("unknown command: " + cmd); return 2

if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
