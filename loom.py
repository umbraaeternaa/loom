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
from contextvars import ContextVar

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


_RUNTIME_STATE = ContextVar("loom_runtime_state", default=None)


def _runtime_state():
    state = _RUNTIME_STATE.get()
    if state is None:
        state = _RuntimeState()
        _RUNTIME_STATE.set(state)
    return state


def _cap_ok(eff):
    caps = _runtime_state().caps
    return (not caps) or (eff in caps[-1])              # top-level host is unrestricted; a seam SANDBOXES its body
def _foreign_logger(args, out):                        # opaque foreign code that WANTS IO; emits ONLY if IO was granted
    if _cap_ok("IO"): out.append("foreign:" + str(args[0]))
    return args[0]
FOREIGN = {"logger": _foreign_logger}                  # registry of effect-opaque foreign functions reached via (ffi ..)
INT_BITS = 31
INT_MIN = -(1 << (INT_BITS - 1))
INT_MAX = (1 << (INT_BITS - 1)) - 1
_INT_MOD = 1 << INT_BITS


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


import loom_checker as _loom_checker

_CHECKER_FRONTEND = _loom_checker.Frontend(
    EFFECTS,
    BUILTIN_EFF,
    PURE_OPS,
    plin,
    pname,
    platent,
    is_var,
    is_fn_expr,
    _int_literal_errors,
    _MISS,
    LoomError,
)


def _roleclauses(tail):
    return _loom_checker._roleclauses(tail)


def check(program):
    """Check one program via the extracted checker module while preserving the public facade."""
    return _loom_checker.check(program, _CHECKER_FRONTEND)


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
    token = _RUNTIME_STATE.set(_RuntimeState())
    try:
        out = []
        call_ast = parse(call_src); _check_call_literals(call_ast)
        return ev(call_ast[0], {}, fns, out), out
    finally:
        _RUNTIME_STATE.reset(token)


# ---- PORTABLE CODEGEN: implementation lives in loom_codegen.py; public facade stays stable. ----
import loom_codegen as _loom_codegen

_CODEGEN_FRONTEND = _loom_codegen.Frontend(parse, check, pname, LoomError, OP, INT_MIN, _INT_MOD, _check_call_literals)

def _emit(node):
    return _loom_codegen._emit(_CODEGEN_FRONTEND, node)

def compile_py(program_src):
    return _loom_codegen.compile_py(program_src, _CODEGEN_FRONTEND)

def run_compiled(program_src, call_src):
    return _loom_codegen.run_compiled(program_src, call_src, _CODEGEN_FRONTEND)

def _emit_js(node):
    return _loom_codegen._emit_js(_CODEGEN_FRONTEND, node)

def compile_js(program_src):
    return _loom_codegen.compile_js(program_src, _CODEGEN_FRONTEND)

def run_js(program_src, call_src):
    return _loom_codegen.run_js(program_src, call_src, _CODEGEN_FRONTEND)

# ---- THIRD TARGET: WebAssembly. The implementation lives in loom_wasm.py;
#      this module supplies the checked LOOM frontend through an explicit dependency boundary. ----
import loom_wasm as _loom_wasm

_WASM_ABI_VERSION = _loom_wasm.WASM_ABI_VERSION
_WASM_FRONTEND = _loom_wasm.Frontend(parse, check, pname, platent, LoomError, OP, _check_call_literals)

def compile_wasm(program_src):
    return _loom_wasm.compile_wasm(program_src, _WASM_FRONTEND)

def emit_wat(program_src):
    return _loom_wasm.emit_wat(program_src, _WASM_FRONTEND)

def run_wasm(program_src, call_src):
    return _loom_wasm.run_wasm(program_src, call_src, _WASM_FRONTEND)

# ---- CLI: turn the kernel into a usable TOOL. `python3 loom.py <check|run|build|audit> file.loom [call] [--target py|js|wat]` ----
def _cli(argv):
    flags, pos, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--target" and i + 1 < len(argv): flags["target"] = argv[i+1]; i += 2
        elif a.startswith("--target="): flags["target"] = a.split("=", 1)[1]; i += 1
        else: pos.append(a); i += 1
    if len(pos) < 2:
        print("usage: python3 loom.py <check|run|build|audit> FILE [call] [--target py|js]"); return 2
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
    if cmd == "audit":                                  # DISTRIBUTION: surface the capability surface of AI-written code
        fns, errs = check(parse(src))                   # check infers every row even when a lie makes it REJECT
        ftab = {}                                        # name-attributed violations ONLY (check()-level errors are "name: ...")
        for e in errs:                                   # infer()-level errors (seam/trust/unresolved) are NOT prefixed
            k = e.split(": ", 1)[0]
            if k in fns: ftab.setdefault(k, []).append(e)
        SENS = {"Net", "IO", "FFI", "Alloc"}             # capabilities a human auditor must scrutinise (Pure is safe)
        print("LOOM AUDIT - capability surface of AI-written code (DECLARED vs actually PERFORMED)")
        for name, info in fns.items():
            decl = set(info["decl"]); perf = set(info["eff"]) - {"?"}   # '?' = un-seamed foreign marker, not a capability
            mine = ftab.get(name, [])
            lies = bool(mine) or bool(perf - decl) or ("?" in info["eff"]) or bool(set(info.get("req", set())) - perf)
            caps = sorted(perf & SENS)
            tag = "LIE   " if lies else ("REVIEW" if caps else "clean ")
            d = " ".join(sorted(decl)) or "Pure"; a = " ".join(sorted(perf)) or "Pure"
            extra = ("  <- holds: " + ", ".join(caps)) if (caps and not lies) else ""
            print(f"  [{tag}] {name}: declared ({d}) | performs ({a}){extra}")
            for e in mine: print("           ! " + e)
        if errs:
            print(f"-- FINDINGS ({len(errs)}), every violation verbatim:")
            for e in errs: print("   ! " + e)
        else:
            print("-- no violations; review every non-Pure capability above")
        return 1 if errs else 0
    print("unknown command: " + cmd); return 2

if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))
