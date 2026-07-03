#!/usr/bin/env python3
"""Portable Python and JavaScript code generators for checked LOOM programs."""

from loom_frontend import CodegenFrontend as _CodegenFrontend, asm_metadata, asm_validation_error


class Frontend(_CodegenFrontend):
    __slots__ = ()


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str

def _emit(frontend, node):
    if isinstance(node, int): return str(node)
    if type(node) is str: return repr(node)                            # string literal
    if _is_symbol(node): return node                                   # variable / symbol
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise frontend.error(error)
        spec = asm_metadata(node)
        if spec["portable_op"] == "add":
            return f"_i31({_emit(frontend, node[3])}+{_emit(frontend, node[4])})"
        raise frontend.error("asm: registered intrinsic has no Python lowering")
    if h == "+": return "_i31(" + "+".join(_emit(frontend, a) for a in node[1:]) + ")"
    if h == "-": return f"_i31(({_emit(frontend, node[1])})-({_emit(frontend, node[2])}))"
    if h == "*": return "_i31(" + "*".join(_emit(frontend, a) for a in node[1:]) + ")"
    if h == "=": return f"(1 if ({_emit(frontend, node[1])}=={_emit(frontend, node[2])}) else 0)"
    if h == "<": return f"(1 if ({_emit(frontend, node[1])}<{_emit(frontend, node[2])}) else 0)"
    if h == ">": return f"(1 if ({_emit(frontend, node[1])}>{_emit(frontend, node[2])}) else 0)"
    if h == "if": return f"({_emit(frontend, node[2])} if ({_emit(frontend, node[1])}!=0) else {_emit(frontend, node[3])})"
    if h == "let": return f"(lambda {node[1][0]}: {_emit(frontend, node[2:][-1])})({_emit(frontend, node[1][1])})"
    if h == "list": return "[" + ",".join(_emit(frontend, a) for a in node[1:]) + "]"
    if h == "cons": return f"([{_emit(frontend, node[1])}]+{_emit(frontend, node[2])})"
    if h == "head": return f"({_emit(frontend, node[1])}[0])"
    if h == "tail": return f"({_emit(frontend, node[1])}[1:])"
    if h == "empty": return f"(1 if len({_emit(frontend, node[1])})==0 else 0)"
    if h == "record": return "{" + ",".join(f"{fld[0]!r}:{_emit(frontend, fld[1])}" for fld in node[1:] if isinstance(fld, list)) + "}"
    if h == "get": return f"({_emit(frontend, node[1])}[{node[2]!r}])"
    if h == "fn": return f"(lambda {','.join(frontend.pname(p) for p in node[1])}: {_emit(frontend, node[2:][-1])})"
    if h == 'seamN': return _emit(frontend, ['seam'] + node[2:])   # D27 meter compiles as a seam (the quantum is a static-only check)
    if h in ("seam", "seam1"): return f"_seam({sorted(set(node[1])-{'Pure'})!r}, lambda: {_emit(frontend, node[2:][-1])})"   # seam SANDBOXES the body: push its granted row so foreign/ffi code is cap-gated exactly like the interpreter
    if h in ("resource", "prov", "declassify"): return _emit(frontend, node[2:][-1])   # value-transparent (effects/prov are static layers)
    if h == "by": return _emit(frontend, node[3:][-1])                           # value-transparent (role tag is a static layer)
    if h == "recall": return _emit(frontend, node[1:][-1])  # value-transparent (persistence taint is a static layer)
    if h == "repro": return _emit(frontend, node[1:][-1])  # value-transparent (reproducibility is a static-only assertion)
    if h == "trust": return _emit(frontend, node[1:][-1])                        # value-transparent (the trust gate is a static check)
    if h == "use": return "'<used>'"
    if h == "print": return f"_p({_emit(frontend, node[1])})"                     # IO: print AND return the value (as the interpreter)
    if h == "variant": return f"({node[1]!r},{_emit(frontend, node[2])})"           # tagged value (Tag, payload) — mirrors the interpreter tuple
    if h == "match":                                                      # dispatch on tag; bind payload; mirror the interpreter
        chain = "_nm(_sc[0])"
        for arm in reversed(node[2:]):
            pat = arm[0]; b = _emit(frontend, arm[1])
            hit = f"(lambda {pat[1]}: {b})(_sc[1])" if len(pat) >= 2 else b
            chain = f"({hit} if _sc[0]=={pat[0]!r} else {chain})"
        return f"(lambda _sc: {chain})({_emit(frontend, node[1])})"
    if h == "net": return f"_net({_emit(frontend, node[1])})"                       # effect OP -> prelude that mirrors the interpreter
    if h == "alloc": return f"_alloc({_emit(frontend, node[1])})" if len(node) > 1 else "[]"
    if h == "rand": return "_rand()"
    if h == "handle": return f"_handle(lambda: {_emit(frontend, node[2:][-1])})" if "IO" in node[1] else _emit(frontend, node[2:][-1])
    if h == "with":
        op = frontend.op.get(node[1])
        return f"_with({op!r}, {_emit(frontend, node[2])}, lambda: {_emit(frontend, node[3:][-1])})" if op else _emit(frontend, node[3:][-1])
    if h == "ffi": return f"_ffi({node[1]!r}, [{','.join(_emit(frontend, a) for a in node[2:])}])"   # foreign call via the emitted registry; cap-gated to mirror the interpreter
    return f"{h}(" + ",".join(_emit(frontend, a) for a in node[1:]) + ")"          # call: a user fn, or a closure-valued name

def compile_py(program_src, frontend):
    """Compile a CHECKED LOOM program to portable Python source (one def per defx). Rejects if it fails the checker."""
    fns, errs = frontend.check(frontend.parse(program_src))
    if errs: raise frontend.error("; ".join(errs))
    lines = ["_sd = [0]", "_h = {}", f"_INT_MIN={frontend.int_min}; _INT_MOD={frontend.int_mod}",
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
    for top in frontend.parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(frontend.pname(p) for p in fn[1]); body = _emit(frontend, fn[2:][-1]) if fn[2:] else "None"
            lines.append(f"def {top[1]}({ps}): return {body}")
    return "\n".join(lines)

def run_compiled(program_src, call_src, frontend):
    """Compile to Python, run it; return (value, output-lines) — proof the emitted code MATCHES the interpreter."""
    import io, contextlib
    call_ast = frontend.parse(call_src); frontend.check_call_literals(call_ast)
    ns = {}; exec(compile_py(program_src, frontend), ns); buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        val = eval(_emit(frontend, call_ast[0]), ns)
    return val, buf.getvalue().splitlines()


# ---- SECOND TARGET: JavaScript. Same emit pattern -> a DIFFERENT platform (browser / Node / any OS) => cross-platform. ----
def _emit_js(frontend, node):
    if isinstance(node, int): return str(node)
    if type(node) is str: return repr(node)
    if _is_symbol(node): return node
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise frontend.error(error)
        spec = asm_metadata(node)
        if spec["portable_op"] == "add":
            return f"_i31({_emit_js(frontend, node[3])}+{_emit_js(frontend, node[4])})"
        raise frontend.error("asm: registered intrinsic has no JavaScript lowering")
    if h == "+": return "_i31(" + "+".join(_emit_js(frontend, a) for a in node[1:]) + ")"
    if h == "-": return f"_i31(({_emit_js(frontend, node[1])})-({_emit_js(frontend, node[2])}))"
    if h == "*":
        out = _emit_js(frontend, node[1])
        for arg in node[2:]: out = f"_imul({out},{_emit_js(frontend, arg)})"
        return out
    if h == "=": return f"(({_emit_js(frontend, node[1])}==={_emit_js(frontend, node[2])})?1:0)"
    if h == "<": return f"(({_emit_js(frontend, node[1])}<{_emit_js(frontend, node[2])})?1:0)"
    if h == ">": return f"(({_emit_js(frontend, node[1])}>{_emit_js(frontend, node[2])})?1:0)"
    if h == "if": return f"(({_emit_js(frontend, node[1])}!==0)?{_emit_js(frontend, node[2])}:{_emit_js(frontend, node[3])})"
    if h == "let": return f"(({node[1][0]})=>{_emit_js(frontend, node[2:][-1])})({_emit_js(frontend, node[1][1])})"
    if h == "list": return "[" + ",".join(_emit_js(frontend, a) for a in node[1:]) + "]"
    if h == "cons": return f"([{_emit_js(frontend, node[1])}].concat({_emit_js(frontend, node[2])}))"
    if h == "head": return f"({_emit_js(frontend, node[1])}[0])"
    if h == "tail": return f"({_emit_js(frontend, node[1])}.slice(1))"
    if h == "empty": return f"(({_emit_js(frontend, node[1])}.length===0)?1:0)"
    if h == "record": return "({" + ",".join(f"{fld[0]!r}:{_emit_js(frontend, fld[1])}" for fld in node[1:] if isinstance(fld, list)) + "})"
    if h == "get": return f"({_emit_js(frontend, node[1])}[{node[2]!r}])"
    if h == "fn": return f"(({','.join(frontend.pname(p) for p in node[1])})=>{_emit_js(frontend, node[2:][-1])})"
    if h == 'seamN': return _emit_js(frontend, ['seam'] + node[2:])   # D27 meter compiles as a seam (JS)
    if h in ("seam", "seam1"): return f"_seam({sorted(set(node[1])-{'Pure'})!r}, ()=>({_emit_js(frontend, node[2:][-1])}))"   # seam SANDBOXES the body (JS): cap-gate foreign code like the interpreter
    if h in ("resource", "prov", "declassify"): return _emit_js(frontend, node[2:][-1])
    if h == "by": return _emit_js(frontend, node[3:][-1])
    if h == "recall": return _emit_js(frontend, node[1:][-1])  # value-transparent (persistence taint is a static layer)
    if h == "repro": return _emit_js(frontend, node[1:][-1])  # value-transparent (reproducibility is a static-only assertion)
    if h == "trust": return _emit_js(frontend, node[1:][-1])
    if h == "use": return "'<used>'"
    if h == "print": return f"_p({_emit_js(frontend, node[1])})"                  # IO: print AND return the value
    if h == "variant": return f"([{node[1]!r},{_emit_js(frontend, node[2])}])"      # tagged value [Tag, payload]
    if h == "match":
        chain = "_nm(_sc[0])"
        for arm in reversed(node[2:]):
            pat = arm[0]; b = _emit_js(frontend, arm[1])
            hit = f"((({pat[1]})=>{b})(_sc[1]))" if len(pat) >= 2 else b
            chain = f"((_sc[0]==={pat[0]!r})?{hit}:{chain})"
        return f"((_sc)=>{chain})({_emit_js(frontend, node[1])})"
    if h == "net": return f"_net({_emit_js(frontend, node[1])})"
    if h == "alloc": return f"_alloc({_emit_js(frontend, node[1])})" if len(node) > 1 else "[]"
    if h == "rand": return "_rand()"
    if h == "handle": return f"_handle(()=>({_emit_js(frontend, node[2:][-1])}))" if "IO" in node[1] else _emit_js(frontend, node[2:][-1])
    if h == "with":
        op = frontend.op.get(node[1])
        return f"_with({op!r}, {_emit_js(frontend, node[2])}, ()=>({_emit_js(frontend, node[3:][-1])}))" if op else _emit_js(frontend, node[3:][-1])
    if h == "ffi": return f"_ffi({node[1]!r}, [{','.join(_emit_js(frontend, a) for a in node[2:])}])"   # foreign call via the emitted registry (JS); cap-gated to mirror the interpreter
    return f"{h}(" + ",".join(_emit_js(frontend, a) for a in node[1:]) + ")"

def compile_js(program_src, frontend):
    """Compile a CHECKED LOOM program to portable JavaScript source (one function per defx)."""
    fns, errs = frontend.check(frontend.parse(program_src))
    if errs: raise frontend.error("; ".join(errs))
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
             "const _FOREIGN={ logger:(a)=>{ if(_cap_ok('IO')&&_sd===0) console.log('foreign:'+String(a[0])); return a[0]; }, lib:(a)=>((a.length>0)?a[0]:0), x:(a)=>((a.length>0)?a[0]:0), other:(a)=>((a.length>0)?a[0]:0) };",
             "function _ffi(name,args){ return _FOREIGN[name](args); }"]  # FFI codegen (JS): cap stack + foreign registry -> ffi mirrors the interpreter
    for top in frontend.parse(program_src):
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]; ps = ",".join(frontend.pname(p) for p in fn[1]); body = _emit_js(frontend, fn[2:][-1]) if fn[2:] else "null"
            lines.append(f"function {top[1]}({ps}){{ return {body}; }}")
    return "\n".join(lines)

def run_js(program_src, call_src, frontend):
    """Compile to JS, run through Node; return (value, output-lines) — proof the JS target matches the interpreter. Needs node."""
    import subprocess, json as _json
    def _norm(v):
        if isinstance(v, dict):
            return {k: _norm(x) for k, x in v.items()}
        if isinstance(v, list):
            vv = [_norm(x) for x in v]
            return tuple(vv) if len(vv) == 2 and isinstance(vv[0], str) and vv[0][:1].isupper() else vv
        return v
    call_ast = frontend.parse(call_src); frontend.check_call_literals(call_ast)
    js = compile_js(program_src, frontend) + "\nconsole.log('__R__'+JSON.stringify(" + _emit_js(frontend, call_ast[0]) + "))"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=15)
    if r.returncode != 0: raise frontend.error("node: " + r.stderr.strip()[:200])
    lines = r.stdout.splitlines(); val = None; out = []
    for ln in lines:
        if ln.startswith("__R__"): val = _norm(_json.loads(ln[5:]))
        else: out.append(ln)
    return val, out
