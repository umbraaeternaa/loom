#!/usr/bin/env python3
"""WebAssembly and WAT backend for LOOM.

The backend is independent of the LOOM frontend. Parser/checker services are
provided explicitly through Frontend, avoiding imports and circular loading.
"""

from loom_frontend import WasmFrontend as _WasmFrontend, asm_metadata, asm_validation_error


class Frontend(_WasmFrontend):
    __slots__ = ()


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str

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
WASM_ABI_VERSION = 1
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

def _wasm_transparent_body(frontend, node):
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
    frontend = ctx.frontend
    callable_env = callable_env or set()
    handled_effs = handled_effs or set()
    with_handlers = with_handlers or {}
    if isinstance(node, int): return _wasm_int(node)                    # immediate integer: n << 1, low bit clear
    if _is_symbol(node):
        if node in lmap: return b"\x20" + _leb_u(lmap[node])            # local.get (param / let / match-bound)
        if node in ctx.topdefs:
            spec = ctx.topdefs[node]
            return _emit_wasm(ctx, ["record", ["code", spec["id"]]], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        raise frontend.error("wasm: free variable " + node)
    if type(node) is str:
        return _wasm_const(ctx.string_layout[node]["tagged"])
    h = node[0]
    if h == "asm":
        error = asm_validation_error(node)
        if error: raise frontend.error(error)
        spec = asm_metadata(node)
        rhs = _emit_wasm(ctx, node[4], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        if spec["wasm_rhs"] == "unbox_i31":
            rhs += _wasm_const(1) + b"\x75"
        return (_emit_wasm(ctx, node[3], lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
                + rhs + bytes([spec["wasm_opcode"]]))
    if isinstance(h, list):                                             # ((fn ..) args) — compute head, then apply as a closure
        arity = len(node[1:])
        apply_id = ctx.apply_ids.get(arity)
        if apply_id is None:
            raise frontend.error("wasm closures currently support this arity only when an apply helper exists")
        out = _emit_wasm(ctx, h, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        for a in node[1:]:
            out += _emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x10" + _leb_u(apply_id + _WASM_IMPORTS)
    if h == "fn":
        spec = ctx.closures.get(id(node))
        if spec is None: raise frontend.error("wasm: missing closure spec")
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
        body = frontend.roleclauses(node[2:])[3]
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
        if node[1] not in frontend.op:
            raise frontend.error("wasm: with currently supports builtin effects only")
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
            raise frontend.error("wasm: missing arity-0 apply helper")
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
    transparent_body = _wasm_transparent_body(frontend, node)
    if transparent_body is not None:
        return _emit_wasm_seq(ctx, transparent_body, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
    if h == "ffi":
        if type(node[1]) is not str:
            raise frontend.error("wasm: ffi name must be a string literal")
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
            raise frontend.error("wasm closures currently support this arity only when an apply helper exists")
        out = b"\x20" + _leb_u(lmap[h])
        for a in node[1:]:
            out += _emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers)
        return out + b"\x10" + _leb_u(apply_id + _WASM_IMPORTS)
    if h in fmap:                                                       # call $fn  (first-order / recursive)
        return b"".join(_emit_wasm(ctx, a, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, callable_env, handled_effs, with_handlers) for a in node[1:]) + b"\x10" + _leb_u(fmap[h] + _WASM_IMPORTS)
    raise frontend.error("wasm: form not yet in the WASM backend: " + str(h))

def _wasm_defxs(program_src, frontend):
    return [t for t in frontend.parse(program_src) if isinstance(t, list) and t and t[0] == "defx"]

def _wasm_topdefs(program_src, frontend):
    return {t[1]: i for i, t in enumerate(_wasm_defxs(program_src, frontend))}

def _wasm_collect_closures(program_src, frontend):
    """Collect lambda literals for the WASM closure runtime.
    A lambda captures the current lexical scope by value (all currently-bound locals in scope order)."""
    ds = _wasm_defxs(program_src, frontend)
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
            params = [frontend.pname(p) for p in node[1]]
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
            if frontend.platent(node[1][0]) is not None if node[1] else False:
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
        params = [frontend.pname(p) for p in fn[1]]
        callable_env = {frontend.pname(p) for p in fn[1] if frontend.platent(p) is not None}
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

def _wasm_tags(program_src, frontend):                               # program-wide tag -> integer id (variant + match tags share one numbering)
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
    for t in _wasm_defxs(program_src, frontend): w(t[3])
    return tags

def _wasm_fields(program_src, frontend, capture_slots=8):            # program-wide field -> integer id (records + get share one numbering)
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
    for t in _wasm_defxs(program_src, frontend): w(t[3])
    return fields

def _wasm_resources(program_src, frontend):
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
    for t in _wasm_defxs(program_src, frontend):
        w(t[3])
    return resources

def _wasm_foreigns(program_src, frontend):
    foreigns = {}
    def w(n):
        if not isinstance(n, list) or not n:
            return
        if n[0] == "ffi" and len(n) >= 2 and type(n[1]) is str:
            foreigns.setdefault(n[1], len(foreigns))
        for a in n[1:]:
            w(a)
    for t in _wasm_defxs(program_src, frontend):
        w(t[3])
    return foreigns

def _wasm_strings(program_src, frontend):
    strings = {}
    def w(n):
        if type(n) is str:
            strings.setdefault(n, len(strings))
            return
        if not isinstance(n, list):
            return
        for a in n:
            w(a)
    for t in _wasm_defxs(program_src, frontend):
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

class _WasmContext:
    """All program-specific WASM state, isolated per compilation."""
    __slots__ = ("frontend", "defs", "top", "closures", "closure_by_id", "order", "topdefs",
                 "helper_base", "apply_arities", "apply_ids", "apply1_id",
                 "variant_id", "alloc_id", "resource_use_id", "tags", "fields", "resources", "foreigns",
                 "strings", "string_layout", "hp_init")

    def __init__(self, program_src, frontend):
        self.frontend = frontend
        self.defs, self.top, self.closures, self.order = _wasm_collect_closures(program_src, frontend)
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
            arity: self.helper_base + 7 + i
            for i, arity in enumerate(self.apply_arities)
        }
        self.apply1_id = self.apply_ids.get(1, self.helper_base + 7)
        self.variant_id = self.helper_base + 4
        self.alloc_id = self.helper_base + 5
        self.resource_use_id = self.helper_base + 6
        self.tags = _wasm_tags(program_src, frontend)
        capture_slots = max([8] + [len(spec["captures"]) for spec in self.order])
        self.fields = _wasm_fields(program_src, frontend, capture_slots)
        self.resources = _wasm_resources(program_src, frontend)
        self.foreigns = _wasm_foreigns(program_src, frontend)
        self.strings = _wasm_strings(program_src, frontend)
        self.string_layout, self.hp_init = _wasm_string_layout(self.strings)

def compile_wasm(program_src, frontend):
    """Compile checked LOOM to a real WebAssembly module.
    Integers use even immediates; odd values are typed heap pointers, so host decoding never guesses from pointer shape."""
    _, errs = frontend.check(frontend.parse(program_src))
    if errs: raise frontend.error("; ".join(errs))
    ctx = _WasmContext(program_src, frontend)
    ds, order = ctx.defs, ctx.order
    helper_base, apply_arities = ctx.helper_base, ctx.apply_arities
    fmap = {t[1]: i for i, t in enumerate(ds)}; rec_i = helper_base; get_i = helper_base + 1; cons_i = helper_base + 2
    tags, fields = ctx.tags, ctx.fields
    funcs = []                                              # (name, arity, n_locals, code, params)
    for t in ds:
        fn = t[3]; params = [frontend.pname(p) for p in fn[1]]; names = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, names, flags)
        seen = list(dict.fromkeys(["hd"] + names))         # handler temp + unique let-names + match-vars -> local slots after the params
        lmap = {p: i for i, p in enumerate(params)}
        for j, nm in enumerate(seen): lmap[nm] = len(params) + j
        si = len(params) + len(seen)                        # one shared scrutinee temp per function (used by match)
        nloc = len(seen) + (1 if flags["match"] else 0)
        funcs.append((t[1], len(params), nloc, _emit_wasm(ctx, fn[2:][-1] if fn[2:] else 0, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, set(frontend.pname(p) for p in fn[1] if frontend.platent(p) is not None), None, None) + b"\x0b", params))
    lambda_funcs = []
    for spec in order:
        fn = spec["node"]; params = spec["captures"] + [frontend.pname(p) for p in fn[1]]
        names = []; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, names, flags)
        seen = list(dict.fromkeys(["hd"] + names))
        lmap = {p: i for i, p in enumerate(params)}
        for j, nm in enumerate(seen): lmap[nm] = len(params) + j
        si = len(params) + len(seen)
        nloc = len(seen) + (1 if flags["match"] else 0)
        lambda_callable = set(spec["callable"]) | {frontend.pname(p) for p in fn[1] if frontend.platent(p) is not None}
        lambda_funcs.append((spec["name"], len(params), nloc, _emit_wasm(ctx, fn[2:][-1] if fn[2:] else 0, lmap, fmap, cons_i, rec_i, get_i, tags, fields, si, lambda_callable, None, None) + b"\x0b", params, spec))
    rec_code = (b"\x23\x00\x21\x03"                                         # $t = $hp
                b"\x23\x00\x41\x10\x6a\x24\x00"                              # $hp += 16
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
    cons_code = (b"\x23\x00\x21\x02" b"\x23\x00\x41\x0c\x6a\x24\x00"
                 b"\x20\x02" + _wasm_const(_WASM_K_LIST) + b"\x36\x02\x00"
                 b"\x20\x02\x20\x00\x36\x02\x04" b"\x20\x02\x20\x01\x36\x02\x08"
                 b"\x20\x02" + _wasm_const(1) + b"\x72\x0b")
    effbox_code = (b"\x23\x00\x21\x02" b"\x23\x00\x41\x0c\x6a\x24\x00"
                   b"\x20\x02" + _wasm_const(_WASM_K_EFFECT) + b"\x36\x02\x00"
                   b"\x20\x02\x20\x00\x36\x02\x04"
                   b"\x20\x02\x20\x01\x36\x02\x08"
                   b"\x20\x02" + _wasm_const(1) + b"\x72\x0b")
    variant_code = (b"\x23\x00\x21\x02" b"\x23\x00\x41\x0c\x6a\x24\x00"
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
    fc = _leb_u(len(funcs) + len(lambda_funcs) + 7 + len(apply_arities)) + b"".join(_leb_u(ti[a]) for _, a, _, _, _ in funcs) + b"".join(_leb_u(ti[a]) for _, a, _, _, _, _ in lambda_funcs) + _leb_u(ti[3]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[2]) + _leb_u(ti[1]) + b"".join(_leb_u(ti[arity + 1]) for arity in apply_arities)
    mc = _leb_u(1) + b"\x00" + _leb_u(1)                    # 1 memory, min 1 page (64 KiB heap)
    gc = (_leb_u(2)
          + b"\x7f\x01" + _wasm_const(ctx.hp_init) + b"\x0b"                       # mutable i32 $hp = static-data end
          + b"\x7f\x00" + _wasm_const(WASM_ABI_VERSION) + b"\x0b")  # immutable raw ABI version
    ic = (_leb_u(8)
          + _leb_u(len("env")) + b"env" + _leb_u(len("push_handler")) + b"push_handler" + b"\x00" + _leb_u(ti[2])
          + _leb_u(len("env")) + b"env" + _leb_u(len("pop_handler")) + b"pop_handler" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("current_handler")) + b"current_handler" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("host_print")) + b"host_print" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("push_caps")) + b"push_caps" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("pop_caps")) + b"pop_caps" + b"\x00" + _leb_u(ti[0])
          + _leb_u(len("env")) + b"env" + _leb_u(len("has_cap")) + b"has_cap" + b"\x00" + _leb_u(ti[1])
          + _leb_u(len("env")) + b"env" + _leb_u(len("host_ffi")) + b"host_ffi" + b"\x00" + _leb_u(ti[3]))
    ec = _leb_u(len(funcs) + 2)
    ec += _leb_u(len("memory")) + b"memory" + b"\x02" + _leb_u(0)                  # export linear memory for the heap-backed runtime
    abi_name = b"loom_abi_version"
    ec += _leb_u(len(abi_name)) + abi_name + b"\x03" + _leb_u(1)                    # export immutable global 1
    for i, t in enumerate(ds):
        nb = t[1].encode(); ec += _leb_u(len(nb)) + nb + b"\x00" + _leb_u(i + _WASM_IMPORTS)         # export func
    cc = _leb_u(len(funcs) + len(lambda_funcs) + 7 + len(apply_arities))
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
    resource_use_code = (b"\x23\x00\x21\x01"
                         b"\x23\x00\x41\x08\x6a\x24\x00"
                         b"\x20\x01" + _wasm_const(_WASM_K_RESOURCE) + b"\x36\x02\x00"
                         b"\x20\x01\x20\x00\x36\x02\x04"
                         b"\x20\x01" + _wasm_const(1) + b"\x72\x0b")
    e = (_leb_u(1) + _leb_u(1) + b"\x7f") + resource_use_code; cc += _leb_u(len(e)) + e         # $resuse: 1 local ($t)
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

def emit_wat(program_src, frontend):
    """Human-readable WebAssembly Text (the 'assembler') for what compile_wasm encodes to bytes:
    tagged integers plus typed list/record/variant/closure/effect objects on a linear-memory heap."""
    _, errs = frontend.check(frontend.parse(program_src))
    if errs: raise frontend.error("; ".join(errs))
    ctx = _WasmContext(program_src, frontend)
    ds, order = ctx.defs, ctx.order
    helper_base, apply_arities = ctx.helper_base, ctx.apply_arities
    fmap = {t[1]: i for i, t in enumerate(ds)}; tags, fields = ctx.tags, ctx.fields; uses_heap = [False]; uses_print = [False]
    _OP = {"+": "i32.add", "-": "i32.sub", "*": "i32.mul", "=": "i32.eq", "<": "i32.lt_s", ">": "i32.gt_s"}
    def w(node, ind, handled_effs=None, with_handlers=None, callable_env=None):
        handled_effs = handled_effs or set()
        with_handlers = with_handlers or {}
        callable_env = callable_env or set()
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
            return [ind + "i32.const " + str(ctx.string_layout[node]["tagged"]) + "  ;; string literal"]
        h = node[0]
        if h == "asm":
            error = asm_validation_error(node)
            if error: raise frontend.error(error)
            spec = asm_metadata(node)
            rhs = w(node[4], ind, handled_effs, with_handlers, callable_env)
            if spec["wasm_rhs"] == "unbox_i31":
                rhs += [ind + "i32.const 1", ind + "i32.shr_s"]
            return (w(node[3], ind, handled_effs, with_handlers, callable_env)
                    + rhs + [ind + spec["wat_opcode"] + "  ;; checked asm " + str(node[1]) + " " + str(node[2])])
        if h == "fn":
            spec = ctx.closures.get(id(node))
            if spec is None: raise frontend.error("wat: missing closure spec")
            uses_heap[0] = True
            rec = [["code", spec["id"]]] + [[f"e{i}", cap] for i, cap in enumerate(spec["captures"])]
            return w(["record"] + rec, ind, handled_effs, with_handlers, callable_env)
        if h in ("+", "*"):
            o = w(node[1], ind, handled_effs, with_handlers, callable_env)
            for a in node[2:]:
                o += w(a, ind, handled_effs, with_handlers, callable_env)
                if h == "*": o += [ind + "i32.const 1", ind + "i32.shr_s"]
                o += [ind + _OP[h]]
            return o
        if h == "-": return w(node[1], ind, handled_effs, with_handlers, callable_env) + w(node[2], ind, handled_effs, with_handlers, callable_env) + [ind + _OP[h]]
        if h in ("=", "<", ">"): return w(node[1], ind, handled_effs, with_handlers, callable_env) + w(node[2], ind, handled_effs, with_handlers, callable_env) + [ind + _OP[h], ind + "i32.const 1", ind + "i32.shl"]
        if h == "if":
            return (w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "if (result i32)"] + w(node[2], ind + "  ", handled_effs, with_handlers, callable_env)
                    + [ind + "else"] + w(node[3], ind + "  ", handled_effs, with_handlers, callable_env) + [ind + "end"])
        if h == "let":
            o = w(node[1][1], ind, handled_effs, with_handlers, callable_env) + [ind + "local.set $" + node[1][0]]
            ncall = set(callable_env)
            if _wasm_is_closure_expr(ctx, node[1][1], callable_env):
                ncall.add(node[1][0])
            for b in node[2:]: o += w(b, ind, handled_effs, with_handlers, ncall)
            return o
        if h == "seamN":
            return w(["seam"] + node[2:], ind, handled_effs, with_handlers, callable_env)
        if h in ("seam", "seam1"):
            body = frontend.roleclauses(node[2:])[3]
            o = [ind + "i32.const " + str(_wasm_capmask(node[1])), ind + "call $push_caps", ind + "drop"]
            for b in body:
                o += w(b, ind, handled_effs, with_handlers, callable_env)
            return o + [ind + "call $pop_caps", ind + "drop"]
        if h == "handle":
            nh = set(handled_effs) | {"IO"}
            o = []
            for b in node[2:]: o += w(b, ind, nh, with_handlers, callable_env)
            return o
        if h == "with":
            if node[1] not in frontend.op:
                raise frontend.error("wat: with currently supports builtin effects only")
            nh = dict(with_handlers); nh[node[1]] = node[2]
            o = []
            for b in node[3:]: o += w(b, ind, handled_effs, nh, callable_env)
            return o
        if h == "print":
            uses_print[0] = True
            if "IO" in with_handlers:
                return w(with_handlers["IO"], ind, handled_effs, with_handlers, callable_env) + w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "call $apply1"]
            cap = [ind + "i32.const 0  ;; effect IO", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end"]
            if "IO" in handled_effs:
                return cap + w(node[1], ind, handled_effs, with_handlers, callable_env)
            return cap + w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "call $host_print"]
        if h == "net":
            uses_heap[0] = True
            if "Net" in with_handlers:
                return w(with_handlers["Net"], ind, handled_effs, with_handlers, callable_env) + w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "call $apply1"]
            return [ind + "i32.const 1  ;; effect Net", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const 1  ;; effect Net"] + w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "call $effbox"]
        if h == "rand":
            uses_heap[0] = True
            if "Rand" in with_handlers:
                return w(with_handlers["Rand"], ind, handled_effs, with_handlers, callable_env) + [ind + "call $apply0"]
            return [ind + "i32.const 2  ;; effect Rand", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const 2  ;; effect Rand", ind + "i32.const 0"] + [ind + "call $effbox"]
        if h == "alloc":
            uses_heap[0] = True
            if "Alloc" in with_handlers:
                return w(with_handlers["Alloc"], ind, handled_effs, with_handlers, callable_env) + w(node[1] if len(node) > 1 else 0, ind, handled_effs, with_handlers, callable_env) + [ind + "call $apply1"]
            if len(node) == 1:
                return [ind + "i32.const 3  ;; effect Alloc", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end", ind + "i32.const " + str(_WASM_NIL)]
            return [ind + "i32.const 3  ;; effect Alloc", ind + "call $has_cap", ind + "i32.eqz", ind + "if", ind + "  unreachable", ind + "end"] + w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "i32.const 0", ind + "call $alloc"]
        transparent_body = _wasm_transparent_body(frontend, node)
        if transparent_body is not None:
            return seq(transparent_body)
        if h == "ffi":
            if type(node[1]) is not str:
                raise frontend.error("wat: ffi name must be a string literal")
            uses_heap[0] = True
            return ([ind + "i32.const " + str(ctx.foreigns[node[1]]) + "  ;; foreign " + node[1]]
                    + w(["list"] + node[2:], ind, handled_effs, with_handlers, callable_env)
                    + [ind + "i32.const " + ("1" if "IO" in handled_effs else "0"),
                       ind + "call $host_ffi"])
        if h == "use":
            uses_heap[0] = True
            return [ind + "i32.const " + str(ctx.resources[node[1]]) + "  ;; resource " + node[1], ind + "call $resuse"]
        if h == "record":
            uses_heap[0] = True
            items = [fld for fld in node[1:] if isinstance(fld, list) and len(fld) >= 2]
            out = [ind + "i32.const 0"]
            for fld in reversed(items):
                out = out + [ind + "i32.const " + str(fields[fld[0]])] + w(fld[1], ind, handled_effs, with_handlers, callable_env) + [ind + "call $rec"]
            return out
        if h == "get":
            uses_heap[0] = True
            return w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "i32.const " + str(fields[node[2]])] + [ind + "call $get"]
        if h == "list":
            uses_heap[0] = True; o = []
            for a in node[1:]: o += w(a, ind, handled_effs, with_handlers, callable_env)
            return o + [ind + "i32.const " + str(_WASM_NIL)] + [ind + "call $cons" for _ in node[1:]]
        if h == "cons": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env) + w(node[2], ind, handled_effs, with_handlers, callable_env) + [ind + "call $cons"]
        if h == "head": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "i32.const -2", ind + "i32.and", ind + "i32.load offset=4"]
        if h == "tail": uses_heap[0] = True; return w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "i32.const -2", ind + "i32.and", ind + "i32.load offset=8"]
        if h == "empty": return w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "i32.const " + str(_WASM_NIL), ind + "i32.eq", ind + "i32.const 1", ind + "i32.shl"]
        if h == "variant":
            uses_heap[0] = True
            return [ind + "i32.const " + str(tags[node[1]]) + "  ;; tag " + node[1]] + w(node[2], ind, handled_effs, with_handlers, callable_env) + [ind + "call $variant"]
        if h == "match":
            uses_heap[0] = True; o = w(node[1], ind, handled_effs, with_handlers, callable_env) + [ind + "local.set $s"]
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
                raise frontend.error("wat closures currently support this arity only when an apply helper exists")
            out = w(h, ind, handled_effs, with_handlers, callable_env)
            for a in node[1:]:
                out += w(a, ind, handled_effs, with_handlers, callable_env)
            return out + [ind + "call $apply" + str(arity)]
        if h in callable_env:
            arity = len(node[1:])
            if arity not in ctx.apply_ids:
                raise frontend.error("wat closures currently support this arity only when an apply helper exists")
            out = [ind + "local.get $" + h]
            for a in node[1:]:
                out += w(a, ind, handled_effs, with_handlers, callable_env)
            return out + [ind + "call $apply" + str(arity)]
        if h in fmap:
            o = []
            for a in node[1:]: o += w(a, ind, handled_effs, with_handlers, callable_env)
            return o + [ind + "call $" + h]
        raise frontend.error("wat: form not yet in the WASM backend: " + str(h))
    bodies = []
    for t in ds:
        fn = t[3]; pn = [frontend.pname(p) for p in fn[1]]; sig = " ".join("(param $" + p + " i32)" for p in pn)
        nm = ["hd"]; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, nm, flags)
        locs = " ".join("(local $" + x + " i32)" for x in dict.fromkeys(nm))
        if flags["match"]: locs = (locs + " " if locs else "") + "(local $s i32)"
        head = "  (func $" + t[1] + ((" " + sig) if sig else "") + " (result i32)" + ((" " + locs) if locs else "")
        callable_env = set(frontend.pname(p) for p in fn[1] if frontend.platent(p) is not None)
        bodies.append([head] + w(fn[2:][-1] if fn[2:] else 0, "    ", None, None, callable_env)
                      + ["  )", '  (export "' + t[1] + '" (func $' + t[1] + "))"])
    for spec in order:
        fn = spec["node"]; params = spec["captures"] + [frontend.pname(p) for p in fn[1]]; sig = " ".join("(param $" + p + " i32)" for p in params)
        nm = ["hd"]; flags = {"match": False}
        for b in fn[2:]: _wasm_locals(b, nm, flags)
        locs = " ".join("(local $" + x + " i32)" for x in dict.fromkeys(nm))
        if flags["match"]: locs = (locs + " " if locs else "") + "(local $s i32)"
        head = "  (func $" + spec["name"] + ((" " + sig) if sig else "") + " (result i32)" + ((" " + locs) if locs else "")
        lambda_callable = set(spec["callable"]) | {frontend.pname(p) for p in fn[1] if frontend.platent(p) is not None}
        bodies.append([head] + w(fn[2:][-1] if fn[2:] else 0, "    ", None, None, lambda_callable) + ["  )"])
    lines = ["(module", "  (global $loom_abi_version i32 (i32.const " + str(WASM_ABI_VERSION) + "))",
             '  (export "loom_abi_version" (global $loom_abi_version))']
    if uses_heap[0]:
        lines += ["  (memory 1)", '  (export "memory" (memory 0))', "  (global $hp (mut i32) (i32.const " + str(ctx.hp_init) + "))",
                  "  (func $rec (param $next i32) (param $fid i32) (param $val i32) (result i32) (local $t i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 16  i32.add  global.set $hp",
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
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 12  i32.add  global.set $hp",
                  "    local.get $t  i32.const 1  i32.store  ;; list kind",
                  "    local.get $t  local.get $v  i32.store offset=4",
                  "    local.get $t  local.get $rest  i32.store offset=8",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $effbox (param $eff i32) (param $payload i32) (result i32) (local $t i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 12  i32.add  global.set $hp",
                  "    local.get $t  i32.const 4  i32.store  ;; effect kind",
                  "    local.get $t  local.get $eff  i32.store offset=4",
                  "    local.get $t  local.get $payload  i32.store offset=8",
                  "    local.get $t  i32.const 1  i32.or)",
                  "  (func $variant (param $tag i32) (param $payload i32) (result i32) (local $t i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 12  i32.add  global.set $hp",
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
                  "    end)",
                  "  (func $resuse (param $rid i32) (result i32) (local $t i32)",
                  "    global.get $hp  local.set $t",
                  "    global.get $hp  i32.const 8  i32.add  global.set $hp",
                  "    local.get $t  i32.const 5  i32.store  ;; resource-use kind",
                  "    local.get $t  local.get $rid  i32.store offset=4",
                  "    local.get $t  i32.const 1  i32.or)"]
        for spec in ctx.string_layout.values():
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

def run_wasm(program_src, call_src, frontend):
    """Compile to wasm bytes, run via node's built-in WebAssembly, and decode the observable result. Needs node."""
    import subprocess, json as _json
    def _norm(v):
        if isinstance(v, dict):
            return {k: _norm(x) for k, x in v.items()}
        if isinstance(v, list):
            vv = [_norm(x) for x in v]
            return tuple(vv) if len(vv) == 2 and isinstance(vv[0], str) and vv[0][:1].isupper() else vv
        return v
    c = frontend.parse(call_src)[0]                                  # call site = (NAME int-args...) for the integer core
    frontend.check_call_literals([c])
    name = c[0] if isinstance(c, list) else c
    args = c[1:] if isinstance(c, list) else []
    if not all(isinstance(a, int) for a in args):
        raise frontend.error("node-wasm: call arguments must currently be integers")
    _, _, _, closure_order = _wasm_collect_closures(program_src, frontend)
    capture_slots = max([8] + [len(spec["captures"]) for spec in closure_order])
    tags_json = _json.dumps({str(v): k for k, v in _wasm_tags(program_src, frontend).items()})
    fields_json = _json.dumps({str(v): k for k, v in _wasm_fields(program_src, frontend, capture_slots).items()})
    resources_json = _json.dumps({str(v): k for k, v in _wasm_resources(program_src, frontend).items()})
    foreigns_json = _json.dumps({str(v): k for k, v in _wasm_foreigns(program_src, frontend).items()})
    arr = ",".join(str(b) for b in compile_wasm(program_src, frontend))
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
          "const __ffi=(id,args,silent)=>{ const name=__foreigns[String(id)]??String(id); const argv=__dec(args); const raw0=(args===3)?0:__rd((args&-2)+4); if(name==='logger'){ if(__has_cap(0) && !silent) __out.push('foreign:'+String(argv[0])); return raw0|0; } if(name==='lib'||name==='x'||name==='other') return raw0|0; throw new Error('unknown foreign fn: '+name); };"
          "const __imports={env:{push_handler:__push,pop_handler:__pop,current_handler:__cur,host_print:(x)=>{__out.push(String(__dec(x)));return x|0;},push_caps:__push_caps,pop_caps:__pop_caps,has_cap:__has_cap,host_ffi:(id,args,silent)=>__ffi(id|0,args|0,silent|0)}};"
          "WebAssembly.instantiate(new Uint8Array([" + arr + "]), __imports)"
          ".then(m=>{__mem=m.instance.exports.memory ? new DataView(m.instance.exports.memory.buffer) : null;"
          "const __abi=m.instance.exports.loom_abi_version;if(!__abi||__abi.value!==" + str(WASM_ABI_VERSION) + ")throw new Error('unsupported LOOM WASM ABI');"
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
    if r.returncode != 0: raise frontend.error("node-wasm: " + r.stderr.strip()[:200])
    val = None; out = []
    for ln in r.stdout.strip().splitlines():
        if ln.startswith("__VAL__"): val = _norm(_json.loads(ln[7:]))
        elif ln.startswith("__OUT__"): out = _json.loads(ln[7:])
    if val is None: raise frontend.error("node-wasm: missing result")
    return val, out
