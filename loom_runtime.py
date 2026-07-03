#!/usr/bin/env python3
"""Runtime evaluator for LOOM programs."""

from contextvars import ContextVar

from loom_frontend import RuntimeFrontend as _RuntimeFrontend, asm_validation_error


class Frontend(_RuntimeFrontend):
    __slots__ = ()


class _RuntimeState:
    """Mutable runtime capability state scoped to one run_call() invocation."""
    __slots__ = ("caps",)

    def __init__(self):
        self.caps = []


class Closure:
    __slots__ = ("params", "body", "env")

    def __init__(self, params, body, env):
        self.params = params
        self.body = body
        self.env = env


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


_RUNTIME_STATE = ContextVar("loom_runtime_state", default=None)


def _runtime_state():
    state = _RUNTIME_STATE.get()
    if state is None:
        state = _RuntimeState()
        _RUNTIME_STATE.set(state)
    return state


def _cap_ok(eff):
    caps = _runtime_state().caps
    return (not caps) or (eff in caps[-1])


def _foreign_logger(args, out):
    if _cap_ok("IO"):
        out.append("foreign:" + str(args[0]))
    return args[0]


def _foreign_opaque(args, out):
    return args[0] if args else 0


FOREIGN = {
    "logger": _foreign_logger,
    "lib": _foreign_opaque,
    "x": _foreign_opaque,
    "other": _foreign_opaque,
}


def _eval_seq(frontend, body, env, fns, out, handlers):
    result = None
    for node in body:
        result = ev(frontend, node, env, fns, out, handlers)
    return result


def _bind_params(frontend, params, args, base_env=None):
    env = {} if base_env is None else dict(base_env)
    env.update(zip([frontend.pname(param) for param in params], args))
    return env


def call_fn(frontend, val, args, fns, out, handlers):
    """Apply a function VALUE (a Closure or a named-fn string) to already-evaluated args."""
    if isinstance(val, Closure):
        return _eval_seq(frontend, val.body, _bind_params(frontend, val.params, args, val.env), fns, out, handlers)
    if _is_symbol(val) and val in fns:
        fn = fns[val]["fn"]
        return _eval_seq(frontend, fn[2:], _bind_params(frontend, fn[1], args), fns, out, handlers)
    raise frontend.error(f"not a function: {val}")


def ev(frontend, node, env, fns, out, handlers=None):
    handlers = handlers or {}
    if isinstance(node, int):
        return node
    if _is_symbol(node):
        return env.get(node, node)
    if type(node) is str:
        return node
    head = node[0]
    if head == "fn":
        return Closure(node[1], node[2:], env)
    if head == "seamN":
        return ev(frontend, ["seam"] + node[2:], env, fns, out, handlers)
    if head == "repro":
        return _eval_seq(frontend, node[1:], env, fns, out, handlers)
    if head in ("seam", "seam1"):
        caps = _runtime_state().caps
        caps.append(set(node[1]) - {"Pure"})
        try:
            return _eval_seq(frontend, frontend.roleclauses(node[2:])[3], env, fns, out, handlers)
        finally:
            caps.pop()
    if head == "ffi":
        foreign = FOREIGN.get(node[1])
        if foreign is None:
            raise frontend.error(f"unknown foreign fn: {node[1]}")
        return foreign([ev(frontend, arg, env, fns, out, handlers) for arg in node[2:]], out)
    if head == "handle":
        sink = [] if "IO" in set(node[1]) else out
        return _eval_seq(frontend, node[2:], env, fns, sink, handlers)
    if head == "with":
        op = frontend.op.get(node[1])
        handler_fn = ev(frontend, node[2], env, fns, out, handlers)
        return _eval_seq(frontend, node[3:], env, fns, out, {**handlers, op: handler_fn} if op else handlers)
    if head == "use":
        return f"<used:{node[1]}>"
    if head in ("resource", "prov"):
        return _eval_seq(frontend, node[2:], env, fns, out, handlers)
    if head == "by":
        return _eval_seq(frontend, node[3:], env, fns, out, handlers)
    if head == "recall":
        return _eval_seq(frontend, node[1:], env, fns, out, handlers)
    if head == "declassify":
        return _eval_seq(frontend, node[2:], env, fns, out, handlers)
    if head == "trust":
        spec = node[1] if len(node) > 1 else None
        if isinstance(spec, int):
            body = node[2:]
        elif isinstance(spec, list) and spec and spec[0] == "roles":
            body = node[2:]
            while body and isinstance(body[0], list) and len(body[0]) >= 3 and body[0][0] == "sub":
                body = body[1:]
        else:
            body = node[1:]
        return _eval_seq(frontend, body, env, fns, out, handlers)
    if head == "record":
        return {field[0]: ev(frontend, field[1], env, fns, out, handlers) for field in node[1:] if isinstance(field, list) and len(field) >= 2}
    if head == "get":
        record = ev(frontend, node[1], env, fns, out, handlers)
        return record[node[2]] if isinstance(record, dict) and node[2] in record else None
    if head == "variant":
        return (node[1], ev(frontend, node[2], env, fns, out, handlers))
    if head == "match":
        tag, value = ev(frontend, node[1], env, fns, out, handlers)
        for arm in node[2:]:
            pattern, body = arm[0], arm[1]
            if pattern[0] == tag:
                local_env = {**env, pattern[1]: value} if len(pattern) >= 2 else env
                return ev(frontend, body, local_env, fns, out, handlers)
        raise frontend.error(f"no match arm for tag {tag!r}")
    if head == "if":
        cond = ev(frontend, node[1], env, fns, out, handlers)
        live = (cond != 0) if isinstance(cond, int) else bool(cond)
        return ev(frontend, node[2] if live else node[3], env, fns, out, handlers)
    if head == "let":
        local_env = {**env, node[1][0]: ev(frontend, node[1][1], env, fns, out, handlers)}
        return _eval_seq(frontend, node[2:], local_env, fns, out, handlers)
    if head == "asm":
        raise frontend.error(asm_validation_error(node))
    args = [ev(frontend, arg, env, fns, out, handlers) for arg in node[1:]]
    if head == "+":
        return frontend.i31(sum(args))
    if head == "-":
        return frontend.i31(args[0] - args[1])
    if head == "*":
        result = 1
        for arg in args:
            result = frontend.i31(result * arg)
        return result
    if head == "=":
        return 1 if args[0] == args[1] else 0
    if head == "<":
        return 1 if args[0] < args[1] else 0
    if head == ">":
        return 1 if args[0] > args[1] else 0
    if head == "list":
        return list(args)
    if head == "cons":
        return [args[0]] + args[1]
    if head == "head":
        return args[0][0]
    if head == "tail":
        return args[0][1:]
    if head == "empty":
        return 1 if len(args[0]) == 0 else 0
    if head in frontend.op.values() and head in handlers:
        return call_fn(frontend, handlers[head], args, fns, out, {name: handler for name, handler in handlers.items() if name != head})
    if head == "print":
        if not _cap_ok("IO"):
            raise frontend.error("capability denied: IO not granted by enclosing seam")
        out.append(str(args[0]))
        return args[0]
    if head == "net":
        if not _cap_ok("Net"):
            raise frontend.error("capability denied: Net not granted by enclosing seam")
        return ("Net", args[0])
    if head == "alloc":
        if not _cap_ok("Alloc"):
            raise frontend.error("capability denied: Alloc not granted by enclosing seam")
        return list(range(args[0])) if args else []
    if head == "rand":
        if not _cap_ok("Rand"):
            raise frontend.error("capability denied: Rand not granted by enclosing seam")
        return ("Rand", 0)
    fn_value = None
    if _is_symbol(head):
        if head in fns:
            fn_value = fns[head]
        else:
            target = env.get(head)
            if _is_symbol(target) and target in fns:
                fn_value = fns[target]
            elif isinstance(target, Closure):
                fn_value = target
    elif isinstance(head, list):
        target = ev(frontend, head, env, fns, out, handlers)
        fn_value = target if isinstance(target, Closure) else (fns[target] if _is_symbol(target) and target in fns else None)
    if isinstance(fn_value, Closure):
        return _eval_seq(frontend, fn_value.body, _bind_params(frontend, fn_value.params, args, fn_value.env), fns, out, handlers)
    if isinstance(fn_value, dict):
        fn = fn_value["fn"]
        return _eval_seq(frontend, fn[2:], _bind_params(frontend, fn[1], args, env), fns, out, handlers)
    raise frontend.error(f"unknown form: {head}")


def run_call(program_src, call_src, frontend):
    """Static-check a program, then evaluate one call against it."""
    fns, errs = frontend.check(frontend.parse(program_src))
    if errs:
        raise frontend.error("; ".join(errs))
    token = _RUNTIME_STATE.set(_RuntimeState())
    try:
        out = []
        call_ast = frontend.parse(call_src)
        frontend.check_call_literals(call_ast)
        return ev(frontend, call_ast[0], {}, fns, out), out
    finally:
        _RUNTIME_STATE.reset(token)
