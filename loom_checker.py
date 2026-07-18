#!/usr/bin/env python3
"""Static checker for LOOM programs.

The checker is frontend-agnostic. Syntax helpers, constants, and error types are
provided explicitly through Frontend, avoiding imports and circular loading.
"""

from contextvars import ContextVar

from loom_frontend import asm_metadata, asm_validation_error
import loom_bounds
from loom_recursion import descent_certificate


class Frontend:
    __slots__ = (
        "effects", "builtin_eff", "pure_ops", "plin", "pname", "platent",
        "is_var", "is_fn_expr", "int_literal_errors", "int_min", "int_max",
        "i31", "miss", "error", "op_eff",
    )

    def __init__(
        self,
        effects,
        builtin_eff,
        pure_ops,
        plin,
        pname,
        platent,
        is_var,
        is_fn_expr,
        int_literal_errors,
        int_min,
        int_max,
        i31,
        miss,
        error,
    ):
        self.effects = effects
        self.builtin_eff = builtin_eff
        self.pure_ops = pure_ops
        self.plin = plin
        self.pname = pname
        self.platent = platent
        self.is_var = is_var
        self.is_fn_expr = is_fn_expr
        self.int_literal_errors = int_literal_errors
        self.int_min = int_min
        self.int_max = int_max
        self.i31 = i31
        self.miss = miss
        self.error = error
        self.op_eff = {op: next(iter(effs)) for op, effs in builtin_eff.items()}


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


def _checker_state():
    state = _CHECKER_STATE.get()
    if state is None:
        state = _CheckerState()
        _CHECKER_STATE.set(state)
    return state


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


def latent_of(frontend, arg, fns, penv, errs):
    """Latent effect-set of a function passed as a value: a named fn, a passed-through fn param, or an inline lambda."""
    if _is_symbol(arg):
        if arg in fns:
            return fns[arg]["eff"]
        if arg in penv:
            return penv[arg]
        return set()
    if isinstance(arg, list) and arg and arg[0] == "fn":
        lpenv = {
            **penv,
            **{frontend.pname(p): frontend.platent(p) for p in arg[1] if frontend.platent(p) is not None},
        }
        eff = set()
        for body in arg[2:]:
            eff |= infer(frontend, body, fns, errs, lpenv)
        return eff
    return set()


def _uadd(a, b):
    return b if a == 0 else a if b == 0 else "M"


def _ulub(a, b):
    order = {0: 0, 1: 1, "M": 2}
    return a if order[a] >= order[b] else b


def _ucount(frontend, node, fns, penv):
    """Abstract use-count {effect: 0/1/'M'} performed along ONE path."""
    out = {}

    def add(counts):
        for eff, count in counts.items():
            out[eff] = _uadd(out.get(eff, 0), count)

    if not isinstance(node, list) or not node:
        return out
    head = node[0]
    if head == "fn":
        return out
    if head == "depthN":
        for item in node[2:]:
            add(_ucount(frontend, item, fns, penv))
        return out
    if head == "use":
        return {node[1]: 1}
    if head == "resource":
        for item in node[2:]:
            add(_ucount(frontend, item, fns, penv))
        rname = node[1][0] if isinstance(node[1], list) else node[1]
        out.pop(rname, None)
        return out
    if head == "record":
        for field in node[1:]:
            if isinstance(field, list) and len(field) >= 2:
                add(_ucount(frontend, field[1], fns, penv))
        return out
    if head == "get":
        return _ucount(frontend, node[1], fns, penv)
    if head == "variant":
        return _ucount(frontend, node[2], fns, penv)
    if head == "match":
        add(_ucount(frontend, node[1], fns, penv))
        arm_counts = [_ucount(frontend, arm[1], fns, penv) for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2]
        union = set().union(*[set(counts) for counts in arm_counts]) if arm_counts else set()
        for eff in union:
            merged = 0
            for counts in arm_counts:
                merged = _ulub(merged, counts.get(eff, 0))
            out[eff] = _uadd(out.get(eff, 0), merged)
        return out
    if head == "if":
        add(_ucount(frontend, node[1], fns, penv))
        then_counts = _ucount(frontend, node[2], fns, penv)
        else_counts = _ucount(frontend, node[3], fns, penv)
        for eff in set(then_counts) | set(else_counts):
            out[eff] = _uadd(out.get(eff, 0), _ulub(then_counts.get(eff, 0), else_counts.get(eff, 0)))
        return out
    if head == "let":
        add(_ucount(frontend, node[1][1], fns, penv))
        for item in node[2:]:
            add(_ucount(frontend, item, fns, penv))
        return out
    if isinstance(head, list):
        add(_ucount(frontend, head, fns, penv))
        for arg in node[1:]:
            add(_ucount(frontend, arg, fns, penv))
        return out
    if head == "seamN":
        return _ucount(frontend, ["seam"] + node[2:], fns, penv)
    if head in ("seam", "seam1"):
        for item in _roleclauses(node[2:])[3]:
            add(_ucount(frontend, item, fns, penv))
        return out
    if head == "handle":
        for item in node[2:]:
            add(_ucount(frontend, item, fns, penv))
        for eff in set(node[1]):
            out[eff] = 0
        return out
    if head == "with":
        for item in node[3:]:
            add(_ucount(frontend, item, fns, penv))
        out[node[1]] = 0
        return out
    for arg in node[1:]:
        add(_ucount(frontend, arg, fns, penv))
    if head in frontend.op_eff:
        out[frontend.op_eff[head]] = _uadd(out.get(frontend.op_eff[head], 0), 1)
    elif head == "ffi":
        out["FFI"] = _uadd(out.get("FFI", 0), 1)
    elif head in fns:
        for eff, count in fns[head].get("uc", {}).items():
            if eff in frontend.effects:
                out[eff] = _uadd(out.get(eff, 0), count)
        for index in fns[head].get("lin", set()):
            if index < len(node) - 1 and _is_symbol(node[index + 1]):
                out[node[index + 1]] = _uadd(out.get(node[index + 1], 0), 1)
    elif penv and head in penv:
        for eff in penv[head]:
            if not frontend.is_var(eff):
                out[eff] = "M"
    return out


_NCAP = 1024
_CONTEXT_CAP = 64  # bounded direct-call specialization; unresolved depth stays fail-closed


def _nadd(a, b):
    return min(a + b, _NCAP)


def _nmul(a, b):
    return min(a * b, _NCAP)


def _nmerge(frontend, target, counts):
    for eff, count in counts.items():
        if eff in frontend.effects or not frontend.is_var(eff):
            target[eff] = _nadd(target.get(eff, 0), count)


def _callable_ncount(frontend, value, fns, penv, cenv, active, venv=None):
    venv = venv or {}
    if _is_symbol(value):
        if value in cenv:
            return dict(cenv[value])
        if value in fns:
            return _function_ncount(frontend, value, fns, {}, active, {})
        if value in penv:
            return {eff: _NCAP for eff in penv[value] if not frontend.is_var(eff)}
        return {}
    if isinstance(value, list) and value and value[0] == "fn":
        lpenv = {
            **penv,
            **{frontend.pname(p): frontend.platent(p) for p in value[1] if frontend.platent(p) is not None},
        }
        local_venv = loom_bounds.shadow(
            venv, {frontend.pname(param) for param in value[1]},
        )
        summary = {}
        for expr in value[2:]:
            _nmerge(frontend, summary, _ncount(frontend, expr, fns, lpenv, cenv, active, local_venv))
        return summary
    return {}


def _call_venv(frontend, info, args, venv):
    """Bind proven value arguments while shadowing every callee parameter."""
    venv = venv or {}
    local = loom_bounds.shadow(venv, {frontend.pname(param) for param in info["params"]})
    for index, param in enumerate(info["params"]):
        if frontend.platent(param) is None and index < len(args):
            name = frontend.pname(param)
            local = loom_bounds.bind(
                local,
                name,
                loom_bounds.value(
                    args[index], venv, frontend.int_min, frontend.int_max, frontend.i31,
                ),
            )
    return local


def _function_ncount(frontend, name, fns, bound_cenv, active, venv=None):
    info = fns[name]
    if name in active or len(active) >= _CONTEXT_CAP:
        potential = set(info.get("eff", set()))
        for expr in info["fn"][2:]:
            potential |= _recursive_meter_effects(frontend, expr, fns, {name})
        return {eff: _NCAP for eff in potential if eff in frontend.effects}
    summary = {}
    next_active = active | {name}
    for expr in info["fn"][2:]:
        _nmerge(frontend, summary, _ncount(frontend, expr, fns, info["penv"], bound_cenv, next_active, venv or {}))
    return summary


def _recursive_meter_effects(frontend, node, fns, seen):
    """Effect requests reachable in a cycle, including locally discharged ones."""
    if not isinstance(node, list) or not node:
        return set()
    head = node[0]
    if head == "fn":
        return set()
    if head == "record":
        children = [field[1] for field in node[1:] if isinstance(field, list) and len(field) >= 2]
    elif head == "get":
        children = node[1:2]
    elif head == "variant":
        children = node[2:3]
    elif head == "match":
        children = node[1:2] + [
            arm[1] for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2
        ]
    elif head == "let":
        children = [node[1][1], *node[2:]]
    elif head == "resource":
        children = node[2:]
    else:
        children = node[1:]
    out = set()
    if head in frontend.op_eff:
        out.add(frontend.op_eff[head])
    elif head == "ffi":
        out.add("FFI")
    elif head == "resource" and isinstance(node[1], list):
        out |= set(node[1][1:]) & frontend.effects
    if _is_symbol(head) and head in fns and head not in seen:
        next_seen = seen | {head}
        for expr in fns[head]["fn"][2:]:
            out |= _recursive_meter_effects(frontend, expr, fns, next_seen)
    for child in children:
        out |= _recursive_meter_effects(frontend, child, fns, seen)
    return out


def _ncount(frontend, node, fns, penv, cenv=None, active=None, venv=None):
    """Saturating path count; exact for finite statically resolved call graphs."""
    cenv = cenv or {}
    active = active or set()
    venv = venv or {}
    out = {}

    def add(counts):
        _nmerge(frontend, out, counts)

    if not isinstance(node, list) or not node:
        return out
    head = node[0]
    if head == "fn":
        return out
    if head == "depthN":
        for item in node[2:]:
            add(_ncount(frontend, item, fns, penv, cenv, active, venv))
        return out
    if head == "seamN":
        return _ncount(frontend, ["seam"] + node[2:], fns, penv, cenv, active, venv)
    if head in ("seam", "seam1"):
        for item in _roleclauses(node[2:])[3]:
            add(_ncount(frontend, item, fns, penv, cenv, active, venv))
        return out
    if head == "if":
        add(_ncount(frontend, node[1], fns, penv, cenv, active, venv))
        then_env = loom_bounds.refine(
            node[1], venv, True, frontend.int_min, frontend.int_max, frontend.i31,
        )
        else_env = loom_bounds.refine(
            node[1], venv, False, frontend.int_min, frontend.int_max, frontend.i31,
        )
        then_counts = (
            _ncount(frontend, node[2], fns, penv, cenv, active, then_env)
            if then_env is not None else {}
        )
        else_counts = (
            _ncount(frontend, node[3], fns, penv, cenv, active, else_env)
            if else_env is not None else {}
        )
        for eff in set(then_counts) | set(else_counts):
            out[eff] = _nadd(out.get(eff, 0), max(then_counts.get(eff, 0), else_counts.get(eff, 0)))
        return out
    if head == "match":
        add(_ncount(frontend, node[1], fns, penv, cenv, active, venv))
        arms = [
            _ncount(
                frontend, arm[1], fns, penv, cenv, active,
                loom_bounds.shadow(venv, loom_bounds.pattern_names(arm[0])),
            )
            for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2
        ]
        union = set().union(*[set(counts) for counts in arms]) if arms else set()
        for eff in union:
            out[eff] = _nadd(out.get(eff, 0), max(counts.get(eff, 0) for counts in arms))
        return out
    if head == "let":
        name, bound_value = node[1][0], node[1][1]
        add(_ncount(frontend, bound_value, fns, penv, cenv, active, venv))
        next_venv = loom_bounds.bind(
            venv,
            name,
            loom_bounds.value(
                bound_value, venv, frontend.int_min, frontend.int_max, frontend.i31,
            ),
        )
        next_cenv = cenv
        if frontend.is_fn_expr(bound_value, fns, penv) or (_is_symbol(bound_value) and bound_value in cenv):
            summary = _callable_ncount(frontend, bound_value, fns, penv, cenv, active, venv)
            if any(_has_head(item, name) for item in bound_value[2:] if isinstance(bound_value, list)):
                summary = {eff: _NCAP for eff in summary}
            next_cenv = {**cenv, name: summary}
        for item in node[2:]:
            add(_ncount(frontend, item, fns, penv, next_cenv, active, next_venv))
        return out
    if isinstance(head, list):
        add(_callable_ncount(frontend, head, fns, penv, cenv, active, venv))
        for arg in node[1:]:
            add(_ncount(frontend, arg, fns, penv, cenv, active, venv))
        return out
    if head == "handle":
        for item in node[2:]:
            add(_ncount(frontend, item, fns, penv, cenv, active, venv))
        return out
    if head == "with":
        body_counts = {}
        for item in node[3:]:
            _nmerge(frontend, body_counts, _ncount(frontend, item, fns, penv, cenv, active, venv))
        add(body_counts)
        requests = body_counts.get(node[1], 0)
        handler_counts = _callable_ncount(frontend, node[2], fns, penv, cenv, active, venv)
        if requests and handler_counts.get(node[1], 0):
            handler_counts = {eff: _NCAP for eff in handler_counts}
        for eff, count in handler_counts.items():
            out[eff] = _nadd(out.get(eff, 0), _nmul(requests, count))
        return out
    if head == "resource":
        spec = node[1]
        rname, reffs = (spec[0], set(spec[1:])) if isinstance(spec, list) else (spec, set())
        for item in node[2:]:
            add(_ncount(frontend, item, fns, penv, cenv, active, venv))
        uses = out.pop(rname, 0)
        for eff in reffs & frontend.effects:
            out[eff] = _nadd(out.get(eff, 0), uses)
        return out
    if head == "use":
        return {node[1]: 1}
    for arg in node[1:]:
        add(_ncount(frontend, arg, fns, penv, cenv, active, venv))
    if head in frontend.op_eff:
        out[frontend.op_eff[head]] = _nadd(out.get(frontend.op_eff[head], 0), 1)
    elif head == "ffi":
        out["FFI"] = _nadd(out.get("FFI", 0), 1)
    elif head in fns:
        bound_cenv = {}
        for index, param in enumerate(fns[head]["params"]):
            if frontend.platent(param) is not None and index + 1 < len(node):
                bound_cenv[frontend.pname(param)] = _callable_ncount(frontend, node[index + 1], fns, penv, cenv, active, venv)
        recurrence = _recurrence_ncount(frontend, head, node[1:], fns, active, venv)
        call_venv = _call_venv(frontend, fns[head], node[1:], venv)
        add(
            recurrence if recurrence is not None
            else _function_ncount(frontend, head, fns, bound_cenv, active, call_venv)
        )
    elif head in cenv:
        add(cenv[head])
    elif penv and head in penv:
        for eff in penv[head]:
            if not frontend.is_var(eff):
                out[eff] = _NCAP
    return out


def _contains_recurrence_call(node, component):
    if not isinstance(node, list) or not node:
        return False
    head = node[0]
    if head == "fn":
        return False
    if head == "record":
        return any(
            _contains_recurrence_call(field[1], component)
            for field in node[1:] if isinstance(field, list) and len(field) >= 2
        )
    if head == "get":
        return _contains_recurrence_call(node[1], component)
    if head == "variant":
        return _contains_recurrence_call(node[2], component)
    if head == "match":
        return _contains_recurrence_call(node[1], component) or any(
            _contains_recurrence_call(arm[1], component)
            for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2
        )
    if head == "let":
        return _contains_recurrence_call(node[1][1], component) or any(
            _contains_recurrence_call(child, component) for child in node[2:]
        )
    if head == "resource":
        return any(_contains_recurrence_call(child, component) for child in node[2:])
    if _is_symbol(head) and head in component:
        return True
    return (
        isinstance(head, list) and _contains_recurrence_call(head, component)
    ) or any(_contains_recurrence_call(child, component) for child in node[1:])


def _path_sequence(frontend, nodes, component, fns, penv, cenv, active):
    paths = [({}, None)]
    for node in nodes:
        next_paths = _recurrence_paths(frontend, node, component, fns, penv, cenv, active)
        if next_paths is None:
            return None
        combined = []
        for left_counts, left_call in paths:
            for right_counts, right_call in next_paths:
                if left_call is not None and right_call is not None:
                    return None
                counts = dict(left_counts)
                _nmerge(frontend, counts, right_counts)
                combined.append((counts, left_call if left_call is not None else right_call))
                if len(combined) > 4096:
                    return None
        paths = combined
    return paths


def _recurrence_paths(frontend, node, component, fns, penv, cenv, active):
    """Local maximal paths for one single-spine SCC invocation."""
    if not isinstance(node, list) or not node:
        return [({}, None)]
    if not _contains_recurrence_call(node, component):
        return [(_ncount(frontend, node, fns, penv, cenv, active), None)]
    head = node[0]
    if head == "fn":
        return [({}, None)]
    if head == "if" and len(node) >= 4:
        prefix = _recurrence_paths(frontend, node[1], component, fns, penv, cenv, active)
        branches = []
        for branch in node[2:4]:
            branch_paths = _recurrence_paths(frontend, branch, component, fns, penv, cenv, active)
            if branch_paths is None:
                return None
            branches.extend(branch_paths)
        return _combine_recurrence_paths(frontend, prefix, branches)
    if head == "match":
        prefix = _recurrence_paths(frontend, node[1], component, fns, penv, cenv, active)
        branches = []
        for arm in node[2:]:
            if isinstance(arm, list) and len(arm) >= 2:
                arm_paths = _recurrence_paths(frontend, arm[1], component, fns, penv, cenv, active)
                if arm_paths is None:
                    return None
                branches.extend(arm_paths)
        return _combine_recurrence_paths(frontend, prefix, branches)
    if head == "let":
        bound_value = node[1][1]
        bound_paths = _recurrence_paths(frontend, bound_value, component, fns, penv, cenv, active)
        if bound_paths is None:
            return None
        next_cenv = cenv
        name = node[1][0]
        if frontend.is_fn_expr(bound_value, fns, penv) or (_is_symbol(bound_value) and bound_value in cenv):
            summary = _callable_ncount(frontend, bound_value, fns, penv, cenv, active)
            next_cenv = {**cenv, name: summary}
        body_paths = _path_sequence(frontend, node[2:], component, fns, penv, next_cenv, active)
        return _combine_recurrence_paths(frontend, bound_paths, body_paths)
    if head == "record":
        return _path_sequence(
            frontend,
            [field[1] for field in node[1:] if isinstance(field, list) and len(field) >= 2],
            component, fns, penv, cenv, active,
        )
    if head == "get":
        return _recurrence_paths(frontend, node[1], component, fns, penv, cenv, active)
    if head == "variant":
        return _recurrence_paths(frontend, node[2], component, fns, penv, cenv, active)
    if head == "depthN":
        return _path_sequence(frontend, node[2:], component, fns, penv, cenv, active)
    if head == "seamN":
        return _path_sequence(frontend, _roleclauses(node[3:])[3], component, fns, penv, cenv, active)
    if head in ("seam", "seam1"):
        return _path_sequence(frontend, _roleclauses(node[2:])[3], component, fns, penv, cenv, active)
    if head == "handle":
        return _path_sequence(frontend, node[2:], component, fns, penv, cenv, active)
    if head in ("with", "resource"):
        return None
    if _is_symbol(head) and head in component:
        paths = _path_sequence(frontend, node[1:], component, fns, penv, cenv, active)
        if paths is None:
            return None
        if any(call is not None for _, call in paths):
            return None
        return [(counts, head) for counts, _ in paths]
    if isinstance(head, list):
        return None
    paths = _path_sequence(frontend, node[1:], component, fns, penv, cenv, active)
    if paths is None:
        return None
    operation = {}
    if head in frontend.op_eff:
        operation[frontend.op_eff[head]] = 1
    elif head == "ffi":
        operation["FFI"] = 1
    elif head in fns:
        _nmerge(frontend, operation, _function_ncount(frontend, head, fns, {}, active))
    elif head in cenv:
        _nmerge(frontend, operation, cenv[head])
    elif penv and head in penv:
        return None
    for counts, _ in paths:
        _nmerge(frontend, counts, operation)
    return paths


def _combine_recurrence_paths(frontend, left, right):
    if left is None or right is None:
        return None
    combined = []
    for left_counts, left_call in left:
        for right_counts, right_call in right:
            if left_call is not None and right_call is not None:
                return None
            counts = dict(left_counts)
            _nmerge(frontend, counts, right_counts)
            combined.append((counts, left_call if left_call is not None else right_call))
            if len(combined) > 4096:
                return None
    return combined


def _static_recurrence_rank(frontend, argument, recurrence, venv):
    return loom_bounds.recurrence_rank(
        argument, recurrence, venv,
        frontend.int_min, frontend.int_max, frontend.i31,
    )


def _recurrence_ncount(frontend, entry, args, fns, active, venv=None):
    certificate = fns[entry].get("descent")
    recurrence = certificate.get("recurrence") if certificate else None
    if recurrence is None or entry in active:
        return None
    measure_index = certificate["measure_index"][entry]
    if measure_index >= len(args):
        return None
    rank = _static_recurrence_rank(frontend, args[measure_index], recurrence, venv or {})
    if rank is None or rank >= _NCAP:
        return None
    component = set(certificate["component"])
    paths = {}
    component_active = set(active) | component
    for name in component:
        paths[name] = _path_sequence(
            frontend, fns[name]["fn"][2:], component, fns,
            fns[name]["penv"], {}, component_active,
        )
        if paths[name] is None:
            return None
    edges = {}
    for edge in recurrence["edges"]:
        edges.setdefault((edge["source"], edge["target"]), []).append(edge)
    weak_targets = {name: set() for name in component}
    for edge in recurrence["edges"]:
        if edge["kind"] == "weak":
            weak_targets[edge["source"]].add(edge["target"])
    order = []
    pending = set(component)
    while pending:
        ready = sorted(name for name in pending if weak_targets[name] <= set(order))
        if not ready:
            return None
        order.extend(ready)
        pending -= set(ready)
    table = {}
    for remaining in range(rank + 1):
        for name in order:
            options = []
            for local, target in paths[name]:
                if target is None:
                    options.append(dict(local))
                    continue
                for edge in edges.get((name, target), ()):
                    if edge["kind"] == "strict" and remaining == 0:
                        continue
                    child_rank = remaining - 1 if edge["kind"] == "strict" else remaining
                    child = table[(target, child_rank)]
                    total = dict(local)
                    _nmerge(frontend, total, child)
                    options.append(total)
            if not options:
                result = {eff: _NCAP for eff in fns[name].get("eff", set()) if eff in frontend.effects}
            else:
                result = {}
                for eff in set().union(*(set(option) for option in options)):
                    result[eff] = max(option.get(eff, 0) for option in options)
            table[(name, remaining)] = result
    return table[(entry, rank)]


def _ambient_op_of(frontend, node, effs):
    """Ambient builtin ops of `effs` reachable without crossing a re-scoping boundary."""
    found = set()
    if not isinstance(node, list) or not node:
        return found
    head = node[0]
    if head in ("seam", "seam1", "seamN", "handle", "with", "resource", "fn", "use"):
        return found
    for arg in node[1:]:
        found |= _ambient_op_of(frontend, arg, effs)
    if head in frontend.builtin_eff:
        found |= (frontend.builtin_eff[head] & effs)
    return found


def instantiate(frontend, callee, args, fns, penv, errs):
    """Callee's effect row with effect variables replaced by actual function arguments' latent effects."""
    subst = {}
    for index, param in enumerate(callee["params"]):
        latent = frontend.platent(param)
        if latent is not None and index < len(args):
            for var in latent:
                if frontend.is_var(var):
                    subst[var] = subst.get(var, set()) | latent_of(frontend, args[index], fns, penv, errs)
    out = set()
    for token in callee["eff"]:
        out |= subst[token] if (frontend.is_var(token) and token in subst) else {token}
    return out


def prov_of(frontend, node, penv=None):
    """Provenance set under a node; provenance flows through lets and computation."""
    penv = penv or {}
    if _is_symbol(node):
        return set(penv.get(node, ()))
    if not isinstance(node, list) or not node:
        return set()
    if node[0] == "prov":
        out = {node[1]}
        for item in node[2:]:
            out |= prov_of(frontend, item, penv)
        return out
    if node[0] == "by":
        out = {node[2]}
        for item in node[3:]:
            out |= prov_of(frontend, item, penv)
        return out
    if node[0] == "recall":
        return {"ai"}
    if node[0] == "ffi":
        return {"ai"}
    if node[0] in ("seam", "seam1", "seamN"):
        vmap = {}
        body = []
        tail = node[3:] if node[0] == "seamN" else node[2:]
        for item in tail:
            if isinstance(item, list) and item and item[0] == "vouch" and len(item) >= 4:
                vmap.setdefault(item[3], set()).add(item[2])
            elif isinstance(item, list) and item and item[0] in ("roles", "sub", "needs"):
                pass
            else:
                body.append(item)
        out = set()
        for item in body:
            if isinstance(item, list) and len(item) > 1 and item[0] == "ffi" and item[1] in vmap:
                out |= vmap[item[1]]
            else:
                out |= prov_of(frontend, item, penv)
        return out
    if node[0] == "declassify":
        inner = set()
        for item in node[2:]:
            inner |= prov_of(frontend, item, penv)
        return (inner - {"ai"}) | {node[1]}
    if node[0] == "let":
        next_penv = dict(penv)
        next_penv[node[1][0]] = prov_of(frontend, node[1][1], penv)
        out = set()
        for body in node[2:]:
            out |= prov_of(frontend, body, next_penv)
        return out
    out = set()
    for arg in node[1:]:
        out |= prov_of(frontend, arg, penv)
    return out


def roles_of(frontend, node, penv=None):
    """Role->author pairs under a node; flows through lets and computation."""
    penv = penv or {}
    if _is_symbol(node):
        return set(penv.get(node, ()))
    if not isinstance(node, list) or not node:
        return set()
    if node[0] == "by":
        out = {(node[1], node[2])}
        for item in node[3:]:
            out |= roles_of(frontend, item, penv)
        return out
    if node[0] in ("recall", "ffi"):
        return set()
    if node[0] in ("seam", "seam1", "seamN"):
        vmap = {}
        body = []
        tail = node[3:] if node[0] == "seamN" else node[2:]
        for item in tail:
            if isinstance(item, list) and item and item[0] == "vouch" and len(item) >= 4:
                vmap.setdefault(item[3], set()).add((item[1], item[2]))
            elif isinstance(item, list) and item and item[0] in ("roles", "sub", "needs"):
                pass
            else:
                body.append(item)
        out = set()
        for item in body:
            if isinstance(item, list) and len(item) > 1 and item[0] == "ffi" and item[1] in vmap:
                out |= vmap[item[1]]
            else:
                out |= roles_of(frontend, item, penv)
        return out
    if node[0] == "let":
        next_penv = dict(penv)
        next_penv[node[1][0]] = roles_of(frontend, node[1][1], penv)
        out = set()
        for body in node[2:]:
            out |= roles_of(frontend, body, next_penv)
        return out
    out = set()
    for arg in node[1:]:
        out |= roles_of(frontend, arg, penv)
    return out


def _prov_reqs(frontend, body, params, fns=None):
    """Infer per-parameter provenance obligations from a function body."""
    req = {}

    def walk(node):
        if not isinstance(node, list) or not node:
            return
        if node[0] == "trust":
            spec = node[1] if len(node) > 1 else None
            if isinstance(spec, int):
                need, trust_body = spec, node[2:]
            elif isinstance(spec, list):
                need, trust_body = None, []
            else:
                need, trust_body = 1, node[1:]
            if need is not None and len(trust_body) == 1 and _is_symbol(trust_body[0]) and trust_body[0] in params:
                req[trust_body[0]] = max(req.get(trust_body[0], 0), need)
        elif fns and _is_symbol(node[0]) and node[0] in fns:
            callee = fns[node[0]]
            param_names = [frontend.pname(param) for param in callee["params"]]
            for param_name, callee_need in callee.get("preq", {}).items():
                callee_index = param_names.index(param_name)
                if callee_index + 1 < len(node) and _is_symbol(node[callee_index + 1]) and node[callee_index + 1] in params:
                    req[node[callee_index + 1]] = max(req.get(node[callee_index + 1], 0), callee_need)
        for child in node[1:]:
            walk(child)

    for expr in body:
        walk(expr)
    return req


def _value_uses(node, obligated):
    """Obligation-bearing function names used as values instead of direct-call heads."""
    if _is_symbol(node):
        return {node} if node in obligated else set()
    out = set()
    if not isinstance(node, list) or not node:
        return out
    for child in node[1:]:
        out |= _value_uses(child, obligated)
    if isinstance(node[0], list):
        out |= _value_uses(node[0], obligated)
    return out


def _quorum_check(frontend, roles_req, up, body, penv=None):
    """Role quorum + role lattice check over a body."""
    def fillers(role):
        seen = {role}
        stack = [role]
        while stack:
            for high in up.get(stack.pop(), ()):
                if high not in seen:
                    seen.add(high)
                    stack.append(high)
        return seen

    pairs = {(role, who) for expr in body for (role, who) in roles_of(frontend, expr, penv) if who != "ai"}
    covered = set()
    authors = set()
    for role in roles_req:
        filler_roles = fillers(role)
        for actual_role, who in pairs:
            if actual_role in filler_roles:
                covered.add(role)
                authors.add(who)
    return roles_req - covered, authors


def _roleclauses(tail):
    """Parse leading trust/grant clauses off a tail, then return the remaining body."""
    role_spec = None
    up = {}
    needs = []
    rest = list(tail)
    while rest and isinstance(rest[0], list) and len(rest[0]) > 0:
        clause = rest[0]
        head = clause[0]
        if head == "roles":
            role_spec = clause
        elif head == "sub" and len(clause) >= 3:
            up.setdefault(clause[1], set()).add(clause[2])
        elif head == "needs" and len(clause) >= 3:
            needs.append((clause[1], clause[2]))
        elif head == "vouch":
            pass
        else:
            break
        rest = rest[1:]
    return role_spec, up, needs, rest


def _with_policy_rank(up):
    """Fold the program-wide rank edges into a gate's local subsumption map."""
    if not _checker_state().policy["rank"]:
        return up
    merged = {key: set(value) for key, value in up.items()}
    for low, highs in _checker_state().policy["rank"].items():
        merged.setdefault(low, set()).update(highs)
    return merged


def _direct_effects(frontend, node):
    """Effects a node performs directly via its own ops, not through callees."""
    out = set()
    if not isinstance(node, list) or not node:
        return out
    head = node[0]
    if head in frontend.builtin_eff:
        out |= frontend.builtin_eff[head]
    elif head == "ffi":
        out.add("FFI")
    elif head == "resource" and isinstance(node[1], list):
        out |= (set(node[1][1:]) & frontend.effects)
    for arg in node[1:]:
        out |= _direct_effects(frontend, arg)
    return out


def _author_covers(pairs, role, up):
    """Does some non-AI author at `role` or higher appear in `pairs`?"""
    seen = {role}
    stack = [role]
    while stack:
        for high in up.get(stack.pop(), ()):
            if high not in seen:
                seen.add(high)
                stack.append(high)
    return any(actual_role in seen and who != "ai" for (actual_role, who) in pairs)


def infer(frontend, node, fns, errs, penv=None, venv=None):
    """Effect row a node performs transitively."""
    penv = penv or {}
    venv = venv or {}
    if not isinstance(node, list) or not node:
        return set()
    head = node[0]
    if head == "fn":
        return set()
    if head == "depthN":
        quantum = node[1] if len(node) > 1 and isinstance(node[1], int) else -1
        if quantum < 0 or quantum >= _NCAP:
            errs.append(f"call budget has invalid quantum {quantum} (expected 0..{_NCAP - 1})")
        eff = set()
        for expr in node[2:]:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if head == "ffi":
        eff = set()
        for arg in node[2:]:
            eff |= infer(frontend, arg, fns, errs, penv, venv)
        return eff | {"?"}
    if head in ("seam", "seam1"):
        decl = set(node[1]) - {"Pure"}
        role_spec, up, needs, body = _roleclauses(node[2:])
        up = _with_policy_rank(up)
        inner = set()
        for expr in body:
            inner |= infer(frontend, expr, fns, errs, penv, venv)
        inner.discard("?")
        if inner - decl:
            errs.append(f"seam under-declares: wraps {sorted(inner)} but contract says {sorted(decl)}")
        if role_spec is not None:
            missing, authors = _quorum_check(frontend, set(role_spec[1:]), up, body, _checker_state().taint_role)
            if missing:
                errs.append(f"seam grant denied: capability {sorted(decl)} requires role(s) {sorted(missing)} — not independently vouched (need a non-ai author, or a subsuming role)")
            elif len(authors) < 2:
                errs.append(f"seam grant denied: capability {sorted(decl)} vouched by a single author {sorted(authors)} — needs >= 2 independent authors")
        for eff, role in needs:
            if eff not in decl:
                errs.append(f"seam: (needs {eff} {role}) names {eff}, not granted by this seam {sorted(decl)}")
            elif _quorum_check(frontend, {role}, up, body, _checker_state().taint_role)[0]:
                errs.append(f"seam grant denied: effect {eff} requires role '{role}' — not vouched by a non-ai author (or a subsuming role)")
        for eff in sorted(decl):
            for spec in sorted(_checker_state().policy["require"].get(eff, ()), key=str):
                if isinstance(spec, int):
                    independent = {prov for expr in body for prov in prov_of(frontend, expr, _checker_state().taint_prov)} - {"ai"}
                    if len(independent) < spec:
                        errs.append(f"policy: effect {eff} requires >= {spec} independent authors (program-wide (require {eff} {spec})), got {len(independent)} {sorted(independent) or '(none)'}")
                elif _quorum_check(frontend, {spec}, up, body, _checker_state().taint_role)[0]:
                    errs.append(f"policy: effect {eff} requires role '{spec}' (program-wide (require {eff} {spec})) — not vouched by a non-ai author")
        if head == "seam1":
            uc = {}
            for expr in body:
                for effect_name, count in _ucount(frontend, expr, fns, penv).items():
                    uc[effect_name] = _uadd(uc.get(effect_name, 0), count)
            for effect_name in sorted(decl):
                if uc.get(effect_name, 0) == "M":
                    errs.append(f"linear capability {effect_name} used more than once (incl. via a call or recursion)")
        return decl
    if head == "seamN":
        quantum = node[1] if isinstance(node[1], int) else -1
        decl = infer(frontend, ["seam"] + node[2:], fns, errs, penv, venv)
        body = _roleclauses(node[3:])[3]
        counts = {}
        for expr in body:
            for effect_name, count in _ncount(frontend, expr, fns, penv, venv=venv).items():
                counts[effect_name] = _nadd(counts.get(effect_name, 0), count)
        for effect_name in sorted(decl):
            direct_count = counts.get(effect_name, 0)
            if quantum < 0 or quantum >= _NCAP or direct_count > quantum:
                errs.append(_meter_error(frontend, effect_name, quantum, direct_count, body, fns, penv))
        return decl
    if head == "repro":
        inner = set()
        for expr in node[1:]:
            inner |= infer(frontend, expr, fns, errs, penv, venv)
        laundered = set()
        for expr in node[1:]:
            laundered |= _sealed_discharges(expr, {"Rand"})
        nondeterministic = (inner | laundered) & {"Rand"}
        if nondeterministic:
            errs.append(f"repro region performs nondeterministic {sorted(nondeterministic)} -- not reproducible/falsifiable (a Rand draw is a hidden input: capture it, remove it, or reinterpret it with `with`)")
        return inner
    if head == "handle":
        handled = set(node[1])
        bad = {eff for eff in handled if eff not in frontend.effects and not frontend.is_var(eff)}
        if bad:
            errs.append(f"handle of unknown effect {sorted(bad)}")
        inner = set()
        for expr in node[2:]:
            inner |= infer(frontend, expr, fns, errs, penv, venv)
        return inner - handled
    if head == "with":
        eff_name = node[1]
        if eff_name not in frontend.effects and not frontend.is_var(eff_name):
            errs.append(f"with of unknown effect ['{eff_name}']")
        handler_latent = latent_of(frontend, node[2], fns, penv, errs)
        inner = set()
        for expr in node[3:]:
            inner |= infer(frontend, expr, fns, errs, penv, venv)
        return (inner - {eff_name}) | handler_latent
    if head == "use":
        for frame in reversed(_checker_state().renv):
            if node[1] in frame:
                return set(frame[node[1]])
        return set()
    if head == "resource":
        spec = node[1]
        rname, reffs = (spec[0], set(spec[1:])) if isinstance(spec, list) else (spec, set())
        bad = {eff for eff in reffs if eff not in frontend.effects and not frontend.is_var(eff)}
        if bad:
            errs.append(f"resource {rname} declares unknown effect {sorted(bad)}")
        if reffs:
            ambient = set()
            for expr in node[2:]:
                ambient |= _ambient_op_of(frontend, expr, reffs)
            if ambient:
                errs.append(f"resource {rname}: effect(s) {sorted(ambient)} performed ambiently inside its scope — route through (use {rname}); the resource is E's sole bearer (a declared (seam ..) re-grant is allowed)")
        _checker_state().renv.append({rname: reffs})
        try:
            eff = set()
            for expr in node[2:]:
                eff |= infer(frontend, expr, fns, errs, penv, venv)
        finally:
            _checker_state().renv.pop()
        uc = {}
        for expr in node[2:]:
            for effect_name, count in _ucount(frontend, expr, fns, penv).items():
                uc[effect_name] = _uadd(uc.get(effect_name, 0), count)
        count = uc.get(rname, 0)
        if count == 0:
            errs.append(f"linear resource {rname} never used (must be used exactly once)")
        elif count == "M":
            errs.append(f"linear resource {rname} used more than once")
        return eff
    if head == "record":
        eff = set()
        for field in node[1:]:
            if isinstance(field, list) and len(field) >= 2:
                eff |= infer(frontend, field[1], fns, errs, penv, venv)
        return eff
    if head == "get":
        return infer(frontend, node[1], fns, errs, penv, venv)
    if head == "variant":
        return infer(frontend, node[2], fns, errs, penv, venv)
    if head == "match":
        eff = infer(frontend, node[1], fns, errs, penv, venv)
        for arm in node[2:]:
            if isinstance(arm, list) and len(arm) >= 2:
                arm_venv = loom_bounds.shadow(venv, loom_bounds.pattern_names(arm[0]))
                eff |= infer(frontend, arm[1], fns, errs, penv, arm_venv)
        return eff
    if head == "if":
        cond_eff = infer(frontend, node[1], fns, errs, penv, venv)
        then_env = loom_bounds.refine(
            node[1], venv, True, frontend.int_min, frontend.int_max, frontend.i31,
        )
        else_env = loom_bounds.refine(
            node[1], venv, False, frontend.int_min, frontend.int_max, frontend.i31,
        )
        then_eff = infer(frontend, node[2], fns, errs, penv, then_env) if then_env is not None else set()
        else_eff = infer(frontend, node[3], fns, errs, penv, else_env) if else_env is not None else set()
        return cond_eff | then_eff | else_eff
    if head == "let":
        name, value = node[1][0], node[1][1]
        eff = infer(frontend, value, fns, errs, penv, venv)
        bound_penv = {**penv, name: latent_of(frontend, value, fns, penv, errs)} if frontend.is_fn_expr(value, fns, penv) else penv
        bound_venv = loom_bounds.bind(
            venv,
            name,
            loom_bounds.value(value, venv, frontend.int_min, frontend.int_max, frontend.i31),
        )
        saved_prov = _checker_state().taint_prov.get(name, frontend.miss)
        saved_role = _checker_state().taint_role.get(name, frontend.miss)
        _checker_state().taint_prov[name] = prov_of(frontend, value, _checker_state().taint_prov)
        _checker_state().taint_role[name] = roles_of(frontend, value, _checker_state().taint_role)
        try:
            for expr in node[2:]:
                eff |= infer(frontend, expr, fns, errs, bound_penv, bound_venv)
        finally:
            if saved_prov is not frontend.miss:
                _checker_state().taint_prov[name] = saved_prov
            else:
                _checker_state().taint_prov.pop(name, None)
            if saved_role is not frontend.miss:
                _checker_state().taint_role[name] = saved_role
            else:
                _checker_state().taint_role.pop(name, None)
        return eff
    if head == "prov":
        eff = set()
        for expr in node[2:]:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if head == "by":
        eff = set()
        for expr in node[3:]:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if head == "recall":
        eff = set()
        for expr in node[1:]:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if head == "declassify":
        if node[1] == "ai":
            errs.append("declassify: 'ai' cannot declassify provenance — only a non-ai role may take responsibility")
        eff = set()
        for expr in node[2:]:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if isinstance(head, list):
        eff = latent_of(frontend, head, fns, penv, errs)
        for arg in node[1:]:
            eff |= infer(frontend, arg, fns, errs, penv, venv)
        return eff
    if head == "trust":
        spec = node[1] if len(node) > 1 else None
        is_roles = isinstance(spec, list) and len(spec) > 0 and spec[0] == "roles"
        if is_roles:
            _, up, _, body = _roleclauses(node[1:])
            roles_req = set(spec[1:])
            missing, authors = _quorum_check(frontend, roles_req, _with_policy_rank(up), body, _checker_state().taint_role)
            if missing:
                errs.append(f"trust gate (roles): role(s) {sorted(missing)} not independently covered (need a non-ai author, or a role that subsumes it) — self-certified")
            elif len(authors) < 2:
                errs.append(f"trust gate (roles): required roles satisfied by a single author {sorted(authors)} — circular trust (one author owns code+spec+proof)")
        else:
            has_count = isinstance(spec, int)
            need = spec if has_count else 1
            body = node[2:] if has_count else node[1:]
            independent = {prov for expr in body for prov in prov_of(frontend, expr, _checker_state().taint_prov)} - {"ai"}
            first = body[0] if len(body) == 1 else None
            deferred = _is_symbol(first) and first in _checker_state().policy.get("params", set()) and first not in _checker_state().taint_prov
            if len(independent) < need and not deferred:
                errs.append(f"trust gate: need >= {need} independent anchor(s), got {len(independent)} {sorted(independent) or '(none)'} — value too self-referential / under-corroborated")
        eff = set()
        for expr in body:
            eff |= infer(frontend, expr, fns, errs, penv, venv)
        return eff
    if head == "asm":
        error = asm_validation_error(node)
        if error:
            errs.append(error)
            return set()
        spec = asm_metadata(node)
        eff = set()
        for arg in node[3:]:
            eff |= infer(frontend, arg, fns, errs, penv, venv)
        eff |= set(spec["effects"])
        return eff
    eff = set()
    for arg in node[1:]:
        eff |= infer(frontend, arg, fns, errs, penv, venv)
    if head in frontend.builtin_eff:
        eff |= frontend.builtin_eff[head]
    elif head in penv:
        eff |= penv[head]
    elif head in fns:
        eff |= instantiate(frontend, fns[head], node[1:], fns, penv, errs)
        param_names = [frontend.pname(param) for param in fns[head]["params"]]
        for param_name, need in fns[head].get("preq", {}).items():
            index = param_names.index(param_name)
            arg = node[index + 1] if index + 1 < len(node) else None
            if _is_symbol(arg) and arg in _checker_state().policy.get("params", set()) and arg not in _checker_state().taint_prov:
                continue
            anchors = (prov_of(frontend, arg, _checker_state().taint_prov) - {"ai"}) if arg is not None else set()
            if len(anchors) < need:
                errs.append(f"call to {head}: arg for trusted param '{param_name}' carries {len(anchors)} independent anchor(s) {sorted(anchors) or '(none)'}, needs >= {need} — provenance does not flow through (or is too self-referential)")
    elif head not in frontend.pure_ops:
        errs.append(f"unresolved call: '{head}' is not a known function or builtin")
    return eff


def _sealed_discharges(node, sealed):
    out = set()
    if not isinstance(node, list) or not node:
        return out
    if node[0] == "handle":
        out |= (set(node[1]) & sealed)
    for arg in node[1:]:
        out |= _sealed_discharges(arg, sealed)
    return out


def _has_head(node, head):
    if not isinstance(node, list) or not node:
        return False
    if node[0] == head:
        return True
    if isinstance(node[0], list) and _has_head(node[0], head):
        return True
    return any(_has_head(child, head) for child in node[1:])


def _meter_error(frontend, effect_name, quantum, direct_count, body, fns, penv):
    if quantum < 0 or quantum >= _NCAP:
        return f"metered capability {effect_name} has invalid quantum {quantum} (expected 0..{_NCAP - 1})"
    if direct_count >= _NCAP:
        return (
            f"metered capability {effect_name} used more than its quantum {quantum} "
            "(meter summary is unbounded via recursion or unresolved higher-order dispatch; fail-closed)"
        )
    return (
        f"metered capability {effect_name} used more than its quantum {quantum} "
        f"(counted {direct_count} use(s) along the maximal finite path)"
    )


def _check_program(frontend, program):
    """Return (fns, errors). Empty errors means the program is accepted."""
    state = _checker_state()
    state.policy["rank"] = {}
    state.policy["require"] = {}
    state.policy["forbid"] = set()
    state.policy["author"] = {}
    state.policy["confine"] = []
    state.policy["seal"] = set()
    state.taint_prov.clear()
    state.taint_role.clear()
    for top in program:
        if isinstance(top, list) and len(top) >= 3 and top[0] == "rank":
            state.policy["rank"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "require":
            state.policy["require"].setdefault(top[1], set()).add(top[2])
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "forbid":
            state.policy["forbid"].add(top[1])
        elif isinstance(top, list) and len(top) >= 4 and top[0] == "author":
            state.policy["author"].setdefault(top[1], set()).add((top[2], top[3]))
        elif isinstance(top, list) and len(top) >= 3 and top[0] == "confine":
            state.policy["confine"].append((top[1], top[2]))
        elif isinstance(top, list) and len(top) >= 2 and top[0] == "seal":
            state.policy["seal"].add(top[1])
    proof_requests = []
    proof_errors = []
    for top in program:
        if isinstance(top, list) and top and top[0] == "prove":
            if (
                len(top) != 2 or not isinstance(top[1], list) or len(top[1]) < 2
                or top[1][0] != "descent" or not all(_is_symbol(name) for name in top[1][1:])
            ):
                proof_errors.append("malformed proof directive (expected (prove (descent function...)))")
            else:
                proof_requests.extend(top[1][1:])
    fns = {}
    for top in program:
        if isinstance(top, list) and top and top[0] == "defx":
            fn = top[3]
            penv = {frontend.pname(param): frontend.platent(param) for param in fn[1] if frontend.platent(param) is not None}
            lin = {index for index, param in enumerate(fn[1]) if frontend.plin(param)}
            raw = top[2]
            decl = {(eff[:-1] if isinstance(eff, str) and eff.endswith("!") else eff) for eff in raw}
            req = {eff[:-1] for eff in raw if isinstance(eff, str) and eff.endswith("!") and eff[:-1] in frontend.effects and eff[:-1] != "Pure"}
            fns[top[1]] = {"decl": decl, "req": req, "fn": fn, "params": fn[1], "penv": penv, "lin": lin, "eff": set(), "uc": {}}
    for _ in range(len(fns) + 2):
        for info in fns.values():
            body = info["fn"][2:]
            tmp = []
            info["eff"] = set().union(*[infer(frontend, expr, fns, tmp, info["penv"]) for expr in body]) if body else set()
            uc = {}
            for expr in body:
                for effect_name, count in _ucount(frontend, expr, fns, info["penv"]).items():
                    uc[effect_name] = _uadd(uc.get(effect_name, 0), count)
            info["uc"] = uc
    for info in fns.values():
        info["preq"] = {}
    for _ in range(len(fns) + 2):
        for _, info in fns.items():
            info["preq"] = _prov_reqs(frontend, info["fn"][2:], {frontend.pname(param) for param in info["params"]}, fns)
    obligated = {name for name, info in fns.items() if info["preq"]}
    errors = frontend.int_literal_errors(program) + proof_errors
    for target in proof_requests:
        if target not in fns:
            errors.append(f"descent proof names unknown function '{target}'")
            continue
        ok, message, certificate = descent_certificate(fns, target)
        if not ok:
            errors.append(message)
            continue
        for name in certificate["component"]:
            fns[name]["descent"] = certificate
    for name, info in fns.items():
        state.policy["params"] = {frontend.pname(param) for param in info["params"]}
        for expr in info["fn"][2:]:
            infer(frontend, expr, fns, errors, info["penv"])
        for expr in info["fn"][2:]:
            for used in _value_uses(expr, obligated):
                errors.append(f"{name}: '{used}' carries a provenance obligation {sorted(fns[used]['preq'])} and is used as a value — call it directly so it is discharged at the call site")
        eff = info["eff"]
        if "?" in eff:
            errors.append(f"{name}: foreign 'ffi' call has no capability seam (wrap it: (seam (..) ...))")
            eff = eff - {"?"}
        if eff - info["decl"]:
            errors.append(f"{name}: performs undeclared {sorted(eff - info['decl'])} (declared {sorted(info['decl'])})")
        banned = eff & state.policy["forbid"]
        if banned:
            errors.append(f"{name}: performs {sorted(banned)} — forbidden program-wide (forbid {sorted(banned)[0]}); discharge it locally or remove it")
        missing = info["req"] - eff
        if missing:
            errors.append(f"{name}: contract requires {sorted(missing)} but body never performs it (stub does not satisfy intent)")
        unknown = {eff for eff in info["decl"] if eff not in frontend.effects and not frontend.is_var(eff)}
        if unknown:
            errors.append(f"{name}: unknown effect {sorted(unknown)}")
        for param in info["params"]:
            rname = frontend.plin(param)
            if rname:
                count = info["uc"].get(rname, 0)
                if count == 0:
                    errors.append(f"{name}: linear param {rname} never used (must be used exactly once)")
                elif count == "M":
                    errors.append(f"{name}: linear param {rname} used more than once")
    if state.policy["confine"]:
        up = _with_policy_rank({})
        for eff, role in state.policy["confine"]:
            for name, info in fns.items():
                if eff in info["eff"] and eff in _direct_effects(frontend, info["fn"]):
                    if not _author_covers(state.policy["author"].get(name, {("ai", "ai")}), role, up):
                        errors.append(f"{name}: wields confined effect {eff} but is not authored by a cleared '{role}' (program-wide (confine {eff} {role})) — uncleared component in the capability graph")
    if state.policy["seal"]:
        for name, info in fns.items():
            bad = _sealed_discharges(info["fn"], state.policy["seal"])
            if bad:
                errors.append(f"{name}: discharges sealed effect(s) {sorted(bad)} via handle (program-wide (seal {sorted(bad)[0]})) -- a sealed effect may not be dropped to nothing; keep it in the accountable row or genuinely reinterpret it with `with`")
    if "declassify" in state.policy["forbid"]:
        for name, info in fns.items():
            if any(_has_head(expr, "declassify") for expr in info["fn"][2:]):
                errors.append(f"{name}: uses (declassify ..) but it is forbidden program-wide (forbid declassify) -- no ai-derived value may be laundered into trust; remove the declassify or lift the policy")
    return fns, errors


def check(program, frontend):
    """Check one program with policy, resource, and taint state isolated from every other invocation."""
    token = _CHECKER_STATE.set(_CheckerState())
    try:
        return _check_program(frontend, program)
    finally:
        _CHECKER_STATE.reset(token)
