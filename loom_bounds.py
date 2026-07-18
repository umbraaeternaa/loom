#!/usr/bin/env python3
"""Fail-closed abstract value bounds used by the LOOM static checker."""


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


def bind(env, name, bound):
    """Lexically bind a value, removing any shadowed fact when it is unknown."""
    out = dict(env)
    out.pop(name, None)
    if bound is not None:
        out[name] = bound
    return out


def shadow(env, names):
    out = dict(env)
    for name in names:
        out.pop(name, None)
    return out


def pattern_names(pattern):
    if _is_symbol(pattern):
        return {pattern}
    if not isinstance(pattern, list):
        return set()
    out = set()
    for child in pattern[1:]:
        out |= pattern_names(child)
    return out


def _join(left, right):
    if left is None or right is None or left[0] != right[0]:
        return None
    lo = None if left[1] is None or right[1] is None else min(left[1], right[1])
    hi = None if left[2] is None or right[2] is None else max(left[2], right[2])
    return (left[0], lo, hi)


def _i31_math(head, args, int_min, int_max, wrap):
    if not all(bound is not None and bound[0] == "i31" for bound in args):
        return None
    exact = all(bound[1] == bound[2] for bound in args)
    if head == "+":
        if exact:
            result = wrap(sum(bound[1] for bound in args))
            return ("i31", result, result)
        lo = sum(bound[1] for bound in args)
        hi = sum(bound[2] for bound in args)
    elif head == "-" and len(args) == 2:
        if exact:
            result = wrap(args[0][1] - args[1][1])
            return ("i31", result, result)
        lo = args[0][1] - args[1][2]
        hi = args[0][2] - args[1][1]
    elif head == "*":
        current = ("i31", 1, 1)
        for bound in args:
            if current[1] == current[2] and bound[1] == bound[2]:
                result = wrap(current[1] * bound[1])
                current = ("i31", result, result)
                continue
            products = (
                current[1] * bound[1], current[1] * bound[2],
                current[2] * bound[1], current[2] * bound[2],
            )
            lo, hi = min(products), max(products)
            if lo < int_min or hi > int_max:
                return None
            current = ("i31", lo, hi)
        return current
    else:
        return None
    if lo < int_min or hi > int_max:
        return None
    return ("i31", lo, hi)


def value(node, env, int_min, int_max, wrap):
    """Return `(domain, lower, upper)` or None when no sound bound is known."""
    if isinstance(node, int):
        return ("i31", node, node) if int_min <= node <= int_max else None
    if _is_symbol(node):
        return env.get(node)
    if not isinstance(node, list) or not node:
        return None
    head = node[0]
    if head in ("+", "-", "*"):
        return _i31_math(
            head,
            [value(arg, env, int_min, int_max, wrap) for arg in node[1:]],
            int_min, int_max, wrap,
        )
    if head in ("=", "<", ">") and len(node) == 3:
        left = value(node[1], env, int_min, int_max, wrap)
        right = value(node[2], env, int_min, int_max, wrap)
        if left is None or right is None or left[0] != right[0]:
            return ("i31", 0, 1)
        if head == "=":
            if left[2] < right[1] or right[2] < left[1]:
                return ("i31", 0, 0)
            if left[1] == left[2] == right[1] == right[2]:
                return ("i31", 1, 1)
        elif head == "<":
            if left[2] < right[1]:
                return ("i31", 1, 1)
            if left[1] >= right[2]:
                return ("i31", 0, 0)
        else:
            if left[1] > right[2]:
                return ("i31", 1, 1)
            if left[2] <= right[1]:
                return ("i31", 0, 0)
        return ("i31", 0, 1)
    if head == "list":
        length = len(node) - 1
        return ("list", length, length)
    if head == "cons" and len(node) == 3:
        tail = value(node[2], env, int_min, int_max, wrap)
        if tail is None or tail[0] != "list" or tail[2] is None:
            return None
        return ("list", tail[1] + 1, tail[2] + 1)
    if head == "tail" and len(node) == 2:
        source = value(node[1], env, int_min, int_max, wrap)
        if source is None or source[0] != "list" or source[2] is None:
            return None
        return ("list", max(0, source[1] - 1), max(0, source[2] - 1))
    if head == "empty" and len(node) == 2:
        source = value(node[1], env, int_min, int_max, wrap)
        if source is None or source[0] != "list":
            return ("i31", 0, 1)
        if source[2] == 0:
            return ("i31", 1, 1)
        if source[1] is not None and source[1] > 0:
            return ("i31", 0, 0)
        return ("i31", 0, 1)
    if head == "if" and len(node) >= 4:
        condition = value(node[1], env, int_min, int_max, wrap)
        if condition is not None and condition[0] == "i31" and condition[1] == condition[2]:
            chosen = node[2] if condition[1] != 0 else node[3]
            return value(chosen, env, int_min, int_max, wrap)
        then_env = refine(node[1], env, True, int_min, int_max, wrap)
        else_env = refine(node[1], env, False, int_min, int_max, wrap)
        then_bound = value(node[2], then_env, int_min, int_max, wrap) if then_env is not None else None
        else_bound = value(node[3], else_env, int_min, int_max, wrap) if else_env is not None else None
        if then_env is None:
            return else_bound
        if else_env is None:
            return then_bound
        return _join(then_bound, else_bound)
    if head == "let" and len(node) >= 3 and isinstance(node[1], list) and len(node[1]) >= 2:
        name, source = node[1][0], node[1][1]
        local = bind(env, name, value(source, env, int_min, int_max, wrap))
        return value(node[-1], local, int_min, int_max, wrap)
    return None


def _restrict(env, name, domain, lo, hi):
    current = env.get(name)
    if current is not None and current[0] != domain:
        return None
    old_lo = current[1] if current is not None else None
    old_hi = current[2] if current is not None else None
    new_lo = lo if old_lo is None else (old_lo if lo is None else max(old_lo, lo))
    new_hi = hi if old_hi is None else (old_hi if hi is None else min(old_hi, hi))
    if new_lo is not None and new_hi is not None and new_lo > new_hi:
        return None
    out = dict(env)
    out[name] = (domain, new_lo, new_hi)
    return out


def refine(condition, env, truth, int_min, int_max, wrap):
    """Refine one branch environment; None denotes a proven unreachable branch."""
    known = value(condition, env, int_min, int_max, wrap)
    if known is not None and known[0] == "i31" and known[1] == known[2]:
        if (known[1] != 0) != truth:
            return None
    if not isinstance(condition, list) or len(condition) != 3:
        return dict(env)
    head, left, right = condition
    if isinstance(left, int) and _is_symbol(right):
        left, right = right, left
        head = {"<": ">", ">": "<"}.get(head, head)
    if not _is_symbol(left) or not isinstance(right, int):
        return dict(env)
    if head == "<":
        lo, hi = (int_min, right - 1) if truth else (right, int_max)
    elif head == ">":
        lo, hi = (right + 1, int_max) if truth else (int_min, right)
    elif head == "=" and truth:
        lo = hi = right
    else:
        return dict(env)
    lo, hi = max(int_min, lo), min(int_max, hi)
    if lo > hi:
        return None
    return _restrict(env, left, "i31", lo, hi)


def recurrence_rank(argument, recurrence, env, int_min, int_max, wrap):
    bound = value(argument, env, int_min, int_max, wrap)
    if bound is None or bound[2] is None or bound[0] != recurrence["domain"]:
        return None
    if recurrence["domain"] == "i31":
        return max(0, bound[2] - recurrence["floor"] + 1)
    if recurrence["domain"] == "list":
        return bound[2]
    return None
