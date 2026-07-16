#!/usr/bin/env python3
"""Static named-call graph utilities shared by LOOM execution backends."""


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


def _named_calls(node, names):
    """Collect direct named calls, excluding deferred lambda bodies."""
    out = set()
    if not isinstance(node, list) or not node:
        return out
    head = node[0]
    if head == "fn":
        return out
    if head == "record":
        for field in node[1:]:
            if isinstance(field, list) and len(field) >= 2:
                out |= _named_calls(field[1], names)
        return out
    if head == "get":
        return _named_calls(node[1], names)
    if head == "variant":
        return _named_calls(node[2], names)
    if head == "match":
        calls = _named_calls(node[1], names)
        for arm in node[2:]:
            if isinstance(arm, list) and len(arm) >= 2:
                calls |= _named_calls(arm[1], names)
        return calls
    if head == "let":
        calls = _named_calls(node[1][1], names)
        for child in node[2:]:
            calls |= _named_calls(child, names)
        return calls
    if _is_symbol(head) and head in names:
        out.add(head)
    if isinstance(head, list):
        out |= _named_calls(head, names)
    for child in node[1:]:
        out |= _named_calls(child, names)
    return out


def recursive_edges(fns):
    """Return direct call edges whose endpoints share a recursive SCC."""
    names = set(fns)
    graph = {
        name: set().union(*(_named_calls(expr, names) for expr in info["fn"][2:]))
        if info["fn"][2:] else set()
        for name, info in fns.items()
    }
    index = 0
    indices = {}
    low = {}
    stack = []
    on_stack = set()
    components = []

    def visit(name):
        nonlocal index
        indices[name] = low[name] = index
        index += 1
        stack.append(name)
        on_stack.add(name)
        for target in graph[name]:
            if target not in indices:
                visit(target)
                low[name] = min(low[name], low[target])
            elif target in on_stack:
                low[name] = min(low[name], indices[target])
        if low[name] == indices[name]:
            component = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.add(member)
                if member == name:
                    break
            components.append(component)

    for name in graph:
        if name not in indices:
            visit(name)

    edges = set()
    for component in components:
        recursive = len(component) > 1 or any(name in graph[name] for name in component)
        if recursive:
            edges |= {(source, target) for source in component for target in graph[source] if target in component}
    return edges
