#!/usr/bin/env python3
"""Static named-call graph and recursive-descent proof utilities."""

from itertools import product


I31_MIN = -(1 << 30)


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


def _call_graph(fns):
    names = set(fns)
    return {
        name: set().union(*(_named_calls(expr, names) for expr in info["fn"][2:]))
        if info["fn"][2:] else set()
        for name, info in fns.items()
    }


def _components(graph):
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
    return components


def recursive_components(fns):
    """Return recursive strongly connected components in the named-call graph."""
    graph = _call_graph(fns)
    return [
        component for component in _components(graph)
        if len(component) > 1 or any(name in graph[name] for name in component)
    ]


def recursive_edges(fns):
    """Return direct call edges whose endpoints share a recursive SCC."""
    graph = _call_graph(fns)
    components = recursive_components(fns)

    edges = set()
    for component in components:
        edges |= {(source, target) for source in component for target in graph[source] if target in component}
    return edges


def _copy_facts(facts):
    return {
        "nonempty": set(facts["nonempty"]),
        "lower": dict(facts["lower"]),
        "shadowed": set(facts["shadowed"]),
    }


def _shadow(facts, names):
    out = _copy_facts(facts)
    for name in names:
        out["nonempty"].discard(name)
        out["lower"].pop(name, None)
        out["shadowed"].add(name)
    return out


def _pattern_names(pattern):
    if not isinstance(pattern, list):
        return set()
    return {item for item in pattern[1:] if _is_symbol(item)}


def _branch_facts(condition, truth, facts):
    out = _copy_facts(facts)
    if not isinstance(condition, list) or len(condition) != 2 and len(condition) != 3:
        return out
    head = condition[0]
    if head == "empty" and len(condition) == 2 and _is_symbol(condition[1]) and not truth:
        out["nonempty"].add(condition[1])
        return out
    if len(condition) != 3:
        return out
    left, right = condition[1], condition[2]
    lower = None
    name = None
    if head == "<" and not truth and _is_symbol(left) and isinstance(right, int):
        name, lower = left, right
    elif head == "<" and truth and isinstance(left, int) and _is_symbol(right):
        name, lower = right, left + 1
    elif head == ">" and truth and _is_symbol(left) and isinstance(right, int):
        name, lower = left, right + 1
    elif head == ">" and not truth and isinstance(left, int) and _is_symbol(right):
        name, lower = right, left
    if name is not None:
        out["lower"][name] = max(out["lower"].get(name, I31_MIN), lower)
    return out


def _call_sites(node, names, facts=None):
    """Collect direct named calls with path facts; deferred lambdas stay opaque."""
    facts = facts or {"nonempty": set(), "lower": {}, "shadowed": set()}
    out = []
    if not isinstance(node, list) or not node:
        return out
    head = node[0]
    if head == "fn":
        return out
    if head == "record":
        for field in node[1:]:
            if isinstance(field, list) and len(field) >= 2:
                out.extend(_call_sites(field[1], names, facts))
        return out
    if head == "get":
        return _call_sites(node[1], names, facts)
    if head == "variant":
        return _call_sites(node[2], names, facts)
    if head == "match":
        out.extend(_call_sites(node[1], names, facts))
        for arm in node[2:]:
            if isinstance(arm, list) and len(arm) >= 2:
                out.extend(_call_sites(arm[1], names, _shadow(facts, _pattern_names(arm[0]))))
        return out
    if head == "let":
        out.extend(_call_sites(node[1][1], names, facts))
        body_facts = _shadow(facts, {node[1][0]} if _is_symbol(node[1][0]) else set())
        for child in node[2:]:
            out.extend(_call_sites(child, names, body_facts))
        return out
    if head == "resource" and len(node) >= 2:
        spec = node[1]
        bound = spec[0] if isinstance(spec, list) and spec else spec
        body_facts = _shadow(facts, {bound} if _is_symbol(bound) else set())
        for child in node[2:]:
            out.extend(_call_sites(child, names, body_facts))
        return out
    if head == "if" and len(node) >= 4:
        out.extend(_call_sites(node[1], names, facts))
        out.extend(_call_sites(node[2], names, _branch_facts(node[1], True, facts)))
        out.extend(_call_sites(node[3], names, _branch_facts(node[1], False, facts)))
        return out
    if _is_symbol(head) and head in names:
        out.append((head, node[1:], _copy_facts(facts)))
    if isinstance(head, list):
        out.extend(_call_sites(head, names, facts))
    for child in node[1:]:
        out.extend(_call_sites(child, names, facts))
    return out


def _contains_component_symbol(node, component):
    if _is_symbol(node):
        return node in component
    if not isinstance(node, list):
        return False
    return any(_contains_component_symbol(child, component) for child in node)


def _contains_component_value(node, component, direct_head=True):
    """Detect an SCC function escaping direct named-call position."""
    if _is_symbol(node):
        return node in component
    if not isinstance(node, list) or not node:
        return False
    head = node[0]
    if head == "fn":
        return any(_contains_component_symbol(child, component) for child in node[2:])
    if head == "record":
        return any(
            _contains_component_value(field[1], component)
            for field in node[1:] if isinstance(field, list) and len(field) >= 2
        )
    if head == "get":
        return _contains_component_value(node[1], component)
    if head == "variant":
        return _contains_component_value(node[2], component)
    if head == "match":
        return _contains_component_value(node[1], component) or any(
            _contains_component_value(arm[1], component)
            for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2
        )
    if head == "let":
        return _contains_component_value(node[1][1], component) or any(
            _contains_component_value(child, component) for child in node[2:]
        )
    if _is_symbol(head) and head in component:
        if not direct_head:
            return True
        return any(_contains_component_value(child, component) for child in node[1:])
    if isinstance(head, list) and _contains_component_value(head, component):
        return True
    return any(_contains_component_value(child, component) for child in node[1:])


def _invokes_function_param(node, function_params):
    if not isinstance(node, list) or not node:
        return False
    if node[0] == "fn":
        return False
    if _is_symbol(node[0]) and node[0] in function_params:
        return True
    return any(_invokes_function_param(child, function_params) for child in node if isinstance(child, list))


def _tail_depth(node, name):
    depth = 0
    while isinstance(node, list) and len(node) == 2 and node[0] == "tail":
        depth += 1
        node = node[1]
    return depth if depth and node == name else 0


def _relation(argument, caller_param, facts):
    if caller_param in facts["shadowed"]:
        return None
    if argument == caller_param:
        return {"kind": "weak"}
    tail_depth = _tail_depth(argument, caller_param)
    if tail_depth:
        return {
            "kind": "strict" if caller_param in facts["nonempty"] else "weak",
            "domain": "list",
            "amount": tail_depth,
        }
    if (
        isinstance(argument, list) and len(argument) == 3 and argument[0] == "-"
        and argument[1] == caller_param and isinstance(argument[2], int) and argument[2] > 0
    ):
        lower = facts["lower"].get(caller_param)
        if lower is not None and lower - argument[2] >= I31_MIN:
            return {
                "kind": "strict",
                "domain": "i31",
                "amount": argument[2],
                "lower": lower,
            }
    return None


def _path_call_count(node, names):
    """Maximum direct named calls along one evaluation path, capped at two."""
    if not isinstance(node, list) or not node:
        return 0
    head = node[0]
    if head == "fn":
        return 0
    if head == "record":
        return min(2, sum(
            _path_call_count(field[1], names)
            for field in node[1:] if isinstance(field, list) and len(field) >= 2
        ))
    if head == "get":
        return _path_call_count(node[1], names)
    if head == "variant":
        return _path_call_count(node[2], names)
    if head == "match":
        prefix = _path_call_count(node[1], names)
        arms = [
            _path_call_count(arm[1], names)
            for arm in node[2:] if isinstance(arm, list) and len(arm) >= 2
        ]
        return min(2, prefix + (max(arms) if arms else 0))
    if head == "if" and len(node) >= 4:
        return min(2, _path_call_count(node[1], names) + max(
            _path_call_count(node[2], names),
            _path_call_count(node[3], names),
        ))
    if head == "let":
        return min(2, _path_call_count(node[1][1], names) + sum(
            _path_call_count(child, names) for child in node[2:]
        ))
    if head == "resource":
        return min(2, sum(_path_call_count(child, names) for child in node[2:]))
    count = 1 if _is_symbol(head) and head in names else 0
    if isinstance(head, list):
        count += _path_call_count(head, names)
    count += sum(_path_call_count(child, names) for child in node[1:])
    return min(2, count)


def _acyclic(nodes, edges):
    graph = {name: set() for name in nodes}
    for source, target in edges:
        graph[source].add(target)
    visiting = set()
    visited = set()

    def visit(name):
        if name in visiting:
            return False
        if name in visited:
            return True
        visiting.add(name)
        if not all(visit(target) for target in graph[name]):
            return False
        visiting.remove(name)
        visited.add(name)
        return True

    return all(visit(name) for name in nodes)


def descent_certificate(fns, target):
    """Prove every cycle in target's named recursive SCC has structural descent."""
    component = next((c for c in recursive_components(fns) if target in c), None)
    if component is None:
        return False, f"{target}: descent proof requires a recursive named-call component", None
    for name in component:
        body = fns[name]["fn"][2:]
        if any(_contains_component_value(expr, component) for expr in body):
            return False, f"{target}: recursive component function escapes direct call position", None
        function_params = {
            param[0] for param in fns[name]["params"]
            if isinstance(param, list) and param and param[0] != "lin"
        }
        if any(_invokes_function_param(expr, function_params) for expr in body):
            return False, f"{target}: recursive component contains unresolved higher-order dispatch", None

    candidates = {}
    for name in component:
        params = fns[name]["params"]
        candidates[name] = [
            (index, param) for index, param in enumerate(params)
            if _is_symbol(param) and index == max(i for i, item in enumerate(params) if item == param)
        ]
        if not candidates[name]:
            return False, f"{target}: recursive function {name} has no value parameter to measure", None

    sites = {}
    for name in component:
        found = []
        for expr in fns[name]["fn"][2:]:
            found.extend(_call_sites(expr, component))
        sites[name] = found

    names = sorted(component)
    choices = 1
    for name in names:
        choices *= len(candidates[name])
    if choices > 4096:
        return False, f"{target}: descent measure search exceeds 4096 assignments", None

    for selected in product(*(candidates[name] for name in names)):
        measure = dict(zip(names, selected))
        weak_edges = []
        relations = []
        valid = True
        for source in names:
            _, caller_param = measure[source]
            for callee, args, facts in sites[source]:
                target_index, _ = measure[callee]
                relation = _relation(args[target_index], caller_param, facts) if target_index < len(args) else None
                if relation is None:
                    valid = False
                    break
                relations.append({"source": str(source), "target": str(callee), **relation})
                if relation["kind"] == "weak":
                    weak_edges.append((source, callee))
            if not valid:
                break
        if valid and _acyclic(component, weak_edges):
            certificate = {name: str(measure[name][1]) for name in names}
            result = {
                "component": names,
                "measure": certificate,
                "measure_index": {name: measure[name][0] for name in names},
            }
            domains = {relation.get("domain") for relation in relations if relation.get("domain")}
            single_spine = all(
                sum(_path_call_count(expr, component) for expr in fns[name]["fn"][2:]) <= 1
                for name in names
            )
            if len(domains) == 1 and single_spine:
                domain = next(iter(domains))
                recurrence = {
                    "kind": "single-spine",
                    "domain": domain,
                    "edges": relations,
                }
                if domain == "i31":
                    recurrence["floor"] = min(
                        relation["lower"] for relation in relations
                        if relation["kind"] == "strict" and relation.get("domain") == "i31"
                    )
                result["recurrence"] = recurrence
            return True, "", result
    return False, f"{target}: no well-founded parameter descent covers every recursive cycle", None
