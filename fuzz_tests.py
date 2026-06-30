#!/usr/bin/env python3
"""Deterministic property and differential fuzzing for the LOOM kernel."""
import argparse
import random
import shutil
import string
import sys

from loom import (
    INT_MAX,
    INT_MIN,
    LoomError,
    check,
    compile_js,
    compile_wasm,
    parse,
    run_call,
    run_compiled,
    run_js,
    run_wasm,
)


INT_MOD = 1 << 31


def i31(n):
    return ((n - INT_MIN) % INT_MOD) + INT_MIN


def render(node):
    if isinstance(node, list):
        return "(" + " ".join(render(x) for x in node) + ")"
    return str(node)


def evaluate(node, env=None):
    env = env or {}
    if isinstance(node, int):
        return node
    if isinstance(node, str):
        return env[node]
    h = node[0]
    if h == "+": return i31(sum(evaluate(x, env) for x in node[1:]))
    if h == "-": return i31(evaluate(node[1], env) - evaluate(node[2], env))
    if h == "*":
        out = 1
        for x in node[1:]: out = i31(out * evaluate(x, env))
        return out
    if h == "=": return int(evaluate(node[1], env) == evaluate(node[2], env))
    if h == "<": return int(evaluate(node[1], env) < evaluate(node[2], env))
    if h == ">": return int(evaluate(node[1], env) > evaluate(node[2], env))
    if h == "if": return evaluate(node[2] if evaluate(node[1], env) != 0 else node[3], env)
    if h == "let":
        local = dict(env); local[node[1][0]] = evaluate(node[1][1], env)
        return evaluate(node[-1], local)
    raise AssertionError("oracle does not support " + repr(h))


def literal(rng):
    edge = [INT_MIN, INT_MIN + 1, -2, -1, 0, 1, 2, INT_MAX - 1, INT_MAX]
    return rng.choice(edge) if rng.random() < 0.45 else rng.randint(-100000, 100000)


def expression(rng, depth, names, serial):
    if depth <= 0 or rng.random() < 0.22:
        if names and rng.random() < 0.25: return rng.choice(names)
        return literal(rng)
    choice = rng.randrange(7)
    if choice == 0:
        return ["+"] + [expression(rng, depth - 1, names, serial) for _ in range(rng.randint(2, 4))]
    if choice == 1:
        return ["-", expression(rng, depth - 1, names, serial), expression(rng, depth - 1, names, serial)]
    if choice == 2:
        return ["*", expression(rng, depth - 1, names, serial), expression(rng, depth - 1, names, serial)]
    if choice in (3, 4, 5):
        return [["=", "<", ">"][choice - 3], expression(rng, depth - 1, names, serial), expression(rng, depth - 1, names, serial)]
    if rng.random() < 0.5:
        cond = [rng.choice(["=", "<", ">"]), expression(rng, depth - 1, names, serial), expression(rng, depth - 1, names, serial)]
        return ["if", cond, expression(rng, depth - 1, names, serial), expression(rng, depth - 1, names, serial)]
    name = "x" + str(serial[0]); serial[0] += 1
    value = expression(rng, depth - 1, names, serial)
    return ["let", [name, value], expression(rng, depth - 1, names + [name], serial)]


def parser_properties(rng, cases):
    malformed = ["(", ")", "(a", "a)", "((1)"]
    for source in malformed:
        try:
            parse(source)
        except LoomError:
            pass
        else:
            raise AssertionError("malformed source accepted: " + repr(source))

    alphabet = "()" + string.ascii_letters + string.digits + " -_;\n\t\""
    for _ in range(cases * 8):
        source = "".join(rng.choice(alphabet) for _ in range(rng.randrange(80)))
        try:
            parse(source)
        except LoomError:
            pass
        except Exception as exc:
            raise AssertionError(f"parser leaked {type(exc).__name__} for {source!r}") from exc


def checker_properties(rng, expressions):
    ops = {"IO": "(print 1)", "Net": "(net 1)", "Alloc": "(alloc 3)", "Rand": "(rand)"}
    for effect, operation in ops.items():
        honest = f"(defx f ({effect}) (fn () {operation}))"
        lie = f"(defx f () (fn () {operation}))"
        if check(parse(honest))[1]: raise AssertionError("honest effect rejected: " + effect)
        if not check(parse(lie))[1]: raise AssertionError("hidden effect accepted: " + effect)

    forbidden = "(forbid Net) (defx f (Net) (fn () (net 1)))"
    clean = "(defx f (Net) (fn () (net 1)))"
    for _ in range(32):
        first, second = (forbidden, clean) if rng.random() < 0.5 else (clean, forbidden)
        check(parse(first))
        second_errors = check(parse(second))[1]
        if second == clean and second_errors:
            raise AssertionError("program-wide policy leaked between checks")

    for node in expressions:
        source = "(defx f () (fn () " + render(node) + "))"
        if check(parse(source))[1]: raise AssertionError("generated pure expression rejected: " + source)
        hidden = "(defx f () (fn () (if 0 " + render(node) + " (print 1))))"
        if not check(parse(hidden))[1]: raise AssertionError("hidden generated IO accepted: " + hidden)


def differential_properties(expressions, use_node):
    fields = [["f" + str(i), node] for i, node in enumerate(expressions)]
    body = ["record"] + fields
    program = "(defx fuzz () (fn () " + render(body) + "))"
    expected = {"f" + str(i): evaluate(node) for i, node in enumerate(expressions)}
    values = [run_call(program, "(fuzz)")[0], run_compiled(program, "(fuzz)")[0]]
    if use_node:
        values += [run_js(program, "(fuzz)")[0], run_wasm(program, "(fuzz)")[0]]
    else:
        if not compile_js(program) or compile_wasm(program)[:4] != b"\x00asm":
            raise AssertionError("backend compilation failed without Node")
    for index, value in enumerate(values):
        if value != expected:
            key = next(k for k in expected if value.get(k) != expected[k])
            expr = expressions[int(key[1:])]
            raise AssertionError(
                f"backend {index} diverged at {key}: expr={render(expr)} "
                f"expected={expected[key]!r} actual={value.get(key)!r}"
            )

    a, b, c = expressions[:3]
    structured = ["record", ["xs", ["list", a, b]], ["v", ["variant", "Some", c]], ["nested", ["record", ["x", a]]]]
    structured_program = "(defx fuzz () (fn () " + render(structured) + "))"
    expected_structured = {"xs": [evaluate(a), evaluate(b)], "v": ("Some", evaluate(c)), "nested": {"x": evaluate(a)}}
    structured_values = [run_call(structured_program, "(fuzz)")[0], run_compiled(structured_program, "(fuzz)")[0]]
    if use_node:
        structured_values += [run_js(structured_program, "(fuzz)")[0], run_wasm(structured_program, "(fuzz)")[0]]
    if any(value != expected_structured for value in structured_values):
        raise AssertionError(f"structured differential mismatch: {structured_values!r}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=lambda x: int(x, 0), default=0xC17ADE1)
    parser.add_argument("--cases", type=int, default=64)
    parser.add_argument("--no-node", action="store_true")
    args = parser.parse_args(argv)
    if args.cases < 3: parser.error("--cases must be at least 3")

    rng = random.Random(args.seed)
    serial = [0]
    expressions = [expression(rng, 4, [], serial) for _ in range(args.cases)]
    try:
        for node in expressions:
            if parse(render(node))[0] != node:
                raise AssertionError("render/parse round-trip mismatch: " + render(node))
        parser_properties(rng, args.cases)
        checker_properties(rng, expressions)
        differential_properties(expressions, bool(shutil.which("node")) and not args.no_node)
    except Exception as exc:
        print(f"FAIL property fuzz seed={args.seed:#x} cases={args.cases}: {exc}")
        return 1
    print(f"PASS property fuzz seed={args.seed:#x} cases={args.cases} parser_inputs={args.cases * 8}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
