#!/usr/bin/env python3
"""Shared frontend contracts for LOOM backend modules.

These contracts capture the services backends need from the main LOOM frontend
without coupling them back to loom.py directly.
"""

ASM_TARGETS = frozenset({"wasm"})
ASM_INTRINSICS = {"i31.add": 2}


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
    arity = ASM_INTRINSICS.get(opcode)
    if arity is None:
        return f"asm: unsupported wasm opcode '{opcode}' in v0"
    got = len(node) - 3
    if got != arity:
        return f"asm: wasm opcode '{opcode}' expects {arity} argument(s), got {got}"
    return None


class BackendFrontend:
    __slots__ = ("parse", "check", "pname", "error", "op", "check_call_literals")

    def __init__(self, parse, check, pname, error, op, check_call_literals):
        self.parse = parse
        self.check = check
        self.pname = pname
        self.error = error
        self.op = op
        self.check_call_literals = check_call_literals


class CodegenFrontend(BackendFrontend):
    __slots__ = ("int_min", "int_mod")

    def __init__(self, parse, check, pname, error, op, check_call_literals, int_min, int_mod):
        super().__init__(parse, check, pname, error, op, check_call_literals)
        self.int_min = int_min
        self.int_mod = int_mod


class WasmFrontend(BackendFrontend):
    __slots__ = ("platent", "roleclauses")

    def __init__(self, parse, check, pname, error, op, check_call_literals, platent, roleclauses):
        super().__init__(parse, check, pname, error, op, check_call_literals)
        self.platent = platent
        self.roleclauses = roleclauses


class RuntimeFrontend(BackendFrontend):
    __slots__ = ("roleclauses", "i31")

    def __init__(self, parse, check, pname, error, op, check_call_literals, roleclauses, i31):
        super().__init__(parse, check, pname, error, op, check_call_literals)
        self.roleclauses = roleclauses
        self.i31 = i31


class CliFrontend:
    __slots__ = ("parse", "check", "run_call", "compile_py", "compile_js", "emit_wat", "error")

    def __init__(self, parse, check, run_call, compile_py, compile_js, emit_wat, error):
        self.parse = parse
        self.check = check
        self.run_call = run_call
        self.compile_py = compile_py
        self.compile_js = compile_js
        self.emit_wat = emit_wat
        self.error = error
