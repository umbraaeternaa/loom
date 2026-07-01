#!/usr/bin/env python3
"""Shared frontend contracts for LOOM backend modules.

These contracts capture the services backends need from the main LOOM frontend
without coupling them back to loom.py directly.
"""


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
    __slots__ = ("platent",)

    def __init__(self, parse, check, pname, error, op, check_call_literals, platent):
        super().__init__(parse, check, pname, error, op, check_call_literals)
        self.platent = platent


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
