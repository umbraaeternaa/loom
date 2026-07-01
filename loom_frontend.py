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
