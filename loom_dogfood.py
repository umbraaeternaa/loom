#!/usr/bin/env python3
"""Four-backend, non-authorizing policy receipts for LOOM's own work."""

from __future__ import annotations

import hashlib
import json


VALIDATION_SCHEMA = "loom-dogfood-validation/v1"
RECEIPT_SCHEMA = "loom-dogfood-receipt/v1"
MAX_SOURCE_BYTES = 256 * 1024
MAX_CALL_BYTES = 4096
I31_MIN = -(1 << 30)
I31_MAX = (1 << 30) - 1
BACKENDS = ("interpreter", "python", "javascript", "webassembly")


class Frontend:
    __slots__ = (
        "parse", "build_verdict", "run_call", "run_compiled", "run_js",
        "run_wasm", "error",
    )

    def __init__(
        self, parse, build_verdict, run_call, run_compiled, run_js, run_wasm,
        error,
    ):
        self.parse = parse
        self.build_verdict = build_verdict
        self.run_call = run_call
        self.run_compiled = run_compiled
        self.run_js = run_js
        self.run_wasm = run_wasm
        self.error = error


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _canonical_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def _validation(receipt=None, findings=()):
    valid = not findings
    accepted = bool(valid and receipt["decision"] == "accept")
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "accepted": accepted,
        "decision": receipt["decision"] if valid else "invalid",
        "advisory": True,
        "authorization": "none",
        "receipt": receipt if valid else None,
        "receipt_sha256": receipt["receipt_sha256"] if valid else None,
        "findings": list(findings),
    }


def _json_value(value, path):
    if value is None or type(value) in {bool, int, str}:
        return value, []
    if isinstance(value, (list, tuple)):
        result = []
        for index, item in enumerate(value):
            normalized, findings = _json_value(item, f"{path}.{index}")
            if findings:
                return None, findings
            result.append(normalized)
        return result, []
    if isinstance(value, dict):
        if not all(type(key) is str for key in value):
            return None, [_finding(path, "non-json-result", "result object keys must be strings")]
        result = {}
        for key in sorted(value):
            normalized, findings = _json_value(value[key], f"{path}.{key}")
            if findings:
                return None, findings
            result[key] = normalized
        return result, []
    return None, [_finding(path, "non-json-result", "backend result is not a canonical JSON value")]


def _bounded_text(value, path, maximum):
    if type(value) is not str:
        return None, [_finding(path, "expected-text", path + " must be text")]
    try:
        payload = value.encode("utf-8", "strict")
    except UnicodeError:
        return None, [_finding(path, "invalid-utf8", path + " must be valid UTF-8")]
    if len(payload) > maximum:
        return None, [_finding(path, "input-too-large", path + " exceeds its byte bound")]
    return payload, []


def _contains_forbidden_call(node, parameters):
    if not isinstance(node, list):
        return None
    if node:
        head = str(node[0])
        if head == "fn":
            return _finding("source.main", "nested-function-forbidden", "Dogfooding v1 forbids nested functions")
        if head == "main":
            return _finding("source.main", "recursion-forbidden", "Dogfooding v1 forbids recursive policy execution")
        if head in parameters:
            return _finding("source.main", "dynamic-call-forbidden", "Dogfooding v1 forbids parameter-dispatched calls")
    for item in node:
        finding = _contains_forbidden_call(item, parameters)
        if finding:
            return finding
    return None


def _policy_shape(frontend, source, call):
    try:
        program = frontend.parse(source)
        call_nodes = frontend.parse(call)
    except frontend.error as error:
        return None, None, [_finding("source", "parse-failed", str(error)[:240])]

    definitions = [
        node for node in program
        if isinstance(node, list) and node and str(node[0]) == "defx"
    ]
    if (
        len(program) != 1 or len(definitions) != 1
        or len(definitions[0]) < 4 or str(definitions[0][1]) != "main"
    ):
        return None, None, [_finding(
            "source", "single-main-required",
            "Dogfooding v1 requires exactly one function definition named main",
        )]
    function = definitions[0][3]
    if not isinstance(function, list) or len(function) < 3 or str(function[0]) != "fn":
        return None, None, [_finding("source.main", "invalid-main", "main must contain one fn body")]
    parameters = function[1]
    if not isinstance(parameters, list) or any(isinstance(item, list) for item in parameters):
        return None, None, [_finding(
            "source.main", "first-order-parameters-required",
            "Dogfooding v1 permits only first-order value parameters",
        )]
    if len(parameters) > 1:
        return None, None, [_finding(
            "source.main", "single-input-profile-required",
            "Dogfooding v1 permits zero or one i31 input",
        )]
    parameter_names = {str(item) for item in parameters}
    for expression in function[2:]:
        finding = _contains_forbidden_call(expression, parameter_names)
        if finding:
            return None, None, [finding]

    if len(call_nodes) != 1 or not isinstance(call_nodes[0], list) or not call_nodes[0]:
        return None, None, [_finding("call", "single-call-required", "call must be one (main ...) expression")]
    call_node = call_nodes[0]
    if str(call_node[0]) != "main":
        return None, None, [_finding("call", "main-call-required", "Dogfooding v1 may invoke only main")]
    if len(call_node) - 1 != len(parameters):
        return None, None, [_finding("call", "arity-mismatch", "call arguments must match main parameters")]
    if any(type(item) is not int for item in call_node[1:]):
        return None, None, [_finding("call", "integer-input-required", "Dogfooding v1 inputs must be i31 integer literals")]
    if any(item < I31_MIN or item > I31_MAX for item in call_node[1:]):
        return None, None, [_finding("call", "i31-input-out-of-range", "Dogfooding v1 inputs must fit signed i31")]
    return program, call_node, []


def evaluate_policy_v1(frontend, source, call="(main)"):
    source_bytes, findings = _bounded_text(source, "source", MAX_SOURCE_BYTES)
    if findings:
        return _validation(findings=findings)
    call_bytes, findings = _bounded_text(call, "call", MAX_CALL_BYTES)
    if findings:
        return _validation(findings=findings)
    _, call_node, findings = _policy_shape(frontend, source, call)
    if findings:
        return _validation(findings=findings)

    try:
        verdict = frontend.build_verdict(source)
    except Exception as error:
        return _validation(findings=[_finding(
            "source", "checker-failed", str(error)[:240],
        )])
    if verdict.get("verdict") != "accept":
        return _validation(findings=[_finding(
            "source", "checker-rejected", "the LOOM checker rejected the dogfood policy",
        )])
    impure = [
        item["name"] for item in verdict.get("functions", [])
        if item.get("declared_effects") or item.get("performed_effects")
        or item.get("required_effects") or item.get("capabilities")
        or item.get("status") != "clean"
    ]
    if impure:
        return _validation(findings=[_finding(
            "source", "pure-policy-required",
            "Dogfooding v1 requires every function to have an empty effect row",
        )])

    runners = (
        ("interpreter", frontend.run_call),
        ("python", frontend.run_compiled),
        ("javascript", frontend.run_js),
        ("webassembly", frontend.run_wasm),
    )
    executions = []
    observables = []
    for backend, runner in runners:
        try:
            value, output = runner(source, call)
        except Exception as error:
            return _validation(findings=[_finding(
                "executions." + backend, "backend-execution-failed", str(error)[:240],
            )])
        value, value_findings = _json_value(value, "executions." + backend + ".value")
        if value_findings:
            return _validation(findings=value_findings)
        if not isinstance(output, list) or any(type(line) is not str for line in output):
            return _validation(findings=[_finding(
                "executions." + backend + ".output", "invalid-output",
                "backend output must be a list of text lines",
            )])
        observable = {"value": value, "output": list(output)}
        observable_sha256 = _sha256(_canonical_bytes(observable))
        executions.append({
            "backend": backend,
            "value": value,
            "output": list(output),
            "observable_sha256": observable_sha256,
        })
        observables.append(observable)

    if any(item != observables[0] for item in observables[1:]):
        return _validation(findings=[_finding(
            "executions", "backend-disagreement",
            "interpreter, Python, JavaScript, and WebAssembly observables must agree exactly",
        )])
    if observables[0]["output"]:
        return _validation(findings=[_finding(
            "executions", "observable-output-forbidden",
            "Dogfooding v1 policies must produce no output",
        )])
    decision_value = observables[0]["value"]
    if type(decision_value) is not int or decision_value not in (0, 1):
        return _validation(findings=[_finding(
            "executions", "binary-decision-required",
            "Dogfooding v1 policy result must be the exact i31 integer 0 or 1",
        )])

    call_normalized = "(" + " ".join(["main"] + [str(item) for item in call_node[1:]]) + ")"
    body = {
        "schema": RECEIPT_SCHEMA,
        "decision": "accept" if decision_value == 1 else "refuse",
        "source": {
            "encoding": "utf-8",
            "bytes": len(source_bytes),
            "sha256": _sha256(source_bytes),
        },
        "call": {
            "expression": call_normalized,
            "sha256": _sha256(call_normalized.encode("utf-8")),
            "input_provenance": "operator-supplied-unverified",
        },
        "policy": {
            "entrypoint": "main",
            "effect_row": [],
            "decision_values": {"accept": 1, "refuse": 0},
            "single_definition": True,
            "maximum_inputs": 1,
            "recursion": "forbidden",
            "dynamic_dispatch": "forbidden",
        },
        "executions": executions,
        "agreement": {
            "backends": list(BACKENDS),
            "exact": True,
            "observable_sha256": executions[0]["observable_sha256"],
        },
        "lifecycle": {
            "advisory": True,
            "authorization": "none",
            "host_actions_executed": False,
            "external_input_identity_verified": False,
            "compiler_is_in_trusted_computing_base": True,
        },
    }
    receipt = dict(body)
    receipt["receipt_sha256"] = _sha256(_canonical_bytes(body))
    return _validation(receipt=receipt)


def verify_policy_receipt_v1(frontend, receipt, source, call="(main)"):
    """Re-execute one policy and require exact equality with its supplied receipt."""
    if not isinstance(receipt, dict):
        return _validation(findings=[_finding(
            "receipt", "expected-object", "Dogfooding v1 receipt must be an object",
        )])
    expected = evaluate_policy_v1(frontend, source, call)
    if not expected["valid"]:
        return expected
    expected_receipt = expected["receipt"]
    if set(receipt) != set(expected_receipt):
        return _validation(findings=[_finding(
            "receipt", "closed-object-mismatch",
            "Dogfooding v1 receipt has missing or unknown fields",
        )])
    if receipt != expected_receipt:
        return _validation(findings=[_finding(
            "receipt", "receipt-mismatch",
            "supplied receipt does not match a fresh four-backend policy evaluation",
        )])
    return expected
