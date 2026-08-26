#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + REQUIRED effects `E!` (two-sided row:
# floor MUST-perform <= actual <= ceiling MAY-perform -> the row IS the D7 synthesis contract) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
import base64
import binascii
import hashlib
import json
import unicodedata
EFFECTS = {"Pure", "IO", "Net", "Alloc", "FFI", "Rand"}   # Rand = nondeterminism (randomness / wall-clock)
# checker vocab MUST stay == interpreter (ev) vocab — no form the checker knows that the runtime can't run.
BUILTIN_EFF = {"print": {"IO"}, "net": {"Net"}, "alloc": {"Alloc"}, "rand": {"Rand"}}
PURE_OPS = {"+", "-", "*", "=", "<", ">",          # pure ops the interpreter runs; legitimate heads, zero effect
            "list", "cons", "head", "tail", "empty"}  # pure list primitives (map/fold are then DEFINABLE in LOOM)
OP = {"IO": "print", "Net": "net", "Alloc": "alloc", "Rand": "rand"}   # which builtin operation a `with`-handler reinterprets
_MISS = object()                                        # sentinel for scoped save/restore
INT_BITS = 31
INT_MIN = -(1 << (INT_BITS - 1))
INT_MAX = (1 << (INT_BITS - 1)) - 1
_INT_MOD = 1 << INT_BITS


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


def _i31(n):
    """Canonical signed i31 wraparound shared by every LOOM execution backend."""
    return ((n - INT_MIN) % _INT_MOD) + INT_MIN


def _int_literal_errors(nodes):
    errors = []
    def walk(node):
        if isinstance(node, int):
            if node < INT_MIN or node > INT_MAX:
                errors.append(f"integer literal {node} outside LOOM i31 range [{INT_MIN}, {INT_MAX}]")
        elif isinstance(node, list):
            for item in node: walk(item)
    for node in nodes: walk(node)
    return errors


def _check_call_literals(call_ast):
    errors = _int_literal_errors(call_ast)
    if errors: raise LoomError("; ".join(errors))


def plin(p): return p[1] if (isinstance(p, list) and len(p) >= 2 and p[0] == "lin") else None   # (lin r) = LINEAR param
def pname(p):                                                    # a param is `name` (value) · `(name eff..)` (fn) · `(lin r)` (linear)
    if isinstance(p, list): return p[1] if p and p[0] == "lin" else p[0]
    return p
def platent(p):                                                 # fn-param's latent effects; None for value / linear params
    if isinstance(p, list) and p and p[0] == "lin": return None
    return set(p[1:]) if isinstance(p, list) else None
def is_var(e): return _is_symbol(e) and e not in EFFECTS and e[:1].islower()  # lowercase token = effect variable
def is_fn_expr(e, fns, penv):                                    # does this expression denote a function?
    return (isinstance(e, list) and len(e) > 0 and e[0] == "fn") or (_is_symbol(e) and (e in fns or e in penv))


class LoomError(Exception): pass


import loom_parse as _loom_parse
import loom_checker as _loom_checker
import loom_runtime as _loom_runtime
import loom_cli as _loom_cli
import loom_gate as _loom_gate
import loom_observer as _loom_observer
import loom_evidence as _loom_evidence
import loom_approval as _loom_approval
import loom_executor as _loom_executor

_PARSE_FRONTEND = _loom_parse.Frontend(LoomError)

_CHECKER_FRONTEND = _loom_checker.Frontend(
    EFFECTS,
    BUILTIN_EFF,
    PURE_OPS,
    plin,
    pname,
    platent,
    is_var,
    is_fn_expr,
    _int_literal_errors,
    INT_MIN,
    INT_MAX,
    _i31,
    _MISS,
    LoomError,
)


def tokenize(s):
    return _loom_parse.tokenize(_PARSE_FRONTEND, s)


def tokenize_spans(s):
    return _loom_parse.tokenize_spans(_PARSE_FRONTEND, s)


def parse_spans(s):
    return _loom_parse.parse_spans(_PARSE_FRONTEND, s)


def _read(t):
    return _loom_parse._read(_PARSE_FRONTEND, t)


def parse(s):
    return _loom_parse.parse(_PARSE_FRONTEND, s)


def _roleclauses(tail):
    return _loom_checker._roleclauses(tail)


def check(program):
    """Check one program via the extracted checker module while preserving the public facade."""
    return _loom_checker.check(program, _CHECKER_FRONTEND)


Closure = _loom_runtime.Closure
FOREIGN = _loom_runtime.FOREIGN
_RUNTIME_FRONTEND = _loom_runtime.Frontend(parse, check, pname, LoomError, OP, _check_call_literals, _roleclauses, _i31)


def call_fn(val, args, fns, out, handlers):
    return _loom_runtime.call_fn(_RUNTIME_FRONTEND, val, args, fns, out, handlers)


def ev(node, env, fns, out, handlers=None):
    return _loom_runtime.ev(_RUNTIME_FRONTEND, node, env, fns, out, handlers)


def run_call(program_src, call_src):
    """Static-check a program, then evaluate one call against it. Rejects if it fails the effect checker."""
    return _loom_runtime.run_call(program_src, call_src, _RUNTIME_FRONTEND)


# ---- PORTABLE CODEGEN: implementation lives in loom_codegen.py; public facade stays stable. ----
import loom_codegen as _loom_codegen

_CODEGEN_FRONTEND = _loom_codegen.Frontend(parse, check, pname, LoomError, OP, _check_call_literals, INT_MIN, _INT_MOD, _roleclauses)

def _emit(node):
    return _loom_codegen._emit(_CODEGEN_FRONTEND, node)

def compile_py(program_src):
    return _loom_codegen.compile_py(program_src, _CODEGEN_FRONTEND)

def run_compiled(program_src, call_src):
    return _loom_codegen.run_compiled(program_src, call_src, _CODEGEN_FRONTEND)

def _emit_js(node):
    return _loom_codegen._emit_js(_CODEGEN_FRONTEND, node)

def compile_js(program_src):
    return _loom_codegen.compile_js(program_src, _CODEGEN_FRONTEND)

def run_js(program_src, call_src):
    return _loom_codegen.run_js(program_src, call_src, _CODEGEN_FRONTEND)

# ---- THIRD TARGET: WebAssembly. The implementation lives in loom_wasm.py;
#      this module supplies the checked LOOM frontend through an explicit dependency boundary. ----
import loom_wasm as _loom_wasm
import loom_provenance as _loom_provenance

_WASM_ABI_VERSION = _loom_wasm.WASM_ABI_VERSION
_WASM_ABI_V2_VERSION = _loom_wasm.WASM_ABI_V2_VERSION
_GATE_COMPILER_SURFACE = "modular-python"
_WASM_FRONTEND = _loom_wasm.Frontend(parse, parse_spans, check, pname, LoomError, OP, _check_call_literals, platent, _roleclauses)

def compile_wasm(program_src):
    return _loom_wasm.compile_wasm(program_src, _WASM_FRONTEND)

def compile_wasm_v2(program_src):
    return _loom_wasm.compile_wasm(program_src, _WASM_FRONTEND, _WASM_ABI_V2_VERSION)

def verify_wasm_trust_receipt(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_trust_receipt_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt_v2(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_trust_receipt_abi_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt(
        program_src, wasm_bytes, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    )

def verify_wasm_trust_receipt_v2_abi_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt_v2(
        program_src, wasm_bytes, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    )

def verify_wasm_source_equivalence(program_src, wasm_bytes):
    return _loom_wasm.verify_source_equivalence(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_source_equivalence_abi_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_source_equivalence(
        program_src, wasm_bytes, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    )

def verify_wasm_component_bridge_v0(program_src, wasm_bytes):
    return _loom_wasm.verify_component_bridge_v0(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_component_bridge_v0_abi_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_component_bridge_v0(
        program_src, wasm_bytes, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    )

def build_wasm_compiler_profile(surface, components):
    return _loom_provenance.build_compiler_profile(surface, components, _WASM_ABI_VERSION)

def verify_wasm_compiler_profile(profile, surface, components):
    return _loom_provenance.verify_compiler_profile(profile, surface, components, _WASM_ABI_VERSION)


def _artifact_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


_INTERFACE_BINDING_SCHEMA = "loom-interface-binding/v0"
_INTERFACE_BINDING_VALIDATION_SCHEMA = "loom-interface-binding-validation/v0"
_TOOL_BINDING_SCHEMA = "loom-tool-binding/v0"
_TOOL_BINDING_VALIDATION_SCHEMA = "loom-tool-binding-validation/v0"
_LOCAL_PROCESS_PROTOCOL = "local-process/v1"
_LOCAL_PROCESS_AUTHORITY = "urn:loom:host:operator-gate"
_LOCAL_PROCESS_DESCRIPTOR = {
    "schema": "loom-local-process-interface/v1",
    "action": "process",
    "plan_schema": "loom-gate-execution-plan/v1",
    "plan_validation_schema": "loom-gate-execution-plan-validation/v1",
    "attempt_schema": "loom-gate-host-attempt/v1",
    "attempt_validation_schema": "loom-gate-host-attempt-validation/v1",
    "attempt_results": ["blocked", "completed", "failed"],
    "executor_boundary": "no-shell/no-network-by-default",
}
_BINDING_MAX_DEPTH = 16
_BINDING_MAX_ITEMS = 256
_BINDING_MAX_STRING_BYTES = 65536
_BINDING_MAX_SAFE_INTEGER = (1 << 53) - 1


def _binding_result(schema, key, value, findings):
    return {
        "schema": schema,
        "valid": not findings,
        "advisory": True,
        key: value if not findings else None,
        "findings": findings,
    }


def _binding_sha256(value):
    return hashlib.sha256(_artifact_json(value).encode("utf-8")).hexdigest()


def _binding_is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _normalize_binding_json(value, path="input", depth=0):
    findings = []
    if depth > _BINDING_MAX_DEPTH:
        return None, [{"path": path, "code": "maximum-depth", "message": "binding JSON exceeds maximum depth 16"}]
    if value is None or isinstance(value, bool):
        return value, []
    if type(value) is int:
        if abs(value) > _BINDING_MAX_SAFE_INTEGER:
            findings.append({"path": path, "code": "unsafe-integer", "message": "binding JSON integer exceeds the portable safe range"})
        return value, findings
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if len(normalized.encode("utf-8")) > _BINDING_MAX_STRING_BYTES:
            findings.append({"path": path, "code": "string-too-large", "message": "binding JSON string exceeds 65536 UTF-8 bytes"})
        return normalized, findings
    if isinstance(value, list):
        if len(value) > _BINDING_MAX_ITEMS:
            findings.append({"path": path, "code": "too-many-items", "message": "binding JSON array exceeds 256 items"})
        normalized = []
        for index, item in enumerate(value):
            child, child_findings = _normalize_binding_json(item, f"{path}[{index}]", depth + 1)
            normalized.append(child)
            findings.extend(child_findings)
        return normalized, findings
    if isinstance(value, dict):
        if len(value) > _BINDING_MAX_ITEMS:
            findings.append({"path": path, "code": "too-many-items", "message": "binding JSON object exceeds 256 fields"})
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str):
                findings.append({"path": path, "code": "non-string-key", "message": "binding JSON object keys must be strings"})
                continue
            normalized_key = unicodedata.normalize("NFC", key)
            if len(normalized_key.encode("utf-8")) > _BINDING_MAX_STRING_BYTES:
                findings.append({"path": path, "code": "key-too-large", "message": "binding JSON key exceeds 65536 UTF-8 bytes"})
            if normalized_key in normalized:
                findings.append({"path": path, "code": "normalized-key-collision", "message": "binding JSON keys collide after NFC normalization"})
                continue
            child, child_findings = _normalize_binding_json(item, f"{path}.{normalized_key}", depth + 1)
            normalized[normalized_key] = child
            findings.extend(child_findings)
        return normalized, findings
    return None, [{"path": path, "code": "non-json-value", "message": "binding input must contain only portable JSON values"}]


def build_interface_binding(protocol):
    """Build a non-authorizing identity for the exact local process interface."""
    findings = []
    if not isinstance(protocol, str):
        findings.append({"path": "protocol", "code": "expected-string", "message": "interface protocol must be a string"})
    elif protocol != _LOCAL_PROCESS_PROTOCOL:
        findings.append({"path": "protocol", "code": "unsupported-protocol", "message": "expected local-process/v1"})
    if findings:
        return _binding_result(_INTERFACE_BINDING_VALIDATION_SCHEMA, "binding", None, findings)
    descriptor = json.loads(_artifact_json(_LOCAL_PROCESS_DESCRIPTOR))
    body = {
        "schema": _INTERFACE_BINDING_SCHEMA,
        "protocol": protocol,
        "descriptor": descriptor,
        "descriptor_sha256": _binding_sha256(descriptor),
    }
    body["binding_sha256"] = _binding_sha256(body)
    return _binding_result(_INTERFACE_BINDING_VALIDATION_SCHEMA, "binding", body, [])


def verify_interface_binding(binding, protocol):
    """Verify a local process interface binding against the closed v0 contract."""
    expected_result = build_interface_binding(protocol)
    findings = list(expected_result["findings"])
    expected_keys = {"schema", "protocol", "descriptor", "descriptor_sha256", "binding_sha256"}
    if not isinstance(binding, dict):
        findings.append({"path": "binding", "code": "expected-object", "message": "interface binding must be an object"})
        return _binding_result(_INTERFACE_BINDING_VALIDATION_SCHEMA, "binding", None, findings)
    for key in sorted(set(binding) - expected_keys):
        findings.append({"path": "binding." + key, "code": "unknown-field", "message": "unknown interface binding field"})
    for key in sorted(expected_keys - set(binding)):
        findings.append({"path": "binding." + key, "code": "missing-field", "message": "missing interface binding field"})
    if binding.get("schema") != _INTERFACE_BINDING_SCHEMA:
        findings.append({"path": "binding.schema", "code": "unsupported-schema", "message": "expected loom-interface-binding/v0"})
    if binding.get("protocol") != _LOCAL_PROCESS_PROTOCOL:
        findings.append({"path": "binding.protocol", "code": "protocol-mismatch", "message": "interface binding must use local-process/v1"})
    for key in ("descriptor_sha256", "binding_sha256"):
        if not _binding_is_sha256(binding.get(key)):
            findings.append({"path": "binding." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
    if set(binding) == expected_keys and isinstance(binding.get("descriptor"), dict):
        if binding.get("descriptor_sha256") != _binding_sha256(binding["descriptor"]):
            findings.append({"path": "binding.descriptor_sha256", "code": "descriptor-hash-mismatch", "message": "descriptor hash does not match the canonical interface descriptor"})
        unsigned = {key: binding[key] for key in sorted(expected_keys - {"binding_sha256"})}
        if binding.get("binding_sha256") != _binding_sha256(unsigned):
            findings.append({"path": "binding.binding_sha256", "code": "binding-hash-mismatch", "message": "binding hash does not match the canonical interface binding"})
    if expected_result["valid"] and binding != expected_result["binding"]:
        findings.append({"path": "binding", "code": "interface-mismatch", "message": "interface binding does not match the exact local process contract"})
    return _binding_result(_INTERFACE_BINDING_VALIDATION_SCHEMA, "binding", binding, findings)


def _local_process_output_contract():
    return {
        "attempt_schema": _LOCAL_PROCESS_DESCRIPTOR["attempt_schema"],
        "attempt_validation_schema": _LOCAL_PROCESS_DESCRIPTOR["attempt_validation_schema"],
        "results": list(_LOCAL_PROCESS_DESCRIPTOR["attempt_results"]),
    }


def build_tool_binding(protocol, authority, operation, input_value):
    """Bind exact local process authority, operation, interface, and JSON input."""
    findings = []
    interface_result = build_interface_binding(protocol)
    findings.extend(interface_result["findings"])
    if not isinstance(authority, str):
        findings.append({"path": "authority", "code": "expected-string", "message": "tool authority must be a string"})
    elif authority != _LOCAL_PROCESS_AUTHORITY:
        findings.append({"path": "authority", "code": "authority-mismatch", "message": "local process authority must be urn:loom:host:operator-gate"})
    if not isinstance(operation, str):
        findings.append({"path": "operation", "code": "expected-string", "message": "tool operation must be a string"})
    elif operation != "process":
        findings.append({"path": "operation", "code": "operation-mismatch", "message": "local-process/v1 supports only process"})
    normalized_input, input_findings = _normalize_binding_json(input_value)
    findings.extend(input_findings)
    if findings:
        return _binding_result(_TOOL_BINDING_VALIDATION_SCHEMA, "binding", None, findings)
    interface_binding = interface_result["binding"]
    body = {
        "schema": _TOOL_BINDING_SCHEMA,
        "protocol": protocol,
        "authority": authority,
        "operation": operation,
        "interface_binding": interface_binding,
        "interface_binding_sha256": interface_binding["binding_sha256"],
        "input_sha256": _binding_sha256(normalized_input),
        "output_contract_sha256": _binding_sha256(_local_process_output_contract()),
    }
    body["binding_sha256"] = _binding_sha256(body)
    return _binding_result(_TOOL_BINDING_VALIDATION_SCHEMA, "binding", body, [])


def verify_tool_binding(binding, protocol, authority, operation, input_value):
    """Verify a local process tool binding against its exact caller inputs."""
    expected_result = build_tool_binding(protocol, authority, operation, input_value)
    findings = list(expected_result["findings"])
    expected_keys = {
        "schema", "protocol", "authority", "operation", "interface_binding",
        "interface_binding_sha256", "input_sha256", "output_contract_sha256", "binding_sha256",
    }
    if not isinstance(binding, dict):
        findings.append({"path": "binding", "code": "expected-object", "message": "tool binding must be an object"})
        return _binding_result(_TOOL_BINDING_VALIDATION_SCHEMA, "binding", None, findings)
    for key in sorted(set(binding) - expected_keys):
        findings.append({"path": "binding." + key, "code": "unknown-field", "message": "unknown tool binding field"})
    for key in sorted(expected_keys - set(binding)):
        findings.append({"path": "binding." + key, "code": "missing-field", "message": "missing tool binding field"})
    if binding.get("schema") != _TOOL_BINDING_SCHEMA:
        findings.append({"path": "binding.schema", "code": "unsupported-schema", "message": "expected loom-tool-binding/v0"})
    if binding.get("protocol") != _LOCAL_PROCESS_PROTOCOL:
        findings.append({"path": "binding.protocol", "code": "protocol-mismatch", "message": "tool binding must use local-process/v1"})
    if binding.get("authority") != _LOCAL_PROCESS_AUTHORITY:
        findings.append({"path": "binding.authority", "code": "authority-mismatch", "message": "tool binding has the wrong local authority"})
    if binding.get("operation") != "process":
        findings.append({"path": "binding.operation", "code": "operation-mismatch", "message": "tool binding has the wrong local operation"})
    for key in ("interface_binding_sha256", "input_sha256", "output_contract_sha256", "binding_sha256"):
        if not _binding_is_sha256(binding.get(key)):
            findings.append({"path": "binding." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
    interface_check = verify_interface_binding(binding.get("interface_binding"), protocol)
    findings.extend({"path": "binding.interface_binding." + item["path"], "code": item["code"], "message": item["message"]} for item in interface_check["findings"])
    if interface_check["valid"] and binding.get("interface_binding_sha256") != interface_check["binding"]["binding_sha256"]:
        findings.append({"path": "binding.interface_binding_sha256", "code": "interface-hash-mismatch", "message": "tool binding does not reference its embedded interface binding"})
    if set(binding) == expected_keys:
        unsigned = {key: binding[key] for key in sorted(expected_keys - {"binding_sha256"})}
        if binding.get("binding_sha256") != _binding_sha256(unsigned):
            findings.append({"path": "binding.binding_sha256", "code": "binding-hash-mismatch", "message": "binding hash does not match the canonical tool binding"})
    if expected_result["valid"] and binding != expected_result["binding"]:
        findings.append({"path": "binding", "code": "tool-mismatch", "message": "tool binding does not match the exact authority, operation, interface, or input"})
    return _binding_result(_TOOL_BINDING_VALIDATION_SCHEMA, "binding", binding, findings)


def _artifact_validation(binding, findings):
    return {
        "schema": "loom-gate-wasm-artifact-validation/v1",
        "valid": not findings,
        "advisory": True,
        "binding": binding if not findings else None,
        "findings": findings,
    }


def build_wasm_artifact_binding(manifest, program_src, wasm_bytes):
    """Build a read-only Gate binding for one exact source/WASM/receipt artifact."""
    validation = validate_manifest(manifest)
    if not validation["valid"]:
        return _artifact_validation(None, list(validation["findings"]))
    verification = verify_wasm_trust_receipt(program_src, wasm_bytes)
    if not verification["valid"]:
        return _artifact_validation(None, [{"path": "wasm", "code": "invalid-trust-receipt", "message": finding} for finding in verification["findings"]])
    verification_v2 = verify_wasm_trust_receipt_v2(program_src, wasm_bytes)
    if not verification_v2["valid"]:
        return _artifact_validation(None, [{"path": "wasm", "code": "invalid-trust-receipt-v2", "message": finding} for finding in verification_v2["findings"]])
    equivalence = verify_wasm_source_equivalence(program_src, wasm_bytes)
    if not equivalence["valid"]:
        return _artifact_validation(None, [{"path": "wasm", "code": "wasm-source-mismatch", "message": finding} for finding in equivalence["findings"]])
    receipt = verification["receipt"]
    receipt_bytes = _artifact_json(receipt).encode("utf-8")
    binding = {
        "schema": "loom-gate-wasm-artifact/v1",
        "manifest_sha256": validation["manifest_sha256"],
        "source_sha256": hashlib.sha256(program_src.encode("utf-8")).hexdigest(),
        "wasm_sha256": hashlib.sha256(bytes(wasm_bytes)).hexdigest(),
        "trust_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "wasm_abi_version": receipt["abi_version"],
    }
    return _artifact_validation(binding, [])


def verify_wasm_artifact_binding(binding, manifest, program_src, wasm_bytes):
    """Verify an artifact binding against the supplied manifest, source, and WASM bytes."""
    findings = []
    validation = validate_manifest(manifest)
    findings.extend(validation["findings"])
    expected_keys = {"schema", "manifest_sha256", "source_sha256", "wasm_sha256", "trust_receipt_sha256", "wasm_abi_version"}
    if not isinstance(binding, dict):
        findings.append({"path": "binding", "code": "expected-object", "message": "artifact binding must be an object"})
        return _artifact_validation(None, findings)
    for key in sorted(set(binding) - expected_keys):
        findings.append({"path": "binding." + key, "code": "unknown-field", "message": "unknown artifact binding field"})
    for key in sorted(expected_keys - set(binding)):
        findings.append({"path": "binding." + key, "code": "missing-field", "message": "missing artifact binding field"})
    if binding.get("schema") != "loom-gate-wasm-artifact/v1":
        findings.append({"path": "binding.schema", "code": "unsupported-schema", "message": "expected loom-gate-wasm-artifact/v1"})
    verification = verify_wasm_trust_receipt(program_src, wasm_bytes)
    findings.extend({"path": "wasm", "code": "invalid-trust-receipt", "message": finding} for finding in verification["findings"])
    verification_v2 = verify_wasm_trust_receipt_v2(program_src, wasm_bytes)
    findings.extend({"path": "wasm", "code": "invalid-trust-receipt-v2", "message": finding} for finding in verification_v2["findings"])
    equivalence = verify_wasm_source_equivalence(program_src, wasm_bytes)
    findings.extend({"path": "wasm", "code": "wasm-source-mismatch", "message": finding} for finding in equivalence["findings"])
    if not findings:
        receipt = verification["receipt"]
        expected = {
            "schema": "loom-gate-wasm-artifact/v1",
            "manifest_sha256": validation["manifest_sha256"],
            "source_sha256": hashlib.sha256(program_src.encode("utf-8")).hexdigest(),
            "wasm_sha256": hashlib.sha256(bytes(wasm_bytes)).hexdigest(),
            "trust_receipt_sha256": hashlib.sha256(_artifact_json(receipt).encode("utf-8")).hexdigest(),
            "wasm_abi_version": receipt["abi_version"],
        }
        if binding != expected:
            findings.append({"path": "binding", "code": "artifact-mismatch", "message": "artifact binding does not match the supplied manifest, source, or WASM"})
    return _artifact_validation(None if findings else binding, findings)


def _artifact_evidence_validation(evidence, findings):
    return {
        "schema": "loom-gate-wasm-artifact-evidence-validation/v1",
        "valid": not findings,
        "advisory": True,
        "evidence": evidence if not findings else None,
        "findings": findings,
    }


def build_wasm_artifact_evidence(manifest, program_src, wasm_bytes):
    """Build a verified, read-only WASM artifact evidence envelope."""
    binding_result = build_wasm_artifact_binding(manifest, program_src, wasm_bytes)
    findings = list(binding_result["findings"])
    if findings:
        return _artifact_evidence_validation(None, findings)
    binding = binding_result["binding"]
    evidence = {
        "schema": "loom-gate-wasm-artifact-evidence/v1",
        "kind": "wasm-artifact",
        "status": "pass",
        "manifest_sha256": binding["manifest_sha256"],
        "binding": binding,
        "binding_sha256": hashlib.sha256(_artifact_json(binding).encode("utf-8")).hexdigest(),
    }
    return _artifact_evidence_validation(evidence, [])


def verify_wasm_artifact_evidence(evidence, manifest, program_src, wasm_bytes):
    """Verify an artifact evidence envelope against its exact source and WASM bytes."""
    expected = build_wasm_artifact_evidence(manifest, program_src, wasm_bytes)
    if not expected["valid"]:
        return expected
    if evidence != expected["evidence"]:
        return _artifact_evidence_validation(None, [{
            "path": "evidence",
            "code": "artifact-evidence-mismatch",
            "message": "artifact evidence does not match the supplied manifest, source, or WASM",
        }])
    return _artifact_evidence_validation(evidence, [])


def _compiler_evidence_validation(evidence, findings):
    return {
        "schema": "loom-gate-wasm-compiler-evidence-validation/v1",
        "valid": not findings,
        "advisory": True,
        "evidence": evidence if not findings else None,
        "findings": findings,
    }


def _compiler_evidence_findings(prefix, findings):
    return [
        {
            "path": prefix + ("." + item["path"] if item.get("path") else ""),
            "code": item["code"],
            "message": item["message"],
        }
        for item in findings
    ]


def build_wasm_compiler_evidence(manifest, program_src, wasm_bytes, components):
    """Bind this verifier's exact compiler surface to one verified WASM artifact."""
    profile_result = build_wasm_compiler_profile(_GATE_COMPILER_SURFACE, components)
    if not profile_result["valid"]:
        return _compiler_evidence_validation(None, _compiler_evidence_findings("compiler_profile", profile_result["findings"]))
    artifact_result = build_wasm_artifact_binding(manifest, program_src, wasm_bytes)
    if not artifact_result["valid"]:
        return _compiler_evidence_validation(None, _compiler_evidence_findings("artifact", artifact_result["findings"]))
    equivalence = verify_wasm_source_equivalence(program_src, wasm_bytes)
    if not equivalence["valid"]:
        findings = [
            {"path": "source_equivalence", "code": "wasm-source-mismatch", "message": message}
            for message in equivalence["findings"]
        ]
        return _compiler_evidence_validation(None, findings)
    profile = profile_result["profile"]
    binding = artifact_result["binding"]
    if profile["wasm_abi_version"] != binding["wasm_abi_version"]:
        return _compiler_evidence_validation(None, [{
            "path": "wasm_abi_version",
            "code": "compiler-artifact-abi-mismatch",
            "message": "compiler profile and artifact binding use different WASM ABI versions",
        }])
    evidence = {
        "schema": "loom-gate-wasm-compiler-evidence/v1",
        "kind": "wasm-compiler",
        "status": "pass",
        "surface": _GATE_COMPILER_SURFACE,
        "compiler_profile": profile,
        "profile_sha256": profile["profile_sha256"],
        "artifact_binding": binding,
        "artifact_binding_sha256": hashlib.sha256(_artifact_json(binding).encode("utf-8")).hexdigest(),
        "source_equivalence": equivalence,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_artifact_json(evidence).encode("utf-8")).hexdigest()
    return _compiler_evidence_validation(evidence, [])


def verify_wasm_compiler_evidence(evidence, manifest, program_src, wasm_bytes, components):
    """Rebuild Compiler Evidence v1 from exact host inputs and compare it closed."""
    expected = build_wasm_compiler_evidence(manifest, program_src, wasm_bytes, components)
    if not expected["valid"]:
        return expected
    findings = []
    expected_keys = {
        "schema", "kind", "status", "surface", "compiler_profile", "profile_sha256",
        "artifact_binding", "artifact_binding_sha256", "source_equivalence", "evidence_sha256",
    }
    if not isinstance(evidence, dict):
        return _compiler_evidence_validation(None, [{
            "path": "evidence", "code": "expected-object", "message": "compiler evidence must be an object",
        }])
    for key in sorted(set(evidence) - expected_keys, key=str):
        findings.append({"path": "evidence." + str(key), "code": "unknown-field", "message": "unknown compiler evidence field"})
    for key in sorted(expected_keys - set(evidence)):
        findings.append({"path": "evidence." + key, "code": "missing-field", "message": "missing compiler evidence field"})
    if evidence.get("schema") != "loom-gate-wasm-compiler-evidence/v1":
        findings.append({"path": "evidence.schema", "code": "unsupported-schema", "message": "expected loom-gate-wasm-compiler-evidence/v1"})
    if evidence.get("kind") != "wasm-compiler":
        findings.append({"path": "evidence.kind", "code": "unsupported-kind", "message": "expected wasm-compiler"})
    if evidence.get("status") != "pass":
        findings.append({"path": "evidence.status", "code": "unsupported-status", "message": "expected pass"})
    if evidence.get("surface") != _GATE_COMPILER_SURFACE:
        findings.append({"path": "evidence.surface", "code": "compiler-surface-mismatch", "message": "evidence surface does not match the running compiler implementation"})
    if set(evidence) >= expected_keys:
        body = {key: evidence[key] for key in expected_keys if key != "evidence_sha256"}
        try:
            digest = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            findings.append({"path": "evidence", "code": "non-canonical-evidence", "message": "compiler evidence fields must be canonical JSON values"})
        else:
            if evidence.get("evidence_sha256") != digest:
                findings.append({"path": "evidence.evidence_sha256", "code": "evidence-hash-mismatch", "message": "compiler evidence hash does not match its canonical fields"})
    if evidence != expected["evidence"]:
        findings.append({"path": "evidence", "code": "compiler-evidence-mismatch", "message": "compiler evidence does not match the exact compiler, manifest, source, or WASM inputs"})
    return _compiler_evidence_validation(evidence if not findings else None, findings)


def _compiler_evidence_v2_attribution(builder_profile=None, verifier_profile=None):
    builder_valid = isinstance(builder_profile, dict)
    verifier_valid = isinstance(verifier_profile, dict)
    relation = "unknown"
    if builder_valid and verifier_valid:
        relation = "same" if builder_profile == verifier_profile else "different"
    return {
        "builder_surface": builder_profile.get("surface") if builder_valid else None,
        "builder_profile_sha256": builder_profile.get("profile_sha256") if builder_valid else None,
        "verifier_surface": verifier_profile.get("surface") if verifier_valid else _GATE_COMPILER_SURFACE,
        "verifier_profile_sha256": verifier_profile.get("profile_sha256") if verifier_valid else None,
        "relation": relation,
    }


def _compiler_evidence_v2_validation(evidence, attribution, findings):
    return {
        "schema": "loom-gate-wasm-compiler-evidence-validation/v2",
        "valid": not findings,
        "advisory": True,
        "evidence": evidence if not findings else None,
        "attribution": attribution,
        "findings": findings,
    }


def build_wasm_compiler_evidence_v2(manifest, program_src, wasm_bytes, builder_components):
    """Bind one artifact to this builder while retaining later verifier attribution."""
    profile_result = build_wasm_compiler_profile(_GATE_COMPILER_SURFACE, builder_components)
    if not profile_result["valid"]:
        return _compiler_evidence_v2_validation(
            None,
            _compiler_evidence_v2_attribution(),
            _compiler_evidence_findings("builder_profile", profile_result["findings"]),
        )
    profile = profile_result["profile"]
    attribution = _compiler_evidence_v2_attribution(profile, profile)
    artifact_result = build_wasm_artifact_binding(manifest, program_src, wasm_bytes)
    if not artifact_result["valid"]:
        return _compiler_evidence_v2_validation(
            None, attribution, _compiler_evidence_findings("artifact", artifact_result["findings"])
        )
    equivalence = verify_wasm_source_equivalence(program_src, wasm_bytes)
    if not equivalence["valid"]:
        findings = [
            {"path": "builder_source_equivalence", "code": "wasm-source-mismatch", "message": message}
            for message in equivalence["findings"]
        ]
        return _compiler_evidence_v2_validation(None, attribution, findings)
    binding = artifact_result["binding"]
    if profile["wasm_abi_version"] != binding["wasm_abi_version"]:
        return _compiler_evidence_v2_validation(None, attribution, [{
            "path": "wasm_abi_version",
            "code": "compiler-artifact-abi-mismatch",
            "message": "builder compiler profile and artifact binding use different WASM ABI versions",
        }])
    evidence = {
        "schema": "loom-gate-wasm-compiler-evidence/v2",
        "kind": "wasm-compiler",
        "status": "pass",
        "builder_surface": _GATE_COMPILER_SURFACE,
        "builder_profile": profile,
        "builder_profile_sha256": profile["profile_sha256"],
        "artifact_binding": binding,
        "artifact_binding_sha256": hashlib.sha256(_artifact_json(binding).encode("utf-8")).hexdigest(),
        "builder_source_equivalence": equivalence,
    }
    evidence["evidence_sha256"] = hashlib.sha256(_artifact_json(evidence).encode("utf-8")).hexdigest()
    return _compiler_evidence_v2_validation(evidence, attribution, [])


def verify_wasm_compiler_evidence_v2(
    evidence,
    manifest,
    program_src,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
):
    """Verify builder identity before attributing source/artifact equivalence."""
    expected_keys = {
        "schema", "kind", "status", "builder_surface", "builder_profile",
        "builder_profile_sha256", "artifact_binding", "artifact_binding_sha256",
        "builder_source_equivalence", "evidence_sha256",
    }
    findings = []
    if not isinstance(evidence, dict):
        return _compiler_evidence_v2_validation(None, _compiler_evidence_v2_attribution(), [{
            "path": "evidence", "code": "expected-object", "message": "compiler evidence must be an object",
        }])
    for key in sorted(set(evidence) - expected_keys, key=str):
        findings.append({"path": "evidence." + str(key), "code": "unknown-field", "message": "unknown compiler evidence field"})
    for key in sorted(expected_keys - set(evidence)):
        findings.append({"path": "evidence." + key, "code": "missing-field", "message": "missing compiler evidence field"})
    if evidence.get("schema") != "loom-gate-wasm-compiler-evidence/v2":
        findings.append({"path": "evidence.schema", "code": "unsupported-schema", "message": "expected loom-gate-wasm-compiler-evidence/v2"})
    if evidence.get("kind") != "wasm-compiler":
        findings.append({"path": "evidence.kind", "code": "unsupported-kind", "message": "expected wasm-compiler"})
    if evidence.get("status") != "pass":
        findings.append({"path": "evidence.status", "code": "unsupported-status", "message": "expected pass"})
    if evidence.get("builder_surface") != builder_surface:
        findings.append({"path": "evidence.builder_surface", "code": "builder-surface-mismatch", "message": "evidence builder surface does not match trusted-host input"})
    if set(evidence) >= expected_keys:
        body = {key: evidence[key] for key in expected_keys if key != "evidence_sha256"}
        try:
            digest = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            findings.append({"path": "evidence", "code": "non-canonical-evidence", "message": "compiler evidence fields must be canonical JSON values"})
        else:
            if evidence.get("evidence_sha256") != digest:
                findings.append({"path": "evidence.evidence_sha256", "code": "evidence-hash-mismatch", "message": "compiler evidence hash does not match its canonical fields"})
    builder_profile_result = verify_wasm_compiler_profile(
        evidence.get("builder_profile"), builder_surface, builder_components
    )
    findings.extend(_compiler_evidence_findings("builder_profile", builder_profile_result["findings"]))
    builder_profile = builder_profile_result["profile"] if builder_profile_result["valid"] else None
    if builder_profile is not None and evidence.get("builder_profile_sha256") != builder_profile["profile_sha256"]:
        findings.append({
            "path": "evidence.builder_profile_sha256",
            "code": "profile-reference-mismatch",
            "message": "evidence does not reference its verified builder profile",
        })
    verifier_profile_result = build_wasm_compiler_profile(_GATE_COMPILER_SURFACE, verifier_components)
    findings.extend(_compiler_evidence_findings("verifier_profile", verifier_profile_result["findings"]))
    verifier_profile = verifier_profile_result["profile"] if verifier_profile_result["valid"] else None
    attribution = _compiler_evidence_v2_attribution(builder_profile, verifier_profile)
    if findings:
        return _compiler_evidence_v2_validation(None, attribution, findings)
    if builder_profile != verifier_profile:
        return _compiler_evidence_v2_validation(None, attribution, [{
            "path": "compiler_profiles",
            "code": "wasm-compiler-drift",
            "message": "builder and verifier compiler profiles differ",
        }])
    expected = build_wasm_compiler_evidence_v2(manifest, program_src, wasm_bytes, builder_components)
    if not expected["valid"]:
        return _compiler_evidence_v2_validation(None, attribution, expected["findings"])
    if evidence != expected["evidence"]:
        return _compiler_evidence_v2_validation(None, attribution, [{
            "path": "evidence",
            "code": "compiler-evidence-mismatch",
            "message": "compiler evidence does not match the exact builder, manifest, source, or WASM inputs",
        }])
    return _compiler_evidence_v2_validation(evidence, attribution, [])

def emit_wat(program_src):
    return _loom_wasm.emit_wat(program_src, _WASM_FRONTEND)

def run_wasm(program_src, call_src):
    return _loom_wasm.run_wasm(program_src, call_src, _WASM_FRONTEND)

def emit_wat_v2(program_src):
    return _loom_wasm.emit_wat(program_src, _WASM_FRONTEND, _WASM_ABI_V2_VERSION)

def run_wasm_v2(program_src, call_src):
    return _loom_wasm.run_wasm(program_src, call_src, _WASM_FRONTEND, _WASM_ABI_V2_VERSION)


# ---- COMPONENT MODEL FRONTIER: bind exact checked core-WASM bytes to WIT without changing ABI v1. ----
import loom_component as _loom_component

_COMPONENT_FRONTEND = _loom_component.Frontend(
    parse,
    check,
    pname,
    compile_wasm,
    verify_wasm_trust_receipt,
    verify_wasm_trust_receipt_v2,
    _WASM_ABI_VERSION,
    LoomError,
)

_COMPONENT_FRONTEND_V2 = _loom_component.Frontend(
    parse,
    check,
    pname,
    compile_wasm_v2,
    lambda source, wasm: _loom_wasm.verify_trust_receipt(
        source, wasm, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    ),
    lambda source, wasm: _loom_wasm.verify_trust_receipt_v2(
        source, wasm, _WASM_FRONTEND, _WASM_ABI_V2_VERSION,
    ),
    _WASM_ABI_V2_VERSION,
    LoomError,
)

def _component_frontend_for_abi(abi_version):
    if abi_version == _WASM_ABI_VERSION:
        return _COMPONENT_FRONTEND
    if abi_version == _WASM_ABI_V2_VERSION:
        return _COMPONENT_FRONTEND_V2
    raise LoomError("component boundary: unsupported LOOM ABI version " + str(abi_version))


def build_wit_component_boundary_v0(program_src, wasm_bytes, package, world, exports=None, *, abi_version=1):
    component_frontend = _component_frontend_for_abi(abi_version)
    return _loom_component.build_wit_component_boundary_v0(
        component_frontend, program_src, wasm_bytes, package, world, exports,
    )


def verify_wit_component_boundary_v0(boundary, program_src, wasm_bytes, package, world, exports=None, *, abi_version=1):
    component_frontend = _component_frontend_for_abi(abi_version)
    return _loom_component.verify_wit_component_boundary_v0(
        component_frontend, boundary, program_src, wasm_bytes, package, world, exports,
    )


import loom_component_adapter as _loom_component_adapter

_COMPONENT_ADAPTER_FRONTEND = _loom_component_adapter.Frontend(
    verify_wit_component_boundary_v0,
    verify_wasm_component_bridge_v0_abi_v2,
)


def build_component_adapter_artifact_v0(
    boundary, program_src, wasm_bytes, package, world, exports=None, *,
    builder_executable, wasm_tools_executable,
):
    return _loom_component_adapter.build_component_adapter_artifact_v0(
        _COMPONENT_ADAPTER_FRONTEND, boundary, program_src, wasm_bytes, package, world, exports,
        builder_executable=builder_executable, wasm_tools_executable=wasm_tools_executable,
    )


def verify_component_adapter_artifact_v0(
    artifact, component_bytes, boundary, program_src, wasm_bytes, package, world, exports=None, *,
    wasm_tools_executable, wasmtime_executable,
):
    return _loom_component_adapter.verify_component_adapter_artifact_v0(
        _COMPONENT_ADAPTER_FRONTEND, artifact, component_bytes, boundary, program_src, wasm_bytes,
        package, world, exports, wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )


# ---- CLI: turn the kernel into a usable TOOL. `python3 loom.py <check|run|build|audit> file.loom [call] [--target py|js|wat]` ----
_CLI_FRONTEND = _loom_cli.Frontend(
    parse,
    check,
    run_call,
    compile_py,
    compile_js,
    emit_wat,
    LoomError,
    metadata={
        "citadel_checks": 503,
        "wasm_abi_version": _WASM_ABI_VERSION,
        "wasm_abi_versions": [_WASM_ABI_VERSION, _WASM_ABI_V2_VERSION],
        "i31_bits": INT_BITS,
        "backends": ["interpreter", "python", "javascript", "webassembly", "wat"],
        "commands": [
            "about",
            "release-check",
            "help",
            "examples",
            "doctor",
            "check",
            "run",
            "build",
            "audit",
            "source-map",
            "gate",
            "gate-workflow",
            "gate-workflow-v3",
            "gate-request",
            "gate-claim",
            "gate-finish",
            "gate-plan",
            "gate-exec-finish",
            "gate-attempt",
            "gate-process-attempt",
            "gate-process-finish",
        ],
    },
)


def build_verdict(program_src):
    """Return the stable JSON-safe checker verdict used by LOOM Gate clients."""
    return _loom_cli.build_verdict(_CLI_FRONTEND, program_src)


def build_about():
    """Return the stable JSON-safe LOOM implementation capability summary."""
    return _loom_cli.build_about(_CLI_FRONTEND)


def build_gate_workflow(manifest):
    """Return a stable JSON-safe route for a bounded Gate action lifecycle."""
    return _loom_cli.build_gate_workflow(manifest)


def build_gate_workflow_v2(manifest):
    """Return the Gate route with an explicit, verified WASM artifact lane."""
    workflow = build_gate_workflow(manifest)
    workflow["schema"] = "loom-gate-workflow/v2"
    workflow["artifact_evidence"] = {
        "schema": "loom-gate-wasm-artifact-evidence/v1",
        "kind": "wasm-artifact",
        "required": True,
        "receipt_api": "build_wasm_artifact_receipt",
    }
    workflow["steps"] = list(workflow["steps"])
    if workflow["valid"] and workflow["decision"] not in {"reject"}:
        artifact_step = {
            "id": "artifact-evidence",
            "kind": "trusted-host",
            "description": "Verify source, trust receipt, and exact WASM bytes before building the v2 receipt.",
            "command": "loom.build_wasm_artifact_receipt(manifest, observation, source, wasm_bytes)",
        }
        if workflow["decision"] == "accept":
            workflow["steps"].append(artifact_step)
        else:
            finish_index = next((index for index, step in enumerate(workflow["steps"]) if step["id"] == "finish"), len(workflow["steps"]))
            workflow["steps"].insert(finish_index, artifact_step)
    return workflow


def build_gate_workflow_v3(manifest):
    """Return the Gate route with compiler identity bound into receipt v3."""
    workflow = build_gate_workflow_v2(manifest)
    workflow["schema"] = "loom-gate-workflow/v3"
    workflow["compiler_evidence"] = {
        "schema": "loom-gate-wasm-compiler-evidence/v1",
        "kind": "wasm-compiler",
        "required": True,
        "surface": _GATE_COMPILER_SURFACE,
        "component_input": "trusted-host-exact-bytes",
        "receipt_api": "build_wasm_compiler_receipt",
    }
    if workflow["valid"] and workflow["decision"] not in {"reject"}:
        artifact_index = next(
            (index for index, step in enumerate(workflow["steps"]) if step["id"] == "artifact-evidence"),
            len(workflow["steps"]),
        )
        if artifact_index < len(workflow["steps"]):
            workflow["steps"][artifact_index] = {
                "id": "artifact-evidence",
                "kind": "trusted-host",
                "description": "Verify exact source, trust receipts, and WASM bytes before compiler attribution.",
                "command": "loom.build_wasm_artifact_evidence(manifest, source, wasm_bytes)",
            }
        compiler_steps = [
            {
                "id": "compiler-evidence",
                "kind": "trusted-host",
                "description": "Bind the running compiler's closed exact-byte surface to the verified artifact.",
                "command": "loom.build_wasm_compiler_evidence(manifest, source, wasm_bytes, components)",
            },
            {
                "id": "compiler-receipt",
                "kind": "trusted-host",
                "description": "Build receipt v3 from the observation, artifact evidence, and compiler evidence.",
                "command": "loom.build_wasm_compiler_receipt(manifest, observation, source, wasm_bytes, components)",
            },
        ]
        workflow["steps"][artifact_index + 1:artifact_index + 1] = compiler_steps
    return workflow


def build_gate_workflow_v4(manifest):
    """Return the Gate route with builder/verifier attribution in receipt v4."""
    workflow = build_gate_workflow_v3(manifest)
    workflow["schema"] = "loom-gate-workflow/v4"
    workflow["compiler_evidence"] = {
        "schema": "loom-gate-wasm-compiler-evidence/v2",
        "kind": "wasm-compiler",
        "required": True,
        "builder_surface": _GATE_COMPILER_SURFACE,
        "verifier_surface": _GATE_COMPILER_SURFACE,
        "builder_component_input": "trusted-host-exact-bytes",
        "verifier_component_input": "trusted-host-exact-bytes",
        "build_api": "build_wasm_compiler_evidence_v2",
        "verify_api": "verify_wasm_compiler_evidence_v2",
        "receipt_api": "build_wasm_compiler_receipt_v4",
    }
    if workflow["valid"] and workflow["decision"] != "reject":
        for step in workflow["steps"]:
            if step["id"] == "compiler-evidence":
                step.update({
                    "description": "Bind the builder compiler and preserve later verifier attribution.",
                    "command": "loom.build_wasm_compiler_evidence_v2(manifest, source, wasm_bytes, builder_components)",
                })
            elif step["id"] == "compiler-receipt":
                step.update({
                    "description": "Build receipt v4 from observation, artifact evidence, and builder evidence v2.",
                    "command": "loom.build_wasm_compiler_receipt_v4(manifest, observation, source, wasm_bytes, builder_components)",
                })
    return workflow


_CLI_FRONTEND.metadata["gate_workflow_v3_builder"] = build_gate_workflow_v3


def validate_manifest(manifest):
    """Validate and hash a read-only LOOM Gate manifest v1."""
    return _loom_gate.validate_manifest(manifest)


def evaluate_manifest(manifest):
    """Apply advisory operator/Codex/Cloud policy v1 to a task manifest."""
    return _loom_gate.evaluate_manifest(manifest)


def build_gate_diagnostics(manifest):
    """Build redacted operator-facing Gate diagnostics for a task manifest."""
    return _loom_gate.build_gate_diagnostics(manifest)


def build_receipt(manifest, observation):
    """Build a deterministic advisory receipt from a manifest and observation."""
    return _loom_gate.build_receipt(manifest, observation)


def _wasm_receipt_v2_validation(receipt, findings):
    return {
        "schema": "loom-gate-receipt-v2-validation/v1",
        "valid": not findings,
        "advisory": True,
        "receipt": receipt if not findings else None,
        "findings": findings,
    }


def build_wasm_artifact_receipt(manifest, observation, program_src, wasm_bytes):
    """Build a Gate receipt v2 containing independently verified WASM evidence."""
    base = build_receipt(manifest, observation)
    artifact = build_wasm_artifact_evidence(manifest, program_src, wasm_bytes)
    findings = list(base["findings"])
    if not artifact["valid"]:
        findings.extend(artifact["findings"])
    if findings:
        return _wasm_receipt_v2_validation(None, findings)
    body = dict(base["receipt"])
    body.pop("receipt_sha256", None)
    body["schema"] = "loom-gate-receipt/v2"
    body["artifact_evidence"] = artifact["evidence"]
    body["receipt_sha256"] = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
    return _wasm_receipt_v2_validation(body, [])


def verify_wasm_artifact_receipt(receipt, manifest, observation, program_src, wasm_bytes):
    """Verify a Gate receipt v2 against observation and exact source/WASM bytes."""
    expected = build_wasm_artifact_receipt(manifest, observation, program_src, wasm_bytes)
    if not expected["valid"]:
        return expected
    if receipt != expected["receipt"]:
        return _wasm_receipt_v2_validation(None, [{
            "path": "receipt",
            "code": "receipt-mismatch",
            "message": "WASM artifact receipt does not match the supplied Gate inputs",
        }])
    return _wasm_receipt_v2_validation(receipt, [])


def _wasm_receipt_v3_validation(receipt, findings):
    return {
        "schema": "loom-gate-receipt-v3-validation/v1",
        "valid": not findings,
        "advisory": True,
        "receipt": receipt if not findings else None,
        "findings": findings,
    }


def build_wasm_compiler_receipt(manifest, observation, program_src, wasm_bytes, components):
    """Build receipt v3 with one exact artifact and compiler-evidence identity."""
    artifact_receipt = build_wasm_artifact_receipt(manifest, observation, program_src, wasm_bytes)
    compiler = build_wasm_compiler_evidence(manifest, program_src, wasm_bytes, components)
    findings = list(artifact_receipt["findings"])
    if not compiler["valid"]:
        findings.extend(_compiler_evidence_findings("compiler_evidence", compiler["findings"]))
    if findings:
        return _wasm_receipt_v3_validation(None, findings)
    body = dict(artifact_receipt["receipt"])
    artifact_evidence = body["artifact_evidence"]
    compiler_evidence = compiler["evidence"]
    if compiler_evidence["artifact_binding"] != artifact_evidence["binding"]:
        findings.append({
            "path": "compiler_evidence.artifact_binding",
            "code": "compiler-artifact-binding-mismatch",
            "message": "compiler and receipt evidence must bind the same exact artifact",
        })
    if compiler_evidence["artifact_binding_sha256"] != artifact_evidence["binding_sha256"]:
        findings.append({
            "path": "compiler_evidence.artifact_binding_sha256",
            "code": "compiler-artifact-hash-mismatch",
            "message": "compiler and receipt evidence must use the same artifact binding hash",
        })
    if findings:
        return _wasm_receipt_v3_validation(None, findings)
    body.pop("receipt_sha256", None)
    body["schema"] = "loom-gate-receipt/v3"
    body["compiler_evidence"] = compiler_evidence
    body["receipt_sha256"] = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
    return _wasm_receipt_v3_validation(body, [])


def verify_wasm_compiler_receipt(receipt, manifest, observation, program_src, wasm_bytes, components):
    """Verify receipt v3 against all exact observation, artifact, and compiler inputs."""
    expected = build_wasm_compiler_receipt(manifest, observation, program_src, wasm_bytes, components)
    if not expected["valid"]:
        return expected
    if receipt != expected["receipt"]:
        return _wasm_receipt_v3_validation(None, [{
            "path": "receipt",
            "code": "receipt-mismatch",
            "message": "WASM compiler receipt does not match the exact Gate and compiler inputs",
        }])
    return _wasm_receipt_v3_validation(receipt, [])


def _wasm_receipt_v4_validation(receipt, compiler_attribution, findings):
    return {
        "schema": "loom-gate-receipt-v4-validation/v1",
        "valid": not findings,
        "advisory": True,
        "receipt": receipt if not findings else None,
        "compiler_attribution": compiler_attribution,
        "findings": findings,
    }


def _compiler_receipt_v4_cross_link_findings(receipt):
    findings = []
    artifact_evidence = receipt["artifact_evidence"]
    compiler_evidence = receipt["compiler_evidence"]
    artifact_binding = artifact_evidence["binding"]
    compiler_binding = compiler_evidence["artifact_binding"]
    if receipt["manifest_sha256"] != artifact_evidence["manifest_sha256"]:
        findings.append({
            "path": "artifact_evidence.manifest_sha256",
            "code": "receipt-artifact-manifest-mismatch",
            "message": "receipt and artifact evidence must bind the same manifest",
        })
    if receipt["manifest_sha256"] != compiler_binding["manifest_sha256"]:
        findings.append({
            "path": "compiler_evidence.artifact_binding.manifest_sha256",
            "code": "receipt-compiler-manifest-mismatch",
            "message": "receipt and compiler evidence must bind the same manifest",
        })
    if compiler_binding != artifact_binding:
        findings.append({
            "path": "compiler_evidence.artifact_binding",
            "code": "compiler-artifact-binding-mismatch",
            "message": "compiler and receipt evidence must bind the same exact artifact",
        })
    if compiler_evidence["artifact_binding_sha256"] != artifact_evidence["binding_sha256"]:
        findings.append({
            "path": "compiler_evidence.artifact_binding_sha256",
            "code": "compiler-artifact-hash-mismatch",
            "message": "compiler and receipt evidence must use the same artifact binding hash",
        })
    if receipt["compiler_evidence_sha256"] != compiler_evidence["evidence_sha256"]:
        findings.append({
            "path": "compiler_evidence_sha256",
            "code": "compiler-evidence-hash-mismatch",
            "message": "receipt does not reference its embedded compiler evidence",
        })
    if compiler_evidence["builder_profile"]["wasm_abi_version"] != artifact_binding["wasm_abi_version"]:
        findings.append({
            "path": "compiler_evidence.builder_profile.wasm_abi_version",
            "code": "compiler-artifact-abi-mismatch",
            "message": "builder compiler profile and artifact evidence use different WASM ABI versions",
        })
    return findings


def build_wasm_compiler_receipt_v4(manifest, observation, program_src, wasm_bytes, builder_components):
    """Build receipt v4 from Artifact Receipt v2 and builder-issued Compiler Evidence v2."""
    artifact_receipt = build_wasm_artifact_receipt(manifest, observation, program_src, wasm_bytes)
    compiler = build_wasm_compiler_evidence_v2(manifest, program_src, wasm_bytes, builder_components)
    attribution = compiler["attribution"]
    findings = list(artifact_receipt["findings"])
    if not compiler["valid"]:
        findings.extend(_compiler_evidence_findings("compiler_evidence", compiler["findings"]))
    if findings:
        return _wasm_receipt_v4_validation(None, attribution, findings)
    body = dict(artifact_receipt["receipt"])
    body.pop("receipt_sha256", None)
    body["schema"] = "loom-gate-receipt/v4"
    body["compiler_evidence"] = compiler["evidence"]
    body["compiler_evidence_sha256"] = compiler["evidence"]["evidence_sha256"]
    findings.extend(_compiler_receipt_v4_cross_link_findings(body))
    if findings:
        return _wasm_receipt_v4_validation(None, attribution, findings)
    body["receipt_sha256"] = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
    return _wasm_receipt_v4_validation(body, attribution, [])


def verify_wasm_compiler_receipt_v4(
    receipt,
    manifest,
    observation,
    program_src,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
):
    """Verify receipt structure and compiler attribution before artifact/observation checks."""
    attribution = _compiler_evidence_v2_attribution()
    findings = []
    expected_keys = {
        "schema", "advisory", "manifest_sha256", "policy", "policy_decision",
        "agent", "result", "repositories", "files_changed", "actions_observed",
        "evidence", "artifact_evidence", "compiler_evidence",
        "compiler_evidence_sha256", "receipt_sha256",
    }
    if not isinstance(receipt, dict):
        return _wasm_receipt_v4_validation(None, attribution, [{
            "path": "receipt", "code": "expected-object", "message": "compiler receipt must be an object",
        }])
    for key in sorted(set(receipt) - expected_keys, key=str):
        findings.append({"path": "receipt." + str(key), "code": "unknown-field", "message": "unknown compiler receipt field"})
    for key in sorted(expected_keys - set(receipt)):
        findings.append({"path": "receipt." + key, "code": "missing-field", "message": "missing compiler receipt field"})
    if receipt.get("schema") != "loom-gate-receipt/v4":
        findings.append({"path": "receipt.schema", "code": "unsupported-schema", "message": "expected loom-gate-receipt/v4"})
    if receipt.get("advisory") is not True:
        findings.append({"path": "receipt.advisory", "code": "invalid-advisory", "message": "compiler receipt must remain advisory"})
    if set(receipt) >= expected_keys:
        body = {key: receipt[key] for key in expected_keys if key != "receipt_sha256"}
        try:
            digest = hashlib.sha256(_artifact_json(body).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            findings.append({"path": "receipt", "code": "non-canonical-receipt", "message": "compiler receipt fields must be canonical JSON values"})
        else:
            if receipt.get("receipt_sha256") != digest:
                findings.append({"path": "receipt.receipt_sha256", "code": "receipt-hash-mismatch", "message": "receipt hash does not match its canonical fields"})
    if findings:
        return _wasm_receipt_v4_validation(None, attribution, findings)
    compiler_check = verify_wasm_compiler_evidence_v2(
        receipt["compiler_evidence"], manifest, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
    )
    attribution = compiler_check["attribution"]
    if not compiler_check["valid"]:
        return _wasm_receipt_v4_validation(
            None, attribution, _compiler_evidence_findings("compiler_evidence", compiler_check["findings"])
        )
    artifact_check = verify_wasm_artifact_evidence(
        receipt["artifact_evidence"], manifest, program_src, wasm_bytes
    )
    if not artifact_check["valid"]:
        return _wasm_receipt_v4_validation(
            None, attribution, _compiler_evidence_findings("artifact_evidence", artifact_check["findings"])
        )
    findings = _compiler_receipt_v4_cross_link_findings(receipt)
    if findings:
        return _wasm_receipt_v4_validation(None, attribution, findings)
    expected = build_wasm_compiler_receipt_v4(
        manifest, observation, program_src, wasm_bytes, builder_components
    )
    if not expected["valid"]:
        return _wasm_receipt_v4_validation(None, attribution, expected["findings"])
    if receipt != expected["receipt"]:
        return _wasm_receipt_v4_validation(None, attribution, [{
            "path": "receipt",
            "code": "receipt-mismatch",
            "message": "WASM compiler receipt v4 does not match the exact Gate and builder inputs",
        }])
    return _wasm_receipt_v4_validation(receipt, attribution, [])


_ACTION_SEMANTICS_SCHEMA = "loom-action-semantics/v0"
_ACTION_SEMANTICS_VALIDATION_SCHEMA = "loom-action-semantics-validation/v0"
_ACTION_SOURCE_LIMITS_SCHEMA = "loom-action-source-limits/v0"
_ACTION_TARGET_MEDIATION_SCHEMA = "loom-action-target-mediation/v0"
_ACTION_ENTRYPOINT = "main"
_ACTION_COMPONENT = "operator-gate"
_ACTION_CAPSULE_SCHEMA = "loom-action-capsule/v0"
_ACTION_CAPSULE_VALIDATION_SCHEMA = "loom-action-capsule-validation/v0"
_ACTION_ACTOR_SCHEMA = "loom-action-actor-declaration/v0"
_ACTION_CAPSULE_BINDINGS_SCHEMA = "loom-action-capsule-bindings/v0"
_ACTION_EXECUTION_CLASS_SCHEMA = "loom-action-execution-class/v0"
_ACTION_CAPSULE_LIFECYCLE_SCHEMA = "loom-action-capsule-lifecycle/v0"
_ACTION_CAPSULE_REQUIRED_BEFORE = (
    "loom-action-invocation-binding/v0",
    "loom-action-capsule-approval/v2",
    "loom-action-capsule-claim/v0",
    "loom-action-host-mediation/v0",
)
_ACTION_CAPSULE_REQUIRED_AFTER = (
    "loom-action-capsule-result/v0",
    "loom-gate-receipt/v4",
)
_ACTION_INVOCATION_BINDING_SCHEMA = "loom-action-invocation-binding/v0"
_ACTION_INVOCATION_BINDING_VALIDATION_SCHEMA = "loom-action-invocation-binding-validation/v0"
_ACTION_INVOCATION_SCHEMA = "loom-local-process-invocation/v0"
_ACTION_INVOCATION_ADAPTER_SCHEMA = "loom-host-adapter-identity/v0"
_ACTION_INVOCATION_STDIN_SCHEMA = "loom-action-invocation-stdin/v0"
_ACTION_INVOCATION_LINKS_SCHEMA = "loom-action-invocation-cross-links/v0"
_ACTION_INVOCATION_LIFECYCLE_SCHEMA = "loom-action-invocation-lifecycle/v0"
_ACTION_INVOCATION_REQUIRED_NEXT = (
    "loom-action-capsule-approval/v2",
    "loom-action-capsule-claim/v0",
    "loom-action-host-mediation/v0",
)
_ACTION_APPROVAL_CHALLENGE_SCHEMA = "loom-action-approval-challenge/v2"
_ACTION_APPROVAL_REQUEST_SCHEMA = "loom-action-approval-request/v2"
_ACTION_APPROVAL_REQUEST_VALIDATION_SCHEMA = "loom-action-approval-request-validation/v2"
_ACTION_APPROVAL_REVIEW_SCHEMA = "loom-action-approval-review/v2"
_ACTION_APPROVAL_REQUEST_LIFECYCLE_SCHEMA = "loom-action-approval-request-lifecycle/v2"
_ACTION_APPROVAL_SCHEMA = "loom-action-capsule-approval/v2"
_ACTION_APPROVAL_VALIDATION_SCHEMA = "loom-action-capsule-approval-validation/v2"
_ACTION_APPROVAL_SCOPE = "exact-invocation"
_ACTION_APPROVAL_MAX_TTL_MS = 900000
_ACTION_CLAIM_SCHEMA = "loom-action-capsule-claim/v0"
_ACTION_CLAIM_VALIDATION_SCHEMA = "loom-action-capsule-claim-validation/v0"
_ACTION_CLAIM_SCOPE = "exact-invocation"
_ACTION_CLAIM_LEDGER_TABLE = "action_claims_v0"
_ACTION_CLAIM_LEDGER_SCHEMA = (
    "CREATE TABLE action_claims_v0 ("
    "approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), "
    "request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64), "
    "challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256)=64), "
    "binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), "
    "capsule_sha256 TEXT NOT NULL CHECK(length(capsule_sha256)=64), "
    "invocation_sha256 TEXT NOT NULL CHECK(length(invocation_sha256)=64), "
    "claimed_at_unix_ms INTEGER NOT NULL CHECK(claimed_at_unix_ms>=0), "
    "approval_expires_at_unix_ms INTEGER NOT NULL CHECK(approval_expires_at_unix_ms>claimed_at_unix_ms), "
    "claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), "
    "status TEXT NOT NULL CHECK(status IN ('claimed','completed','failed')))"
)
_ACTION_CLAIM_LEDGER_CREATE = _ACTION_CLAIM_LEDGER_SCHEMA.replace(
    "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1,
)
_ACTION_MEDIATION_SCHEMA = "loom-action-host-mediation/v0"
_ACTION_MEDIATION_VALIDATION_SCHEMA = "loom-action-host-mediation-validation/v0"
_ACTION_HOST_MEASUREMENT_SCHEMA = "loom-action-host-measurement/v0"
_ACTION_MEDIATION_LEDGER_TABLE = "action_mediations_v0"
_ACTION_MEDIATION_LEDGER_SCHEMA = (
    "CREATE TABLE action_mediations_v0 ("
    "claim_sha256 TEXT PRIMARY KEY CHECK(length(claim_sha256)=64), "
    "approval_sha256 TEXT NOT NULL CHECK(length(approval_sha256)=64), "
    "binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), "
    "invocation_sha256 TEXT NOT NULL CHECK(length(invocation_sha256)=64), "
    "host_measurement_sha256 TEXT NOT NULL CHECK(length(host_measurement_sha256)=64), "
    "executable_sha256 TEXT NOT NULL CHECK(length(executable_sha256)=64), "
    "environment_sha256 TEXT NOT NULL CHECK(length(environment_sha256)=64), "
    "stdin_sha256 TEXT NOT NULL CHECK(length(stdin_sha256)=64), "
    "mediated_at_unix_ms INTEGER NOT NULL CHECK(mediated_at_unix_ms>=0), "
    "approval_expires_at_unix_ms INTEGER NOT NULL CHECK(approval_expires_at_unix_ms>mediated_at_unix_ms), "
    "mediation_sha256 TEXT UNIQUE NOT NULL CHECK(length(mediation_sha256)=64), "
    "status TEXT NOT NULL CHECK(status='ready'))"
)
_ACTION_MEDIATION_LEDGER_CREATE = _ACTION_MEDIATION_LEDGER_SCHEMA.replace(
    "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1,
)
_ACTION_MEDIATION_OBLIGATIONS = (
    "reopen-executable-no-follow",
    "remeasure-executable-before-spawn",
    "reverify-working-directory-identity",
    "supply-exact-environment",
    "supply-exact-stdin",
    "enforce-timeout",
    "deny-shell",
    "deny-network",
)
_ACTION_MEDIATION_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_ACTION_EXECUTION_SCHEMA = "loom-action-bounded-execution/v0"
_ACTION_EXECUTION_VALIDATION_SCHEMA = "loom-action-bounded-execution-validation/v0"
_ACTION_EXECUTION_ATTEMPT_SCHEMA = "loom-action-process-attempt/v0"
_ACTION_EXECUTION_REMEASUREMENT_SCHEMA = "loom-action-host-remeasurement/v0"
_ACTION_EXECUTION_SANDBOX_SCHEMA = "loom-action-network-sandbox/v0"
_ACTION_EXECUTION_LEDGER_TABLE = "action_executions_v0"
_ACTION_EXECUTION_LEDGER_SCHEMA = (
    "CREATE TABLE action_executions_v0 ("
    "mediation_sha256 TEXT PRIMARY KEY CHECK(length(mediation_sha256)=64), "
    "claim_sha256 TEXT NOT NULL CHECK(length(claim_sha256)=64), "
    "binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), "
    "host_remeasurement_sha256 TEXT NOT NULL CHECK(length(host_remeasurement_sha256)=64), "
    "reserved_at_unix_ms INTEGER NOT NULL CHECK(reserved_at_unix_ms>=0), "
    "approval_expires_at_unix_ms INTEGER NOT NULL CHECK(approval_expires_at_unix_ms>reserved_at_unix_ms), "
    "status TEXT NOT NULL CHECK(status IN ('reserved','completed','failed','timed-out','output-limit-exceeded','spawn-failed')), "
    "duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms>=0), "
    "exit_code INTEGER, terminating_signal INTEGER, "
    "stdout_sha256 TEXT CHECK(stdout_sha256 IS NULL OR length(stdout_sha256)=64), "
    "stdout_size_bytes INTEGER CHECK(stdout_size_bytes IS NULL OR stdout_size_bytes>=0), "
    "stderr_sha256 TEXT CHECK(stderr_sha256 IS NULL OR length(stderr_sha256)=64), "
    "stderr_size_bytes INTEGER CHECK(stderr_size_bytes IS NULL OR stderr_size_bytes>=0), "
    "attempt_sha256 TEXT UNIQUE CHECK(attempt_sha256 IS NULL OR length(attempt_sha256)=64))"
)
_ACTION_EXECUTION_LEDGER_CREATE = _ACTION_EXECUTION_LEDGER_SCHEMA.replace(
    "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1,
)
_ACTION_EXECUTION_RESULTS = (
    "completed", "failed", "timed-out", "output-limit-exceeded", "spawn-failed",
)
_ACTION_EXECUTION_MAX_OUTPUT_BYTES = 1024 * 1024
_ACTION_EXECUTION_DARWIN_PROFILE = "(version 1)(allow default)(deny network*)"
_ACTION_RESULT_SCHEMA = "loom-action-capsule-result/v0"
_ACTION_RESULT_VALIDATION_SCHEMA = "loom-action-capsule-result-validation/v0"
_ACTION_RESULT_OUTCOME_SCHEMA = "loom-action-terminal-outcome/v0"
_ACTION_RESULT_LIFECYCLE_SCHEMA = "loom-action-result-lifecycle/v0"
_ACTION_RESULT_LEDGER_TABLE = "action_results_v0"
_ACTION_RESULT_LEDGER_SCHEMA = (
    "CREATE TABLE action_results_v0 ("
    "execution_sha256 TEXT PRIMARY KEY CHECK(length(execution_sha256)=64), "
    "attempt_sha256 TEXT UNIQUE NOT NULL CHECK(length(attempt_sha256)=64), "
    "mediation_sha256 TEXT UNIQUE NOT NULL CHECK(length(mediation_sha256)=64), "
    "claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), "
    "approval_sha256 TEXT UNIQUE NOT NULL CHECK(length(approval_sha256)=64), "
    "request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64), "
    "binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), "
    "capsule_sha256 TEXT NOT NULL CHECK(length(capsule_sha256)=64), "
    "outcome_sha256 TEXT UNIQUE NOT NULL CHECK(length(outcome_sha256)=64), "
    "finalized_at_unix_ms INTEGER NOT NULL CHECK(finalized_at_unix_ms>=0), "
    "status TEXT NOT NULL CHECK(status IN ('completed','failed','timed-out','output-limit-exceeded','spawn-failed')), "
    "claim_status TEXT NOT NULL CHECK(claim_status IN ('completed','failed')), "
    "result_sha256 TEXT UNIQUE NOT NULL CHECK(length(result_sha256)=64))"
)
_ACTION_RESULT_LEDGER_CREATE = _ACTION_RESULT_LEDGER_SCHEMA.replace(
    "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1,
)
_ACTION_ATTESTATION_VALIDATION_SCHEMA = "loom-action-result-attestation-validation/v0"
_ACTION_ATTESTATION_PREDICATE_SCHEMA = "loom-action-result-attestation-predicate/v0"
_ACTION_ATTESTATION_CROSS_LINKS_SCHEMA = "loom-action-result-attestation-links/v0"
_ACTION_ATTESTATION_ATTESTER_SCHEMA = "loom-action-result-attester/v0"
_ACTION_ATTESTATION_LIFECYCLE_SCHEMA = "loom-action-result-attestation-lifecycle/v0"
_ACTION_ATTESTATION_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_ACTION_ATTESTATION_PREDICATE_TYPE = "https://umbraaeternaa.github.io/loom/attestation/action-result/v0"
_ACTION_ATTESTATION_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_ACTION_ATTESTATION_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
_ACTION_ATTESTATION_MAX_SIGNATURE_BYTES = 8192
_ACTION_ATTESTATION_MAX_SIGNATURES = 16
_ACTION_ATTESTATION_MAX_JSON_DEPTH = 64
_ACTION_ATTESTATION_MAX_JSON_NODES = 65536


def _action_semantics_validation(semantics, compiler_attribution, findings):
    return {
        "schema": _ACTION_SEMANTICS_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "semantics": semantics if not findings else None,
        "compiler_attribution": compiler_attribution,
        "findings": findings,
    }


def _action_semantics_attribution():
    return _compiler_evidence_v2_attribution()


def _action_semantics_prefixed(path, findings):
    return [{
        "path": path + ("." + item["path"] if item.get("path") else ""),
        "code": item["code"],
        "message": item["message"],
    } for item in findings]


def _action_closed_findings(value, path, expected_keys):
    findings = []
    if not isinstance(value, dict):
        return [{"path": path, "code": "expected-object", "message": path + " must be an object"}]
    for key in sorted(set(value) - expected_keys, key=str):
        findings.append({"path": path + "." + str(key), "code": "unknown-field", "message": "unknown action semantics field"})
    for key in sorted(expected_keys - set(value)):
        findings.append({"path": path + "." + key, "code": "missing-field", "message": "missing action semantics field"})
    return findings


def _action_tool_structure_findings(binding):
    keys = {
        "schema", "protocol", "authority", "operation", "interface_binding",
        "interface_binding_sha256", "input_sha256", "output_contract_sha256", "binding_sha256",
    }
    findings = _action_closed_findings(binding, "semantics.tool_binding", keys)
    if not isinstance(binding, dict):
        return findings
    if binding.get("schema") != _TOOL_BINDING_SCHEMA:
        findings.append({"path": "semantics.tool_binding.schema", "code": "unsupported-schema", "message": "expected loom-tool-binding/v0"})
    if binding.get("protocol") != _LOCAL_PROCESS_PROTOCOL:
        findings.append({"path": "semantics.tool_binding.protocol", "code": "protocol-mismatch", "message": "expected local-process/v1"})
    if binding.get("authority") != _LOCAL_PROCESS_AUTHORITY:
        findings.append({"path": "semantics.tool_binding.authority", "code": "authority-mismatch", "message": "expected the operator-gate authority"})
    if binding.get("operation") != "process":
        findings.append({"path": "semantics.tool_binding.operation", "code": "operation-mismatch", "message": "expected process"})
    for key in ("interface_binding_sha256", "input_sha256", "output_contract_sha256", "binding_sha256"):
        if not _binding_is_sha256(binding.get(key)):
            findings.append({"path": "semantics.tool_binding." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
    interface = verify_interface_binding(binding.get("interface_binding"), _LOCAL_PROCESS_PROTOCOL)
    findings.extend(_action_semantics_prefixed("semantics.tool_binding.interface_binding", interface["findings"]))
    if interface["valid"] and binding.get("interface_binding_sha256") != interface["binding"]["binding_sha256"]:
        findings.append({"path": "semantics.tool_binding.interface_binding_sha256", "code": "interface-hash-mismatch", "message": "tool binding does not reference its embedded interface"})
    if binding.get("output_contract_sha256") != _binding_sha256(_local_process_output_contract()):
        findings.append({"path": "semantics.tool_binding.output_contract_sha256", "code": "output-contract-mismatch", "message": "tool binding has the wrong process output contract"})
    if set(binding) == keys:
        unsigned = {key: binding[key] for key in sorted(keys - {"binding_sha256"})}
        if binding.get("binding_sha256") != _binding_sha256(unsigned):
            findings.append({"path": "semantics.tool_binding.binding_sha256", "code": "binding-hash-mismatch", "message": "tool binding hash does not match its canonical fields"})
    return findings


def _action_semantics_context(manifest, tool_binding, tool_input, entrypoint):
    findings = []
    validation = validate_manifest(manifest)
    findings.extend(_action_semantics_prefixed("manifest", validation["findings"]))
    normalized_manifest = validation["normalized_manifest"] if validation["valid"] else None
    if normalized_manifest is not None:
        if normalized_manifest["schema"] != "loom-gate-manifest/v1":
            findings.append({"path": "manifest.schema", "code": "unsupported-action-manifest", "message": "Action Semantics v0 requires loom-gate-manifest/v1"})
        if normalized_manifest["actions"] != ["process"]:
            findings.append({"path": "manifest.actions", "code": "process-only-required", "message": "Action Semantics v0 requires exactly the process action"})
    decision = evaluate_manifest(manifest)
    if validation["valid"] and decision["decision"] != "operator-required":
        findings.append({"path": "manifest", "code": "operator-required", "message": "Action Semantics v0 requires an operator-required Gate decision"})
    normalized_input, input_findings = _normalize_binding_json(tool_input)
    findings.extend(_action_semantics_prefixed("tool_input", input_findings))
    expected_input = {
        "action": "process",
        "manifest_sha256": validation["manifest_sha256"],
    } if validation["valid"] else None
    if not input_findings and normalized_input != expected_input:
        findings.append({"path": "tool_input", "code": "action-input-mismatch", "message": "tool input must contain only process and the exact manifest hash"})
    tool_check = verify_tool_binding(
        tool_binding, _LOCAL_PROCESS_PROTOCOL, _LOCAL_PROCESS_AUTHORITY, "process", tool_input
    )
    findings.extend(_action_semantics_prefixed("tool_binding", tool_check["findings"]))
    if not isinstance(entrypoint, str) or entrypoint != _ACTION_ENTRYPOINT:
        findings.append({"path": "entrypoint", "code": "unsupported-entrypoint", "message": "Action Semantics v0 requires entrypoint 'main'"})
    return {
        "validation": validation,
        "manifest": normalized_manifest,
        "decision": decision,
        "tool_input": normalized_input,
        "tool_binding": tool_check["binding"] if tool_check["valid"] else None,
    }, findings


def _action_source_contract(program_src, binding_sha256):
    findings = []
    try:
        program = parse(program_src)
    except LoomError as error:
        return None, [{"path": "source", "code": "parse-error", "message": str(error)}]
    verdict = build_verdict(program_src)
    if verdict["verdict"] != "accept":
        findings.append({"path": "source", "code": "checker-rejected", "message": "Action Semantics source must pass the LOOM checker"})
        return None, findings
    if len(program) != 1:
        findings.append({"path": "source", "code": "single-main-required", "message": "Action Semantics v0 requires exactly one top-level form"})
        return None, findings
    top = program[0]
    if not (isinstance(top, list) and len(top) == 4 and _is_symbol(top[0]) and str(top[0]) == "defx"):
        findings.append({"path": "source", "code": "invalid-main-shape", "message": "expected one defx main form"})
        return None, findings
    if not (_is_symbol(top[1]) and str(top[1]) == _ACTION_ENTRYPOINT):
        findings.append({"path": "source.main", "code": "invalid-main-name", "message": "entrypoint must be symbol main"})
    effects = top[2]
    if not (isinstance(effects, list) and len(effects) == 1 and _is_symbol(effects[0]) and str(effects[0]) == "FFI!"):
        findings.append({"path": "source.main.effects", "code": "exact-ffi-required", "message": "main must declare exactly FFI!"})
    fn = top[3]
    if not (isinstance(fn, list) and len(fn) == 3 and _is_symbol(fn[0]) and str(fn[0]) == "fn"):
        findings.append({"path": "source.main", "code": "invalid-main-function", "message": "main must contain one function body expression"})
        return None, findings
    if fn[1] != []:
        findings.append({"path": "source.main.parameters", "code": "zero-arguments-required", "message": "Action Semantics v0 main must take no arguments"})
    meter = fn[2]
    if not (isinstance(meter, list) and len(meter) == 4 and _is_symbol(meter[0]) and str(meter[0]) == "seamN"):
        findings.append({"path": "source.main.body", "code": "outer-meter-required", "message": "main must contain one outer seamN expression"})
        return None, findings
    if type(meter[1]) is not int or meter[1] != 1:
        findings.append({"path": "source.main.body.quantum", "code": "single-effect-required", "message": "outer seamN quantum must be exactly 1"})
    meter_effects = meter[2]
    if not (isinstance(meter_effects, list) and len(meter_effects) == 1 and _is_symbol(meter_effects[0]) and str(meter_effects[0]) == "FFI"):
        findings.append({"path": "source.main.body.effects", "code": "ffi-meter-required", "message": "outer seamN must meter exactly FFI"})
    foreign = meter[3]
    if not (isinstance(foreign, list) and len(foreign) == 3 and _is_symbol(foreign[0]) and str(foreign[0]) == "ffi"):
        findings.append({"path": "source.main.body", "code": "direct-ffi-required", "message": "meter body must be one direct ffi call"})
        return None, findings
    if not (type(foreign[1]) is str and foreign[1] == _ACTION_COMPONENT):
        findings.append({"path": "source.main.body.ffi.component", "code": "component-mismatch", "message": "ffi component must be quoted operator-gate"})
    if not (type(foreign[2]) is str and foreign[2] == binding_sha256):
        findings.append({"path": "source.main.body.ffi.binding", "code": "tool-binding-literal-mismatch", "message": "ffi argument must be the quoted exact Tool Binding hash"})
    expected_function = {
        "name": "main",
        "declared_effects": ["FFI"],
        "performed_effects": ["FFI"],
        "required_effects": ["FFI"],
        "capabilities": ["FFI"],
        "status": "review",
        "findings": [],
    }
    if verdict["function_count"] != 1 or verdict["finding_count"] != 0 or verdict["functions"] != [expected_function]:
        findings.append({"path": "checker_verdict", "code": "checker-contract-mismatch", "message": "checker verdict must describe exactly one honest required FFI main"})
    if findings:
        return None, findings
    return {
        "verdict": verdict,
        "effect_contract": {
            "declared": ["FFI"],
            "performed": ["FFI"],
            "required": ["FFI"],
            "capabilities": ["FFI"],
        },
        "source_limits": {
            "schema": _ACTION_SOURCE_LIMITS_SCHEMA,
            "scope": "entrypoint-invocation",
            "effect_meters": [{
                "effect": "FFI", "maximum": 1, "counted_max_path": 1, "mechanism": "seamN/v1",
            }],
            "recursive_calls": None,
        },
    }, []


def _action_semantics_structure_findings(semantics):
    outer_keys = {
        "schema", "advisory", "manifest_sha256", "policy", "policy_decision",
        "tool_binding", "tool_binding_sha256", "compiler_evidence",
        "compiler_evidence_sha256", "artifact_binding_sha256", "entrypoint",
        "checker_verdict", "checker_verdict_sha256", "effect_contract",
        "source_limits", "target_mediation", "semantics_sha256",
    }
    findings = _action_closed_findings(semantics, "semantics", outer_keys)
    if not isinstance(semantics, dict):
        return findings
    if semantics.get("schema") != _ACTION_SEMANTICS_SCHEMA:
        findings.append({"path": "semantics.schema", "code": "unsupported-schema", "message": "expected loom-action-semantics/v0"})
    if semantics.get("advisory") is not True:
        findings.append({"path": "semantics.advisory", "code": "invalid-advisory", "message": "Action Semantics must remain advisory"})
    for key in (
        "manifest_sha256", "tool_binding_sha256", "compiler_evidence_sha256",
        "artifact_binding_sha256", "checker_verdict_sha256", "semantics_sha256",
    ):
        if not _binding_is_sha256(semantics.get(key)):
            findings.append({"path": "semantics." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
    findings.extend(_action_tool_structure_findings(semantics.get("tool_binding")))
    nested = (
        ("entrypoint", {"function", "arguments", "arguments_sha256", "reachable_functions"}),
        ("effect_contract", {"declared", "performed", "required", "capabilities"}),
        ("source_limits", {"schema", "scope", "effect_meters", "recursive_calls"}),
        ("target_mediation", {
            "schema", "profile", "foreign_component", "source_binding_literal",
            "protocol", "authority", "operation", "input_sha256", "output_contract_sha256",
        }),
    )
    for key, expected in nested:
        findings.extend(_action_closed_findings(semantics.get(key), "semantics." + key, expected))
    verdict = semantics.get("checker_verdict")
    if not isinstance(verdict, dict) or verdict.get("schema") != "loom-verdict/v1":
        findings.append({"path": "semantics.checker_verdict", "code": "unsupported-checker-verdict", "message": "expected loom-verdict/v1"})
    elif semantics.get("checker_verdict_sha256") != _binding_sha256(verdict):
        findings.append({"path": "semantics.checker_verdict_sha256", "code": "checker-verdict-hash-mismatch", "message": "checker verdict hash does not match its canonical fields"})
    compiler = semantics.get("compiler_evidence")
    if not isinstance(compiler, dict):
        findings.append({"path": "semantics.compiler_evidence", "code": "expected-object", "message": "compiler evidence must be an object"})
    else:
        if semantics.get("compiler_evidence_sha256") != compiler.get("evidence_sha256"):
            findings.append({"path": "semantics.compiler_evidence_sha256", "code": "compiler-evidence-hash-mismatch", "message": "semantics does not reference embedded compiler evidence"})
        if semantics.get("artifact_binding_sha256") != compiler.get("artifact_binding_sha256"):
            findings.append({"path": "semantics.artifact_binding_sha256", "code": "artifact-binding-hash-mismatch", "message": "semantics does not reference compiler artifact binding"})
    tool = semantics.get("tool_binding")
    if isinstance(tool, dict) and semantics.get("tool_binding_sha256") != tool.get("binding_sha256"):
        findings.append({"path": "semantics.tool_binding_sha256", "code": "tool-binding-hash-mismatch", "message": "semantics does not reference embedded tool binding"})
    if set(semantics) >= outer_keys:
        body = {key: semantics[key] for key in outer_keys if key != "semantics_sha256"}
        try:
            digest = _binding_sha256(body)
        except (TypeError, ValueError):
            findings.append({"path": "semantics", "code": "non-canonical-semantics", "message": "Action Semantics fields must be canonical JSON values"})
        else:
            if semantics.get("semantics_sha256") != digest:
                findings.append({"path": "semantics.semantics_sha256", "code": "semantics-hash-mismatch", "message": "Action Semantics hash does not match its canonical fields"})
    return findings


def build_action_semantics_v0(
    manifest, tool_binding, tool_input, program_src, wasm_bytes, builder_components, entrypoint
):
    """Build one pure, non-authorizing semantic binding for an exact process action."""
    context, findings = _action_semantics_context(manifest, tool_binding, tool_input, entrypoint)
    attribution = _action_semantics_attribution()
    if findings:
        return _action_semantics_validation(None, attribution, findings)
    compiler = build_wasm_compiler_evidence_v2(manifest, program_src, wasm_bytes, builder_components)
    attribution = compiler["attribution"]
    if not compiler["valid"]:
        return _action_semantics_validation(
            None, attribution, _action_semantics_prefixed("compiler_evidence", compiler["findings"])
        )
    binding = context["tool_binding"]
    source_contract, source_findings = _action_source_contract(program_src, binding["binding_sha256"])
    if source_findings:
        return _action_semantics_validation(None, attribution, source_findings)
    evidence = compiler["evidence"]
    verdict = source_contract["verdict"]
    body = {
        "schema": _ACTION_SEMANTICS_SCHEMA,
        "advisory": True,
        "manifest_sha256": context["validation"]["manifest_sha256"],
        "policy": context["decision"]["policy"],
        "policy_decision": context["decision"]["decision"],
        "tool_binding": binding,
        "tool_binding_sha256": binding["binding_sha256"],
        "compiler_evidence": evidence,
        "compiler_evidence_sha256": evidence["evidence_sha256"],
        "artifact_binding_sha256": evidence["artifact_binding_sha256"],
        "entrypoint": {
            "function": _ACTION_ENTRYPOINT,
            "arguments": [],
            "arguments_sha256": _binding_sha256([]),
            "reachable_functions": [_ACTION_ENTRYPOINT],
        },
        "checker_verdict": verdict,
        "checker_verdict_sha256": _binding_sha256(verdict),
        "effect_contract": source_contract["effect_contract"],
        "source_limits": source_contract["source_limits"],
        "target_mediation": {
            "schema": _ACTION_TARGET_MEDIATION_SCHEMA,
            "profile": "local-process-ffi-binding/v0",
            "foreign_component": _ACTION_COMPONENT,
            "source_binding_literal": binding["binding_sha256"],
            "protocol": binding["protocol"],
            "authority": binding["authority"],
            "operation": binding["operation"],
            "input_sha256": binding["input_sha256"],
            "output_contract_sha256": binding["output_contract_sha256"],
        },
    }
    body["semantics_sha256"] = _binding_sha256(body)
    return _action_semantics_validation(body, attribution, [])


def verify_action_semantics_v0(
    semantics,
    manifest,
    tool_binding,
    tool_input,
    program_src,
    wasm_bytes,
    builder_surface,
    builder_components,
    verifier_components,
    entrypoint,
):
    """Verify structure and compiler attribution before exact action semantics."""
    attribution = _action_semantics_attribution()
    findings = _action_semantics_structure_findings(semantics)
    if findings:
        return _action_semantics_validation(None, attribution, findings)
    compiler = verify_wasm_compiler_evidence_v2(
        semantics["compiler_evidence"], manifest, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
    )
    attribution = compiler["attribution"]
    if not compiler["valid"]:
        return _action_semantics_validation(
            None, attribution, _action_semantics_prefixed("compiler_evidence", compiler["findings"])
        )
    context, context_findings = _action_semantics_context(
        manifest, tool_binding, tool_input, entrypoint
    )
    if context_findings:
        return _action_semantics_validation(None, attribution, context_findings)
    source_contract, source_findings = _action_source_contract(
        program_src, context["tool_binding"]["binding_sha256"]
    )
    if source_findings:
        return _action_semantics_validation(None, attribution, source_findings)
    expected = build_action_semantics_v0(
        manifest, tool_binding, tool_input, program_src, wasm_bytes,
        builder_components, entrypoint,
    )
    if not expected["valid"]:
        return _action_semantics_validation(None, attribution, expected["findings"])
    if semantics != expected["semantics"]:
        return _action_semantics_validation(None, attribution, [{
            "path": "semantics",
            "code": "action-semantics-mismatch",
            "message": "Action Semantics does not match the exact manifest, tool, compiler, source, or effect inputs",
        }])
    return _action_semantics_validation(semantics, attribution, [])


def _action_capsule_validation(capsule, compiler_attribution, findings):
    return {
        "schema": _ACTION_CAPSULE_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "capsule": capsule if not findings else None,
        "compiler_attribution": compiler_attribution,
        "findings": findings,
    }


def _action_capsule_prefixed(path, findings):
    return [{
        "path": path + ("." + item["path"] if item.get("path") else ""),
        "code": item["code"],
        "message": item["message"],
    } for item in findings]


def _action_capsule_closed_findings(value, path, expected_keys):
    findings = []
    if not isinstance(value, dict):
        return [{"path": path, "code": "expected-object", "message": path + " must be an object"}]
    for key in sorted(set(value) - expected_keys, key=str):
        findings.append({"path": path + "." + str(key), "code": "unknown-field", "message": "unknown Action Capsule field"})
    for key in sorted(expected_keys - set(value)):
        findings.append({"path": path + "." + key, "code": "missing-field", "message": "missing Action Capsule field"})
    return findings


def _action_capsule_issue_list_findings(value, path):
    if not isinstance(value, list):
        return [{"path": path, "code": "expected-array", "message": path + " must be an array"}]
    findings = []
    keys = {"path", "code", "message"}
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        findings.extend(_action_capsule_closed_findings(item, item_path, keys))
        if isinstance(item, dict):
            for key in keys:
                if key in item and not isinstance(item[key], str):
                    findings.append({"path": item_path + "." + key, "code": "expected-string", "message": key + " must be a string"})
    return findings


def _action_capsule_body(normalized_manifest, manifest_sha256, decision, semantics):
    tool = semantics["tool_binding"]
    mediation = semantics["target_mediation"]
    meter = semantics["source_limits"]["effect_meters"][0]
    return {
        "schema": _ACTION_CAPSULE_SCHEMA,
        "advisory": True,
        "manifest": normalized_manifest,
        "manifest_sha256": manifest_sha256,
        "gate_decision": decision,
        "declared_actor": {
            "schema": _ACTION_ACTOR_SCHEMA,
            "profile": "manifest-declared/v0",
            "id": normalized_manifest["agent"]["id"],
            "role": normalized_manifest["agent"]["role"],
            "identity_assurance": "declaration-only",
        },
        "action_semantics": semantics,
        "action_semantics_sha256": semantics["semantics_sha256"],
        "bindings": {
            "schema": _ACTION_CAPSULE_BINDINGS_SCHEMA,
            "tool_binding_sha256": semantics["tool_binding_sha256"],
            "compiler_evidence_sha256": semantics["compiler_evidence_sha256"],
            "artifact_binding_sha256": semantics["artifact_binding_sha256"],
        },
        "execution_class": {
            "schema": _ACTION_EXECUTION_CLASS_SCHEMA,
            "protocol": tool["protocol"],
            "authority": tool["authority"],
            "operation": tool["operation"],
            "foreign_component": mediation["foreign_component"],
            "maximum_ffi_requests": meter["maximum"],
            "concrete_invocation": "unbound",
            "host_boundary": tool["interface_binding"]["descriptor"]["executor_boundary"],
        },
        "lifecycle": {
            "schema": _ACTION_CAPSULE_LIFECYCLE_SCHEMA,
            "authorization": "none",
            "approval_eligible": False,
            "required_before_authorization": list(_ACTION_CAPSULE_REQUIRED_BEFORE),
            "required_after_attempt": list(_ACTION_CAPSULE_REQUIRED_AFTER),
        },
    }


def _action_capsule_structure_findings(capsule):
    outer_keys = {
        "schema", "advisory", "manifest", "manifest_sha256", "gate_decision",
        "declared_actor", "action_semantics", "action_semantics_sha256",
        "bindings", "execution_class", "lifecycle", "capsule_sha256",
    }
    findings = _action_capsule_closed_findings(capsule, "capsule", outer_keys)
    if not isinstance(capsule, dict):
        return findings
    if capsule.get("schema") != _ACTION_CAPSULE_SCHEMA:
        findings.append({"path": "capsule.schema", "code": "unsupported-schema", "message": "expected loom-action-capsule/v0"})
    if capsule.get("advisory") is not True:
        findings.append({"path": "capsule.advisory", "code": "invalid-advisory", "message": "Action Capsule must remain advisory"})
    for key in ("manifest_sha256", "action_semantics_sha256", "capsule_sha256"):
        if not _binding_is_sha256(capsule.get(key)):
            findings.append({"path": "capsule." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})

    manifest_check = validate_manifest(capsule.get("manifest"))
    findings.extend(_action_capsule_prefixed("capsule.manifest", manifest_check["findings"]))
    if manifest_check["valid"]:
        if manifest_check["normalized_manifest"]["schema"] != "loom-gate-manifest/v1":
            findings.append({"path": "capsule.manifest.schema", "code": "unsupported-action-manifest", "message": "Action Capsule v0 requires loom-gate-manifest/v1"})
        if capsule.get("manifest") != manifest_check["normalized_manifest"]:
            findings.append({"path": "capsule.manifest", "code": "non-normalized-manifest", "message": "embedded manifest must already be normalized"})
        if capsule.get("manifest_sha256") != manifest_check["manifest_sha256"]:
            findings.append({"path": "capsule.manifest_sha256", "code": "manifest-hash-mismatch", "message": "capsule does not reference its embedded manifest"})

    decision = capsule.get("gate_decision")
    decision_keys = {"schema", "advisory", "policy", "manifest_sha256", "decision", "reasons", "violations"}
    findings.extend(_action_capsule_closed_findings(decision, "capsule.gate_decision", decision_keys))
    if isinstance(decision, dict):
        if decision.get("schema") != "loom-gate-decision/v1":
            findings.append({"path": "capsule.gate_decision.schema", "code": "unsupported-schema", "message": "expected loom-gate-decision/v1"})
        if decision.get("advisory") is not True:
            findings.append({"path": "capsule.gate_decision.advisory", "code": "invalid-advisory", "message": "Gate decision must remain advisory"})
        if decision.get("decision") != "operator-required":
            findings.append({"path": "capsule.gate_decision.decision", "code": "operator-required", "message": "Action Capsule v0 requires an operator-required decision"})
        if decision.get("violations") != []:
            findings.append({"path": "capsule.gate_decision.violations", "code": "decision-violations", "message": "Action Capsule v0 cannot contain Gate violations"})
        if decision.get("manifest_sha256") != capsule.get("manifest_sha256"):
            findings.append({"path": "capsule.gate_decision.manifest_sha256", "code": "manifest-hash-mismatch", "message": "Gate decision does not reference the embedded manifest"})
        findings.extend(_action_capsule_issue_list_findings(decision.get("reasons"), "capsule.gate_decision.reasons"))
        findings.extend(_action_capsule_issue_list_findings(decision.get("violations"), "capsule.gate_decision.violations"))

    actor = capsule.get("declared_actor")
    actor_keys = {"schema", "profile", "id", "role", "identity_assurance"}
    findings.extend(_action_capsule_closed_findings(actor, "capsule.declared_actor", actor_keys))
    if isinstance(actor, dict):
        fixed_actor = {
            "schema": _ACTION_ACTOR_SCHEMA,
            "profile": "manifest-declared/v0",
            "identity_assurance": "declaration-only",
        }
        for key, value in fixed_actor.items():
            if actor.get(key) != value:
                findings.append({"path": "capsule.declared_actor." + key, "code": "actor-declaration-mismatch", "message": key + " must preserve declaration-only actor semantics"})

    semantics_findings = _action_semantics_structure_findings(capsule.get("action_semantics"))
    embedded_findings = []
    for item in semantics_findings:
        item = dict(item)
        if item.get("path", "").startswith("semantics."):
            item["path"] = item["path"][len("semantics."):]
        elif item.get("path") == "semantics":
            item["path"] = ""
        embedded_findings.append(item)
    findings.extend(_action_capsule_prefixed("capsule.action_semantics", embedded_findings))
    semantics = capsule.get("action_semantics")
    if isinstance(semantics, dict) and capsule.get("action_semantics_sha256") != semantics.get("semantics_sha256"):
        findings.append({"path": "capsule.action_semantics_sha256", "code": "action-semantics-hash-mismatch", "message": "capsule does not reference embedded Action Semantics"})

    bindings = capsule.get("bindings")
    binding_keys = {"schema", "tool_binding_sha256", "compiler_evidence_sha256", "artifact_binding_sha256"}
    findings.extend(_action_capsule_closed_findings(bindings, "capsule.bindings", binding_keys))
    if isinstance(bindings, dict):
        if bindings.get("schema") != _ACTION_CAPSULE_BINDINGS_SCHEMA:
            findings.append({"path": "capsule.bindings.schema", "code": "unsupported-schema", "message": "expected loom-action-capsule-bindings/v0"})
        for key in binding_keys - {"schema"}:
            if not _binding_is_sha256(bindings.get(key)):
                findings.append({"path": "capsule.bindings." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
            if isinstance(semantics, dict) and bindings.get(key) != semantics.get(key):
                findings.append({"path": "capsule.bindings." + key, "code": "binding-hash-mismatch", "message": key + " does not match embedded Action Semantics"})

    execution = capsule.get("execution_class")
    execution_keys = {
        "schema", "protocol", "authority", "operation", "foreign_component",
        "maximum_ffi_requests", "concrete_invocation", "host_boundary",
    }
    findings.extend(_action_capsule_closed_findings(execution, "capsule.execution_class", execution_keys))
    if isinstance(execution, dict):
        fixed_execution = {
            "schema": _ACTION_EXECUTION_CLASS_SCHEMA,
            "protocol": _LOCAL_PROCESS_PROTOCOL,
            "authority": _LOCAL_PROCESS_AUTHORITY,
            "operation": "process",
            "foreign_component": _ACTION_COMPONENT,
            "concrete_invocation": "unbound",
            "host_boundary": "no-shell/no-network-by-default",
        }
        for key, value in fixed_execution.items():
            if execution.get(key) != value:
                findings.append({"path": "capsule.execution_class." + key, "code": "execution-class-mismatch", "message": key + " violates the fixed Action Capsule v0 execution class"})
        if type(execution.get("maximum_ffi_requests")) is not int or execution.get("maximum_ffi_requests") != 1:
            findings.append({"path": "capsule.execution_class.maximum_ffi_requests", "code": "execution-class-mismatch", "message": "maximum_ffi_requests must be the integer 1"})

    lifecycle = capsule.get("lifecycle")
    lifecycle_keys = {"schema", "authorization", "approval_eligible", "required_before_authorization", "required_after_attempt"}
    findings.extend(_action_capsule_closed_findings(lifecycle, "capsule.lifecycle", lifecycle_keys))
    if isinstance(lifecycle, dict):
        fixed_lifecycle = {
            "schema": _ACTION_CAPSULE_LIFECYCLE_SCHEMA,
            "authorization": "none",
            "required_before_authorization": list(_ACTION_CAPSULE_REQUIRED_BEFORE),
            "required_after_attempt": list(_ACTION_CAPSULE_REQUIRED_AFTER),
        }
        for key, value in fixed_lifecycle.items():
            if lifecycle.get(key) != value:
                findings.append({"path": "capsule.lifecycle." + key, "code": "lifecycle-mismatch", "message": key + " violates the fixed non-authorizing lifecycle"})
        if lifecycle.get("approval_eligible") is not False:
            findings.append({"path": "capsule.lifecycle.approval_eligible", "code": "lifecycle-mismatch", "message": "approval_eligible must be the boolean false"})

    if set(capsule) >= outer_keys:
        body = {key: capsule[key] for key in outer_keys if key != "capsule_sha256"}
        try:
            digest = _binding_sha256(body)
        except (TypeError, ValueError):
            findings.append({"path": "capsule", "code": "non-canonical-capsule", "message": "Action Capsule fields must be canonical JSON values"})
        else:
            if capsule.get("capsule_sha256") != digest:
                findings.append({"path": "capsule.capsule_sha256", "code": "capsule-hash-mismatch", "message": "Action Capsule hash does not match its canonical fields"})
    return findings


def build_action_capsule_v0(
    manifest, tool_binding, tool_input, program_src, wasm_bytes, builder_components, entrypoint
):
    """Build one pure, deterministic, advisory, and non-authorizing Action Capsule."""
    semantics_result = build_action_semantics_v0(
        manifest, tool_binding, tool_input, program_src, wasm_bytes,
        builder_components, entrypoint,
    )
    attribution = semantics_result["compiler_attribution"]
    if not semantics_result["valid"]:
        return _action_capsule_validation(
            None, attribution,
            _action_capsule_prefixed("action_semantics", semantics_result["findings"]),
        )
    validation = validate_manifest(manifest)
    normalized = validation["normalized_manifest"]
    body = _action_capsule_body(
        normalized, validation["manifest_sha256"], evaluate_manifest(normalized),
        semantics_result["semantics"],
    )
    body["capsule_sha256"] = _binding_sha256(body)
    return _action_capsule_validation(body, attribution, [])


def verify_action_capsule_v0(
    capsule, manifest, tool_binding, tool_input, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components, entrypoint,
):
    """Verify Capsule structure and compiler attribution before exact composition."""
    attribution = _action_semantics_attribution()
    findings = _action_capsule_structure_findings(capsule)
    if findings:
        return _action_capsule_validation(None, attribution, findings)
    semantics_check = verify_action_semantics_v0(
        capsule["action_semantics"], manifest, tool_binding, tool_input,
        program_src, wasm_bytes, builder_surface, builder_components,
        verifier_components, entrypoint,
    )
    attribution = semantics_check["compiler_attribution"]
    if not semantics_check["valid"]:
        return _action_capsule_validation(
            None, attribution,
            _action_capsule_prefixed("action_semantics", semantics_check["findings"]),
        )
    expected = build_action_capsule_v0(
        manifest, tool_binding, tool_input, program_src, wasm_bytes,
        builder_components, entrypoint,
    )
    if not expected["valid"]:
        return _action_capsule_validation(None, attribution, expected["findings"])
    if capsule != expected["capsule"]:
        return _action_capsule_validation(None, attribution, [{
            "path": "capsule",
            "code": "action-capsule-mismatch",
            "message": "Action Capsule does not match the exact manifest, decision, actor, semantics, or lifecycle inputs",
        }])
    return _action_capsule_validation(capsule, attribution, [])


def _action_invocation_binding_validation(binding, compiler_attribution, findings):
    return {
        "schema": _ACTION_INVOCATION_BINDING_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "binding": binding if not findings else None,
        "compiler_attribution": compiler_attribution,
        "findings": findings,
    }


def _action_invocation_closed_findings(value, path, expected_keys):
    findings = []
    if not isinstance(value, dict):
        return [{"path": path, "code": "expected-object", "message": path + " must be an object"}]
    for key in sorted(set(value) - expected_keys, key=str):
        findings.append({"path": path + "." + str(key), "code": "unknown-field", "message": "unknown Invocation Binding field"})
    for key in sorted(expected_keys - set(value)):
        findings.append({"path": path + "." + key, "code": "missing-field", "message": "missing Invocation Binding field"})
    return findings


def _action_invocation_string(value, path):
    if not isinstance(value, str):
        return None, [{"path": path, "code": "expected-string", "message": path + " must be a string"}]
    normalized = unicodedata.normalize("NFC", value)
    findings = []
    if not normalized:
        findings.append({"path": path, "code": "empty-string", "message": path + " must not be empty"})
    if "\x00" in normalized:
        findings.append({"path": path, "code": "nul-byte", "message": path + " must not contain NUL"})
    if len(normalized.encode("utf-8")) > _BINDING_MAX_STRING_BYTES:
        findings.append({"path": path, "code": "string-too-large", "message": path + " exceeds 65536 UTF-8 bytes"})
    return normalized, findings


def _action_invocation_file_uri(value, path):
    normalized, findings = _action_invocation_string(value, path)
    if normalized is not None and not normalized.startswith("file:///"):
        findings.append({"path": path, "code": "expected-file-uri", "message": path + " must be an absolute file URI"})
    if normalized is not None and normalized.startswith("file:///"):
        uri_path = normalized[len("file://"):]
        segments = uri_path.split("/")
        if "?" in normalized or "#" in normalized or "\\" in normalized:
            findings.append({"path": path, "code": "non-canonical-file-uri", "message": path + " must not contain query, fragment, or backslash syntax"})
        if any(segment in {".", ".."} for segment in segments) or "" in segments[1:]:
            findings.append({"path": path, "code": "non-canonical-file-uri", "message": path + " must not contain dot or empty path segments"})
    return normalized, findings


def _normalize_action_invocation(invocation, capsule, path="invocation"):
    keys = {
        "schema", "protocol", "authority", "operation", "foreign_component",
        "adapter", "argv", "working_directory_uri", "environment", "stdin",
        "timeout_ms", "shell", "network",
    }
    findings = _action_invocation_closed_findings(invocation, path, keys)
    if not isinstance(invocation, dict):
        return None, findings

    fixed = {
        "schema": _ACTION_INVOCATION_SCHEMA,
        "protocol": _LOCAL_PROCESS_PROTOCOL,
        "authority": _LOCAL_PROCESS_AUTHORITY,
        "operation": "process",
        "foreign_component": _ACTION_COMPONENT,
        "shell": "denied",
        "network": "denied",
    }
    for key, value in fixed.items():
        if invocation.get(key) != value:
            findings.append({"path": path + "." + key, "code": "invocation-class-mismatch", "message": key + " violates the fixed local process invocation class"})

    adapter = invocation.get("adapter")
    adapter_keys = {"schema", "executable_uri", "artifact_sha256", "entrypoint"}
    findings.extend(_action_invocation_closed_findings(adapter, path + ".adapter", adapter_keys))
    normalized_adapter = None
    if isinstance(adapter, dict):
        executable_uri, uri_findings = _action_invocation_file_uri(
            adapter.get("executable_uri"), path + ".adapter.executable_uri"
        )
        findings.extend(uri_findings)
        if adapter.get("schema") != _ACTION_INVOCATION_ADAPTER_SCHEMA:
            findings.append({"path": path + ".adapter.schema", "code": "unsupported-schema", "message": "expected loom-host-adapter-identity/v0"})
        if not _binding_is_sha256(adapter.get("artifact_sha256")):
            findings.append({"path": path + ".adapter.artifact_sha256", "code": "expected-sha256", "message": "artifact_sha256 must be lowercase SHA-256 hex"})
        if adapter.get("entrypoint") != "process":
            findings.append({"path": path + ".adapter.entrypoint", "code": "entrypoint-mismatch", "message": "host adapter entrypoint must be process"})
        normalized_adapter = {
            "schema": adapter.get("schema"),
            "executable_uri": executable_uri,
            "artifact_sha256": adapter.get("artifact_sha256"),
            "entrypoint": adapter.get("entrypoint"),
        }

    argv = invocation.get("argv")
    normalized_argv = []
    if not isinstance(argv, list):
        findings.append({"path": path + ".argv", "code": "expected-array", "message": "argv must be an array"})
    else:
        if len(argv) > _BINDING_MAX_ITEMS:
            findings.append({"path": path + ".argv", "code": "too-many-items", "message": "argv exceeds 256 items"})
        for index, item in enumerate(argv):
            normalized, item_findings = _action_invocation_string(item, f"{path}.argv[{index}]")
            normalized_argv.append(normalized)
            findings.extend(item_findings)

    working_directory_uri, cwd_findings = _action_invocation_file_uri(
        invocation.get("working_directory_uri"), path + ".working_directory_uri"
    )
    findings.extend(cwd_findings)

    environment = invocation.get("environment")
    normalized_environment = []
    environment_names = []
    if not isinstance(environment, list):
        findings.append({"path": path + ".environment", "code": "expected-array", "message": "environment must be an array"})
    else:
        if len(environment) > _BINDING_MAX_ITEMS:
            findings.append({"path": path + ".environment", "code": "too-many-items", "message": "environment exceeds 256 entries"})
        for index, item in enumerate(environment):
            item_path = f"{path}.environment[{index}]"
            item_keys = {"name", "value_sha256"}
            findings.extend(_action_invocation_closed_findings(item, item_path, item_keys))
            if not isinstance(item, dict):
                continue
            name, name_findings = _action_invocation_string(item.get("name"), item_path + ".name")
            findings.extend(name_findings)
            if isinstance(name, str) and ("=" in name or "\x00" in name):
                findings.append({"path": item_path + ".name", "code": "invalid-environment-name", "message": "environment name must not contain '=' or NUL"})
            if not _binding_is_sha256(item.get("value_sha256")):
                findings.append({"path": item_path + ".value_sha256", "code": "expected-sha256", "message": "environment value_sha256 must be lowercase SHA-256 hex"})
            normalized_environment.append({"name": name, "value_sha256": item.get("value_sha256")})
            if isinstance(name, str):
                environment_names.append(name)
        for name in sorted({name for name in environment_names if environment_names.count(name) > 1}):
            findings.append({"path": path + ".environment", "code": "duplicate-environment-name", "message": "duplicate environment name '" + name + "'"})
        normalized_environment.sort(key=lambda item: item.get("name") or "")

    stdin = invocation.get("stdin")
    stdin_keys = {"schema", "encoding", "payload_sha256"}
    findings.extend(_action_invocation_closed_findings(stdin, path + ".stdin", stdin_keys))
    normalized_stdin = None
    expected_input_sha256 = None
    try:
        expected_input_sha256 = capsule["action_semantics"]["tool_binding"]["input_sha256"]
    except (KeyError, TypeError):
        pass
    if isinstance(stdin, dict):
        if stdin.get("schema") != _ACTION_INVOCATION_STDIN_SCHEMA:
            findings.append({"path": path + ".stdin.schema", "code": "unsupported-schema", "message": "expected loom-action-invocation-stdin/v0"})
        if stdin.get("encoding") != "canonical-json/utf-8":
            findings.append({"path": path + ".stdin.encoding", "code": "encoding-mismatch", "message": "stdin must carry canonical JSON UTF-8"})
        if not _binding_is_sha256(stdin.get("payload_sha256")):
            findings.append({"path": path + ".stdin.payload_sha256", "code": "expected-sha256", "message": "payload_sha256 must be lowercase SHA-256 hex"})
        elif stdin.get("payload_sha256") != expected_input_sha256:
            findings.append({"path": path + ".stdin.payload_sha256", "code": "tool-input-mismatch", "message": "stdin payload must be the exact Tool Binding input"})
        normalized_stdin = {
            "schema": stdin.get("schema"),
            "encoding": stdin.get("encoding"),
            "payload_sha256": stdin.get("payload_sha256"),
        }

    timeout_ms = invocation.get("timeout_ms")
    if type(timeout_ms) is not int:
        findings.append({"path": path + ".timeout_ms", "code": "expected-integer", "message": "timeout_ms must be an integer"})
    elif not 1 <= timeout_ms <= 3600000:
        findings.append({"path": path + ".timeout_ms", "code": "timeout-out-of-range", "message": "timeout_ms must be between 1 and 3600000"})

    if findings:
        return None, findings
    normalized = {
        **fixed,
        "adapter": normalized_adapter,
        "argv": normalized_argv,
        "working_directory_uri": working_directory_uri,
        "environment": normalized_environment,
        "stdin": normalized_stdin,
        "timeout_ms": timeout_ms,
    }
    return normalized, []


def _action_invocation_binding_structure_findings(binding):
    outer_keys = {
        "schema", "advisory", "capsule", "capsule_sha256", "invocation",
        "invocation_sha256", "cross_links", "lifecycle", "binding_sha256",
    }
    findings = _action_invocation_closed_findings(binding, "binding", outer_keys)
    if not isinstance(binding, dict):
        return findings
    if binding.get("schema") != _ACTION_INVOCATION_BINDING_SCHEMA:
        findings.append({"path": "binding.schema", "code": "unsupported-schema", "message": "expected loom-action-invocation-binding/v0"})
    if binding.get("advisory") is not True:
        findings.append({"path": "binding.advisory", "code": "invalid-advisory", "message": "Invocation Binding must remain advisory"})
    for key in ("capsule_sha256", "invocation_sha256", "binding_sha256"):
        if not _binding_is_sha256(binding.get(key)):
            findings.append({"path": "binding." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})

    capsule = binding.get("capsule")
    capsule_findings = _action_capsule_structure_findings(capsule)
    findings.extend(_action_capsule_prefixed("binding.capsule", [
        {**item, "path": item["path"][len("capsule."):] if item.get("path", "").startswith("capsule.") else ""}
        for item in capsule_findings
    ]))
    if isinstance(capsule, dict) and binding.get("capsule_sha256") != capsule.get("capsule_sha256"):
        findings.append({"path": "binding.capsule_sha256", "code": "capsule-hash-mismatch", "message": "Invocation Binding does not reference its embedded Capsule"})

    invocation = binding.get("invocation")
    invocation_keys = {
        "schema", "protocol", "authority", "operation", "foreign_component",
        "adapter", "argv", "working_directory_uri", "environment", "stdin",
        "timeout_ms", "shell", "network", "invocation_sha256",
    }
    findings.extend(_action_invocation_closed_findings(invocation, "binding.invocation", invocation_keys))
    normalized_invocation = None
    if isinstance(invocation, dict):
        unsigned_invocation = {key: value for key, value in invocation.items() if key != "invocation_sha256"}
        normalized_invocation, invocation_findings = _normalize_action_invocation(
            unsigned_invocation, capsule, "binding.invocation"
        )
        findings.extend(invocation_findings)
        if normalized_invocation is not None and unsigned_invocation != normalized_invocation:
            findings.append({"path": "binding.invocation", "code": "non-canonical-invocation", "message": "embedded invocation must already be normalized"})
        if normalized_invocation is not None:
            expected_invocation_sha256 = _binding_sha256(normalized_invocation)
            if invocation.get("invocation_sha256") != expected_invocation_sha256:
                findings.append({"path": "binding.invocation.invocation_sha256", "code": "invocation-hash-mismatch", "message": "invocation_sha256 does not match the exact invocation"})
            if binding.get("invocation_sha256") != invocation.get("invocation_sha256"):
                findings.append({"path": "binding.invocation_sha256", "code": "invocation-hash-mismatch", "message": "Invocation Binding does not reference its embedded invocation"})

    links = binding.get("cross_links")
    link_keys = {"schema", "capsule_sha256", "tool_binding_sha256", "input_sha256", "adapter_artifact_sha256"}
    findings.extend(_action_invocation_closed_findings(links, "binding.cross_links", link_keys))
    if isinstance(links, dict):
        capsule_bindings = capsule.get("bindings") if isinstance(capsule, dict) else None
        capsule_semantics = capsule.get("action_semantics") if isinstance(capsule, dict) else None
        capsule_tool = capsule_semantics.get("tool_binding") if isinstance(capsule_semantics, dict) else None
        invocation_adapter = invocation.get("adapter") if isinstance(invocation, dict) else None
        expected_links = {
            "schema": _ACTION_INVOCATION_LINKS_SCHEMA,
            "capsule_sha256": binding.get("capsule_sha256"),
            "tool_binding_sha256": capsule_bindings.get("tool_binding_sha256") if isinstance(capsule_bindings, dict) else None,
            "input_sha256": capsule_tool.get("input_sha256") if isinstance(capsule_tool, dict) else None,
            "adapter_artifact_sha256": invocation_adapter.get("artifact_sha256") if isinstance(invocation_adapter, dict) else None,
        }
        for key in link_keys - {"schema"}:
            if not _binding_is_sha256(links.get(key)):
                findings.append({"path": "binding.cross_links." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
        if links != expected_links:
            findings.append({"path": "binding.cross_links", "code": "cross-link-mismatch", "message": "Invocation Binding cross-links do not match Capsule, Tool Input, or adapter"})

    lifecycle = binding.get("lifecycle")
    lifecycle_keys = {"schema", "authorization", "approval_eligible", "approval_subject", "required_next"}
    findings.extend(_action_invocation_closed_findings(lifecycle, "binding.lifecycle", lifecycle_keys))
    expected_lifecycle = {
        "schema": _ACTION_INVOCATION_LIFECYCLE_SCHEMA,
        "authorization": "none",
        "approval_eligible": True,
        "approval_subject": "binding_sha256",
        "required_next": list(_ACTION_INVOCATION_REQUIRED_NEXT),
    }
    if isinstance(lifecycle, dict) and lifecycle != expected_lifecycle:
        findings.append({"path": "binding.lifecycle", "code": "lifecycle-mismatch", "message": "Invocation Binding lifecycle must remain non-authorizing and approval-bound"})

    if set(binding) >= outer_keys:
        body = {key: binding[key] for key in outer_keys if key != "binding_sha256"}
        try:
            digest = _binding_sha256(body)
        except (TypeError, ValueError):
            findings.append({"path": "binding", "code": "non-canonical-binding", "message": "Invocation Binding fields must be canonical JSON values"})
        else:
            if binding.get("binding_sha256") != digest:
                findings.append({"path": "binding.binding_sha256", "code": "binding-hash-mismatch", "message": "binding_sha256 does not match the canonical Invocation Binding"})
    return findings


def build_action_invocation_binding_v0(
    manifest, tool_binding, tool_input, program_src, wasm_bytes,
    builder_components, entrypoint, invocation,
):
    """Bind one exact host invocation to a rebuilt Action Capsule without authorizing it."""
    capsule_result = build_action_capsule_v0(
        manifest, tool_binding, tool_input, program_src, wasm_bytes,
        builder_components, entrypoint,
    )
    attribution = capsule_result["compiler_attribution"]
    if not capsule_result["valid"]:
        return _action_invocation_binding_validation(
            None, attribution,
            _action_capsule_prefixed("capsule", capsule_result["findings"]),
        )
    capsule = capsule_result["capsule"]
    normalized_invocation, findings = _normalize_action_invocation(invocation, capsule)
    if findings:
        return _action_invocation_binding_validation(None, attribution, findings)
    normalized_invocation["invocation_sha256"] = _binding_sha256(normalized_invocation)
    body = {
        "schema": _ACTION_INVOCATION_BINDING_SCHEMA,
        "advisory": True,
        "capsule": capsule,
        "capsule_sha256": capsule["capsule_sha256"],
        "invocation": normalized_invocation,
        "invocation_sha256": normalized_invocation["invocation_sha256"],
        "cross_links": {
            "schema": _ACTION_INVOCATION_LINKS_SCHEMA,
            "capsule_sha256": capsule["capsule_sha256"],
            "tool_binding_sha256": capsule["bindings"]["tool_binding_sha256"],
            "input_sha256": capsule["action_semantics"]["tool_binding"]["input_sha256"],
            "adapter_artifact_sha256": normalized_invocation["adapter"]["artifact_sha256"],
        },
        "lifecycle": {
            "schema": _ACTION_INVOCATION_LIFECYCLE_SCHEMA,
            "authorization": "none",
            "approval_eligible": True,
            "approval_subject": "binding_sha256",
            "required_next": list(_ACTION_INVOCATION_REQUIRED_NEXT),
        },
    }
    body["binding_sha256"] = _binding_sha256(body)
    return _action_invocation_binding_validation(body, attribution, [])


def verify_action_invocation_binding_v0(
    binding, manifest, tool_binding, tool_input, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components, entrypoint,
    invocation,
):
    """Verify exact Capsule and host invocation identity without performing host IO."""
    attribution = _action_semantics_attribution()
    findings = _action_invocation_binding_structure_findings(binding)
    if findings:
        return _action_invocation_binding_validation(None, attribution, findings)
    capsule_check = verify_action_capsule_v0(
        binding["capsule"], manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint,
    )
    attribution = capsule_check["compiler_attribution"]
    if not capsule_check["valid"]:
        return _action_invocation_binding_validation(
            None, attribution,
            _action_capsule_prefixed("capsule", capsule_check["findings"]),
        )
    expected = build_action_invocation_binding_v0(
        manifest, tool_binding, tool_input, program_src, wasm_bytes,
        builder_components, entrypoint, invocation,
    )
    if not expected["valid"]:
        return _action_invocation_binding_validation(None, attribution, expected["findings"])
    if binding != expected["binding"]:
        return _action_invocation_binding_validation(None, attribution, [{
            "path": "binding",
            "code": "action-invocation-binding-mismatch",
            "message": "Invocation Binding does not match the exact Capsule, adapter, argv, cwd, environment, stdin, or timeout inputs",
        }])
    return _action_invocation_binding_validation(binding, attribution, [])


def _action_approval_request_validation(request, findings):
    return {
        "schema": _ACTION_APPROVAL_REQUEST_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "none",
        "request": request if not findings else None,
        "findings": findings,
    }


def _action_approval_validation(approval, approval_sha256, findings):
    return {
        "schema": _ACTION_APPROVAL_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "claim-required" if not findings else "none",
        "approval": approval if not findings else None,
        "approval_sha256": approval_sha256 if not findings else None,
        "findings": findings,
    }


def _action_claim_validation(claim, findings):
    return {
        "schema": _ACTION_CLAIM_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "authorization": "host-mediation-required" if not findings else "none",
        "claim": claim if not findings else None,
        "findings": findings,
    }


def _action_mediation_validation(mediation, findings):
    return {
        "schema": _ACTION_MEDIATION_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "authorization": "bounded-execution-required" if not findings else "none",
        "mediation": mediation if not findings else None,
        "findings": findings,
    }


def _action_execution_validation(execution, findings):
    return {
        "schema": _ACTION_EXECUTION_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "authorization": "terminal-result-required" if not findings else "none",
        "execution": execution if execution is not None else None,
        "findings": findings,
    }


def _action_execution_structure_findings(execution):
    outer_keys = {
        "schema", "mediation_sha256", "claim_sha256", "binding_sha256",
        "host_remeasurement", "host_remeasurement_sha256", "sandbox",
        "sandbox_sha256", "attempt", "attempt_sha256", "executed_at_unix_ms",
        "approval_expires_at_unix_ms", "status", "execution_sha256",
    }
    findings = _action_invocation_closed_findings(execution, "execution", outer_keys)
    if not isinstance(execution, dict):
        return findings
    if execution.get("schema") != _ACTION_EXECUTION_SCHEMA:
        findings.append({"path": "execution.schema", "code": "schema-mismatch", "message": "unsupported Bounded Execution schema"})
    for key in (
        "mediation_sha256", "claim_sha256", "binding_sha256",
        "host_remeasurement_sha256", "sandbox_sha256", "attempt_sha256",
        "execution_sha256",
    ):
        if not _binding_is_sha256(execution.get(key)):
            findings.append({"path": "execution." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})

    remeasurement = execution.get("host_remeasurement")
    remeasurement_keys = {
        "schema", "source_host_measurement_sha256", "executable_sha256",
        "executable_identity", "launch_identity", "path_custody",
        "working_directory_identity", "environment_sha256", "stdin_sha256",
        "stdin_size_bytes", "spawn_boundary", "host_remeasurement_sha256",
    }
    findings.extend(_action_invocation_closed_findings(
        remeasurement, "execution.host_remeasurement", remeasurement_keys,
    ))
    if isinstance(remeasurement, dict):
        if remeasurement.get("schema") != _ACTION_EXECUTION_REMEASUREMENT_SCHEMA:
            findings.append({"path": "execution.host_remeasurement.schema", "code": "schema-mismatch", "message": "unsupported host remeasurement schema"})
        for key in (
            "source_host_measurement_sha256", "executable_sha256", "environment_sha256",
            "stdin_sha256", "host_remeasurement_sha256",
        ):
            if not _binding_is_sha256(remeasurement.get(key)):
                findings.append({"path": "execution.host_remeasurement." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
        findings.extend(_action_mediation_identity_findings(
            remeasurement.get("executable_identity"),
            "execution.host_remeasurement.executable_identity", "regular-file",
        ))
        findings.extend(_action_mediation_identity_findings(
            remeasurement.get("launch_identity"),
            "execution.host_remeasurement.launch_identity", "regular-file",
        ))
        findings.extend(_action_mediation_identity_findings(
            remeasurement.get("working_directory_identity"),
            "execution.host_remeasurement.working_directory_identity", "directory",
        ))
        stdin_size = remeasurement.get("stdin_size_bytes")
        if type(stdin_size) is not int or stdin_size < 0:
            findings.append({"path": "execution.host_remeasurement.stdin_size_bytes", "code": "expected-size", "message": "stdin_size_bytes must be a non-negative integer"})
        boundary = remeasurement.get("spawn_boundary")
        custody = remeasurement.get("path_custody")
        if boundary not in {"private-executable-snapshot", "root-owned-immutable-path"}:
            findings.append({"path": "execution.host_remeasurement.spawn_boundary", "code": "unsupported-spawn-boundary", "message": "spawn boundary is not supported by Bounded Execution v0"})
        if not isinstance(custody, list) or len(custody) > 256:
            findings.append({"path": "execution.host_remeasurement.path_custody", "code": "invalid-path-custody", "message": "path_custody must be a bounded list"})
        else:
            for index, item in enumerate(custody):
                item_path = "execution.host_remeasurement.path_custody[" + str(index) + "]"
                findings.extend(_action_invocation_closed_findings(item, item_path, {"component_index", "identity"}))
                if not isinstance(item, dict):
                    continue
                if item.get("component_index") != index:
                    findings.append({"path": item_path + ".component_index", "code": "path-custody-order", "message": "path custody components must be contiguous and ordered"})
                expected_kind = "regular-file" if index == len(custody) - 1 else "directory"
                identity = item.get("identity")
                findings.extend(_action_mediation_identity_findings(identity, item_path + ".identity", expected_kind))
                if isinstance(identity, dict):
                    if identity.get("owner_uid") != "0":
                        findings.append({"path": item_path + ".identity.owner_uid", "code": "path-custody-owner", "message": "immutable path custody must remain root-owned"})
                    mode = identity.get("mode")
                    if isinstance(mode, str) and len(mode) == 4 and all(char in "01234567" for char in mode) and int(mode, 8) & 0o022:
                        findings.append({"path": item_path + ".identity.mode", "code": "path-custody-writable", "message": "immutable path custody must not be group/world-writable"})
            if boundary == "private-executable-snapshot" and custody:
                findings.append({"path": "execution.host_remeasurement.path_custody", "code": "unexpected-path-custody", "message": "private snapshots must not claim root path custody"})
            if boundary == "root-owned-immutable-path":
                if not custody:
                    findings.append({"path": "execution.host_remeasurement.path_custody", "code": "missing-path-custody", "message": "immutable path execution requires complete root path custody"})
                elif isinstance(custody[-1], dict) and remeasurement.get("launch_identity") != custody[-1].get("identity"):
                    findings.append({"path": "execution.host_remeasurement.launch_identity", "code": "launch-custody-mismatch", "message": "launch identity must be the final immutable path component"})
                if remeasurement.get("launch_identity") != remeasurement.get("executable_identity"):
                    findings.append({"path": "execution.host_remeasurement.launch_identity", "code": "launch-identity-mismatch", "message": "immutable path launch must preserve the mediated executable identity"})
        try:
            expected_remeasurement_hash = _binding_sha256({
                key: remeasurement[key] for key in remeasurement_keys if key != "host_remeasurement_sha256"
            }) if set(remeasurement) >= remeasurement_keys else None
        except (TypeError, ValueError):
            expected_remeasurement_hash = None
            findings.append({"path": "execution.host_remeasurement", "code": "non-canonical-remeasurement", "message": "host remeasurement must contain canonical JSON values"})
        if expected_remeasurement_hash is not None and remeasurement.get("host_remeasurement_sha256") != expected_remeasurement_hash:
            findings.append({"path": "execution.host_remeasurement.host_remeasurement_sha256", "code": "remeasurement-hash-mismatch", "message": "host_remeasurement_sha256 does not match the canonical remeasurement"})

    sandbox = execution.get("sandbox")
    sandbox_keys = {"schema", "profile", "policy_sha256", "provider_sha256", "provider_identity", "network", "sandbox_sha256"}
    findings.extend(_action_invocation_closed_findings(sandbox, "execution.sandbox", sandbox_keys))
    if isinstance(sandbox, dict):
        if sandbox.get("schema") != _ACTION_EXECUTION_SANDBOX_SCHEMA:
            findings.append({"path": "execution.sandbox.schema", "code": "schema-mismatch", "message": "unsupported network sandbox schema"})
        if sandbox.get("profile") not in {"darwin-seatbelt-network-deny/v0", "linux-user-network-namespace/v0"}:
            findings.append({"path": "execution.sandbox.profile", "code": "unsupported-sandbox-profile", "message": "network sandbox profile is not supported"})
        if sandbox.get("network") != "denied":
            findings.append({"path": "execution.sandbox.network", "code": "network-not-denied", "message": "sandbox evidence must deny network access"})
        if not _binding_is_sha256(sandbox.get("provider_sha256")):
            findings.append({"path": "execution.sandbox.provider_sha256", "code": "expected-sha256", "message": "provider_sha256 must be lowercase SHA-256 hex"})
        expected_policy = {
            "darwin-seatbelt-network-deny/v0": ["-p", _ACTION_EXECUTION_DARWIN_PROFILE],
            "linux-user-network-namespace/v0": ["--user", "--map-root-user", "--net", "--"],
        }.get(sandbox.get("profile"))
        if expected_policy is not None and sandbox.get("policy_sha256") != _binding_sha256({
            "profile": sandbox["profile"], "arguments": expected_policy,
        }):
            findings.append({"path": "execution.sandbox.policy_sha256", "code": "sandbox-policy-mismatch", "message": "sandbox policy hash does not bind the fixed v0 profile arguments"})
        elif not _binding_is_sha256(sandbox.get("policy_sha256")):
            findings.append({"path": "execution.sandbox.policy_sha256", "code": "expected-sha256", "message": "policy_sha256 must be lowercase SHA-256 hex"})
        identity = sandbox.get("provider_identity")
        findings.extend(_action_mediation_identity_findings(identity, "execution.sandbox.provider_identity", "regular-file"))
        if isinstance(identity, dict) and identity.get("owner_uid") != "0":
            findings.append({"path": "execution.sandbox.provider_identity.owner_uid", "code": "sandbox-provider-owner", "message": "sandbox provider must be root-owned"})
        try:
            expected_sandbox_hash = _binding_sha256({key: sandbox[key] for key in sandbox_keys if key != "sandbox_sha256"}) if set(sandbox) >= sandbox_keys else None
        except (TypeError, ValueError):
            expected_sandbox_hash = None
            findings.append({"path": "execution.sandbox", "code": "non-canonical-sandbox", "message": "sandbox evidence must contain canonical JSON values"})
        if expected_sandbox_hash is not None and sandbox.get("sandbox_sha256") != expected_sandbox_hash:
            findings.append({"path": "execution.sandbox.sandbox_sha256", "code": "sandbox-hash-mismatch", "message": "sandbox_sha256 does not match the canonical sandbox evidence"})

    attempt = execution.get("attempt")
    attempt_keys = {
        "schema", "result", "mediation_sha256", "host_remeasurement_sha256",
        "sandbox_sha256", "timeout_ms", "output_limit_bytes", "duration_ms",
        "exit_code", "terminating_signal", "stdout", "stderr", "stdin_sha256",
        "shell", "network", "attempt_sha256",
    }
    findings.extend(_action_invocation_closed_findings(attempt, "execution.attempt", attempt_keys))
    if isinstance(attempt, dict):
        if attempt.get("schema") != _ACTION_EXECUTION_ATTEMPT_SCHEMA:
            findings.append({"path": "execution.attempt.schema", "code": "schema-mismatch", "message": "unsupported process attempt schema"})
        if attempt.get("result") not in _ACTION_EXECUTION_RESULTS:
            findings.append({"path": "execution.attempt.result", "code": "invalid-execution-result", "message": "attempt result is not terminal"})
        for key in ("mediation_sha256", "host_remeasurement_sha256", "sandbox_sha256", "stdin_sha256", "attempt_sha256"):
            if not _binding_is_sha256(attempt.get(key)):
                findings.append({"path": "execution.attempt." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
        if type(attempt.get("timeout_ms")) is not int or attempt.get("timeout_ms", 0) <= 0:
            findings.append({"path": "execution.attempt.timeout_ms", "code": "invalid-timeout", "message": "timeout_ms must be a positive integer"})
        if attempt.get("output_limit_bytes") != _ACTION_EXECUTION_MAX_OUTPUT_BYTES:
            findings.append({"path": "execution.attempt.output_limit_bytes", "code": "output-limit-mismatch", "message": "output limit must match the Bounded Execution v0 constant"})
        if type(attempt.get("duration_ms")) is not int or attempt.get("duration_ms", -1) < 0:
            findings.append({"path": "execution.attempt.duration_ms", "code": "invalid-duration", "message": "duration_ms must be a non-negative integer"})
        for key in ("exit_code", "terminating_signal"):
            value = attempt.get(key)
            if value is not None and type(value) is not int:
                findings.append({"path": "execution.attempt." + key, "code": "invalid-process-status", "message": key + " must be an integer or null"})
        for name in ("stdout", "stderr"):
            stream = attempt.get(name)
            stream_path = "execution.attempt." + name
            findings.extend(_action_invocation_closed_findings(stream, stream_path, {"sha256", "size_bytes"}))
            if isinstance(stream, dict):
                if not _binding_is_sha256(stream.get("sha256")):
                    findings.append({"path": stream_path + ".sha256", "code": "expected-sha256", "message": name + " sha256 must be lowercase SHA-256 hex"})
                if type(stream.get("size_bytes")) is not int or stream.get("size_bytes", -1) < 0:
                    findings.append({"path": stream_path + ".size_bytes", "code": "expected-size", "message": name + " size must be a non-negative integer"})
                if stream.get("size_bytes", 0) > _ACTION_EXECUTION_MAX_OUTPUT_BYTES and attempt.get("result") != "output-limit-exceeded":
                    findings.append({"path": stream_path + ".size_bytes", "code": "unaccounted-output-overflow", "message": "oversized output requires output-limit-exceeded result"})
        if attempt.get("shell") != "denied" or attempt.get("network") != "denied":
            findings.append({"path": "execution.attempt", "code": "execution-control-mismatch", "message": "attempt must record shell and network as denied"})
        if attempt.get("result") == "completed" and (attempt.get("exit_code") != 0 or attempt.get("terminating_signal") is not None):
            findings.append({"path": "execution.attempt", "code": "completed-status-mismatch", "message": "completed attempts require exit code zero and no signal"})
        if attempt.get("result") == "spawn-failed" and (attempt.get("exit_code") is not None or attempt.get("terminating_signal") is not None):
            findings.append({"path": "execution.attempt", "code": "spawn-status-mismatch", "message": "spawn-failed attempts cannot contain child process status"})
        try:
            expected_attempt_hash = _binding_sha256({key: attempt[key] for key in attempt_keys if key != "attempt_sha256"}) if set(attempt) >= attempt_keys else None
        except (TypeError, ValueError):
            expected_attempt_hash = None
            findings.append({"path": "execution.attempt", "code": "non-canonical-attempt", "message": "process attempt must contain canonical JSON values"})
        if expected_attempt_hash is not None and attempt.get("attempt_sha256") != expected_attempt_hash:
            findings.append({"path": "execution.attempt.attempt_sha256", "code": "attempt-hash-mismatch", "message": "attempt_sha256 does not match the canonical process attempt"})

    if isinstance(remeasurement, dict) and execution.get("host_remeasurement_sha256") != remeasurement.get("host_remeasurement_sha256"):
        findings.append({"path": "execution.host_remeasurement_sha256", "code": "remeasurement-link-mismatch", "message": "outer remeasurement hash does not match nested evidence"})
    if isinstance(sandbox, dict) and execution.get("sandbox_sha256") != sandbox.get("sandbox_sha256"):
        findings.append({"path": "execution.sandbox_sha256", "code": "sandbox-link-mismatch", "message": "outer sandbox hash does not match nested evidence"})
    if isinstance(attempt, dict):
        links = {
            "mediation_sha256": execution.get("mediation_sha256"),
            "host_remeasurement_sha256": execution.get("host_remeasurement_sha256"),
            "sandbox_sha256": execution.get("sandbox_sha256"),
        }
        for key, expected in links.items():
            if attempt.get(key) != expected:
                findings.append({"path": "execution.attempt." + key, "code": "attempt-link-mismatch", "message": key + " does not match outer execution evidence"})
        if execution.get("attempt_sha256") != attempt.get("attempt_sha256"):
            findings.append({"path": "execution.attempt_sha256", "code": "attempt-link-mismatch", "message": "outer attempt hash does not match nested evidence"})
        if execution.get("status") != attempt.get("result"):
            findings.append({"path": "execution.status", "code": "execution-status-mismatch", "message": "execution status must match the terminal process result"})
        if isinstance(remeasurement, dict) and attempt.get("stdin_sha256") != remeasurement.get("stdin_sha256"):
            findings.append({"path": "execution.attempt.stdin_sha256", "code": "stdin-link-mismatch", "message": "attempt stdin does not match host remeasurement"})
    executed = execution.get("executed_at_unix_ms")
    expires = execution.get("approval_expires_at_unix_ms")
    if type(executed) is not int or executed < 0:
        findings.append({"path": "execution.executed_at_unix_ms", "code": "invalid-time", "message": "execution time must be a non-negative integer"})
    if type(expires) is not int or type(executed) is not int or expires <= executed:
        findings.append({"path": "execution.approval_expires_at_unix_ms", "code": "invalid-expiry", "message": "approval expiry must be later than execution time"})
    try:
        expected_execution_hash = _binding_sha256({key: execution[key] for key in outer_keys if key != "execution_sha256"}) if set(execution) >= outer_keys else None
    except (TypeError, ValueError):
        expected_execution_hash = None
        findings.append({"path": "execution", "code": "non-canonical-execution", "message": "Bounded Execution must contain canonical JSON values"})
    if expected_execution_hash is not None and execution.get("execution_sha256") != expected_execution_hash:
        findings.append({"path": "execution.execution_sha256", "code": "execution-hash-mismatch", "message": "execution_sha256 does not match the canonical Bounded Execution"})
    return findings


def validate_action_bounded_execution_v0(execution):
    """Validate a closed Bounded Execution artifact without performing host IO."""
    findings = _action_execution_structure_findings(execution)
    return _action_execution_validation(execution, findings)


def _action_approval_prefixed(path, findings):
    return [{
        "path": path + ("." + item["path"] if item.get("path") else ""),
        "code": item["code"],
        "message": item["message"],
    } for item in findings]


def _action_approval_review(binding):
    capsule = binding["capsule"]
    invocation = binding["invocation"]
    return {
        "schema": _ACTION_APPROVAL_REVIEW_SCHEMA,
        "agent": capsule["manifest"]["agent"],
        "task": capsule["manifest"]["task"],
        "adapter": invocation["adapter"],
        "argv": invocation["argv"],
        "working_directory_uri": invocation["working_directory_uri"],
        "environment": invocation["environment"],
        "stdin": invocation["stdin"],
        "timeout_ms": invocation["timeout_ms"],
        "shell": invocation["shell"],
        "network": invocation["network"],
    }


def _action_approval_challenge(binding, nonce):
    findings = _action_invocation_binding_structure_findings(binding)
    if not _binding_is_sha256(nonce):
        findings.append({
            "path": "nonce", "code": "invalid-nonce",
            "message": "nonce must be 64 lowercase hexadecimal characters",
        })
    if findings:
        return None, findings
    body = {
        "schema": _ACTION_APPROVAL_CHALLENGE_SCHEMA,
        "binding_sha256": binding["binding_sha256"],
        "capsule_sha256": binding["capsule_sha256"],
        "invocation_sha256": binding["invocation_sha256"],
        "nonce": nonce,
    }
    body["challenge_sha256"] = _binding_sha256(body)
    return body, []


def build_action_approval_request_v2(binding, nonce):
    """Build the closed human-review envelope for one exact Invocation Binding."""
    challenge, findings = _action_approval_challenge(binding, nonce)
    if findings:
        return _action_approval_request_validation(None, findings)
    body = {
        "schema": _ACTION_APPROVAL_REQUEST_SCHEMA,
        "binding": binding,
        "challenge": challenge,
        "review": _action_approval_review(binding),
        "lifecycle": {
            "schema": _ACTION_APPROVAL_REQUEST_LIFECYCLE_SCHEMA,
            "authorization": "none",
            "approval_subject": "binding_sha256",
            "approval_schema": _ACTION_APPROVAL_SCHEMA,
            "claim_required": True,
            "maximum_ttl_ms": _ACTION_APPROVAL_MAX_TTL_MS,
        },
    }
    body["request_sha256"] = _binding_sha256(body)
    return _action_approval_request_validation(body, [])


def validate_action_approval_request_v2(request):
    """Rebuild an Action Approval request before an issuer displays or signs it."""
    if not isinstance(request, dict):
        return _action_approval_request_validation(None, [{
            "path": "request", "code": "expected-object",
            "message": "Action Approval request must be an object",
        }])
    required = {"schema", "binding", "challenge", "review", "lifecycle", "request_sha256"}
    findings = []
    for key in sorted(set(request) - required, key=str):
        findings.append({"path": "request." + str(key), "code": "unknown-field", "message": "unknown Action Approval request field"})
    for key in sorted(required - set(request)):
        findings.append({"path": "request." + key, "code": "missing-field", "message": "missing Action Approval request field"})
    if findings:
        return _action_approval_request_validation(None, findings)
    challenge = request.get("challenge")
    nonce = challenge.get("nonce") if isinstance(challenge, dict) else None
    rebuilt = build_action_approval_request_v2(request.get("binding"), nonce)
    if not rebuilt["valid"]:
        return rebuilt
    if request != rebuilt["request"]:
        return _action_approval_request_validation(None, [{
            "path": "request", "code": "request-mismatch",
            "message": "Action Approval request does not match its exact binding, challenge, review, lifecycle, and hash",
        }])
    return rebuilt


def _action_approval_validate_public_key(value):
    if "_loom_approval" in globals():
        return _loom_approval._validate_public_key(value)
    return _gate_validate_public_key(value)


def _action_approval_rsa_verify(message, signature, public_key):
    if "_loom_approval" in globals():
        return _loom_approval._rsa_verify(message, signature, public_key)
    return _gate_rsa_verify(message, signature, public_key)


def _action_approval_canonical(value):
    if "_loom_approval" in globals():
        return _loom_approval._canonical(value)
    return _gate_canonical(value)


def _action_approval_load_public_key():
    if "_loom_approval" in globals():
        return _loom_approval._load_public_key()
    return _gate_load_operator_key()


def _verify_action_capsule_approval_v2(
    approval, request, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, now_unix_ms, public_key_value,
):
    request_check = validate_action_approval_request_v2(request)
    findings = list(request_check["findings"])
    if request_check["valid"]:
        binding_check = verify_action_invocation_binding_v0(
            request["binding"], manifest, tool_binding, tool_input, program_src,
            wasm_bytes, builder_surface, builder_components,
            verifier_components, entrypoint, invocation,
        )
        findings.extend(_action_approval_prefixed("request.binding", binding_check["findings"]))
    public_key, key_findings = _action_approval_validate_public_key(public_key_value)
    findings.extend(key_findings)
    if type(now_unix_ms) is not int or now_unix_ms < 0:
        findings.append({
            "path": "now_unix_ms", "code": "invalid-verification-time",
            "message": "verification time must be a non-negative integer Unix millisecond value",
        })
    if not isinstance(approval, dict):
        findings.append({"path": "approval", "code": "expected-object", "message": "Action Approval must be an object"})
        return _action_approval_validation(None, None, findings)
    required = {
        "schema", "request_sha256", "challenge_sha256", "binding_sha256",
        "capsule_sha256", "invocation_sha256", "approval_scope", "approver",
        "decision", "issued_at_unix_ms", "expires_at_unix_ms", "claim_required",
        "key_sha256", "signature",
    }
    for key in sorted(set(approval) - required, key=str):
        findings.append({"path": "approval." + str(key), "code": "unknown-field", "message": "unknown Action Approval field"})
    for key in sorted(required - set(approval)):
        findings.append({"path": "approval." + key, "code": "missing-field", "message": "missing Action Approval field"})
    if findings:
        return _action_approval_validation(None, None, findings)
    binding = request["binding"]
    challenge = request["challenge"]
    fixed = {
        "schema": _ACTION_APPROVAL_SCHEMA,
        "request_sha256": request["request_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "capsule_sha256": binding["capsule_sha256"],
        "invocation_sha256": binding["invocation_sha256"],
        "approval_scope": _ACTION_APPROVAL_SCOPE,
        "approver": "operator",
        "decision": "approve",
        "claim_required": True,
    }
    for key, value in fixed.items():
        if approval.get(key) != value:
            findings.append({
                "path": "approval." + key, "code": "approval-binding-mismatch",
                "message": key + " does not match the exact Action Approval request",
            })
    issued = approval.get("issued_at_unix_ms")
    expires = approval.get("expires_at_unix_ms")
    if type(issued) is not int or issued < 0:
        findings.append({"path": "approval.issued_at_unix_ms", "code": "invalid-issued-time", "message": "issued_at_unix_ms must be a non-negative integer"})
    if type(expires) is not int or expires < 0:
        findings.append({"path": "approval.expires_at_unix_ms", "code": "invalid-expiry-time", "message": "expires_at_unix_ms must be a non-negative integer"})
    if type(issued) is int and type(expires) is int:
        if expires <= issued or expires - issued > _ACTION_APPROVAL_MAX_TTL_MS:
            findings.append({"path": "approval.expires_at_unix_ms", "code": "invalid-validity-window", "message": "Action Approval validity must be positive and at most 900000 milliseconds"})
        if type(now_unix_ms) is int and now_unix_ms < issued:
            findings.append({"path": "approval.issued_at_unix_ms", "code": "approval-not-yet-valid", "message": "Action Approval was issued after the trusted host verification time"})
        if type(now_unix_ms) is int and now_unix_ms >= expires:
            findings.append({"path": "approval.expires_at_unix_ms", "code": "approval-expired", "message": "Action Approval has expired"})
    if public_key is not None:
        key_sha256 = _binding_sha256(public_key)
        if approval.get("key_sha256") != key_sha256:
            findings.append({"path": "approval.key_sha256", "code": "key-mismatch", "message": "Action Approval is signed by a different key"})
        signed = {key: approval[key] for key in sorted(required - {"signature"})}
        if not _action_approval_rsa_verify(_action_approval_canonical(signed).encode("utf-8"), approval.get("signature"), public_key):
            findings.append({"path": "approval.signature", "code": "invalid-signature", "message": "Action Approval signature is invalid"})
    if findings:
        return _action_approval_validation(None, None, findings)
    approval_sha256 = _binding_sha256(approval)
    return _action_approval_validation(approval, approval_sha256, [])


def verify_action_capsule_approval_v2(
    approval, request, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, now_unix_ms,
):
    """Verify one short-lived Approval v2 against the pinned operator key."""
    try:
        public_key = _action_approval_load_public_key()
    except ValueError as error:
        return _action_approval_validation(None, None, [{
            "path": "public_key", "code": "public-key-unavailable", "message": str(error),
        }])
    return _verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, now_unix_ms, public_key,
    )


def _action_claim_ledger_path():
    if "_loom_approval" in globals():
        return _loom_approval._LEDGER_PATH
    return _GATE_LEDGER_PATH


def _action_claim_once(approval_check, request, now_unix_ms, ledger_path):
    try:
        import os
        import sqlite3
        import stat
    except ImportError as error:
        raise ValueError("Action Claim ledger is unavailable in this Python runtime: " + str(error)) from error
    approval = approval_check["approval"]
    binding = request["binding"]
    body = {
        "schema": _ACTION_CLAIM_SCHEMA,
        "approval_sha256": approval_check["approval_sha256"],
        "request_sha256": request["request_sha256"],
        "challenge_sha256": request["challenge"]["challenge_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "capsule_sha256": binding["capsule_sha256"],
        "invocation_sha256": binding["invocation_sha256"],
        "claim_scope": _ACTION_CLAIM_SCOPE,
        "claimed_at_unix_ms": now_unix_ms,
        "approval_expires_at_unix_ms": approval["expires_at_unix_ms"],
        "status": "claimed",
    }
    body["claim_sha256"] = _binding_sha256(body)
    parent = ledger_path.parent
    if parent.exists():
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("Action Claim ledger parent must be a regular non-symlink directory")
    else:
        parent.mkdir(mode=0o700, parents=True)
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid():
        raise ValueError("Action Claim ledger parent must be owned by the current user")
    parent.chmod(0o700)
    if ledger_path.exists() or ledger_path.is_symlink():
        if ledger_path.is_symlink() or not ledger_path.is_file():
            raise ValueError("Action Claim ledger must be a regular non-symlink file")
        ledger_stat = ledger_path.stat()
        if ledger_stat.st_uid != os.getuid():
            raise ValueError("Action Claim ledger must be owned by the current user")
        if ledger_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("Action Claim ledger must not be group/world-writable")
    connection = None
    try:
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
        if ledger_path.is_symlink() or not ledger_path.is_file() or ledger_path.stat().st_uid != os.getuid():
            raise ValueError("Action Claim ledger identity changed during open")
        ledger_path.chmod(0o600)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(_ACTION_CLAIM_LEDGER_CREATE)
        stored_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (_ACTION_CLAIM_LEDGER_TABLE,),
        ).fetchone()
        if stored_schema != (_ACTION_CLAIM_LEDGER_SCHEMA,):
            connection.execute("ROLLBACK")
            raise ValueError("Action Claim ledger table schema is not canonical")
        foreign_objects = connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('trigger','view') AND tbl_name=?",
            (_ACTION_CLAIM_LEDGER_TABLE,),
        ).fetchall()
        if foreign_objects:
            connection.execute("ROLLBACK")
            raise ValueError("Action Claim ledger table has unrecognized triggers or views")
        if connection.execute(
            "SELECT 1 FROM action_claims_v0 WHERE approval_sha256=?",
            (body["approval_sha256"],),
        ).fetchone():
            connection.execute("ROLLBACK")
            raise ValueError("Action Approval v2 was already claimed")
        connection.execute(
            "INSERT INTO action_claims_v0 (approval_sha256,request_sha256,challenge_sha256,binding_sha256,"
            "capsule_sha256,invocation_sha256,claimed_at_unix_ms,approval_expires_at_unix_ms,claim_sha256,status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                body["approval_sha256"], body["request_sha256"], body["challenge_sha256"],
                body["binding_sha256"], body["capsule_sha256"], body["invocation_sha256"],
                body["claimed_at_unix_ms"], body["approval_expires_at_unix_ms"],
                body["claim_sha256"], body["status"],
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Approval v2 was already claimed or the claim ledger rejected it") from error
    except sqlite3.Error as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Claim ledger failed: " + str(error)) from error
    finally:
        if connection is not None:
            connection.close()
    return body


def _claim_action_capsule_approval_v0(
    approval, request, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, now_unix_ms, public_key_value, ledger_path,
):
    approval_check = _verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, now_unix_ms, public_key_value,
    )
    if not approval_check["valid"]:
        return _action_claim_validation(None, approval_check["findings"])
    try:
        claim = _action_claim_once(approval_check, request, now_unix_ms, ledger_path)
    except (OSError, ValueError) as error:
        return _action_claim_validation(None, [{
            "path": "ledger", "code": "action-claim-failed", "message": str(error),
        }])
    return _action_claim_validation(claim, [])


def claim_action_capsule_approval_v0(
    approval, request, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, now_unix_ms,
):
    """Atomically reserve one valid Action Approval v2 for host mediation."""
    try:
        public_key = _action_approval_load_public_key()
    except ValueError as error:
        return _action_claim_validation(None, [{
            "path": "public_key", "code": "public-key-unavailable", "message": str(error),
        }])
    return _claim_action_capsule_approval_v0(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, now_unix_ms, public_key,
        _action_claim_ledger_path(),
    )


def _action_claim_findings(claim, approval_check, request, now_unix_ms):
    keys = {
        "schema", "approval_sha256", "request_sha256", "challenge_sha256",
        "binding_sha256", "capsule_sha256", "invocation_sha256", "claim_scope",
        "claimed_at_unix_ms", "approval_expires_at_unix_ms", "status", "claim_sha256",
    }
    findings = _action_invocation_closed_findings(claim, "claim", keys)
    if not isinstance(claim, dict):
        return findings
    binding = request["binding"]
    approval = approval_check["approval"]
    fixed = {
        "schema": _ACTION_CLAIM_SCHEMA,
        "approval_sha256": approval_check["approval_sha256"],
        "request_sha256": request["request_sha256"],
        "challenge_sha256": request["challenge"]["challenge_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "capsule_sha256": binding["capsule_sha256"],
        "invocation_sha256": binding["invocation_sha256"],
        "claim_scope": _ACTION_CLAIM_SCOPE,
        "approval_expires_at_unix_ms": approval["expires_at_unix_ms"],
        "status": "claimed",
    }
    for key, value in fixed.items():
        if claim.get(key) != value:
            findings.append({
                "path": "claim." + key, "code": "claim-binding-mismatch",
                "message": key + " does not match the verified Approval v2 and request",
            })
    claimed_at = claim.get("claimed_at_unix_ms")
    if type(claimed_at) is not int or claimed_at < 0:
        findings.append({
            "path": "claim.claimed_at_unix_ms", "code": "invalid-claim-time",
            "message": "claimed_at_unix_ms must be a non-negative integer",
        })
    elif claimed_at > now_unix_ms:
        findings.append({
            "path": "claim.claimed_at_unix_ms", "code": "claim-from-future",
            "message": "claim time must not be after the trusted host mediation time",
        })
    if not _binding_is_sha256(claim.get("claim_sha256")):
        findings.append({
            "path": "claim.claim_sha256", "code": "expected-sha256",
            "message": "claim_sha256 must be lowercase SHA-256 hex",
        })
    if set(claim) == keys:
        body = {key: claim[key] for key in sorted(keys - {"claim_sha256"})}
        if claim.get("claim_sha256") != _binding_sha256(body):
            findings.append({
                "path": "claim.claim_sha256", "code": "claim-hash-mismatch",
                "message": "claim_sha256 does not match the canonical Claim v0 body",
            })
    return findings


def _action_mediation_file_path(uri, path):
    if not isinstance(uri, str) or not uri.startswith("file:///"):
        raise ValueError(path + " must be an absolute file URI")
    if "%" in uri:
        raise ValueError(path + " must not use percent-encoded path bytes in mediation v0")
    value = uri[len("file://"):]
    if not value.startswith("/") or value == "/":
        raise ValueError(path + " must identify a non-root absolute path")
    segments = value.split("/")[1:]
    if not segments or any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError(path + " contains a non-canonical path segment")
    return value


def _action_mediation_open_path(path, directory):
    import os
    required = ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY")
    if any(not hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd:
        raise ValueError("host runtime cannot provide no-follow descriptor-relative path traversal")
    base_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent_fd = os.open("/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
    try:
        segments = path.split("/")[1:]
        for segment in segments[:-1]:
            child_fd = os.open(
                segment, base_flags | os.O_DIRECTORY, dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = child_fd
        flags = base_flags | (os.O_DIRECTORY if directory else 0)
        return os.open(segments[-1], flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _action_mediation_stat_identity(value, kind):
    import stat
    return {
        "kind": kind,
        "device_id": str(value.st_dev),
        "inode_id": str(value.st_ino),
        "owner_uid": str(value.st_uid),
        "owner_gid": str(value.st_gid),
        "mode": format(stat.S_IMODE(value.st_mode), "04o"),
        "size_bytes": value.st_size,
        "mtime_ns": str(value.st_mtime_ns),
    }


def _action_mediation_measure_host(binding, tool_input, environment_values):
    import os
    import stat
    invocation = binding["invocation"]
    if not isinstance(environment_values, dict):
        raise ValueError("environment_values must be an exact name-to-string object")
    normalized_environment = {}
    for name, value in environment_values.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("environment_values names and values must be strings")
        normalized_name = unicodedata.normalize("NFC", name)
        normalized_value = unicodedata.normalize("NFC", value)
        if not normalized_name or "=" in normalized_name or "\x00" in normalized_name:
            raise ValueError("environment_values contains an invalid name")
        if "\x00" in normalized_value:
            raise ValueError("environment_values must not contain NUL")
        if len(normalized_name.encode("utf-8")) > _BINDING_MAX_STRING_BYTES:
            raise ValueError("environment_values contains an oversized name")
        if len(normalized_value.encode("utf-8")) > _BINDING_MAX_STRING_BYTES:
            raise ValueError("environment_values contains an oversized value")
        if normalized_name in normalized_environment:
            raise ValueError("environment_values names collide after NFC normalization")
        normalized_environment[normalized_name] = normalized_value
    expected_environment = invocation["environment"]
    expected_names = [item["name"] for item in expected_environment]
    if sorted(normalized_environment) != expected_names:
        raise ValueError("environment_values must contain exactly the committed environment names")
    measured_environment = []
    for expected in expected_environment:
        value_sha256 = hashlib.sha256(
            normalized_environment[expected["name"]].encode("utf-8")
        ).hexdigest()
        if value_sha256 != expected["value_sha256"]:
            raise ValueError("environment value commitment mismatch for " + expected["name"])
        measured_environment.append({"name": expected["name"], "value_sha256": value_sha256})

    executable_uri = invocation["adapter"]["executable_uri"]
    executable_path = _action_mediation_file_path(executable_uri, "invocation.adapter.executable_uri")
    executable_fd = _action_mediation_open_path(executable_path, False)
    try:
        before = os.fstat(executable_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("host adapter executable must be a regular file")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("host adapter executable must not be group/world-writable")
        if before.st_size > _ACTION_MEDIATION_MAX_EXECUTABLE_BYTES:
            raise ValueError("host adapter executable exceeds the 64 MiB mediation limit")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(executable_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _ACTION_MEDIATION_MAX_EXECUTABLE_BYTES:
                raise ValueError("host adapter executable changed beyond the mediation size limit")
            digest.update(chunk)
        after = os.fstat(executable_fd)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable_fields) or total != after.st_size:
            raise ValueError("host adapter executable changed while it was measured")
        executable_sha256 = digest.hexdigest()
        if executable_sha256 != invocation["adapter"]["artifact_sha256"]:
            raise ValueError("host adapter executable bytes do not match artifact_sha256")
        executable_identity = _action_mediation_stat_identity(after, "regular-file")
    finally:
        os.close(executable_fd)

    cwd_uri = invocation["working_directory_uri"]
    cwd_path = _action_mediation_file_path(cwd_uri, "invocation.working_directory_uri")
    cwd_fd = _action_mediation_open_path(cwd_path, True)
    try:
        cwd_stat = os.fstat(cwd_fd)
        if not stat.S_ISDIR(cwd_stat.st_mode):
            raise ValueError("working directory must be a directory")
        if cwd_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("working directory must not be group/world-writable")
        cwd_identity = _action_mediation_stat_identity(cwd_stat, "directory")
    finally:
        os.close(cwd_fd)

    normalized_input, input_findings = _normalize_binding_json(tool_input)
    if input_findings:
        raise ValueError("tool input is not canonical at the host boundary")
    stdin_bytes = _artifact_json(normalized_input).encode("utf-8")
    stdin_sha256 = hashlib.sha256(stdin_bytes).hexdigest()
    if stdin_sha256 != invocation["stdin"]["payload_sha256"]:
        raise ValueError("canonical stdin bytes do not match the invocation payload commitment")

    measurement = {
        "schema": _ACTION_HOST_MEASUREMENT_SCHEMA,
        "executable": {
            "uri": executable_uri,
            "artifact_sha256": executable_sha256,
            "identity": executable_identity,
        },
        "working_directory": {"uri": cwd_uri, "identity": cwd_identity},
        "environment": measured_environment,
        "environment_sha256": _binding_sha256(measured_environment),
        "stdin": {
            "encoding": "canonical-json/utf-8",
            "payload_sha256": stdin_sha256,
            "size_bytes": len(stdin_bytes),
        },
        "controls": {
            "timeout_ms": invocation["timeout_ms"],
            "shell": "denied",
            "network": "denied",
            "credentials": "none",
        },
        "execution_obligations": list(_ACTION_MEDIATION_OBLIGATIONS),
    }
    measurement["host_measurement_sha256"] = _binding_sha256(measurement)
    return measurement


def _action_mediation_identity_findings(identity, path, expected_kind):
    keys = {
        "kind", "device_id", "inode_id", "owner_uid", "owner_gid", "mode",
        "size_bytes", "mtime_ns",
    }
    findings = _action_invocation_closed_findings(identity, path, keys)
    if not isinstance(identity, dict):
        return findings
    if identity.get("kind") != expected_kind:
        findings.append({"path": path + ".kind", "code": "identity-kind-mismatch", "message": "unexpected host identity kind"})
    for key in ("device_id", "inode_id", "owner_uid", "owner_gid", "mtime_ns"):
        value = identity.get(key)
        if not isinstance(value, str) or not value.isdigit():
            findings.append({"path": path + "." + key, "code": "expected-decimal-string", "message": key + " must be a decimal string"})
    mode = identity.get("mode")
    if not isinstance(mode, str) or len(mode) != 4 or any(char not in "01234567" for char in mode):
        findings.append({"path": path + ".mode", "code": "expected-octal-mode", "message": "mode must be four octal digits"})
    if type(identity.get("size_bytes")) is not int or identity.get("size_bytes", -1) < 0:
        findings.append({"path": path + ".size_bytes", "code": "expected-size", "message": "size_bytes must be a non-negative integer"})
    return findings


def _action_mediation_structure_findings(mediation):
    outer_keys = {
        "schema", "claim_sha256", "approval_sha256", "request_sha256",
        "binding_sha256", "capsule_sha256", "invocation_sha256",
        "host_measurement", "host_measurement_sha256", "mediated_at_unix_ms",
        "approval_expires_at_unix_ms", "status", "mediation_sha256",
    }
    findings = _action_invocation_closed_findings(mediation, "mediation", outer_keys)
    if not isinstance(mediation, dict):
        return findings
    if mediation.get("schema") != _ACTION_MEDIATION_SCHEMA:
        findings.append({"path": "mediation.schema", "code": "unsupported-schema", "message": "expected loom-action-host-mediation/v0"})
    if mediation.get("status") != "ready":
        findings.append({"path": "mediation.status", "code": "mediation-not-ready", "message": "mediation status must be ready"})
    for key in (
        "claim_sha256", "approval_sha256", "request_sha256", "binding_sha256",
        "capsule_sha256", "invocation_sha256", "host_measurement_sha256", "mediation_sha256",
    ):
        if not _binding_is_sha256(mediation.get(key)):
            findings.append({"path": "mediation." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
    mediated_at = mediation.get("mediated_at_unix_ms")
    expires_at = mediation.get("approval_expires_at_unix_ms")
    if type(mediated_at) is not int or mediated_at < 0:
        findings.append({"path": "mediation.mediated_at_unix_ms", "code": "invalid-mediation-time", "message": "mediation time must be a non-negative integer"})
    if type(expires_at) is not int or expires_at < 0:
        findings.append({"path": "mediation.approval_expires_at_unix_ms", "code": "invalid-expiry-time", "message": "approval expiry must be a non-negative integer"})
    if type(mediated_at) is int and type(expires_at) is int and expires_at <= mediated_at:
        findings.append({"path": "mediation.approval_expires_at_unix_ms", "code": "expired-mediation", "message": "mediation must precede approval expiry"})

    measurement = mediation.get("host_measurement")
    measurement_keys = {
        "schema", "executable", "working_directory", "environment",
        "environment_sha256", "stdin", "controls", "execution_obligations",
        "host_measurement_sha256",
    }
    findings.extend(_action_invocation_closed_findings(measurement, "mediation.host_measurement", measurement_keys))
    if isinstance(measurement, dict):
        if measurement.get("schema") != _ACTION_HOST_MEASUREMENT_SCHEMA:
            findings.append({"path": "mediation.host_measurement.schema", "code": "unsupported-schema", "message": "expected loom-action-host-measurement/v0"})
        for key in ("environment_sha256", "host_measurement_sha256"):
            if not _binding_is_sha256(measurement.get(key)):
                findings.append({"path": "mediation.host_measurement." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})
        executable = measurement.get("executable")
        findings.extend(_action_invocation_closed_findings(
            executable, "mediation.host_measurement.executable", {"uri", "artifact_sha256", "identity"},
        ))
        if isinstance(executable, dict):
            try:
                _action_mediation_file_path(executable.get("uri"), "mediation.host_measurement.executable.uri")
            except ValueError as error:
                findings.append({"path": "mediation.host_measurement.executable.uri", "code": "invalid-host-uri", "message": str(error)})
            if not _binding_is_sha256(executable.get("artifact_sha256")):
                findings.append({"path": "mediation.host_measurement.executable.artifact_sha256", "code": "expected-sha256", "message": "artifact_sha256 must be lowercase SHA-256 hex"})
            findings.extend(_action_mediation_identity_findings(
                executable.get("identity"), "mediation.host_measurement.executable.identity", "regular-file",
            ))
        cwd = measurement.get("working_directory")
        findings.extend(_action_invocation_closed_findings(
            cwd, "mediation.host_measurement.working_directory", {"uri", "identity"},
        ))
        if isinstance(cwd, dict):
            try:
                _action_mediation_file_path(cwd.get("uri"), "mediation.host_measurement.working_directory.uri")
            except ValueError as error:
                findings.append({"path": "mediation.host_measurement.working_directory.uri", "code": "invalid-host-uri", "message": str(error)})
            findings.extend(_action_mediation_identity_findings(
                cwd.get("identity"), "mediation.host_measurement.working_directory.identity", "directory",
            ))
        environment = measurement.get("environment")
        if not isinstance(environment, list):
            findings.append({"path": "mediation.host_measurement.environment", "code": "expected-array", "message": "environment must be an array"})
        else:
            names = []
            for index, item in enumerate(environment):
                item_path = f"mediation.host_measurement.environment[{index}]"
                findings.extend(_action_invocation_closed_findings(item, item_path, {"name", "value_sha256"}))
                if isinstance(item, dict):
                    name = item.get("name")
                    if not isinstance(name, str) or not name:
                        findings.append({"path": item_path + ".name", "code": "expected-string", "message": "environment name must be non-empty"})
                    else:
                        if (
                            name != unicodedata.normalize("NFC", name) or "=" in name or "\x00" in name
                            or len(name.encode("utf-8")) > _BINDING_MAX_STRING_BYTES
                        ):
                            findings.append({"path": item_path + ".name", "code": "non-canonical-environment-name", "message": "environment name violates the closed NFC profile"})
                        names.append(name)
                    if not _binding_is_sha256(item.get("value_sha256")):
                        findings.append({"path": item_path + ".value_sha256", "code": "expected-sha256", "message": "environment commitment must be lowercase SHA-256 hex"})
            if names != sorted(names) or len(names) != len(set(names)):
                findings.append({"path": "mediation.host_measurement.environment", "code": "non-canonical-environment", "message": "environment names must be sorted and unique"})
            try:
                environment_sha256 = _binding_sha256(environment)
            except (TypeError, ValueError):
                environment_sha256 = None
                findings.append({"path": "mediation.host_measurement.environment", "code": "non-canonical-environment", "message": "environment commitments must be canonical JSON values"})
            if environment_sha256 is not None and measurement.get("environment_sha256") != environment_sha256:
                findings.append({"path": "mediation.host_measurement.environment_sha256", "code": "environment-hash-mismatch", "message": "environment hash does not match commitments"})
        stdin = measurement.get("stdin")
        findings.extend(_action_invocation_closed_findings(
            stdin, "mediation.host_measurement.stdin", {"encoding", "payload_sha256", "size_bytes"},
        ))
        if isinstance(stdin, dict):
            if stdin.get("encoding") != "canonical-json/utf-8":
                findings.append({"path": "mediation.host_measurement.stdin.encoding", "code": "encoding-mismatch", "message": "stdin must be canonical JSON UTF-8"})
            if not _binding_is_sha256(stdin.get("payload_sha256")):
                findings.append({"path": "mediation.host_measurement.stdin.payload_sha256", "code": "expected-sha256", "message": "stdin payload hash must be lowercase SHA-256 hex"})
            if type(stdin.get("size_bytes")) is not int or stdin.get("size_bytes", -1) < 0:
                findings.append({"path": "mediation.host_measurement.stdin.size_bytes", "code": "expected-size", "message": "stdin size must be a non-negative integer"})
        controls = measurement.get("controls")
        expected_controls = {"timeout_ms", "shell", "network", "credentials"}
        findings.extend(_action_invocation_closed_findings(controls, "mediation.host_measurement.controls", expected_controls))
        if isinstance(controls, dict):
            if type(controls.get("timeout_ms")) is not int or not 1 <= controls.get("timeout_ms", 0) <= 3600000:
                findings.append({"path": "mediation.host_measurement.controls.timeout_ms", "code": "timeout-out-of-range", "message": "timeout must be between 1 and 3600000 milliseconds"})
            for key, value in {"shell": "denied", "network": "denied", "credentials": "none"}.items():
                if controls.get(key) != value:
                    findings.append({"path": "mediation.host_measurement.controls." + key, "code": "control-mismatch", "message": key + " violates mediation v0 controls"})
        if measurement.get("execution_obligations") != list(_ACTION_MEDIATION_OBLIGATIONS):
            findings.append({"path": "mediation.host_measurement.execution_obligations", "code": "obligation-mismatch", "message": "bounded executor obligations are not canonical"})
        if set(measurement) == measurement_keys:
            body = {key: measurement[key] for key in measurement_keys if key != "host_measurement_sha256"}
            try:
                body_sha256 = _binding_sha256(body)
            except (TypeError, ValueError):
                body_sha256 = None
                findings.append({"path": "mediation.host_measurement", "code": "non-canonical-measurement", "message": "host measurement must contain canonical JSON values"})
            if body_sha256 is not None and measurement.get("host_measurement_sha256") != body_sha256:
                findings.append({"path": "mediation.host_measurement.host_measurement_sha256", "code": "measurement-hash-mismatch", "message": "host measurement hash does not match its canonical body"})
        if mediation.get("host_measurement_sha256") != measurement.get("host_measurement_sha256"):
            findings.append({"path": "mediation.host_measurement_sha256", "code": "measurement-link-mismatch", "message": "mediation does not reference its embedded host measurement"})
    if set(mediation) == outer_keys:
        body = {key: mediation[key] for key in outer_keys if key != "mediation_sha256"}
        try:
            body_sha256 = _binding_sha256(body)
        except (TypeError, ValueError):
            body_sha256 = None
            findings.append({"path": "mediation", "code": "non-canonical-mediation", "message": "mediation must contain canonical JSON values"})
        if body_sha256 is not None and mediation.get("mediation_sha256") != body_sha256:
            findings.append({"path": "mediation.mediation_sha256", "code": "mediation-hash-mismatch", "message": "mediation hash does not match its canonical body"})
    return findings


def validate_action_host_mediation_v0(mediation):
    """Validate one closed mediation artifact without re-reading its host resources."""
    findings = _action_mediation_structure_findings(mediation)
    return _action_mediation_validation(mediation, findings)


def _action_mediation_once(claim, approval_check, request, measurement, now_unix_ms, ledger_path):
    import os
    import sqlite3
    import stat
    if not ledger_path.exists() or ledger_path.is_symlink() or not ledger_path.is_file():
        raise ValueError("Action Claim ledger must already exist as a regular non-symlink file")
    parent = ledger_path.parent
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid():
        raise ValueError("Action Claim ledger parent must be a current-user-owned non-symlink directory")
    ledger_stat = ledger_path.stat()
    if ledger_stat.st_uid != os.getuid() or ledger_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Action Claim ledger must be current-user-owned and not group/world-writable")
    body = {
        "schema": _ACTION_MEDIATION_SCHEMA,
        "claim_sha256": claim["claim_sha256"],
        "approval_sha256": approval_check["approval_sha256"],
        "request_sha256": request["request_sha256"],
        "binding_sha256": request["binding"]["binding_sha256"],
        "capsule_sha256": request["binding"]["capsule_sha256"],
        "invocation_sha256": request["binding"]["invocation_sha256"],
        "host_measurement": measurement,
        "host_measurement_sha256": measurement["host_measurement_sha256"],
        "mediated_at_unix_ms": now_unix_ms,
        "approval_expires_at_unix_ms": approval_check["approval"]["expires_at_unix_ms"],
        "status": "ready",
    }
    body["mediation_sha256"] = _binding_sha256(body)
    claim_row = (
        claim["approval_sha256"], claim["request_sha256"], claim["challenge_sha256"],
        claim["binding_sha256"], claim["capsule_sha256"], claim["invocation_sha256"],
        claim["claimed_at_unix_ms"], claim["approval_expires_at_unix_ms"],
        claim["claim_sha256"], claim["status"],
    )
    connection = None
    try:
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
        opened_stat = ledger_path.stat()
        if ledger_path.is_symlink() or opened_stat.st_dev != ledger_stat.st_dev or opened_stat.st_ino != ledger_stat.st_ino:
            raise ValueError("Action Claim ledger identity changed during mediation open")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        claim_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (_ACTION_CLAIM_LEDGER_TABLE,),
        ).fetchone()
        if claim_schema != (_ACTION_CLAIM_LEDGER_SCHEMA,):
            raise ValueError("Action Claim ledger table schema is not canonical")
        connection.execute(_ACTION_MEDIATION_LEDGER_CREATE)
        mediation_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (_ACTION_MEDIATION_LEDGER_TABLE,),
        ).fetchone()
        if mediation_schema != (_ACTION_MEDIATION_LEDGER_SCHEMA,):
            raise ValueError("Action Mediation ledger table schema is not canonical")
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1"
        ).fetchone():
            raise ValueError("Action ledger must not contain triggers or views")
        stored_claim = connection.execute(
            "SELECT approval_sha256,request_sha256,challenge_sha256,binding_sha256,"
            "capsule_sha256,invocation_sha256,claimed_at_unix_ms,"
            "approval_expires_at_unix_ms,claim_sha256,status "
            "FROM action_claims_v0 WHERE claim_sha256=?",
            (claim["claim_sha256"],),
        ).fetchone()
        if stored_claim != claim_row:
            raise ValueError("Action Claim is absent, terminal, or does not match the private ledger row")
        connection.execute(
            "INSERT INTO action_mediations_v0 (claim_sha256,approval_sha256,binding_sha256,invocation_sha256,"
            "host_measurement_sha256,executable_sha256,environment_sha256,stdin_sha256,mediated_at_unix_ms,"
            "approval_expires_at_unix_ms,mediation_sha256,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                body["claim_sha256"], body["approval_sha256"], body["binding_sha256"],
                body["invocation_sha256"], body["host_measurement_sha256"],
                measurement["executable"]["artifact_sha256"], measurement["environment_sha256"],
                measurement["stdin"]["payload_sha256"], body["mediated_at_unix_ms"],
                body["approval_expires_at_unix_ms"], body["mediation_sha256"], body["status"],
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Claim was already mediated or the mediation ledger rejected it") from error
    except (sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(error, ValueError):
            raise
        raise ValueError("Action Mediation ledger failed: " + str(error)) from error
    finally:
        if connection is not None:
            connection.close()
    return body


def _mediate_action_capsule_claim_v0(
    approval, request, claim, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, environment_values, now_unix_ms,
    public_key_value, ledger_path,
):
    approval_check = _verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, now_unix_ms, public_key_value,
    )
    if not approval_check["valid"]:
        return _action_mediation_validation(None, approval_check["findings"])
    claim_findings = _action_claim_findings(claim, approval_check, request, now_unix_ms)
    if claim_findings:
        return _action_mediation_validation(None, claim_findings)
    try:
        measurement = _action_mediation_measure_host(
            request["binding"], tool_input, environment_values,
        )
        mediation = _action_mediation_once(
            claim, approval_check, request, measurement, now_unix_ms, ledger_path,
        )
    except (OSError, ValueError) as error:
        return _action_mediation_validation(None, [{
            "path": "host", "code": "action-host-mediation-failed", "message": str(error),
        }])
    return _action_mediation_validation(mediation, [])


def mediate_action_capsule_claim_v0(
    approval, request, claim, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, environment_values, now_unix_ms,
):
    """Remeasure one claimed exact invocation without executing its process."""
    try:
        public_key = _action_approval_load_public_key()
    except ValueError as error:
        return _action_mediation_validation(None, [{
            "path": "public_key", "code": "public-key-unavailable", "message": str(error),
        }])
    return _mediate_action_capsule_claim_v0(
        approval, request, claim, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, environment_values, now_unix_ms, public_key,
        _action_claim_ledger_path(),
    )


def _action_execution_sandbox_provider():
    import os
    import stat
    import sys
    if sys.platform == "darwin":
        path = "/usr/bin/sandbox-exec"
        profile = "darwin-seatbelt-network-deny/v0"
        prefix = [path, "-p", _ACTION_EXECUTION_DARWIN_PROFILE]
    elif sys.platform.startswith("linux"):
        path = next((item for item in ("/usr/bin/unshare", "/bin/unshare") if os.path.exists(item)), None)
        if path is None:
            raise ValueError("Linux network namespace provider is unavailable")
        profile = "linux-user-network-namespace/v0"
        prefix = [path, "--user", "--map-root-user", "--net", "--"]
    else:
        raise ValueError("Bounded Execution v0 has no verified network sandbox provider for this platform")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0:
            raise ValueError("network sandbox provider must be a root-owned regular file")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("network sandbox provider must not be group/world-writable")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _ACTION_MEDIATION_MAX_EXECUTABLE_BYTES:
                raise ValueError("network sandbox provider exceeds the 64 MiB trust limit")
            digest.update(chunk)
        after = os.fstat(fd)
        if any(getattr(before, key) != getattr(after, key) for key in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")):
            raise ValueError("network sandbox provider changed while measured")
    finally:
        os.close(fd)
    provider = {
        "schema": _ACTION_EXECUTION_SANDBOX_SCHEMA,
        "profile": profile,
        "policy_sha256": _binding_sha256({"profile": profile, "arguments": prefix[1:]}),
        "provider_sha256": digest.hexdigest(),
        "provider_identity": _action_mediation_stat_identity(after, "regular-file"),
        "network": "denied",
    }
    provider["sandbox_sha256"] = _binding_sha256(provider)
    return provider, prefix


def _action_execution_probe_sandbox(prefix):
    import os
    import subprocess
    true_path = next((item for item in ("/usr/bin/true", "/bin/true") if os.path.exists(item)), None)
    if true_path is None:
        raise ValueError("network sandbox capability probe is unavailable")
    try:
        probe = subprocess.run(
            prefix + [true_path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env={}, shell=False, close_fds=True,
            start_new_session=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("network sandbox capability probe failed: " + str(error)) from error
    if probe.returncode != 0:
        detail = probe.stderr[:256].decode("utf-8", "replace").strip()
        raise ValueError("network sandbox provider cannot enforce its profile" + (": " + detail if detail else ""))


def _action_execution_normalized_inputs(binding, tool_input, environment_values):
    measurement = _action_mediation_measure_host(binding, tool_input, environment_values)
    normalized_environment = {
        unicodedata.normalize("NFC", name): unicodedata.normalize("NFC", value)
        for name, value in environment_values.items()
    }
    normalized_input, findings = _normalize_binding_json(tool_input)
    if findings:
        raise ValueError("tool input is not canonical at the execution boundary")
    stdin_bytes = _artifact_json(normalized_input).encode("utf-8")
    return measurement, normalized_environment, stdin_bytes


def _action_execution_snapshot(executable_fd, expected_sha256, parent):
    import os
    import tempfile
    directory = tempfile.mkdtemp(prefix=".loom-exec-", dir=str(parent))
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "adapter")
    target_fd = None
    try:
        target_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o500)
        os.lseek(executable_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(executable_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _ACTION_MEDIATION_MAX_EXECUTABLE_BYTES:
                raise ValueError("execution snapshot exceeds the 64 MiB limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                view = view[written:]
        os.fsync(target_fd)
        if digest.hexdigest() != expected_sha256:
            raise ValueError("execution snapshot bytes do not match the mediated executable")
        snapshot_stat = os.fstat(target_fd)
        os.fchmod(target_fd, 0o500)
    except Exception:
        if target_fd is not None:
            os.close(target_fd)
            target_fd = None
        try:
            os.unlink(path)
        except OSError:
            pass
        try:
            os.rmdir(directory)
        except OSError:
            pass
        raise
    finally:
        if target_fd is not None:
            os.close(target_fd)
    return directory, path, _action_mediation_stat_identity(snapshot_stat, "regular-file")


def _action_execution_root_path_custody(path):
    import os
    import stat
    base_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent_fd = os.open("/", base_flags | os.O_DIRECTORY)
    custody = []
    try:
        root_stat = os.fstat(parent_fd)
        custody.append({
            "component_index": 0,
            "identity": _action_mediation_stat_identity(root_stat, "directory"),
        })
        segments = path.split("/")[1:]
        for index, segment in enumerate(segments, 1):
            final = index == len(segments)
            flags = base_flags | (0 if final else os.O_DIRECTORY)
            child_fd = os.open(segment, flags, dir_fd=parent_fd)
            child_stat = os.fstat(child_fd)
            expected_kind = "regular-file" if final else "directory"
            valid_kind = stat.S_ISREG(child_stat.st_mode) if final else stat.S_ISDIR(child_stat.st_mode)
            if not valid_kind or child_stat.st_uid != 0:
                os.close(child_fd)
                raise ValueError("macOS immutable launch path must be root-owned and type-stable")
            if child_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                os.close(child_fd)
                raise ValueError("macOS immutable launch path must not be group/world-writable")
            custody.append({
                "component_index": index,
                "identity": _action_mediation_stat_identity(child_stat, expected_kind),
            })
            os.close(parent_fd)
            parent_fd = child_fd
        if any(item["identity"]["owner_uid"] != "0" for item in custody):
            raise ValueError("macOS immutable launch path must be root-owned from filesystem root")
        if any(int(item["identity"]["mode"], 8) & 0o022 for item in custody):
            raise ValueError("macOS immutable launch path must not be group/world-writable")
        return custody
    finally:
        os.close(parent_fd)


def _action_execution_remeasure(binding, tool_input, environment_values, mediation, ledger_path):
    import os
    import sys
    measurement, normalized_environment, stdin_bytes = _action_execution_normalized_inputs(
        binding, tool_input, environment_values,
    )
    if measurement != mediation["host_measurement"]:
        raise ValueError("live host measurement no longer matches the mediated host state")
    executable_path = _action_mediation_file_path(
        binding["invocation"]["adapter"]["executable_uri"], "binding.invocation.adapter.executable_uri",
    )
    cwd_path = _action_mediation_file_path(
        binding["invocation"]["working_directory_uri"], "binding.invocation.working_directory_uri",
    )
    executable_fd = _action_mediation_open_path(executable_path, False)
    cwd_fd = _action_mediation_open_path(cwd_path, True)
    snapshot_directory = None
    try:
        executable_stat = os.fstat(executable_fd)
        cwd_stat = os.fstat(cwd_fd)
        executable_identity = _action_mediation_stat_identity(executable_stat, "regular-file")
        cwd_identity = _action_mediation_stat_identity(cwd_stat, "directory")
        if executable_identity != measurement["executable"]["identity"]:
            raise ValueError("executable identity changed at the spawn boundary")
        if cwd_identity != measurement["working_directory"]["identity"]:
            raise ValueError("working-directory identity changed at the spawn boundary")
        if sys.platform == "darwin":
            try:
                path_custody = _action_execution_root_path_custody(executable_path)
            except (OSError, ValueError):
                path_custody = []
        else:
            path_custody = []
        if path_custody:
            if path_custody[-1]["identity"] != executable_identity:
                raise ValueError("macOS immutable launch path changed between remeasurement and custody proof")
            launch_path = executable_path
            launch_identity = executable_identity
            spawn_boundary = "root-owned-immutable-path"
        else:
            snapshot_directory, launch_path, launch_identity = _action_execution_snapshot(
                executable_fd, measurement["executable"]["artifact_sha256"], ledger_path.parent,
            )
            spawn_boundary = "private-executable-snapshot"
        body = {
            "schema": _ACTION_EXECUTION_REMEASUREMENT_SCHEMA,
            "source_host_measurement_sha256": measurement["host_measurement_sha256"],
            "executable_sha256": measurement["executable"]["artifact_sha256"],
            "executable_identity": executable_identity,
            "launch_identity": launch_identity,
            "path_custody": path_custody,
            "working_directory_identity": cwd_identity,
            "environment_sha256": measurement["environment_sha256"],
            "stdin_sha256": measurement["stdin"]["payload_sha256"],
            "stdin_size_bytes": len(stdin_bytes),
            "spawn_boundary": spawn_boundary,
        }
        body["host_remeasurement_sha256"] = _binding_sha256(body)
        return body, normalized_environment, stdin_bytes, cwd_path, snapshot_directory, launch_path
    except Exception:
        if snapshot_directory is not None:
            try:
                os.unlink(os.path.join(snapshot_directory, "adapter"))
            except OSError:
                pass
            try:
                os.rmdir(snapshot_directory)
            except OSError:
                pass
        raise
    finally:
        os.close(executable_fd)
        os.close(cwd_fd)


def _action_execution_claim_row(claim):
    return (
        claim["approval_sha256"], claim["request_sha256"], claim["challenge_sha256"],
        claim["binding_sha256"], claim["capsule_sha256"], claim["invocation_sha256"],
        claim["claimed_at_unix_ms"], claim["approval_expires_at_unix_ms"],
        claim["claim_sha256"], claim["status"],
    )


def _action_execution_mediation_row(mediation):
    measurement = mediation["host_measurement"]
    return (
        mediation["claim_sha256"], mediation["approval_sha256"], mediation["binding_sha256"],
        mediation["invocation_sha256"], mediation["host_measurement_sha256"],
        measurement["executable"]["artifact_sha256"], measurement["environment_sha256"],
        measurement["stdin"]["payload_sha256"], mediation["mediated_at_unix_ms"],
        mediation["approval_expires_at_unix_ms"], mediation["mediation_sha256"], mediation["status"],
    )


def _action_execution_open_ledger(ledger_path):
    import os
    import sqlite3
    import stat
    if not ledger_path.exists() or ledger_path.is_symlink() or not ledger_path.is_file():
        raise ValueError("Action ledger must already exist as a regular non-symlink file")
    parent = ledger_path.parent
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid():
        raise ValueError("Action ledger parent must be a current-user-owned non-symlink directory")
    before = ledger_path.stat()
    if before.st_uid != os.getuid() or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Action ledger must be current-user-owned and not group/world-writable")
    connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
    after = ledger_path.stat()
    if ledger_path.is_symlink() or after.st_dev != before.st_dev or after.st_ino != before.st_ino:
        connection.close()
        raise ValueError("Action ledger identity changed during execution open")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def _action_execution_verify_ledger(connection, claim, mediation):
    claim_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_ACTION_CLAIM_LEDGER_TABLE,),
    ).fetchone()
    mediation_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_ACTION_MEDIATION_LEDGER_TABLE,),
    ).fetchone()
    if claim_schema != (_ACTION_CLAIM_LEDGER_SCHEMA,) or mediation_schema != (_ACTION_MEDIATION_LEDGER_SCHEMA,):
        raise ValueError("Action Claim or Mediation ledger schema is not canonical")
    connection.execute(_ACTION_EXECUTION_LEDGER_CREATE)
    execution_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_ACTION_EXECUTION_LEDGER_TABLE,),
    ).fetchone()
    if execution_schema != (_ACTION_EXECUTION_LEDGER_SCHEMA,):
        raise ValueError("Action Execution ledger table schema is not canonical")
    if connection.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
        raise ValueError("Action ledger must not contain triggers or views")
    stored_claim = connection.execute(
        "SELECT approval_sha256,request_sha256,challenge_sha256,binding_sha256,capsule_sha256,"
        "invocation_sha256,claimed_at_unix_ms,approval_expires_at_unix_ms,claim_sha256,status "
        "FROM action_claims_v0 WHERE claim_sha256=?", (claim["claim_sha256"],),
    ).fetchone()
    stored_mediation = connection.execute(
        "SELECT claim_sha256,approval_sha256,binding_sha256,invocation_sha256,host_measurement_sha256,"
        "executable_sha256,environment_sha256,stdin_sha256,mediated_at_unix_ms,"
        "approval_expires_at_unix_ms,mediation_sha256,status FROM action_mediations_v0 WHERE mediation_sha256=?",
        (mediation["mediation_sha256"],),
    ).fetchone()
    if stored_claim != _action_execution_claim_row(claim):
        raise ValueError("Action Claim does not match its private ledger row")
    if stored_mediation != _action_execution_mediation_row(mediation):
        raise ValueError("Action Mediation is absent or does not match its private ledger row")


def _action_execution_reserve(claim, mediation, remeasurement, now_unix_ms, ledger_path):
    import sqlite3
    connection = None
    try:
        connection = _action_execution_open_ledger(ledger_path)
        connection.execute("BEGIN IMMEDIATE")
        _action_execution_verify_ledger(connection, claim, mediation)
        connection.execute(
            "INSERT INTO action_executions_v0 (mediation_sha256,claim_sha256,binding_sha256,"
            "host_remeasurement_sha256,reserved_at_unix_ms,approval_expires_at_unix_ms,status) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                mediation["mediation_sha256"], claim["claim_sha256"], mediation["binding_sha256"],
                remeasurement["host_remeasurement_sha256"], now_unix_ms,
                mediation["approval_expires_at_unix_ms"], "reserved",
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Mediation was already consumed by an execution attempt") from error
    except (sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(error, ValueError):
            raise
        raise ValueError("Action Execution reservation failed: " + str(error)) from error
    finally:
        if connection is not None:
            connection.close()


def _action_execution_kill_group(process):
    import os
    import signal
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _action_execution_run(prefix, snapshot_path, argv, cwd_path, environment, stdin_bytes, timeout_ms,
                          mediation, remeasurement, sandbox):
    import subprocess
    import threading
    import time
    command = prefix + [snapshot_path] + list(argv)
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd_path, env=environment, shell=False, close_fds=True,
            start_new_session=True, bufsize=0,
        )
    except OSError:
        attempt = {
            "schema": _ACTION_EXECUTION_ATTEMPT_SCHEMA,
            "result": "spawn-failed", "mediation_sha256": mediation["mediation_sha256"],
            "host_remeasurement_sha256": remeasurement["host_remeasurement_sha256"],
            "sandbox_sha256": sandbox["sandbox_sha256"], "timeout_ms": timeout_ms,
            "output_limit_bytes": _ACTION_EXECUTION_MAX_OUTPUT_BYTES,
            "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            "exit_code": None, "terminating_signal": None,
            "stdout": {"sha256": empty_sha256, "size_bytes": 0},
            "stderr": {"sha256": empty_sha256, "size_bytes": 0},
            "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            "shell": "denied", "network": "denied",
        }
        attempt["attempt_sha256"] = _binding_sha256(attempt)
        return attempt

    overflow = threading.Event()
    streams = {}

    def drain(name, stream):
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if total > _ACTION_EXECUTION_MAX_OUTPUT_BYTES:
                overflow.set()
        streams[name] = {"sha256": digest.hexdigest(), "size_bytes": total}

    def feed():
        try:
            process.stdin.write(stdin_bytes)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    workers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        threading.Thread(target=feed, daemon=True),
    ]
    for worker in workers:
        worker.start()
    deadline = started + timeout_ms / 1000.0
    forced = None
    while process.poll() is None:
        if overflow.is_set():
            forced = "output-limit-exceeded"
            _action_execution_kill_group(process)
            break
        if time.monotonic() >= deadline:
            forced = "timed-out"
            _action_execution_kill_group(process)
            break
        time.sleep(0.005)
    returncode = process.wait()
    for worker in workers:
        worker.join(timeout=5)
    if "stdout" not in streams or "stderr" not in streams:
        forced = forced or "failed"
        streams.setdefault("stdout", {"sha256": empty_sha256, "size_bytes": 0})
        streams.setdefault("stderr", {"sha256": empty_sha256, "size_bytes": 0})
    result = forced or ("completed" if returncode == 0 else "failed")
    attempt = {
        "schema": _ACTION_EXECUTION_ATTEMPT_SCHEMA,
        "result": result,
        "mediation_sha256": mediation["mediation_sha256"],
        "host_remeasurement_sha256": remeasurement["host_remeasurement_sha256"],
        "sandbox_sha256": sandbox["sandbox_sha256"],
        "timeout_ms": timeout_ms,
        "output_limit_bytes": _ACTION_EXECUTION_MAX_OUTPUT_BYTES,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "exit_code": returncode if returncode >= 0 else None,
        "terminating_signal": -returncode if returncode < 0 else None,
        "stdout": streams["stdout"],
        "stderr": streams["stderr"],
        "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
        "shell": "denied",
        "network": "denied",
    }
    attempt["attempt_sha256"] = _binding_sha256(attempt)
    return attempt


def _action_execution_finish(mediation, remeasurement, attempt, now_unix_ms, ledger_path):
    import sqlite3
    connection = None
    try:
        connection = _action_execution_open_ledger(ledger_path)
        connection.execute("BEGIN IMMEDIATE")
        execution_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_ACTION_EXECUTION_LEDGER_TABLE,),
        ).fetchone()
        if execution_schema != (_ACTION_EXECUTION_LEDGER_SCHEMA,):
            raise ValueError("Action Execution ledger table schema is not canonical")
        if connection.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
            raise ValueError("Action ledger must not contain triggers or views")
        stored = connection.execute(
            "SELECT claim_sha256,binding_sha256,host_remeasurement_sha256,reserved_at_unix_ms,"
            "approval_expires_at_unix_ms,status,duration_ms,exit_code,terminating_signal,stdout_sha256,"
            "stdout_size_bytes,stderr_sha256,stderr_size_bytes,attempt_sha256 FROM action_executions_v0 "
            "WHERE mediation_sha256=?", (mediation["mediation_sha256"],),
        ).fetchone()
        expected = (
            mediation["claim_sha256"], mediation["binding_sha256"],
            remeasurement["host_remeasurement_sha256"], now_unix_ms,
            mediation["approval_expires_at_unix_ms"], "reserved",
            None, None, None, None, None, None, None, None,
        )
        if stored != expected:
            raise ValueError("Action Execution reservation is absent, terminal, or changed")
        updated = connection.execute(
            "UPDATE action_executions_v0 SET status=?,duration_ms=?,exit_code=?,terminating_signal=?,"
            "stdout_sha256=?,stdout_size_bytes=?,stderr_sha256=?,stderr_size_bytes=?,attempt_sha256=? "
            "WHERE mediation_sha256=? AND status='reserved'",
            (
                attempt["result"], attempt["duration_ms"], attempt["exit_code"],
                attempt["terminating_signal"], attempt["stdout"]["sha256"],
                attempt["stdout"]["size_bytes"], attempt["stderr"]["sha256"],
                attempt["stderr"]["size_bytes"], attempt["attempt_sha256"],
                mediation["mediation_sha256"],
            ),
        )
        if updated.rowcount != 1:
            raise ValueError("Action Execution terminal transition was not unique")
        connection.execute("COMMIT")
    except (sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(error, ValueError):
            raise
        raise ValueError("Action Execution finalization failed: " + str(error)) from error
    finally:
        if connection is not None:
            connection.close()


def _action_execution_mediation_findings(mediation, claim, approval_check, request, now_unix_ms):
    findings = _action_mediation_structure_findings(mediation)
    if not isinstance(mediation, dict):
        return findings
    expected = {
        "claim_sha256": claim.get("claim_sha256"),
        "approval_sha256": approval_check.get("approval_sha256"),
        "request_sha256": request.get("request_sha256"),
        "binding_sha256": request["binding"].get("binding_sha256"),
        "capsule_sha256": request["binding"].get("capsule_sha256"),
        "invocation_sha256": request["binding"].get("invocation_sha256"),
        "approval_expires_at_unix_ms": approval_check["approval"].get("expires_at_unix_ms"),
    }
    for key, value in expected.items():
        if mediation.get(key) != value:
            findings.append({"path": "mediation." + key, "code": "mediation-binding-mismatch", "message": key + " does not match the verified execution chain"})
    if type(now_unix_ms) is not int or now_unix_ms < 0:
        findings.append({"path": "now_unix_ms", "code": "invalid-time", "message": "execution time must be a non-negative integer"})
    elif type(mediation.get("mediated_at_unix_ms")) is int and now_unix_ms < mediation["mediated_at_unix_ms"]:
        findings.append({"path": "now_unix_ms", "code": "execution-before-mediation", "message": "execution cannot precede mediation"})
    return findings


def _execute_action_host_mediation_v0(
    approval, request, claim, mediation, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, environment_values, now_unix_ms, public_key_value, ledger_path,
):
    import os
    approval_check = _verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, now_unix_ms, public_key_value,
    )
    if not approval_check["valid"]:
        return _action_execution_validation(None, approval_check["findings"])
    claim_findings = _action_claim_findings(claim, approval_check, request, now_unix_ms)
    if claim_findings:
        return _action_execution_validation(None, claim_findings)
    mediation_findings = _action_execution_mediation_findings(
        mediation, claim, approval_check, request, now_unix_ms,
    )
    if mediation_findings:
        return _action_execution_validation(None, mediation_findings)
    snapshot_directory = None
    execution = None
    try:
        sandbox, prefix = _action_execution_sandbox_provider()
        _action_execution_probe_sandbox(prefix)
        remeasurement, environment, stdin_bytes, cwd_path, snapshot_directory, snapshot_path = _action_execution_remeasure(
            request["binding"], tool_input, environment_values, mediation, ledger_path,
        )
        _action_execution_reserve(claim, mediation, remeasurement, now_unix_ms, ledger_path)
        attempt = _action_execution_run(
            prefix, snapshot_path, request["binding"]["invocation"]["argv"], cwd_path,
            environment, stdin_bytes, request["binding"]["invocation"]["timeout_ms"],
            mediation, remeasurement, sandbox,
        )
        body = {
            "schema": _ACTION_EXECUTION_SCHEMA,
            "mediation_sha256": mediation["mediation_sha256"],
            "claim_sha256": mediation["claim_sha256"],
            "binding_sha256": mediation["binding_sha256"],
            "host_remeasurement": remeasurement,
            "host_remeasurement_sha256": remeasurement["host_remeasurement_sha256"],
            "sandbox": sandbox,
            "sandbox_sha256": sandbox["sandbox_sha256"],
            "attempt": attempt,
            "attempt_sha256": attempt["attempt_sha256"],
            "executed_at_unix_ms": now_unix_ms,
            "approval_expires_at_unix_ms": mediation["approval_expires_at_unix_ms"],
            "status": attempt["result"],
        }
        body["execution_sha256"] = _binding_sha256(body)
        execution = body
        _action_execution_finish(mediation, remeasurement, attempt, now_unix_ms, ledger_path)
    except (OSError, ValueError) as error:
        return _action_execution_validation(execution, [{
            "path": "host", "code": "action-bounded-execution-failed", "message": str(error),
        }])
    finally:
        if snapshot_directory is not None:
            try:
                os.unlink(os.path.join(snapshot_directory, "adapter"))
            except OSError:
                pass
            try:
                os.rmdir(snapshot_directory)
            except OSError:
                pass
    return _action_execution_validation(execution, [])


def execute_action_host_mediation_v0(
    approval, request, claim, mediation, manifest, tool_binding, tool_input, program_src,
    wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, environment_values, now_unix_ms,
):
    """Execute one mediated exact invocation once under a verified network sandbox."""
    try:
        public_key = _action_approval_load_public_key()
    except ValueError as error:
        return _action_execution_validation(None, [{
            "path": "public_key", "code": "public-key-unavailable", "message": str(error),
        }])
    return _execute_action_host_mediation_v0(
        approval, request, claim, mediation, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, environment_values, now_unix_ms, public_key,
        _action_claim_ledger_path(),
    )


def _action_result_validation(result, findings):
    return {
        "schema": _ACTION_RESULT_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "authorization": "none",
        "result": result if not findings else None,
        "result_sha256": result.get("result_sha256") if not findings else None,
        "findings": findings,
    }


def _action_result_approval_check(approval, request, execution_time, public_key_value):
    request_check = validate_action_approval_request_v2(request)
    findings = _action_approval_prefixed("request", request_check["findings"])
    public_key, key_findings = _action_approval_validate_public_key(public_key_value)
    findings.extend(key_findings)
    required = {
        "schema", "request_sha256", "challenge_sha256", "binding_sha256",
        "capsule_sha256", "invocation_sha256", "approval_scope", "approver",
        "decision", "issued_at_unix_ms", "expires_at_unix_ms", "claim_required",
        "key_sha256", "signature",
    }
    findings.extend(_action_invocation_closed_findings(approval, "approval", required))
    if not isinstance(approval, dict) or not request_check["valid"]:
        return _action_approval_validation(None, None, findings)
    binding = request["binding"]
    challenge = request["challenge"]
    fixed = {
        "schema": _ACTION_APPROVAL_SCHEMA,
        "request_sha256": request["request_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "capsule_sha256": binding["capsule_sha256"],
        "invocation_sha256": binding["invocation_sha256"],
        "approval_scope": _ACTION_APPROVAL_SCOPE,
        "approver": "operator",
        "decision": "approve",
        "claim_required": True,
    }
    for key, value in fixed.items():
        if approval.get(key) != value:
            findings.append({
                "path": "approval." + key, "code": "approval-binding-mismatch",
                "message": key + " does not match the embedded Action Approval request",
            })
    issued = approval.get("issued_at_unix_ms")
    expires = approval.get("expires_at_unix_ms")
    if type(issued) is not int or issued < 0:
        findings.append({"path": "approval.issued_at_unix_ms", "code": "invalid-issued-time", "message": "issued_at_unix_ms must be a non-negative integer"})
    if type(expires) is not int or expires < 0:
        findings.append({"path": "approval.expires_at_unix_ms", "code": "invalid-expiry-time", "message": "expires_at_unix_ms must be a non-negative integer"})
    if type(execution_time) is not int or execution_time < 0:
        findings.append({"path": "execution.executed_at_unix_ms", "code": "invalid-execution-time", "message": "execution time must be a non-negative integer"})
    if type(issued) is int and type(expires) is int:
        if expires <= issued or expires - issued > _ACTION_APPROVAL_MAX_TTL_MS:
            findings.append({"path": "approval.expires_at_unix_ms", "code": "invalid-validity-window", "message": "Action Approval validity must be positive and at most 900000 milliseconds"})
        if type(execution_time) is int and not issued <= execution_time < expires:
            findings.append({"path": "execution.executed_at_unix_ms", "code": "execution-outside-approval", "message": "Bounded Execution must begin inside the signed approval window"})
    if public_key is not None:
        if approval.get("key_sha256") != _binding_sha256(public_key):
            findings.append({"path": "approval.key_sha256", "code": "key-mismatch", "message": "Action Approval is signed by a different key"})
        signed = {key: approval[key] for key in sorted(required - {"signature"})} if set(approval) >= required else None
        if signed is not None:
            try:
                signed_bytes = _action_approval_canonical(signed).encode("utf-8")
            except (TypeError, ValueError):
                findings.append({"path": "approval", "code": "non-canonical-approval", "message": "Action Approval must contain canonical JSON values"})
            else:
                if not _action_approval_rsa_verify(signed_bytes, approval.get("signature"), public_key):
                    findings.append({"path": "approval.signature", "code": "invalid-signature", "message": "Action Approval signature is invalid"})
    if findings:
        return _action_approval_validation(None, None, findings)
    return _action_approval_validation(approval, _binding_sha256(approval), [])


def _action_result_outcome(execution):
    attempt = execution["attempt"]
    outcome = {
        "schema": _ACTION_RESULT_OUTCOME_SCHEMA,
        "status": execution["status"],
        "duration_ms": attempt["duration_ms"],
        "exit_code": attempt["exit_code"],
        "terminating_signal": attempt["terminating_signal"],
        "stdout": dict(attempt["stdout"]),
        "stderr": dict(attempt["stderr"]),
        "host_remeasurement_sha256": execution["host_remeasurement_sha256"],
        "sandbox_sha256": execution["sandbox_sha256"],
        "attempt_sha256": execution["attempt_sha256"],
    }
    outcome["outcome_sha256"] = _binding_sha256(outcome)
    return outcome


def _action_result_structure_findings(result, public_key_value):
    outer_keys = {
        "schema", "request", "request_sha256", "approval", "approval_sha256",
        "claim", "claim_sha256", "mediation", "mediation_sha256", "execution",
        "execution_sha256", "outcome", "outcome_sha256", "finalized_at_unix_ms",
        "lifecycle", "result_sha256",
    }
    findings = _action_invocation_closed_findings(result, "result", outer_keys)
    if not isinstance(result, dict):
        return findings
    if result.get("schema") != _ACTION_RESULT_SCHEMA:
        findings.append({"path": "result.schema", "code": "schema-mismatch", "message": "unsupported Action Capsule Result schema"})
    for key in (
        "request_sha256", "approval_sha256", "claim_sha256", "mediation_sha256",
        "execution_sha256", "outcome_sha256", "result_sha256",
    ):
        if not _binding_is_sha256(result.get(key)):
            findings.append({"path": "result." + key, "code": "expected-sha256", "message": key + " must be lowercase SHA-256 hex"})

    request = result.get("request")
    request_check = validate_action_approval_request_v2(request)
    findings.extend(_action_approval_prefixed("result.request", request_check["findings"]))
    execution = result.get("execution")
    execution_findings = _action_execution_structure_findings(execution)
    findings.extend(_action_approval_prefixed("result", execution_findings))
    execution_time = execution.get("executed_at_unix_ms") if isinstance(execution, dict) else None
    approval_check = _action_result_approval_check(
        result.get("approval"), request, execution_time, public_key_value,
    )
    findings.extend(_action_approval_prefixed("result", approval_check["findings"]))

    claim = result.get("claim")
    mediation = result.get("mediation")
    if approval_check["valid"] and request_check["valid"]:
        findings.extend(_action_approval_prefixed(
            "result", _action_claim_findings(claim, approval_check, request, execution_time),
        ))
        if isinstance(claim, dict):
            findings.extend(_action_approval_prefixed(
                "result", _action_execution_mediation_findings(
                    mediation, claim, approval_check, request, execution_time,
                ),
            ))
        else:
            findings.extend(_action_approval_prefixed("result", _action_mediation_structure_findings(mediation)))
    else:
        findings.extend(_action_approval_prefixed("result", _action_mediation_structure_findings(mediation)))

    try:
        embedded_approval_sha256 = _binding_sha256(result["approval"]) if isinstance(result.get("approval"), dict) else None
    except (TypeError, ValueError):
        embedded_approval_sha256 = None
        findings.append({"path": "result.approval", "code": "non-canonical-approval", "message": "embedded Action Approval must contain canonical JSON values"})
    links = {
        "request_sha256": request.get("request_sha256") if isinstance(request, dict) else None,
        "approval_sha256": embedded_approval_sha256,
        "claim_sha256": claim.get("claim_sha256") if isinstance(claim, dict) else None,
        "mediation_sha256": mediation.get("mediation_sha256") if isinstance(mediation, dict) else None,
        "execution_sha256": execution.get("execution_sha256") if isinstance(execution, dict) else None,
    }
    for key, value in links.items():
        if result.get(key) != value:
            findings.append({"path": "result." + key, "code": "result-link-mismatch", "message": key + " does not match its embedded lifecycle artifact"})
    if isinstance(request, dict) and isinstance(execution, dict):
        binding = request.get("binding")
        expected_execution_links = {
            "binding_sha256": binding.get("binding_sha256") if isinstance(binding, dict) else None,
            "claim_sha256": result.get("claim_sha256"),
            "mediation_sha256": result.get("mediation_sha256"),
        }
        for key, value in expected_execution_links.items():
            if execution.get(key) != value:
                findings.append({"path": "result.execution." + key, "code": "execution-link-mismatch", "message": key + " does not match the embedded Result chain"})

    outcome = result.get("outcome")
    if isinstance(execution, dict) and not execution_findings:
        expected_outcome = _action_result_outcome(execution)
        if outcome != expected_outcome:
            findings.append({"path": "result.outcome", "code": "outcome-mismatch", "message": "terminal outcome does not match the exact Bounded Execution"})
        if result.get("outcome_sha256") != expected_outcome["outcome_sha256"]:
            findings.append({"path": "result.outcome_sha256", "code": "outcome-link-mismatch", "message": "outer outcome hash does not match terminal outcome"})
    else:
        findings.extend(_action_invocation_closed_findings(outcome, "result.outcome", {
            "schema", "status", "duration_ms", "exit_code", "terminating_signal", "stdout",
            "stderr", "host_remeasurement_sha256", "sandbox_sha256", "attempt_sha256", "outcome_sha256",
        }))

    finalized = result.get("finalized_at_unix_ms")
    if type(finalized) is not int or not 0 <= finalized <= _BINDING_MAX_SAFE_INTEGER:
        findings.append({"path": "result.finalized_at_unix_ms", "code": "invalid-finalization-time", "message": "finalization time must be a non-negative portable integer"})
    elif isinstance(execution, dict) and type(execution_time) is int:
        duration = execution.get("attempt", {}).get("duration_ms")
        if type(duration) is int and finalized < execution_time + duration:
            findings.append({"path": "result.finalized_at_unix_ms", "code": "result-before-execution-finished", "message": "Result cannot predate the measured execution duration"})
    status = execution.get("status") if isinstance(execution, dict) else None
    claim_status = "completed" if status == "completed" else "failed"
    expected_lifecycle = {
        "schema": _ACTION_RESULT_LIFECYCLE_SCHEMA,
        "terminal": True,
        "claim_status": claim_status,
        "authorization": "none",
        "replay": "denied",
        "remaining_evidence": ["loom-gate-receipt/v4"],
    }
    if result.get("lifecycle") != expected_lifecycle:
        findings.append({"path": "result.lifecycle", "code": "lifecycle-mismatch", "message": "Action Capsule Result must be terminal, non-authorizing, and replay-denied"})
    if set(result) >= outer_keys:
        try:
            expected_hash = _binding_sha256({key: result[key] for key in outer_keys if key != "result_sha256"})
        except (TypeError, ValueError):
            findings.append({"path": "result", "code": "non-canonical-result", "message": "Action Capsule Result must contain canonical JSON values"})
        else:
            if result.get("result_sha256") != expected_hash:
                findings.append({"path": "result.result_sha256", "code": "result-hash-mismatch", "message": "result_sha256 does not match the canonical terminal Result"})
    return findings


def validate_action_capsule_result_v0(result, public_key_value):
    """Validate a terminal Result and its operator signature without host IO."""
    findings = _action_result_structure_findings(result, public_key_value)
    return _action_result_validation(result, findings)


def _action_result_execution_row(execution):
    attempt = execution["attempt"]
    return (
        execution["claim_sha256"], execution["binding_sha256"],
        execution["host_remeasurement_sha256"], execution["executed_at_unix_ms"],
        execution["approval_expires_at_unix_ms"], execution["status"],
        attempt["duration_ms"], attempt["exit_code"], attempt["terminating_signal"],
        attempt["stdout"]["sha256"], attempt["stdout"]["size_bytes"],
        attempt["stderr"]["sha256"], attempt["stderr"]["size_bytes"],
        execution["attempt_sha256"],
    )


def _action_result_finalize_once(result, ledger_path):
    import sqlite3
    claim = result["claim"]
    mediation = result["mediation"]
    execution = result["execution"]
    connection = None
    try:
        connection = _action_execution_open_ledger(ledger_path)
        connection.execute("BEGIN IMMEDIATE")
        schemas = {}
        for name in (_ACTION_CLAIM_LEDGER_TABLE, _ACTION_MEDIATION_LEDGER_TABLE, _ACTION_EXECUTION_LEDGER_TABLE):
            schemas[name] = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,),
            ).fetchone()
        if schemas != {
            _ACTION_CLAIM_LEDGER_TABLE: (_ACTION_CLAIM_LEDGER_SCHEMA,),
            _ACTION_MEDIATION_LEDGER_TABLE: (_ACTION_MEDIATION_LEDGER_SCHEMA,),
            _ACTION_EXECUTION_LEDGER_TABLE: (_ACTION_EXECUTION_LEDGER_SCHEMA,),
        }:
            raise ValueError("Action Result source ledger schemas are not canonical")
        connection.execute(_ACTION_RESULT_LEDGER_CREATE)
        result_schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_ACTION_RESULT_LEDGER_TABLE,),
        ).fetchone()
        if result_schema != (_ACTION_RESULT_LEDGER_SCHEMA,):
            raise ValueError("Action Result ledger table schema is not canonical")
        if connection.execute("SELECT name FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
            raise ValueError("Action ledger must not contain triggers or views")
        stored_claim = connection.execute(
            "SELECT approval_sha256,request_sha256,challenge_sha256,binding_sha256,capsule_sha256,"
            "invocation_sha256,claimed_at_unix_ms,approval_expires_at_unix_ms,claim_sha256,status "
            "FROM action_claims_v0 WHERE claim_sha256=?", (claim["claim_sha256"],),
        ).fetchone()
        stored_mediation = connection.execute(
            "SELECT claim_sha256,approval_sha256,binding_sha256,invocation_sha256,host_measurement_sha256,"
            "executable_sha256,environment_sha256,stdin_sha256,mediated_at_unix_ms,"
            "approval_expires_at_unix_ms,mediation_sha256,status FROM action_mediations_v0 WHERE mediation_sha256=?",
            (mediation["mediation_sha256"],),
        ).fetchone()
        stored_execution = connection.execute(
            "SELECT claim_sha256,binding_sha256,host_remeasurement_sha256,reserved_at_unix_ms,"
            "approval_expires_at_unix_ms,status,duration_ms,exit_code,terminating_signal,stdout_sha256,"
            "stdout_size_bytes,stderr_sha256,stderr_size_bytes,attempt_sha256 FROM action_executions_v0 "
            "WHERE mediation_sha256=?", (execution["mediation_sha256"],),
        ).fetchone()
        if stored_claim != _action_execution_claim_row(claim):
            raise ValueError("Action Claim is absent, terminal, or changed")
        if stored_mediation != _action_execution_mediation_row(mediation):
            raise ValueError("Action Mediation is absent or changed")
        if stored_execution != _action_result_execution_row(execution):
            raise ValueError("Bounded Execution is absent or does not match its terminal ledger row")
        claim_status = result["lifecycle"]["claim_status"]
        updated = connection.execute(
            "UPDATE action_claims_v0 SET status=? WHERE claim_sha256=? AND status='claimed'",
            (claim_status, claim["claim_sha256"]),
        )
        if updated.rowcount != 1:
            raise ValueError("Action Claim terminal transition was not unique")
        connection.execute(
            "INSERT INTO action_results_v0 (execution_sha256,attempt_sha256,mediation_sha256,claim_sha256,"
            "approval_sha256,request_sha256,binding_sha256,capsule_sha256,outcome_sha256,"
            "finalized_at_unix_ms,status,claim_status,result_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                result["execution_sha256"], execution["attempt_sha256"], result["mediation_sha256"],
                result["claim_sha256"], result["approval_sha256"], result["request_sha256"],
                result["request"]["binding"]["binding_sha256"],
                result["request"]["binding"]["capsule_sha256"], result["outcome_sha256"],
                result["finalized_at_unix_ms"], execution["status"], claim_status,
                result["result_sha256"],
            ),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Result was already finalized or the result ledger rejected it") from error
    except (sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(error, ValueError):
            raise
        raise ValueError("Action Result finalization failed: " + str(error)) from error
    finally:
        if connection is not None:
            connection.close()


def _finalize_action_capsule_result_v0(
    approval, request, claim, mediation, execution, manifest, tool_binding, tool_input,
    program_src, wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, finalized_at_unix_ms, public_key_value, ledger_path,
):
    execution_time = execution.get("executed_at_unix_ms") if isinstance(execution, dict) else None
    approval_check = _verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, program_src,
        wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, execution_time, public_key_value,
    )
    if not approval_check["valid"]:
        return _action_result_validation(None, approval_check["findings"])
    findings = _action_claim_findings(claim, approval_check, request, execution_time)
    if isinstance(claim, dict):
        findings.extend(_action_execution_mediation_findings(
            mediation, claim, approval_check, request, execution_time,
        ))
    else:
        findings.extend(_action_mediation_structure_findings(mediation))
    findings.extend(_action_execution_structure_findings(execution))
    if isinstance(execution, dict):
        expected_links = {
            "mediation_sha256": mediation.get("mediation_sha256") if isinstance(mediation, dict) else None,
            "claim_sha256": claim.get("claim_sha256") if isinstance(claim, dict) else None,
            "binding_sha256": request["binding"]["binding_sha256"],
        }
        for key, value in expected_links.items():
            if execution.get(key) != value:
                findings.append({"path": "execution." + key, "code": "execution-link-mismatch", "message": key + " does not match the verified action lifecycle"})
    if findings:
        return _action_result_validation(None, findings)
    outcome = _action_result_outcome(execution)
    claim_status = "completed" if execution["status"] == "completed" else "failed"
    body = {
        "schema": _ACTION_RESULT_SCHEMA,
        "request": request,
        "request_sha256": request["request_sha256"],
        "approval": approval,
        "approval_sha256": approval_check["approval_sha256"],
        "claim": claim,
        "claim_sha256": claim["claim_sha256"],
        "mediation": mediation,
        "mediation_sha256": mediation["mediation_sha256"],
        "execution": execution,
        "execution_sha256": execution["execution_sha256"],
        "outcome": outcome,
        "outcome_sha256": outcome["outcome_sha256"],
        "finalized_at_unix_ms": finalized_at_unix_ms,
        "lifecycle": {
            "schema": _ACTION_RESULT_LIFECYCLE_SCHEMA,
            "terminal": True,
            "claim_status": claim_status,
            "authorization": "none",
            "replay": "denied",
            "remaining_evidence": ["loom-gate-receipt/v4"],
        },
    }
    body["result_sha256"] = _binding_sha256(body)
    validation = validate_action_capsule_result_v0(body, public_key_value)
    if not validation["valid"]:
        return validation
    try:
        _action_result_finalize_once(body, ledger_path)
    except (OSError, ValueError) as error:
        return _action_result_validation(None, [{
            "path": "ledger", "code": "action-result-finalization-failed", "message": str(error),
        }])
    return validation


def finalize_action_capsule_result_v0(
    approval, request, claim, mediation, execution, manifest, tool_binding, tool_input,
    program_src, wasm_bytes, builder_surface, builder_components, verifier_components,
    entrypoint, invocation, finalized_at_unix_ms,
):
    """Finalize one Bounded Execution as a terminal, replay-denied Result v0."""
    try:
        public_key = _action_approval_load_public_key()
    except ValueError as error:
        return _action_result_validation(None, [{
            "path": "public_key", "code": "public-key-unavailable", "message": str(error),
        }])
    return _finalize_action_capsule_result_v0(
        approval, request, claim, mediation, execution, manifest, tool_binding, tool_input,
        program_src, wasm_bytes, builder_surface, builder_components, verifier_components,
        entrypoint, invocation, finalized_at_unix_ms, public_key, _action_claim_ledger_path(),
    )


def _action_attestation_validation(statement, envelope, attester_key_sha256, findings):
    return {
        "schema": _ACTION_ATTESTATION_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "none",
        "statement": statement if not findings else None,
        "envelope": envelope if not findings else None,
        "attester_key_sha256": attester_key_sha256 if not findings else None,
        "findings": findings,
    }


def _action_attestation_pae(payload_type, payload):
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes
        + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )


def _action_attestation_base64_decode(value, path, maximum):
    if not isinstance(value, str):
        return None, [{"path": path, "code": "expected-base64", "message": "expected a Base64 string"}]
    if len(value) > ((maximum + 2) // 3) * 4 + 4:
        return None, [{"path": path, "code": "base64-too-large", "message": "Base64 value exceeds the LOOM attestation bound"}]
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return None, [{"path": path, "code": "invalid-base64", "message": "invalid standard or URL-safe Base64"}]
    if len(decoded) > maximum:
        return None, [{"path": path, "code": "base64-too-large", "message": "decoded value exceeds the LOOM attestation bound"}]
    return decoded, []


def _action_attestation_json(payload):
    def closed_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key: " + key)
            value[key] = item
        return value
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=closed_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant: " + value)),
        )
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        return None, [{"path": "envelope.payload", "code": "invalid-statement-json", "message": str(error)}]
    if not isinstance(value, dict):
        return None, [{"path": "envelope.payload", "code": "expected-statement-object", "message": "in-toto payload must decode to an object"}]
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _ACTION_ATTESTATION_MAX_JSON_NODES:
            return None, [{"path": "envelope.payload", "code": "statement-too-large", "message": "attestation statement exceeds the LOOM JSON node bound"}]
        if depth > _ACTION_ATTESTATION_MAX_JSON_DEPTH:
            return None, [{"path": "envelope.payload", "code": "statement-too-deep", "message": "attestation statement exceeds the LOOM JSON depth bound"}]
        if isinstance(item, dict):
            stack.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
    try:
        canonical = _artifact_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return None, [{"path": "envelope.payload", "code": "non-canonical-statement", "message": "attestation statement must contain canonical JSON values"}]
    if canonical != payload:
        return None, [{"path": "envelope.payload", "code": "non-canonical-statement", "message": "LOOM attestation payload must use canonical UTF-8 JSON"}]
    return value, []


def _action_attestation_cross_links(result, receipt):
    capsule = result["request"]["binding"]["capsule"]
    semantics = capsule["action_semantics"]
    artifact = receipt["artifact_evidence"]
    compiler = receipt["compiler_evidence"]
    links = {
        "schema": _ACTION_ATTESTATION_CROSS_LINKS_SCHEMA,
        "manifest_sha256": capsule["manifest_sha256"],
        "capsule_sha256": result["request"]["binding"]["capsule_sha256"],
        "invocation_sha256": result["request"]["binding"]["invocation_sha256"],
        "approval_sha256": result["approval_sha256"],
        "execution_sha256": result["execution_sha256"],
        "outcome_sha256": result["outcome_sha256"],
        "result_sha256": result["result_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "artifact_binding_sha256": artifact["binding_sha256"],
        "compiler_evidence_sha256": compiler["evidence_sha256"],
    }
    findings = []
    expected_receipt_result = "completed" if result["execution"]["status"] == "completed" else "failed"
    checks = (
        ("gate_receipt.manifest_sha256", receipt["manifest_sha256"], capsule["manifest_sha256"], "attestation-manifest-mismatch"),
        ("gate_receipt.result", receipt["result"], expected_receipt_result, "attestation-result-status-mismatch"),
        ("gate_receipt.actions_observed", receipt["actions_observed"], ["process"], "attestation-observation-mismatch"),
        ("gate_receipt.compiler_evidence", compiler, semantics["compiler_evidence"], "attestation-compiler-evidence-mismatch"),
        ("gate_receipt.compiler_evidence_sha256", receipt["compiler_evidence_sha256"], semantics["compiler_evidence_sha256"], "attestation-compiler-hash-mismatch"),
        ("gate_receipt.artifact_evidence.binding_sha256", artifact["binding_sha256"], semantics["artifact_binding_sha256"], "attestation-artifact-mismatch"),
    )
    for path, actual, expected, code in checks:
        if actual != expected:
            findings.append({"path": path, "code": code, "message": "Action Result and Gate Receipt v4 do not describe the same exact action evidence"})
    return links, findings


def prepare_action_result_attestation_v0(
    result, gate_receipt, manifest, observation, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key, attested_at_unix_ms,
):
    """Prepare a canonical in-toto Statement and DSSE PAE without touching a private key."""
    result_check = validate_action_capsule_result_v0(result, approval_public_key)
    receipt_check = verify_wasm_compiler_receipt_v4(
        gate_receipt, manifest, observation, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
    )
    attester_key, key_findings = _action_approval_validate_public_key(attester_public_key)
    findings = _action_approval_prefixed("action_result", result_check["findings"])
    findings.extend(_compiler_evidence_findings("gate_receipt", receipt_check["findings"]))
    findings.extend(_action_approval_prefixed("attester_public_key", key_findings))
    if type(attested_at_unix_ms) is not int or not 0 <= attested_at_unix_ms <= _BINDING_MAX_SAFE_INTEGER:
        findings.append({"path": "attested_at_unix_ms", "code": "invalid-attestation-time", "message": "attestation time must be a non-negative portable integer"})
    elif result_check["valid"] and attested_at_unix_ms < result["finalized_at_unix_ms"]:
        findings.append({"path": "attested_at_unix_ms", "code": "attestation-before-result", "message": "post-execution attestation cannot predate terminal Result finalization"})
    if findings:
        return _action_attestation_validation(None, None, None, findings)

    links, link_findings = _action_attestation_cross_links(result, gate_receipt)
    if link_findings:
        return _action_attestation_validation(None, None, None, link_findings)
    key_sha256 = _binding_sha256(attester_key)
    wasm_sha256 = gate_receipt["artifact_evidence"]["binding"]["wasm_sha256"]
    predicate = {
        "schema": _ACTION_ATTESTATION_PREDICATE_SCHEMA,
        "attester": {
            "schema": _ACTION_ATTESTATION_ATTESTER_SCHEMA,
            "role": "post-execution-attester",
            "algorithm": attester_key["algorithm"],
            "key_sha256": key_sha256,
        },
        "action_result": result,
        "action_result_sha256": result["result_sha256"],
        "gate_receipt": gate_receipt,
        "gate_receipt_sha256": gate_receipt["receipt_sha256"],
        "cross_links": links,
        "attested_at_unix_ms": attested_at_unix_ms,
        "lifecycle": {
            "schema": _ACTION_ATTESTATION_LIFECYCLE_SCHEMA,
            "terminal": True,
            "evidence": "signed-post-execution",
            "authorization": "none",
            "execution_repeated": False,
        },
    }
    statement = {
        "_type": _ACTION_ATTESTATION_STATEMENT_TYPE,
        "subject": [
            {"name": "loom-action-result.json", "digest": {"sha256": result["result_sha256"]}},
            {"name": "loom-gate-receipt-v4.json", "digest": {"sha256": gate_receipt["receipt_sha256"]}},
            {"name": "loom-program.wasm", "digest": {"sha256": wasm_sha256}},
        ],
        "predicateType": _ACTION_ATTESTATION_PREDICATE_TYPE,
        "predicate": predicate,
    }
    payload = _artifact_json(statement).encode("utf-8")
    pae = _action_attestation_pae(_ACTION_ATTESTATION_PAYLOAD_TYPE, payload)
    validation = _action_attestation_validation(statement, None, key_sha256, [])
    validation.update({
        "payload_type": _ACTION_ATTESTATION_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signing_bytes": base64.b64encode(pae).decode("ascii"),
        "signing_bytes_sha256": hashlib.sha256(pae).hexdigest(),
    })
    return validation


def build_action_result_attestation_v0(
    result, gate_receipt, manifest, observation, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key, attested_at_unix_ms, signature,
):
    """Build one DSSE envelope from an externally produced post-execution signature."""
    prepared = prepare_action_result_attestation_v0(
        result, gate_receipt, manifest, observation, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
        approval_public_key, attester_public_key, attested_at_unix_ms,
    )
    if not prepared["valid"]:
        return prepared
    signature_bytes, findings = _action_attestation_base64_decode(
        signature, "signature", _ACTION_ATTESTATION_MAX_SIGNATURE_BYTES,
    )
    if findings:
        return _action_attestation_validation(None, None, None, findings)
    pae, _ = _action_attestation_base64_decode(
        prepared["signing_bytes"], "signing_bytes", _ACTION_ATTESTATION_MAX_PAYLOAD_BYTES + 1024,
    )
    public_key, key_findings = _action_approval_validate_public_key(attester_public_key)
    if key_findings or not _action_approval_rsa_verify(pae, signature_bytes.hex(), public_key):
        return _action_attestation_validation(None, None, None, [{
            "path": "signature", "code": "invalid-attestation-signature",
            "message": "post-execution DSSE signature is invalid for the attester key",
        }])
    envelope = {
        "payloadType": prepared["payload_type"],
        "payload": prepared["payload"],
        "signatures": [{
            "keyid": prepared["attester_key_sha256"],
            "sig": base64.b64encode(signature_bytes).decode("ascii"),
        }],
    }
    return _action_attestation_validation(
        prepared["statement"], envelope, prepared["attester_key_sha256"], [],
    )


def verify_action_result_attestation_v0(
    envelope, manifest, observation, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, attester_public_key,
):
    """Verify DSSE bytes before parsing one exact in-toto Action Result Statement."""
    if not isinstance(envelope, dict):
        return _action_attestation_validation(None, None, None, [{
            "path": "envelope", "code": "expected-object", "message": "DSSE envelope must be an object",
        }])
    for key in ("payloadType", "payload", "signatures"):
        if key not in envelope:
            return _action_attestation_validation(None, None, None, [{
                "path": "envelope." + key, "code": "missing-field", "message": "DSSE envelope is missing a required field",
            }])
    if envelope.get("payloadType") != _ACTION_ATTESTATION_PAYLOAD_TYPE:
        return _action_attestation_validation(None, None, None, [{
            "path": "envelope.payloadType", "code": "unsupported-payload-type", "message": "expected application/vnd.in-toto+json",
        }])
    payload, findings = _action_attestation_base64_decode(
        envelope.get("payload"), "envelope.payload", _ACTION_ATTESTATION_MAX_PAYLOAD_BYTES,
    )
    if findings:
        return _action_attestation_validation(None, None, None, findings)
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= _ACTION_ATTESTATION_MAX_SIGNATURES:
        return _action_attestation_validation(None, None, None, [{
            "path": "envelope.signatures", "code": "invalid-signature-set", "message": "DSSE envelope requires 1 to 16 signatures",
        }])
    public_key, key_findings = _action_approval_validate_public_key(attester_public_key)
    if key_findings:
        return _action_attestation_validation(
            None, None, None, _action_approval_prefixed("attester_public_key", key_findings),
        )
    pae = _action_attestation_pae(_ACTION_ATTESTATION_PAYLOAD_TYPE, payload)
    signature_valid = False
    for item in signatures:
        if not isinstance(item, dict) or "sig" not in item:
            continue
        signature_bytes, signature_findings = _action_attestation_base64_decode(
            item.get("sig"), "envelope.signatures.sig", _ACTION_ATTESTATION_MAX_SIGNATURE_BYTES,
        )
        if not signature_findings and _action_approval_rsa_verify(pae, signature_bytes.hex(), public_key):
            signature_valid = True
            break
    if not signature_valid:
        return _action_attestation_validation(None, None, None, [{
            "path": "envelope.signatures", "code": "invalid-attestation-signature",
            "message": "no DSSE signature verifies with the trusted attester key",
        }])

    statement, findings = _action_attestation_json(payload)
    if findings:
        return _action_attestation_validation(None, None, None, findings)
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    result = predicate.get("action_result") if isinstance(predicate, dict) else None
    receipt = predicate.get("gate_receipt") if isinstance(predicate, dict) else None
    attested_at = predicate.get("attested_at_unix_ms") if isinstance(predicate, dict) else None
    expected = prepare_action_result_attestation_v0(
        result, receipt, manifest, observation, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
        approval_public_key, attester_public_key, attested_at,
    )
    if not expected["valid"]:
        return expected
    if statement != expected["statement"]:
        return _action_attestation_validation(None, None, None, [{
            "path": "statement", "code": "attestation-statement-mismatch",
            "message": "signed statement does not match the exact Action Result, Gate Receipt, and attester inputs",
        }])
    return _action_attestation_validation(
        statement, envelope, expected["attester_key_sha256"], [],
    )


import loom_component_release as _loom_component_release

_COMPONENT_RELEASE_FRONTEND = _loom_component_release.Frontend(
    build_component_adapter_artifact_v0,
    verify_component_adapter_artifact_v0,
    _loom_component_adapter._builder_source_identity,
    _action_approval_validate_public_key,
    _action_approval_rsa_verify,
)


def build_component_release_reproducibility_v0(
    boundary, program_src, wasm_bytes, package, world, exports=None, *,
    builder_source_root, cargo_executable, rustc_executable, cargo_home,
    wasm_tools_executable, wasmtime_executable,
):
    return _loom_component_release.build_component_release_reproducibility_v0(
        _COMPONENT_RELEASE_FRONTEND, boundary, program_src, wasm_bytes, package,
        world, exports, builder_source_root=builder_source_root,
        cargo_executable=cargo_executable, rustc_executable=rustc_executable,
        cargo_home=cargo_home, wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )


def verify_component_release_reproducibility_v0(
    evidence, component_bytes, boundary, program_src, wasm_bytes, package, world,
    exports=None, *, builder_source_root, cargo_executable, rustc_executable,
    cargo_home, wasm_tools_executable, wasmtime_executable,
):
    return _loom_component_release.verify_component_release_reproducibility_v0(
        _COMPONENT_RELEASE_FRONTEND, evidence, component_bytes, boundary,
        program_src, wasm_bytes, package, world, exports,
        builder_source_root=builder_source_root,
        cargo_executable=cargo_executable, rustc_executable=rustc_executable,
        cargo_home=cargo_home, wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )


def prepare_component_release_attestation_v0(
    evidence, component_bytes, release_name, release_version,
    attester_public_key, attested_at_unix_ms,
):
    return _loom_component_release.prepare_component_release_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, evidence, component_bytes, release_name,
        release_version, attester_public_key, attested_at_unix_ms,
    )


def build_component_release_attestation_v0(
    evidence, component_bytes, release_name, release_version,
    attester_public_key, attested_at_unix_ms, signature,
):
    return _loom_component_release.build_component_release_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, evidence, component_bytes, release_name,
        release_version, attester_public_key, attested_at_unix_ms, signature,
    )


def verify_component_release_attestation_v0(
    envelope, evidence, component_bytes, boundary, program_src, wasm_bytes,
    package, world, exports, release_name, release_version, attester_public_key,
    *, builder_source_root, cargo_executable, rustc_executable, cargo_home,
    wasm_tools_executable, wasmtime_executable,
):
    return _loom_component_release.verify_component_release_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, envelope, evidence, component_bytes,
        boundary, program_src, wasm_bytes, package, world, exports, release_name,
        release_version, attester_public_key,
        builder_source_root=builder_source_root,
        cargo_executable=cargo_executable, rustc_executable=rustc_executable,
        cargo_home=cargo_home, wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )


def build_component_release_federation_v0(
    platform_attestations, component_bytes, release_name, release_version,
):
    return _loom_component_release.build_component_release_federation_v0(
        _COMPONENT_RELEASE_FRONTEND, platform_attestations, component_bytes,
        release_name, release_version,
    )


def prepare_component_release_federation_attestation_v0(
    platform_attestations, component_bytes, release_name, release_version,
    federation_public_key, federated_at_unix_ms,
):
    return _loom_component_release.prepare_component_release_federation_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, platform_attestations, component_bytes,
        release_name, release_version, federation_public_key,
        federated_at_unix_ms,
    )


def build_component_release_federation_attestation_v0(
    platform_attestations, component_bytes, release_name, release_version,
    federation_public_key, federated_at_unix_ms, signature,
):
    return _loom_component_release.build_component_release_federation_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, platform_attestations, component_bytes,
        release_name, release_version, federation_public_key,
        federated_at_unix_ms, signature,
    )


def verify_component_release_federation_attestation_v0(
    envelope, platform_attestations, component_bytes, release_name,
    release_version, federation_public_key,
):
    return _loom_component_release.verify_component_release_federation_attestation_v0(
        _COMPONENT_RELEASE_FRONTEND, envelope, platform_attestations,
        component_bytes, release_name, release_version, federation_public_key,
    )


def collect_observation(manifest, result, actions_observed, evidence):
    """Collect read-only Git facts for a LOOM Gate observation."""
    return _loom_observer.collect_observation(manifest, result, actions_observed, evidence)


def collect_ci_evidence(manifest, observation, run_id):
    """Collect read-only GitHub CI evidence bound to an observed LOOM head."""
    return _loom_evidence.collect_ci_evidence(manifest, observation, run_id)


def build_approval_challenge(manifest, nonce):
    """Build a manifest-bound operator approval challenge."""
    return _loom_approval.build_approval_challenge(manifest, nonce)


def build_approval_request(manifest, challenge):
    """Build a closed approval envelope for an operator-controlled issuer."""
    return _loom_approval.build_approval_request(manifest, challenge)


def validate_approval_request(request):
    """Validate an approval envelope at the operator issuer boundary."""
    return _loom_approval.validate_approval_request(request)


def verify_operator_approval(manifest, challenge, approval):
    """Verify a signed approval against the pinned operator public key."""
    return _loom_approval.verify_operator_approval(manifest, challenge, approval)


def consume_operator_approval(manifest, challenge, approval):
    """Verify and atomically consume a signed one-use operator approval."""
    return _loom_approval.consume_operator_approval(manifest, challenge, approval)


def claim_operator_approval(manifest, challenge, approval):
    """Claim a signed approval before a trusted host starts its action."""
    return _loom_approval.claim_operator_approval(manifest, challenge, approval)


def finish_claimed_receipt(manifest, observation, challenge, approval, claim):
    """Finalize a claimed action exactly once as completed or failed."""
    return _loom_approval.finish_claimed_receipt(manifest, observation, challenge, approval, claim)


def plan_claimed_execution(manifest, challenge, approval, claim, actions):
    """Build a bounded host execution plan for an already claimed approval."""
    return _loom_executor.plan_claimed_execution(manifest, challenge, approval, claim, actions)


def finish_claimed_execution(manifest, challenge, approval, claim, plan, result, actions_observed, evidence):
    """Collect observation facts and finalize a claimed execution plan."""
    return _loom_executor.finish_claimed_execution(manifest, challenge, approval, claim, plan, result, actions_observed, evidence)


def plan_process_execution(manifest, challenge, approval, claim):
    """Build the narrow process-only trusted host plan."""
    return _loom_executor.plan_process_execution(manifest, challenge, approval, claim)


def finish_process_execution(manifest, challenge, approval, claim, plan, result, evidence=None):
    """Finalize a process-only trusted host plan."""
    return _loom_executor.finish_process_execution(manifest, challenge, approval, claim, plan, result, evidence)


def validate_host_attempt(attempt):
    """Validate the closed trusted-host attempt result contract."""
    return _loom_executor.validate_host_attempt(attempt)


def validate_process_attempt(plan, attempt):
    """Dry-run validate a host attempt against a process-only plan."""
    return _loom_executor.validate_process_attempt(plan, attempt)


def finish_process_attempt(manifest, challenge, approval, claim, plan, attempt):
    """Finalize a process-only plan from a validated host attempt object."""
    return _loom_executor.finish_process_attempt(manifest, challenge, approval, claim, plan, attempt)


def build_consumed_receipt(manifest, observation, challenge, approval):
    """Build a receipt after atomically consuming its signed operator approval."""
    return _loom_approval.build_consumed_receipt(manifest, observation, challenge, approval)


def _cli(argv):
    return _loom_cli.cli(argv, _CLI_FRONTEND)

def main(argv=None):
    import sys
    return _cli(sys.argv[1:] if argv is None else argv)

if __name__ == "__main__":
    import sys
    sys.exit(main())
