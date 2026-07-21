#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + REQUIRED effects `E!` (two-sided row:
# floor MUST-perform <= actual <= ceiling MAY-perform -> the row IS the D7 synthesis contract) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
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
_GATE_COMPILER_SURFACE = "modular-python"
_WASM_FRONTEND = _loom_wasm.Frontend(parse, parse_spans, check, pname, LoomError, OP, _check_call_literals, platent, _roleclauses)

def compile_wasm(program_src):
    return _loom_wasm.compile_wasm(program_src, _WASM_FRONTEND)

def verify_wasm_trust_receipt(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_trust_receipt_v2(program_src, wasm_bytes):
    return _loom_wasm.verify_trust_receipt_v2(program_src, wasm_bytes, _WASM_FRONTEND)

def verify_wasm_source_equivalence(program_src, wasm_bytes):
    return _loom_wasm.verify_source_equivalence(program_src, wasm_bytes, _WASM_FRONTEND)

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
        "citadel_checks": 489,
        "wasm_abi_version": _WASM_ABI_VERSION,
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
