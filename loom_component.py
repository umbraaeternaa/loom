#!/usr/bin/env python3
"""Evidence-carrying WIT boundary for checked LOOM core WebAssembly modules."""

import hashlib
import json
import re


SCHEMA = "loom-wit-component-boundary/v0"
VALIDATION_SCHEMA = "loom-wit-component-boundary-validation/v0"
TRANSPORT_SCHEMA = "loom-canonical-json-utf8/v0"
MAX_SOURCE_BYTES = 1 << 20
MAX_WASM_BYTES = 16 << 20
MAX_EXPORTS = 128
MAX_ARITY = 32
MAX_ENVELOPE_BYTES = 1 << 20

_PACKAGE = re.compile(
    r"^[a-z][a-z0-9-]{0,62}:[a-z][a-z0-9-]{0,62}@[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_WIT_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_WIT_RESERVED = {
    "as", "constructor", "enum", "export", "flags", "from", "func", "future",
    "import", "include", "interface", "list", "option", "package", "record",
    "resource", "result", "static", "stream", "tuple", "type", "use", "variant",
    "with", "world",
}
_CORE_IMPORTS = (
    "env.push_handler", "env.pop_handler", "env.current_handler", "env.host_print",
    "env.push_caps", "env.pop_caps", "env.has_cap", "env.host_ffi",
)


class Frontend:
    __slots__ = (
        "parse", "check", "pname", "compile_wasm", "verify_trust_receipt",
        "verify_trust_receipt_v2", "abi_version", "error",
    )

    def __init__(
        self, parse, check, pname, compile_wasm, verify_trust_receipt,
        verify_trust_receipt_v2, abi_version, error,
    ):
        self.parse = parse
        self.check = check
        self.pname = pname
        self.compile_wasm = compile_wasm
        self.verify_trust_receipt = verify_trust_receipt
        self.verify_trust_receipt_v2 = verify_trust_receipt_v2
        self.abi_version = abi_version
        self.error = error


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _validation(boundary, findings):
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": not findings,
        "boundary": boundary if not findings else None,
        "findings": findings,
    }


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _wit_name(name):
    candidate = name.replace("_", "-")
    if not _WIT_ID.fullmatch(candidate) or candidate in _WIT_RESERVED:
        return None
    return candidate


def _checked_program(frontend, program_src, findings):
    if not isinstance(program_src, str):
        findings.append(_finding("source", "expected-string", "source must be a string"))
        return None, None
    try:
        source_bytes = program_src.encode("utf-8")
    except UnicodeEncodeError:
        findings.append(_finding("source", "invalid-utf8", "source must encode as valid UTF-8"))
        return None, None
    if len(source_bytes) > MAX_SOURCE_BYTES:
        findings.append(_finding("source", "source-too-large", "source exceeds the 1 MiB v0 limit"))
        return None, None
    try:
        program = frontend.parse(program_src)
        functions, errors = frontend.check(program)
    except frontend.error as exc:
        findings.append(_finding("source", "parse-rejected", str(exc)))
        return None, None
    if errors:
        findings.append(_finding("source", "checker-rejected", "; ".join(errors)))
        return None, None
    return program, functions


def _checked_wasm(frontend, program_src, wasm_bytes, findings):
    if not isinstance(wasm_bytes, (bytes, bytearray)):
        findings.append(_finding("core_module", "expected-bytes", "core WebAssembly must be bytes"))
        return None
    wasm = bytes(wasm_bytes)
    if len(wasm) > MAX_WASM_BYTES:
        findings.append(_finding("core_module", "wasm-too-large", "core WebAssembly exceeds the 16 MiB v0 limit"))
        return None
    try:
        expected = frontend.compile_wasm(program_src)
    except frontend.error as exc:
        findings.append(_finding("core_module", "compile-rejected", str(exc)))
        return None
    if wasm != expected:
        findings.append(_finding(
            "core_module", "source-wasm-mismatch",
            "core WebAssembly is not byte-identical to deterministic compilation of the supplied source",
        ))
        return None
    for path, verify in (
        ("core_module.trust.v1", frontend.verify_trust_receipt),
        ("core_module.trust.v2", frontend.verify_trust_receipt_v2),
    ):
        result = verify(program_src, wasm)
        if not result.get("valid"):
            findings.append(_finding(path, "trust-receipt-rejected", "; ".join(result.get("findings", ()))))
    return wasm


def _selected_exports(frontend, program, functions, exports, findings):
    ordered = [
        str(node[1]) for node in program
        if isinstance(node, list) and len(node) >= 4 and str(node[0]) == "defx"
    ]
    if exports is None:
        selected = ordered
    elif not isinstance(exports, (list, tuple)):
        findings.append(_finding("exports", "expected-list", "exports must be a list of LOOM function names"))
        return []
    else:
        selected = list(exports)
    if len(selected) > MAX_EXPORTS:
        findings.append(_finding("exports", "too-many-exports", "v0 permits at most 128 exports"))
        return []
    if any(not isinstance(name, str) for name in selected):
        findings.append(_finding("exports", "expected-name", "every export must be a string"))
        return []
    if len(set(selected)) != len(selected):
        findings.append(_finding("exports", "duplicate-export", "exports must not contain duplicates"))
        return []

    result = []
    seen_wit = set()
    for name in selected:
        if name not in functions:
            findings.append(_finding(f"exports.{name}", "unknown-export", "export does not name a checked top-level defx"))
            continue
        info = functions[name]
        effects = sorted((set(info.get("decl", ())) | set(info.get("eff", ())) | set(info.get("req", ()))) - {"Pure"})
        if effects:
            findings.append(_finding(
                f"exports.{name}.effects", "effectful-export-denied",
                "WIT boundary v0 exports Pure entrypoints only; effectful imports require a future explicit capability projection",
            ))
            continue
        fn = info.get("fn")
        params = fn[1] if isinstance(fn, list) and len(fn) >= 2 and isinstance(fn[1], list) else None
        if params is None or any(isinstance(param, list) for param in params):
            findings.append(_finding(
                f"exports.{name}.params", "non-value-parameter-denied",
                "v0 does not transport higher-order or linear parameters across the component boundary",
            ))
            continue
        if len(params) > MAX_ARITY:
            findings.append(_finding(f"exports.{name}.params", "arity-too-large", "v0 permits at most 32 arguments"))
            continue
        wit_name = _wit_name(name)
        if wit_name is None:
            findings.append(_finding(
                f"exports.{name}.wit_name", "invalid-wit-identifier",
                "export name must map uniquely to a lowercase WIT kebab identifier",
            ))
            continue
        if wit_name in seen_wit:
            findings.append(_finding(f"exports.{name}.wit_name", "wit-name-collision", "two LOOM exports map to one WIT name"))
            continue
        seen_wit.add(wit_name)
        result.append({
            "loom_name": name,
            "wit_name": wit_name,
            "arity": len(params),
            "effects": [],
            "request": "list<u8>:loom-canonical-json-utf8/v0",
            "result": "result<list<u8>,list<u8>>:loom-canonical-json-utf8/v0",
        })
    if not result and not findings:
        findings.append(_finding("exports", "empty-boundary", "component boundary must export at least one Pure entrypoint"))
    return sorted(result, key=lambda item: item["wit_name"])


def _validate_identity(package, world, findings):
    if not isinstance(package, str) or not _PACKAGE.fullmatch(package):
        findings.append(_finding(
            "package", "invalid-wit-package",
            "package must be lowercase namespace:name@major.minor.patch WIT identity",
        ))
    if not isinstance(world, str) or not _WIT_ID.fullmatch(world) or world in _WIT_RESERVED:
        findings.append(_finding("world", "invalid-wit-world", "world must be a lowercase WIT kebab identifier"))


def _emit_wit(package, world, exports):
    lines = [f"package {package};", "", f"world {world} {{"]
    for item in exports:
        lines.append(
            f"  export {item['wit_name']}: func(request: list<u8>) -> result<list<u8>, list<u8>>;"
        )
    lines += ["}", ""]
    return "\n".join(lines)


def build_wit_component_boundary_v0(frontend, program_src, wasm_bytes, package, world, exports=None):
    """Bind checked Pure LOOM exports to deterministic WIT without claiming an adapter exists."""
    findings = []
    _validate_identity(package, world, findings)
    program, functions = _checked_program(frontend, program_src, findings)
    wasm = _checked_wasm(frontend, program_src, wasm_bytes, findings) if program is not None else None
    selected = _selected_exports(frontend, program, functions, exports, findings) if program is not None else []
    if findings:
        return _validation(None, findings)

    wit_source = _emit_wit(package, world, selected)
    body = {
        "schema": SCHEMA,
        "advisory": False,
        "source": {
            "sha256": _sha256(program_src.encode("utf-8")),
            "checker": "accepted",
        },
        "core_module": {
            "format": "core-webassembly/v1",
            "sha256": _sha256(wasm),
            "loom_abi_version": frontend.abi_version,
            "required_adapter_imports": list(_CORE_IMPORTS),
        },
        "wit": {
            "package": package,
            "world": world,
            "source": wit_source,
            "sha256": _sha256(wit_source.encode("utf-8")),
        },
        "exports": selected,
        "capability_projection": {
            "mode": "pure-only",
            "wasi_release": "0.2",
            "imports": [],
        },
        "transport": {
            "schema": TRANSPORT_SCHEMA,
            "encoding": "canonical-json",
            "character_encoding": "utf-8",
            "request_shape": {"args": "array"},
            "success_shape": {"ok": "loom-value"},
            "error_shape": {"error": {"code": "string", "message": "string"}},
            "value_domain": ["i31", "boolean", "string", "list", "record", "variant"],
            "variant_shape": {"$variant": ["tag", "value"]},
            "forbidden_values": ["closure", "resource", "effect-box", "float", "null"],
            "canonicalization": {
                "object_keys": "unicode-codepoint-order",
                "whitespace": "none",
                "non_ascii": "escaped",
                "numbers": "signed-i31-only",
            },
            "max_envelope_bytes": MAX_ENVELOPE_BYTES,
        },
        "lifecycle": {
            "component_binary": "absent",
            "adapter": "required",
            "executable": False,
            "authorization": "none",
        },
    }
    body["boundary_sha256"] = _sha256(_json_bytes(body))
    return _validation(body, [])


def verify_wit_component_boundary_v0(frontend, boundary, program_src, wasm_bytes, package, world, exports=None):
    """Rebuild the closed boundary from exact inputs and reject every mismatch."""
    if not isinstance(boundary, dict):
        return _validation(None, [_finding("boundary", "expected-object", "boundary must be an object")])
    expected_result = build_wit_component_boundary_v0(
        frontend, program_src, wasm_bytes, package, world, exports,
    )
    if not expected_result["valid"]:
        return expected_result
    expected = expected_result["boundary"]
    supplied_body = dict(boundary)
    supplied_hash = supplied_body.pop("boundary_sha256", None)
    findings = []
    try:
        actual_hash = _sha256(_json_bytes(supplied_body))
    except (TypeError, ValueError):
        actual_hash = None
    if supplied_hash != actual_hash:
        findings.append(_finding("boundary_sha256", "boundary-hash-mismatch", "boundary hash does not match canonical boundary bytes"))
    if boundary != expected:
        findings.append(_finding(
            "boundary", "boundary-mismatch",
            "boundary does not match the exact source, core module, WIT identity, exports, or v0 policy",
        ))
    return _validation(boundary if not findings else None, findings)
