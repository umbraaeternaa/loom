#!/usr/bin/env python3
"""Closed, non-authorizing LOOM effect-to-WASI capability projection v0."""

from __future__ import annotations

import hashlib
import json
import re


SCHEMA = "loom-typed-wasi-capability-mapping/v0"
VALIDATION_SCHEMA = "loom-typed-wasi-capability-mapping-validation/v0"
PROJECTION_SCHEMA = "loom-wasi-effect-projection/v0"
TRANSPORT_SCHEMA = "loom-canonical-json-utf8/v0"
WASI_RELEASE = "0.2.8"
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
_SUPPORTED_EFFECTS = frozenset(("IO", "Rand", "Alloc"))
_DENIED_EFFECTS = frozenset(("Net", "FFI"))

_SPEC_SOURCES = {
    "wasi:io/error@0.2.8": [{
        "repository": "https://github.com/WebAssembly/wasi-io",
        "tag": "v0.2.8", "path": "wit/error.wit",
        "sha256": "55c598b16829f7dfcd3fd373d96dd86ef0373d9354745436a61c2d3832791e11",
    }],
    "wasi:cli/stdout@0.2.8": [
        {
            "repository": "https://github.com/WebAssembly/wasi-cli",
            "tag": "v0.2.8", "path": "wit/command.wit",
            "sha256": "bd407a235c57d06d9337df7ded7608fb006a9bf9959c20d0296b3608e39b0304",
        },
        {
            "repository": "https://github.com/WebAssembly/wasi-cli",
            "tag": "v0.2.8", "path": "wit/stdio.wit",
            "sha256": "f43b2af1349fb01758d0e3b61f84d45163116d918421ba00af2f9d8e7c11131b",
        },
    ],
    "wasi:io/streams@0.2.8": [{
        "repository": "https://github.com/WebAssembly/wasi-io",
        "tag": "v0.2.8", "path": "wit/streams.wit",
        "sha256": "f0c0932aaf39a7a318b765b985f030380988284e8c9cf592494a08aa899d9bad",
    }],
    "wasi:random/random@0.2.8": [{
        "repository": "https://github.com/WebAssembly/wasi-random",
        "tag": "v0.2.8", "path": "wit/random.wit",
        "sha256": "a7aa818ca7f252e87670ac6e0ef749eaba8cb85870701a19933c813bc28c6e51",
    }],
}

_EFFECT_PROJECTIONS = {
    "IO": {
        "effect": "IO",
        "loom_operation": "print",
        "disposition": "wasi-import",
        "imports": [
            "wasi:cli/stdout@0.2.8", "wasi:io/error@0.2.8",
            "wasi:io/streams@0.2.8",
        ],
        "calls": [
            "wasi:cli/stdout.get-stdout",
            "wasi:io/streams.output-stream.blocking-write-and-flush",
        ],
        "payload": "canonical loom value JSON bytes; no implicit stderr or filesystem",
        "resource_lifecycle": "get output-stream per effect; blocking write+flush; drop before return",
    },
    "Rand": {
        "effect": "Rand",
        "loom_operation": "rand",
        "disposition": "wasi-import",
        "imports": ["wasi:random/random@0.2.8"],
        "calls": ["wasi:random/random.get-random-u64"],
        "result_projection": {
            "source": "u64", "target": "nonnegative-i31",
            "rule": "u64 modulo 1073741824", "uniform": True,
        },
        "resource_lifecycle": "none",
    },
    "Alloc": {
        "effect": "Alloc",
        "loom_operation": "alloc",
        "disposition": "internal-runtime",
        "imports": [],
        "calls": ["loom.$reserve"],
        "authority": "none",
        "resource_lifecycle": "private fixed-page linear memory; memory.grow forbidden",
    },
}


class Frontend:
    __slots__ = (
        "parse", "check", "compile_wasm", "verify_trust_receipt",
        "verify_trust_receipt_v2", "abi_version", "error",
    )

    def __init__(
        self, parse, check, compile_wasm, verify_trust_receipt,
        verify_trust_receipt_v2, abi_version, error,
    ):
        self.parse = parse
        self.check = check
        self.compile_wasm = compile_wasm
        self.verify_trust_receipt = verify_trust_receipt
        self.verify_trust_receipt_v2 = verify_trust_receipt_v2
        self.abi_version = abi_version
        self.error = error


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _validation(mapping, findings):
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": not findings,
        "mapping": mapping if not findings else None,
        "findings": list(findings),
    }


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _clone(value):
    return json.loads(_json_bytes(value).decode("ascii"))


def _wit_name(name):
    candidate = name.replace("_", "-")
    if not _WIT_ID.fullmatch(candidate) or candidate in _WIT_RESERVED:
        return None
    return candidate


def _validate_identity(package, world, findings):
    if not isinstance(package, str) or not _PACKAGE.fullmatch(package):
        findings.append(_finding(
            "package", "invalid-wit-package",
            "package must be lowercase namespace:name@major.minor.patch WIT identity",
        ))
    if not isinstance(world, str) or not _WIT_ID.fullmatch(world) or world in _WIT_RESERVED:
        findings.append(_finding(
            "world", "invalid-wit-world", "world must be a lowercase WIT kebab identifier",
        ))


def _checked_program(frontend, source, wasm_bytes, findings):
    if not isinstance(source, str):
        findings.append(_finding("source", "expected-string", "source must be a string"))
        return None, None, None
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeEncodeError:
        findings.append(_finding("source", "invalid-utf8", "source must encode as valid UTF-8"))
        return None, None, None
    if len(source_bytes) > MAX_SOURCE_BYTES:
        findings.append(_finding("source", "source-too-large", "source exceeds the 1 MiB v0 limit"))
        return None, None, None
    try:
        program = frontend.parse(source)
        functions, errors = frontend.check(program)
    except frontend.error as exc:
        findings.append(_finding("source", "parse-rejected", str(exc)))
        return None, None, None
    if errors:
        findings.append(_finding("source", "checker-rejected", "; ".join(errors)))
        return None, None, None
    if not isinstance(wasm_bytes, (bytes, bytearray)):
        findings.append(_finding("core_module", "expected-bytes", "core WebAssembly must be bytes"))
        return program, functions, None
    wasm = bytes(wasm_bytes)
    if len(wasm) > MAX_WASM_BYTES:
        findings.append(_finding("core_module", "wasm-too-large", "core WebAssembly exceeds the 16 MiB v0 limit"))
        return program, functions, None
    try:
        expected = frontend.compile_wasm(source)
    except frontend.error as exc:
        findings.append(_finding("core_module", "compile-rejected", str(exc)))
        return program, functions, None
    if wasm != expected:
        findings.append(_finding(
            "core_module", "source-wasm-mismatch",
            "core WebAssembly is not byte-identical to deterministic ABI v2 compilation",
        ))
        return program, functions, None
    for path, verifier in (
        ("core_module.trust.v1", frontend.verify_trust_receipt),
        ("core_module.trust.v2", frontend.verify_trust_receipt_v2),
    ):
        result = verifier(source, wasm)
        if not result.get("valid"):
            findings.append(_finding(
                path, "trust-receipt-rejected", "; ".join(result.get("findings", ())),
            ))
    return program, functions, wasm


def _effect_set(info, key):
    return sorted(set(info.get(key, ())) - {"Pure"})


def _selected_exports(program, functions, exports, findings):
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

    rows = []
    seen_wit = set()
    for name in selected:
        if name not in functions:
            findings.append(_finding(f"exports.{name}", "unknown-export", "export does not name a checked top-level defx"))
            continue
        info = functions[name]
        fn = info.get("fn")
        params = fn[1] if isinstance(fn, list) and len(fn) >= 2 and isinstance(fn[1], list) else None
        if params is None or any(isinstance(param, list) for param in params):
            findings.append(_finding(
                f"exports.{name}.params", "non-value-parameter-denied",
                "Typed WASI v0 does not transport higher-order or linear parameters",
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
        declared = _effect_set(info, "decl")
        performed = _effect_set(info, "eff")
        required = _effect_set(info, "req")
        effects = sorted(set(declared) | set(performed) | set(required))
        denied = sorted(set(effects) & _DENIED_EFFECTS)
        unknown = sorted(set(effects) - _SUPPORTED_EFFECTS - _DENIED_EFFECTS)
        if denied:
            findings.append(_finding(
                f"exports.{name}.effects", "unmapped-wasi-effect",
                "Typed WASI v0 refuses effects without exact portable semantics: " + ", ".join(denied),
            ))
            continue
        if unknown:
            findings.append(_finding(
                f"exports.{name}.effects", "unknown-wasi-effect",
                "effect is outside the closed Typed WASI v0 set: " + ", ".join(unknown),
            ))
            continue
        rows.append({
            "loom_name": name,
            "wit_name": wit_name,
            "arity": len(params),
            "effects": {
                "declared": declared, "performed": performed, "required": required,
                "projected": effects,
            },
            "request": "list<u8>:loom-canonical-json-utf8/v0",
            "result": "result<list<u8>,list<u8>>:loom-canonical-json-utf8/v0",
        })
    if not rows and not findings:
        findings.append(_finding("exports", "empty-boundary", "mapping must export at least one checked entrypoint"))
    if rows and not any(row["effects"]["projected"] for row in rows):
        findings.append(_finding(
            "exports", "empty-capability-projection",
            "all-Pure exports belong to WIT Component Boundary v0, not Typed WASI v0",
        ))
    return sorted(rows, key=lambda item: item["wit_name"])


def _projection(exports):
    effects = sorted({effect for row in exports for effect in row["effects"]["projected"]})
    imports = sorted({
        name for effect in effects for name in _EFFECT_PROJECTIONS[effect]["imports"]
    })
    specs = [
        {"interface": name, "sources": _clone(_SPEC_SOURCES[name])}
        for name in imports
    ]
    return {
        "schema": PROJECTION_SCHEMA,
        "wasi_release": WASI_RELEASE,
        "effects": [_clone(_EFFECT_PROJECTIONS[effect]) for effect in effects],
        "imports": imports,
        "spec_sources": specs,
        "denied_effects": ["FFI", "Net"],
        "ambient_authority": False,
    }


def _emit_wit(package, world, projection, exports):
    lines = [f"package {package};", "", f"world {world} {{"]
    for name in projection["imports"]:
        lines.append(f"  import {name};")
    if projection["imports"]:
        lines.append("")
    for item in exports:
        lines.append(
            f"  export {item['wit_name']}: func(request: list<u8>) -> result<list<u8>, list<u8>>;"
        )
    lines += ["}", ""]
    return "\n".join(lines)


def build_typed_wasi_capability_mapping_v0(
    frontend, source, wasm_bytes, package, world, exports=None,
):
    """Build a closed effect-to-WASI projection without building or authorizing a component."""
    findings = []
    if frontend.abi_version != 2:
        findings.append(_finding("core_module.loom_abi_version", "abi-v2-required", "Typed WASI v0 requires LOOM ABI v2"))
    _validate_identity(package, world, findings)
    program, functions, wasm = _checked_program(frontend, source, wasm_bytes, findings)
    selected = _selected_exports(program, functions, exports, findings) if program is not None else []
    if findings:
        return _validation(None, findings)
    projection = _projection(selected)
    wit_source = _emit_wit(package, world, projection, selected)
    body = {
        "schema": SCHEMA,
        "advisory": False,
        "authorization": "none",
        "source": {"sha256": _sha256(source.encode("utf-8")), "checker": "accepted"},
        "core_module": {
            "format": "core-webassembly/v1",
            "sha256": _sha256(wasm),
            "loom_abi_version": 2,
            "required_adapter_imports": list(_CORE_IMPORTS),
        },
        "wit": {
            "package": package, "world": world,
            "source": wit_source, "sha256": _sha256(wit_source.encode("utf-8")),
        },
        "exports": selected,
        "capability_projection": projection,
        "transport": {
            "schema": TRANSPORT_SCHEMA,
            "encoding": "canonical-json", "character_encoding": "utf-8",
            "request_shape": {"args": "array"},
            "success_shape": {"ok": "loom-value"},
            "error_shape": {"error": {"code": "string", "message": "string"}},
            "max_envelope_bytes": MAX_ENVELOPE_BYTES,
        },
        "lifecycle": {
            "component_binary": "absent",
            "effect_adapter": "required",
            "executable": False,
            "authorization": "none",
            "host_policy_binding": "required-before-instantiation",
        },
    }
    body["mapping_sha256"] = _sha256(_json_bytes(body))
    return _validation(body, [])


def verify_typed_wasi_capability_mapping_v0(
    frontend, mapping, source, wasm_bytes, package, world, exports=None,
):
    """Rebuild the exact mapping and reject hash, input, schema, or policy drift."""
    expected_result = build_typed_wasi_capability_mapping_v0(
        frontend, source, wasm_bytes, package, world, exports,
    )
    if not expected_result["valid"]:
        return expected_result
    if not isinstance(mapping, dict):
        return _validation(None, [_finding("mapping", "expected-object", "mapping must be an object")])
    supplied_body = dict(mapping)
    supplied_hash = supplied_body.pop("mapping_sha256", None)
    findings = []
    try:
        actual_hash = _sha256(_json_bytes(supplied_body))
    except (TypeError, ValueError):
        actual_hash = None
    if supplied_hash != actual_hash:
        findings.append(_finding(
            "mapping.mapping_sha256", "mapping-hash-mismatch",
            "mapping hash does not match canonical mapping bytes",
        ))
    if mapping != expected_result["mapping"]:
        findings.append(_finding(
            "mapping", "mapping-mismatch",
            "mapping does not match the exact source, ABI v2 core, exports, WIT identity, or WASI policy",
        ))
    return _validation(mapping if not findings else None, findings)
