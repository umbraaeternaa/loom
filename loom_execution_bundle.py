#!/usr/bin/env python3
"""Portable, externally anchored evidence for one effectful Component execution."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json


VALIDATION_SCHEMA = "loom-effectful-component-execution-evidence-bundle-validation/v0"
BUNDLE_SCHEMA = "loom-effectful-component-execution-evidence-bundle/v0"
EVIDENCE_SCHEMA = "loom-effectful-component-execution-evidence-set/v0"
PROGRAM_SCHEMA = "loom-effectful-component-execution-program-bytes/v0"
COMPILER_SCHEMA = "loom-effectful-component-execution-compiler-evidence/v0"
TRUST_MATERIAL_SCHEMA = "loom-effectful-component-execution-trust-material/v0"
LIFECYCLE_SCHEMA = "loom-effectful-component-execution-evidence-bundle-lifecycle/v0"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_WASM_BYTES = 32 * 1024 * 1024
MAX_COMPILER_COMPONENT_BYTES = 8 * 1024 * 1024
MAX_COMPILER_SURFACE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_JSON_NODES = 300_000
MAX_JSON_DEPTH = 200


class Frontend:
    __slots__ = ("verify_attestation",)

    def __init__(self, verify_attestation):
        self.verify_attestation = verify_attestation


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _result(
    bundle=None, bundle_sha256=None, attestation=None, findings=(), *,
    identity_trusted=False,
):
    valid = not findings
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": True,
        "authorization": "none",
        "identity_trusted": bool(valid and identity_trusted),
        "trust_anchor": (
            "external-execution-attester-key-pin"
            if valid and identity_trusted else None
        ),
        "bundle": bundle if valid else None,
        "bundle_sha256": bundle_sha256 if valid else None,
        "execution_attestation": attestation if valid else None,
        "findings": list(findings),
    }


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _validate_json_tree(value, path):
    stack = [(value, path, 0)]
    nodes = 0
    while stack:
        item, item_path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            return [_finding(path, "bundle-too-large", "bundle exceeds the JSON node bound")]
        if depth > MAX_JSON_DEPTH:
            return [_finding(path, "bundle-too-deep", "bundle exceeds the JSON depth bound")]
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    return [_finding(item_path, "non-json-key", "JSON object keys must be strings")]
                stack.append((child, item_path + "." + key, depth + 1))
        elif isinstance(item, list):
            stack.extend(
                (child, item_path + "." + str(index), depth + 1)
                for index, child in enumerate(item)
            )
        elif item is not None and not (
            isinstance(item, str) or type(item) in {int, bool}
        ):
            return [_finding(
                item_path, "non-canonical-json-value",
                "bundle evidence must contain only canonical JSON values",
            )]
    return []


def _json_bytes(value, path="bundle"):
    findings = _validate_json_tree(value, path)
    if findings:
        return None, findings
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None, [_finding(
            path, "non-canonical-json", "bundle evidence cannot be encoded as canonical JSON",
        )]
    if len(encoded) > MAX_BUNDLE_BYTES:
        return None, [_finding(path, "bundle-too-large", "canonical bundle exceeds 64 MiB")]
    return encoded, []


def _encode_bytes(value):
    return base64.b64encode(value).decode("ascii")


def _decode_bytes(value, path, maximum):
    if type(value) is not str:
        return None, [_finding(path, "expected-base64", "expected canonical standard Base64")]
    if len(value) > ((maximum + 2) // 3) * 4 + 4:
        return None, [_finding(path, "base64-too-large", "encoded evidence exceeds its bound")]
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return None, [_finding(path, "invalid-base64", "expected canonical standard Base64")]
    if len(decoded) > maximum:
        return None, [_finding(path, "evidence-too-large", "decoded evidence exceeds its bound")]
    if _encode_bytes(decoded) != value:
        return None, [_finding(path, "non-canonical-base64", "Base64 must use one canonical spelling")]
    return decoded, []


def _prefixed_findings(prefix, check):
    if isinstance(check, dict) and check.get("valid") is True:
        return []
    nested = check.get("findings", ()) if isinstance(check, dict) else ()
    if not nested:
        return [_finding(prefix, "invalid-execution-attestation", "execution attestation failed")]
    return [
        _finding(
            prefix + "." + item.get("path", ""),
            item.get("code", "invalid-execution-attestation"),
            item.get("message", "execution attestation failed"),
        )
        for item in nested
    ]


def _is_sha256(value):
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _closed(value, keys, path):
    if not isinstance(value, dict) or set(value) != set(keys):
        return [_finding(path, "closed-object-mismatch", path + " has missing or unknown fields")]
    return []


def _encode_components(components):
    return {
        path: {
            "encoding": "base64",
            "base64": _encode_bytes(bytes(payload)),
            "sha256": _sha256(bytes(payload)),
        }
        for path, payload in components.items()
    }


def _decode_components(components, path):
    if not isinstance(components, dict):
        return None, [_finding(path, "expected-object", "compiler components must be an object")]
    decoded = {}
    total = 0
    for name, row in components.items():
        if type(name) is not str or not name:
            return None, [_finding(path, "invalid-component-path", "compiler component paths must be non-empty strings")]
        findings = _closed(row, {"encoding", "base64", "sha256"}, path + "." + name)
        if findings:
            return None, findings
        if row.get("encoding") != "base64" or not _is_sha256(row.get("sha256")):
            return None, [_finding(
                path + "." + name, "component-contract-mismatch",
                "compiler component requires canonical Base64 and lowercase SHA-256",
            )]
        payload, findings = _decode_bytes(
            row.get("base64"), path + "." + name + ".base64",
            MAX_COMPILER_COMPONENT_BYTES,
        )
        if findings:
            return None, findings
        if _sha256(payload) != row.get("sha256"):
            return None, [_finding(
                path + "." + name + ".sha256", "component-hash-mismatch",
                "decoded compiler component does not match its evidence hash",
            )]
        total += len(payload)
        if total > MAX_COMPILER_SURFACE_BYTES:
            return None, [_finding(
                path, "compiler-surface-too-large",
                "decoded compiler surface exceeds 32 MiB",
            )]
        decoded[name] = payload
    return decoded, []


def _bundle_core(
    envelope, binding, manifest, observation, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, result_attester_public_key, execution_attester_public_key,
    execution_attester_key_sha256,
):
    source_bytes = program_src.encode("utf-8")
    return {
        "schema": BUNDLE_SCHEMA,
        "execution_attestation": envelope,
        "evidence": {
            "schema": EVIDENCE_SCHEMA,
            "result_binding": binding,
            "manifest": manifest,
            "observation": observation,
            "program": {
                "schema": PROGRAM_SCHEMA,
                "source_encoding": "utf-8-base64",
                "source_base64": _encode_bytes(source_bytes),
                "source_sha256": _sha256(source_bytes),
                "wasm_encoding": "base64",
                "wasm_base64": _encode_bytes(wasm_bytes),
                "wasm_sha256": _sha256(wasm_bytes),
            },
            "compiler": {
                "schema": COMPILER_SCHEMA,
                "builder_surface": builder_surface,
                "builder_components": _encode_components(builder_components),
                "verifier_components": _encode_components(verifier_components),
            },
        },
        "trust_material": {
            "schema": TRUST_MATERIAL_SCHEMA,
            "approval_public_key": approval_public_key,
            "result_attester_public_key": result_attester_public_key,
            "execution_attester_public_key": execution_attester_public_key,
            "execution_attester_key_sha256": execution_attester_key_sha256,
        },
        "lifecycle": {
            "schema": LIFECYCLE_SCHEMA,
            "terminal": True,
            "portable": True,
            "offline_verification": True,
            "external_execution_key_pin_required": True,
            "authorization": "none",
            "execution_repeated": False,
            "private_key_material": False,
            "embedded_key_identity_claim": False,
            "slsa_level_claim": "none",
        },
    }


def build_bundle(
    frontend, envelope, binding, manifest, observation, program_src, wasm_bytes,
    builder_surface, builder_components, verifier_components,
    approval_public_key, result_attester_public_key, execution_attester_public_key,
):
    if type(program_src) is not str:
        return _result(findings=[_finding("evidence.program", "expected-source-text", "program source must be text")])
    try:
        source_bytes = program_src.encode("utf-8")
    except UnicodeEncodeError:
        return _result(findings=[_finding("evidence.program", "invalid-source-unicode", "program source must be valid UTF-8")])
    if len(source_bytes) > MAX_SOURCE_BYTES:
        return _result(findings=[_finding("evidence.program", "source-too-large", "program source exceeds 8 MiB")])
    if type(wasm_bytes) is not bytes:
        return _result(findings=[_finding("evidence.program", "expected-wasm-bytes", "program WASM must be exact bytes")])
    if len(wasm_bytes) > MAX_WASM_BYTES:
        return _result(findings=[_finding("evidence.program", "wasm-too-large", "program WASM exceeds 32 MiB")])
    attestation = frontend.verify_attestation(
        envelope, binding, manifest, observation, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
        approval_public_key, result_attester_public_key, execution_attester_public_key,
    )
    findings = _prefixed_findings("execution_attestation", attestation)
    if findings:
        return _result(findings=findings)
    key_sha256 = attestation.get("attester_key_sha256")
    if not _is_sha256(key_sha256):
        return _result(findings=[_finding(
            "execution_attestation.attester_key_sha256", "invalid-attester-key-id",
            "verified execution attestation did not return one canonical key identity",
        )])
    core = _bundle_core(
        envelope, binding, manifest, observation, program_src, wasm_bytes,
        builder_surface, builder_components, verifier_components,
        approval_public_key, result_attester_public_key, execution_attester_public_key,
        key_sha256,
    )
    encoded, findings = _json_bytes(core)
    if findings:
        return _result(findings=findings)
    bundle_sha256 = _sha256(encoded)
    bundle = dict(core)
    bundle["bundle_sha256"] = bundle_sha256
    return _result(
        bundle=bundle, bundle_sha256=bundle_sha256, attestation=attestation,
    )


def verify_bundle(frontend, bundle, expected_execution_attester_key_sha256):
    if not _is_sha256(expected_execution_attester_key_sha256):
        return _result(findings=[_finding(
            "expected_execution_attester_key_sha256", "external-key-pin-required",
            "verification requires one externally obtained lowercase SHA-256 execution-key pin",
        )])
    findings = _closed(bundle, {
        "schema", "execution_attestation", "evidence", "trust_material", "lifecycle",
        "bundle_sha256",
    }, "bundle")
    if findings:
        return _result(findings=findings)
    if bundle.get("schema") != BUNDLE_SCHEMA:
        return _result(findings=[_finding("bundle.schema", "unsupported-schema", "unsupported execution evidence bundle schema")])
    claimed_sha256 = bundle.get("bundle_sha256")
    if not _is_sha256(claimed_sha256):
        return _result(findings=[_finding("bundle.bundle_sha256", "invalid-bundle-hash", "bundle hash must be lowercase SHA-256")])
    core = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    encoded, findings = _json_bytes(core)
    if findings:
        return _result(findings=findings)
    actual_sha256 = _sha256(encoded)
    if actual_sha256 != claimed_sha256:
        return _result(findings=[_finding("bundle.bundle_sha256", "bundle-hash-mismatch", "bundle content does not match its content address")])

    evidence = bundle.get("evidence")
    trust = bundle.get("trust_material")
    lifecycle = bundle.get("lifecycle")
    findings = _closed(evidence, {
        "schema", "result_binding", "manifest", "observation", "program", "compiler",
    }, "bundle.evidence")
    findings.extend(_closed(trust, {
        "schema", "approval_public_key", "result_attester_public_key",
        "execution_attester_public_key", "execution_attester_key_sha256",
    }, "bundle.trust_material"))
    findings.extend(_closed(lifecycle, {
        "schema", "terminal", "portable", "offline_verification",
        "external_execution_key_pin_required", "authorization", "execution_repeated",
        "private_key_material", "embedded_key_identity_claim", "slsa_level_claim",
    }, "bundle.lifecycle"))
    if findings:
        return _result(findings=findings)
    expected_lifecycle = {
        "schema": LIFECYCLE_SCHEMA,
        "terminal": True,
        "portable": True,
        "offline_verification": True,
        "external_execution_key_pin_required": True,
        "authorization": "none",
        "execution_repeated": False,
        "private_key_material": False,
        "embedded_key_identity_claim": False,
        "slsa_level_claim": "none",
    }
    if evidence.get("schema") != EVIDENCE_SCHEMA or trust.get("schema") != TRUST_MATERIAL_SCHEMA or lifecycle != expected_lifecycle:
        return _result(findings=[_finding(
            "bundle", "bundle-contract-mismatch",
            "evidence, trust material, or lifecycle does not match the closed v0 contract",
        )])
    embedded_key_sha256 = trust.get("execution_attester_key_sha256")
    if embedded_key_sha256 != expected_execution_attester_key_sha256:
        return _result(findings=[_finding(
            "bundle.trust_material.execution_attester_key_sha256", "external-key-pin-mismatch",
            "embedded execution-attester key does not match the external trust pin",
        )])

    program = evidence.get("program")
    compiler = evidence.get("compiler")
    findings = _closed(program, {
        "schema", "source_encoding", "source_base64", "source_sha256",
        "wasm_encoding", "wasm_base64", "wasm_sha256",
    }, "bundle.evidence.program")
    findings.extend(_closed(compiler, {
        "schema", "builder_surface", "builder_components", "verifier_components",
    }, "bundle.evidence.compiler"))
    if findings:
        return _result(findings=findings)
    if (
        program.get("schema") != PROGRAM_SCHEMA
        or program.get("source_encoding") != "utf-8-base64"
        or program.get("wasm_encoding") != "base64"
        or compiler.get("schema") != COMPILER_SCHEMA
    ):
        return _result(findings=[_finding(
            "bundle.evidence", "evidence-contract-mismatch",
            "program or compiler evidence does not match the closed v0 contract",
        )])
    source_bytes, source_findings = _decode_bytes(
        program.get("source_base64"), "bundle.evidence.program.source_base64", MAX_SOURCE_BYTES,
    )
    wasm_bytes, wasm_findings = _decode_bytes(
        program.get("wasm_base64"), "bundle.evidence.program.wasm_base64", MAX_WASM_BYTES,
    )
    findings = source_findings + wasm_findings
    if findings:
        return _result(findings=findings)
    if program.get("source_sha256") != _sha256(source_bytes) or program.get("wasm_sha256") != _sha256(wasm_bytes):
        return _result(findings=[_finding(
            "bundle.evidence.program", "program-bytes-hash-mismatch",
            "decoded source or WASM bytes do not match their evidence hash",
        )])
    try:
        program_src = source_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return _result(findings=[_finding(
            "bundle.evidence.program.source_base64", "invalid-source-utf8",
            "decoded program source is not strict UTF-8",
        )])
    builder_components, builder_findings = _decode_components(
        compiler.get("builder_components"),
        "bundle.evidence.compiler.builder_components",
    )
    verifier_components, verifier_findings = _decode_components(
        compiler.get("verifier_components"),
        "bundle.evidence.compiler.verifier_components",
    )
    findings = builder_findings + verifier_findings
    if findings:
        return _result(findings=findings)

    attestation = frontend.verify_attestation(
        bundle.get("execution_attestation"), evidence.get("result_binding"),
        evidence.get("manifest"), evidence.get("observation"), program_src, wasm_bytes,
        compiler.get("builder_surface"), builder_components,
        verifier_components, trust.get("approval_public_key"),
        trust.get("result_attester_public_key"), trust.get("execution_attester_public_key"),
    )
    findings = _prefixed_findings("execution_attestation", attestation)
    if findings:
        return _result(findings=findings)
    if attestation.get("attester_key_sha256") != expected_execution_attester_key_sha256:
        return _result(findings=[_finding(
            "execution_attestation.attester_key_sha256", "verified-key-pin-mismatch",
            "verified signature key does not match the external trust pin",
        )])
    return _result(
        bundle=bundle, bundle_sha256=claimed_sha256, attestation=attestation,
        identity_trusted=True,
    )
