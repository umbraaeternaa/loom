#!/usr/bin/env python3
"""Host-only binding from a verified Effectful Component to an Action lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata


SCHEMA = "loom-effectful-component-execution-binding/v0"
VALIDATION_SCHEMA = "loom-effectful-component-execution-binding-validation/v0"
RESOURCE_SCHEMA = "loom-effectful-component-resource-measurement/v0"
CROSS_LINKS_SCHEMA = "loom-effectful-component-execution-links/v0"
LIFECYCLE_SCHEMA = "loom-effectful-component-execution-lifecycle/v0"
REQUIRED_NEXT = "loom-effectful-component-host-execution/v0"
MAX_COMPONENT_BYTES = 16 * 1024 * 1024
class Frontend:
    __slots__ = (
        "verify_component", "validate_request", "validate_mediation",
        "resolve_file_uri", "open_path", "stat_identity", "verify_ledger",
    )

    def __init__(
        self, verify_component, validate_request, validate_mediation,
        resolve_file_uri, open_path, stat_identity, verify_ledger,
    ):
        self.verify_component = verify_component
        self.validate_request = validate_request
        self.validate_mediation = validate_mediation
        self.resolve_file_uri = resolve_file_uri
        self.open_path = open_path
        self.stat_identity = stat_identity
        self.verify_ledger = verify_ledger


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _linked_validation_findings(boundary, validation):
    nested = validation.get("findings") if isinstance(validation, dict) else None
    if not isinstance(nested, list) or not nested:
        return [_finding(
            "binding." + boundary,
            boundary + "-validation-rejected",
            boundary + " validation failed without structured findings",
        )]
    findings = []
    for index, item in enumerate(nested):
        if not isinstance(item, dict):
            findings.append(_finding(
                f"binding.{boundary}.findings[{index}]",
                boundary + "-invalid-finding",
                boundary + " validation returned a non-object finding",
            ))
            continue
        path = item.get("path")
        code = item.get("code")
        message = item.get("message")
        if not all(isinstance(value, str) and value for value in (path, code, message)):
            findings.append(_finding(
                f"binding.{boundary}.findings[{index}]",
                boundary + "-invalid-finding",
                boundary + " validation returned a malformed finding",
            ))
            continue
        findings.append(_finding(
            "binding." + boundary + "." + path, code, message,
        ))
    return findings


def _result(binding=None, findings=()):
    valid = not findings
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": False,
        "authorization": "none",
        "binding": binding if valid else None,
        "binding_sha256": binding.get("binding_sha256") if valid else None,
        "findings": list(findings),
    }


def _measure_component(frontend, component_uri, component_bytes):
    path = frontend.resolve_file_uri(component_uri, "component_uri")
    fd = frontend.open_path(path, False)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("effectful Component resource must be a regular file")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("effectful Component resource must not be group/world-writable")
        if before.st_size > MAX_COMPONENT_BYTES:
            raise ValueError("effectful Component resource exceeds the 16 MiB binding limit")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_COMPONENT_BYTES:
                raise ValueError("effectful Component changed beyond the binding size limit")
            digest.update(chunk)
        after = os.fstat(fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable) or total != after.st_size:
            raise ValueError("effectful Component changed while it was measured")
        supplied = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else None
        if supplied is None or len(supplied) != total or _sha256(supplied) != digest.hexdigest():
            raise ValueError("effectful Component URI bytes differ from the verified Component bytes")
        body = {
            "schema": RESOURCE_SCHEMA,
            "uri": component_uri,
            "component_sha256": digest.hexdigest(),
            "byte_length": total,
            "identity": frontend.stat_identity(after, "regular-file"),
            "measurement": "descriptor-relative-no-follow-sha256/v0",
        }
        body["measurement_sha256"] = _sha256(_json_bytes(body))
        return body, path
    finally:
        os.close(fd)


def _selected_export(mapping, export):
    if not isinstance(export, str) or not export:
        raise ValueError("export must be one selected LOOM or WIT export name")
    matches = [
        item for item in mapping.get("exports", ())
        if isinstance(item, dict) and export in {item.get("loom_name"), item.get("wit_name")}
    ]
    if len(matches) != 1:
        raise ValueError("export must select exactly one export from the verified mapping")
    item = matches[0]
    return {"loom_name": item["loom_name"], "wit_name": item["wit_name"]}


def _request_body(component_request, transport):
    if not isinstance(component_request, dict) or set(component_request) != {"args"}:
        raise ValueError("component_request must be the closed {'args': [...]} envelope")
    args = component_request.get("args")
    if not isinstance(args, list) or len(args) > transport.get("max_args", -1):
        raise ValueError("component_request args exceed the verified transport arity")
    encoded = _json_bytes(component_request)
    if len(encoded) > transport.get("max_envelope_bytes", -1):
        raise ValueError("component_request exceeds the verified transport byte limit")
    return encoded


def _committed_environment(invocation, environment_values, expected):
    if not isinstance(environment_values, dict):
        raise ValueError("environment_values must be an exact name-to-string object")
    normalized = {}
    for name, value in environment_values.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("environment_values names and values must be strings")
        normalized_name = unicodedata.normalize("NFC", name)
        normalized_value = unicodedata.normalize("NFC", value)
        if normalized_name != name or normalized_value != value or "\x00" in name or "\x00" in value:
            raise ValueError("environment_values must use canonical NFC text without NUL")
        if normalized_name in normalized:
            raise ValueError("environment_values names collide")
        normalized[normalized_name] = normalized_value
    if normalized != expected:
        raise ValueError("environment_values do not equal the closed Effectful Component commitments")
    commitments = invocation.get("environment")
    expected_commitments = [
        {"name": name, "value_sha256": _sha256(value.encode("utf-8"))}
        for name, value in sorted(expected.items())
    ]
    if commitments != expected_commitments:
        raise ValueError("Invocation Binding does not commit to the exact Effectful Component context")
    return expected_commitments


def _action_links(frontend, request, claim, mediation, observed_at_unix_ms):
    request_check = frontend.validate_request(request)
    if not request_check.get("valid"):
        return None, _linked_validation_findings("request", request_check)
    mediation_check = frontend.validate_mediation(mediation)
    if not mediation_check.get("valid"):
        return None, _linked_validation_findings("mediation", mediation_check)
    if not isinstance(claim, dict):
        raise ValueError("Action Claim must be an object")
    claim_keys = {
        "schema", "approval_sha256", "request_sha256", "challenge_sha256",
        "binding_sha256", "capsule_sha256", "invocation_sha256", "claim_scope",
        "claimed_at_unix_ms", "approval_expires_at_unix_ms", "status", "claim_sha256",
    }
    if set(claim) != claim_keys or claim.get("schema") != "loom-action-capsule-claim/v0":
        raise ValueError("Action Claim schema has unknown or missing fields")
    body = {key: claim[key] for key in sorted(claim_keys - {"claim_sha256"})}
    if claim.get("claim_sha256") != _sha256(_json_bytes(body)):
        raise ValueError("Action Claim hash does not match its canonical body")
    binding = request["binding"]
    expected_claim = {
        "approval_sha256": mediation.get("approval_sha256"),
        "request_sha256": request.get("request_sha256"),
        "challenge_sha256": request["challenge"].get("challenge_sha256"),
        "binding_sha256": binding.get("binding_sha256"),
        "capsule_sha256": binding.get("capsule_sha256"),
        "invocation_sha256": binding.get("invocation_sha256"),
        "claim_scope": "exact-invocation",
        "approval_expires_at_unix_ms": mediation.get("approval_expires_at_unix_ms"),
        "status": "claimed",
    }
    if any(claim.get(key) != value for key, value in expected_claim.items()):
        raise ValueError("Action Claim does not match the exact request and mediation")
    expected_mediation = {
        "claim_sha256": claim.get("claim_sha256"),
        "request_sha256": request.get("request_sha256"),
        "binding_sha256": binding.get("binding_sha256"),
        "capsule_sha256": binding.get("capsule_sha256"),
        "invocation_sha256": binding.get("invocation_sha256"),
        "status": "ready",
    }
    if any(mediation.get(key) != value for key, value in expected_mediation.items()):
        raise ValueError("Action Mediation does not match the exact request and Claim")
    claimed_at = claim.get("claimed_at_unix_ms")
    mediated_at = mediation.get("mediated_at_unix_ms")
    if type(claimed_at) is not int or type(mediated_at) is not int or claimed_at > mediated_at:
        raise ValueError("Action Claim time must not follow host mediation")
    if type(observed_at_unix_ms) is not int or observed_at_unix_ms < 0:
        raise ValueError("observed_at_unix_ms must be a non-negative integer")
    if observed_at_unix_ms < mediated_at:
        raise ValueError("Effectful binding cannot precede host mediation")
    if observed_at_unix_ms >= mediation.get("approval_expires_at_unix_ms", -1):
        raise ValueError("operator approval expired before Effectful binding")
    frontend.verify_ledger(claim, mediation)
    return binding, []


def _structure_findings(binding):
    findings = []
    keys = {
        "schema", "effectful_artifact", "component_resource", "mapping",
        "host_policy", "selected_export", "request", "runtime",
        "environment_commitments", "cross_links", "observed_at_unix_ms",
        "approval_expires_at_unix_ms", "lifecycle", "binding_sha256",
    }
    if not isinstance(binding, dict):
        return [_finding("binding", "expected-object", "binding must be an object")]
    if set(binding) != keys or binding.get("schema") != SCHEMA:
        findings.append(_finding(
            "binding", "schema-mismatch", "binding schema has unknown or missing fields",
        ))
        return findings
    lifecycle = binding.get("lifecycle")
    expected_lifecycle = {
        "schema": LIFECYCLE_SCHEMA,
        "authorization": "none",
        "execution_authorized": False,
        "operator_approval_recheck_required": True,
        "component_remeasurement_required": True,
        "private_component_snapshot_required": True,
        "required_next": REQUIRED_NEXT,
    }
    if lifecycle != expected_lifecycle:
        findings.append(_finding(
            "binding.lifecycle", "lifecycle-mismatch",
            "Effectful execution lifecycle cannot grant authority or skip remeasurement",
        ))
    resource = binding.get("component_resource")
    if not isinstance(resource, dict):
        findings.append(_finding(
            "binding.component_resource", "expected-object", "component resource must be an object",
        ))
    else:
        resource_keys = {
            "schema", "uri", "component_sha256", "byte_length", "identity",
            "measurement", "measurement_sha256",
        }
        if set(resource) != resource_keys or resource.get("schema") != RESOURCE_SCHEMA:
            findings.append(_finding(
                "binding.component_resource", "resource-schema-mismatch",
                "component resource schema has unknown or missing fields",
            ))
        else:
            resource_body = dict(resource)
            resource_hash = resource_body.pop("measurement_sha256")
            if resource_hash != _sha256(_json_bytes(resource_body)):
                findings.append(_finding(
                    "binding.component_resource.measurement_sha256", "resource-hash-mismatch",
                    "component resource measurement hash does not match its canonical body",
                ))
    try:
        body = dict(binding)
        supplied_hash = body.pop("binding_sha256")
        if supplied_hash != _sha256(_json_bytes(body)):
            findings.append(_finding(
                "binding.binding_sha256", "binding-hash-mismatch",
                "binding hash does not match its canonical body",
            ))
    except (TypeError, ValueError):
        findings.append(_finding(
            "binding", "non-canonical-binding", "binding must contain canonical JSON values",
        ))
    return findings


def build_effectful_component_execution_binding_v0(
    frontend, artifact, component_bytes, mapping, host_policy, source, core_wasm,
    package, world, request, claim, mediation, environment_values, component_uri,
    component_request, export, observed_at_unix_ms, *, wasm_tools_executable,
    wasmtime_executable, exports=None,
):
    findings = []
    try:
        action_binding, action_findings = _action_links(
            frontend, request, claim, mediation, observed_at_unix_ms,
        )
        if action_findings:
            return _result(None, action_findings)
        invocation = action_binding["invocation"]
        if invocation.get("shell") != "denied" or invocation.get("network") != "denied":
            raise ValueError("Effectful Component invocation must deny shell and network")
        resource, component_path = _measure_component(
            frontend, component_uri, component_bytes,
        )
        selected = _selected_export(mapping, export)
        request_bytes = _request_body(component_request, artifact["transport"])
        request_sha256 = _sha256(request_bytes)
        expected_environment = {
            "LOOM_EFFECTFUL_ARTIFACT_SHA256": artifact["artifact_sha256"],
            "LOOM_EFFECTFUL_COMPONENT_SHA256": artifact["component"]["sha256"],
            "LOOM_EFFECTFUL_EXPORT": selected["wit_name"],
            "LOOM_EFFECTFUL_HOST_POLICY_SHA256": host_policy["policy_sha256"],
            "LOOM_EFFECTFUL_MAPPING_SHA256": mapping["mapping_sha256"],
            "LOOM_EFFECTFUL_REQUEST_SHA256": request_sha256,
        }
        commitments = _committed_environment(
            invocation, environment_values, expected_environment,
        )
        wave = "[" + ",".join(str(byte) for byte in request_bytes) + "]"
        expected_argv = [
            "run", "--invoke", f"{selected['wit_name']}({wave})", component_path,
        ]
        if invocation.get("argv") != expected_argv:
            raise ValueError("Invocation argv does not name the exact WIT export, request, and Component URI")
        component_check = frontend.verify_component(
            artifact, component_bytes, mapping, host_policy, source, core_wasm,
            package, world, exports,
            wasm_tools_executable=wasm_tools_executable,
            wasmtime_executable=wasmtime_executable,
        )
        if not component_check.get("valid"):
            raise ValueError("Effectful Component Adapter v1 verification failed")
        runtime = component_check["evidence"]["wasmtime"]
        if invocation["adapter"].get("artifact_sha256") != runtime.get("sha256"):
            raise ValueError("Invocation Binding adapter is not the pinned verified Wasmtime executable")
        body = {
            "schema": SCHEMA,
            "effectful_artifact": {
                "schema": artifact["schema"],
                "artifact_sha256": artifact["artifact_sha256"],
            },
            "component_resource": resource,
            "mapping": {"schema": mapping["schema"], "mapping_sha256": mapping["mapping_sha256"]},
            "host_policy": {
                "schema": host_policy["schema"],
                "policy_id": host_policy["policy_id"],
                "policy_sha256": host_policy["policy_sha256"],
            },
            "selected_export": selected,
            "request": {
                "encoding": "canonical-json/utf-8",
                "sha256": request_sha256,
                "byte_length": len(request_bytes),
            },
            "runtime": {
                "engine": runtime["version"],
                "executable_sha256": runtime["sha256"],
            },
            "environment_commitments": commitments,
            "cross_links": {
                "schema": CROSS_LINKS_SCHEMA,
                "approval_sha256": claim["approval_sha256"],
                "request_sha256": request["request_sha256"],
                "binding_sha256": action_binding["binding_sha256"],
                "capsule_sha256": action_binding["capsule_sha256"],
                "invocation_sha256": action_binding["invocation_sha256"],
                "claim_sha256": claim["claim_sha256"],
                "mediation_sha256": mediation["mediation_sha256"],
                "host_measurement_sha256": mediation["host_measurement_sha256"],
            },
            "observed_at_unix_ms": observed_at_unix_ms,
            "approval_expires_at_unix_ms": mediation["approval_expires_at_unix_ms"],
            "lifecycle": {
                "schema": LIFECYCLE_SCHEMA,
                "authorization": "none",
                "execution_authorized": False,
                "operator_approval_recheck_required": True,
                "component_remeasurement_required": True,
                "private_component_snapshot_required": True,
                "required_next": REQUIRED_NEXT,
            },
        }
        body["binding_sha256"] = _sha256(_json_bytes(body))
        return _result(body)
    except (KeyError, OSError, TypeError, ValueError, UnicodeError) as exc:
        findings.append(_finding(
            "binding", "effectful-component-execution-binding-rejected", str(exc),
        ))
        return _result(None, findings)


def verify_effectful_component_execution_binding_v0(
    frontend, binding, artifact, component_bytes, mapping, host_policy, source,
    core_wasm, package, world, request, claim, mediation, environment_values,
    component_uri, component_request, export, observed_at_unix_ms, *,
    wasm_tools_executable, wasmtime_executable, exports=None,
):
    structure_findings = _structure_findings(binding)
    if structure_findings:
        return _result(None, structure_findings)
    expected = build_effectful_component_execution_binding_v0(
        frontend, artifact, component_bytes, mapping, host_policy, source, core_wasm,
        package, world, request, claim, mediation, environment_values, component_uri,
        component_request, export, observed_at_unix_ms,
        wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
        exports=exports,
    )
    if not expected["valid"]:
        return expected
    if binding != expected["binding"]:
        return _result(None, [_finding(
            "binding", "effectful-component-execution-binding-mismatch",
            "binding does not match the exact Component, policy, request, host resource, or claimed Action lifecycle",
        )])
    return expected
