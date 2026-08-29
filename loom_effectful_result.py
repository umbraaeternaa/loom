#!/usr/bin/env python3
"""Terminal evidence binding for one Effectful Component execution."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json


SCHEMA = "loom-effectful-component-result-binding/v0"
VALIDATION_SCHEMA = "loom-effectful-component-result-binding-validation/v0"
CROSS_LINKS_SCHEMA = "loom-effectful-component-result-links/v0"
LIFECYCLE_SCHEMA = "loom-effectful-component-result-lifecycle/v0"
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 128
MAX_JSON_TEXT_BYTES = 8 * 1024 * 1024


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _bounded_json_findings(value, path):
    stack = [(value, 0)]
    nodes = 0
    text_bytes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            return [_finding(path, "evidence-too-large", "result binding exceeds the JSON node limit")]
        if depth > MAX_JSON_DEPTH:
            return [_finding(path, "evidence-too-deep", "result binding exceeds the JSON depth limit")]
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    return [_finding(path, "non-canonical-evidence", "result binding object keys must be strings")]
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeEncodeError:
                    return [_finding(path, "non-canonical-evidence", "result binding contains invalid Unicode text")]
                stack.append((nested, depth + 1))
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
        elif isinstance(item, str):
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeEncodeError:
                return [_finding(path, "non-canonical-evidence", "result binding contains invalid Unicode text")]
        elif item is not None and type(item) not in {bool, int, float}:
            return [_finding(path, "non-canonical-evidence", "result binding contains a non-JSON value")]
        if text_bytes > MAX_JSON_TEXT_BYTES:
            return [_finding(path, "evidence-too-large", "result binding exceeds the JSON text limit")]
    return []


def _json_bytes(value):
    bounds = _bounded_json_findings(value, "binding")
    if bounds:
        raise ValueError(bounds[0]["message"])
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_JSON_TEXT_BYTES:
        raise ValueError("result binding exceeds the canonical byte limit")
    return encoded


def _sha256_json(value):
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _is_sha256(value):
    return (
        isinstance(value, str) and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


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


def _validated_artifact(check, key, path, code):
    if not isinstance(check, dict) or check.get("valid") is not True:
        findings = check.get("findings", ()) if isinstance(check, dict) else ()
        if findings:
            return None, [
                _finding(path + "." + item.get("path", ""), item.get("code", code),
                         item.get("message", "invalid nested evidence"))
                for item in findings
            ]
        return None, [_finding(path, code, path + " validation failed")]
    value = check.get(key)
    if not isinstance(value, dict):
        return None, [_finding(path, code, path + " validator returned no artifact")]
    return value, []


def _relationship(host_execution, action_result, statement, envelope, attester_key_sha256):
    findings = []
    envelope_keys = {"payloadType", "payload", "signatures"}
    signatures = envelope.get("signatures") if isinstance(envelope, dict) else None
    if (
        not isinstance(envelope, dict) or set(envelope) != envelope_keys
        or not isinstance(signatures, list) or len(signatures) != 1
        or not isinstance(signatures[0], dict) or set(signatures[0]) != {"keyid", "sig"}
        or signatures[0].get("keyid") != attester_key_sha256
    ):
        findings.append(_finding(
            "action_result_attestation", "non-canonical-effectful-attestation",
            "Effectful Result Binding requires one closed DSSE envelope and one trusted signature",
        ))
    else:
        for field, value in (
            ("payload", envelope.get("payload")),
            ("signatures.0.sig", signatures[0].get("sig")),
        ):
            try:
                raw = base64.b64decode(value.encode("ascii"), validate=True)
                canonical = base64.b64encode(raw).decode("ascii")
            except (AttributeError, UnicodeEncodeError, ValueError, binascii.Error):
                canonical = None
            if canonical != value:
                findings.append(_finding(
                    "action_result_attestation." + field,
                    "non-canonical-effectful-attestation",
                    "Effectful Result Binding requires canonical standard Base64 DSSE bytes",
                ))
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    attested_result = predicate.get("action_result") if isinstance(predicate, dict) else None
    attested_result_sha256 = (
        predicate.get("action_result_sha256") if isinstance(predicate, dict) else None
    )
    if attested_result != action_result or attested_result_sha256 != action_result.get("result_sha256"):
        findings.append(_finding(
            "action_result_attestation", "attested-result-link-mismatch",
            "signed Action Result attestation does not contain the exact terminal Result",
        ))

    host_action = host_execution.get("action_execution")
    result_action = action_result.get("execution")
    if (
        host_action != result_action
        or host_execution.get("action_execution_sha256") != action_result.get("execution_sha256")
    ):
        findings.append(_finding(
            "action_result.execution_sha256", "effectful-execution-link-mismatch",
            "terminal Action Result does not close the exact Component host execution",
        ))

    execution_binding = host_execution.get("execution_binding", {})
    host_links = execution_binding.get("cross_links", {})
    result_request = action_result.get("request", {})
    result_binding = result_request.get("binding", {})
    expected_links = {
        "approval_sha256": action_result.get("approval_sha256"),
        "request_sha256": action_result.get("request_sha256"),
        "claim_sha256": action_result.get("claim_sha256"),
        "mediation_sha256": action_result.get("mediation_sha256"),
        "binding_sha256": result_binding.get("binding_sha256"),
    }
    for key, expected in expected_links.items():
        if host_links.get(key) != expected:
            findings.append(_finding(
                "host_execution.execution_binding.cross_links." + key,
                "effectful-lifecycle-link-mismatch",
                key + " does not match the terminal Action Result lifecycle",
            ))
    host_status = host_execution.get("status")
    result_status = action_result.get("outcome", {}).get("status")
    if host_status != result_status:
        findings.append(_finding(
            "action_result.outcome.status", "effectful-status-link-mismatch",
            "Component host status and terminal Action outcome differ",
        ))
    if not _is_sha256(attester_key_sha256):
        findings.append(_finding(
            "attester_key_sha256", "expected-sha256",
            "trusted attester key identity must be lowercase SHA-256 hex",
        ))
    return predicate, host_links, findings


def build_binding(host_check, result_check, attestation_check):
    host_execution, findings = _validated_artifact(
        host_check, "execution", "host_execution", "invalid-host-execution",
    )
    action_result, result_findings = _validated_artifact(
        result_check, "result", "action_result", "invalid-action-result",
    )
    findings.extend(result_findings)
    statement, statement_findings = _validated_artifact(
        attestation_check, "statement", "action_result_attestation",
        "invalid-action-result-attestation",
    )
    findings.extend(statement_findings)
    envelope = attestation_check.get("envelope") if isinstance(attestation_check, dict) else None
    if not isinstance(envelope, dict):
        findings.append(_finding(
            "action_result_attestation", "invalid-action-result-attestation",
            "verified Action Result attestation must retain its DSSE envelope",
        ))
    if findings:
        return _result(None, findings)

    attester_key_sha256 = attestation_check.get("attester_key_sha256")
    predicate, host_links, relationship_findings = _relationship(
        host_execution, action_result, statement, envelope, attester_key_sha256,
    )
    if relationship_findings:
        return _result(None, relationship_findings)
    try:
        attestation_sha256 = _sha256_json(envelope)
        component_measurement = host_execution["component_spawn_measurement"]
        cross_links = {
            "schema": CROSS_LINKS_SCHEMA,
            "effectful_execution_binding_sha256": host_execution["binding_sha256"],
            "component_spawn_measurement_sha256": host_execution["component_spawn_measurement_sha256"],
            "component_sha256": component_measurement["snapshot_component_sha256"],
            "launch_sha256": host_execution["launch_sha256"],
            "action_execution_sha256": host_execution["action_execution_sha256"],
            "action_outcome_sha256": action_result["outcome_sha256"],
            "action_result_sha256": action_result["result_sha256"],
            "action_result_attestation_sha256": attestation_sha256,
            "gate_receipt_sha256": predicate["gate_receipt_sha256"],
            "operator_approval_sha256": host_links["approval_sha256"],
            "attester_key_sha256": attester_key_sha256,
        }
        body = {
            "schema": SCHEMA,
            "host_execution": host_execution,
            "host_execution_sha256": host_execution["execution_sha256"],
            "action_result": action_result,
            "action_result_sha256": action_result["result_sha256"],
            "action_result_attestation": envelope,
            "action_result_attestation_sha256": attestation_sha256,
            "attester_key_sha256": attester_key_sha256,
            "cross_links": cross_links,
            "lifecycle": {
                "schema": LIFECYCLE_SCHEMA,
                "terminal": True,
                "authorization": "none",
                "execution_repeated": False,
                "effectful_execution_closed": True,
                "signed_result_evidence": True,
                "remaining_evidence": [],
            },
        }
        body["binding_sha256"] = _sha256_json(body)
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        return _result(None, [_finding(
            "binding", "effectful-result-binding-rejected", str(error),
        )])
    return _result(body)


def _structure_findings(binding):
    findings = _bounded_json_findings(binding, "binding")
    if findings:
        return findings
    outer_keys = {
        "schema", "host_execution", "host_execution_sha256", "action_result",
        "action_result_sha256", "action_result_attestation",
        "action_result_attestation_sha256", "attester_key_sha256", "cross_links",
        "lifecycle", "binding_sha256",
    }
    if not isinstance(binding, dict):
        return [_finding("binding", "expected-object", "binding must be an object")]
    if set(binding) != outer_keys or binding.get("schema") != SCHEMA:
        return [_finding(
            "binding", "schema-mismatch", "result binding schema has unknown or missing fields",
        )]
    for key in (
        "host_execution_sha256", "action_result_sha256",
        "action_result_attestation_sha256", "attester_key_sha256", "binding_sha256",
    ):
        if not _is_sha256(binding.get(key)):
            findings.append(_finding(
                "binding." + key, "expected-sha256", key + " must be lowercase SHA-256 hex",
            ))
    expected_lifecycle = {
        "schema": LIFECYCLE_SCHEMA,
        "terminal": True,
        "authorization": "none",
        "execution_repeated": False,
        "effectful_execution_closed": True,
        "signed_result_evidence": True,
        "remaining_evidence": [],
    }
    if binding.get("lifecycle") != expected_lifecycle:
        findings.append(_finding(
            "binding.lifecycle", "lifecycle-mismatch",
            "Effectful Component Result Binding must be terminal and non-authorizing",
        ))
    cross_links = binding.get("cross_links")
    cross_link_keys = {
        "schema", "effectful_execution_binding_sha256",
        "component_spawn_measurement_sha256", "component_sha256", "launch_sha256",
        "action_execution_sha256", "action_outcome_sha256", "action_result_sha256",
        "action_result_attestation_sha256", "gate_receipt_sha256",
        "operator_approval_sha256", "attester_key_sha256",
    }
    if not isinstance(cross_links, dict) or set(cross_links) != cross_link_keys:
        findings.append(_finding(
            "binding.cross_links", "closed-schema-mismatch",
            "result cross-links have unknown or missing fields",
        ))
    elif cross_links.get("schema") != CROSS_LINKS_SCHEMA:
        findings.append(_finding(
            "binding.cross_links.schema", "schema-mismatch", "unsupported result cross-links schema",
        ))
    try:
        body = dict(binding)
        supplied_hash = body.pop("binding_sha256")
        if supplied_hash != _sha256_json(body):
            findings.append(_finding(
                "binding.binding_sha256", "binding-hash-mismatch",
                "result binding hash does not match its canonical body",
            ))
    except (TypeError, ValueError, UnicodeError):
        findings.append(_finding(
            "binding", "non-canonical-binding", "result binding must contain canonical JSON values",
        ))
    return findings


def validate_binding(binding, host_check, result_check, attestation_check):
    findings = _structure_findings(binding)
    if findings:
        return _result(None, findings)
    expected = build_binding(host_check, result_check, attestation_check)
    if not expected["valid"]:
        return expected
    if binding != expected["binding"]:
        return _result(None, [_finding(
            "binding", "effectful-component-result-binding-mismatch",
            "binding does not match the exact Component host execution, terminal Result, or signed attestation",
        )])
    return expected
