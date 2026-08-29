#!/usr/bin/env python3
"""Externally signed terminal evidence for one Effectful Component execution."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json


VALIDATION_SCHEMA = "loom-effectful-component-execution-attestation-validation/v0"
PREDICATE_SCHEMA = "loom-effectful-component-execution-attestation-predicate/v0"
LINKS_SCHEMA = "loom-effectful-component-execution-attestation-links/v0"
ATTESTER_SCHEMA = "loom-effectful-component-execution-attester/v0"
LIFECYCLE_SCHEMA = "loom-effectful-component-execution-attestation-lifecycle/v0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://umbraaeternaa.github.io/loom/attestation/effectful-component-execution/v0"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_SIGNATURE_BYTES = 8192
MAX_JSON_NODES = 150_000
MAX_JSON_DEPTH = 160
MAX_SAFE_INTEGER = (1 << 53) - 1


class Frontend:
    __slots__ = ("validate_public_key", "rsa_verify")

    def __init__(self, validate_public_key, rsa_verify):
        self.validate_public_key = validate_public_key
        self.rsa_verify = rsa_verify


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _result(statement=None, envelope=None, key_sha256=None, findings=()):
    valid = not findings
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": True,
        "authorization": "none",
        "statement": statement if valid else None,
        "envelope": envelope if valid else None,
        "attester_key_sha256": key_sha256 if valid else None,
        "findings": list(findings),
    }


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _pae(payload_type, payload):
    kind = payload_type.encode("utf-8")
    return (
        b"DSSEv1 " + str(len(kind)).encode("ascii") + b" " + kind
        + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )


def _decode_base64(value, path, maximum):
    if not isinstance(value, str):
        return None, [_finding(path, "expected-base64", "expected a canonical Base64 string")]
    if len(value) > ((maximum + 2) // 3) * 4 + 4:
        return None, [_finding(path, "base64-too-large", "Base64 value exceeds the execution attestation bound")]
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return None, [_finding(path, "invalid-base64", "expected canonical standard Base64")]
    if len(decoded) > maximum:
        return None, [_finding(path, "base64-too-large", "decoded value exceeds the execution attestation bound")]
    if base64.b64encode(decoded).decode("ascii") != value:
        return None, [_finding(path, "non-canonical-base64", "Base64 must use one canonical standard encoding")]
    return decoded, []


def _statement_json(payload):
    def closed(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    try:
        statement = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=closed,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        return None, [_finding(
            "envelope.payload", "invalid-statement-json",
            "payload must be strict duplicate-free JSON",
        )]
    stack = [(statement, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            return None, [_finding(
                "envelope.payload", "statement-too-large",
                "statement exceeds the JSON node bound",
            )]
        if depth > MAX_JSON_DEPTH:
            return None, [_finding(
                "envelope.payload", "statement-too-deep",
                "statement exceeds the JSON depth bound",
            )]
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif value is not None and type(value) not in {str, int, bool}:
            return None, [_finding(
                "envelope.payload", "non-canonical-statement",
                "statement contains a non-canonical JSON value",
            )]
    try:
        canonical = _json_bytes(statement)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None, [_finding(
            "envelope.payload", "non-canonical-statement",
            "statement contains non-canonical text or values",
        )]
    if canonical != payload:
        return None, [_finding(
            "envelope.payload", "non-canonical-statement",
            "statement must use canonical UTF-8 JSON",
        )]
    return statement, []


def _prefixed_findings(prefix, check, fallback):
    if isinstance(check, dict) and check.get("valid") is True:
        return []
    nested = check.get("findings", ()) if isinstance(check, dict) else ()
    if not nested:
        return [_finding(prefix, fallback, prefix + " validation failed")]
    return [
        _finding(
            prefix + "." + item.get("path", ""), item.get("code", fallback),
            item.get("message", prefix + " validation failed"),
        )
        for item in nested
    ]


def prepare_attestation(
    frontend, binding_check, nested_attestation_check,
    attester_public_key, attested_at_unix_ms,
):
    findings = _prefixed_findings(
        "result_binding", binding_check, "invalid-effectful-result-binding",
    )
    findings.extend(_prefixed_findings(
        "action_result_attestation", nested_attestation_check,
        "invalid-action-result-attestation",
    ))
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    findings.extend(
        _finding(
            "attester_public_key." + item.get("path", ""),
            item.get("code", "invalid-public-key"),
            item.get("message", "invalid execution attester public key"),
        )
        for item in key_findings
    )
    if type(attested_at_unix_ms) is not int or not 0 <= attested_at_unix_ms <= MAX_SAFE_INTEGER:
        findings.append(_finding(
            "attested_at_unix_ms", "invalid-attestation-time",
            "execution attestation time must be a non-negative portable integer",
        ))
    if findings:
        return _result(findings=findings)

    binding = binding_check["binding"]
    nested_statement = nested_attestation_check["statement"]
    nested_predicate = nested_statement.get("predicate", {})
    nested_attested_at = nested_predicate.get("attested_at_unix_ms")
    finalized_at = binding["action_result"].get("finalized_at_unix_ms")
    if (
        type(nested_attested_at) is not int
        or type(finalized_at) is not int
        or attested_at_unix_ms < nested_attested_at
        or attested_at_unix_ms < finalized_at
    ):
        return _result(findings=[_finding(
            "attested_at_unix_ms", "attestation-before-evidence",
            "execution attestation cannot predate the signed Result evidence",
        )])
    links = binding["cross_links"]
    if nested_attestation_check.get("attester_key_sha256") != links.get("attester_key_sha256"):
        return _result(findings=[_finding(
            "action_result_attestation", "nested-attester-link-mismatch",
            "nested signed Result attester does not match the terminal Result Binding",
        )])
    key_sha256 = _sha256(_json_bytes(public_key))
    execution_links = {
        "schema": LINKS_SCHEMA,
        "result_binding_sha256": binding["binding_sha256"],
        "host_execution_sha256": binding["host_execution_sha256"],
        "effectful_execution_binding_sha256": links["effectful_execution_binding_sha256"],
        "component_spawn_measurement_sha256": links["component_spawn_measurement_sha256"],
        "component_sha256": links["component_sha256"],
        "launch_sha256": links["launch_sha256"],
        "action_execution_sha256": links["action_execution_sha256"],
        "action_result_sha256": links["action_result_sha256"],
        "action_result_attestation_sha256": links["action_result_attestation_sha256"],
        "gate_receipt_sha256": links["gate_receipt_sha256"],
        "operator_approval_sha256": links["operator_approval_sha256"],
        "result_attester_key_sha256": links["attester_key_sha256"],
        "execution_attester_key_sha256": key_sha256,
    }
    predicate = {
        "schema": PREDICATE_SCHEMA,
        "result_binding": binding,
        "result_binding_sha256": binding["binding_sha256"],
        "cross_links": execution_links,
        "attester": {
            "schema": ATTESTER_SCHEMA,
            "role": "effectful-component-execution-attester",
            "algorithm": public_key["algorithm"],
            "key_sha256": key_sha256,
        },
        "attested_at_unix_ms": attested_at_unix_ms,
        "lifecycle": {
            "schema": LIFECYCLE_SCHEMA,
            "terminal": True,
            "evidence": "signed-effectful-component-execution",
            "authorization": "none",
            "execution_repeated": False,
            "nested_signature_verified": True,
            "portable_verification": True,
            "independent_attester_claim": False,
            "slsa_level_claim": "none",
        },
    }
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "loom-effectful-component-result-binding-v0.json", "digest": {"sha256": binding["binding_sha256"]}},
            {"name": "loom-effectful-component-host-execution-v0.json", "digest": {"sha256": binding["host_execution_sha256"]}},
            {"name": "loom-action-result.json", "digest": {"sha256": binding["action_result_sha256"]}},
            {"name": "loom-effectful-component.wasm", "digest": {"sha256": links["component_sha256"]}},
            {"name": "loom-gate-receipt-v4.json", "digest": {"sha256": links["gate_receipt_sha256"]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    try:
        payload = _json_bytes(statement)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return _result(findings=[_finding(
            "statement", "non-canonical-statement",
            "execution attestation statement contains non-canonical evidence",
        )])
    if len(payload) > MAX_PAYLOAD_BYTES:
        return _result(findings=[_finding(
            "statement", "statement-too-large",
            "execution attestation statement exceeds the payload bound",
        )])
    signing = _pae(PAYLOAD_TYPE, payload)
    result = _result(statement=statement, key_sha256=key_sha256)
    result.update({
        "payload_type": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signing_bytes": base64.b64encode(signing).decode("ascii"),
        "signing_bytes_sha256": _sha256(signing),
    })
    return result


def build_attestation(
    frontend, binding_check, nested_attestation_check,
    attester_public_key, attested_at_unix_ms, signature,
):
    prepared = prepare_attestation(
        frontend, binding_check, nested_attestation_check,
        attester_public_key, attested_at_unix_ms,
    )
    if not prepared["valid"]:
        return prepared
    signature_bytes, findings = _decode_base64(
        signature, "signature", MAX_SIGNATURE_BYTES,
    )
    if findings:
        return _result(findings=findings)
    signing, findings = _decode_base64(
        prepared["signing_bytes"], "signing_bytes", MAX_PAYLOAD_BYTES + 1024,
    )
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    if findings or key_findings or not frontend.rsa_verify(signing, signature_bytes.hex(), public_key):
        return _result(findings=[_finding(
            "signature", "invalid-effectful-execution-signature",
            "DSSE signature is invalid for the trusted execution attester key",
        )])
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": prepared["payload"],
        "signatures": [{
            "keyid": prepared["attester_key_sha256"],
            "sig": base64.b64encode(signature_bytes).decode("ascii"),
        }],
    }
    return _result(
        statement=prepared["statement"], envelope=envelope,
        key_sha256=prepared["attester_key_sha256"],
    )


def verify_attestation(
    frontend, envelope, binding_check, nested_attestation_check, attester_public_key,
):
    envelope_keys = {"payloadType", "payload", "signatures"}
    if not isinstance(envelope, dict) or set(envelope) != envelope_keys:
        return _result(findings=[_finding(
            "envelope", "closed-envelope-mismatch",
            "execution attestation requires one closed DSSE envelope",
        )])
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return _result(findings=[_finding(
            "envelope.payloadType", "unsupported-payload-type",
            "expected application/vnd.in-toto+json",
        )])
    payload, findings = _decode_base64(
        envelope.get("payload"), "envelope.payload", MAX_PAYLOAD_BYTES,
    )
    if findings:
        return _result(findings=findings)
    signatures = envelope.get("signatures")
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    if key_findings:
        return _result(findings=[_finding(
            "attester_public_key", "invalid-public-key",
            "execution attester public key is invalid",
        )])
    key_sha256 = _sha256(_json_bytes(public_key))
    if (
        not isinstance(signatures, list) or len(signatures) != 1
        or not isinstance(signatures[0], dict)
        or set(signatures[0]) != {"keyid", "sig"}
        or signatures[0].get("keyid") != key_sha256
    ):
        return _result(findings=[_finding(
            "envelope.signatures", "closed-signature-set-mismatch",
            "execution attestation requires one exact trusted-key signature",
        )])
    signature_bytes, findings = _decode_base64(
        signatures[0].get("sig"), "envelope.signatures.0.sig", MAX_SIGNATURE_BYTES,
    )
    signing = _pae(PAYLOAD_TYPE, payload)
    if findings or not frontend.rsa_verify(signing, signature_bytes.hex(), public_key):
        return _result(findings=[_finding(
            "envelope.signatures", "invalid-effectful-execution-signature",
            "DSSE signature does not verify with the trusted execution attester key",
        )])
    statement, findings = _statement_json(payload)
    if findings:
        return _result(findings=findings)
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    attested_at = predicate.get("attested_at_unix_ms") if isinstance(predicate, dict) else None
    expected = prepare_attestation(
        frontend, binding_check, nested_attestation_check,
        attester_public_key, attested_at,
    )
    if not expected["valid"]:
        return expected
    if statement != expected["statement"]:
        return _result(findings=[_finding(
            "statement", "effectful-execution-statement-mismatch",
            "signed statement does not match the exact terminal Component execution binding",
        )])
    return _result(statement=statement, envelope=envelope, key_sha256=key_sha256)
