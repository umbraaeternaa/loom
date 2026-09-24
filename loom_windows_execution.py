"""Closed contracts for the Windows Bounded Execution Integration v0 profile."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3

import loom_windows_host


CLAIM_SCHEMA = "loom-windows-action-claim/v0"
MEDIATION_SCHEMA = "loom-windows-action-host-mediation/v0"
NATIVE_RECEIPT_SCHEMA = "loom-windows-bounded-execution-native-receipt/v0"
EXECUTION_SCHEMA = "loom-windows-action-bounded-execution/v0"
RESULT_SCHEMA = "loom-windows-action-result/v0"
WITNESS_SCHEMA = "loom-windows-bounded-execution-ci-witness/v0"

EXPECTED_CHECKS = (
    "signed-action-approval-v2",
    "atomic-one-use-windows-claim",
    "exact-input-environment-adapter-mediation",
    "native-appcontainer-job-object-execution",
    "bounded-terminal-result",
    "replay-and-tamper-refusal",
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-)+[0-9]+\Z")
_LEDGER_SCHEMA = (
    "CREATE TABLE windows_action_lifecycle_v0 ("
    "approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), "
    "request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64), "
    "binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), "
    "claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), "
    "mediation_sha256 TEXT UNIQUE, execution_sha256 TEXT UNIQUE, "
    "result_sha256 TEXT UNIQUE, "
    "status TEXT NOT NULL CHECK(status IN ('claimed','mediated','reserved','terminal')))"
)
_LEDGER_CREATE = _LEDGER_SCHEMA.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_json(value):
    return sha256_bytes(canonical_json(value))


def _closed(value, keys, label, findings):
    if not isinstance(value, dict):
        findings.append(f"{label} must be an object")
        return False
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        findings.append(
            f"{label} keys differ: missing={sorted(expected - actual)!r} "
            f"extra={sorted(actual - expected)!r}"
        )
        return False
    return True


def _hash(value, label, findings):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        findings.append(f"{label} must be lowercase SHA-256")


def _hashed_artifact(value, schema, hash_key, label, findings):
    if not isinstance(value, dict):
        findings.append(f"{label} must be an object")
        return
    if value.get("schema") != schema:
        findings.append(f"{label}.schema must equal {schema!r}")
    _hash(value.get(hash_key), f"{label}.{hash_key}", findings)
    if hash_key in value:
        body = {key: value[key] for key in value if key != hash_key}
        try:
            expected = sha256_json(body)
        except (TypeError, ValueError):
            findings.append(f"{label} is not canonical JSON")
        else:
            if value.get(hash_key) != expected:
                findings.append(f"{label}.{hash_key} does not match canonical bytes")


def _rsa_verify(message, signature_hex, public_key):
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]+", signature_hex):
        return False
    try:
        modulus = int(public_key["n"], 16)
        exponent = public_key["e"]
        signature = bytes.fromhex(signature_hex)
    except (KeyError, TypeError, ValueError):
        return False
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size or exponent != 65537:
        return False
    decoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return decoded == expected


def validate_approval_evidence(request, approval_validation, public_key):
    """Verify the self-contained test Approval v2 evidence carried by a witness."""
    findings = []
    if not isinstance(request, dict) or request.get("schema") != "loom-action-approval-request/v2":
        return ["approval_request must be one Action Approval request v2"]
    request_sha256 = request.get("request_sha256")
    _hash(request_sha256, "approval_request.request_sha256", findings)
    if request_sha256 != sha256_json({key: request[key] for key in request if key != "request_sha256"}):
        findings.append("approval_request.request_sha256 does not match canonical bytes")
    if not _closed(public_key, {"algorithm", "n", "e"}, "operator_public_key", findings):
        return findings
    if public_key.get("algorithm") != "rsa-pkcs1v15-sha256" or public_key.get("e") != 65537:
        findings.append("operator_public_key algorithm or exponent is outside the fixed profile")
    if not isinstance(public_key.get("n"), str) or not re.fullmatch(r"[0-9a-f]+", public_key["n"]) or len(public_key["n"]) < 512:
        findings.append("operator_public_key modulus must be at least 2048-bit lowercase hex")
    if not isinstance(approval_validation, dict) or approval_validation.get("schema") != "loom-action-capsule-approval-validation/v2" or approval_validation.get("valid") is not True or approval_validation.get("authorization") != "claim-required":
        findings.append("approval_validation must be one successful Action Approval v2 validation")
        return findings
    approval = approval_validation.get("approval")
    approval_sha256 = approval_validation.get("approval_sha256")
    if not isinstance(approval, dict):
        findings.append("approval_validation.approval must be an object")
        return findings
    required = {
        "schema", "request_sha256", "challenge_sha256", "binding_sha256",
        "capsule_sha256", "invocation_sha256", "approval_scope", "approver",
        "decision", "issued_at_unix_ms", "expires_at_unix_ms", "claim_required",
        "key_sha256", "signature",
    }
    if set(approval) != required:
        findings.append("approval_validation.approval is not a closed Action Approval v2")
        return findings
    binding = request.get("binding", {})
    challenge = request.get("challenge", {})
    fixed = {
        "schema": "loom-action-capsule-approval/v2",
        "request_sha256": request_sha256,
        "challenge_sha256": challenge.get("challenge_sha256"),
        "binding_sha256": binding.get("binding_sha256"),
        "capsule_sha256": binding.get("capsule_sha256"),
        "invocation_sha256": binding.get("invocation_sha256"),
        "approval_scope": "exact-invocation", "approver": "operator",
        "decision": "approve", "claim_required": True,
        "key_sha256": sha256_json(public_key),
    }
    for key, expected in fixed.items():
        if approval.get(key) != expected:
            findings.append(f"approval_validation.approval.{key} does not match the request")
    signed = {key: approval[key] for key in approval if key != "signature"}
    if not _rsa_verify(canonical_json(signed), approval.get("signature"), public_key):
        findings.append("approval_validation.approval signature is invalid")
    if approval_sha256 != sha256_json(approval):
        findings.append("approval_validation.approval_sha256 does not match canonical approval bytes")
    issued = approval.get("issued_at_unix_ms")
    expires = approval.get("expires_at_unix_ms")
    if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= 900000:
        findings.append("approval_validation.approval lifetime is invalid")
    return findings


def _ledger_connection(path):
    path = Path(path)
    parent = path.parent
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise ValueError("Windows lifecycle ledger parent must be a non-symlink directory")
    parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Windows lifecycle ledger must be a regular non-symlink file")
    connection = sqlite3.connect(str(path), timeout=5, isolation_level=None)
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(_LEDGER_CREATE)
    stored = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='windows_action_lifecycle_v0'"
    ).fetchone()
    if stored != (_LEDGER_SCHEMA,):
        connection.execute("ROLLBACK")
        connection.close()
        raise ValueError("Windows lifecycle ledger schema is not canonical")
    foreign = connection.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('trigger','view') "
        "AND tbl_name='windows_action_lifecycle_v0'"
    ).fetchall()
    if foreign:
        connection.execute("ROLLBACK")
        connection.close()
        raise ValueError("Windows lifecycle ledger has unrecognized triggers or views")
    return connection


def claim_once(approval_validation, request, now_unix_ms, ledger_path):
    """Atomically consume one already cryptographically verified Approval v2."""
    if not isinstance(approval_validation, dict) or not approval_validation.get("valid"):
        raise ValueError("Action Approval v2 must be valid before Windows claim")
    if approval_validation.get("schema") != "loom-action-capsule-approval-validation/v2":
        raise ValueError("Action Approval validation schema is outside the contract")
    if approval_validation.get("authorization") != "claim-required":
        raise ValueError("Action Approval must require a claim")
    approval = approval_validation.get("approval")
    approval_sha256 = approval_validation.get("approval_sha256")
    if not isinstance(approval, dict) or not _HEX64.fullmatch(str(approval_sha256)):
        raise ValueError("Action Approval validation is incomplete")
    if type(now_unix_ms) is not int or now_unix_ms < 0:
        raise ValueError("claim time must be a non-negative integer")
    expires = approval.get("expires_at_unix_ms")
    if type(expires) is not int or now_unix_ms >= expires:
        raise ValueError("Action Approval expired before Windows claim")
    try:
        binding = request["binding"]
        links = {
            "request_sha256": request["request_sha256"],
            "challenge_sha256": request["challenge"]["challenge_sha256"],
            "binding_sha256": binding["binding_sha256"],
            "capsule_sha256": binding["capsule_sha256"],
            "invocation_sha256": binding["invocation_sha256"],
        }
    except (KeyError, TypeError) as exc:
        raise ValueError("Action Approval request is incomplete") from exc
    expected = {
        "request_sha256": approval.get("request_sha256"),
        "challenge_sha256": approval.get("challenge_sha256"),
        "binding_sha256": approval.get("binding_sha256"),
        "capsule_sha256": approval.get("capsule_sha256"),
        "invocation_sha256": approval.get("invocation_sha256"),
    }
    if links != expected:
        raise ValueError("Action Approval does not bind the exact request")
    body = {
        "schema": CLAIM_SCHEMA,
        "approval_sha256": approval_sha256,
        **links,
        "claimed_at_unix_ms": now_unix_ms,
        "approval_expires_at_unix_ms": expires,
        "status": "claimed",
    }
    body["claim_sha256"] = sha256_json(body)
    connection = _ledger_connection(ledger_path)
    try:
        connection.execute(
            "INSERT INTO windows_action_lifecycle_v0 "
            "(approval_sha256,request_sha256,binding_sha256,claim_sha256,status) "
            "VALUES (?,?,?,?,?)",
            (approval_sha256, links["request_sha256"], links["binding_sha256"],
             body["claim_sha256"], "claimed"),
        )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ValueError("Action Approval v2 was already claimed") from exc
    finally:
        connection.close()
    return body


def mediate(claim, request, adapter_sha256, environment, stdin_bytes, now_unix_ms, ledger_path):
    """Bind one Windows-native adapter, exact environment commitments, and stdin."""
    findings = validate_claim(claim)
    if findings:
        raise ValueError("invalid Windows claim: " + "; ".join(findings))
    if request.get("request_sha256") != claim["request_sha256"]:
        raise ValueError("request does not match the Windows claim")
    invocation = request.get("binding", {}).get("invocation", {})
    if invocation.get("adapter", {}).get("artifact_sha256") != adapter_sha256:
        raise ValueError("native adapter bytes do not match the Invocation Binding")
    if invocation.get("stdin", {}).get("payload_sha256") != sha256_bytes(stdin_bytes):
        raise ValueError("stdin bytes do not match the Invocation Binding")
    expected_environment = invocation.get("environment")
    observed_environment = [
        {"name": name, "value_sha256": sha256_bytes(value.encode("utf-8"))}
        for name, value in sorted(environment.items())
    ]
    if observed_environment != expected_environment:
        raise ValueError("environment values do not match the Invocation Binding")
    if type(now_unix_ms) is not int or not claim["claimed_at_unix_ms"] <= now_unix_ms < claim["approval_expires_at_unix_ms"]:
        raise ValueError("mediation time is outside the approval lifetime")
    body = {
        "schema": MEDIATION_SCHEMA,
        "claim_sha256": claim["claim_sha256"],
        "approval_sha256": claim["approval_sha256"],
        "request_sha256": claim["request_sha256"],
        "binding_sha256": claim["binding_sha256"],
        "adapter_sha256": adapter_sha256,
        "environment_sha256": sha256_json(observed_environment),
        "stdin_sha256": sha256_bytes(stdin_bytes),
        "stdin_size_bytes": len(stdin_bytes),
        "timeout_ms": invocation.get("timeout_ms"),
        "shell": "denied",
        "network": "denied",
        "mediated_at_unix_ms": now_unix_ms,
        "approval_expires_at_unix_ms": claim["approval_expires_at_unix_ms"],
        "status": "ready",
    }
    body["mediation_sha256"] = sha256_json(body)
    connection = _ledger_connection(ledger_path)
    try:
        changed = connection.execute(
            "UPDATE windows_action_lifecycle_v0 SET mediation_sha256=?,status='mediated' "
            "WHERE approval_sha256=? AND claim_sha256=? AND status='claimed'",
            (body["mediation_sha256"], claim["approval_sha256"], claim["claim_sha256"]),
        ).rowcount
        if changed != 1:
            raise ValueError("Windows claim is absent, replayed, or not claimable")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return body


def reserve(mediation, reserved_at_unix_ms, ledger_path):
    findings = validate_mediation(mediation)
    if findings:
        raise ValueError("invalid Windows mediation: " + "; ".join(findings))
    if type(reserved_at_unix_ms) is not int or not mediation["mediated_at_unix_ms"] <= reserved_at_unix_ms < mediation["approval_expires_at_unix_ms"]:
        raise ValueError("execution reservation is outside the approval lifetime")
    ticket = sha256_json({
        "schema": "loom-windows-execution-reservation/v0",
        "mediation_sha256": mediation["mediation_sha256"],
        "reserved_at_unix_ms": reserved_at_unix_ms,
    })
    connection = _ledger_connection(ledger_path)
    try:
        changed = connection.execute(
            "UPDATE windows_action_lifecycle_v0 SET execution_sha256=?,status='reserved' "
            "WHERE claim_sha256=? AND mediation_sha256=? AND status='mediated'",
            (ticket, mediation["claim_sha256"], mediation["mediation_sha256"]),
        ).rowcount
        if changed != 1:
            raise ValueError("Windows mediation is absent, replayed, or not executable")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return ticket


def complete(mediation, reservation_sha256, native_receipt, executed_at_unix_ms, ledger_path):
    findings = validate_native_receipt(native_receipt)
    if findings:
        raise ValueError("invalid native receipt: " + "; ".join(findings))
    if native_receipt["adapter_sha256"] != mediation["adapter_sha256"]:
        raise ValueError("native receipt adapter does not match mediation")
    if native_receipt["input"]["stdin_sha256"] != mediation["stdin_sha256"]:
        raise ValueError("native receipt stdin does not match mediation")
    if native_receipt["environment_sha256"] != mediation["environment_sha256"]:
        raise ValueError("native receipt environment does not match mediation")
    if native_receipt["limits"]["timeout_ms"] != mediation["timeout_ms"]:
        raise ValueError("native receipt timeout does not match mediation")
    if type(executed_at_unix_ms) is not int or executed_at_unix_ms >= mediation["approval_expires_at_unix_ms"]:
        raise ValueError("native execution completed outside the approval lifetime")
    status = native_receipt["process"]["result"]
    body = {
        "schema": EXECUTION_SCHEMA,
        "mediation_sha256": mediation["mediation_sha256"],
        "claim_sha256": mediation["claim_sha256"],
        "binding_sha256": mediation["binding_sha256"],
        "reservation_sha256": reservation_sha256,
        "native_receipt": native_receipt,
        "native_receipt_sha256": native_receipt["native_receipt_sha256"],
        "executed_at_unix_ms": executed_at_unix_ms,
        "approval_expires_at_unix_ms": mediation["approval_expires_at_unix_ms"],
        "status": status,
    }
    body["execution_sha256"] = sha256_json(body)
    result = {
        "schema": RESULT_SCHEMA,
        "approval_sha256": mediation["approval_sha256"],
        "request_sha256": mediation["request_sha256"],
        "binding_sha256": mediation["binding_sha256"],
        "claim_sha256": mediation["claim_sha256"],
        "mediation_sha256": mediation["mediation_sha256"],
        "execution_sha256": body["execution_sha256"],
        "outcome": status,
        "exit_code": native_receipt["process"]["exit_code"],
        "stdout_sha256": native_receipt["output"]["stdout_sha256"],
        "stderr_sha256": native_receipt["output"]["stderr_sha256"],
        "terminal": True,
    }
    result["result_sha256"] = sha256_json(result)
    connection = _ledger_connection(ledger_path)
    try:
        changed = connection.execute(
            "UPDATE windows_action_lifecycle_v0 SET execution_sha256=?,result_sha256=?,status='terminal' "
            "WHERE claim_sha256=? AND mediation_sha256=? AND execution_sha256=? AND status='reserved'",
            (body["execution_sha256"], result["result_sha256"], mediation["claim_sha256"],
             mediation["mediation_sha256"], reservation_sha256),
        ).rowcount
        if changed != 1:
            raise ValueError("Windows execution reservation is absent, replayed, or not terminalizable")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return body, result


def validate_claim(claim):
    findings = []
    keys = {
        "schema", "approval_sha256", "request_sha256", "challenge_sha256",
        "binding_sha256", "capsule_sha256", "invocation_sha256",
        "claimed_at_unix_ms", "approval_expires_at_unix_ms", "status", "claim_sha256",
    }
    if not _closed(claim, keys, "claim", findings):
        return findings
    _hashed_artifact(claim, CLAIM_SCHEMA, "claim_sha256", "claim", findings)
    for key in keys & {"approval_sha256", "request_sha256", "challenge_sha256", "binding_sha256", "capsule_sha256", "invocation_sha256"}:
        _hash(claim.get(key), f"claim.{key}", findings)
    if claim.get("status") != "claimed":
        findings.append("claim.status must equal 'claimed'")
    if type(claim.get("claimed_at_unix_ms")) is not int or type(claim.get("approval_expires_at_unix_ms")) is not int or claim.get("approval_expires_at_unix_ms", 0) <= claim.get("claimed_at_unix_ms", 0):
        findings.append("claim lifetime is invalid")
    return findings


def validate_mediation(mediation):
    findings = []
    keys = {
        "schema", "claim_sha256", "approval_sha256", "request_sha256",
        "binding_sha256", "adapter_sha256", "environment_sha256", "stdin_sha256",
        "stdin_size_bytes", "timeout_ms", "shell", "network", "mediated_at_unix_ms",
        "approval_expires_at_unix_ms", "status", "mediation_sha256",
    }
    if not _closed(mediation, keys, "mediation", findings):
        return findings
    _hashed_artifact(mediation, MEDIATION_SCHEMA, "mediation_sha256", "mediation", findings)
    for key in ("claim_sha256", "approval_sha256", "request_sha256", "binding_sha256", "adapter_sha256", "environment_sha256", "stdin_sha256"):
        _hash(mediation.get(key), f"mediation.{key}", findings)
    if mediation.get("shell") != "denied" or mediation.get("network") != "denied" or mediation.get("status") != "ready":
        findings.append("mediation must remain ready with shell and network denied")
    if type(mediation.get("stdin_size_bytes")) is not int or mediation.get("stdin_size_bytes", -1) < 0:
        findings.append("mediation.stdin_size_bytes must be non-negative")
    if type(mediation.get("timeout_ms")) is not int or not 1 <= mediation.get("timeout_ms", 0) <= 3600000:
        findings.append("mediation.timeout_ms is outside the bounded range")
    return findings


def validate_native_receipt(receipt):
    findings = []
    keys = {
        "schema", "adapter_sha256", "host_probe", "host_probe_sha256",
        "environment_sha256", "input", "limits", "output", "process",
        "native_receipt_sha256",
    }
    if not _closed(receipt, keys, "native_receipt", findings):
        return findings
    _hashed_artifact(receipt, NATIVE_RECEIPT_SCHEMA, "native_receipt_sha256", "native_receipt", findings)
    _hash(receipt.get("adapter_sha256"), "native_receipt.adapter_sha256", findings)
    _hash(receipt.get("host_probe_sha256"), "native_receipt.host_probe_sha256", findings)
    _hash(receipt.get("environment_sha256"), "native_receipt.environment_sha256", findings)
    probe = receipt.get("host_probe")
    findings.extend("native_receipt.host_probe: " + item for item in loom_windows_host.validate_native_probe(probe))
    if isinstance(probe, dict) and receipt.get("host_probe_sha256") != sha256_json(probe):
        findings.append("native_receipt.host_probe_sha256 does not match the native probe")
    input_value = receipt.get("input")
    if _closed(input_value, {"stdin_sha256", "stdin_size_bytes"}, "native_receipt.input", findings):
        _hash(input_value.get("stdin_sha256"), "native_receipt.input.stdin_sha256", findings)
        if type(input_value.get("stdin_size_bytes")) is not int or input_value["stdin_size_bytes"] < 0:
            findings.append("native_receipt.input.stdin_size_bytes must be non-negative")
    limits = receipt.get("limits")
    if _closed(limits, {"timeout_ms", "maximum_output_bytes"}, "native_receipt.limits", findings):
        if type(limits.get("timeout_ms")) is not int or limits["timeout_ms"] <= 0:
            findings.append("native_receipt.limits.timeout_ms must be positive")
        if type(limits.get("maximum_output_bytes")) is not int or limits["maximum_output_bytes"] <= 0:
            findings.append("native_receipt.limits.maximum_output_bytes must be positive")
    output = receipt.get("output")
    output_keys = {"stdout_sha256", "stdout_size_bytes", "stderr_sha256", "stderr_size_bytes"}
    if _closed(output, output_keys, "native_receipt.output", findings):
        for key in ("stdout_sha256", "stderr_sha256"):
            _hash(output.get(key), f"native_receipt.output.{key}", findings)
        for key in ("stdout_size_bytes", "stderr_size_bytes"):
            if type(output.get(key)) is not int or output[key] < 0:
                findings.append(f"native_receipt.output.{key} must be non-negative")
        if isinstance(limits, dict) and all(type(output.get(key)) is int for key in ("stdout_size_bytes", "stderr_size_bytes")) and output["stdout_size_bytes"] + output["stderr_size_bytes"] > limits.get("maximum_output_bytes", -1):
            findings.append("native receipt exceeds the output bound")
    process = receipt.get("process")
    if _closed(process, {"result", "exit_code", "duration_ms"}, "native_receipt.process", findings):
        if process.get("result") not in {"completed", "failed", "timed-out", "output-limit-exceeded", "spawn-failed"}:
            findings.append("native_receipt.process.result is unsupported")
        if process.get("exit_code") is not None and type(process.get("exit_code")) is not int:
            findings.append("native_receipt.process.exit_code must be integer or null")
        if type(process.get("duration_ms")) is not int or process["duration_ms"] < 0:
            findings.append("native_receipt.process.duration_ms must be non-negative")
    return findings


def validate_execution(execution):
    findings = []
    keys = {
        "schema", "mediation_sha256", "claim_sha256", "binding_sha256",
        "reservation_sha256", "native_receipt", "native_receipt_sha256",
        "executed_at_unix_ms", "approval_expires_at_unix_ms", "status", "execution_sha256",
    }
    if not _closed(execution, keys, "execution", findings):
        return findings
    _hashed_artifact(execution, EXECUTION_SCHEMA, "execution_sha256", "execution", findings)
    for key in ("mediation_sha256", "claim_sha256", "binding_sha256", "reservation_sha256", "native_receipt_sha256"):
        _hash(execution.get(key), f"execution.{key}", findings)
    findings.extend(validate_native_receipt(execution.get("native_receipt")))
    receipt = execution.get("native_receipt")
    if isinstance(receipt, dict):
        if execution.get("native_receipt_sha256") != receipt.get("native_receipt_sha256"):
            findings.append("execution native receipt link does not match")
        if execution.get("status") != receipt.get("process", {}).get("result"):
            findings.append("execution status does not match native process result")
    return findings


def validate_result(result):
    findings = []
    keys = {
        "schema", "approval_sha256", "request_sha256", "binding_sha256",
        "claim_sha256", "mediation_sha256", "execution_sha256", "outcome",
        "exit_code", "stdout_sha256", "stderr_sha256", "terminal", "result_sha256",
    }
    if not _closed(result, keys, "result", findings):
        return findings
    _hashed_artifact(result, RESULT_SCHEMA, "result_sha256", "result", findings)
    for key in ("approval_sha256", "request_sha256", "binding_sha256", "claim_sha256", "mediation_sha256", "execution_sha256", "stdout_sha256", "stderr_sha256"):
        _hash(result.get(key), f"result.{key}", findings)
    if result.get("terminal") is not True:
        findings.append("result.terminal must be true")
    if result.get("outcome") not in {"completed", "failed", "timed-out", "output-limit-exceeded", "spawn-failed"}:
        findings.append("result.outcome is unsupported")
    return findings


def validate_witness(witness, expected_commit=None):
    findings = []
    keys = {
        "schema", "test_only", "authorization", "certification_scope", "source",
        "ci", "platform", "toolchain", "approval_request", "operator_public_key",
        "approval_validation", "claim", "mediation",
        "execution", "result_artifact", "checks", "scope", "limitations", "result",
        "witness_sha256",
    }
    if not _closed(witness, keys, "witness", findings):
        return {"valid": False, "findings": findings}
    fixed = {
        "schema": WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-bounded-execution-integration",
        "result": "pass",
    }
    for key, expected in fixed.items():
        if witness.get(key) != expected:
            findings.append(f"witness.{key} must equal {expected!r}")
    source = witness.get("source")
    if _closed(source, {"repository", "commit_sha"}, "source", findings):
        if source.get("repository") != "umbraaeternaa/loom":
            findings.append("source.repository is outside the closed contract")
        if not isinstance(source.get("commit_sha"), str) or not _SHA40.fullmatch(source["commit_sha"]):
            findings.append("source.commit_sha must be lowercase 40-hex")
        if expected_commit is not None and source.get("commit_sha") != expected_commit:
            findings.append("source.commit_sha does not match the expected revision")
    ci = witness.get("ci")
    if _closed(ci, {"provider", "workflow", "job", "runner", "run_id", "run_attempt"}, "ci", findings):
        expected_ci = {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-bounded-execution", "runner": "windows-2025",
        }
        for key, expected in expected_ci.items():
            if ci.get(key) != expected:
                findings.append(f"ci.{key} must equal {expected!r}")
        for key in ("run_id", "run_attempt"):
            if type(ci.get(key)) is not int or ci[key] <= 0:
                findings.append(f"ci.{key} must be positive")
    platform_value = witness.get("platform")
    if _closed(platform_value, {"os", "architecture", "python", "windows_build"}, "platform", findings):
        if platform_value.get("os") != "windows" or platform_value.get("architecture") != "x86_64":
            findings.append("platform must be Windows x86_64")
    toolchain = witness.get("toolchain")
    if _closed(toolchain, {"cl_version", "cl_sha256", "source_sha256", "adapter_sha256"}, "toolchain", findings):
        for key in ("cl_sha256", "source_sha256", "adapter_sha256"):
            _hash(toolchain.get(key), f"toolchain.{key}", findings)
        if not isinstance(toolchain.get("cl_version"), str) or "Compiler Version" not in toolchain["cl_version"]:
            findings.append("toolchain.cl_version is not an MSVC identity")
    approval_validation = witness.get("approval_validation")
    findings.extend(validate_approval_evidence(
        witness.get("approval_request"), approval_validation,
        witness.get("operator_public_key"),
    ))
    claim = witness.get("claim")
    mediation = witness.get("mediation")
    execution = witness.get("execution")
    result = witness.get("result_artifact")
    findings.extend(validate_claim(claim))
    findings.extend(validate_mediation(mediation))
    findings.extend(validate_execution(execution))
    findings.extend(validate_result(result))
    if all(isinstance(item, dict) for item in (approval_validation, claim, mediation, execution, result)):
        expected_links = (
            approval_validation.get("approval_sha256") == claim.get("approval_sha256"),
            claim.get("claim_sha256") == mediation.get("claim_sha256") == execution.get("claim_sha256") == result.get("claim_sha256"),
            mediation.get("mediation_sha256") == execution.get("mediation_sha256") == result.get("mediation_sha256"),
            execution.get("execution_sha256") == result.get("execution_sha256"),
            claim.get("binding_sha256") == mediation.get("binding_sha256") == execution.get("binding_sha256") == result.get("binding_sha256"),
            execution.get("status") == result.get("outcome"),
        )
        if not all(expected_links):
            findings.append("Windows Approval-to-Result cross-links do not close")
    checks = witness.get("checks")
    if not isinstance(checks, list) or [item.get("id") for item in checks if isinstance(item, dict)] != list(EXPECTED_CHECKS) or any(set(item) != {"id", "status"} or item.get("status") != "pass" for item in checks if isinstance(item, dict)):
        findings.append("checks must contain the complete ordered passing check set")
    scope = witness.get("scope")
    expected_scope = {
        "approval_to_result_lifecycle": True,
        "bounded_execution_integration": True,
        "general_purpose_executor": False,
        "operator_presence": False,
        "federation": False,
    }
    if _closed(scope, expected_scope, "scope", findings) and scope != expected_scope:
        findings.append("scope differs from the fixed integration profile")
    limitations = witness.get("limitations")
    if not isinstance(limitations, list) or len(limitations) < 3 or any(not isinstance(item, str) or not item for item in limitations):
        findings.append("limitations must be a non-empty string list")
    else:
        words = " ".join(limitations)
        for marker in ("test-only", "fixed native adapter", "operator presence", "Federation v1"):
            if marker not in words:
                findings.append(f"limitations omit {marker!r}")
    _hash(witness.get("witness_sha256"), "witness.witness_sha256", findings)
    if isinstance(witness.get("witness_sha256"), str):
        body = {key: witness[key] for key in witness if key != "witness_sha256"}
        if witness["witness_sha256"] != sha256_json(body):
            findings.append("witness.witness_sha256 does not match canonical bytes")
    return {"valid": not findings, "findings": findings}
