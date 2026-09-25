"""Closed contracts for Windows General Adapter Execution v1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct

import loom_windows_execution as lifecycle


REQUEST_SCHEMA = "loom-windows-general-execution-request/v1"
OBSERVATION_SCHEMA = "loom-windows-general-native-observation/v1"
RECEIPT_SCHEMA = "loom-windows-general-native-receipt/v1"
EXECUTION_SCHEMA = "loom-windows-general-execution/v1"
RESULT_SCHEMA = "loom-windows-general-result/v1"
WITNESS_SCHEMA = "loom-windows-general-execution-ci-witness/v1"

REQUEST_MAGIC = b"LOOMGX1\0"
RESPONSE_MAGIC = b"LOOMGR1\0"
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_STDIN_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ITEMS = 64
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_json(value):
    return sha256_bytes(canonical_json(value))


def _closed(value, keys, label, findings):
    if not isinstance(value, dict):
        findings.append(f"{label} must be an object")
        return False
    if set(value) != set(keys):
        findings.append(f"{label} is not closed")
        return False
    return True


def _hash(value, label, findings):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        findings.append(f"{label} must be lowercase SHA-256")


def _text(value, label, findings):
    if not isinstance(value, str) or not value or "\x00" in value:
        findings.append(f"{label} must be non-empty text without NUL")
        return
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        findings.append(f"{label} exceeds the UTF-8 byte bound")


def build_request(approval_request, target_path, target_argv, environment, stdin_bytes,
                  timeout_ms, maximum_output_bytes=MAX_OUTPUT_BYTES):
    """Bind one exact approved general target invocation to the native frame."""
    findings = []
    supplied_path = Path(target_path)
    if supplied_path.is_symlink():
        raise ValueError("general execution target must not be a symlink")
    path = supplied_path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("general execution target must be one regular non-symlink file")
    target_sha256 = sha256_bytes(path.read_bytes())
    if not isinstance(target_argv, list) or len(target_argv) > MAX_ITEMS:
        raise ValueError("target argv is outside the closed item bound")
    if not isinstance(environment, dict) or len(environment) > MAX_ITEMS:
        raise ValueError("target environment is outside the closed item bound")
    if not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STDIN_BYTES:
        raise ValueError("target stdin is outside the closed byte bound")
    for index, value in enumerate(target_argv):
        _text(value, f"target_argv[{index}]", findings)
    reserved = {"LOCALAPPDATA", "TEMP", "TMP"}
    for name, value in environment.items():
        _text(name, "environment name", findings)
        if "=" in name or name.upper() in reserved:
            findings.append(f"environment name {name!r} is reserved or malformed")
        _text(value, f"environment[{name!r}]", findings)
    if findings:
        raise ValueError("invalid general execution input: " + "; ".join(findings))
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 300000:
        raise ValueError("timeout_ms must be in 1..300000")
    if type(maximum_output_bytes) is not int or not 1 <= maximum_output_bytes <= MAX_OUTPUT_BYTES:
        raise ValueError("maximum_output_bytes is outside the closed bound")
    invocation = approval_request.get("binding", {}).get("invocation", {})
    expected_argv = ["--execute-v1", target_sha256, *target_argv]
    commitments = [
        {"name": name, "value_sha256": sha256_bytes(value.encode("utf-8"))}
        for name, value in sorted(environment.items())
    ]
    expected = {
        "argv": expected_argv,
        "environment": commitments,
        "stdin_sha256": sha256_bytes(stdin_bytes),
        "timeout_ms": timeout_ms,
        "shell": "denied",
        "network": "denied",
    }
    observed = {
        "argv": invocation.get("argv"),
        "environment": invocation.get("environment"),
        "stdin_sha256": invocation.get("stdin", {}).get("payload_sha256"),
        "timeout_ms": invocation.get("timeout_ms"),
        "shell": invocation.get("shell"),
        "network": invocation.get("network"),
    }
    if observed != expected:
        raise ValueError("Approval v2 Invocation Binding does not match the general execution")
    body = {
        "schema": REQUEST_SCHEMA,
        "approval_request_sha256": approval_request.get("request_sha256"),
        "binding_sha256": approval_request.get("binding", {}).get("binding_sha256"),
        "target": {
            "path": str(path),
            "artifact_sha256": target_sha256,
            "argv": target_argv,
        },
        "environment": [{"name": name, "value": value} for name, value in sorted(environment.items())],
        "stdin": {"sha256": sha256_bytes(stdin_bytes), "size_bytes": len(stdin_bytes)},
        "limits": {"timeout_ms": timeout_ms, "maximum_output_bytes": maximum_output_bytes},
        "shell": "denied",
        "network": "denied",
    }
    body["request_sha256"] = sha256_json(body)
    return body


def validate_request(request):
    findings = []
    keys = {
        "schema", "approval_request_sha256", "binding_sha256", "target", "environment",
        "stdin", "limits", "shell", "network", "request_sha256",
    }
    if not _closed(request, keys, "request", findings):
        return findings
    if request.get("schema") != REQUEST_SCHEMA:
        findings.append("request.schema is unsupported")
    for key in ("approval_request_sha256", "binding_sha256", "request_sha256"):
        _hash(request.get(key), f"request.{key}", findings)
    try:
        expected_hash = sha256_json({key: request[key] for key in request if key != "request_sha256"})
        if request.get("request_sha256") != expected_hash:
            findings.append("request.request_sha256 does not match canonical bytes")
    except (TypeError, ValueError):
        findings.append("request is not canonical JSON")
    target = request.get("target")
    if _closed(target, {"path", "artifact_sha256", "argv"}, "request.target", findings):
        _text(target.get("path"), "request.target.path", findings)
        _hash(target.get("artifact_sha256"), "request.target.artifact_sha256", findings)
        argv = target.get("argv")
        if not isinstance(argv, list) or len(argv) > MAX_ITEMS:
            findings.append("request.target.argv is outside the item bound")
        else:
            for index, value in enumerate(argv):
                _text(value, f"request.target.argv[{index}]", findings)
    environment = request.get("environment")
    if not isinstance(environment, list) or len(environment) > MAX_ITEMS:
        findings.append("request.environment is outside the item bound")
    else:
        names = []
        for index, item in enumerate(environment):
            if _closed(item, {"name", "value"}, f"request.environment[{index}]", findings):
                _text(item.get("name"), f"request.environment[{index}].name", findings)
                _text(item.get("value"), f"request.environment[{index}].value", findings)
                names.append(item.get("name"))
        if names != sorted(names) or len(set(name.lower() for name in names if isinstance(name, str))) != len(names):
            findings.append("request.environment names must be sorted and case-insensitively unique")
        if any(isinstance(name, str) and ("=" in name or name.upper() in {"LOCALAPPDATA", "TEMP", "TMP"}) for name in names):
            findings.append("request.environment contains a reserved or malformed name")
    stdin = request.get("stdin")
    if _closed(stdin, {"sha256", "size_bytes"}, "request.stdin", findings):
        _hash(stdin.get("sha256"), "request.stdin.sha256", findings)
        if type(stdin.get("size_bytes")) is not int or not 0 <= stdin["size_bytes"] <= MAX_STDIN_BYTES:
            findings.append("request.stdin.size_bytes is outside the byte bound")
    limits = request.get("limits")
    if _closed(limits, {"timeout_ms", "maximum_output_bytes"}, "request.limits", findings):
        if type(limits.get("timeout_ms")) is not int or not 1 <= limits["timeout_ms"] <= 300000:
            findings.append("request.limits.timeout_ms is outside the bound")
        if type(limits.get("maximum_output_bytes")) is not int or not 1 <= limits["maximum_output_bytes"] <= MAX_OUTPUT_BYTES:
            findings.append("request.limits.maximum_output_bytes is outside the bound")
    if request.get("shell") != "denied" or request.get("network") != "denied":
        findings.append("general execution must deny shell and network")
    return findings


def encode_request(request, stdin_bytes):
    findings = validate_request(request)
    if findings:
        raise ValueError("invalid general execution request: " + "; ".join(findings))
    if not isinstance(stdin_bytes, bytes) or sha256_bytes(stdin_bytes) != request["stdin"]["sha256"]:
        raise ValueError("stdin bytes do not match the general execution request")
    target_path = Path(request["target"]["path"])
    if target_path.is_symlink() or not target_path.is_file():
        raise ValueError("target became a non-file or symlink before framing")
    if sha256_bytes(target_path.read_bytes()) != request["target"]["artifact_sha256"]:
        raise ValueError("target bytes changed before framing")

    def field(value):
        raw = value.encode("utf-8")
        if not 0 < len(raw) <= MAX_TEXT_BYTES:
            raise ValueError("request text is outside the byte bound")
        return struct.pack("<I", len(raw)) + raw

    body = bytearray(REQUEST_MAGIC)
    body.extend(bytes.fromhex(request["request_sha256"]))
    body.extend(bytes.fromhex(request["target"]["artifact_sha256"]))
    body.extend(struct.pack(
        "<7I", 1, request["limits"]["timeout_ms"],
        request["limits"]["maximum_output_bytes"], len(request["target"]["argv"]),
        len(request["environment"]), len(stdin_bytes), 0,
    ))
    body.extend(field(request["target"]["path"]))
    for value in request["target"]["argv"]:
        body.extend(field(value))
    for item in request["environment"]:
        body.extend(field(item["name"]))
        body.extend(field(item["value"]))
    body.extend(stdin_bytes)
    if len(body) > MAX_FRAME_BYTES:
        raise ValueError("encoded general execution request exceeds the frame bound")
    return bytes(body)


def parse_response(raw, request):
    if not isinstance(raw, bytes) or len(raw) < 20 or raw[:8] != RESPONSE_MAGIC:
        raise ValueError("native response has an invalid envelope")
    json_size, stdout_size, stderr_size = struct.unpack("<3I", raw[8:20])
    expected_size = 20 + json_size + stdout_size + stderr_size
    if expected_size != len(raw) or stdout_size + stderr_size > request["limits"]["maximum_output_bytes"]:
        raise ValueError("native response lengths violate the exact output bound")
    try:
        observation = json.loads(raw[20:20 + json_size].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("native observation is not canonical UTF-8 JSON") from exc
    stdout_start = 20 + json_size
    stdout_bytes = raw[stdout_start:stdout_start + stdout_size]
    stderr_bytes = raw[stdout_start + stdout_size:]
    findings = validate_observation(observation, request)
    if findings:
        raise ValueError("invalid native observation: " + "; ".join(findings))
    return observation, stdout_bytes, stderr_bytes


def validate_observation(observation, request):
    findings = []
    keys = {
        "schema", "request_sha256", "target_sha256", "snapshot_sha256", "private_snapshot",
        "appcontainer", "capabilities", "job_process_limit", "network", "status", "exit_code",
        "timed_out", "output_limited",
    }
    if not _closed(observation, keys, "observation", findings):
        return findings
    fixed = {
        "schema": OBSERVATION_SCHEMA,
        "request_sha256": request.get("request_sha256"),
        "target_sha256": request.get("target", {}).get("artifact_sha256"),
        "snapshot_sha256": request.get("target", {}).get("artifact_sha256"),
        "private_snapshot": "byte-identical", "appcontainer": True,
        "capabilities": [], "job_process_limit": 1, "network": "denied",
    }
    for key, expected in fixed.items():
        if observation.get(key) != expected:
            findings.append(f"observation.{key} does not match the closed contract")
    status = observation.get("status")
    if status not in {"exited", "failed", "timeout", "output-limit"}:
        findings.append("observation.status is unsupported")
    if type(observation.get("exit_code")) is not int:
        findings.append("observation.exit_code must be an integer")
    if type(observation.get("timed_out")) is not bool or type(observation.get("output_limited")) is not bool:
        findings.append("observation terminal flags must be booleans")
    if (status == "timeout") != (observation.get("timed_out") is True):
        findings.append("observation timeout status and flag differ")
    if (status == "output-limit") != (observation.get("output_limited") is True):
        findings.append("observation output-limit status and flag differ")
    return findings


def build_native_receipt(adapter_sha256, request, observation, stdout_bytes, stderr_bytes,
                         duration_ms):
    findings = validate_observation(observation, request)
    if findings:
        raise ValueError("invalid native observation: " + "; ".join(findings))
    status_map = {
        "exited": "completed", "failed": "failed", "timeout": "timed-out",
        "output-limit": "output-limit-exceeded",
    }
    body = {
        "schema": RECEIPT_SCHEMA,
        "adapter_sha256": adapter_sha256,
        "general_request_sha256": request["request_sha256"],
        "native_observation": observation,
        "native_observation_sha256": sha256_json(observation),
        "input": {"stdin_sha256": request["stdin"]["sha256"], "stdin_size_bytes": request["stdin"]["size_bytes"]},
        "environment_sha256": sha256_json([
            {"name": item["name"], "value_sha256": sha256_bytes(item["value"].encode("utf-8"))}
            for item in request["environment"]
        ]),
        "limits": request["limits"],
        "output": {
            "stdout_sha256": sha256_bytes(stdout_bytes), "stdout_size_bytes": len(stdout_bytes),
            "stderr_sha256": sha256_bytes(stderr_bytes), "stderr_size_bytes": len(stderr_bytes),
        },
        "process": {
            "result": status_map[observation["status"]],
            "exit_code": observation["exit_code"], "duration_ms": duration_ms,
        },
    }
    body["native_receipt_sha256"] = sha256_json(body)
    return body


def validate_native_receipt(receipt):
    findings = []
    keys = {
        "schema", "adapter_sha256", "general_request_sha256", "native_observation",
        "native_observation_sha256", "input", "environment_sha256", "limits", "output",
        "process", "native_receipt_sha256",
    }
    if not _closed(receipt, keys, "native_receipt", findings):
        return findings
    if receipt.get("schema") != RECEIPT_SCHEMA:
        findings.append("native_receipt.schema is unsupported")
    for key in ("adapter_sha256", "general_request_sha256", "native_observation_sha256", "environment_sha256", "native_receipt_sha256"):
        _hash(receipt.get(key), f"native_receipt.{key}", findings)
    try:
        if receipt.get("native_observation_sha256") != sha256_json(receipt.get("native_observation")):
            findings.append("native observation hash does not match")
        if receipt.get("native_receipt_sha256") != sha256_json({key: receipt[key] for key in receipt if key != "native_receipt_sha256"}):
            findings.append("native receipt hash does not match")
    except (TypeError, ValueError):
        findings.append("native receipt is not canonical JSON")
    input_value = receipt.get("input")
    if _closed(input_value, {"stdin_sha256", "stdin_size_bytes"}, "native_receipt.input", findings):
        _hash(input_value.get("stdin_sha256"), "native_receipt.input.stdin_sha256", findings)
        if type(input_value.get("stdin_size_bytes")) is not int or not 0 <= input_value["stdin_size_bytes"] <= MAX_STDIN_BYTES:
            findings.append("native receipt stdin size is outside the bound")
    limits = receipt.get("limits")
    if _closed(limits, {"timeout_ms", "maximum_output_bytes"}, "native_receipt.limits", findings):
        if type(limits.get("timeout_ms")) is not int or not 1 <= limits["timeout_ms"] <= 300000:
            findings.append("native receipt timeout is outside the bound")
        if type(limits.get("maximum_output_bytes")) is not int or not 1 <= limits["maximum_output_bytes"] <= MAX_OUTPUT_BYTES:
            findings.append("native receipt output limit is outside the bound")
    output = receipt.get("output", {})
    if set(output) != {"stdout_sha256", "stdout_size_bytes", "stderr_sha256", "stderr_size_bytes"}:
        findings.append("native receipt output is not closed")
    else:
        _hash(output.get("stdout_sha256"), "native_receipt.output.stdout_sha256", findings)
        _hash(output.get("stderr_sha256"), "native_receipt.output.stderr_sha256", findings)
        if any(type(output.get(key)) is not int or output[key] < 0 for key in ("stdout_size_bytes", "stderr_size_bytes")):
            findings.append("native receipt output sizes are invalid")
        elif isinstance(limits, dict) and output["stdout_size_bytes"] + output["stderr_size_bytes"] > limits.get("maximum_output_bytes", -1):
            findings.append("native receipt exceeds the combined output bound")
    process = receipt.get("process", {})
    if set(process) != {"result", "exit_code", "duration_ms"} or process.get("result") not in {
        "completed", "failed", "timed-out", "output-limit-exceeded",
    }:
        findings.append("native receipt process is unsupported")
    return findings


def validate_witness(witness, expected_commit=None):
    findings = []
    keys = {
        "schema", "test_only", "authorization", "certification_scope", "source", "ci",
        "platform", "toolchain", "approval_request", "operator_public_key",
        "approval_validation", "general_request", "claim", "mediation", "execution",
        "result_artifact", "checks", "scope", "limitations", "result", "witness_sha256",
    }
    if not _closed(witness, keys, "witness", findings):
        return {"valid": False, "findings": findings}
    fixed = {
        "schema": WITNESS_SCHEMA, "test_only": True, "authorization": "none",
        "certification_scope": "windows-general-adapter-execution-v1", "result": "pass",
    }
    for key, expected in fixed.items():
        if witness.get(key) != expected:
            findings.append(f"witness.{key} differs from the closed profile")
    source = witness.get("source", {})
    if set(source) != {"repository", "commit_sha"} or source.get("repository") != "umbraaeternaa/loom":
        findings.append("witness.source is outside the repository profile")
    elif expected_commit is not None and source.get("commit_sha") != expected_commit:
        findings.append("witness source commit does not match the expected revision")
    ci = witness.get("ci", {})
    expected_ci = {
        "provider": "github-actions", "workflow": "LOOM Citadel",
        "job": "verify-windows-general-execution", "runner": "windows-2025",
    }
    if not all(ci.get(key) == value for key, value in expected_ci.items()):
        findings.append("witness CI identity differs from the closed profile")
    toolchain = witness.get("toolchain", {})
    toolchain_keys = {
        "cl_version", "cl_sha256", "adapter_source_sha256", "host_source_sha256",
        "target_source_sha256", "adapter_sha256", "target_sha256", "reproducible_builds",
    }
    if set(toolchain) != toolchain_keys or toolchain.get("reproducible_builds") is not True:
        findings.append("witness toolchain is not one closed reproducible build record")
    else:
        for key in toolchain_keys - {"cl_version", "reproducible_builds"}:
            _hash(toolchain.get(key), f"witness.toolchain.{key}", findings)
    findings.extend(lifecycle.validate_approval_evidence(
        witness.get("approval_request"), witness.get("approval_validation"),
        witness.get("operator_public_key"),
    ))
    request = witness.get("general_request")
    findings.extend(validate_request(request))
    claim = witness.get("claim")
    mediation = witness.get("mediation")
    execution = witness.get("execution")
    result = witness.get("result_artifact")
    findings.extend(lifecycle.validate_claim(claim))
    findings.extend(lifecycle.validate_mediation(mediation))
    if not isinstance(execution, dict) or execution.get("schema") != EXECUTION_SCHEMA:
        findings.append("witness execution schema is unsupported")
    elif execution.get("execution_sha256") != sha256_json({key: execution[key] for key in execution if key != "execution_sha256"}):
        findings.append("witness execution hash does not match")
    else:
        findings.extend(validate_native_receipt(execution.get("native_receipt")))
        nested_receipt = execution.get("native_receipt")
        if isinstance(nested_receipt, dict):
            findings.extend(validate_observation(nested_receipt.get("native_observation"), request))
    if not isinstance(result, dict) or result.get("schema") != RESULT_SCHEMA:
        findings.append("witness result schema is unsupported")
    elif result.get("result_sha256") != sha256_json({key: result[key] for key in result if key != "result_sha256"}):
        findings.append("witness result hash does not match")
    if all(isinstance(item, dict) for item in (claim, mediation, execution, result, request)):
        links = (
            claim.get("claim_sha256") == mediation.get("claim_sha256") == execution.get("claim_sha256") == result.get("claim_sha256"),
            mediation.get("mediation_sha256") == execution.get("mediation_sha256") == result.get("mediation_sha256"),
            execution.get("execution_sha256") == result.get("execution_sha256"),
            execution.get("general_request_sha256") == request.get("request_sha256"),
            execution.get("status") == result.get("outcome"),
        )
        if not all(links):
            findings.append("witness Approval-to-Result cross-links do not close")
    expected_checks = [
        "signed-approval-to-terminal-result", "exact-environment-parent-secret-denial",
        "one-use-replay-refusal",
        "target-hash-tamper-refusal", "target-reparse-refusal",
        "live-loopback-network-denial", "child-process-denial",
        "streaming-output-limit-termination", "wall-clock-timeout-termination",
    ]
    checks = witness.get("checks")
    if not isinstance(checks, list) or [item.get("id") for item in checks if isinstance(item, dict)] != expected_checks:
        findings.append("witness checks are incomplete or out of order")
    elif any(set(item) != {"id", "status"} or item.get("status") != "pass" for item in checks):
        findings.append("witness checks must all pass")
    scope = witness.get("scope", {})
    expected_scope = {
        "arbitrary_approved_pe_target": True, "zero_capability_appcontainer": True,
        "one_process_job": True, "bounded_streams": True,
        "operator_presence": False, "production_authority": False,
    }
    if scope != expected_scope:
        findings.append("witness scope differs from the bounded v1 profile")
    limitations = witness.get("limitations")
    if not isinstance(limitations, list) or len(limitations) < 3 or any(not isinstance(item, str) or not item for item in limitations):
        findings.append("witness limitations are incomplete")
    _hash(witness.get("witness_sha256"), "witness.witness_sha256", findings)
    try:
        if witness.get("witness_sha256") != sha256_json({key: witness[key] for key in witness if key != "witness_sha256"}):
            findings.append("witness hash does not match canonical bytes")
    except (TypeError, ValueError):
        findings.append("witness is not canonical JSON")
    return {"valid": not findings, "findings": findings}


def complete(mediation, reservation_sha256, request, native_receipt,
             executed_at_unix_ms, ledger_path):
    """Atomically terminalize one v0 claim/mediation as a general v1 result."""
    findings = validate_native_receipt(native_receipt)
    findings.extend(validate_observation(native_receipt.get("native_observation"), request))
    if findings:
        raise ValueError("invalid general native receipt: " + "; ".join(findings))
    links = {
        "adapter": native_receipt["adapter_sha256"] == mediation["adapter_sha256"],
        "stdin": native_receipt["input"]["stdin_sha256"] == mediation["stdin_sha256"],
        "environment": native_receipt["environment_sha256"] == mediation["environment_sha256"],
        "timeout": native_receipt["limits"]["timeout_ms"] == mediation["timeout_ms"],
        "request": native_receipt["general_request_sha256"] == request["request_sha256"],
    }
    if not all(links.values()):
        raise ValueError("general native receipt does not match mediation or request")
    if type(executed_at_unix_ms) is not int or executed_at_unix_ms >= mediation["approval_expires_at_unix_ms"]:
        raise ValueError("general execution completed outside the approval lifetime")
    body = {
        "schema": EXECUTION_SCHEMA,
        "mediation_sha256": mediation["mediation_sha256"],
        "claim_sha256": mediation["claim_sha256"],
        "binding_sha256": mediation["binding_sha256"],
        "general_request_sha256": request["request_sha256"],
        "reservation_sha256": reservation_sha256,
        "native_receipt": native_receipt,
        "native_receipt_sha256": native_receipt["native_receipt_sha256"],
        "executed_at_unix_ms": executed_at_unix_ms,
        "status": native_receipt["process"]["result"],
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
        "outcome": body["status"],
        "exit_code": native_receipt["process"]["exit_code"],
        "stdout_sha256": native_receipt["output"]["stdout_sha256"],
        "stderr_sha256": native_receipt["output"]["stderr_sha256"],
        "terminal": True,
    }
    result["result_sha256"] = sha256_json(result)
    connection = lifecycle._ledger_connection(ledger_path)
    try:
        changed = connection.execute(
            "UPDATE windows_action_lifecycle_v0 SET execution_sha256=?,result_sha256=?,status='terminal' "
            "WHERE claim_sha256=? AND mediation_sha256=? AND execution_sha256=? AND status='reserved'",
            (body["execution_sha256"], result["result_sha256"], mediation["claim_sha256"],
             mediation["mediation_sha256"], reservation_sha256),
        ).rowcount
        if changed != 1:
            raise ValueError("general execution reservation is absent, replayed, or not terminalizable")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return body, result


def require_windows():
    """Fail closed on hosts that cannot produce native Windows evidence."""
    import os
    if os.name != "nt":
        raise RuntimeError("Windows General Adapter Execution v1 requires a native Windows host")
