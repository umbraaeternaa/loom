#!/usr/bin/env python3
"""Spawn-boundary evidence for one mediated Effectful Component execution."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile


SCHEMA = "loom-effectful-component-host-execution/v0"
VALIDATION_SCHEMA = "loom-effectful-component-host-execution-validation/v0"
MEASUREMENT_SCHEMA = "loom-effectful-component-spawn-measurement/v0"
LAUNCH_SCHEMA = "loom-effectful-component-private-launch/v0"
LIFECYCLE_SCHEMA = "loom-effectful-component-host-execution-lifecycle/v0"
MAX_COMPONENT_BYTES = 16 * 1024 * 1024


class Frontend:
    __slots__ = ("resolve_file_uri", "open_path", "stat_identity")

    def __init__(self, resolve_file_uri, open_path, stat_identity):
        self.resolve_file_uri = resolve_file_uri
        self.open_path = open_path
        self.stat_identity = stat_identity


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value):
    return (
        isinstance(value, str) and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _closed_findings(value, path, keys):
    if not isinstance(value, dict):
        return [_finding(path, "expected-object", path + " must be an object")]
    if set(value) != keys:
        return [_finding(
            path, "closed-schema-mismatch", path + " has unknown or missing fields",
        )]
    return []


def result(execution=None, findings=()):
    valid = not findings
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": False,
        "authorization": "terminal-result-required" if valid else "none",
        "execution": execution if valid else None,
        "execution_sha256": execution.get("execution_sha256") if valid else None,
        "findings": list(findings),
    }


def snapshot_component(frontend, binding, component_bytes, component_uri, parent):
    resource = binding["component_resource"]
    source_path = frontend.resolve_file_uri(component_uri, "component_uri")
    source_fd = frontend.open_path(source_path, False)
    directory = None
    target_fd = None
    target_path = None
    try:
        before = os.fstat(source_fd)
        source_identity = frontend.stat_identity(before, "regular-file")
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Effectful Component launch source must be a regular file")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("Effectful Component launch source must not be group/world-writable")
        if source_identity != resource.get("identity"):
            raise ValueError("Effectful Component identity changed after execution binding")
        if before.st_size > MAX_COMPONENT_BYTES:
            raise ValueError("Effectful Component exceeds the 16 MiB launch limit")

        directory = tempfile.mkdtemp(prefix=".loom-effectful-component-", dir=str(parent))
        os.chmod(directory, 0o700)
        target_path = os.path.join(directory, "component.wasm")
        target_fd = os.open(
            target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400,
        )
        source_digest = hashlib.sha256()
        target_digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_COMPONENT_BYTES:
                raise ValueError("Effectful Component changed beyond the launch limit")
            source_digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise OSError("private Component snapshot write made no progress")
                target_digest.update(view[:written])
                view = view[written:]
        os.fsync(target_fd)
        os.fchmod(target_fd, 0o400)
        after = os.fstat(source_fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable):
            raise ValueError("Effectful Component changed while its private snapshot was created")
        supplied = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else None
        digest = source_digest.hexdigest()
        if (
            supplied is None or len(supplied) != total or _sha256(supplied) != digest
            or digest != resource.get("component_sha256")
            or total != resource.get("byte_length")
            or target_digest.hexdigest() != digest
        ):
            raise ValueError("private Component snapshot differs from the verified bound bytes")
        snapshot_stat = os.fstat(target_fd)
        if snapshot_stat.st_size != total or snapshot_stat.st_mode & 0o077:
            raise ValueError("private Component snapshot permissions or size are not closed")
        body = {
            "schema": MEASUREMENT_SCHEMA,
            "source_binding_sha256": binding["binding_sha256"],
            "source_measurement_sha256": resource["measurement_sha256"],
            "source_component_sha256": resource["component_sha256"],
            "source_identity": source_identity,
            "snapshot_component_sha256": digest,
            "snapshot_identity": frontend.stat_identity(snapshot_stat, "regular-file"),
            "byte_length": total,
            "spawn_boundary": "private-component-snapshot",
        }
        body["spawn_measurement_sha256"] = _sha256(_json_bytes(body))
        return body, directory, target_path
    except Exception:
        if target_fd is not None:
            os.close(target_fd)
            target_fd = None
        if target_path is not None:
            try:
                os.unlink(target_path)
            except OSError:
                pass
        if directory is not None:
            try:
                os.rmdir(directory)
            except OSError:
                pass
        raise
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(source_fd)


def build_execution(binding, measurement, action_execution, signed_invocation):
    signed_argv = signed_invocation["argv"]
    argv_prefix = signed_argv[:-1]
    launch = {
        "schema": LAUNCH_SCHEMA,
        "signed_invocation": signed_invocation,
        "signed_invocation_sha256": binding["cross_links"]["invocation_sha256"],
        "runtime_sha256": binding["runtime"]["executable_sha256"],
        "argv_count": len(signed_argv),
        "component_argument_index": len(signed_argv) - 1,
        "argv_prefix_sha256": _sha256(_json_bytes(argv_prefix)),
        "signed_component_uri_sha256": _sha256(signed_argv[-1].encode("utf-8")),
        "snapshot_component_sha256": measurement["snapshot_component_sha256"],
        "path_substitution": "signed-component-uri-to-private-snapshot/v0",
        "shell": "denied",
        "network": "denied",
    }
    launch["launch_sha256"] = _sha256(_json_bytes(launch))
    body = {
        "schema": SCHEMA,
        "execution_binding": binding,
        "binding_sha256": binding["binding_sha256"],
        "component_spawn_measurement": measurement,
        "component_spawn_measurement_sha256": measurement["spawn_measurement_sha256"],
        "launch": launch,
        "launch_sha256": launch["launch_sha256"],
        "action_execution": action_execution,
        "action_execution_sha256": action_execution["execution_sha256"],
        "executed_at_unix_ms": action_execution["executed_at_unix_ms"],
        "approval_expires_at_unix_ms": action_execution["approval_expires_at_unix_ms"],
        "status": action_execution["status"],
        "lifecycle": {
            "schema": LIFECYCLE_SCHEMA,
            "authorization": "none",
            "execution_completed": True,
            "terminal_result_required": True,
            "effectful_result_binding_required": True,
            "component_snapshot_retention": "ephemeral-host-cleanup-required",
            "required_next": "loom-action-capsule-result/v0",
        },
    }
    body["execution_sha256"] = _sha256(_json_bytes(body))
    return body


def structure_findings(execution, binding_findings, action_validation):
    outer_keys = {
        "schema", "execution_binding", "binding_sha256",
        "component_spawn_measurement", "component_spawn_measurement_sha256",
        "launch", "launch_sha256", "action_execution", "action_execution_sha256",
        "executed_at_unix_ms", "approval_expires_at_unix_ms", "status",
        "lifecycle", "execution_sha256",
    }
    findings = _closed_findings(execution, "execution", outer_keys)
    if findings:
        return findings
    if execution.get("schema") != SCHEMA:
        findings.append(_finding("execution.schema", "schema-mismatch", "unsupported host execution schema"))
    for key in (
        "binding_sha256", "component_spawn_measurement_sha256", "launch_sha256",
        "action_execution_sha256", "execution_sha256",
    ):
        if not _is_sha256(execution.get(key)):
            findings.append(_finding("execution." + key, "expected-sha256", key + " must be lowercase SHA-256 hex"))

    binding = execution.get("execution_binding")
    findings.extend(binding_findings(binding))
    if isinstance(binding, dict) and execution.get("binding_sha256") != binding.get("binding_sha256"):
        findings.append(_finding("execution.binding_sha256", "binding-link-mismatch", "outer binding hash does not match the embedded binding"))

    measurement_keys = {
        "schema", "source_binding_sha256", "source_measurement_sha256",
        "source_component_sha256", "source_identity", "snapshot_component_sha256",
        "snapshot_identity", "byte_length", "spawn_boundary", "spawn_measurement_sha256",
    }
    measurement = execution.get("component_spawn_measurement")
    findings.extend(_closed_findings(measurement, "execution.component_spawn_measurement", measurement_keys))
    if isinstance(measurement, dict) and set(measurement) == measurement_keys:
        if measurement.get("schema") != MEASUREMENT_SCHEMA:
            findings.append(_finding("execution.component_spawn_measurement.schema", "schema-mismatch", "unsupported Component spawn measurement schema"))
        if measurement.get("spawn_boundary") != "private-component-snapshot":
            findings.append(_finding("execution.component_spawn_measurement.spawn_boundary", "boundary-mismatch", "Component execution requires a private snapshot"))
        if type(measurement.get("byte_length")) is not int or measurement.get("byte_length", -1) < 0:
            findings.append(_finding("execution.component_spawn_measurement.byte_length", "expected-size", "byte_length must be a non-negative integer"))
        for key in (
            "source_binding_sha256", "source_measurement_sha256", "source_component_sha256",
            "snapshot_component_sha256", "spawn_measurement_sha256",
        ):
            if not _is_sha256(measurement.get(key)):
                findings.append(_finding("execution.component_spawn_measurement." + key, "expected-sha256", key + " must be lowercase SHA-256 hex"))
        try:
            measurement_body = dict(measurement)
            measurement_hash = measurement_body.pop("spawn_measurement_sha256")
            if measurement_hash != _sha256(_json_bytes(measurement_body)):
                findings.append(_finding("execution.component_spawn_measurement.spawn_measurement_sha256", "measurement-hash-mismatch", "Component spawn measurement hash does not match its body"))
        except (TypeError, ValueError):
            findings.append(_finding("execution.component_spawn_measurement", "non-canonical-measurement", "Component spawn measurement must be canonical JSON"))
        if isinstance(binding, dict):
            resource = binding.get("component_resource", {})
            links = {
                "source_binding_sha256": binding.get("binding_sha256"),
                "source_measurement_sha256": resource.get("measurement_sha256"),
                "source_component_sha256": resource.get("component_sha256"),
                "snapshot_component_sha256": resource.get("component_sha256"),
                "byte_length": resource.get("byte_length"),
            }
            for key, expected in links.items():
                if measurement.get(key) != expected:
                    findings.append(_finding("execution.component_spawn_measurement." + key, "measurement-link-mismatch", key + " does not match the execution binding"))
        if execution.get("component_spawn_measurement_sha256") != measurement.get("spawn_measurement_sha256"):
            findings.append(_finding("execution.component_spawn_measurement_sha256", "measurement-link-mismatch", "outer measurement hash does not match the nested measurement"))

    launch_keys = {
        "schema", "signed_invocation", "signed_invocation_sha256", "runtime_sha256", "argv_count",
        "component_argument_index", "argv_prefix_sha256", "signed_component_uri_sha256",
        "snapshot_component_sha256", "path_substitution", "shell", "network", "launch_sha256",
    }
    launch = execution.get("launch")
    findings.extend(_closed_findings(launch, "execution.launch", launch_keys))
    if isinstance(launch, dict) and set(launch) == launch_keys:
        if launch.get("schema") != LAUNCH_SCHEMA:
            findings.append(_finding("execution.launch.schema", "schema-mismatch", "unsupported private launch schema"))
        if launch.get("path_substitution") != "signed-component-uri-to-private-snapshot/v0":
            findings.append(_finding("execution.launch.path_substitution", "substitution-mismatch", "launch must replace only the signed Component path"))
        if launch.get("shell") != "denied" or launch.get("network") != "denied":
            findings.append(_finding("execution.launch", "execution-control-mismatch", "Effectful launch must deny shell and network"))
        signed_invocation = launch.get("signed_invocation")
        signed_argv = (
            signed_invocation.get("argv") if isinstance(signed_invocation, dict) else None
        )
        if isinstance(signed_invocation, dict):
            invocation_keys = {
                "schema", "protocol", "authority", "operation", "foreign_component",
                "adapter", "argv", "working_directory_uri", "environment", "stdin",
                "timeout_ms", "shell", "network", "invocation_sha256",
            }
            if set(signed_invocation) != invocation_keys:
                findings.append(_finding("execution.launch.signed_invocation", "closed-schema-mismatch", "signed invocation has unknown or missing fields"))
            try:
                invocation_body = dict(signed_invocation)
                invocation_hash = invocation_body.pop("invocation_sha256")
                if (
                    invocation_hash != _sha256(_json_bytes(invocation_body))
                    or launch.get("signed_invocation_sha256") != invocation_hash
                ):
                    findings.append(_finding("execution.launch.signed_invocation", "invocation-hash-mismatch", "signed invocation hash does not match its canonical body"))
            except (KeyError, TypeError, ValueError):
                findings.append(_finding("execution.launch.signed_invocation", "non-canonical-invocation", "signed invocation must contain canonical JSON values and its hash"))
            if signed_invocation.get("shell") != "denied" or signed_invocation.get("network") != "denied":
                findings.append(_finding("execution.launch.signed_invocation", "invocation-control-mismatch", "signed invocation must deny shell and network"))
            adapter = signed_invocation.get("adapter")
            if not isinstance(adapter, dict) or adapter.get("artifact_sha256") != launch.get("runtime_sha256"):
                findings.append(_finding("execution.launch.signed_invocation.adapter", "runtime-link-mismatch", "signed invocation adapter does not match the measured runtime"))
        if (
            not isinstance(signed_argv, list) or not signed_argv
            or not all(isinstance(item, str) for item in signed_argv)
        ):
            findings.append(_finding("execution.launch.signed_invocation.argv", "invalid-signed-argv", "signed invocation argv must be a non-empty string array"))
        else:
            expected_argv_links = {
                "argv_count": len(signed_argv),
                "component_argument_index": len(signed_argv) - 1,
                "argv_prefix_sha256": _sha256(_json_bytes(signed_argv[:-1])),
                "signed_component_uri_sha256": _sha256(signed_argv[-1].encode("utf-8")),
            }
            for key, expected in expected_argv_links.items():
                if launch.get(key) != expected:
                    findings.append(_finding("execution.launch." + key, "argv-link-mismatch", key + " does not match signed_argv"))
        try:
            launch_body = dict(launch)
            launch_hash = launch_body.pop("launch_sha256")
            if launch_hash != _sha256(_json_bytes(launch_body)):
                findings.append(_finding("execution.launch.launch_sha256", "launch-hash-mismatch", "launch hash does not match its body"))
        except (TypeError, ValueError):
            findings.append(_finding("execution.launch", "non-canonical-launch", "launch must contain canonical JSON values"))
        if isinstance(binding, dict):
            action_binding = binding.get("cross_links", {})
            expected_launch = {
                "signed_invocation_sha256": action_binding.get("invocation_sha256"),
                "runtime_sha256": binding.get("runtime", {}).get("executable_sha256"),
                "snapshot_component_sha256": binding.get("component_resource", {}).get("component_sha256"),
            }
            for key, expected in expected_launch.items():
                if launch.get(key) != expected:
                    findings.append(_finding("execution.launch." + key, "launch-link-mismatch", key + " does not match the execution binding"))
        if isinstance(measurement, dict) and launch.get("snapshot_component_sha256") != measurement.get("snapshot_component_sha256"):
            findings.append(_finding("execution.launch.snapshot_component_sha256", "launch-link-mismatch", "launch does not reference the measured private Component snapshot"))
        if execution.get("launch_sha256") != launch.get("launch_sha256"):
            findings.append(_finding("execution.launch_sha256", "launch-link-mismatch", "outer launch hash does not match nested launch evidence"))

    action_execution = execution.get("action_execution")
    action_check = action_validation(action_execution)
    if not action_check.get("valid"):
        for item in action_check.get("findings", ()):
            findings.append(_finding(
                "execution.action_execution." + item.get("path", ""),
                item.get("code", "invalid-action-execution"), item.get("message", "invalid Action execution"),
            ))
    if isinstance(action_execution, dict):
        if execution.get("action_execution_sha256") != action_execution.get("execution_sha256"):
            findings.append(_finding("execution.action_execution_sha256", "action-execution-link-mismatch", "outer Action execution hash does not match the nested execution"))
        if isinstance(binding, dict):
            cross_links = binding.get("cross_links", {})
            links = {
                "mediation_sha256": cross_links.get("mediation_sha256"),
                "claim_sha256": cross_links.get("claim_sha256"),
                "binding_sha256": cross_links.get("binding_sha256"),
            }
            for key, expected in links.items():
                if action_execution.get(key) != expected:
                    findings.append(_finding("execution.action_execution." + key, "action-link-mismatch", key + " does not match the Effectful execution binding"))
        for key in ("executed_at_unix_ms", "approval_expires_at_unix_ms", "status"):
            if execution.get(key) != action_execution.get(key):
                findings.append(_finding("execution." + key, "action-link-mismatch", key + " does not match the nested Action execution"))

    expected_lifecycle = {
        "schema": LIFECYCLE_SCHEMA,
        "authorization": "none",
        "execution_completed": True,
        "terminal_result_required": True,
        "effectful_result_binding_required": True,
        "component_snapshot_retention": "ephemeral-host-cleanup-required",
        "required_next": "loom-action-capsule-result/v0",
    }
    if execution.get("lifecycle") != expected_lifecycle:
        findings.append(_finding("execution.lifecycle", "lifecycle-mismatch", "host execution lifecycle must require the terminal Action Result"))
    try:
        body = dict(execution)
        supplied_hash = body.pop("execution_sha256")
        if supplied_hash != _sha256(_json_bytes(body)):
            findings.append(_finding("execution.execution_sha256", "execution-hash-mismatch", "host execution hash does not match its body"))
    except (TypeError, ValueError):
        findings.append(_finding("execution", "non-canonical-execution", "host execution must contain canonical JSON values"))
    return findings


def validate_execution(execution, binding_findings, action_validation):
    findings = structure_findings(execution, binding_findings, action_validation)
    return result(execution, findings)
