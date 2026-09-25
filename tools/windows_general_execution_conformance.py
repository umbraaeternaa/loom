#!/usr/bin/env python3
"""Certify Windows General Adapter Execution v1 and its adversarial boundaries."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom
import loom_provenance
import loom_windows_execution as lifecycle
import loom_windows_general as contract
from tools import windows_bounded_execution_conformance as fixture


EXPECTED_RUNNER = "windows-2025"
EXPECTED_PYTHON = (3, 12)
ADAPTER_SOURCE = ROOT / "tools" / "windows-bounded-execution" / "general_execution_adapter.c"
TARGET_SOURCE = ROOT / "tools" / "windows-bounded-execution" / "general_execution_target.c"
HOST_SOURCE = ROOT / "tools" / "windows-host-security" / "host_security_probe.c"


def _run(argv, *, cwd=ROOT, timeout=180, input_bytes=None, env=None):
    return subprocess.run(
        [str(item) for item in argv], cwd=cwd, input=input_bytes,
        capture_output=True, timeout=timeout, env=env,
    )


def _compiler():
    raw = os.environ.get("LOOM_WINDOWS_CL", "")
    if not raw:
        raise AssertionError("LOOM_WINDOWS_CL is required")
    path = Path(raw).resolve(strict=True)
    if not path.is_file() or path.name.lower() != "cl.exe":
        raise AssertionError("LOOM_WINDOWS_CL must name cl.exe")
    version = _run([path], timeout=30)
    identity = (version.stdout + version.stderr).decode("utf-8", "strict").strip()
    if "Compiler Version" not in identity or "for x64" not in identity:
        raise AssertionError("MSVC x64 compiler identity is outside the contract")
    return path, identity


def _build(cl, source, destination, output_name, libraries):
    output = destination / output_name
    result = _run([
        cl, "/nologo", "/W4", "/WX", "/O2", "/MT", "/Brepro", "/DUNICODE",
        "/D_UNICODE", "/D_WIN32_WINNT=0x0A00", source, f"/Fe:{output}",
        "/link", "/Brepro", *libraries,
    ], cwd=destination)
    if result.returncode or not output.is_file():
        detail = (result.stdout + result.stderr).decode("utf-8", "replace")[-4000:]
        raise AssertionError(f"native build failed for {source.name}: {detail}")
    return output


def _build_pair(cl, root):
    adapter_a = root / "adapter-a"
    adapter_b = root / "adapter-b"
    target_a = root / "target-a"
    target_b = root / "target-b"
    for directory in (adapter_a, adapter_b, target_a, target_b):
        directory.mkdir()
    adapter_libs = ["advapi32.lib", "bcrypt.lib", "ole32.lib", "userenv.lib", "ws2_32.lib"]
    target_libs = ["advapi32.lib", "ws2_32.lib"]
    adapters = [
        _build(cl, ADAPTER_SOURCE, adapter_a, "loom-windows-general-adapter.exe", adapter_libs),
        _build(cl, ADAPTER_SOURCE, adapter_b, "loom-windows-general-adapter.exe", adapter_libs),
    ]
    targets = [
        _build(cl, TARGET_SOURCE, target_a, "loom-windows-general-target.exe", target_libs),
        _build(cl, TARGET_SOURCE, target_b, "loom-windows-general-target.exe", target_libs),
    ]
    if contract.sha256_bytes(adapters[0].read_bytes()) != contract.sha256_bytes(adapters[1].read_bytes()):
        raise AssertionError("/Brepro adapter builds differ")
    if contract.sha256_bytes(targets[0].read_bytes()) != contract.sha256_bytes(targets[1].read_bytes()):
        raise AssertionError("/Brepro target builds differ")
    return adapters[0], targets[0]


def _approval_fixture(adapter, target, argv, environment, timeout_ms, issued_at):
    compiler_components = loom_provenance.collect_compiler_components(ROOT, "modular-python")
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Certify one Windows general adapter execution",
            "intent": "Bind an exact target to zero-capability native confinement",
        },
        "repositories": [], "read_paths": [], "write_paths": [],
        "actions": ["process"], "evidence_required": [],
    }
    manifest_check = loom.validate_manifest(manifest)
    if not manifest_check["valid"]:
        raise AssertionError("fixture manifest failed: " + repr(manifest_check["findings"]))
    tool_input = {"action": "process", "manifest_sha256": manifest_check["manifest_sha256"]}
    tool_check = loom.build_tool_binding(
        "local-process/v1", "urn:loom:host:operator-gate", "process", tool_input,
    )
    if not tool_check["valid"]:
        raise AssertionError("fixture Tool Binding failed: " + repr(tool_check["findings"]))
    tool_binding = tool_check["binding"]
    stdin_bytes = contract.canonical_json(tool_input)
    if tool_binding["input_sha256"] != contract.sha256_bytes(stdin_bytes):
        raise AssertionError("Tool Binding input is not canonical invocation stdin")
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool_binding["binding_sha256"]}"))))'
    )
    wasm = loom.compile_wasm(source)
    target_sha256 = contract.sha256_bytes(target.read_bytes())
    commitments = [
        {"name": name, "value_sha256": contract.sha256_bytes(value.encode("utf-8"))}
        for name, value in sorted(environment.items())
    ]
    invocation = {
        "schema": "loom-local-process-invocation/v0",
        "protocol": "local-process/v1",
        "authority": "urn:loom:host:operator-gate",
        "operation": "process",
        "foreign_component": "operator-gate",
        "adapter": {
            "schema": "loom-host-adapter-identity/v0",
            "executable_uri": adapter.resolve().as_uri(),
            "artifact_sha256": contract.sha256_bytes(adapter.read_bytes()),
            "entrypoint": "process",
        },
        "argv": ["--execute-v1", target_sha256, *argv],
        "working_directory_uri": adapter.parent.resolve().as_uri(),
        "environment": commitments,
        "stdin": {
            "schema": "loom-action-invocation-stdin/v0",
            "encoding": "canonical-json/utf-8",
            "payload_sha256": contract.sha256_bytes(stdin_bytes),
        },
        "timeout_ms": timeout_ms,
        "shell": "denied",
        "network": "denied",
    }
    binding_check = loom.build_action_invocation_binding_v0(
        manifest, tool_binding, tool_input, source, wasm, compiler_components, "main", invocation,
    )
    if not binding_check["valid"]:
        raise AssertionError("Invocation Binding failed: " + repr(binding_check["findings"]))
    request_check = loom.build_action_approval_request_v2(binding_check["binding"], "8" * 64)
    if not request_check["valid"]:
        raise AssertionError("Approval request failed: " + repr(request_check["findings"]))
    request = request_check["request"]
    approval = fixture._sign({
        "schema": "loom-action-capsule-approval/v2",
        "request_sha256": request["request_sha256"],
        "challenge_sha256": request["challenge"]["challenge_sha256"],
        "binding_sha256": request["binding"]["binding_sha256"],
        "capsule_sha256": request["binding"]["capsule_sha256"],
        "invocation_sha256": request["binding"]["invocation_sha256"],
        "approval_scope": "exact-invocation", "approver": "operator", "decision": "approve",
        "issued_at_unix_ms": issued_at, "expires_at_unix_ms": issued_at + 300000,
        "claim_required": True, "key_sha256": loom._binding_sha256(fixture.TEST_KEY),
    })
    approval_check = loom._verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, source, wasm,
        "modular-python", compiler_components, compiler_components, "main", invocation,
        issued_at + 1, fixture.TEST_KEY,
    )
    if not approval_check["valid"]:
        raise AssertionError("signed Approval v2 failed: " + repr(approval_check["findings"]))
    return request, approval_check, stdin_bytes


def _unchecked_frame(request, stdin_bytes):
    def field(value):
        raw = value.encode("utf-8")
        return struct.pack("<I", len(raw)) + raw
    body = bytearray(contract.REQUEST_MAGIC)
    body.extend(bytes.fromhex(request["request_sha256"]))
    body.extend(bytes.fromhex(request["target"]["artifact_sha256"]))
    body.extend(struct.pack(
        "<7I", 1, request["limits"]["timeout_ms"], request["limits"]["maximum_output_bytes"],
        len(request["target"]["argv"]), len(request["environment"]), len(stdin_bytes), 0,
    ))
    body.extend(field(request["target"]["path"]))
    for item in request["target"]["argv"]:
        body.extend(field(item))
    for item in request["environment"]:
        body.extend(field(item["name"])); body.extend(field(item["value"]))
    body.extend(stdin_bytes)
    return bytes(body)


def _variant(base, *, argv, environment=None, stdin_bytes=b"", timeout_ms=10000,
             maximum_output_bytes=65536, path=None):
    value = copy.deepcopy(base)
    value["target"]["argv"] = argv
    if path is not None:
        value["target"]["path"] = str(path)
    value["environment"] = [
        {"name": name, "value": content}
        for name, content in sorted((environment or {}).items())
    ]
    value["stdin"] = {"sha256": contract.sha256_bytes(stdin_bytes), "size_bytes": len(stdin_bytes)}
    value["limits"] = {"timeout_ms": timeout_ms, "maximum_output_bytes": maximum_output_bytes}
    value["request_sha256"] = contract.sha256_json({key: value[key] for key in value if key != "request_sha256"})
    return value


def _invoke(adapter, request, stdin_bytes, *, checked=True, timeout=30):
    frame = contract.encode_request(request, stdin_bytes) if checked else _unchecked_frame(request, stdin_bytes)
    environment = dict(os.environ)
    environment["LOOM_PARENT_SECRET"] = "must-not-cross"
    started = time.monotonic_ns()
    result = _run(
        [adapter, "--execute-v1"], cwd=adapter.parent, timeout=timeout,
        input_bytes=frame, env=environment,
    )
    duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    return result, duration_ms


def _expect_native(adapter, request, stdin_bytes, status):
    result, duration_ms = _invoke(adapter, request, stdin_bytes)
    if result.returncode != 0:
        raise AssertionError("native adapter failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
    observation, stdout_bytes, stderr_bytes = contract.parse_response(result.stdout, request)
    if observation["status"] != status:
        raise AssertionError(f"expected native status {status!r}, got {observation['status']!r}")
    return observation, stdout_bytes, stderr_bytes, duration_ms


def _live_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    with socket.create_connection(listener.getsockname(), timeout=2):
        accepted, _ = listener.accept()
        accepted.close()
    return listener


def _portable_self_test():
    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "target.exe"
        target.write_bytes(b"portable-target")
        base = {
            "schema": contract.REQUEST_SCHEMA,
            "approval_request_sha256": "1" * 64,
            "binding_sha256": "2" * 64,
            "target": {"path": str(target), "artifact_sha256": contract.sha256_bytes(target.read_bytes()), "argv": ["echo"]},
            "environment": [{"name": "LOOM_ALLOWED", "value": "exact"}],
            "stdin": {"sha256": contract.sha256_bytes(b"hello"), "size_bytes": 5},
            "limits": {"timeout_ms": 1000, "maximum_output_bytes": 4096},
            "shell": "denied", "network": "denied",
        }
        base["request_sha256"] = contract.sha256_json(base)
        if contract.validate_request(base):
            raise AssertionError(contract.validate_request(base))
        frame = contract.encode_request(base, b"hello")
        if not frame.startswith(contract.REQUEST_MAGIC):
            raise AssertionError("portable request frame magic differs")
        observation = {
            "schema": contract.OBSERVATION_SCHEMA,
            "request_sha256": base["request_sha256"],
            "target_sha256": base["target"]["artifact_sha256"],
            "snapshot_sha256": base["target"]["artifact_sha256"],
            "private_snapshot": "byte-identical", "appcontainer": True, "capabilities": [],
            "job_process_limit": 1, "network": "denied", "status": "exited",
            "exit_code": 0, "timed_out": False, "output_limited": False,
        }
        payload = contract.canonical_json(observation)
        response = contract.RESPONSE_MAGIC + struct.pack("<3I", len(payload), 5, 0) + payload + b"hello"
        parsed, stdout_bytes, stderr_bytes = contract.parse_response(response, base)
        receipt = contract.build_native_receipt("3" * 64, base, parsed, stdout_bytes, stderr_bytes, 1)
        if contract.validate_native_receipt(receipt):
            raise AssertionError(contract.validate_native_receipt(receipt))
        changed_observation = dict(observation)
        changed_observation["target_sha256"] = "4" * 64
        if not contract.validate_observation(changed_observation, base):
            raise AssertionError("target-hash observation tamper was accepted")
        oversized = copy.deepcopy(receipt)
        oversized["output"]["stdout_size_bytes"] = 4097
        oversized["native_receipt_sha256"] = contract.sha256_json(
            {key: oversized[key] for key in oversized if key != "native_receipt_sha256"}
        )
        if not contract.validate_native_receipt(oversized):
            raise AssertionError("combined output-bound receipt tamper was accepted")
        tampered = bytearray(response); tampered[-1] ^= 1
        _, changed, _ = contract.parse_response(bytes(tampered), base)
        if changed == b"hello":
            raise AssertionError("response tamper fixture did not change bytes")
        try:
            contract.require_windows()
        except RuntimeError:
            if os.name == "nt":
                raise
        else:
            if os.name != "nt":
                raise AssertionError("non-Windows host did not fail closed")
    print("PASS Windows General Adapter Execution v1 portable self-test (non-certifying)")


def _native(output_path):
    if os.name != "nt" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise AssertionError("native certification requires Windows x86_64")
    if os.environ.get("LOOM_WINDOWS_RUNNER") != EXPECTED_RUNNER or sys.version_info[:2] != EXPECTED_PYTHON:
        raise AssertionError("native certification requires windows-2025 and Python 3.12")
    cl, cl_identity = _compiler()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        adapter, target = _build_pair(cl, root)
        environment = {"LOOM_ALLOWED": "exact"}
        issued_at = int(time.time() * 1000)
        approval_request, approval_validation, stdin_bytes = _approval_fixture(
            adapter, target, ["echo"], environment, 10000, issued_at,
        )
        general = contract.build_request(
            approval_request, target, ["echo"], environment, stdin_bytes, 10000, 65536,
        )
        ledger = root / "lifecycle.sqlite3"
        claim = lifecycle.claim_once(approval_validation, approval_request, issued_at + 2, ledger)
        mediation = lifecycle.mediate(
            claim, approval_request, contract.sha256_bytes(adapter.read_bytes()),
            environment, stdin_bytes, issued_at + 3, ledger,
        )
        reservation = lifecycle.reserve(mediation, issued_at + 4, ledger)
        observation, stdout_bytes, stderr_bytes, duration_ms = _expect_native(
            adapter, general, stdin_bytes, "exited",
        )
        if stdout_bytes != stdin_bytes or b"loom-general-target:echo" not in stderr_bytes:
            raise AssertionError("exact stdin/stdout/stderr target behavior was not observed")
        receipt = contract.build_native_receipt(
            mediation["adapter_sha256"], general, observation,
            stdout_bytes, stderr_bytes, duration_ms,
        )
        execution, result_artifact = contract.complete(
            mediation, reservation, general, receipt, issued_at + 5, ledger,
        )

        checks = []
        checks.append({"id": "signed-approval-to-terminal-result", "status": "pass"})
        checks.append({"id": "exact-environment-parent-secret-denial", "status": "pass"})
        try:
            lifecycle.claim_once(approval_validation, approval_request, issued_at + 6, ledger)
        except ValueError:
            checks.append({"id": "one-use-replay-refusal", "status": "pass"})
        else:
            raise AssertionError("Approval replay was accepted")

        bad_frame = bytearray(contract.encode_request(general, stdin_bytes))
        bad_frame[40:72] = b"\0" * 32
        bad = _run([adapter, "--execute-v1"], cwd=adapter.parent, input_bytes=bytes(bad_frame), timeout=20)
        if bad.returncode == 0:
            raise AssertionError("target hash tamper was accepted")
        checks.append({"id": "target-hash-tamper-refusal", "status": "pass"})

        link = target.with_name("loom-windows-general-link.exe")
        linked = _run([target, "--make-link", target, link], cwd=target.parent, timeout=10)
        if linked.returncode != 0 or not link.is_symlink():
            raise AssertionError("cannot create reparse-point adversarial fixture")
        link_request = _variant(general, argv=["echo"], environment=environment,
                                stdin_bytes=stdin_bytes, path=link)
        linked_run, _ = _invoke(adapter, link_request, stdin_bytes, checked=False)
        if linked_run.returncode == 0:
            raise AssertionError("target reparse point was accepted")
        checks.append({"id": "target-reparse-refusal", "status": "pass"})

        listener = _live_listener()
        network_request = _variant(
            general, argv=["network"], environment={"LOOM_TEST_PORT": str(listener.getsockname()[1])},
        )
        network_observation, _, _, _ = _expect_native(adapter, network_request, b"", "exited")
        listener.close()
        if network_observation["exit_code"] != 0:
            raise AssertionError("zero-capability network denial target failed")
        checks.append({"id": "live-loopback-network-denial", "status": "pass"})

        spawn_request = _variant(general, argv=["spawn"])
        spawn_observation, _, _, _ = _expect_native(adapter, spawn_request, b"", "exited")
        if spawn_observation["exit_code"] != 0:
            raise AssertionError("child-spawn denial target failed")
        checks.append({"id": "child-process-denial", "status": "pass"})

        overflow_request = _variant(general, argv=["overflow"], maximum_output_bytes=8192)
        overflow, overflow_stdout, overflow_stderr, _ = _expect_native(
            adapter, overflow_request, b"", "output-limit",
        )
        if len(overflow_stdout) + len(overflow_stderr) > 8192 or not overflow["output_limited"]:
            raise AssertionError("output flood was not bounded")
        checks.append({"id": "streaming-output-limit-termination", "status": "pass"})

        timeout_request = _variant(general, argv=["timeout"], timeout_ms=250)
        timeout_observation, _, _, timeout_duration = _expect_native(
            adapter, timeout_request, b"", "timeout",
        )
        if not timeout_observation["timed_out"] or timeout_duration > 10000:
            raise AssertionError("timeout did not terminate the Job Object promptly")
        checks.append({"id": "wall-clock-timeout-termination", "status": "pass"})

        witness = {
            "schema": contract.WITNESS_SCHEMA,
            "test_only": True,
            "authorization": "none",
            "certification_scope": "windows-general-adapter-execution-v1",
            "source": {
                "repository": "umbraaeternaa/loom",
                "commit_sha": os.environ.get("GITHUB_SHA", "0" * 40),
            },
            "ci": {
                "provider": "github-actions", "workflow": "LOOM Citadel",
                "job": "verify-windows-general-execution", "runner": EXPECTED_RUNNER,
                "run_id": int(os.environ.get("GITHUB_RUN_ID", "1")),
                "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
            },
            "platform": {
                "os": "windows", "architecture": "x86_64",
                "python": platform.python_version(), "windows_build": platform.version(),
            },
            "toolchain": {
                "cl_version": cl_identity,
                "cl_sha256": contract.sha256_bytes(cl.read_bytes()),
                "adapter_source_sha256": contract.sha256_bytes(ADAPTER_SOURCE.read_bytes()),
                "host_source_sha256": contract.sha256_bytes(HOST_SOURCE.read_bytes()),
                "target_source_sha256": contract.sha256_bytes(TARGET_SOURCE.read_bytes()),
                "adapter_sha256": contract.sha256_bytes(adapter.read_bytes()),
                "target_sha256": contract.sha256_bytes(target.read_bytes()),
                "reproducible_builds": True,
            },
            "approval_request": approval_request,
            "operator_public_key": fixture.TEST_KEY,
            "approval_validation": approval_validation,
            "general_request": general,
            "claim": claim, "mediation": mediation,
            "execution": execution, "result_artifact": result_artifact,
            "checks": checks,
            "scope": {
                "arbitrary_approved_pe_target": True,
                "zero_capability_appcontainer": True,
                "one_process_job": True,
                "bounded_streams": True,
                "operator_presence": False,
                "production_authority": False,
            },
            "limitations": [
                "test-only witness; it grants no production authority",
                "Windows x86_64 PE targets only in v1",
                "zero capabilities intentionally deny network and child processes",
            ],
            "result": "pass",
        }
        witness["witness_sha256"] = contract.sha256_json(witness)
        validation = contract.validate_witness(witness, os.environ.get("GITHUB_SHA"))
        if not validation["valid"]:
            raise AssertionError("witness failed: " + repr(validation["findings"]))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(contract.canonical_json(witness) + b"\n")
        print(f"PASS Windows General Adapter Execution v1 ({len(checks)} adversarial checks)")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", "--portable-self-test", dest="portable_self_test", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("windows-general-execution-witness.json"))
    args = parser.parse_args(argv)
    if args.portable_self_test:
        _portable_self_test()
        return 0
    _native(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
