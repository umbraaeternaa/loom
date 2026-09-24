#!/usr/bin/env python3
"""Certify the fixed Windows Approval-to-Result Bounded Execution profile."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom
import loom_provenance
import loom_windows_execution as contract
import loom_windows_host


EXPECTED_RUNNER = "windows-2025"
EXPECTED_PYTHON = (3, 12)
MAXIMUM_OUTPUT_BYTES = 1024 * 1024
ADAPTER_SOURCE = ROOT / "tools" / "windows-bounded-execution" / "bounded_execution_adapter.c"
HOST_SOURCE = ROOT / "tools" / "windows-host-security" / "host_security_probe.c"

# Repository-owned test key.  It grants no authority outside this test-only CI fixture.
TEST_N_HEX = (
    "9839b5f2780d273a675993740acd545b6081d18edba0e9dffb4b2623faf6143d"
    "4b649d8ab89da611a5cae1128a5690607011601bbb94585a477d4e75f3a94f225"
    "dfacfc8911a5f68a4c558c7162305d63eb03e46c8c1438f1d6d4cae24e936ef"
    "0958756fcd8ea083b3bc262356b9d5b2427711319452b5b9c0f979d8be60571d"
    "b915b21faa530653a6e92bdbb9d33cbfdc1040f9910a593b055f5e6eee0a189"
    "f300b41a63ff7dd9ec5185ebcb58c3927945fbf73014fdaccf1fe1179595b030"
    "0f8f80684e2b40508e68c09ef88893b9446149bcb150a5e0a12fed31cdf5eda"
    "1d18adb645a089dcf2e845e52f999c2c3939ccf652f92a07d175a5149e8bba81b7"
)
TEST_D = int(
    "87308eeb37684c5e61f550d9787e6cb1cf937b3869750eea0c3d413228699805"
    "4234fe74cf0b08616e8c2ee1a304c853dd333bd7654f943d19205528b6576175"
    "740be5b1df5691efad3b010cf8c141d31e4eb200206a58457c2cdadcb835d0c3"
    "992e7b9d3f410641f0c2e25bf56434e9e07d3ded24d20f9cad9f8c717676b8e"
    "61d7fdbbe4fa8008f088253e843d29a1c01ca9b6d6cbffbb92a77dcac860b9e"
    "ad5eee8d9ef6b211dd44dd78075d2da309fa68db5c405fd58ccab32042982594"
    "495cc1aaab526e0d752f180cd526ab01017dc2ad9b01d354fc22e80b8797faef"
    "44e507344ac53b7ae388d65e54299dfbbdeff9be821b0692172736e6de90a2989",
    16,
)
TEST_KEY = {"algorithm": "rsa-pkcs1v15-sha256", "n": TEST_N_HEX, "e": 65537}


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


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


def _build_adapter(cl, destination):
    if not destination.is_dir() or any(destination.iterdir()):
        raise AssertionError("native build destination must be one existing empty directory")
    output = destination / "loom-windows-bounded-execution-adapter.exe"
    result = _run([
        cl, "/nologo", "/W4", "/WX", "/O2", "/Brepro", "/DUNICODE",
        "/D_UNICODE", "/D_WIN32_WINNT=0x0A00", ADAPTER_SOURCE,
        f"/Fe:{output}", "/link", "/Brepro", "advapi32.lib", "bcrypt.lib",
        "ole32.lib", "userenv.lib", "ws2_32.lib",
    ], cwd=destination)
    if result.returncode or not output.is_file():
        detail = (result.stdout + result.stderr).decode("utf-8", "replace")[-2000:]
        raise AssertionError("native adapter build failed: " + detail)
    return output


def _fixed_environment():
    names = ("SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "COMSPEC")
    environment = {}
    for name in names:
        value = os.environ.get(name)
        if not value:
            raise AssertionError("required fixed adapter environment variable is absent: " + name)
        environment[name] = value
    return environment


def _sign(body):
    message = contract.canonical_json(body)
    size = (int(TEST_N_HEX, 16).bit_length() + 7) // 8
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), TEST_D, int(TEST_N_HEX, 16)).to_bytes(size, "big")
    return {**body, "signature": signature.hex()}


def _approval_fixture(adapter, environment, stdin_bytes, issued_at_unix_ms):
    compiler_components = loom_provenance.collect_compiler_components(ROOT, "modular-python")
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Certify one fixed Windows bounded execution action",
            "intent": "Bind native AppContainer and Job Object evidence to Approval v2",
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
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool_binding["binding_sha256"]}"))))'
    )
    wasm = loom.compile_wasm(source)
    expected_stdin = contract.canonical_json(tool_input)
    if stdin_bytes != expected_stdin or tool_binding["input_sha256"] != _sha256_bytes(stdin_bytes):
        raise AssertionError("fixture stdin is not the exact Tool Binding input")
    environment_commitments = [
        {"name": name, "value_sha256": _sha256_bytes(value.encode("utf-8"))}
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
            "artifact_sha256": _sha256_bytes(adapter.read_bytes()),
            "entrypoint": "process",
        },
        "argv": ["--json"],
        "working_directory_uri": adapter.parent.resolve().as_uri(),
        "environment": environment_commitments,
        "stdin": {
            "schema": "loom-action-invocation-stdin/v0",
            "encoding": "canonical-json/utf-8",
            "payload_sha256": _sha256_bytes(stdin_bytes),
        },
        "timeout_ms": 60000,
        "shell": "denied",
        "network": "denied",
    }
    binding_check = loom.build_action_invocation_binding_v0(
        manifest, tool_binding, tool_input, source, wasm, compiler_components, "main", invocation,
    )
    if not binding_check["valid"]:
        raise AssertionError("fixture Invocation Binding failed: " + repr(binding_check["findings"]))
    request_check = loom.build_action_approval_request_v2(binding_check["binding"], "7" * 64)
    if not request_check["valid"]:
        raise AssertionError("fixture Approval request failed: " + repr(request_check["findings"]))
    request = request_check["request"]
    key_sha256 = loom._binding_sha256(TEST_KEY)
    approval = _sign({
        "schema": "loom-action-capsule-approval/v2",
        "request_sha256": request["request_sha256"],
        "challenge_sha256": request["challenge"]["challenge_sha256"],
        "binding_sha256": request["binding"]["binding_sha256"],
        "capsule_sha256": request["binding"]["capsule_sha256"],
        "invocation_sha256": request["binding"]["invocation_sha256"],
        "approval_scope": "exact-invocation",
        "approver": "operator",
        "decision": "approve",
        "issued_at_unix_ms": issued_at_unix_ms,
        "expires_at_unix_ms": issued_at_unix_ms + 300000,
        "claim_required": True,
        "key_sha256": key_sha256,
    })
    approval_check = loom._verify_action_capsule_approval_v2(
        approval, request, manifest, tool_binding, tool_input, source, wasm,
        "modular-python", compiler_components, compiler_components, "main", invocation,
        issued_at_unix_ms + 1, TEST_KEY,
    )
    if not approval_check["valid"]:
        raise AssertionError("signed Action Approval v2 failed: " + repr(approval_check["findings"]))
    return request, approval_check


def _native_execute(adapter, environment, stdin_bytes, mediation):
    started = time.monotonic_ns()
    result = _run(
        [adapter, "--json"], cwd=adapter.parent,
        timeout=(mediation["timeout_ms"] / 1000), input_bytes=stdin_bytes,
        env=environment,
    )
    duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    total_output = len(result.stdout) + len(result.stderr)
    if total_output > MAXIMUM_OUTPUT_BYTES:
        process_result = "output-limit-exceeded"
    elif result.returncode == 0:
        process_result = "completed"
    else:
        process_result = "failed"
    if process_result != "completed":
        raise AssertionError(
            "fixed native adapter failed: " + result.stderr.decode("utf-8", "replace")[-2000:]
        )
    try:
        probe = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError("fixed native adapter did not emit one JSON probe") from exc
    probe_findings = loom_windows_host.validate_native_probe(probe)
    if probe_findings:
        raise AssertionError("native Host Security evidence failed: " + "; ".join(probe_findings))
    receipt = {
        "schema": contract.NATIVE_RECEIPT_SCHEMA,
        "adapter_sha256": _sha256_bytes(adapter.read_bytes()),
        "host_probe": probe,
        "host_probe_sha256": contract.sha256_json(probe),
        "environment_sha256": mediation["environment_sha256"],
        "input": {"stdin_sha256": _sha256_bytes(stdin_bytes), "stdin_size_bytes": len(stdin_bytes)},
        "limits": {
            "timeout_ms": mediation["timeout_ms"],
            "maximum_output_bytes": MAXIMUM_OUTPUT_BYTES,
        },
        "output": {
            "stdout_sha256": _sha256_bytes(result.stdout), "stdout_size_bytes": len(result.stdout),
            "stderr_sha256": _sha256_bytes(result.stderr), "stderr_size_bytes": len(result.stderr),
        },
        "process": {"result": process_result, "exit_code": result.returncode, "duration_ms": duration_ms},
    }
    receipt["native_receipt_sha256"] = contract.sha256_json(receipt)
    findings = contract.validate_native_receipt(receipt)
    if findings:
        raise AssertionError("constructed native receipt failed: " + "; ".join(findings))
    return receipt


def _environment_gate():
    findings = []
    if sys.platform != "win32":
        findings.append("certifying mode requires sys.platform == 'win32'")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Windows":
        findings.append("certifying mode requires GitHub Actions on Windows")
    if os.environ.get("LOOM_WINDOWS_RUNNER") != EXPECTED_RUNNER:
        findings.append("LOOM_WINDOWS_RUNNER must equal windows-2025")
    if sys.version_info[:2] != EXPECTED_PYTHON or platform.python_implementation() != "CPython":
        findings.append("certifying mode requires CPython 3.12")
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        findings.append("certifying mode requires x86_64/AMD64")
    commit = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        findings.append("GITHUB_SHA must be exact lowercase 40-hex")
    if not run_id.isdigit() or not run_attempt.isdigit():
        findings.append("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be decimal integers")
    if findings:
        raise AssertionError("; ".join(findings))
    return commit, int(run_id), int(run_attempt)


def _certify():
    commit, run_id, run_attempt = _environment_gate()
    cl, cl_version = _compiler()
    with tempfile.TemporaryDirectory(prefix="loom-windows-bounded-build-a-") as first_raw:
        with tempfile.TemporaryDirectory(prefix="loom-windows-bounded-build-b-") as second_raw:
            first = _build_adapter(cl, Path(first_raw))
            second = _build_adapter(cl, Path(second_raw))
            first_bytes = first.read_bytes()
            if first_bytes != second.read_bytes():
                raise AssertionError("two /Brepro native adapter builds are not byte-identical")
            adapter_sha256 = _sha256_bytes(first_bytes)
            environment = _fixed_environment()
            manifest = {
                "schema": "loom-gate-manifest/v1",
                "agent": {"id": "codex", "role": "code"},
                "task": {
                    "summary": "Certify one fixed Windows bounded execution action",
                    "intent": "Bind native AppContainer and Job Object evidence to Approval v2",
                },
                "repositories": [], "read_paths": [], "write_paths": [],
                "actions": ["process"], "evidence_required": [],
            }
            manifest_sha = loom.validate_manifest(manifest)["manifest_sha256"]
            stdin_bytes = contract.canonical_json({"action": "process", "manifest_sha256": manifest_sha})
            now = int(time.time() * 1000)
            request, approval_check = _approval_fixture(first, environment, stdin_bytes, now)
            with tempfile.TemporaryDirectory(prefix="loom-windows-lifecycle-") as ledger_raw:
                ledger = Path(ledger_raw) / "windows-action.sqlite3"
                claim = contract.claim_once(approval_check, request, now + 2, ledger)
                replay_refused = False
                try:
                    contract.claim_once(approval_check, request, now + 3, ledger)
                except ValueError:
                    replay_refused = True
                if not replay_refused:
                    raise AssertionError("Windows Action Approval replay was accepted")
                mediation = contract.mediate(
                    claim, request, adapter_sha256, environment, stdin_bytes, now + 4, ledger,
                )
                reservation = contract.reserve(mediation, now + 5, ledger)
                native_receipt = _native_execute(first, environment, stdin_bytes, mediation)
                completed_at = int(time.time() * 1000)
                execution, result = contract.complete(
                    mediation, reservation, native_receipt, completed_at, ledger,
                )
                terminal_replay_refused = False
                try:
                    contract.complete(mediation, reservation, native_receipt, completed_at + 1, ledger)
                except ValueError:
                    terminal_replay_refused = True
                if not terminal_replay_refused:
                    raise AssertionError("Windows terminal result replay was accepted")
            source_sha256 = contract.sha256_json({
                "adapter": _sha256_bytes(ADAPTER_SOURCE.read_bytes()),
                "host_security": _sha256_bytes(HOST_SOURCE.read_bytes()),
            })
            toolchain = {
                "cl_version": cl_version,
                "cl_sha256": _sha256_bytes(cl.read_bytes()),
                "source_sha256": source_sha256,
                "adapter_sha256": adapter_sha256,
            }
    witness = {
        "schema": contract.WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-bounded-execution-integration",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": commit},
        "ci": {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-bounded-execution", "runner": EXPECTED_RUNNER,
            "run_id": run_id, "run_attempt": run_attempt,
        },
        "platform": {
            "os": "windows", "architecture": "x86_64",
            "python": platform.python_version(), "windows_build": platform.version(),
        },
        "toolchain": toolchain,
        "approval_request": request,
        "operator_public_key": TEST_KEY,
        "approval_validation": approval_check,
        "claim": claim,
        "mediation": mediation,
        "execution": execution,
        "result_artifact": result,
        "checks": [{"id": item, "status": "pass"} for item in contract.EXPECTED_CHECKS],
        "scope": {
            "approval_to_result_lifecycle": True,
            "bounded_execution_integration": True,
            "general_purpose_executor": False,
            "operator_presence": False,
            "federation": False,
        },
        "limitations": [
            "This test-only witness grants no runtime authority.",
            "The fixed native adapter certifies one repository-owned integration action, not arbitrary commands.",
            "Native operator presence and Federation v1 remain unclaimed.",
        ],
        "result": "pass",
    }
    witness["witness_sha256"] = contract.sha256_json(witness)
    checked = contract.validate_witness(witness, commit)
    if not checked["valid"]:
        raise AssertionError("constructed Windows lifecycle witness failed: " + repr(checked["findings"]))
    tampered = copy.deepcopy(witness)
    tampered["execution"]["native_receipt"]["host_probe"]["network"] = "allowed"
    tampered["execution"]["native_receipt"]["native_receipt_sha256"] = contract.sha256_json({
        key: tampered["execution"]["native_receipt"][key]
        for key in tampered["execution"]["native_receipt"] if key != "native_receipt_sha256"
    })
    if contract.validate_witness(tampered, commit)["valid"]:
        raise AssertionError("tampered Windows native evidence was accepted")
    return witness


def _portable_self_test():
    request = {
        "schema": "loom-action-approval-request/v2",
        "binding": {
            "binding_sha256": "1" * 64,
            "capsule_sha256": "2" * 64,
            "invocation_sha256": "3" * 64,
        },
        "challenge": {"challenge_sha256": "4" * 64},
    }
    request["request_sha256"] = contract.sha256_json(request)
    issued = 1800000000000
    approval = _sign({
        "schema": "loom-action-capsule-approval/v2",
        "request_sha256": request["request_sha256"],
        "challenge_sha256": "4" * 64,
        "binding_sha256": "1" * 64,
        "capsule_sha256": "2" * 64,
        "invocation_sha256": "3" * 64,
        "approval_scope": "exact-invocation", "approver": "operator",
        "decision": "approve", "issued_at_unix_ms": issued,
        "expires_at_unix_ms": issued + 300000, "claim_required": True,
        "key_sha256": contract.sha256_json(TEST_KEY),
    })
    approval_validation = {
        "schema": "loom-action-capsule-approval-validation/v2",
        "valid": True, "advisory": True, "authorization": "claim-required",
        "approval": approval, "approval_sha256": contract.sha256_json(approval),
        "findings": [],
    }
    if contract.validate_approval_evidence(request, approval_validation, TEST_KEY):
        return False
    tampered_approval = copy.deepcopy(approval_validation)
    tampered_approval["approval"]["binding_sha256"] = "9" * 64
    tampered_approval["approval_sha256"] = contract.sha256_json(tampered_approval["approval"])
    if not contract.validate_approval_evidence(request, tampered_approval, TEST_KEY):
        return False
    probe = {
        "schema": loom_windows_host.PROBE_SCHEMA,
        "owner_sid": "S-1-5-21-1-2-3-1001", "appcontainer_sid": "S-1-15-2-1",
        "capabilities": [], "acl_broad_write": "denied", "reparse_points": "denied",
        "final_handle": "stable", "private_snapshot": "byte-identical",
        "token_is_appcontainer": True, "network": "denied", "child_process": "denied",
        "job_process_limit": 1, "job_kill_on_close": True,
    }
    receipt = {
        "schema": contract.NATIVE_RECEIPT_SCHEMA, "adapter_sha256": "a" * 64,
        "host_probe": probe, "host_probe_sha256": contract.sha256_json(probe),
        "environment_sha256": "b" * 64,
        "input": {"stdin_sha256": "c" * 64, "stdin_size_bytes": 2},
        "limits": {"timeout_ms": 1000, "maximum_output_bytes": 1024},
        "output": {
            "stdout_sha256": "d" * 64, "stdout_size_bytes": 2,
            "stderr_sha256": "e" * 64, "stderr_size_bytes": 0,
        },
        "process": {"result": "completed", "exit_code": 0, "duration_ms": 1},
    }
    receipt["native_receipt_sha256"] = contract.sha256_json(receipt)
    if contract.validate_native_receipt(receipt):
        return False
    tampered = copy.deepcopy(receipt)
    tampered["host_probe"]["network"] = "allowed"
    tampered["host_probe_sha256"] = contract.sha256_json(tampered["host_probe"])
    tampered["native_receipt_sha256"] = contract.sha256_json({
        key: tampered[key] for key in tampered if key != "native_receipt_sha256"
    })
    return bool(contract.validate_native_receipt(tampered))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.self_test and args.output is not None:
        parser.error("--self-test does not emit --output")
    if not args.self_test and args.output is None:
        parser.error("certifying mode requires --output")
    if args.self_test:
        if not _portable_self_test():
            print("FAIL Windows Bounded Execution Integration v0 portable self-test", file=sys.stderr)
            return 1
        print("PASS Windows Bounded Execution Integration v0 portable self-test (non-certifying)")
        return 0
    try:
        witness = _certify()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_bytes(contract.canonical_json(witness) + b"\n")
        os.replace(temporary, args.output)
        print("PASS Windows Bounded Execution Integration v0: " + witness["witness_sha256"])
        return 0
    except Exception as exc:
        print("FAIL Windows Bounded Execution Integration v0: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
