#!/usr/bin/env python3
"""Fail-closed Windows Host Security Substrate v0 conformance runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom_windows_host as contract


EXPECTED_RUNNER = "windows-2025"
EXPECTED_PYTHON = (3, 12)
PROBE_SOURCE = ROOT / "tools" / "windows-host-security" / "host_security_probe.c"


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _run(argv, *, cwd=ROOT, timeout=180):
    return subprocess.run(
        [str(item) for item in argv], cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=timeout,
    )


def _compiler():
    raw = os.environ.get("LOOM_WINDOWS_CL", "")
    if not raw:
        raise AssertionError("LOOM_WINDOWS_CL is required")
    path = Path(raw).resolve(strict=True)
    if not path.is_file() or path.name.lower() != "cl.exe":
        raise AssertionError("LOOM_WINDOWS_CL must name cl.exe")
    version = _run([path], timeout=30)
    identity = (version.stdout + version.stderr).strip()
    if "Compiler Version" not in identity or "for x64" not in identity:
        raise AssertionError("MSVC x64 compiler identity is outside the contract")
    return path, identity


def _build_probe(cl, destination):
    if not destination.is_dir() or any(destination.iterdir()):
        raise AssertionError("native build destination must be one existing empty directory")
    output = destination / "loom-windows-host-security-probe.exe"
    result = _run([
        cl, "/nologo", "/W4", "/WX", "/O2", "/Brepro", "/DUNICODE",
        "/D_UNICODE", "/D_WIN32_WINNT=0x0A00", str(PROBE_SOURCE), f"/Fe:{output}", "/link",
        "/Brepro", "advapi32.lib", "bcrypt.lib", "ole32.lib", "userenv.lib", "ws2_32.lib",
    ], cwd=destination)
    if result.returncode or not output.is_file():
        raise AssertionError("native probe build failed: " + (result.stdout + result.stderr)[-2000:])
    return output


def _native_probe():
    cl, cl_version = _compiler()
    source_bytes = PROBE_SOURCE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="loom-windows-host-build-a-") as a_raw:
        with tempfile.TemporaryDirectory(prefix="loom-windows-host-build-b-") as b_raw:
            first = _build_probe(cl, Path(a_raw))
            second = _build_probe(cl, Path(b_raw))
            first_bytes = first.read_bytes()
            if first_bytes != second.read_bytes():
                raise AssertionError("two /Brepro native probe builds are not byte-identical")
            executed = _run([first, "--json"], cwd=Path(a_raw), timeout=60)
            if executed.returncode:
                raise AssertionError("native security probe failed: " + executed.stderr[-2000:])
            try:
                probe = json.loads(executed.stdout)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AssertionError("native probe did not emit one JSON object") from exc
            findings = contract.validate_native_probe(probe)
            if findings:
                raise AssertionError("native probe contract failed: " + "; ".join(findings))
            toolchain = {
                "cl_version": cl_version,
                "cl_sha256": _sha256_bytes(cl.read_bytes()),
                "source_sha256": _sha256_bytes(source_bytes),
                "probe_sha256": _sha256_bytes(first_bytes),
            }
    return probe, toolchain


def _environment():
    findings = []
    if sys.platform != "win32":
        findings.append("certifying mode requires sys.platform == 'win32'")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        findings.append("certifying mode requires GITHUB_ACTIONS=true")
    if os.environ.get("RUNNER_OS") != "Windows":
        findings.append("certifying mode requires RUNNER_OS=Windows")
    if os.environ.get("LOOM_WINDOWS_RUNNER") != EXPECTED_RUNNER:
        findings.append(f"LOOM_WINDOWS_RUNNER must equal {EXPECTED_RUNNER}")
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


def _witness(commit, run_id, run_attempt, probe, toolchain):
    witness = {
        "schema": contract.WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-host-security-substrate",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": commit},
        "ci": {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-host-security", "runner": EXPECTED_RUNNER,
            "run_id": run_id, "run_attempt": run_attempt,
        },
        "platform": {
            "os": "windows", "architecture": "x86_64",
            "python": platform.python_version(),
            "windows_build": platform.version(),
        },
        "toolchain": toolchain,
        "probe": probe,
        "checks": [{"id": item, "status": "pass"} for item in contract.EXPECTED_CHECKS],
        "scope": {
            "sid_acl_custody": True,
            "reparse_point_defense": True,
            "private_snapshot": True,
            "appcontainer_network_isolation": True,
            "job_object_lifecycle": True,
            "bounded_execution_integration": False,
            "operator_presence": False,
            "federation": False,
        },
        "result": "pass",
        "limitations": [
            "This test-only witness grants no authority and is not an operator approval.",
            "Bounded Execution integration remains outside this substrate profile.",
            "Native operator presence and Federation v1 remain unclaimed.",
        ],
    }
    witness["witness_sha256"] = contract.sha256_json(witness)
    checked = contract.validate_witness(witness, commit)
    if not checked["valid"]:
        raise AssertionError("constructed witness is invalid: " + repr(checked["findings"]))
    return witness


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
        if not contract.portable_self_test():
            print("FAIL Windows Host Security Substrate v0 portable self-test", file=sys.stderr)
            return 1
        print("PASS Windows Host Security Substrate v0 portable self-test (non-certifying)")
        return 0
    try:
        commit, run_id, run_attempt = _environment()
        probe, toolchain = _native_probe()
        witness = _witness(commit, run_id, run_attempt, probe, toolchain)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_bytes(contract.canonical_json(witness) + b"\n")
        os.replace(temporary, args.output)
        print("PASS Windows Host Security Substrate v0: " + witness["witness_sha256"])
        return 0
    except Exception as exc:
        print("FAIL Windows Host Security Substrate v0: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
