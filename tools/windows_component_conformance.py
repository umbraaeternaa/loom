#!/usr/bin/env python3
"""Fail-closed Windows Component Conformance v0 runner for LOOM."""

from __future__ import annotations

import argparse
import base64
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

import loom


SCHEMA = "loom-windows-component-ci-witness/v0"
EXPECTED_RUNNER = "windows-2025"
EXPECTED_HOST = "x86_64-pc-windows-msvc"
EXPECTED_PYTHON = (3, 12)
WINDOWS_TOOL_SHA256 = {
    "wasm_tools": "51698e3975100f5ee65a72e998eb958fd254e3bed99b9ba2ac3ac0025088a4b8",
    "wasmtime": "cadcc7480082a372256d6dae7b2855aca3d74edbfa844838b4a33076e5ec40b8",
}
TOOL_ENV = {
    "wasm_tools": "LOOM_WASM_TOOLS",
    "wasmtime": "LOOM_WASMTIME",
    "component_builder": "LOOM_COMPONENT_BUILDER",
    "effectful_builder": "LOOM_EFFECTFUL_COMPONENT_BUILDER",
    "cargo": "LOOM_CARGO",
    "rustc": "LOOM_RUSTC",
    "cargo_home": "LOOM_COMPONENT_CARGO_HOME",
}


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value):
    return _sha256_bytes(_canonical(value))


def _run(argv, *, timeout=180):
    return subprocess.run(
        [str(item) for item in argv], cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=timeout,
    )


def _tools():
    result = {}
    for label, variable in TOOL_ENV.items():
        raw = os.environ.get(variable, "")
        if not raw:
            raise AssertionError(f"{variable} is required")
        path = Path(raw).resolve(strict=True)
        if label == "cargo_home":
            if not path.is_dir():
                raise AssertionError(f"{variable} must name a directory")
        elif not path.is_file():
            raise AssertionError(f"{variable} must name a file")
        result[label] = path
    return result


def _version(executable, *args):
    probe = _run([executable, *args])
    if probe.returncode:
        raise AssertionError(f"version probe failed for {executable}: {probe.stderr.strip()}")
    return (probe.stdout + probe.stderr).strip()


def _tool_identities(tools, *, certifying):
    identities = {}
    for label in ("wasm_tools", "wasmtime", "component_builder", "effectful_builder", "cargo", "rustc"):
        path = tools[label]
        identities[label] = {"sha256": _sha256_bytes(path.read_bytes())}
    identities["wasm_tools"]["version"] = _version(tools["wasm_tools"], "--version")
    identities["wasmtime"]["version"] = _version(tools["wasmtime"], "--version")
    identities["cargo"]["version"] = _version(tools["cargo"], "--version", "--verbose")
    identities["rustc"]["version"] = _version(tools["rustc"], "--version", "--verbose")
    if identities["wasm_tools"]["version"] != loom._loom_component_adapter.WASM_TOOLS_VERSION:
        raise AssertionError("wasm-tools version is outside the closed Component contract")
    if identities["wasmtime"]["version"] != loom._loom_component_adapter.WASMTIME_VERSION:
        raise AssertionError("Wasmtime version is outside the closed Component contract")
    if certifying:
        for label, digest in WINDOWS_TOOL_SHA256.items():
            if identities[label]["sha256"] != digest:
                raise AssertionError(f"{label} Windows executable hash mismatch")
        if f"host: {EXPECTED_HOST}" not in identities["cargo"]["version"]:
            raise AssertionError("Cargo host is not x86_64-pc-windows-msvc")
        if f"host: {EXPECTED_HOST}" not in identities["rustc"]["version"]:
            raise AssertionError("rustc host is not x86_64-pc-windows-msvc")
    return identities


def _wave_request(args):
    payload = _canonical({"args": args})
    return "[" + ",".join(str(byte) for byte in payload) + "]"


def _invoke(wasmtime, component, export, args):
    with tempfile.TemporaryDirectory(prefix="loom-windows-component-") as raw_tmp:
        component_path = Path(raw_tmp) / "component.wasm"
        component_path.write_bytes(component)
        return _run([
            wasmtime, "run", "--invoke", f"{export}({_wave_request(args)})",
            component_path,
        ])


def _decode_ok(stdout):
    marker = "ok(["
    start = stdout.rfind(marker)
    end = stdout.find("])", start)
    if start < 0 or end < 0:
        raise AssertionError("Wasmtime output has no canonical ok payload")
    numbers = stdout[start + len(marker):end].strip()
    payload = bytes(int(item.strip()) for item in numbers.split(",") if item.strip())
    return stdout[:start], json.loads(payload.decode("utf-8"))


def _pure_fixture(tools):
    source = (
        '(defx ident () (fn (x) x)) '
        '(defx mkrec () (fn () (record (a 1) (b (= 1 1))))) '
        '(defx mkvar () (fn () (variant Some "hi")))'
    )
    package, world, exports = "umbra:loom@0.3.0", "adapter-test", ["ident"]
    core = loom.compile_wasm_v2(source)
    boundary_result = loom.build_wit_component_boundary_v0(
        source, core, package, world, exports, abi_version=2,
    )
    if not boundary_result["valid"]:
        raise AssertionError("Pure WIT boundary build failed")
    boundary = boundary_result["boundary"]
    kwargs = {
        "builder_executable": str(tools["component_builder"]),
        "wasm_tools_executable": str(tools["wasm_tools"]),
    }
    first = loom.build_component_adapter_artifact_v0(
        boundary, source, core, package, world, exports, **kwargs,
    )
    second = loom.build_component_adapter_artifact_v0(
        boundary, source, core, package, world, exports, **kwargs,
    )
    if not first["valid"] or first != second:
        raise AssertionError("Pure Component build is invalid or non-deterministic")
    verified = loom.verify_component_adapter_artifact_v0(
        first["artifact"], first["component"], boundary, source, core,
        package, world, exports, wasm_tools_executable=str(tools["wasm_tools"]),
        wasmtime_executable=str(tools["wasmtime"]),
    )
    if not verified["valid"]:
        raise AssertionError("Pure Component independent verification failed")
    invocation = _invoke(tools["wasmtime"], first["component"], "ident", ["windows"])
    prefix, value = _decode_ok(invocation.stdout)
    if invocation.returncode or prefix or value != {"ok": "windows"}:
        raise AssertionError("Pure Component Wasmtime execution diverged")
    tampered = first["component"][:-1] + bytes([first["component"][-1] ^ 1])
    rejected = loom.verify_component_adapter_artifact_v0(
        first["artifact"], tampered, boundary, source, core, package, world,
        exports, wasm_tools_executable=str(tools["wasm_tools"]),
        wasmtime_executable=str(tools["wasmtime"]),
    )
    if rejected["valid"]:
        raise AssertionError("tampered Pure Component was accepted")
    return {
        "source": source, "core": core, "boundary": boundary,
        "package": package, "world": world, "exports": exports,
        "build": first,
    }


def _effectful_fixture(tools):
    source = '(defx emit (IO) (fn (x) (print x)))'
    package, world, exports = "umbra:loom@0.5.0", "effectful-io", ["emit"]
    core = loom.compile_wasm_v2(source)
    mapped = loom.build_typed_wasi_capability_mapping_v0(
        source, core, package, world, exports,
    )
    mapping = mapped.get("mapping") or {}
    prepared = loom.prepare_effectful_component_host_policy_v1(
        mapping, "windows-component-io",
    )
    policy = prepared.get("policy") or {}
    kwargs = {
        "builder_executable": str(tools["effectful_builder"]),
        "wasm_tools_executable": str(tools["wasm_tools"]),
    }
    first = loom.build_effectful_component_adapter_v1(
        mapping, policy, source, core, package, world, exports, **kwargs,
    )
    second = loom.build_effectful_component_adapter_v1(
        mapping, policy, source, core, package, world, exports, **kwargs,
    )
    if not first["valid"] or first != second:
        raise AssertionError("effectful Component build is invalid or non-deterministic")
    verified = loom.verify_effectful_component_adapter_v1(
        first["artifact"], first["component"], mapping, policy, source, core,
        package, world, exports, wasm_tools_executable=str(tools["wasm_tools"]),
        wasmtime_executable=str(tools["wasmtime"]),
    )
    if not verified["valid"]:
        raise AssertionError("effectful Component independent verification failed")
    invocation = _invoke(tools["wasmtime"], first["component"], "emit", [7])
    prefix, value = _decode_ok(invocation.stdout)
    if invocation.returncode or prefix.strip() != "7" or value != {"ok": 7}:
        raise AssertionError("effectful IO Component execution diverged")
    tampered = first["component"][:-1] + bytes([first["component"][-1] ^ 1])
    rejected = loom.verify_effectful_component_adapter_v1(
        first["artifact"], tampered, mapping, policy, source, core, package,
        world, exports, wasm_tools_executable=str(tools["wasm_tools"]),
        wasmtime_executable=str(tools["wasmtime"]),
    )
    if rejected["valid"]:
        raise AssertionError("tampered effectful Component was accepted")
    return first


def _release_reproducibility(tools, pure):
    kwargs = {
        "builder_source_root": ROOT / "tools" / "loom-component-builder",
        "cargo_executable": tools["cargo"],
        "rustc_executable": tools["rustc"],
        "cargo_home": tools["cargo_home"],
        "wasm_tools_executable": tools["wasm_tools"],
        "wasmtime_executable": tools["wasmtime"],
    }
    built = loom.build_component_release_reproducibility_v0(
        pure["boundary"], pure["source"], pure["core"], pure["package"],
        pure["world"], pure["exports"], **kwargs,
    )
    if not built["valid"]:
        raise AssertionError("Windows frozen release rebuild failed: " + repr(built["findings"]))
    verified = loom.verify_component_release_reproducibility_v0(
        built["evidence"], built["component"], pure["boundary"], pure["source"],
        pure["core"], pure["package"], pure["world"], pure["exports"], **kwargs,
    )
    if not verified["valid"]:
        raise AssertionError("independent Windows release rebuild diverged")
    return built


def run_checks(*, certifying):
    tools = _tools()
    identities = _tool_identities(tools, certifying=certifying)
    pure = _pure_fixture(tools)
    effectful = _effectful_fixture(tools)
    release = _release_reproducibility(tools, pure)
    checks = [
        {"id": "pinned-native-toolchain", "status": "pass"},
        {"id": "pure-component-build-verify-execute-refuse", "status": "pass"},
        {"id": "effectful-io-component-build-verify-execute-refuse", "status": "pass"},
        {"id": "same-host-frozen-release-reproducibility", "status": "pass"},
    ]
    artifacts = {
        "pure_component_sha256": _sha256_bytes(pure["build"]["component"]),
        "effectful_component_sha256": _sha256_bytes(effectful["component"]),
        "release_component_sha256": _sha256_bytes(release["component"]),
        "release_evidence_sha256": release["evidence"]["evidence_sha256"],
        "release_component_base64": base64.b64encode(release["component"]).decode("ascii"),
    }
    return checks, identities, artifacts


def _validate_windows_ci_environment():
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
        findings.append("certifying mode requires an x86_64/AMD64 host")
    commit_sha = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        findings.append("GITHUB_SHA must be one exact lowercase 40-hex commit")
    if not run_id.isdigit() or not run_attempt.isdigit():
        findings.append("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be decimal integers")
    if findings:
        raise AssertionError("; ".join(findings))
    return commit_sha, int(run_id), int(run_attempt)


def _witness(checks, identities, artifacts, commit_sha, run_id, run_attempt):
    witness = {
        "schema": SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-component",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": commit_sha},
        "ci": {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-component", "runner": EXPECTED_RUNNER,
            "run_id": run_id, "run_attempt": run_attempt,
        },
        "platform": {
            "os": "windows", "architecture": "x86_64",
            "python": ".".join(str(part) for part in sys.version_info[:3]),
            "rust_host": EXPECTED_HOST,
        },
        "tools": identities,
        "artifacts": artifacts,
        "checks": checks,
        "result": "pass",
        "limitations": [
            "This witness grants no authority and is not an operator approval or release signature.",
            "It does not certify Gate custody, ACL/SID policy, reparse-point defense, AppContainer, Job Object, or operator presence.",
            "Windows is not added to Component Release Evidence Federation v0; three-platform equality requires a later additive federation profile.",
        ],
    }
    witness["witness_sha256"] = _sha256_json(witness)
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
    try:
        if args.self_test:
            run_checks(certifying=False)
            print("PASS Windows Component Conformance v0 portable self-test (non-certifying)")
            return 0
        commit_sha, run_id, run_attempt = _validate_windows_ci_environment()
        checks, identities, artifacts = run_checks(certifying=True)
        witness = _witness(
            checks, identities, artifacts, commit_sha, run_id, run_attempt,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_bytes(_canonical(witness) + b"\n")
        os.replace(temporary, args.output)
        print("PASS Windows Component Conformance v0: " + witness["witness_sha256"])
        return 0
    except Exception as exc:
        print("FAIL Windows Component Conformance v0: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
