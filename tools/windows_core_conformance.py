#!/usr/bin/env python3
"""Fail-closed Windows Core Conformance v0 runner for LOOM."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom


SCHEMA = "loom-windows-core-ci-witness/v0"
EXPECTED_RUNNER = "windows-2025"
EXPECTED_PYTHON = (3, 12)
EXPECTED_NODE_MAJOR = 22
EXPECTED_PACKAGE = "loom-lang"
EXPECTED_PACKAGE_VERSION = "0.1.0"
FUZZ_CASES = 256
FUZZ_SEEDS = (0xC17ADE1, 0xBADC0DE, 0xA11CE)


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _run(argv, *, cwd=ROOT):
    return subprocess.run(
        [str(item) for item in argv], cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=120,
    )


def _node_version():
    executable = shutil.which("node")
    if not executable:
        raise AssertionError("Node.js is required; JavaScript/WASM execution may not be skipped")
    result = _run([executable, "--version"])
    if result.returncode != 0:
        raise AssertionError("Node.js version probe failed: " + result.stderr.strip())
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", result.stdout.strip())
    if not match:
        raise AssertionError("unexpected Node.js version: " + result.stdout.strip())
    return executable, tuple(int(part) for part in match.groups())


def _record(checks, check_id, action):
    try:
        detail = action()
    except Exception as exc:
        checks.append({
            "id": check_id,
            "status": "fail",
            "detail": f"{type(exc).__name__}: {exc}",
        })
    else:
        checks.append({"id": check_id, "status": "pass", "detail": detail})


def _check_parser_checker():
    valid = '(defx main () (fn () (record (answer (+ 20 22)) (label "windows"))))'
    functions, errors = loom.check(loom.parse(valid))
    if errors or "main" not in functions:
        raise AssertionError("valid Pure program was rejected: " + repr(errors))
    _, hidden_errors = loom.check(loom.parse('(defx hidden () (fn () (print "no")))'))
    if not hidden_errors or "performs undeclared ['IO'] (declared [])" not in hidden_errors[0]:
        raise AssertionError("hidden IO was not rejected with the pinned diagnostic")
    try:
        loom.parse("(")
    except loom.LoomError:
        pass
    else:
        raise AssertionError("malformed source was accepted")
    return "valid Pure source accepted; malformed source and hidden IO rejected"


def _all_backends(program, call):
    return {
        "interpreter": loom.run_call(program, call)[0],
        "python": loom.run_compiled(program, call)[0],
        "javascript": loom.run_js(program, call)[0],
        "webassembly": loom.run_wasm(program, call)[0],
    }


def _check_scalar_parity():
    program = (
        "(defx fact () (fn (n) (if (< n 2) 1 (* n (fact (- n 1))))))"
    )
    values = _all_backends(program, "(fact 6)")
    if set(values.values()) != {720}:
        raise AssertionError("backend divergence: " + repr(values))
    return "interpreter == Python == JavaScript == WebAssembly == 720"


def _check_structured_parity():
    program = (
        '(defx main () (fn () '
        '(record (xs (list 4 5)) (v (variant Some "ok")) '
        '(nested (record (x 7))))))'
    )
    expected = {"xs": [4, 5], "v": ("Some", "ok"), "nested": {"x": 7}}
    values = _all_backends(program, "(main)")
    if any(value != expected for value in values.values()):
        raise AssertionError("structured backend divergence: " + repr(values))
    return "records, lists, variants, nested values, and strings agree on four backends"


def _check_handler_parity():
    program = (
        "(defx realwork (Net) (fn (x) (net x))) "
        "(defx mock () (fn (x) (* x 2))) "
        "(defx tested () (fn (x) (with Net mock (realwork x))))"
    )
    values = _all_backends(program, "(tested 21)")
    if set(values.values()) != {42}:
        raise AssertionError("handler backend divergence: " + repr(values))
    return "Pure reinterpretation of Net agrees on four backends"


def _check_wasm_wat():
    program = '(defx main () (fn () (asm wasm i31.add 20 22)))'
    wasm = loom.compile_wasm(program)
    wat = loom.emit_wat(program)
    if wasm[:4] != b"\x00asm" or len(wasm) < 8:
        raise AssertionError("compiler did not emit a WebAssembly binary")
    if "(module" not in wat or "i32.add" not in wat or '(export "main"' not in wat:
        raise AssertionError("WAT output lost module, ASM lowering, or main export")
    if loom.run_wasm(program, "(main)")[0] != 42:
        raise AssertionError("emitted WebAssembly did not execute to 42")
    return "binary magic, WAT lowering, export, and Node WebAssembly execution verified"


def _check_cli():
    with tempfile.TemporaryDirectory() as temp_dir:
        source = Path(temp_dir, "core.loom")
        source.write_text('(defx main () (fn () 42))\n', encoding="utf-8")
        check_result = _run([
            sys.executable, ROOT / "loom.py", "check", source, "--format=json",
        ])
        run_result = _run([sys.executable, ROOT / "loom.py", "run", source])
        if check_result.returncode != 0:
            raise AssertionError("CLI check failed: " + check_result.stderr.strip())
        verdict = json.loads(check_result.stdout)
        if verdict.get("schema") != "loom-verdict/v1" or verdict.get("verdict") != "accept":
            raise AssertionError("CLI emitted an unexpected verdict: " + repr(verdict))
        if run_result.returncode != 0 or run_result.stdout.strip() != "=> 42":
            raise AssertionError("CLI run diverged: " + repr(run_result.stdout))
    return "repo-local CLI check JSON and execution are exact"


def _check_distribution():
    distribution = importlib.metadata.distribution(EXPECTED_PACKAGE)
    if distribution.version != EXPECTED_PACKAGE_VERSION:
        raise AssertionError(
            f"installed {EXPECTED_PACKAGE} version {distribution.version}, "
            f"expected {EXPECTED_PACKAGE_VERSION}"
        )
    entry_points = {
        (entry.name, entry.group, entry.value) for entry in distribution.entry_points
    }
    if ("loom", "console_scripts", "loom:main") not in entry_points:
        raise AssertionError("installed distribution lost the loom console entry point")
    executable = shutil.which("loom")
    if not executable:
        raise AssertionError("installed loom console command is not on PATH")
    about = _run([executable, "about", "--format=json"], cwd=Path(tempfile.gettempdir()))
    if about.returncode != 0:
        raise AssertionError("installed loom command failed: " + about.stderr.strip())
    payload = json.loads(about.stdout)
    if payload.get("schema") != "loom-about/v1" or "webassembly" not in payload.get("backends", []):
        raise AssertionError("installed loom command reported an unexpected capability surface")
    return "wheel metadata, console entry point, and installed CLI invocation verified"


def _check_fuzz_seeds():
    completed = []
    for seed in FUZZ_SEEDS:
        result = _run([
            sys.executable, ROOT / "fuzz_tests.py", "--require-node",
            "--cases", str(FUZZ_CASES), "--seed", hex(seed),
        ])
        if result.returncode != 0 or "PASS property fuzz" not in result.stdout:
            raise AssertionError(
                f"fuzz seed {seed:#x} failed: "
                + (result.stdout.strip() or result.stderr.strip())
            )
        completed.append(f"{seed:#x}")
    return f"{FUZZ_CASES} cases for each mandatory seed: " + ", ".join(completed)


def run_core_checks(*, require_distribution):
    _node_version()
    checks = []
    _record(checks, "parser-checker", _check_parser_checker)
    _record(checks, "scalar-four-backend-parity", _check_scalar_parity)
    _record(checks, "structured-four-backend-parity", _check_structured_parity)
    _record(checks, "handler-four-backend-parity", _check_handler_parity)
    _record(checks, "wasm-wat", _check_wasm_wat)
    _record(checks, "cli", _check_cli)
    _record(checks, "deterministic-four-backend-fuzz", _check_fuzz_seeds)
    if require_distribution:
        _record(checks, "installed-package", _check_distribution)
    return checks


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
    if sys.version_info[:2] != EXPECTED_PYTHON:
        findings.append("certifying mode requires CPython 3.12")
    if platform.python_implementation() != "CPython":
        findings.append("certifying mode requires the CPython implementation")
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        findings.append("certifying mode requires an x86_64/AMD64 host")
    commit_sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        findings.append("GITHUB_SHA must be one exact lowercase 40-hex commit")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not run_id.isdigit() or not run_attempt.isdigit():
        findings.append("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be decimal integers")
    try:
        _, node_version = _node_version()
    except Exception as exc:
        findings.append(str(exc))
        node_version = None
    if node_version and node_version[0] != EXPECTED_NODE_MAJOR:
        findings.append(f"certifying mode requires Node.js {EXPECTED_NODE_MAJOR}.x")
    if findings:
        raise AssertionError("; ".join(findings))
    return commit_sha, run_id, run_attempt, node_version


def _build_witness(checks, commit_sha, run_id, run_attempt, node_version):
    witness = {
        "schema": SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-core",
        "source": {
            "repository": "umbraaeternaa/loom",
            "commit_sha": commit_sha,
        },
        "ci": {
            "provider": "github-actions",
            "workflow": "LOOM Citadel",
            "job": "verify-windows-core",
            "runner": EXPECTED_RUNNER,
            "run_id": int(run_id),
            "run_attempt": int(run_attempt),
        },
        "platform": {
            "os": "windows",
            "architecture": "x86_64",
            "python": ".".join(str(part) for part in sys.version_info[:3]),
            "node": ".".join(str(part) for part in node_version),
        },
        "scope": {
            "parser_checker": True,
            "interpreter": True,
            "python_backend": True,
            "javascript_backend": True,
            "webassembly_backend": True,
            "wat": True,
            "cli": True,
            "package_install": True,
            "component_model": False,
            "host_mediation": False,
            "bounded_execution": False,
            "operator_presence": False,
            "federation": False,
        },
        "checks": checks,
        "result": "pass",
        "limitations": [
            "This witness certifies the portable language core only.",
            "It grants no authority and is not an operator approval or release signature.",
            "Windows Component Model, host mediation, sandbox, ACL/SID, reparse-point, and Job Object contracts are outside v0.",
            "Cross-platform equality is not claimed until a later additive federation profile verifies this witness.",
        ],
    }
    witness["witness_sha256"] = _sha256(witness)
    return witness


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test", action="store_true",
        help="run all portable core checks without emitting a certifying witness",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    if args.self_test:
        if args.output is not None:
            parser.error("--self-test does not emit --output")
        checks = run_core_checks(require_distribution=False)
        failed = [item for item in checks if item["status"] != "pass"]
        if failed:
            print(json.dumps({"valid": False, "checks": checks}, sort_keys=True))
            return 1
        print("PASS Windows Core Conformance v0 portable self-test (non-certifying)")
        return 0

    if args.output is None:
        parser.error("certifying mode requires --output")
    try:
        commit_sha, run_id, run_attempt, node_version = _validate_windows_ci_environment()
        checks = run_core_checks(require_distribution=True)
    except Exception as exc:
        print("FAIL Windows Core Conformance v0: " + str(exc), file=sys.stderr)
        return 1
    failed = [item for item in checks if item["status"] != "pass"]
    if failed:
        print(json.dumps({"valid": False, "checks": checks}, sort_keys=True), file=sys.stderr)
        return 1

    witness = _build_witness(checks, commit_sha, run_id, run_attempt, node_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_bytes(_canonical(witness) + b"\n")
    os.replace(temporary, args.output)
    print("PASS Windows Core Conformance v0: " + witness["witness_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
