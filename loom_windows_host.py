"""Pure contracts for native Windows Host Security Substrate v0 evidence."""

from __future__ import annotations

import hashlib
import json
import re


WITNESS_SCHEMA = "loom-windows-host-security-ci-witness/v0"
PROBE_SCHEMA = "loom-windows-host-security-native-probe/v0"
EXPECTED_CHECKS = (
    "native-toolchain-two-build-reproducibility",
    "sid-dacl-private-custody",
    "component-path-reparse-refusal",
    "private-snapshot-byte-identity",
    "zero-capability-appcontainer-network-denial",
    "job-object-process-tree-containment",
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-)+[0-9]+\Z")


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


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


def validate_native_probe(probe):
    findings = []
    keys = {
        "schema", "owner_sid", "appcontainer_sid", "capabilities",
        "acl_broad_write", "reparse_points", "final_handle",
        "private_snapshot", "token_is_appcontainer", "network",
        "child_process", "job_process_limit", "job_kill_on_close",
    }
    if not _closed(probe, keys, "probe", findings):
        return findings
    fixed = {
        "schema": PROBE_SCHEMA,
        "capabilities": [],
        "acl_broad_write": "denied",
        "reparse_points": "denied",
        "final_handle": "stable",
        "private_snapshot": "byte-identical",
        "token_is_appcontainer": True,
        "network": "denied",
        "child_process": "denied",
        "job_process_limit": 1,
        "job_kill_on_close": True,
    }
    for key, expected in fixed.items():
        if probe.get(key) != expected:
            findings.append(f"probe.{key} must equal {expected!r}")
    for key in ("owner_sid", "appcontainer_sid"):
        if not isinstance(probe.get(key), str) or not _SID.fullmatch(probe[key]):
            findings.append(f"probe.{key} must be one canonical SID string")
    if (
        isinstance(probe.get("owner_sid"), str)
        and probe.get("owner_sid") == probe.get("appcontainer_sid")
    ):
        findings.append("probe owner and AppContainer SIDs must be distinct")
    return findings


def validate_witness(witness, expected_commit=None):
    findings = []
    top = {
        "schema", "test_only", "authorization", "certification_scope",
        "source", "ci", "platform", "toolchain", "probe", "checks",
        "scope", "result", "limitations", "witness_sha256",
    }
    if not _closed(witness, top, "witness", findings):
        return {"valid": False, "findings": findings}
    fixed = {
        "schema": WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-host-security-substrate",
        "result": "pass",
    }
    for key, expected in fixed.items():
        if witness.get(key) != expected:
            findings.append(f"witness.{key} must equal {expected!r}")

    source = witness.get("source")
    if _closed(source, {"repository", "commit_sha"}, "source", findings):
        if source.get("repository") != "umbraaeternaa/loom":
            findings.append("source.repository is outside the closed contract")
        commit = source.get("commit_sha")
        if not isinstance(commit, str) or not _SHA40.fullmatch(commit):
            findings.append("source.commit_sha must be lowercase 40-hex")
        if expected_commit is not None and commit != expected_commit:
            findings.append("source.commit_sha does not match the expected revision")

    ci = witness.get("ci")
    ci_keys = {"provider", "workflow", "job", "runner", "run_id", "run_attempt"}
    if _closed(ci, ci_keys, "ci", findings):
        expected_ci = {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-host-security", "runner": "windows-2025",
        }
        for key, expected in expected_ci.items():
            if ci.get(key) != expected:
                findings.append(f"ci.{key} must equal {expected!r}")
        if type(ci.get("run_id")) is not int or ci["run_id"] <= 0:
            findings.append("ci.run_id must be a positive integer")
        if type(ci.get("run_attempt")) is not int or ci["run_attempt"] <= 0:
            findings.append("ci.run_attempt must be a positive integer")

    platform = witness.get("platform")
    if _closed(platform, {"os", "architecture", "python", "windows_build"}, "platform", findings):
        if platform.get("os") != "windows" or platform.get("architecture") != "x86_64":
            findings.append("platform must be Windows x86_64")
        if not isinstance(platform.get("python"), str) or not platform["python"]:
            findings.append("platform.python must be present")
        if not isinstance(platform.get("windows_build"), str) or not platform["windows_build"]:
            findings.append("platform.windows_build must be present")

    toolchain = witness.get("toolchain")
    if _closed(toolchain, {"cl_version", "cl_sha256", "source_sha256", "probe_sha256"}, "toolchain", findings):
        for key in ("cl_sha256", "source_sha256", "probe_sha256"):
            if not isinstance(toolchain.get(key), str) or not _HEX64.fullmatch(toolchain[key]):
                findings.append(f"toolchain.{key} must be lowercase SHA-256")
        if not isinstance(toolchain.get("cl_version"), str) or "Compiler Version" not in toolchain["cl_version"]:
            findings.append("toolchain.cl_version is not an MSVC compiler identity")

    findings.extend(validate_native_probe(witness.get("probe")))
    checks = witness.get("checks")
    if not isinstance(checks, list) or len(checks) != len(EXPECTED_CHECKS):
        findings.append("checks must contain the complete closed check set")
    else:
        observed = []
        for index, item in enumerate(checks):
            if not _closed(item, {"id", "status"}, f"checks[{index}]", findings):
                continue
            observed.append(item.get("id"))
            if item.get("status") != "pass":
                findings.append(f"checks[{index}].status must equal 'pass'")
        if tuple(observed) != EXPECTED_CHECKS:
            findings.append("checks are missing, reordered, or outside the closed set")

    scope = witness.get("scope")
    expected_scope = {
        "sid_acl_custody": True,
        "reparse_point_defense": True,
        "private_snapshot": True,
        "appcontainer_network_isolation": True,
        "job_object_lifecycle": True,
        "bounded_execution_integration": False,
        "operator_presence": False,
        "federation": False,
    }
    if _closed(scope, expected_scope, "scope", findings):
        for key, expected in expected_scope.items():
            if scope.get(key) is not expected:
                findings.append(f"scope.{key} must equal {expected!r}")

    limitations = witness.get("limitations")
    if not isinstance(limitations, list) or len(limitations) < 3 or any(
        not isinstance(item, str) or not item for item in limitations
    ):
        findings.append("limitations must be a non-empty string list")
    else:
        words = " ".join(limitations)
        for marker in ("test-only", "Bounded Execution", "operator presence", "Federation v1"):
            if marker not in words:
                findings.append(f"limitations omit {marker!r}")

    digest = witness.get("witness_sha256")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        findings.append("witness_sha256 must be lowercase SHA-256")
    else:
        body = {key: witness[key] for key in sorted(top - {"witness_sha256"})}
        if digest != sha256_json(body):
            findings.append("witness_sha256 does not match canonical witness bytes")
    return {"valid": not findings, "findings": findings}


def portable_self_test():
    probe = {
        "schema": PROBE_SCHEMA,
        "owner_sid": "S-1-5-21-1-2-3-1001",
        "appcontainer_sid": "S-1-15-2-1",
        "capabilities": [],
        "acl_broad_write": "denied",
        "reparse_points": "denied",
        "final_handle": "stable",
        "private_snapshot": "byte-identical",
        "token_is_appcontainer": True,
        "network": "denied",
        "child_process": "denied",
        "job_process_limit": 1,
        "job_kill_on_close": True,
    }
    witness = {
        "schema": WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "windows-host-security-substrate",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": "a" * 40},
        "ci": {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "job": "verify-windows-host-security", "runner": "windows-2025",
            "run_id": 1, "run_attempt": 1,
        },
        "platform": {
            "os": "windows", "architecture": "x86_64", "python": "3.12.0",
            "windows_build": "10.0.26100",
        },
        "toolchain": {
            "cl_version": "Microsoft (R) C/C++ Optimizing Compiler Version 19.00 for x64",
            "cl_sha256": "b" * 64, "source_sha256": "c" * 64,
            "probe_sha256": "d" * 64,
        },
        "probe": probe,
        "checks": [{"id": item, "status": "pass"} for item in EXPECTED_CHECKS],
        "scope": {
            "sid_acl_custody": True, "reparse_point_defense": True,
            "private_snapshot": True, "appcontainer_network_isolation": True,
            "job_object_lifecycle": True, "bounded_execution_integration": False,
            "operator_presence": False, "federation": False,
        },
        "result": "pass",
        "limitations": [
            "This test-only witness grants no authority.",
            "Bounded Execution integration remains outside this substrate profile.",
            "Native operator presence and Federation v1 remain unclaimed.",
        ],
    }
    witness["witness_sha256"] = sha256_json(witness)
    if not validate_witness(witness, "a" * 40)["valid"]:
        return False
    tampered = json.loads(canonical_json(witness))
    tampered["probe"]["network"] = "allowed"
    if validate_witness(tampered, "a" * 40)["valid"]:
        return False
    tampered = json.loads(canonical_json(witness))
    tampered["scope"]["bounded_execution_integration"] = True
    tampered["witness_sha256"] = sha256_json({
        key: tampered[key] for key in sorted(set(tampered) - {"witness_sha256"})
    })
    return not validate_witness(tampered, "a" * 40)["valid"]
