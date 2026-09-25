"""Cross-platform federation for native LOOM general-execution evidence."""

from __future__ import annotations

import hashlib
import json
import re

import loom
import loom_windows_general


POSIX_WITNESS_SCHEMA = "loom-posix-general-execution-ci-witness/v0"
FEDERATION_SCHEMA = "loom-cross-platform-general-execution-federation/v0"
FEDERATION_VALIDATION_SCHEMA = (
    "loom-cross-platform-general-execution-federation-validation/v0"
)

PLATFORMS = (
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
)
POSIX_PROFILES = {
    "aarch64-apple-darwin": "darwin-seatbelt-network-deny/v0",
    "x86_64-unknown-linux-gnu": "linux-user-network-namespace/v0",
}
POSIX_JOBS = {
    "aarch64-apple-darwin": "verify-macos-component",
    "x86_64-unknown-linux-gnu": "verify",
}
POSIX_CHECKS = (
    "signed-approval-to-terminal-result",
    "exact-executable-argv-environment-stdin-binding",
    "one-use-replay-refusal",
    "network-isolation-enforced",
    "streaming-output-limit-termination",
    "wall-clock-timeout-termination",
)
SEMANTIC_CONTROLS = (
    "signed-exact-invocation",
    "hash-pinned-native-target",
    "exact-argv-environment-stdin",
    "shell-denied",
    "network-isolated",
    "one-use-replay-denied",
    "wall-clock-timeout-bounded",
    "output-bounded",
    "terminal-result-hash-linked",
    "production-authority-none",
)
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def semantic_contract():
    body = {
        "schema": "loom-general-execution-semantic-contract/v0",
        "controls": list(SEMANTIC_CONTROLS),
        "equality_claim": "observable-control-concordance",
        "native_mechanisms_equal": False,
        "target_bytes_equal": False,
        "authorization": "none",
    }
    body["contract_sha256"] = sha256_json(body)
    return body


def _result(valid, federation=None, findings=None):
    return {
        "schema": FEDERATION_VALIDATION_SCHEMA,
        "valid": bool(valid),
        "advisory": False,
        "authorization": "none",
        "federation": federation if valid else None,
        "federation_sha256": (
            federation.get("federation_sha256") if valid and federation else None
        ),
        "findings": findings or [],
    }


def _closed(value, keys, path, findings):
    if not isinstance(value, dict):
        findings.append({"path": path, "code": "expected-object", "message": "expected an object"})
        return False
    if set(value) != set(keys):
        findings.append({"path": path, "code": "closed-object-mismatch", "message": "object fields differ from the closed contract"})
        return False
    return True


def _sha(value, path, findings, length=64):
    pattern = _HEX64 if length == 64 else _HEX40
    if not isinstance(value, str) or not pattern.fullmatch(value):
        findings.append({"path": path, "code": "expected-sha", "message": f"expected {length}-character lowercase hexadecimal digest"})


def build_posix_witness(platform_id, source_commit, ci, public_key, action_result, checks):
    """Build a revision-bound test witness from a verified native POSIX Result."""
    witness = {
        "schema": POSIX_WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "posix-general-bounded-execution-v0",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": source_commit},
        "ci": ci,
        "platform_id": platform_id,
        "semantic_contract": semantic_contract(),
        "operator_public_key": public_key,
        "action_result": action_result,
        "checks": checks,
        "scope": {
            "arbitrary_approved_native_target": True,
            "native_network_sandbox": True,
            "bounded_streams": True,
            "operator_presence": False,
            "production_authority": False,
        },
        "limitations": [
            "test-only witness; it grants no production authority",
            "native confinement remains platform-specific",
            "cross-platform concordance does not imply identical target bytes",
        ],
        "result": "pass",
    }
    witness["witness_sha256"] = sha256_json(witness)
    return validate_posix_witness(witness, source_commit)


def validate_posix_witness(witness, expected_commit=None):
    findings = []
    keys = {
        "schema", "test_only", "authorization", "certification_scope", "source",
        "ci", "platform_id", "semantic_contract", "operator_public_key",
        "action_result", "checks", "scope", "limitations", "result",
        "witness_sha256",
    }
    if not _closed(witness, keys, "witness", findings):
        return {"valid": False, "witness": None, "findings": findings}
    fixed = {
        "schema": POSIX_WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "posix-general-bounded-execution-v0",
        "result": "pass",
    }
    for key, expected in fixed.items():
        if witness.get(key) != expected:
            findings.append({"path": "witness." + key, "code": "profile-mismatch", "message": "field differs from the closed POSIX witness profile"})
    platform_id = witness.get("platform_id")
    if platform_id not in POSIX_PROFILES:
        findings.append({"path": "witness.platform_id", "code": "unsupported-platform", "message": "platform is outside the closed federation set"})
    source = witness.get("source")
    if _closed(source, {"repository", "commit_sha"}, "witness.source", findings):
        if source.get("repository") != "umbraaeternaa/loom":
            findings.append({"path": "witness.source.repository", "code": "repository-mismatch", "message": "unexpected source repository"})
        _sha(source.get("commit_sha"), "witness.source.commit_sha", findings, 40)
        if expected_commit is not None and source.get("commit_sha") != expected_commit:
            findings.append({"path": "witness.source.commit_sha", "code": "revision-mismatch", "message": "witness does not bind the expected revision"})
    ci = witness.get("ci")
    ci_keys = {"provider", "workflow", "job", "runner", "run_id", "run_attempt"}
    if _closed(ci, ci_keys, "witness.ci", findings):
        expected_job = POSIX_JOBS.get(platform_id)
        if (
            ci.get("provider") != "github-actions"
            or ci.get("workflow") != "LOOM Citadel"
            or ci.get("job") != expected_job
            or not isinstance(ci.get("runner"), str)
            or not ci.get("runner")
            or type(ci.get("run_id")) is not int
            or ci.get("run_id", 0) < 1
            or type(ci.get("run_attempt")) is not int
            or ci.get("run_attempt", 0) < 1
        ):
            findings.append({"path": "witness.ci", "code": "ci-identity-mismatch", "message": "CI identity differs from the closed platform profile"})
    if witness.get("semantic_contract") != semantic_contract():
        findings.append({"path": "witness.semantic_contract", "code": "semantic-contract-mismatch", "message": "witness does not bind the federation semantic contract"})
    action_result = witness.get("action_result")
    result_check = loom.validate_action_capsule_result_v0(
        action_result, witness.get("operator_public_key"),
    )
    if not result_check["valid"]:
        findings.append({"path": "witness.action_result", "code": "invalid-action-result", "message": "embedded signed terminal Result is invalid"})
    elif isinstance(action_result, dict):
        execution = action_result["execution"]
        invocation = action_result["request"]["binding"]["invocation"]
        remeasurement = execution["host_remeasurement"]
        sandbox = execution["sandbox"]
        expected_profile = POSIX_PROFILES.get(platform_id)
        if sandbox.get("profile") != expected_profile:
            findings.append({"path": "witness.action_result.execution.sandbox.profile", "code": "sandbox-profile-mismatch", "message": "native sandbox does not match the declared platform"})
        if remeasurement.get("executable_sha256") != invocation.get("adapter", {}).get("artifact_sha256"):
            findings.append({"path": "witness.action_result.execution.host_remeasurement", "code": "target-hash-mismatch", "message": "spawn-boundary executable does not match the signed target hash"})
        if execution.get("status") != "completed" or action_result.get("lifecycle", {}).get("terminal") is not True:
            findings.append({"path": "witness.action_result", "code": "non-terminal-success", "message": "certifying execution must finish successfully and terminally"})
    checks = witness.get("checks")
    if (
        not isinstance(checks, list)
        or [item.get("id") for item in checks if isinstance(item, dict)] != list(POSIX_CHECKS)
        or any(not isinstance(item, dict) or set(item) != {"id", "status"} or item.get("status") != "pass" for item in checks)
    ):
        findings.append({"path": "witness.checks", "code": "incomplete-check-set", "message": "POSIX adversarial checks are incomplete, reordered, or failing"})
    expected_scope = {
        "arbitrary_approved_native_target": True,
        "native_network_sandbox": True,
        "bounded_streams": True,
        "operator_presence": False,
        "production_authority": False,
    }
    if witness.get("scope") != expected_scope:
        findings.append({"path": "witness.scope", "code": "scope-mismatch", "message": "witness scope differs from the closed non-authorizing profile"})
    limitations = witness.get("limitations")
    if not isinstance(limitations, list) or len(limitations) < 3 or any(not isinstance(item, str) or not item for item in limitations):
        findings.append({"path": "witness.limitations", "code": "incomplete-limitations", "message": "witness limitations are incomplete"})
    _sha(witness.get("witness_sha256"), "witness.witness_sha256", findings)
    try:
        expected_hash = sha256_json({key: witness[key] for key in witness if key != "witness_sha256"})
    except (TypeError, ValueError):
        expected_hash = None
        findings.append({"path": "witness", "code": "non-canonical-witness", "message": "witness is not canonical JSON"})
    if expected_hash is not None and witness.get("witness_sha256") != expected_hash:
        findings.append({"path": "witness.witness_sha256", "code": "witness-hash-mismatch", "message": "witness hash does not match canonical bytes"})
    return {"valid": not findings, "witness": witness if not findings else None, "findings": findings}


def build_federation(witnesses, expected_commit=None):
    """Verify exactly one native witness per closed platform and federate semantics."""
    if not isinstance(witnesses, list) or len(witnesses) != len(PLATFORMS):
        return _result(False, findings=[{"path": "witnesses", "code": "invalid-platform-set", "message": "federation requires exactly three native platform witnesses"}])
    records = []
    findings = []
    for index, witness in enumerate(witnesses):
        if isinstance(witness, dict) and witness.get("schema") == POSIX_WITNESS_SCHEMA:
            checked = validate_posix_witness(witness, expected_commit)
            if checked["valid"]:
                result = witness["action_result"]
                records.append({
                    "platform_id": witness["platform_id"],
                    "witness_schema": POSIX_WITNESS_SCHEMA,
                    "witness_sha256": witness["witness_sha256"],
                    "terminal_result_sha256": result["result_sha256"],
                    "native_confinement": result["execution"]["sandbox"]["profile"],
                    "ci_job": witness["ci"]["job"],
                    "commit_sha": witness["source"]["commit_sha"],
                })
            else:
                findings.extend({**item, "path": f"witnesses[{index}]." + item["path"]} for item in checked["findings"])
        elif isinstance(witness, dict) and witness.get("schema") == loom_windows_general.WITNESS_SCHEMA:
            checked = loom_windows_general.validate_witness(witness, expected_commit)
            if checked["valid"]:
                records.append({
                    "platform_id": "x86_64-pc-windows-msvc",
                    "witness_schema": loom_windows_general.WITNESS_SCHEMA,
                    "witness_sha256": witness["witness_sha256"],
                    "terminal_result_sha256": witness["result_artifact"]["result_sha256"],
                    "native_confinement": "windows-appcontainer-zero-capability-one-process-job/v1",
                    "ci_job": witness["ci"]["job"],
                    "commit_sha": witness["source"]["commit_sha"],
                })
            else:
                findings.extend({"path": f"witnesses[{index}]", "code": "invalid-windows-witness", "message": item} for item in checked["findings"])
        else:
            findings.append({"path": f"witnesses[{index}]", "code": "unsupported-witness", "message": "unsupported native witness schema"})
    if findings:
        return _result(False, findings=findings)
    records.sort(key=lambda item: item["platform_id"])
    if tuple(item["platform_id"] for item in records) != PLATFORMS:
        return _result(False, findings=[{"path": "witnesses", "code": "incomplete-platform-set", "message": "macOS arm64, Linux x86_64, and Windows x86_64 must each appear exactly once"}])
    commits = {item["commit_sha"] for item in records}
    jobs = {item["ci_job"] for item in records}
    if any(not isinstance(value, str) or not _HEX40.fullmatch(value) for value in commits):
        return _result(False, findings=[{"path": "witnesses", "code": "invalid-revision", "message": "every platform witness must bind one full lowercase Git commit"}])
    if len(commits) != 1:
        return _result(False, findings=[{"path": "witnesses", "code": "revision-mismatch", "message": "platform witnesses do not bind one exact revision"}])
    if len(jobs) != len(records):
        return _result(False, findings=[{"path": "witnesses", "code": "non-independent-ci-jobs", "message": "each native witness must come from a distinct CI job"}])
    body = {
        "schema": FEDERATION_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": records[0]["commit_sha"]},
        "semantic_contract": semantic_contract(),
        "platforms": records,
        "threshold": {"required_platforms": list(PLATFORMS), "minimum_witnesses": 3, "distinct_ci_jobs": True},
        "equality": {
            "observable_control_semantics": True,
            "native_confinement_mechanisms": False,
            "target_bytes": False,
            "toolchain_bytes": False,
        },
        "lifecycle": {
            "schema": "loom-cross-platform-general-execution-federation-lifecycle/v0",
            "terminal_native_results": 3,
            "cross_platform_claim": "native-control-semantic-concordance",
            "operator_presence": False,
            "production_authority": False,
            "authorization": "none",
        },
        "limitations": [
            "test-only federation; it grants no production authority",
            "native sandbox mechanisms remain intentionally platform-specific",
            "semantic concordance does not claim identical target or toolchain bytes",
        ],
    }
    body["federation_sha256"] = sha256_json(body)
    return _result(True, federation=body)


def validate_federation(federation, witnesses, expected_commit=None):
    rebuilt = build_federation(witnesses, expected_commit)
    if not rebuilt["valid"]:
        return rebuilt
    if federation != rebuilt["federation"]:
        return _result(False, findings=[{"path": "federation", "code": "federation-mismatch", "message": "federation does not match the exact native witnesses"}])
    return rebuilt
