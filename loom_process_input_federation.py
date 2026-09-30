"""Cross-platform federation for native LOOM process-input receipts."""

from __future__ import annotations

import hashlib
import json
import re

import loom
import loom_windows_execution


POSIX_WITNESS_SCHEMA = "loom-posix-process-input-receipt-ci-witness/v0"
FEDERATION_SCHEMA = "loom-cross-platform-process-input-receipt-federation/v0"
FEDERATION_VALIDATION_SCHEMA = (
    "loom-cross-platform-process-input-receipt-federation-validation/v0"
)

PLATFORMS = (
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
)
POSIX_JOBS = {
    "aarch64-apple-darwin": "verify-macos-component",
    "x86_64-unknown-linux-gnu": "verify",
}
POSIX_RUNNERS = {
    "aarch64-apple-darwin": "macos-14",
    "x86_64-unknown-linux-gnu": "ubuntu-latest",
}
POSIX_CHECKS = (
    "byte-counted-posix-pipe-write",
    "early-close-partial-write-refusal",
    "receipt-tamper-and-rebinding-refusal",
)
SEMANTIC_CONTROLS = (
    "parent-side-byte-counted-pipe-delivery",
    "exact-stdin-digest-and-size",
    "writer-end-closed",
    "partial-delivery-fails-closed",
    "receipt-content-addressed-and-execution-bound",
    "payload-not-embedded",
    "process-consumption-not-proven",
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
        "schema": "loom-process-input-delivery-semantic-contract/v0",
        "controls": list(SEMANTIC_CONTROLS),
        "equality_claim": "parent-side-pipe-delivery-semantic-concordance",
        "native_pipe_mechanisms_equal": False,
        "payload_bytes_equal": False,
        "process_consumption_proven": False,
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


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _closed(value, keys, path, findings):
    if not isinstance(value, dict):
        findings.append(_finding(path, "expected-object", "expected an object"))
        return False
    if set(value) != set(keys):
        findings.append(_finding(
            path, "closed-object-mismatch",
            "object fields differ from the closed contract",
        ))
        return False
    return True


def _sha(value, path, findings, length=64):
    pattern = _HEX64 if length == 64 else _HEX40
    if not isinstance(value, str) or not pattern.fullmatch(value):
        findings.append(_finding(
            path, "expected-sha",
            f"expected {length}-character lowercase hexadecimal digest",
        ))


def build_posix_witness(
    platform_id, source_commit, ci, execution, process_input_receipt, checks,
):
    """Build a revision-bound POSIX receipt witness from native host evidence."""
    witness = {
        "schema": POSIX_WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "posix-native-process-input-receipt",
        "source": {"repository": "umbraaeternaa/loom", "commit_sha": source_commit},
        "ci": ci,
        "platform_id": platform_id,
        "execution": execution,
        "process_input_receipt": process_input_receipt,
        "checks": checks,
        "scope": {
            "posix_pipe_delivery": True,
            "process_consumption_proven": False,
            "operator_presence": False,
            "production_authority": False,
        },
        "limitations": [
            "This test-only witness proves parent-side POSIX pipe acceptance only.",
            "Process consumption is not proven by a successful pipe write.",
            "The receipt grants no operator presence or production authority.",
        ],
        "result": "pass",
    }
    witness["witness_sha256"] = sha256_json(witness)
    return validate_posix_witness(witness, source_commit)


def validate_posix_witness(witness, expected_commit=None):
    findings = []
    keys = {
        "schema", "test_only", "authorization", "certification_scope", "source",
        "ci", "platform_id", "execution", "process_input_receipt", "checks",
        "scope", "limitations", "result", "witness_sha256",
    }
    if not _closed(witness, keys, "witness", findings):
        return {"valid": False, "witness": None, "findings": findings}
    fixed = {
        "schema": POSIX_WITNESS_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "certification_scope": "posix-native-process-input-receipt",
        "result": "pass",
    }
    for key, expected in fixed.items():
        if witness.get(key) != expected:
            findings.append(_finding(
                "witness." + key, "profile-mismatch",
                "field differs from the closed POSIX receipt-witness profile",
            ))
    platform_id = witness.get("platform_id")
    if platform_id not in POSIX_JOBS:
        findings.append(_finding(
            "witness.platform_id", "unsupported-platform",
            "platform is outside the closed POSIX receipt set",
        ))
    source = witness.get("source")
    if _closed(source, {"repository", "commit_sha"}, "witness.source", findings):
        if source.get("repository") != "umbraaeternaa/loom":
            findings.append(_finding(
                "witness.source.repository", "repository-mismatch",
                "unexpected source repository",
            ))
        _sha(source.get("commit_sha"), "witness.source.commit_sha", findings, 40)
        if expected_commit is not None and source.get("commit_sha") != expected_commit:
            findings.append(_finding(
                "witness.source.commit_sha", "revision-mismatch",
                "witness does not bind the expected revision",
            ))
    ci = witness.get("ci")
    ci_keys = {"provider", "workflow", "job", "runner", "run_id", "run_attempt"}
    if _closed(ci, ci_keys, "witness.ci", findings):
        expected = {
            "provider": "github-actions",
            "workflow": "LOOM Citadel",
            "job": POSIX_JOBS.get(platform_id),
            "runner": POSIX_RUNNERS.get(platform_id),
        }
        if any(ci.get(key) != value for key, value in expected.items()):
            findings.append(_finding(
                "witness.ci", "ci-identity-mismatch",
                "CI identity differs from the closed platform profile",
            ))
        for key in ("run_id", "run_attempt"):
            if type(ci.get(key)) is not int or ci.get(key, 0) < 1:
                findings.append(_finding(
                    "witness.ci." + key, "invalid-ci-number",
                    key + " must be a positive integer",
                ))
    execution = witness.get("execution")
    receipt = witness.get("process_input_receipt")
    receipt_check = loom.validate_action_process_input_receipt_v0(receipt, execution)
    if not receipt_check["valid"]:
        findings.extend(_finding(
            "witness.process_input_receipt." + item.get("path", ""),
            item.get("code", "invalid-posix-receipt"), item.get("message", "invalid receipt"),
        ) for item in receipt_check["findings"])
    if isinstance(execution, dict) and execution.get("status") != "completed":
        findings.append(_finding(
            "witness.execution.status", "non-completed-execution",
            "certifying process-input execution must complete",
        ))
    checks = witness.get("checks")
    if (
        not isinstance(checks, list)
        or [item.get("id") for item in checks if isinstance(item, dict)]
        != list(POSIX_CHECKS)
        or any(
            not isinstance(item, dict) or set(item) != {"id", "status"}
            or item.get("status") != "pass" for item in checks
        )
    ):
        findings.append(_finding(
            "witness.checks", "incomplete-check-set",
            "POSIX process-input checks are incomplete, reordered, or failing",
        ))
    expected_scope = {
        "posix_pipe_delivery": True,
        "process_consumption_proven": False,
        "operator_presence": False,
        "production_authority": False,
    }
    if witness.get("scope") != expected_scope:
        findings.append(_finding(
            "witness.scope", "scope-mismatch",
            "witness scope differs from the closed non-authorizing profile",
        ))
    limitations = witness.get("limitations")
    if (
        not isinstance(limitations, list) or len(limitations) < 3
        or any(not isinstance(item, str) or not item for item in limitations)
    ):
        findings.append(_finding(
            "witness.limitations", "incomplete-limitations",
            "witness limitations are incomplete",
        ))
    else:
        words = " ".join(limitations).lower()
        for marker in ("test-only", "pipe acceptance", "process consumption", "production authority"):
            if marker not in words:
                findings.append(_finding(
                    "witness.limitations", "missing-limitation",
                    "witness limitations omit " + marker,
                ))
    _sha(witness.get("witness_sha256"), "witness.witness_sha256", findings)
    try:
        expected_hash = sha256_json({
            key: witness[key] for key in witness if key != "witness_sha256"
        })
    except (TypeError, ValueError):
        expected_hash = None
        findings.append(_finding(
            "witness", "non-canonical-witness", "witness is not canonical JSON",
        ))
    if expected_hash is not None and witness.get("witness_sha256") != expected_hash:
        findings.append(_finding(
            "witness.witness_sha256", "witness-hash-mismatch",
            "witness hash does not match canonical bytes",
        ))
    return {
        "valid": not findings,
        "witness": witness if not findings else None,
        "findings": findings,
    }


def _posix_record(witness):
    receipt = witness["process_input_receipt"]
    stdin = receipt["stdin"]
    return {
        "platform_id": witness["platform_id"],
        "witness_schema": POSIX_WITNESS_SCHEMA,
        "witness_sha256": witness["witness_sha256"],
        "receipt_schema": receipt["schema"],
        "receipt_sha256": receipt["receipt_sha256"],
        "execution_sha256": witness["execution"]["execution_sha256"],
        "stdin_sha256": stdin["expected_sha256"],
        "stdin_size_bytes": stdin["expected_size_bytes"],
        "native_delivery_mechanism": "python-unbuffered-pipe-write-loop/v0",
        "positive_write_calls_recorded": False,
        "ci_job": witness["ci"]["job"],
        "ci_run_id": witness["ci"]["run_id"],
        "ci_run_attempt": witness["ci"]["run_attempt"],
        "commit_sha": witness["source"]["commit_sha"],
    }


def _windows_record(witness):
    receipt = witness["process_input_receipt"]
    stdin = receipt["stdin"]
    pipe = receipt["pipe"]
    return {
        "platform_id": "x86_64-pc-windows-msvc",
        "witness_schema": loom_windows_execution.PROCESS_INPUT_WITNESS_SCHEMA,
        "witness_sha256": witness["witness_sha256"],
        "receipt_schema": receipt["schema"],
        "receipt_sha256": receipt["receipt_sha256"],
        "execution_sha256": witness["execution"]["execution_sha256"],
        "stdin_sha256": stdin["expected_sha256"],
        "stdin_size_bytes": stdin["expected_size_bytes"],
        "native_delivery_mechanism": pipe["native_api"],
        "positive_write_calls_recorded": True,
        "ci_job": witness["ci"]["job"],
        "ci_run_id": witness["ci"]["run_id"],
        "ci_run_attempt": witness["ci"]["run_attempt"],
        "commit_sha": witness["source"]["commit_sha"],
    }


def build_federation(witnesses, expected_commit=None):
    """Validate exactly three native receipt witnesses and federate semantics."""
    if not isinstance(witnesses, list) or len(witnesses) != len(PLATFORMS):
        return _result(False, findings=[_finding(
            "witnesses", "invalid-platform-set",
            "federation requires exactly three native process-input witnesses",
        )])
    records = []
    findings = []
    for index, witness in enumerate(witnesses):
        if isinstance(witness, dict) and witness.get("schema") == POSIX_WITNESS_SCHEMA:
            checked = validate_posix_witness(witness, expected_commit)
            if checked["valid"]:
                records.append(_posix_record(witness))
            else:
                findings.extend({
                    **item, "path": f"witnesses[{index}]." + item["path"],
                } for item in checked["findings"])
        elif (
            isinstance(witness, dict)
            and witness.get("schema")
            == loom_windows_execution.PROCESS_INPUT_WITNESS_SCHEMA
        ):
            checked = loom_windows_execution.validate_process_input_witness(
                witness, expected_commit,
            )
            if checked["valid"]:
                records.append(_windows_record(witness))
            else:
                findings.extend(_finding(
                    f"witnesses[{index}]", "invalid-windows-witness", item,
                ) for item in checked["findings"])
        else:
            findings.append(_finding(
                f"witnesses[{index}]", "unsupported-witness",
                "unsupported native process-input witness schema",
            ))
    if findings:
        return _result(False, findings=findings)
    records.sort(key=lambda item: item["platform_id"])
    if tuple(item["platform_id"] for item in records) != PLATFORMS:
        return _result(False, findings=[_finding(
            "witnesses", "incomplete-platform-set",
            "macOS arm64, Linux x86_64, and Windows x86_64 must each appear exactly once",
        )])
    commits = {item["commit_sha"] for item in records}
    jobs = {item["ci_job"] for item in records}
    runs = {(item["ci_run_id"], item["ci_run_attempt"]) for item in records}
    if any(not isinstance(value, str) or not _HEX40.fullmatch(value) for value in commits):
        return _result(False, findings=[_finding(
            "witnesses", "invalid-revision",
            "every platform witness must bind one full lowercase Git commit",
        )])
    if len(commits) != 1:
        return _result(False, findings=[_finding(
            "witnesses", "revision-mismatch",
            "platform witnesses do not bind one exact revision",
        )])
    if len(jobs) != len(records):
        return _result(False, findings=[_finding(
            "witnesses", "non-independent-ci-jobs",
            "each native witness must come from a distinct CI job",
        )])
    if len(runs) != 1:
        return _result(False, findings=[_finding(
            "witnesses", "ci-run-mismatch",
            "all native witnesses must originate from one workflow run and attempt",
        )])
    run_id, run_attempt = next(iter(runs))
    body = {
        "schema": FEDERATION_SCHEMA,
        "test_only": True,
        "authorization": "none",
        "source": {
            "repository": "umbraaeternaa/loom",
            "commit_sha": records[0]["commit_sha"],
        },
        "ci": {
            "provider": "github-actions", "workflow": "LOOM Citadel",
            "run_id": run_id, "run_attempt": run_attempt,
        },
        "semantic_contract": semantic_contract(),
        "platforms": records,
        "threshold": {
            "required_platforms": list(PLATFORMS),
            "minimum_witnesses": 3,
            "distinct_ci_jobs": True,
            "single_ci_run": True,
        },
        "equality": {
            "parent_side_pipe_delivery_semantics": True,
            "native_pipe_mechanisms": False,
            "payload_bytes": False,
            "process_consumption": False,
        },
        "lifecycle": {
            "schema": "loom-cross-platform-process-input-receipt-federation-lifecycle/v0",
            "native_receipts": 3,
            "cross_platform_claim": "parent-side-pipe-delivery-semantic-concordance",
            "process_consumption_proven": False,
            "operator_presence": False,
            "production_authority": False,
            "authorization": "none",
        },
        "limitations": [
            "This test-only federation grants no production authority.",
            "Native pipe mechanisms and payload bytes may differ across platforms.",
            "Parent-side pipe acceptance does not prove child process consumption.",
        ],
    }
    body["federation_sha256"] = sha256_json(body)
    return _result(True, federation=body)


def validate_federation(federation, witnesses, expected_commit=None):
    rebuilt = build_federation(witnesses, expected_commit)
    if not rebuilt["valid"]:
        return rebuilt
    if federation != rebuilt["federation"]:
        return _result(False, findings=[_finding(
            "federation", "federation-mismatch",
            "federation does not match the exact native witnesses",
        )])
    return rebuilt
