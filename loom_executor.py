#!/usr/bin/env python3
"""Host-side executor contracts for claimed LOOM Gate actions.

This module does not execute commands. It builds and validates the narrow
contract a trusted host must follow around the approval claim lifecycle.
"""

import hashlib
import json

import loom_approval
import loom_gate
import loom_observer


PLAN_SCHEMA = "loom-gate-execution-plan/v1"
PLAN_VALIDATION_SCHEMA = "loom-gate-execution-plan-validation/v1"
HOST_ATTEMPT_SCHEMA = "loom-gate-host-attempt/v1"
HOST_ATTEMPT_VALIDATION_SCHEMA = "loom-gate-host-attempt-validation/v1"
PROCESS_ACTION = "process"
_HOST_ATTEMPT_KEYS = frozenset({"schema", "result", "evidence"})
_HOST_RESULTS = frozenset({"completed", "failed", "blocked"})
_PLAN_KEYS = frozenset({
    "schema",
    "manifest_sha256",
    "challenge_sha256",
    "approval_sha256",
    "claim_sha256",
    "executor_boundary",
    "actions_allowed",
    "read_paths",
    "write_paths",
    "secret_lanes",
    "plan_sha256",
})


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _plan_result(plan, findings):
    return {
        "schema": PLAN_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "plan": plan if not findings else None,
        "findings": loom_gate._unique_issues(findings),
    }


def _host_attempt_result(attempt, findings):
    return {
        "schema": HOST_ATTEMPT_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": False,
        "attempt": attempt if not findings else None,
        "findings": loom_gate._unique_issues(findings),
    }


def _validate_actions(actions, declared):
    findings = []
    if not isinstance(actions, list):
        return None, [_finding("actions", "expected-array", "actions must be an array")]
    normalized = []
    for index, action in enumerate(actions):
        if not isinstance(action, str) or not action.strip():
            findings.append(_finding(f"actions[{index}]", "expected-string", "action must be a non-empty string"))
            continue
        if action not in loom_gate.ACTIONS:
            findings.append(_finding(f"actions[{index}]", "unknown-action", f"unknown action '{action}'"))
        normalized.append(action)
    for action in sorted({item for item in normalized if normalized.count(item) > 1}):
        findings.append(_finding("actions", "duplicate-action", f"duplicate action '{action}'"))
    for action in sorted(set(normalized) - set(declared)):
        findings.append(_finding("actions", "undeclared-action", f"action '{action}' was not declared by the manifest"))
    return sorted(set(normalized)), findings


def _validate_evidence(evidence):
    findings = []
    if not isinstance(evidence, list):
        return None, [_finding("evidence", "expected-array", "evidence must be an array")]
    normalized = []
    for index, item in enumerate(evidence):
        base = f"evidence[{index}]"
        if not isinstance(item, dict):
            findings.append(_finding(base, "expected-object", "evidence item must be an object"))
            continue
        for key in sorted(set(item) - {"kind", "status", "detail"}):
            findings.append(_finding(base + "." + key, "unknown-field", f"unknown evidence field '{key}'"))
        for key in sorted({"kind", "status", "detail"} - set(item)):
            findings.append(_finding(base + "." + key, "missing-field", f"missing evidence field '{key}'"))
        kind = item.get("kind")
        status = item.get("status")
        detail = item.get("detail")
        if not isinstance(kind, str) or not kind:
            findings.append(_finding(base + ".kind", "expected-string", "evidence kind must be a non-empty string"))
        elif kind not in loom_gate.EVIDENCE:
            findings.append(_finding(base + ".kind", "unknown-evidence", f"unknown evidence '{kind}'"))
        if not isinstance(status, str) or not status:
            findings.append(_finding(base + ".status", "expected-string", "evidence status must be a non-empty string"))
        elif status not in {"pass", "fail", "not-run"}:
            findings.append(_finding(base + ".status", "unknown-evidence-status", f"unknown evidence status '{status}'"))
        if not isinstance(detail, str) or not detail:
            findings.append(_finding(base + ".detail", "expected-string", "evidence detail must be a non-empty string"))
        normalized.append({"kind": kind, "status": status, "detail": detail})
    kinds = [item["kind"] for item in normalized if isinstance(item["kind"], str)]
    for kind in sorted({kind for kind in kinds if kinds.count(kind) > 1}):
        findings.append(_finding("evidence", "duplicate-evidence", f"duplicate evidence '{kind}'"))
    return sorted(normalized, key=lambda item: item["kind"] or ""), findings


def validate_host_attempt(attempt):
    """Validate the closed trusted-host attempt result contract."""
    findings = []
    if not isinstance(attempt, dict):
        return _host_attempt_result(None, [_finding("attempt", "expected-object", "host attempt must be an object")])
    for key in sorted(set(attempt) - _HOST_ATTEMPT_KEYS):
        findings.append(_finding(key, "unknown-field", f"unknown host attempt field '{key}'"))
    for key in sorted(_HOST_ATTEMPT_KEYS - set(attempt)):
        findings.append(_finding(key, "missing-field", f"missing host attempt field '{key}'"))
    schema = attempt.get("schema")
    if not isinstance(schema, str):
        findings.append(_finding("schema", "expected-string", "schema must be a string"))
    elif schema != HOST_ATTEMPT_SCHEMA:
        findings.append(_finding("schema", "unsupported-schema", f"expected '{HOST_ATTEMPT_SCHEMA}'"))
    result = attempt.get("result")
    if not isinstance(result, str):
        findings.append(_finding("result", "expected-string", "result must be a string"))
    elif result not in _HOST_RESULTS:
        findings.append(_finding("result", "unknown-result", f"unknown result '{result}'"))
    evidence, evidence_findings = _validate_evidence(attempt.get("evidence"))
    findings.extend(evidence_findings)
    normalized = {"schema": schema, "result": result, "evidence": evidence}
    return _host_attempt_result(normalized, findings)


def _validate_process_plan_surface(plan):
    findings = []
    if not isinstance(plan, dict):
        return None, [_finding("plan", "expected-object", "execution plan must be an object")]
    for key in sorted(set(plan) - _PLAN_KEYS):
        findings.append(_finding("plan." + key, "unknown-field", f"unknown execution plan field '{key}'"))
    for key in sorted(_PLAN_KEYS - set(plan)):
        findings.append(_finding("plan." + key, "missing-field", f"missing execution plan field '{key}'"))
    if findings:
        return None, findings
    if plan["schema"] != PLAN_SCHEMA:
        findings.append(_finding("plan.schema", "unsupported-schema", f"expected '{PLAN_SCHEMA}'"))
    if plan["executor_boundary"] != "no-shell/no-network-by-default":
        findings.append(_finding("plan.executor_boundary", "executor-boundary-mismatch", "process plan must keep the no-shell/no-network boundary"))
    if plan["actions_allowed"] != [PROCESS_ACTION]:
        findings.append(_finding("plan.actions_allowed", "process-only-required", "process attempt dry-run requires actions_allowed to be exactly ['process']"))
    for key in ("manifest_sha256", "challenge_sha256", "approval_sha256", "claim_sha256", "plan_sha256"):
        value = plan.get(key)
        if not isinstance(value, str) or len(value) != 64:
            findings.append(_finding("plan." + key, "expected-sha256", f"{key} must be a 64-character SHA-256 hex string"))
    for key in ("read_paths", "write_paths", "secret_lanes"):
        if not isinstance(plan.get(key), list):
            findings.append(_finding("plan." + key, "expected-array", f"{key} must be an array"))
    if not findings:
        unsigned = {key: plan[key] for key in sorted(_PLAN_KEYS - {"plan_sha256"})}
        expected = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
        if plan["plan_sha256"] != expected:
            findings.append(_finding("plan.plan_sha256", "plan-sha256-mismatch", "plan_sha256 does not match the process execution plan body"))
    normalized = {key: plan.get(key) for key in sorted(_PLAN_KEYS)}
    return normalized, findings


def validate_process_attempt(plan, attempt):
    """Dry-run validate a host attempt against a process-only plan."""
    normalized_plan, plan_findings = _validate_process_plan_surface(plan)
    checked = validate_host_attempt(attempt)
    findings = list(plan_findings) + list(checked["findings"])
    body = checked["attempt"] if checked["valid"] else None
    if normalized_plan is not None and body is not None:
        body = dict(body)
        body["plan_sha256"] = normalized_plan["plan_sha256"]
    return _host_attempt_result(body, findings)


def _redacted_secret_lanes(manifest):
    decision = loom_gate.evaluate_manifest(manifest)
    lanes = []
    for item in decision["reasons"] + decision["violations"]:
        if not item["code"].startswith("secret-"):
            continue
        lanes.append({
            "field": item["path"],
            "code": item["code"],
            "class": loom_gate._secret_issue_class(item["code"], item["message"]),
            "disposition": loom_gate._secret_issue_disposition(item["code"]),
        })
    return sorted(lanes, key=lambda item: (item["field"], item["code"], item["class"]))


def _expected_claim(manifest, challenge, approval, verified):
    return {
        "schema": loom_approval.CLAIM_SCHEMA,
        "approval_sha256": verified["approval_sha256"],
        "manifest_sha256": challenge.get("manifest_sha256"),
        "challenge_sha256": challenge.get("challenge_sha256"),
        "status": "claimed",
    }


def _bind_claim(expected):
    body = dict(expected)
    body["claim_sha256"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return body


def _verify_claim(manifest, challenge, approval, claim):
    verified = loom_approval.verify_operator_approval(manifest, challenge, approval)
    if not verified["valid"]:
        return None, verified["findings"]
    expected = _bind_claim(_expected_claim(manifest, challenge, approval, verified))
    if claim != expected:
        return None, [_finding("claim", "claim-mismatch", "claim does not match the signed manifest and challenge")]
    return verified, []


def plan_claimed_execution(manifest, challenge, approval, claim, actions):
    """Build a bounded host execution plan for an already claimed approval."""
    validation = loom_gate.validate_manifest(manifest)
    findings = list(validation["findings"])
    if findings:
        return _plan_result(None, findings)
    normalized = validation["normalized_manifest"]
    decision = loom_gate.evaluate_manifest(normalized)
    if decision["decision"] != "operator-required":
        findings.append(_finding("manifest", "approval-not-required", "executor plan requires an operator-required manifest"))
    verified, claim_findings = _verify_claim(normalized, challenge, approval, claim)
    findings.extend(claim_findings)
    normalized_actions, action_findings = _validate_actions(actions, normalized["actions"])
    findings.extend(action_findings)
    if findings:
        return _plan_result(None, findings)

    body = {
        "schema": PLAN_SCHEMA,
        "manifest_sha256": validation["manifest_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "approval_sha256": verified["approval_sha256"],
        "claim_sha256": claim["claim_sha256"],
        "executor_boundary": "no-shell/no-network-by-default",
        "actions_allowed": normalized_actions,
        "read_paths": normalized["read_paths"],
        "write_paths": normalized["write_paths"],
        "secret_lanes": _redacted_secret_lanes(normalized),
    }
    body["plan_sha256"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return _plan_result(body, [])


def finish_claimed_execution(manifest, challenge, approval, claim, plan, result, actions_observed, evidence):
    """Collect observation facts and finalize a claimed execution through the plan."""
    rebuilt = plan_claimed_execution(manifest, challenge, approval, claim, plan.get("actions_allowed") if isinstance(plan, dict) else None)
    if not rebuilt["valid"]:
        return loom_gate._receipt_validation(None, rebuilt["findings"])
    if plan != rebuilt["plan"]:
        return loom_gate._receipt_validation(None, [_finding("plan", "plan-mismatch", "execution plan does not match manifest, approval claim, and actions")])
    action_check, action_findings = _validate_actions(actions_observed, plan["actions_allowed"])
    if action_findings:
        return loom_gate._receipt_validation(None, action_findings)
    collection = loom_observer.collect_observation(manifest, result, action_check, evidence)
    if not collection["valid"]:
        return loom_gate._receipt_validation(None, collection["findings"])
    return loom_approval.finish_claimed_receipt(manifest, collection["observation"], challenge, approval, claim)


def plan_process_execution(manifest, challenge, approval, claim):
    """Build the narrow process-only trusted host plan."""
    return plan_claimed_execution(manifest, challenge, approval, claim, [PROCESS_ACTION])


def finish_process_execution(manifest, challenge, approval, claim, plan, result, evidence=None):
    """Finalize a process-only trusted host plan without accepting arbitrary actions."""
    return finish_claimed_execution(
        manifest,
        challenge,
        approval,
        claim,
        plan,
        result,
        [PROCESS_ACTION],
        [] if evidence is None else evidence,
    )


def finish_process_attempt(manifest, challenge, approval, claim, plan, attempt):
    """Validate a host attempt object and finalize the process-only plan."""
    checked = validate_process_attempt(plan, attempt)
    if not checked["valid"]:
        return loom_gate._receipt_validation(None, checked["findings"])
    body = checked["attempt"]
    return finish_process_execution(manifest, challenge, approval, claim, plan, body["result"], body["evidence"])
