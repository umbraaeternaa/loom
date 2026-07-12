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
PROCESS_ACTION = "process"


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
