"""Closed, non-authorizing composition for bounded Action Capsule DAGs."""

import hashlib
import json
import re
import unicodedata


PLAN_SCHEMA = "loom-multi-action-plan/v0"
PLAN_VALIDATION_SCHEMA = "loom-multi-action-plan-validation/v0"
STEP_SCHEMA = "loom-multi-action-step/v0"
BOUNDARY_SCHEMA = "loom-multi-action-approval-boundary/v0"
LIMITS_SCHEMA = "loom-multi-action-limits/v0"
EXECUTION_POLICY_SCHEMA = "loom-multi-action-execution-policy/v0"
LIFECYCLE_SCHEMA = "loom-multi-action-lifecycle/v0"
RECEIPT_SCHEMA = "loom-multi-action-receipt/v0"
RECEIPT_VALIDATION_SCHEMA = "loom-multi-action-receipt-validation/v0"
OUTCOME_SCHEMA = "loom-multi-action-outcome/v0"
SUMMARY_SCHEMA = "loom-multi-action-summary/v0"
RECEIPT_LIFECYCLE_SCHEMA = "loom-multi-action-receipt-lifecycle/v0"

MAX_STEPS = 64
MAX_DEPENDENCIES_PER_STEP = 64
_STEP_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class Frontend:
    def __init__(self, capsule_structure_findings, validate_result):
        self.capsule_structure_findings = capsule_structure_findings
        self.validate_result = validate_result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _is_sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _prefixed(path, findings):
    return [{
        "path": path + ("." + item["path"] if item.get("path") else ""),
        "code": item["code"],
        "message": item["message"],
    } for item in findings]


def _closed(value, path, keys):
    if not isinstance(value, dict):
        return [_finding(path, "expected-object", path + " must be an object")]
    findings = []
    for key in sorted(set(value) - keys, key=str):
        findings.append(_finding(path + "." + str(key), "unknown-field", "unknown Multi-Action field"))
    for key in sorted(keys - set(value)):
        findings.append(_finding(path + "." + key, "missing-field", "missing Multi-Action field"))
    return findings


def _validation(plan, findings):
    return {
        "schema": PLAN_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "none",
        "plan": plan if not findings else None,
        "plan_sha256": plan.get("plan_sha256") if not findings else None,
        "findings": findings,
    }


def _receipt_validation(receipt, findings):
    return {
        "schema": RECEIPT_VALIDATION_SCHEMA,
        "valid": not findings,
        "authorization": "none",
        "receipt": receipt if not findings else None,
        "receipt_sha256": receipt.get("receipt_sha256") if not findings else None,
        "findings": findings,
    }


def _step_id_findings(value, path):
    if not isinstance(value, str):
        return [_finding(path, "expected-string", "step id must be a string")]
    if value != unicodedata.normalize("NFC", value):
        return [_finding(path, "non-canonical-step-id", "step id must be NFC-normalized")]
    if _STEP_ID.fullmatch(value) is None:
        return [_finding(path, "invalid-step-id", "step id must match [a-z][a-z0-9-]{0,63}")]
    return []


def _dependency_findings(value, path):
    if not isinstance(value, list):
        return [_finding(path, "expected-array", "depends_on must be an array")]
    findings = []
    if len(value) > MAX_DEPENDENCIES_PER_STEP:
        findings.append(_finding(path, "dependency-limit-exceeded", "a step may have at most 64 dependencies"))
    for index, item in enumerate(value):
        findings.extend(_step_id_findings(item, f"{path}[{index}]"))
    if all(isinstance(item, str) for item in value):
        if len(set(value)) != len(value):
            findings.append(_finding(path, "duplicate-dependency", "dependencies must be unique"))
    return findings


def _topological_order(ids, dependencies):
    incoming = {step_id: set(dependencies[step_id]) for step_id in ids}
    ready = sorted(step_id for step_id in ids if not incoming[step_id])
    visited = []
    while ready:
        current = ready.pop(0)
        visited.append(current)
        for step_id in ids:
            if current in incoming[step_id]:
                incoming[step_id].remove(current)
                if not incoming[step_id] and step_id not in visited and step_id not in ready:
                    ready.append(step_id)
                    ready.sort()
    return visited


def _cycle_findings(ids, dependencies):
    visited = _topological_order(ids, dependencies)
    if len(visited) != len(ids):
        cyclic = sorted(set(ids) - set(visited))
        return [_finding("steps", "dependency-cycle", "dependency graph contains a cycle: " + ", ".join(cyclic))]
    return []


def _approval_boundary(step_id, capsule_sha256):
    boundary = {
        "schema": BOUNDARY_SCHEMA,
        "mode": "per-step",
        "step_id": step_id,
        "capsule_sha256": capsule_sha256,
        "approval_schema": "loom-action-capsule-approval/v2",
        "shareable": False,
    }
    boundary["boundary_sha256"] = _sha256(boundary)
    return boundary


def build_plan(frontend, step_specs):
    """Build one deterministic DAG over existing non-authorizing Action Capsules."""
    if not isinstance(step_specs, list):
        return _validation(None, [_finding("steps", "expected-array", "steps must be an array")])
    findings = []
    if not 1 <= len(step_specs) <= MAX_STEPS:
        findings.append(_finding("steps", "step-limit", "a plan requires 1 to 64 steps"))
    parsed = []
    ids = []
    for index, spec in enumerate(step_specs):
        path = f"steps[{index}]"
        findings.extend(_closed(spec, path, {"id", "depends_on", "capsule"}))
        if not isinstance(spec, dict):
            continue
        step_id = spec.get("id")
        findings.extend(_step_id_findings(step_id, path + ".id"))
        dependencies = spec.get("depends_on")
        findings.extend(_dependency_findings(dependencies, path + ".depends_on"))
        capsule = spec.get("capsule")
        capsule_findings = frontend.capsule_structure_findings(capsule)
        findings.extend(_prefixed(path + ".capsule", capsule_findings))
        if not _step_id_findings(step_id, path + ".id") and isinstance(dependencies, list) and not capsule_findings:
            parsed.append((step_id, list(dependencies), capsule))
            ids.append(step_id)
    if len(set(ids)) != len(ids):
        findings.append(_finding("steps", "duplicate-step-id", "step ids must be unique"))
    id_set = set(ids)
    dependencies_by_id = {}
    for step_id, dependencies, _ in parsed:
        dependencies_by_id[step_id] = dependencies
        if step_id in dependencies:
            findings.append(_finding("steps." + step_id + ".depends_on", "self-dependency", "a step cannot depend on itself"))
        for dependency in dependencies:
            if dependency not in id_set:
                findings.append(_finding("steps." + step_id + ".depends_on", "unknown-dependency", "dependency does not name a plan step"))
    if not findings and len(parsed) == len(step_specs):
        findings.extend(_cycle_findings(sorted(ids), dependencies_by_id))
    if findings:
        return _validation(None, findings)

    steps = []
    for step_id, dependencies, capsule in sorted(parsed, key=lambda item: item[0]):
        effects = capsule["action_semantics"]["effect_contract"]["declared"]
        step = {
            "schema": STEP_SCHEMA,
            "id": step_id,
            "depends_on": sorted(dependencies),
            "capsule": capsule,
            "capsule_sha256": capsule["capsule_sha256"],
            "declared_effects": list(effects),
            "approval_boundary": _approval_boundary(step_id, capsule["capsule_sha256"]),
        }
        step["step_sha256"] = _sha256(step)
        steps.append(step)
    depended_on = {dependency for step in steps for dependency in step["depends_on"]}
    roots = [step["id"] for step in steps if not step["depends_on"]]
    terminals = [step["id"] for step in steps if step["id"] not in depended_on]
    body = {
        "schema": PLAN_SCHEMA,
        "advisory": True,
        "steps": steps,
        "roots": roots,
        "terminals": terminals,
        "limits": {
            "schema": LIMITS_SCHEMA,
            "maximum_steps": MAX_STEPS,
            "maximum_dependencies_per_step": MAX_DEPENDENCIES_PER_STEP,
        },
        "execution_policy": {
            "schema": EXECUTION_POLICY_SCHEMA,
            "mode": "not-executable",
            "dependency_policy": "all-success-before-start",
            "failure_policy": "skip-transitive-dependents",
            "effect_escalation": "forbidden",
            "approval_inheritance": "forbidden",
            "host_actions_executed": False,
        },
        "lifecycle": {
            "schema": LIFECYCLE_SCHEMA,
            "authorization": "none",
            "approval_eligible": False,
            "per_step_approval_required": True,
            "aggregate_receipt_schema": RECEIPT_SCHEMA,
            "required_next": [
                "loom-action-invocation-binding/v0",
                "loom-action-capsule-approval/v2",
                "loom-action-capsule-result/v0",
                RECEIPT_SCHEMA,
            ],
        },
    }
    body["plan_sha256"] = _sha256(body)
    return _validation(body, [])


def validate_plan(frontend, plan):
    outer_keys = {
        "schema", "advisory", "steps", "roots", "terminals", "limits",
        "execution_policy", "lifecycle", "plan_sha256",
    }
    findings = _closed(plan, "plan", outer_keys)
    if not isinstance(plan, dict):
        return _validation(None, findings)
    if plan.get("schema") != PLAN_SCHEMA:
        findings.append(_finding("plan.schema", "unsupported-schema", "expected " + PLAN_SCHEMA))
    if plan.get("advisory") is not True:
        findings.append(_finding("plan.advisory", "invalid-advisory", "plan must remain advisory"))
    if not _is_sha256(plan.get("plan_sha256")):
        findings.append(_finding("plan.plan_sha256", "expected-sha256", "plan_sha256 must be lowercase SHA-256"))
    steps = plan.get("steps")
    if not isinstance(steps, list):
        findings.append(_finding("plan.steps", "expected-array", "steps must be an array"))
        return _validation(None, findings)
    specs = []
    for index, step in enumerate(steps):
        path = f"plan.steps[{index}]"
        step_keys = {
            "schema", "id", "depends_on", "capsule", "capsule_sha256",
            "declared_effects", "approval_boundary", "step_sha256",
        }
        findings.extend(_closed(step, path, step_keys))
        if isinstance(step, dict):
            specs.append({
                "id": step.get("id"),
                "depends_on": step.get("depends_on"),
                "capsule": step.get("capsule"),
            })
    expected = build_plan(frontend, specs)
    if not expected["valid"]:
        findings.extend(_prefixed("plan", expected["findings"]))
    elif plan != expected["plan"]:
        findings.append(_finding("plan", "plan-mismatch", "plan does not match its exact capsules, DAG, effects, boundaries, or lifecycle"))
    return _validation(plan, findings)


def _terminal_success(result):
    outcome = result["outcome"]
    return (
        outcome["status"] == "completed"
        and outcome["exit_code"] == 0
        and outcome["terminating_signal"] is None
    )


def build_receipt(frontend, plan, results_by_step, public_key_value):
    """Compose terminal Action Results without executing or authorizing any action."""
    plan_check = validate_plan(frontend, plan)
    if not plan_check["valid"]:
        return _receipt_validation(None, _prefixed("plan", plan_check["findings"]))
    if not isinstance(results_by_step, dict):
        return _receipt_validation(None, [_finding("results", "expected-object", "results must map step ids to terminal Results")])
    findings = []
    step_map = {step["id"]: step for step in plan["steps"]}
    for key in sorted(set(results_by_step) - set(step_map), key=str):
        findings.append(_finding("results." + str(key), "unknown-step-result", "result does not belong to this plan"))
    validated = {}
    result_hashes = set()
    approval_hashes = set()
    for step_id, result in results_by_step.items():
        if step_id not in step_map:
            continue
        check = frontend.validate_result(result, public_key_value)
        findings.extend(_prefixed("results." + step_id, check["findings"]))
        if not check["valid"]:
            continue
        if result["request"]["binding"]["capsule_sha256"] != step_map[step_id]["capsule_sha256"]:
            findings.append(_finding("results." + step_id, "capsule-result-mismatch", "Result does not bind this step's Action Capsule"))
            continue
        if result["result_sha256"] in result_hashes:
            findings.append(_finding("results." + step_id, "reused-result", "one terminal Result cannot satisfy multiple steps"))
        if result["approval_sha256"] in approval_hashes:
            findings.append(_finding("results." + step_id, "reused-approval", "each step requires a distinct approval boundary"))
        result_hashes.add(result["result_sha256"])
        approval_hashes.add(result["approval_sha256"])
        validated[step_id] = result
    if findings:
        return _receipt_validation(None, findings)

    outcomes = []
    successful = {}
    dependencies = {step["id"]: step["depends_on"] for step in plan["steps"]}
    order = _topological_order(sorted(step_map), dependencies)
    for step_id in order:
        step = step_map[step_id]
        blockers = [dependency for dependency in step["depends_on"] if not successful.get(dependency, False)]
        result = validated.get(step_id)
        if blockers:
            if result is not None:
                findings.append(_finding("results." + step_id, "blocked-step-result", "a step ran despite an unsuccessful dependency"))
            outcomes.append({
                "schema": OUTCOME_SCHEMA,
                "step_id": step_id,
                "state": "skipped",
                "capsule_sha256": step["capsule_sha256"],
                "blocked_by": blockers,
            })
            successful[step_id] = False
            continue
        if result is None:
            findings.append(_finding("results." + step_id, "missing-result", "an unblocked step requires one terminal Result"))
            successful[step_id] = False
            continue
        for dependency in step["depends_on"]:
            parent = validated[dependency]
            if parent["finalized_at_unix_ms"] > result["execution"]["executed_at_unix_ms"]:
                findings.append(_finding("results." + step_id, "dependency-order-violation", "step started before its dependency finalized"))
        success = _terminal_success(result)
        successful[step_id] = success
        outcomes.append({
            "schema": OUTCOME_SCHEMA,
            "step_id": step_id,
            "state": "terminal",
            "capsule_sha256": step["capsule_sha256"],
            "approval_boundary_sha256": step["approval_boundary"]["boundary_sha256"],
            "approval_sha256": result["approval_sha256"],
            "result_sha256": result["result_sha256"],
            "status": result["outcome"]["status"],
            "successful": success,
            "started_at_unix_ms": result["execution"]["executed_at_unix_ms"],
            "finalized_at_unix_ms": result["finalized_at_unix_ms"],
        })
    if findings:
        return _receipt_validation(None, findings)
    succeeded = [step_id for step_id in sorted(successful) if successful[step_id]]
    failed = [item["step_id"] for item in outcomes if item["state"] == "terminal" and not item["successful"]]
    skipped = [item["step_id"] for item in outcomes if item["state"] == "skipped"]
    body = {
        "schema": RECEIPT_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "outcomes": outcomes,
        "summary": {
            "schema": SUMMARY_SCHEMA,
            "decision": "completed" if len(succeeded) == len(plan["steps"]) else "stopped",
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
        },
        "lifecycle": {
            "schema": RECEIPT_LIFECYCLE_SCHEMA,
            "terminal": True,
            "authorization": "none",
            "replay": "denied",
            "host_actions_executed": bool(validated),
            "further_execution": "none",
        },
    }
    body["receipt_sha256"] = _sha256(body)
    return _receipt_validation(body, [])


def verify_receipt(frontend, receipt, plan, results_by_step, public_key_value):
    expected = build_receipt(frontend, plan, results_by_step, public_key_value)
    if not expected["valid"]:
        return expected
    if not isinstance(receipt, dict):
        return _receipt_validation(None, [_finding("receipt", "expected-object", "receipt must be an object")])
    expected_keys = {"schema", "plan_sha256", "outcomes", "summary", "lifecycle", "receipt_sha256"}
    findings = _closed(receipt, "receipt", expected_keys)
    if receipt != expected["receipt"]:
        findings.append(_finding("receipt", "receipt-mismatch", "receipt does not match the exact plan and terminal Results"))
    return _receipt_validation(receipt, findings)
