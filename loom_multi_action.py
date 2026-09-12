"""Closed, non-authorizing composition and replay for Action Capsule DAGs."""

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
STATE_SCHEMA = "loom-multi-action-execution-state/v0"
STATE_VALIDATION_SCHEMA = "loom-multi-action-execution-state-validation/v0"
STEP_STATE_SCHEMA = "loom-multi-action-step-state/v0"
EVENT_SCHEMA = "loom-multi-action-execution-event/v0"
RESULT_EVIDENCE_SCHEMA = "loom-multi-action-result-evidence/v0"
TRANSITION_LINK_SCHEMA = "loom-multi-action-transition-link/v0"
DEPENDENCY_EVIDENCE_SCHEMA = "loom-multi-action-dependency-evidence/v0"
STATE_LIFECYCLE_SCHEMA = "loom-multi-action-execution-lifecycle/v0"

MAX_STEPS = 64
MAX_DEPENDENCIES_PER_STEP = 64
MAX_EVENTS = MAX_STEPS * 3
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


def _state_validation(state, findings):
    return {
        "schema": STATE_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "none",
        "state": state if not findings else None,
        "state_sha256": state.get("state_sha256") if not findings else None,
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


def _finish_state(state):
    by_id = {item["step_id"]: item for item in state["steps"]}
    for name, status in (
        ("ready", "ready"), ("running", "running"),
        ("completed", "completed"), ("failed", "failed"),
        ("skipped", "skipped"),
    ):
        state[name] = sorted(step_id for step_id, item in by_id.items() if item["state"] == status)
    state["revision"] = len(state["events"])
    state["event_chain_sha256"] = (
        state["events"][-1]["event_sha256"] if state["events"]
        else _sha256({"schema": EVENT_SCHEMA, "plan_sha256": state["plan_sha256"], "events": []})
    )
    state["lifecycle"] = {
        "schema": STATE_LIFECYCLE_SCHEMA,
        "terminal": not state["ready"] and not state["running"] and not any(
            item["state"] == "blocked" for item in state["steps"]
        ),
        "authorization": "none",
        "accepts": "verified-action-result-only",
        "host_actions_executed_by_state_machine": False,
        "replay": "denied",
    }
    state["state_sha256"] = _sha256({
        key: value for key, value in state.items() if key != "state_sha256"
    })
    return state


def _initial_state(plan):
    steps = []
    for step in plan["steps"]:
        blocked_by = list(step["depends_on"])
        steps.append({
            "schema": STEP_STATE_SCHEMA,
            "step_id": step["id"],
            "capsule_sha256": step["capsule_sha256"],
            "approval_boundary_sha256": step["approval_boundary"]["boundary_sha256"],
            "state": "blocked" if blocked_by else "ready",
            "blocked_by": blocked_by,
            "execution_sha256": None,
            "result_sha256": None,
            "started_at_unix_ms": None,
            "finalized_at_unix_ms": None,
            "last_event_sha256": None,
        })
    return _finish_state({
        "schema": STATE_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "revision": 0,
        "steps": steps,
        "ready": [],
        "running": [],
        "completed": [],
        "failed": [],
        "skipped": [],
        "events": [],
        "event_chain_sha256": "",
        "lifecycle": {},
    })


def _append_event(state, step, kind, from_state, to_state, at_unix_ms, evidence):
    event = {
        "schema": EVENT_SCHEMA,
        "index": len(state["events"]),
        "kind": kind,
        "step_id": step["step_id"],
        "from_state": from_state,
        "to_state": to_state,
        "at_unix_ms": at_unix_ms,
        "previous_event_sha256": state["event_chain_sha256"],
        "evidence": evidence,
    }
    event["event_sha256"] = _sha256(event)
    state["events"].append(event)
    state["event_chain_sha256"] = event["event_sha256"]
    step["state"] = to_state
    step["last_event_sha256"] = event["event_sha256"]
    return event


def _dependency_evidence(step_map, dependency_ids, trigger_event_sha256):
    return {
        "schema": DEPENDENCY_EVIDENCE_SCHEMA,
        "dependencies": [{
            "step_id": dependency,
            "state": step_map[dependency]["state"],
            "last_event_sha256": step_map[dependency]["last_event_sha256"],
        } for dependency in dependency_ids],
        "trigger_event_sha256": trigger_event_sha256,
    }


def _refresh_dependencies(state, plan, at_unix_ms, trigger_event_sha256):
    step_map = {item["step_id"]: item for item in state["steps"]}
    plan_steps = {item["id"]: item for item in plan["steps"]}
    order = _topological_order(
        sorted(plan_steps), {step_id: item["depends_on"] for step_id, item in plan_steps.items()},
    )
    for step_id in order:
        current = step_map[step_id]
        if current["state"] != "blocked":
            continue
        dependencies = plan_steps[step_id]["depends_on"]
        failed = [
            dependency for dependency in dependencies
            if step_map[dependency]["state"] in {"failed", "skipped"}
        ]
        if failed:
            current["blocked_by"] = failed
            event = _append_event(
                state, current, "dependency-skipped", "blocked", "skipped",
                at_unix_ms, _dependency_evidence(step_map, dependencies, trigger_event_sha256),
            )
            current["finalized_at_unix_ms"] = at_unix_ms
            trigger_event_sha256 = event["event_sha256"]
        elif all(step_map[dependency]["state"] == "completed" for dependency in dependencies):
            current["blocked_by"] = []
            event = _append_event(
                state, current, "dependency-satisfied", "blocked", "ready",
                at_unix_ms, _dependency_evidence(step_map, dependencies, trigger_event_sha256),
            )
            trigger_event_sha256 = event["event_sha256"]


def build_execution_state(frontend, plan):
    """Build the deterministic zero-result state for one validated plan."""
    plan_check = validate_plan(frontend, plan)
    if not plan_check["valid"]:
        return _state_validation(None, _prefixed("plan", plan_check["findings"]))
    return _state_validation(_initial_state(plan), [])


def _result_events(state):
    results = []
    events = state.get("events") if isinstance(state, dict) else None
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        return results
    for event in events:
        if not isinstance(event, dict) or event.get("kind") != "execution-observed":
            continue
        evidence = event.get("evidence")
        if isinstance(evidence, dict) and evidence.get("schema") == RESULT_EVIDENCE_SCHEMA:
            results.append((event.get("step_id"), evidence.get("result")))
    return results


def _ingest_result(frontend, state, plan, step_id, result, public_key_value):
    step_map = {item["step_id"]: item for item in state["steps"]}
    if step_id not in step_map:
        return None, [_finding("step_id", "unknown-step", "step does not belong to this plan")]
    step = step_map[step_id]
    if step["state"] != "ready":
        return None, [_finding("step_id", "invalid-state-transition", "only a ready step can accept a terminal Result")]
    result_check = frontend.validate_result(result, public_key_value)
    if not result_check["valid"]:
        return None, _prefixed("result", result_check["findings"])
    plan_step = next(item for item in plan["steps"] if item["id"] == step_id)
    if result["request"]["binding"]["capsule_sha256"] != plan_step["capsule_sha256"]:
        return None, [_finding("result", "capsule-result-mismatch", "Result does not bind this plan step's Action Capsule")]
    existing = [item for _, item in _result_events(state)]
    if any(item["result_sha256"] == result["result_sha256"] for item in existing):
        return None, [_finding("result.result_sha256", "reused-result", "one Result cannot advance multiple plan steps")]
    if any(item["approval_sha256"] == result["approval_sha256"] for item in existing):
        return None, [_finding("result.approval_sha256", "reused-approval", "each plan step requires a distinct Action Approval")]
    for dependency in plan_step["depends_on"]:
        parent = step_map[dependency]
        if parent["state"] != "completed":
            return None, [_finding("step_id", "dependency-not-completed", "all dependencies must complete successfully before execution")]
        if parent["finalized_at_unix_ms"] > result["execution"]["executed_at_unix_ms"]:
            return None, [_finding("result.execution.executed_at_unix_ms", "dependency-order-violation", "step execution predates dependency finalization")]

    next_state = json.loads(_canonical(state))
    next_step = next(item for item in next_state["steps"] if item["step_id"] == step_id)
    execution = result["execution"]
    execution_event = _append_event(
        next_state, next_step, "execution-observed", "ready", "running",
        execution["executed_at_unix_ms"], {
            "schema": RESULT_EVIDENCE_SCHEMA,
            "approval_boundary_sha256": next_step["approval_boundary_sha256"],
            "result": result,
        },
    )
    next_step["blocked_by"] = []
    next_step["execution_sha256"] = result["execution_sha256"]
    next_step["result_sha256"] = result["result_sha256"]
    next_step["started_at_unix_ms"] = execution["executed_at_unix_ms"]
    successful = _terminal_success(result)
    final_state = "completed" if successful else "failed"
    final_event = _append_event(
        next_state, next_step, "result-finalized", "running", final_state,
        result["finalized_at_unix_ms"], {
            "schema": TRANSITION_LINK_SCHEMA,
            "source_event_sha256": execution_event["event_sha256"],
            "execution_sha256": result["execution_sha256"],
            "result_sha256": result["result_sha256"],
        },
    )
    next_step["finalized_at_unix_ms"] = result["finalized_at_unix_ms"]
    _refresh_dependencies(
        next_state, plan, result["finalized_at_unix_ms"], final_event["event_sha256"],
    )
    return _finish_state(next_state), []


def verify_execution_state(frontend, state, plan, public_key_value):
    outer_keys = {
        "schema", "plan_sha256", "revision", "steps", "ready", "running",
        "completed", "failed", "skipped", "events", "event_chain_sha256",
        "lifecycle", "state_sha256",
    }
    findings = _closed(state, "state", outer_keys)
    plan_check = validate_plan(frontend, plan)
    if not plan_check["valid"]:
        findings.extend(_prefixed("plan", plan_check["findings"]))
    if not isinstance(state, dict) or not plan_check["valid"]:
        return _state_validation(None, findings)
    if state.get("schema") != STATE_SCHEMA:
        findings.append(_finding("state.schema", "unsupported-schema", "expected " + STATE_SCHEMA))
    if state.get("plan_sha256") != plan["plan_sha256"]:
        findings.append(_finding("state.plan_sha256", "plan-mismatch", "state does not bind this plan"))
    events = state.get("events")
    if not isinstance(events, list):
        findings.append(_finding("state.events", "expected-array", "events must be an array"))
    elif len(events) > MAX_EVENTS:
        findings.append(_finding("state.events", "event-limit", "an execution state may contain at most 192 events"))
    if not _is_sha256(state.get("state_sha256")):
        findings.append(_finding("state.state_sha256", "expected-sha256", "state_sha256 must be lowercase SHA-256"))
    else:
        try:
            expected_hash = _sha256({key: value for key, value in state.items() if key != "state_sha256"})
        except (TypeError, ValueError):
            expected_hash = None
            findings.append(_finding("state", "non-canonical-state", "state must contain canonical JSON values"))
        if expected_hash is not None and state["state_sha256"] != expected_hash:
            findings.append(_finding("state.state_sha256", "state-hash-mismatch", "state hash does not match its canonical body"))

    expected = _initial_state(plan)
    for index, (event_step_id, result) in enumerate(_result_events(state)):
        expected, replay_findings = _ingest_result(
            frontend, expected, plan, event_step_id, result, public_key_value,
        )
        if replay_findings:
            findings.extend(_prefixed(f"state.events[{index}]", replay_findings))
            break
    if expected is not None and state != expected:
        findings.append(_finding("state", "state-mismatch", "state is not the exact deterministic replay of its verified Results"))
    return _state_validation(state, findings)


def ingest_execution_result(frontend, state, plan, step_id, result, public_key_value):
    """Advance one ready step from a complete signed Result; never execute it."""
    state_check = verify_execution_state(frontend, state, plan, public_key_value)
    if not state_check["valid"]:
        return _state_validation(None, _prefixed("state", state_check["findings"]))
    next_state, findings = _ingest_result(
        frontend, state, plan, step_id, result, public_key_value,
    )
    return _state_validation(next_state, findings)
