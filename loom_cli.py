#!/usr/bin/env python3
"""CLI orchestration and structured verdicts for the LOOM kernel."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import loom_approval as _loom_approval
import loom_executor as _loom_executor
import loom_gate as _loom_gate
from loom_frontend import CliFrontend as _CliFrontend


class Frontend(_CliFrontend):
    __slots__ = ()


_COMMANDS = (
    "about",
    "release-check",
    "help",
    "examples",
    "check",
    "run",
    "build",
    "audit",
    "source-map",
    "gate",
    "gate-workflow",
    "gate-request",
    "gate-claim",
    "gate-finish",
    "gate-plan",
    "gate-exec-finish",
    "gate-attempt",
    "gate-process-attempt",
    "gate-process-finish",
)

_EXAMPLES = (
    {
        "path": "examples/first.loom",
        "title": "smallest pure program",
        "purpose": "proves and runs a pure main that returns 42",
        "check": "python3 -m loom check examples/first.loom",
        "run": "python3 -m loom run examples/first.loom",
    },
    {
        "path": "examples/trust.loom",
        "title": "trust gate",
        "purpose": "shows why AI-only trust is circular unless independent anchors vouch",
        "check": "python3 -m loom check examples/trust.loom",
        "run": "python3 -m loom run examples/trust.loom",
    },
    {
        "path": "examples/demo.loom",
        "title": "effects and capability seams",
        "purpose": "demonstrates checked effects, capability seams, and honest declarations",
        "check": "python3 -m loom check examples/demo.loom",
        "run": "python3 -m loom run examples/demo.loom",
    },
    {
        "path": "examples/flagship.loom",
        "title": "flagship proof sketch",
        "purpose": "larger public example for the trust-layer story",
        "check": "python3 -m loom check examples/flagship.loom",
        "run": "python3 -m loom run examples/flagship.loom",
    },
)


def _usage():
    return (
        "usage: python3 loom.py <"
        + "|".join(_COMMANDS)
        + "> FILE... [call] [--target py|js|wat] [--format text|json] [--nonce HEX64] [--dry-run]"
    )


def _help(frontend, topic=None):
    about = build_about(frontend)
    if topic == "quickstart":
        print("LOOM quickstart")
        print("1. Inspect the local build:")
        print("   python3 -m loom about --format json")
        print("2. Check and run the smallest honest program:")
        print("   python3 -m loom check examples/first.loom")
        print("   python3 -m loom run examples/first.loom")
        print("3. Verify the checkout:")
        print("   python3 -m loom release-check")
        print("4. See the trust gate:")
        print("   python3 -m loom check examples/trust.loom")
        print("   python3 -m loom run examples/trust.loom")
        print("5. Discover bundled examples:")
        print("   python3 -m loom examples")
        print("Docs: docs/quickstart.md")
        return 0
    if topic and topic not in ("commands",):
        print("unknown help topic: " + topic)
        print("try: python3 loom.py help quickstart")
        return 2
    print("LOOM — trust layer for AI-written code")
    print(f"citadel: {about['citadel_checks']} self-verifying checks")
    print("")
    print("Start here:")
    print("  python3 -m loom help quickstart")
    print("  python3 -m loom check examples/first.loom")
    print("  python3 -m loom run examples/first.loom")
    print("  python3 -m loom examples")
    print("  python3 -m loom release-check")
    print("")
    print("Core commands:")
    print("  about                 machine-readable capability/canon summary")
    print("  check FILE            prove every effect declaration is honest")
    print("  run FILE [call]       check, then run a function call; default is (main)")
    print("  build FILE            compile checked code; use --target py|js|wat")
    print("  audit FILE            show declared-vs-performed capability surface")
    print("  source-map FILE       show WAT heap allocation source locations")
    print("  examples              list bundled example programs and runnable commands")
    print("  release-check         run the public verification checklist")
    print("")
    print("Gate commands:")
    print("  gate, gate-workflow, gate-request, gate-claim, gate-finish")
    print("  gate-plan, gate-exec-finish, gate-attempt, gate-process-attempt, gate-process-finish")
    print("")
    print(_usage())
    return 0


def _parse_flags(argv):
    flags, pos, index = {}, [], 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--target" and index + 1 < len(argv):
            flags["target"] = argv[index + 1]
            index += 2
        elif arg.startswith("--target="):
            flags["target"] = arg.split("=", 1)[1]
            index += 1
        elif arg == "--format" and index + 1 < len(argv):
            flags["format"] = argv[index + 1]
            index += 2
        elif arg.startswith("--format="):
            flags["format"] = arg.split("=", 1)[1]
            index += 1
        elif arg == "--nonce" and index + 1 < len(argv):
            flags["nonce"] = argv[index + 1]
            index += 2
        elif arg.startswith("--nonce="):
            flags["nonce"] = arg.split("=", 1)[1]
            index += 1
        elif arg == "--dry-run":
            flags["dry_run"] = True
            index += 1
        else:
            pos.append(arg)
            index += 1
    return flags, pos


def _partition_findings(fns, errs):
    findings, global_findings = {}, []
    for err in errs:
        key = err.split(": ", 1)[0]
        if key in fns:
            findings.setdefault(key, []).append(err)
        else:
            global_findings.append(err)
    return findings, global_findings


def build_verdict(frontend, src):
    """Return the deterministic, JSON-safe checker verdict used by Gate clients."""
    try:
        fns, errs = frontend.check(frontend.parse(src))
    except frontend.error as err:
        fns, errs = {}, ["parse: " + str(err)]
    findings, global_findings = _partition_findings(fns, errs)
    sensitive = {"Net", "IO", "FFI", "Alloc", "Rand"}
    functions = []
    for name, info in fns.items():
        declared = set(info["decl"])
        performed = set(info["eff"]) - {"?"}
        own_findings = findings.get(name, [])
        lies = bool(own_findings) or bool(performed - declared) or ("?" in info["eff"]) or bool(set(info.get("req", set())) - performed)
        capabilities = sorted(performed & sensitive)
        functions.append({
            "name": name,
            "declared_effects": sorted(declared),
            "performed_effects": sorted(performed),
            "required_effects": sorted(info.get("req", set())),
            "capabilities": capabilities,
            "status": "lie" if lies else ("review" if capabilities else "clean"),
            "findings": list(own_findings),
        })
    return {
        "schema": "loom-verdict/v1",
        "verdict": "reject" if errs else "accept",
        "advisory": True,
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "function_count": len(functions),
        "functions": functions,
        "global_findings": list(global_findings),
        "finding_count": len(errs),
    }


def _emit_json(verdict):
    print(json.dumps(verdict, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def build_about(frontend):
    meta = getattr(frontend, "metadata", {}) or {}
    return {
        "schema": "loom-about/v1",
        "language": "LOOM",
        "citadel_checks": meta.get("citadel_checks"),
        "wasm_abi_version": meta.get("wasm_abi_version"),
        "i31_bits": meta.get("i31_bits"),
        "backends": list(meta.get("backends", [])),
        "commands": list(meta.get("commands", [])),
    }


def _about(frontend, output_format="text"):
    about = build_about(frontend)
    if output_format == "json":
        _emit_json(about)
        return 0
    print("LOOM — trust layer for AI-written code")
    print(f"citadel: {about['citadel_checks']} self-verifying checks")
    print(f"WASM ABI: v{about['wasm_abi_version']}")
    print(f"i31: {about['i31_bits']} bit signed wraparound")
    print("backends: " + ", ".join(about["backends"]))
    return 0


def build_examples():
    return {
        "schema": "loom-examples/v1",
        "examples": [dict(item) for item in _EXAMPLES],
    }


def _examples(output_format="text"):
    payload = build_examples()
    if output_format == "json":
        _emit_json(payload)
        return 0
    print("LOOM examples")
    for item in payload["examples"]:
        print(f"- {item['path']} — {item['title']}")
        print(f"  {item['purpose']}")
        print(f"  check: {item['check']}")
        print(f"  run:   {item['run']}")
    return 0


_RELEASE_CHECK_STEPS = (
    ("citadel", ("python3", "run_tests.py")),
    ("docs-parity", ("python3", "verify_docs_parity.py")),
    ("fuzz", ("python3", "fuzz_tests.py", "--cases", "256", "--seed", "0xBADC0DE")),
    ("about", ("python3", "loom.py", "about", "--format", "json")),
)


def _summarize_output(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1][:240]


def _release_check(frontend, output_format="text", dry_run=False):
    del frontend
    root = Path(__file__).resolve().parent
    steps = []
    ok = True
    for step_id, command in _RELEASE_CHECK_STEPS:
        item = {
            "id": step_id,
            "command": list(command),
            "returncode": None,
            "summary": "planned",
        }
        if dry_run:
            steps.append(item)
            continue
        run_command = [sys.executable if part == "python3" else part for part in command]
        proc = subprocess.run(run_command, cwd=str(root), capture_output=True, text=True)
        item.update({
            "returncode": proc.returncode,
            "summary": _summarize_output(proc.stdout) or _summarize_output(proc.stderr),
        })
        if proc.returncode != 0:
            ok = False
            item["stderr_tail"] = _summarize_output(proc.stderr)
            item["stdout_tail"] = _summarize_output(proc.stdout)
        steps.append(item)
    result = {
        "schema": "loom-release-check/v1",
        "ok": ok,
        "dry_run": bool(dry_run),
        "steps": steps,
    }
    if output_format == "json":
        _emit_json(result)
        return 0 if ok else 1
    print("LOOM release check" + (" (dry run)" if dry_run else ""))
    for item in steps:
        status = "PLAN" if dry_run else ("PASS" if item["returncode"] == 0 else "FAIL")
        print(f"{status} {item['id']}: " + " ".join(item["command"]))
        if item["summary"] and item["summary"] != "planned":
            print("  " + item["summary"])
    print("PASS release-check" if ok else "FAIL release-check")
    return 0 if ok else 1


def _gate(frontend, src, output_format="text"):
    del frontend
    try:
        manifest = json.loads(src)
    except json.JSONDecodeError as err:
        print("invalid Gate manifest JSON: " + str(err))
        return 2
    diagnostics = _loom_gate.build_gate_diagnostics(manifest)
    if output_format == "json":
        _emit_json(diagnostics)
        return 1 if diagnostics["decision"] == "reject" else 0
    print("LOOM GATE - redacted advisory manifest diagnostics")
    print("decision: " + diagnostics["decision"])
    if diagnostics["secret_lanes"]:
        print("secret lanes:")
        for item in diagnostics["secret_lanes"]:
            print(f"  [{item['disposition']}] {item['class']} at {item['field']} ({item['code']})")
    else:
        print("secret lanes: none")
    return 1 if diagnostics["decision"] == "reject" else 0


def build_gate_workflow(manifest):
    validation = _loom_gate.validate_manifest(manifest)
    workflow = {
        "schema": "loom-gate-workflow/v1",
        "valid": validation["valid"],
        "advisory": False,
        "manifest_sha256": validation.get("manifest_sha256"),
        "decision": None,
        "task_summary": None,
        "agent": None,
        "actions": [],
        "steps": [],
        "findings": list(validation["findings"]),
    }
    if not validation["valid"]:
        workflow["steps"] = [{
            "id": "fix-manifest",
            "kind": "operator",
            "description": "Fix the manifest until LOOM Gate validation accepts it.",
        }]
        return workflow
    normalized = validation["normalized_manifest"]
    decision = _loom_gate.evaluate_manifest(normalized)
    diagnostics = _loom_gate.build_gate_diagnostics(normalized)
    workflow.update({
        "decision": decision["decision"],
        "task_summary": normalized["task"]["summary"],
        "agent": normalized["agent"],
        "actions": list(normalized["actions"]),
        "findings": list(decision["violations"]),
    })
    if decision["decision"] == "reject":
        workflow["steps"] = [{
            "id": "fix-policy",
            "kind": "operator",
            "description": "Resolve policy violations before requesting approval or execution.",
        }]
        return workflow
    if decision["decision"] == "accept":
        workflow["steps"] = [{
            "id": "collect-observation",
            "kind": "trusted-host",
            "description": "Run only the manifest-declared action, then collect observation evidence.",
        }]
        return workflow
    workflow["steps"] = [
        {
            "id": "approval-request",
            "kind": "operator",
            "description": "Build a nonce-bound approval request for the operator issuer.",
            "command": "python3 loom.py gate-request manifest.json --nonce <64-hex> --format json",
        },
        {
            "id": "claim",
            "kind": "trusted-host",
            "description": "Claim the signed approval before any bounded host action starts.",
            "command": "python3 loom.py gate-claim manifest.json challenge.json approval.json --format json",
        },
        {
            "id": "plan",
            "kind": "trusted-host",
            "description": "Build the bounded execution plan for the declared process action.",
            "command": "python3 loom.py gate-plan manifest.json challenge.json approval.json claim.json process --format json",
        },
        {
            "id": "attempt-dry-run",
            "kind": "trusted-host",
            "description": "Validate the trusted host attempt envelope against the plan without finalizing.",
            "command": "python3 loom.py gate-process-attempt plan.json attempt.json --format json",
        },
        {
            "id": "finish",
            "kind": "trusted-host",
            "description": "Finalize the claimed approval exactly once from the validated process attempt.",
            "command": "python3 loom.py gate-process-finish manifest.json challenge.json approval.json claim.json plan.json attempt.json --format json",
        },
    ]
    if diagnostics["secret_lanes"]:
        workflow["steps"].insert(1, {
            "id": "secret-lane-review",
            "kind": "operator",
            "description": "Review redacted secret-lane diagnostics; raw secret paths or values must stay hidden.",
        })
    return workflow


def _gate_workflow(frontend, src, output_format="text"):
    del frontend
    try:
        manifest = json.loads(src)
    except json.JSONDecodeError as err:
        print("invalid Gate manifest JSON: " + str(err))
        return 2
    workflow = build_gate_workflow(manifest)
    if output_format == "json":
        _emit_json(workflow)
        return 0 if workflow["valid"] and workflow["decision"] != "reject" else 1
    print("LOOM GATE WORKFLOW - bounded AI action route")
    print("decision: " + str(workflow["decision"]))
    if workflow["agent"]:
        print("agent: " + workflow["agent"]["id"] + " (" + workflow["agent"]["role"] + ")")
    if workflow["task_summary"]:
        print("task: " + workflow["task_summary"])
    if workflow["actions"]:
        print("requested actions: " + ", ".join(workflow["actions"]))
    step_ids = [step["id"] for step in workflow["steps"]]
    if not workflow["valid"]:
        print("allowed now: fix the manifest only")
        print("blocked until valid: approval, claim, plan, execution, finish")
        print("next safe step: " + workflow["steps"][0]["id"])
    elif workflow["decision"] == "reject":
        print("allowed now: fix policy violations only")
        print("blocked until policy accepts: approval, claim, plan, execution, finish")
        print("next safe step: " + workflow["steps"][0]["id"])
    elif workflow["decision"] == "accept":
        print("allowed now: manifest-declared action only")
        print("blocked always: anything outside declared actions and paths")
        print("next safe step: " + workflow["steps"][0]["id"])
    else:
        print("allowed now: operator approval request only")
        print("blocked until approval: " + ", ".join(step_ids[1:]))
        print("next safe step: " + workflow["steps"][0]["id"])
    print("safety: this command explains the route; it does not execute shell/network/tools")
    for step in workflow["steps"]:
        print(f"  {step['id']}: {step['description']}")
        if "command" in step:
            print("    " + step["command"])
    return 0 if workflow["valid"] and workflow["decision"] != "reject" else 1


def _gate_request(frontend, src, nonce, output_format="text"):
    del frontend
    if not nonce:
        print("gate-request requires --nonce 64 lowercase hex characters")
        return 2
    try:
        manifest = json.loads(src)
    except json.JSONDecodeError as err:
        print("invalid Gate manifest JSON: " + str(err))
        return 2
    challenge = _loom_approval.build_approval_challenge(manifest, nonce)
    if not challenge["valid"]:
        if output_format == "json":
            _emit_json(challenge)
        else:
            print("LOOM GATE REQUEST - challenge refused")
            for item in challenge["findings"]:
                print(f"  [{item['code']}] {item['path']}: {item['message']}")
        return 1
    request = _loom_approval.build_approval_request(manifest, challenge["challenge"])
    if output_format == "json":
        _emit_json(request)
        return 0 if request["valid"] else 1
    if not request["valid"]:
        print("LOOM GATE REQUEST - refused")
        for item in request["findings"]:
            print(f"  [{item['code']}] {item['path']}: {item['message']}")
        return 1
    body = request["request"]
    print("LOOM GATE REQUEST - operator approval envelope")
    print("request_sha256: " + body["request_sha256"])
    print("challenge_sha256: " + body["challenge"]["challenge_sha256"])
    print("manifest_sha256: " + body["challenge"]["manifest_sha256"])
    print("policy_decision: " + body["challenge"]["policy_decision"])
    print("policy_reasons:")
    for item in body["policy_reasons"]:
        print(f"  [{item['code']}] {item['path']}: {item['message']}")
    return 0


def _load_json_file(path, label):
    try:
        return json.loads(Path(path).read_text()), None
    except OSError as err:
        return None, f"cannot read {label}: {err}"
    except json.JSONDecodeError as err:
        return None, f"invalid {label} JSON: {err}"


def _emit_validation_result(result, success_key, title, output_format):
    if output_format == "json":
        _emit_json(result)
        return 0 if result["valid"] else 1
    if not result["valid"]:
        print(title + " - refused")
        for item in result["findings"]:
            print(f"  [{item['code']}] {item['path']}: {item['message']}")
        return 1
    body = result[success_key]
    print(title)
    if success_key == "claim":
        print("claim_sha256: " + body["claim_sha256"])
        print("approval_sha256: " + body["approval_sha256"])
        print("manifest_sha256: " + body["manifest_sha256"])
        print("challenge_sha256: " + body["challenge_sha256"])
        print("status: " + body["status"])
    elif success_key == "plan":
        print("plan_sha256: " + body["plan_sha256"])
        print("claim_sha256: " + body["claim_sha256"])
        print("executor_boundary: " + body["executor_boundary"])
        print("actions_allowed: " + ", ".join(body["actions_allowed"]))
    elif success_key == "attempt":
        print("schema: " + body["schema"])
        print("result: " + body["result"])
        print("evidence_count: " + str(len(body["evidence"])))
    else:
        print("receipt_sha256: " + body["receipt_sha256"])
        print("policy_decision: " + body["policy_decision"])
        print("result: " + body["result"])
    return 0


def _gate_claim(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 3:
        print("usage: python3 loom.py gate-claim MANIFEST CHALLENGE APPROVAL [--format text|json]")
        return 2
    manifest, error = _load_json_file(paths[0], "Gate manifest")
    if error: print(error); return 2
    challenge, error = _load_json_file(paths[1], "Gate challenge")
    if error: print(error); return 2
    approval, error = _load_json_file(paths[2], "operator approval")
    if error: print(error); return 2
    result = _loom_approval.claim_operator_approval(manifest, challenge, approval)
    return _emit_validation_result(result, "claim", "LOOM GATE CLAIM - approval claimed for execution", output_format)


def _gate_finish(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 5:
        print("usage: python3 loom.py gate-finish MANIFEST OBSERVATION CHALLENGE APPROVAL CLAIM [--format text|json]")
        return 2
    manifest, error = _load_json_file(paths[0], "Gate manifest")
    if error: print(error); return 2
    observation, error = _load_json_file(paths[1], "Gate observation")
    if error: print(error); return 2
    challenge, error = _load_json_file(paths[2], "Gate challenge")
    if error: print(error); return 2
    approval, error = _load_json_file(paths[3], "operator approval")
    if error: print(error); return 2
    claim, error = _load_json_file(paths[4], "Gate claim")
    if error: print(error); return 2
    result = _loom_approval.finish_claimed_receipt(manifest, observation, challenge, approval, claim)
    return _emit_validation_result(result, "receipt", "LOOM GATE FINISH - claimed execution finalized", output_format)


def _gate_plan(frontend, paths, output_format="text"):
    del frontend
    if len(paths) < 5:
        print("usage: python3 loom.py gate-plan MANIFEST CHALLENGE APPROVAL CLAIM ACTION... [--format text|json]")
        return 2
    manifest, error = _load_json_file(paths[0], "Gate manifest")
    if error: print(error); return 2
    challenge, error = _load_json_file(paths[1], "Gate challenge")
    if error: print(error); return 2
    approval, error = _load_json_file(paths[2], "operator approval")
    if error: print(error); return 2
    claim, error = _load_json_file(paths[3], "Gate claim")
    if error: print(error); return 2
    result = _loom_executor.plan_claimed_execution(manifest, challenge, approval, claim, paths[4:])
    return _emit_validation_result(result, "plan", "LOOM GATE PLAN - bounded execution plan", output_format)


def _gate_exec_finish(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 8:
        print("usage: python3 loom.py gate-exec-finish MANIFEST CHALLENGE APPROVAL CLAIM PLAN RESULT ACTIONS_JSON EVIDENCE_JSON [--format text|json]")
        return 2
    manifest, error = _load_json_file(paths[0], "Gate manifest")
    if error: print(error); return 2
    challenge, error = _load_json_file(paths[1], "Gate challenge")
    if error: print(error); return 2
    approval, error = _load_json_file(paths[2], "operator approval")
    if error: print(error); return 2
    claim, error = _load_json_file(paths[3], "Gate claim")
    if error: print(error); return 2
    plan, error = _load_json_file(paths[4], "Gate execution plan")
    if error: print(error); return 2
    actions_observed, error = _load_json_file(paths[6], "observed actions")
    if error: print(error); return 2
    evidence, error = _load_json_file(paths[7], "Gate evidence")
    if error: print(error); return 2
    result = _loom_executor.finish_claimed_execution(manifest, challenge, approval, claim, plan, paths[5], actions_observed, evidence)
    return _emit_validation_result(result, "receipt", "LOOM GATE EXEC FINISH - bounded execution finalized", output_format)


def _gate_attempt(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 1:
        print("usage: python3 loom.py gate-attempt ATTEMPT_JSON [--format text|json]")
        return 2
    attempt, error = _load_json_file(paths[0], "Gate host attempt")
    if error: print(error); return 2
    result = _loom_executor.validate_host_attempt(attempt)
    return _emit_validation_result(result, "attempt", "LOOM GATE ATTEMPT - host attempt dry-run validated", output_format)


def _gate_process_attempt(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 2:
        print("usage: python3 loom.py gate-process-attempt PLAN_JSON ATTEMPT_JSON [--format text|json]")
        return 2
    plan, error = _load_json_file(paths[0], "Gate execution plan")
    if error: print(error); return 2
    attempt, error = _load_json_file(paths[1], "Gate host attempt")
    if error: print(error); return 2
    result = _loom_executor.validate_process_attempt(plan, attempt)
    return _emit_validation_result(result, "attempt", "LOOM GATE PROCESS ATTEMPT - plan/attempt dry-run validated", output_format)


def _gate_process_finish(frontend, paths, output_format="text"):
    del frontend
    if len(paths) != 6:
        print("usage: python3 loom.py gate-process-finish MANIFEST CHALLENGE APPROVAL CLAIM PLAN ATTEMPT [--format text|json]")
        return 2
    manifest, error = _load_json_file(paths[0], "Gate manifest")
    if error: print(error); return 2
    challenge, error = _load_json_file(paths[1], "Gate challenge")
    if error: print(error); return 2
    approval, error = _load_json_file(paths[2], "operator approval")
    if error: print(error); return 2
    claim, error = _load_json_file(paths[3], "Gate claim")
    if error: print(error); return 2
    plan, error = _load_json_file(paths[4], "Gate execution plan")
    if error: print(error); return 2
    attempt, error = _load_json_file(paths[5], "Gate host attempt")
    if error: print(error); return 2
    result = _loom_executor.finish_process_attempt(manifest, challenge, approval, claim, plan, attempt)
    return _emit_validation_result(result, "receipt", "LOOM GATE PROCESS FINISH - process attempt finalized", output_format)


def allocation_source_map_lines(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    if not rows:
        return ["allocation source map: no heap allocation sites"]
    return ["allocation source map"] + [f"  {line}:{column}  {label}" for line, column, label in rows]


def allocation_source_map_entries(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    return [{"line": line, "column": column, "label": label} for line, column, label in rows]


def build_source_map_verdict(frontend, src):
    """Return the deterministic JSON-safe WAT allocation source-map verdict."""
    try:
        allocations = allocation_source_map_entries(frontend.emit_wat(src))
    except frontend.error as err:
        return {
            "schema": "loom-source-map/v1",
            "verdict": "reject",
            "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
            "allocation_count": 0,
            "allocations": [],
            "error": str(err),
        }
    return {
        "schema": "loom-source-map/v1",
        "verdict": "accept",
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "allocation_count": len(allocations),
        "allocations": allocations,
    }


def _audit(frontend, src, output_format="text"):
    verdict = build_verdict(frontend, src)
    if output_format == "json":
        _emit_json(verdict)
        return 1 if verdict["verdict"] == "reject" else 0
    print("LOOM AUDIT - capability surface of AI-written code (DECLARED vs actually PERFORMED)")
    for item in verdict["functions"]:
        tag = {"lie": "LIE   ", "review": "REVIEW", "clean": "clean "}[item["status"]]
        declared_text = " ".join(item["declared_effects"]) or "Pure"
        performed_text = " ".join(item["performed_effects"]) or "Pure"
        extra = ("  <- holds: " + ", ".join(item["capabilities"])) if (item["capabilities"] and item["status"] != "lie") else ""
        print(f"  [{tag}] {item['name']}: declared ({declared_text}) | performs ({performed_text}){extra}")
        for err in item["findings"]:
            print("           ! " + err)
    if verdict["finding_count"]:
        print(f"-- FINDINGS ({verdict['finding_count']}), every violation verbatim:")
        for item in verdict["functions"]:
            for err in item["findings"]:
                print("   ! " + err)
        for err in verdict["global_findings"]:
            print("   ! " + err)
        if verdict["global_findings"]:
            print("-- global findings:")
            for err in verdict["global_findings"]:
                print("   ! " + err)
    else:
        print("-- no violations; review every non-Pure capability above")
    return 1 if verdict["verdict"] == "reject" else 0


def _check(frontend, src, output_format="text"):
    verdict = build_verdict(frontend, src)
    if output_format == "json":
        _emit_json(verdict)
        return 1 if verdict["verdict"] == "reject" else 0
    if verdict["verdict"] == "accept":
        print(f"OK — checked, all effects honest ({verdict['function_count']} function(s))")
        return 0
    touched = sum(bool(item["findings"]) for item in verdict["functions"]) + (1 if verdict["global_findings"] else 0)
    print(f"REJECTED — {verdict['finding_count']} finding(s) across {touched} scope(s)")
    for item in verdict["functions"]:
        if not item["findings"]:
            continue
        print(f"  [{item['name']}] {len(item['findings'])} finding(s)")
        for err in item["findings"]:
            print("    - " + err)
    if verdict["global_findings"]:
        print(f"  [global] {len(verdict['global_findings'])} finding(s)")
        for err in verdict["global_findings"]:
            print("    - " + err)
    return 1


def cli(argv, frontend):
    flags, pos = _parse_flags(argv)
    if len(pos) < 1:
        print(_usage())
        return 2
    cmd = pos[0]
    output_format = flags.get("format", "text")
    if output_format not in ("text", "json"):
        print("unsupported format: " + output_format)
        return 2
    if cmd in ("--help", "-h", "help"):
        return _help(frontend, pos[1] if len(pos) > 1 else None)
    if cmd == "about":
        return _about(frontend, output_format)
    if cmd == "examples":
        return _examples(output_format)
    if cmd == "release-check":
        return _release_check(frontend, output_format, bool(flags.get("dry_run")))
    if len(pos) < 2:
        print(_usage())
        return 2
    if cmd == "gate-claim":
        return _gate_claim(frontend, pos[1:], output_format)
    if cmd == "gate-finish":
        return _gate_finish(frontend, pos[1:], output_format)
    if cmd == "gate-plan":
        return _gate_plan(frontend, pos[1:], output_format)
    if cmd == "gate-exec-finish":
        return _gate_exec_finish(frontend, pos[1:], output_format)
    if cmd == "gate-attempt":
        return _gate_attempt(frontend, pos[1:], output_format)
    if cmd == "gate-process-attempt":
        return _gate_process_attempt(frontend, pos[1:], output_format)
    if cmd == "gate-process-finish":
        return _gate_process_finish(frontend, pos[1:], output_format)
    path = pos[1]
    call = pos[2] if len(pos) > 2 else "(main)"
    try:
        src = Path(path).read_text()
    except OSError as err:
        print("cannot read file: " + str(err))
        return 2
    if cmd == "check":
        return _check(frontend, src, output_format)
    if cmd == "gate":
        return _gate(frontend, src, output_format)
    if cmd == "gate-workflow":
        return _gate_workflow(frontend, src, output_format)
    if cmd == "gate-request":
        return _gate_request(frontend, src, flags.get("nonce"), output_format)
    if cmd == "run":
        try:
            value, out = frontend.run_call(src, call)
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        for line in out:
            print(line)
        print("=> " + repr(value))
        return 0
    if cmd == "build":
        target = flags.get("target", "py")
        try:
            print(frontend.emit_wat(src) if target == "wat" else (frontend.compile_js(src) if target == "js" else frontend.compile_py(src)))
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        return 0
    if cmd == "source-map":
        if output_format == "json":
            verdict = build_source_map_verdict(frontend, src)
            _emit_json(verdict)
            return 1 if verdict["verdict"] == "reject" else 0
        try:
            lines = allocation_source_map_lines(frontend.emit_wat(src))
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        for line in lines:
            print(line)
        return 0
    if cmd == "audit":
        return _audit(frontend, src, output_format)
    print("unknown command: " + cmd)
    return 2
