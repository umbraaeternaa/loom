#!/usr/bin/env python3
"""Four-backend, non-authorizing policy receipts for LOOM's own work."""

from __future__ import annotations

import hashlib
import json
import re


VALIDATION_SCHEMA = "loom-dogfood-validation/v1"
RECEIPT_SCHEMA = "loom-dogfood-receipt/v1"
VALIDATION_SCHEMA_V2 = "loom-dogfood-validation/v2"
RECEIPT_SCHEMA_V2 = "loom-dogfood-receipt/v2"
REVIEW_REQUEST_SCHEMA = "loom-dogfood-review-request/v1"
REVIEW_REQUEST_VALIDATION_SCHEMA = "loom-dogfood-review-request-validation/v1"
REVIEW_SCHEMA = "loom-dogfood-review/v1"
REVIEW_VALIDATION_SCHEMA = "loom-dogfood-review-validation/v1"
MAX_SOURCE_BYTES = 256 * 1024
MAX_CALL_BYTES = 4096
MAX_REVIEW_REQUEST_BYTES = 1024 * 1024
MAX_CHANGED_FILES = 4096
I31_MIN = -(1 << 30)
I31_MAX = (1 << 30) - 1
BACKENDS = ("interpreter", "python", "javascript", "webassembly")
EVIDENCE_KINDS = ("citadel", "docs-parity", "fuzz", "git-sync", "syntax")
TEST_EVIDENCE_KINDS = ("citadel", "docs-parity", "fuzz", "syntax")
POLICY_SOURCE_SHA256 = "9d7396bd8eea80aeb3bca6df601e99b9c52662d834837127552669ffffa4d306"
_NONCE = re.compile(r"^[0-9a-f]{64}$")


class Frontend:
    __slots__ = (
        "parse", "build_verdict", "run_call", "run_compiled", "run_js",
        "run_wasm", "error", "collect_ci_evidence", "validate_manifest",
        "validate_observation", "load_public_key", "validate_public_key",
        "key_sha256", "rsa_verify",
    )

    def __init__(
        self, parse, build_verdict, run_call, run_compiled, run_js, run_wasm,
        error, collect_ci_evidence=None, validate_manifest=None,
        validate_observation=None, load_public_key=None,
        validate_public_key=None, key_sha256=None, rsa_verify=None,
    ):
        self.parse = parse
        self.build_verdict = build_verdict
        self.run_call = run_call
        self.run_compiled = run_compiled
        self.run_js = run_js
        self.run_wasm = run_wasm
        self.error = error
        self.collect_ci_evidence = collect_ci_evidence
        self.validate_manifest = validate_manifest
        self.validate_observation = validate_observation
        self.load_public_key = load_public_key
        self.validate_public_key = validate_public_key
        self.key_sha256 = key_sha256
        self.rsa_verify = rsa_verify


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _canonical_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def _validation(receipt=None, findings=()):
    valid = not findings
    accepted = bool(valid and receipt["decision"] == "accept")
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": valid,
        "accepted": accepted,
        "decision": receipt["decision"] if valid else "invalid",
        "advisory": True,
        "authorization": "none",
        "receipt": receipt if valid else None,
        "receipt_sha256": receipt["receipt_sha256"] if valid else None,
        "findings": list(findings),
    }


def _validation_v2(receipt=None, findings=()):
    valid = not findings
    accepted = bool(valid and receipt["decision"] == "accept")
    return {
        "schema": VALIDATION_SCHEMA_V2,
        "valid": valid,
        "accepted": accepted,
        "decision": receipt["decision"] if valid else "invalid",
        "advisory": True,
        "authorization": "none",
        "receipt": receipt if valid else None,
        "receipt_sha256": receipt["receipt_sha256"] if valid else None,
        "findings": list(findings),
    }


def _review_request_validation(request=None, findings=()):
    valid = not findings
    return {
        "schema": REVIEW_REQUEST_VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": True,
        "authorization": "none",
        "request": request if valid else None,
        "request_sha256": request["request_sha256"] if valid else None,
        "findings": list(findings),
    }


def _review_validation(evidence=None, findings=()):
    valid = not findings
    return {
        "schema": REVIEW_VALIDATION_SCHEMA,
        "valid": valid,
        "advisory": True,
        "authorization": "none",
        "evidence": evidence if valid else None,
        "findings": list(findings),
    }


def _closed_object(value, path, required):
    if not isinstance(value, dict):
        return [_finding(path, "expected-object", path + " must be an object")]
    findings = []
    for key in sorted(set(value) - set(required), key=str):
        findings.append(_finding(path + "." + str(key), "unknown-field", "unknown field"))
    for key in sorted(set(required) - set(value)):
        findings.append(_finding(path + "." + key, "missing-field", "missing required field"))
    return findings


def _evidence_frontend_findings(frontend):
    required = (
        "collect_ci_evidence", "validate_manifest", "validate_observation",
        "load_public_key", "validate_public_key", "key_sha256", "rsa_verify",
    )
    missing = [name for name in required if not callable(getattr(frontend, name, None))]
    return [
        _finding("frontend." + name, "evidence-adapter-unavailable", name + " is unavailable")
        for name in missing
    ]


def _json_value(value, path):
    if value is None or type(value) in {bool, int, str}:
        return value, []
    if isinstance(value, (list, tuple)):
        result = []
        for index, item in enumerate(value):
            normalized, findings = _json_value(item, f"{path}.{index}")
            if findings:
                return None, findings
            result.append(normalized)
        return result, []
    if isinstance(value, dict):
        if not all(type(key) is str for key in value):
            return None, [_finding(path, "non-json-result", "result object keys must be strings")]
        result = {}
        for key in sorted(value):
            normalized, findings = _json_value(value[key], f"{path}.{key}")
            if findings:
                return None, findings
            result[key] = normalized
        return result, []
    return None, [_finding(path, "non-json-result", "backend result is not a canonical JSON value")]


def _bounded_text(value, path, maximum):
    if type(value) is not str:
        return None, [_finding(path, "expected-text", path + " must be text")]
    try:
        payload = value.encode("utf-8", "strict")
    except UnicodeError:
        return None, [_finding(path, "invalid-utf8", path + " must be valid UTF-8")]
    if len(payload) > maximum:
        return None, [_finding(path, "input-too-large", path + " exceeds its byte bound")]
    return payload, []


def _contains_forbidden_call(node, parameters):
    if not isinstance(node, list):
        return None
    if node:
        head = str(node[0])
        if head == "fn":
            return _finding("source.main", "nested-function-forbidden", "Dogfooding v1 forbids nested functions")
        if head == "main":
            return _finding("source.main", "recursion-forbidden", "Dogfooding v1 forbids recursive policy execution")
        if head in parameters:
            return _finding("source.main", "dynamic-call-forbidden", "Dogfooding v1 forbids parameter-dispatched calls")
    for item in node:
        finding = _contains_forbidden_call(item, parameters)
        if finding:
            return finding
    return None


def _policy_shape(frontend, source, call):
    try:
        program = frontend.parse(source)
        call_nodes = frontend.parse(call)
    except frontend.error as error:
        return None, None, [_finding("source", "parse-failed", str(error)[:240])]

    definitions = [
        node for node in program
        if isinstance(node, list) and node and str(node[0]) == "defx"
    ]
    if (
        len(program) != 1 or len(definitions) != 1
        or len(definitions[0]) < 4 or str(definitions[0][1]) != "main"
    ):
        return None, None, [_finding(
            "source", "single-main-required",
            "Dogfooding v1 requires exactly one function definition named main",
        )]
    function = definitions[0][3]
    if not isinstance(function, list) or len(function) < 3 or str(function[0]) != "fn":
        return None, None, [_finding("source.main", "invalid-main", "main must contain one fn body")]
    parameters = function[1]
    if not isinstance(parameters, list) or any(isinstance(item, list) for item in parameters):
        return None, None, [_finding(
            "source.main", "first-order-parameters-required",
            "Dogfooding v1 permits only first-order value parameters",
        )]
    if len(parameters) > 1:
        return None, None, [_finding(
            "source.main", "single-input-profile-required",
            "Dogfooding v1 permits zero or one i31 input",
        )]
    parameter_names = {str(item) for item in parameters}
    for expression in function[2:]:
        finding = _contains_forbidden_call(expression, parameter_names)
        if finding:
            return None, None, [finding]

    if len(call_nodes) != 1 or not isinstance(call_nodes[0], list) or not call_nodes[0]:
        return None, None, [_finding("call", "single-call-required", "call must be one (main ...) expression")]
    call_node = call_nodes[0]
    if str(call_node[0]) != "main":
        return None, None, [_finding("call", "main-call-required", "Dogfooding v1 may invoke only main")]
    if len(call_node) - 1 != len(parameters):
        return None, None, [_finding("call", "arity-mismatch", "call arguments must match main parameters")]
    if any(type(item) is not int for item in call_node[1:]):
        return None, None, [_finding("call", "integer-input-required", "Dogfooding v1 inputs must be i31 integer literals")]
    if any(item < I31_MIN or item > I31_MAX for item in call_node[1:]):
        return None, None, [_finding("call", "i31-input-out-of-range", "Dogfooding v1 inputs must fit signed i31")]
    return program, call_node, []


def evaluate_policy_v1(frontend, source, call="(main)"):
    source_bytes, findings = _bounded_text(source, "source", MAX_SOURCE_BYTES)
    if findings:
        return _validation(findings=findings)
    call_bytes, findings = _bounded_text(call, "call", MAX_CALL_BYTES)
    if findings:
        return _validation(findings=findings)
    _, call_node, findings = _policy_shape(frontend, source, call)
    if findings:
        return _validation(findings=findings)

    try:
        verdict = frontend.build_verdict(source)
    except Exception as error:
        return _validation(findings=[_finding(
            "source", "checker-failed", str(error)[:240],
        )])
    if verdict.get("verdict") != "accept":
        return _validation(findings=[_finding(
            "source", "checker-rejected", "the LOOM checker rejected the dogfood policy",
        )])
    impure = [
        item["name"] for item in verdict.get("functions", [])
        if item.get("declared_effects") or item.get("performed_effects")
        or item.get("required_effects") or item.get("capabilities")
        or item.get("status") != "clean"
    ]
    if impure:
        return _validation(findings=[_finding(
            "source", "pure-policy-required",
            "Dogfooding v1 requires every function to have an empty effect row",
        )])

    runners = (
        ("interpreter", frontend.run_call),
        ("python", frontend.run_compiled),
        ("javascript", frontend.run_js),
        ("webassembly", frontend.run_wasm),
    )
    executions = []
    observables = []
    for backend, runner in runners:
        try:
            value, output = runner(source, call)
        except Exception as error:
            return _validation(findings=[_finding(
                "executions." + backend, "backend-execution-failed", str(error)[:240],
            )])
        value, value_findings = _json_value(value, "executions." + backend + ".value")
        if value_findings:
            return _validation(findings=value_findings)
        if not isinstance(output, list) or any(type(line) is not str for line in output):
            return _validation(findings=[_finding(
                "executions." + backend + ".output", "invalid-output",
                "backend output must be a list of text lines",
            )])
        observable = {"value": value, "output": list(output)}
        observable_sha256 = _sha256(_canonical_bytes(observable))
        executions.append({
            "backend": backend,
            "value": value,
            "output": list(output),
            "observable_sha256": observable_sha256,
        })
        observables.append(observable)

    if any(item != observables[0] for item in observables[1:]):
        return _validation(findings=[_finding(
            "executions", "backend-disagreement",
            "interpreter, Python, JavaScript, and WebAssembly observables must agree exactly",
        )])
    if observables[0]["output"]:
        return _validation(findings=[_finding(
            "executions", "observable-output-forbidden",
            "Dogfooding v1 policies must produce no output",
        )])
    decision_value = observables[0]["value"]
    if type(decision_value) is not int or decision_value not in (0, 1):
        return _validation(findings=[_finding(
            "executions", "binary-decision-required",
            "Dogfooding v1 policy result must be the exact i31 integer 0 or 1",
        )])

    call_normalized = "(" + " ".join(["main"] + [str(item) for item in call_node[1:]]) + ")"
    body = {
        "schema": RECEIPT_SCHEMA,
        "decision": "accept" if decision_value == 1 else "refuse",
        "source": {
            "encoding": "utf-8",
            "bytes": len(source_bytes),
            "sha256": _sha256(source_bytes),
        },
        "call": {
            "expression": call_normalized,
            "sha256": _sha256(call_normalized.encode("utf-8")),
            "input_provenance": "operator-supplied-unverified",
        },
        "policy": {
            "entrypoint": "main",
            "effect_row": [],
            "decision_values": {"accept": 1, "refuse": 0},
            "single_definition": True,
            "maximum_inputs": 1,
            "recursion": "forbidden",
            "dynamic_dispatch": "forbidden",
        },
        "executions": executions,
        "agreement": {
            "backends": list(BACKENDS),
            "exact": True,
            "observable_sha256": executions[0]["observable_sha256"],
        },
        "lifecycle": {
            "advisory": True,
            "authorization": "none",
            "host_actions_executed": False,
            "external_input_identity_verified": False,
            "compiler_is_in_trusted_computing_base": True,
        },
    }
    receipt = dict(body)
    receipt["receipt_sha256"] = _sha256(_canonical_bytes(body))
    return _validation(receipt=receipt)


def verify_policy_receipt_v1(frontend, receipt, source, call="(main)"):
    """Re-execute one policy and require exact equality with its supplied receipt."""
    if not isinstance(receipt, dict):
        return _validation(findings=[_finding(
            "receipt", "expected-object", "Dogfooding v1 receipt must be an object",
        )])
    expected = evaluate_policy_v1(frontend, source, call)
    if not expected["valid"]:
        return expected
    expected_receipt = expected["receipt"]
    if set(receipt) != set(expected_receipt):
        return _validation(findings=[_finding(
            "receipt", "closed-object-mismatch",
            "Dogfooding v1 receipt has missing or unknown fields",
        )])
    if receipt != expected_receipt:
        return _validation(findings=[_finding(
            "receipt", "receipt-mismatch",
            "supplied receipt does not match a fresh four-backend policy evaluation",
        )])
    return expected


def build_review_request_v1(frontend, source, manifest, observation, run_id, nonce):
    """Build the exact externally evidenced candidate surface an operator reviews."""
    adapter_findings = _evidence_frontend_findings(frontend)
    if adapter_findings:
        return _review_request_validation(findings=adapter_findings)
    source_bytes, findings = _bounded_text(source, "source", MAX_SOURCE_BYTES)
    if findings:
        return _review_request_validation(findings=findings)
    if _sha256(source_bytes) != POLICY_SOURCE_SHA256:
        return _review_request_validation(findings=[_finding(
            "source", "policy-source-mismatch",
            "Dogfooding v2 requires the exact pinned canonical release policy",
        )])
    policy_result = evaluate_policy_v1(frontend, source, "(main 3)")
    if not policy_result["valid"]:
        return _review_request_validation(findings=[
            _finding("policy." + item["path"], item["code"], item["message"])
            for item in policy_result["findings"]
        ])
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        return _review_request_validation(findings=[_finding(
            "nonce", "invalid-nonce", "nonce must be 64 lowercase hexadecimal characters",
        )])
    if isinstance(run_id, bool) or not isinstance(run_id, (int, str)) or not str(run_id).isdigit() or int(run_id) <= 0:
        return _review_request_validation(findings=[_finding(
            "run_id", "invalid-run-id", "run_id must be a positive decimal integer",
        )])

    manifest_validation = frontend.validate_manifest(manifest)
    normalized_observation, observation_findings = frontend.validate_observation(observation)
    findings = list(manifest_validation.get("findings", [])) + list(observation_findings)
    if findings:
        return _review_request_validation(findings=findings)
    normalized_manifest = manifest_validation["normalized_manifest"]
    if normalized_manifest.get("agent") != {"id": "ci", "role": "trace"}:
        findings.append(_finding(
            "manifest.agent", "ci-observer-required",
            "Dogfooding v2 requires the non-mutating ci/trace evidence profile",
        ))
    if normalized_manifest.get("actions") != ["read", "test"] or normalized_manifest.get("write_paths") != []:
        findings.append(_finding(
            "manifest.actions", "read-only-evidence-profile-required",
            "Dogfooding v2 permits exactly read and test with no write paths",
        ))
    if normalized_manifest.get("evidence_required") != list(EVIDENCE_KINDS):
        findings.append(_finding(
            "manifest.evidence_required", "exact-evidence-profile-required",
            "Dogfooding v2 requires syntax, citadel, docs-parity, fuzz, and git-sync",
        ))
    if normalized_observation.get("result") != "completed":
        findings.append(_finding(
            "observation.result", "completed-evidence-required",
            "Dogfooding v2 requires a completed read-only observation",
        ))
    if normalized_observation.get("actions_observed") != ["read", "test"]:
        findings.append(_finding(
            "observation.actions_observed", "read-only-observation-required",
            "Dogfooding v2 observation must contain exactly read and test",
        ))
    if normalized_observation.get("evidence") != []:
        findings.append(_finding(
            "observation.evidence", "caller-evidence-forbidden",
            "Dogfooding v2 accepts evidence only from its fixed adapters",
        ))
    changed_files = normalized_observation.get("files_changed", [])
    if len(changed_files) > MAX_CHANGED_FILES:
        findings.append(_finding(
            "observation.files_changed", "too-many-changed-files",
            "Dogfooding v2 review is bounded to 4096 changed paths",
        ))
    if findings:
        return _review_request_validation(findings=findings)

    ci_result = frontend.collect_ci_evidence(manifest, observation, int(run_id))
    if not isinstance(ci_result, dict) or not ci_result.get("valid"):
        ci_findings = ci_result.get("findings", []) if isinstance(ci_result, dict) else []
        return _review_request_validation(findings=(ci_findings or [_finding(
            "ci", "ci-evidence-invalid", "the fixed GitHub CI adapter did not return valid evidence",
        )]))
    ci_evidence = ci_result.get("evidence")
    kinds = [item.get("kind") for item in ci_evidence] if isinstance(ci_evidence, list) else []
    after_head = normalized_observation["repositories"][0]["after_head"]
    if (
        kinds != list(EVIDENCE_KINDS)
        or any(item.get("status") != "pass" for item in ci_evidence)
        or any(after_head not in item.get("detail", "") for item in ci_evidence)
        or any(
            str(run_id) not in item.get("detail", "")
            for item in ci_evidence if item.get("kind") != "git-sync"
        )
    ):
        return _review_request_validation(findings=[_finding(
            "ci.evidence", "exact-ci-evidence-required",
            "CI adapter evidence must contain the exact passing v2 taxonomy bound to run and head",
        )])

    observation_sha256 = _sha256(_canonical_bytes(normalized_observation))
    ci_collection_sha256 = _sha256(_canonical_bytes(ci_result))
    body = {
        "schema": REVIEW_REQUEST_SCHEMA,
        "policy": {
            "source_sha256": _sha256(source_bytes),
            "source_bytes": len(source_bytes),
            "entrypoint": "main",
            "derived_call": "(main 3)",
        },
        "gate": {
            "manifest_sha256": manifest_validation["manifest_sha256"],
            "observation_sha256": observation_sha256,
            "repository": normalized_observation["repositories"][0]["root"],
            "before_head": normalized_observation["repositories"][0]["before_head"],
            "after_head": after_head,
            "files_changed": changed_files,
        },
        "ci": {
            "run_id": int(run_id),
            "collection_schema": ci_result.get("schema"),
            "collection_sha256": ci_collection_sha256,
            "test_evidence": list(TEST_EVIDENCE_KINDS),
            "git_evidence": "git-sync",
        },
        "review": {
            "agent": normalized_manifest["agent"],
            "task": normalized_manifest["task"],
            "actions": normalized_manifest["actions"],
            "write_paths": [],
        },
        "nonce": nonce,
        "lifecycle": {
            "advisory": True,
            "authorization": "none",
            "host_actions_executed": False,
            "private_key_required_by_loom": False,
        },
    }
    if len(_canonical_bytes(body)) > MAX_REVIEW_REQUEST_BYTES:
        return _review_request_validation(findings=[_finding(
            "request", "request-too-large", "Dogfooding review request exceeds 1 MiB",
        )])
    request = dict(body)
    request["request_sha256"] = _sha256(_canonical_bytes(body))
    return _review_request_validation(request=request)


def verify_review_v1(frontend, request, review, source, manifest, observation, run_id, nonce):
    """Rebuild one request and verify the operator's domain-separated signature."""
    expected = build_review_request_v1(
        frontend, source, manifest, observation, run_id, nonce,
    )
    if not expected["valid"]:
        return _review_validation(findings=expected["findings"])
    request_findings = _closed_object(request, "request", set(expected["request"]))
    if request_findings:
        return _review_validation(findings=request_findings)
    if request != expected["request"]:
        return _review_validation(findings=[_finding(
            "request", "request-mismatch",
            "review request does not match freshly collected policy, Git, and CI evidence",
        )])
    review_findings = _closed_object(review, "review", {
        "schema", "request_sha256", "reviewer", "decision", "key_sha256", "signature",
    })
    if review_findings:
        return _review_validation(findings=review_findings)
    if review["schema"] != REVIEW_SCHEMA:
        review_findings.append(_finding(
            "review.schema", "unsupported-schema", "expected " + REVIEW_SCHEMA,
        ))
    if review["request_sha256"] != request["request_sha256"]:
        review_findings.append(_finding(
            "review.request_sha256", "request-mismatch", "review is bound to another request",
        ))
    if review["reviewer"] != "operator":
        review_findings.append(_finding(
            "review.reviewer", "invalid-reviewer", "reviewer must be operator",
        ))
    if review["decision"] != "approve":
        review_findings.append(_finding(
            "review.decision", "not-approved", "operator review decision must be approve",
        ))
    try:
        public_key_value = frontend.load_public_key()
    except Exception as error:
        review_findings.append(_finding(
            "public_key", "public-key-unavailable", str(error)[:240],
        ))
        public_key_value = None
    public_key = None
    if public_key_value is not None:
        public_key, key_findings = frontend.validate_public_key(public_key_value)
        review_findings.extend(key_findings)
    if public_key is not None:
        expected_key_sha256 = frontend.key_sha256(public_key)
        if review["key_sha256"] != expected_key_sha256:
            review_findings.append(_finding(
                "review.key_sha256", "key-mismatch", "review is signed by a different key",
            ))
        signed = {key: review[key] for key in sorted(set(review) - {"signature"})}
        if not frontend.rsa_verify(_canonical_bytes(signed), review["signature"], public_key):
            review_findings.append(_finding(
                "review.signature", "invalid-signature", "operator review signature is invalid",
            ))
    if review_findings:
        return _review_validation(findings=review_findings)
    review_sha256 = _sha256(_canonical_bytes(review))
    return _review_validation(evidence={
        "schema": REVIEW_SCHEMA,
        "request_sha256": request["request_sha256"],
        "review_sha256": review_sha256,
        "key_sha256": review["key_sha256"],
        "reviewer": "operator",
        "decision": "approve",
        "identity": "pinned-operator-public-key",
    })


def evaluate_policy_v2(frontend, source, manifest, observation, run_id, request, review):
    """Derive the policy input from reverified CI, Git, and signed review evidence."""
    nonce = request.get("nonce") if isinstance(request, dict) else None
    verified_review = verify_review_v1(
        frontend, request, review, source, manifest, observation, run_id, nonce,
    )
    if not verified_review["valid"]:
        return _validation_v2(findings=verified_review["findings"])
    policy_result = evaluate_policy_v1(frontend, source, "(main 3)")
    if not policy_result["valid"]:
        return _validation_v2(findings=policy_result["findings"])
    v1 = policy_result["receipt"]
    call = dict(v1["call"])
    call["input_provenance"] = "derived-from-reverified-ci-git-and-signed-review"
    body = {
        "schema": RECEIPT_SCHEMA_V2,
        "decision": v1["decision"],
        "source": v1["source"],
        "call": call,
        "evidence_input": {
            "facts": [
                {"kind": "git", "status": "pass", "source": "fixed-github-ci-adapter"},
                {"kind": "review", "status": "pass", "source": "pinned-operator-public-key"},
                {"kind": "tests", "status": "pass", "source": "fixed-github-ci-adapter"},
            ],
            "quorum": 3,
            "derived_value": 3,
            "manual_value_accepted": False,
            "manifest_sha256": request["gate"]["manifest_sha256"],
            "observation_sha256": request["gate"]["observation_sha256"],
            "after_head": request["gate"]["after_head"],
            "ci_run_id": request["ci"]["run_id"],
            "ci_collection_sha256": request["ci"]["collection_sha256"],
            "review_request_sha256": request["request_sha256"],
            "review_sha256": verified_review["evidence"]["review_sha256"],
            "reviewer_key_sha256": verified_review["evidence"]["key_sha256"],
        },
        "policy": v1["policy"],
        "executions": v1["executions"],
        "agreement": v1["agreement"],
        "lifecycle": {
            "advisory": True,
            "authorization": "none",
            "host_actions_executed": False,
            "external_evidence_reverified": True,
            "reviewer_identity_verified_by_pinned_key": True,
            "github_api_is_trusted_oracle": True,
            "compiler_is_in_trusted_computing_base": True,
        },
    }
    receipt = dict(body)
    receipt["receipt_sha256"] = _sha256(_canonical_bytes(body))
    return _validation_v2(receipt=receipt)


def verify_policy_receipt_v2(frontend, receipt, source, manifest, observation, run_id, request, review):
    """Recollect every external fact and require exact v2 receipt equality."""
    if not isinstance(receipt, dict):
        return _validation_v2(findings=[_finding(
            "receipt", "expected-object", "Dogfooding v2 receipt must be an object",
        )])
    expected = evaluate_policy_v2(
        frontend, source, manifest, observation, run_id, request, review,
    )
    if not expected["valid"]:
        return expected
    expected_receipt = expected["receipt"]
    if set(receipt) != set(expected_receipt):
        return _validation_v2(findings=[_finding(
            "receipt", "closed-object-mismatch",
            "Dogfooding v2 receipt has missing or unknown fields",
        )])
    if receipt != expected_receipt:
        return _validation_v2(findings=[_finding(
            "receipt", "receipt-mismatch",
            "supplied receipt does not match fresh evidence collection and policy execution",
        )])
    return expected
