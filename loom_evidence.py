#!/usr/bin/env python3
"""Read-only GitHub CI evidence collection for canonical LOOM."""

import json
import re
import ssl
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import loom_gate


COLLECTION_SCHEMA = "loom-gate-evidence-collection/v1"
_API_ROOT = "https://api.github.com/repos/umbraaeternaa/loom"
_REPOSITORY = "umbraaeternaa/loom"
_WORKFLOW = "LOOM Citadel"
_MAX_RESPONSE_BYTES = 1_000_000
_STEPS = {
    "Compile Python sources": "syntax",
    "Run citadel": "citadel",
    "Verify published docs parity": "docs-parity",
    "Run extended deterministic fuzz seeds": "fuzz",
}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_CA_BUNDLES = (Path("/etc/ssl/cert.pem"), Path("/opt/homebrew/etc/openssl@3/cert.pem"), Path("/usr/local/etc/openssl@3/cert.pem"))


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _result(evidence, findings):
    return {
        "schema": COLLECTION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "read_only": True,
        "evidence": evidence if not findings else None,
        "findings": loom_gate._unique_issues(findings),
    }


def _fetch_json(path):
    url = _API_ROOT + path
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "loom-gate-evidence-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    ca_bundle = next((path for path in _CA_BUNDLES if path.is_file()), None)
    context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    try:
        with urlopen(request, timeout=5, context=context) as response:
            if response.geturl() != url:
                raise ValueError("GitHub API redirect refused")
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        raise ValueError(f"GitHub API read failed: {error}") from error
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ValueError("GitHub API response exceeds size limit")
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"GitHub API returned invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("GitHub API response must be an object")
    return value


def collect_ci_evidence(manifest, observation, run_id):
    """Verify one canonical GitHub Actions run against an observed LOOM head."""
    validation = loom_gate.validate_manifest(manifest)
    observed, observation_findings = loom_gate._validate_observation(observation)
    findings = list(validation["findings"]) + observation_findings
    if isinstance(run_id, bool) or not isinstance(run_id, (int, str)) or not str(run_id).isdigit() or int(run_id) <= 0:
        findings.append(_finding("run_id", "invalid-run-id", "run_id must be a positive decimal integer"))
    if findings:
        return _result(None, findings)

    normalized = validation["normalized_manifest"]
    declared_roots = {item["root"] for item in normalized["repositories"]}
    observed_repositories = {item["root"]: item for item in observed["repositories"]}
    if declared_roots != {loom_gate._LOOM_ROOT}:
        findings.append(_finding("repositories", "unsupported-ci-repository", "CI evidence v1 supports exactly the canonical LOOM repository"))
    if set(observed_repositories) != declared_roots:
        findings.append(_finding("observation.repositories", "repository-mismatch", "observation repositories must exactly match the manifest"))
    if findings:
        return _result(None, findings)

    after_head = observed_repositories[loom_gate._LOOM_ROOT]["after_head"]
    if len(after_head) != 40:
        return _result(None, [_finding("observation.repositories.after_head", "full-head-required", "CI evidence requires a full 40-character observed after_head")])
    run_id = int(run_id)
    try:
        run = _fetch_json(f"/actions/runs/{run_id}")
        jobs = _fetch_json(f"/actions/runs/{run_id}/jobs?per_page=100")
        branch = _fetch_json("/branches/main")
    except ValueError as error:
        return _result(None, [_finding("github", "github-api-failed", str(error))])

    repository = run.get("repository")
    head_sha = run.get("head_sha")
    if not isinstance(repository, dict) or repository.get("full_name") != _REPOSITORY:
        findings.append(_finding("github.run.repository", "repository-mismatch", "workflow run does not belong to canonical LOOM"))
    if run.get("name") != _WORKFLOW:
        findings.append(_finding("github.run.name", "workflow-mismatch", f"expected workflow '{_WORKFLOW}'"))
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        findings.append(_finding("github.run", "workflow-not-successful", "workflow run must be completed with success"))
    if not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha) or not head_sha.startswith(after_head):
        findings.append(_finding("github.run.head_sha", "head-mismatch", "workflow head_sha does not match observed after_head"))

    branch_commit = branch.get("commit")
    branch_sha = branch_commit.get("sha") if isinstance(branch_commit, dict) else None
    if not isinstance(branch_sha, str) or not _SHA.fullmatch(branch_sha) or not branch_sha.startswith(after_head):
        findings.append(_finding("github.branch.main", "git-sync-failed", "origin main does not match observed after_head"))

    job_list = jobs.get("jobs")
    verify_jobs = [job for job in job_list if isinstance(job, dict) and job.get("name") == "verify"] if isinstance(job_list, list) else []
    if len(verify_jobs) != 1:
        findings.append(_finding("github.jobs", "verify-job-missing", "expected exactly one verify job"))
        verify_job = None
    else:
        verify_job = verify_jobs[0]
        if verify_job.get("status") != "completed" or verify_job.get("conclusion") != "success":
            findings.append(_finding("github.jobs.verify", "verify-job-not-successful", "verify job must be completed with success"))

    steps_by_name = {}
    if verify_job is not None and isinstance(verify_job.get("steps"), list):
        steps_by_name = {step.get("name"): step for step in verify_job["steps"] if isinstance(step, dict) and isinstance(step.get("name"), str)}
    for step_name in sorted(_STEPS):
        step = steps_by_name.get(step_name)
        if step is None or step.get("status") != "completed" or step.get("conclusion") != "success":
            findings.append(_finding("github.jobs.verify.steps", "required-step-not-successful", f"required step '{step_name}' must complete successfully"))

    if findings:
        return _result(None, findings)
    evidence = [
        {"kind": kind, "status": "pass", "detail": f"GitHub Actions run {run_id}: {step_name} passed at {head_sha}"}
        for step_name, kind in sorted(_STEPS.items(), key=lambda item: item[1])
    ]
    evidence.append({"kind": "git-sync", "status": "pass", "detail": f"GitHub main matches {head_sha}"})
    return _result(sorted(evidence, key=lambda item: item["kind"]), [])
