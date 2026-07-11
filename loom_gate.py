#!/usr/bin/env python3
"""Deterministic, advisory task manifests for LOOM Gate phase 1."""

import hashlib
import json
import re
import unicodedata


MANIFEST_SCHEMA = "loom-gate-manifest/v1"
MANIFEST_SCHEMA_V2 = "loom-gate-manifest/v2"
MANIFEST_SCHEMAS = frozenset({MANIFEST_SCHEMA, MANIFEST_SCHEMA_V2})
VALIDATION_SCHEMA = "loom-gate-manifest-validation/v1"
DECISION_SCHEMA = "loom-gate-decision/v1"
OBSERVATION_SCHEMA = "loom-gate-observation/v1"
RECEIPT_SCHEMA = "loom-gate-receipt/v1"
RECEIPT_VALIDATION_SCHEMA = "loom-gate-receipt-validation/v1"
DIAGNOSTICS_SCHEMA = "loom-gate-diagnostics/v1"
POLICY_ID = "operator-codex-cloud/v1"
AGENTS = frozenset({"codex", "cloud-code", "auditor", "argus", "nostromo", "ci", "operator"})
ROLES = frozenset({"code", "organism", "audit", "night", "trace", "operator"})
ACTIONS = frozenset({
    "read", "write", "test", "process", "network", "git-commit",
    "git-push", "delete", "backup", "memory-write", "dashboard", "report", "audit",
})
EVIDENCE = frozenset({
    "syntax", "citadel", "docs-parity", "fuzz", "git-clean", "git-sync",
    "live-site", "backup", "operator-approval", "audit", "secret-lane",
})
_TOP_KEYS = frozenset({
    "schema", "agent", "task", "repositories", "read_paths", "write_paths",
    "actions", "evidence_required",
})
_TOP_KEYS_V2 = _TOP_KEYS | {"secret_access"}
_HEX_HEAD = re.compile(r"^[0-9a-f]{7,40}$")
_OBSERVATION_KEYS = frozenset({"schema", "result", "repositories", "files_changed", "actions_observed", "evidence"})
_OBSERVATION_RESULTS = frozenset({"completed", "failed", "blocked"})
_EVIDENCE_STATUS = frozenset({"pass", "fail", "not-run"})
_EXPECTED_ROLES = {
    "codex": "code", "cloud-code": "organism", "auditor": "audit",
    "argus": "organism", "nostromo": "night", "ci": "trace", "operator": "operator",
}
_LOOM_ROOT = "/Users/macbook/Projects/loom"
_ARGUS_ROOT = "/Users/macbook/Projects/argus"
_NOSTROMO_ROOT = "/Users/macbook/Projects/nostromo"
_MEMORY_ROOT = "/Users/macbook/codex/Кодекс"
_FROZEN_ROOT = "/Users/macbook/Projects/argus/citadel"
_AUDIT_ROOT = "/Users/macbook/Projects/audit-targets"
_SECRET_SEGMENTS = frozenset({
    ".aws", ".azure", ".config/gcloud", ".docker", ".gnupg", ".kube",
    ".ssh", ".1password", "keychain", "keychains", "password-store",
})
_CREDENTIAL_FILES = frozenset({
    ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json",
    "hosts.yml", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
})
_CREDENTIAL_TOKENS = ("api_key", "apikey", "auth_token", "cookie", "password", "session", "token")
_WALLET_TOKENS = ("keystore", "mnemonic", "privatekey", "private_key", "seed", "wallet")
_BANK_TOKENS = ("bank", "card", "payment")
_SECRET_EVIDENCE_PREFIXES = ("secret lane approved:", "secret lane blocked:")
_SECRET_ACCESS_CLASSES = frozenset({"SecretRead", "CredentialAccess", "WalletKey", "BankCredential"})
_SECRET_ACCESS_MODES = frozenset({"read"})


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _text(value, path, findings):
    if not isinstance(value, str):
        findings.append(_finding(path, "expected-string", "expected a string"))
        return None
    value = unicodedata.normalize("NFC", value)
    if not value.strip():
        findings.append(_finding(path, "empty-string", "value must not be empty"))
        return None
    return value


def _closed_object(value, path, required, findings):
    if not isinstance(value, dict):
        findings.append(_finding(path, "expected-object", "expected an object"))
        return False
    for key in sorted(set(value) - set(required)):
        findings.append(_finding(f"{path}.{key}", "unknown-field", f"unknown field '{key}'"))
    for key in sorted(set(required) - set(value)):
        findings.append(_finding(f"{path}.{key}", "missing-field", f"missing required field '{key}'"))
    return set(value) == set(required)


def _enum_list(value, path, allowed, findings):
    if not isinstance(value, list):
        findings.append(_finding(path, "expected-array", "expected an array"))
        return None
    normalized = []
    for index, item in enumerate(value):
        item = _text(item, f"{path}[{index}]", findings)
        if item is None:
            continue
        if item not in allowed:
            findings.append(_finding(f"{path}[{index}]", "unknown-value", f"unknown value '{item}'"))
        normalized.append(item)
    duplicates = sorted({item for item in normalized if normalized.count(item) > 1})
    for item in duplicates:
        findings.append(_finding(path, "duplicate-value", f"duplicate value '{item}'"))
    return sorted(set(normalized))


def _path_list(value, path, findings):
    if not isinstance(value, list):
        findings.append(_finding(path, "expected-array", "expected an array"))
        return None
    normalized = []
    for index, item in enumerate(value):
        item = _text(item, f"{path}[{index}]", findings)
        if item is None:
            continue
        parts = item.split("/")
        if not item.startswith("/"):
            findings.append(_finding(f"{path}[{index}]", "path-not-absolute", "path must be absolute"))
        elif ".." in parts or "~" in parts:
            findings.append(_finding(f"{path}[{index}]", "unsafe-path", "path must not contain '..' or '~'"))
        else:
            canonical = "/" + "/".join(part for part in parts if part)
            normalized.append(canonical or "/")
    duplicates = sorted({item for item in normalized if normalized.count(item) > 1})
    for item in duplicates:
        findings.append(_finding(path, "duplicate-path", f"duplicate path '{item}'"))
    return sorted(set(normalized))


def _secret_access_list(value, path, findings):
    if not isinstance(value, list):
        findings.append(_finding(path, "expected-array", "expected an array"))
        return None
    normalized = []
    for index, item in enumerate(value):
        base = f"{path}[{index}]"
        if not _closed_object(item, base, {"class", "path", "mode", "reason"}, findings):
            continue
        secret_class = _text(item["class"], base + ".class", findings)
        mode = _text(item["mode"], base + ".mode", findings)
        reason = _text(item["reason"], base + ".reason", findings)
        paths = _path_list([item["path"]], base + ".path", findings)
        lane_path = paths[0] if paths else None
        if secret_class is not None and secret_class not in _SECRET_ACCESS_CLASSES:
            findings.append(_finding(base + ".class", "unknown-secret-class", f"unknown secret class '{secret_class}'"))
        if mode is not None and mode not in _SECRET_ACCESS_MODES:
            findings.append(_finding(base + ".mode", "unknown-secret-mode", f"unknown secret access mode '{mode}'"))
        if reason is not None:
            if len(reason.split()) < 4:
                findings.append(_finding(base + ".reason", "vague-secret-reason", "secret access reason must be specific"))
            if "=" in reason:
                findings.append(_finding(base + ".reason", "unsafe-secret-reason", "secret access reason must not contain secret assignments"))
        inferred = _secret_class(lane_path) if lane_path else None
        if lane_path and inferred is None:
            findings.append(_finding(base + ".path", "secret-path-not-classified", "secret_access path must be classified as secret-like"))
        elif secret_class and inferred and secret_class not in {inferred, "SecretRead"}:
            findings.append(_finding(base + ".class", "secret-class-mismatch", f"declared class '{secret_class}' does not match path class '{inferred}'"))
        normalized.append({"class": secret_class, "path": lane_path, "mode": mode, "reason": reason})
    keys = [(item["class"], item["path"], item["mode"]) for item in normalized]
    for key in sorted({key for key in keys if keys.count(key) > 1}):
        findings.append(_finding(path, "duplicate-secret-access", f"duplicate secret access lane '{key[0]} {key[2]} {key[1]}'"))
    return sorted(normalized, key=lambda item: (item["path"] or "", item["class"] or "", item["mode"] or ""))


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_manifest(manifest):
    """Validate and hash a phase-1 manifest without reading or enforcing host state."""
    findings = []
    if not isinstance(manifest, dict):
        findings.append(_finding("$", "expected-object", "manifest must be an object"))
        return _validation(None, findings)

    schema = _text(manifest.get("schema"), "schema", findings)
    top_keys = _TOP_KEYS_V2 if schema == MANIFEST_SCHEMA_V2 else _TOP_KEYS

    for key in sorted(set(manifest) - top_keys):
        findings.append(_finding(key, "unknown-field", f"unknown field '{key}'"))
    for key in sorted(top_keys - set(manifest)):
        findings.append(_finding(key, "missing-field", f"missing required field '{key}'"))

    normalized = {}
    if schema is not None and schema not in MANIFEST_SCHEMAS:
        findings.append(_finding("schema", "unsupported-schema", f"expected one of {sorted(MANIFEST_SCHEMAS)}"))
    normalized["schema"] = schema

    agent = manifest.get("agent")
    if _closed_object(agent, "agent", {"id", "role"}, findings):
        agent_id = _text(agent["id"], "agent.id", findings)
        role = _text(agent["role"], "agent.role", findings)
        if agent_id is not None and agent_id not in AGENTS:
            findings.append(_finding("agent.id", "unknown-agent", f"unknown agent '{agent_id}'"))
        if role is not None and role not in ROLES:
            findings.append(_finding("agent.role", "unknown-role", f"unknown role '{role}'"))
        normalized["agent"] = {"id": agent_id, "role": role}

    task = manifest.get("task")
    if _closed_object(task, "task", {"summary", "intent"}, findings):
        normalized["task"] = {
            "summary": _text(task["summary"], "task.summary", findings),
            "intent": _text(task["intent"], "task.intent", findings),
        }

    repositories = manifest.get("repositories")
    normalized_repositories = []
    if not isinstance(repositories, list):
        findings.append(_finding("repositories", "expected-array", "expected an array"))
    else:
        for index, repository in enumerate(repositories):
            base = f"repositories[{index}]"
            if not _closed_object(repository, base, {"root", "expected_head", "require_clean"}, findings):
                continue
            roots = _path_list([repository["root"]], base + ".root", findings)
            head = _text(repository["expected_head"], base + ".expected_head", findings)
            clean = repository["require_clean"]
            if head is not None and not _HEX_HEAD.fullmatch(head):
                findings.append(_finding(base + ".expected_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            if not isinstance(clean, bool):
                findings.append(_finding(base + ".require_clean", "expected-boolean", "expected true or false"))
            normalized_repositories.append({
                "root": roots[0] if roots else None,
                "expected_head": head,
                "require_clean": clean if isinstance(clean, bool) else None,
            })
        roots = [item["root"] for item in normalized_repositories if item["root"] is not None]
        for root in sorted({root for root in roots if roots.count(root) > 1}):
            findings.append(_finding("repositories", "duplicate-repository", f"duplicate repository root '{root}'"))
    normalized["repositories"] = sorted(normalized_repositories, key=lambda item: item["root"] or "")
    normalized["read_paths"] = _path_list(manifest.get("read_paths"), "read_paths", findings)
    normalized["write_paths"] = _path_list(manifest.get("write_paths"), "write_paths", findings)
    normalized["actions"] = _enum_list(manifest.get("actions"), "actions", ACTIONS, findings)
    normalized["evidence_required"] = _enum_list(manifest.get("evidence_required"), "evidence_required", EVIDENCE, findings)
    if schema == MANIFEST_SCHEMA_V2:
        normalized["secret_access"] = _secret_access_list(manifest.get("secret_access"), "secret_access", findings)

    if findings:
        return _validation(None, findings)
    canonical = _canonical_json(normalized)
    return _validation(normalized, [], hashlib.sha256(canonical.encode("utf-8")).hexdigest())


def _validation(normalized, findings, digest=None):
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "manifest_sha256": digest,
        "normalized_manifest": normalized,
        "findings": findings,
    }


def _under(path, root):
    return path == root or path.startswith(root + "/")


def _zone(path):
    if _under(path, _FROZEN_ROOT): return "frozen"
    if _under(path, _LOOM_ROOT): return "loom"
    if _under(path, _ARGUS_ROOT): return "argus"
    if _under(path, _NOSTROMO_ROOT): return "nostromo"
    if _under(path, _MEMORY_ROOT): return "memory"
    if _under(path, _AUDIT_ROOT): return "audit-target"
    return "external"


def _secret_class(path):
    lowered = path.lower()
    parts = [part for part in lowered.split("/") if part]
    base = parts[-1] if parts else ""
    if base.startswith(".env"):
        return "CredentialAccess"
    joined_pairs = {"/".join(parts[index:index + 2]) for index in range(max(0, len(parts) - 1))}
    if any(segment in _SECRET_SEGMENTS for segment in parts) or any(pair in _SECRET_SEGMENTS for pair in joined_pairs):
        return "CredentialAccess"
    if base in _CREDENTIAL_FILES or any(token in base for token in _CREDENTIAL_TOKENS):
        return "CredentialAccess"
    if any(token in lowered for token in _WALLET_TOKENS):
        return "WalletKey"
    if any(token in lowered for token in _BANK_TOKENS):
        return "BankCredential"
    return None


def _issue(code, message, path="$"):
    return {"path": path, "code": code, "message": message}


def _autonomous_organism_write(agent, path, actions):
    if agent == "cloud-code":
        if _under(path, _MEMORY_ROOT) and "memory-write" in actions: return True
        if _under(path, _ARGUS_ROOT + "/reports") and "report" in actions: return True
        if _under(path, _ARGUS_ROOT + "/state") and actions & {"report", "dashboard", "backup"}: return True
        if _under(path, _NOSTROMO_ROOT + "/reports") and "report" in actions: return True
    if agent == "auditor":
        return _under(path, _ARGUS_ROOT + "/reports/auditor") and "report" in actions
    if agent == "argus":
        roots = (_ARGUS_ROOT + "/reports", _ARGUS_ROOT + "/state", _ARGUS_ROOT + "/design", _ARGUS_ROOT + "/experiments")
        return any(_under(path, root) for root in roots) and bool(actions & {"report", "audit", "dashboard", "test"})
    if agent == "nostromo":
        return _under(path, _NOSTROMO_ROOT + "/reports") and "report" in actions
    return False


def evaluate_manifest(manifest):
    """Classify a declared task under policy v1 without inspecting or enforcing host state."""
    validation = validate_manifest(manifest)
    if not validation["valid"]:
        return _decision("reject", None, [], validation["findings"])

    normalized = validation["normalized_manifest"]
    digest = validation["manifest_sha256"]
    agent = normalized["agent"]["id"]
    role = normalized["agent"]["role"]
    actions = set(normalized["actions"])
    evidence = set(normalized["evidence_required"])
    reasons, violations = [], []

    expected_role = _EXPECTED_ROLES[agent]
    if role != expected_role:
        violations.append(_issue("role-mismatch", f"agent '{agent}' must use role '{expected_role}', not '{role}'", "agent.role"))

    allowed_actions = {
        "codex": {"read", "write", "test", "process", "network", "git-commit", "git-push", "delete", "memory-write", "report", "audit"},
        "cloud-code": {"read", "write", "test", "process", "network", "git-commit", "git-push", "delete", "backup", "memory-write", "dashboard", "report", "audit"},
        "auditor": {"read", "network", "report", "audit"},
        "argus": {"read", "write", "test", "process", "network", "dashboard", "report", "audit"},
        "nostromo": {"read", "write", "process", "network", "backup", "report"},
        "ci": {"read", "test", "report"},
        "operator": set(ACTIONS),
    }[agent]
    for action in sorted(actions - allowed_actions):
        violations.append(_issue("action-forbidden", f"agent '{agent}' may not request action '{action}'", "actions"))

    if actions & {"write", "delete", "memory-write"} and not normalized["write_paths"]:
        violations.append(_issue("missing-write-scope", "mutating action requires at least one write path", "write_paths"))

    secret_reads = []
    for index, path in enumerate(normalized["read_paths"]):
        secret = _secret_class(path)
        if secret is None:
            continue
        issue_path = f"read_paths[{index}]"
        secret_reads.append((path, secret, issue_path))
        reasons.append(_issue(
            "secret-read-operator-required",
            f"secret-like read path requires manifest-bound operator approval ({secret})",
            issue_path,
        ))
    for index, lane in enumerate(normalized.get("secret_access", [])):
        secret_reads.append((lane["path"], lane["class"], f"secret_access[{index}]"))
        reasons.append(_issue(
            "secret-access-operator-required",
            f"declared secret_access lane requires manifest-bound operator approval ({lane['class']})",
            f"secret_access[{index}]",
        ))

    for index, path in enumerate(normalized["write_paths"]):
        zone = _zone(path)
        issue_path = f"write_paths[{index}]"
        secret = _secret_class(path)
        if secret is not None:
            violations.append(_issue(
                "secret-write-forbidden",
                f"secret-like write/delete path is rejected by Gate policy ({secret})",
                issue_path,
            ))
            continue
        if zone == "frozen":
            violations.append(_issue("frozen-zone", "the frozen ARGUS citadel is read-only for every agent", issue_path))
            continue
        if agent == "operator":
            continue
        if agent == "codex":
            if zone not in {"loom", "memory"}:
                violations.append(_issue("write-zone-forbidden", f"Codex may not write zone '{zone}'", issue_path))
            else:
                reasons.append(_issue("operator-gate", f"Codex write to {zone} requires operator approval", issue_path))
        elif agent in {"cloud-code", "argus", "nostromo", "auditor"}:
            owned = zone in ({"argus", "nostromo", "memory"} if agent == "cloud-code" else ({"argus"} if agent in {"argus", "auditor"} else {"nostromo"}))
            if not owned or zone == "audit-target":
                violations.append(_issue("write-zone-forbidden", f"agent '{agent}' may not write zone '{zone}'", issue_path))
            elif not _autonomous_organism_write(agent, path, actions):
                reasons.append(_issue("operator-gate", f"agent '{agent}' write outside its autonomous report/state lane requires operator approval", issue_path))
        else:
            violations.append(_issue("write-zone-forbidden", f"agent '{agent}' may not write host files", issue_path))

    if agent == "ci":
        for index, path in enumerate(normalized["read_paths"]):
            if _zone(path) != "loom":
                violations.append(_issue("read-zone-forbidden", "CI may read only the canonical LOOM zone", f"read_paths[{index}]"))

    git_actions = actions & {"git-commit", "git-push"}
    if git_actions and not normalized["repositories"]:
        violations.append(_issue("missing-repository", "Git action requires a declared repository", "repositories"))
    for index, repository in enumerate(normalized["repositories"]):
        if not git_actions:
            break
        zone = _zone(repository["root"])
        owner = "codex" if zone == "loom" else ("cloud-code" if zone in {"argus", "nostromo"} else None)
        if agent != "operator" and owner != agent:
            violations.append(_issue("git-zone-forbidden", f"agent '{agent}' may not perform Git actions in zone '{zone}'", f"repositories[{index}].root"))

    operator_actions = {
        "codex": {"write", "memory-write", "process", "network", "git-commit", "git-push", "delete"},
        "cloud-code": {"process", "git-commit", "git-push", "delete"},
        "auditor": {"network"},
        "argus": {"process"},
        "nostromo": {"process"},
        "ci": set(),
        "operator": set(),
    }[agent]
    for action in sorted(actions & operator_actions):
        reasons.append(_issue("operator-gate", f"action '{action}' requires operator approval", "actions"))
    if secret_reads and actions & {"network", "report", "dashboard", "git-push"}:
        for _, secret, issue_path in secret_reads:
            violations.append(_issue(
                "secret-exfil-forbidden",
                f"secret-like read combined with outbound/reporting action is rejected by Gate policy ({secret})",
                issue_path,
            ))

    required = set()
    loom_writes = [path for path in normalized["write_paths"] if _zone(path) == "loom"]
    if loom_writes:
        required |= {"syntax", "citadel", "docs-parity", "git-clean"}
    if any(_under(path, _LOOM_ROOT + "/docs") for path in loom_writes):
        required.add("live-site")
    if "git-push" in actions:
        required |= {"git-sync", "operator-approval"}
    if "backup" in actions:
        required.add("backup")
    for item in sorted(required - evidence):
        violations.append(_issue("missing-evidence", f"action set requires evidence '{item}'", "evidence_required"))

    reasons = _unique_issues(reasons)
    violations = _unique_issues(violations)
    decision = "reject" if violations else ("operator-required" if reasons else "accept")
    return _decision(decision, digest, reasons, violations)


def _unique_issues(items):
    keyed = {(item["path"], item["code"], item["message"]): item for item in items}
    return [keyed[key] for key in sorted(keyed)]


def _decision(decision, digest, reasons, violations):
    return {
        "schema": DECISION_SCHEMA,
        "decision": decision,
        "advisory": True,
        "manifest_sha256": digest,
        "policy": POLICY_ID,
        "reasons": _unique_issues(reasons),
        "violations": _unique_issues(violations),
    }


def _secret_issue_class(code, message):
    if code == "secret-exfil-forbidden":
        return "SecretExfil"
    match = re.search(r"\(([^()]+)\)\s*$", message)
    return match.group(1) if match else "SecretRead"


def _secret_issue_disposition(code):
    if code in {"secret-read-operator-required", "secret-access-operator-required"}:
        return "approval-required"
    return "blocked"


def build_gate_diagnostics(manifest):
    """Return redacted, operator-facing diagnostics for a Gate manifest."""
    decision = evaluate_manifest(manifest)
    secret_lanes = []
    for item in decision["reasons"] + decision["violations"]:
        code = item["code"]
        if not code.startswith("secret-"):
            continue
        secret_lanes.append({
            "field": item["path"],
            "code": code,
            "class": _secret_issue_class(code, item["message"]),
            "disposition": _secret_issue_disposition(code),
        })
    return {
        "schema": DIAGNOSTICS_SCHEMA,
        "advisory": True,
        "decision": decision["decision"],
        "policy": decision["policy"],
        "manifest_sha256": decision["manifest_sha256"],
        "secret_lane_count": len(secret_lanes),
        "secret_lanes": sorted(
            secret_lanes,
            key=lambda item: (
                item["field"],
                item["disposition"] != "approval-required",
                item["code"],
            ),
        ),
    }


def _has_secret_issue(decision):
    return any(item["code"].startswith("secret-") for item in decision["reasons"] + decision["violations"])


def _validate_secret_evidence_detail(detail, path, findings):
    lowered = detail.lower()
    if not lowered.startswith(_SECRET_EVIDENCE_PREFIXES):
        findings.append(_finding(path, "unsafe-secret-evidence", "secret-lane evidence must start with 'secret lane approved:' or 'secret lane blocked:'"))
    if "/" in detail or "\\" in detail or "=" in detail:
        findings.append(_finding(path, "unsafe-secret-evidence", "secret-lane evidence must not contain raw paths or secret assignments"))


def _validate_observation(observation):
    findings = []
    if not isinstance(observation, dict):
        return None, [_finding("observation", "expected-object", "observation must be an object")]
    for key in sorted(set(observation) - _OBSERVATION_KEYS):
        findings.append(_finding(key, "unknown-field", f"unknown observation field '{key}'"))
    for key in sorted(_OBSERVATION_KEYS - set(observation)):
        findings.append(_finding(key, "missing-field", f"missing required observation field '{key}'"))
    normalized = {}
    schema = _text(observation.get("schema"), "schema", findings)
    if schema is not None and schema != OBSERVATION_SCHEMA:
        findings.append(_finding("schema", "unsupported-schema", f"expected '{OBSERVATION_SCHEMA}'"))
    normalized["schema"] = schema
    result = _text(observation.get("result"), "result", findings)
    if result is not None and result not in _OBSERVATION_RESULTS:
        findings.append(_finding("result", "unknown-result", f"unknown result '{result}'"))
    normalized["result"] = result
    normalized["files_changed"] = _path_list(observation.get("files_changed"), "files_changed", findings)
    normalized["actions_observed"] = _enum_list(observation.get("actions_observed"), "actions_observed", ACTIONS, findings)

    repositories = observation.get("repositories")
    normalized_repositories = []
    if not isinstance(repositories, list):
        findings.append(_finding("repositories", "expected-array", "expected an array"))
    else:
        for index, repository in enumerate(repositories):
            base = f"repositories[{index}]"
            if not _closed_object(repository, base, {"root", "before_head", "after_head"}, findings):
                continue
            roots = _path_list([repository["root"]], base + ".root", findings)
            before = _text(repository["before_head"], base + ".before_head", findings)
            after = _text(repository["after_head"], base + ".after_head", findings)
            if before is not None and not _HEX_HEAD.fullmatch(before):
                findings.append(_finding(base + ".before_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            if after is not None and not _HEX_HEAD.fullmatch(after):
                findings.append(_finding(base + ".after_head", "invalid-git-head", "expected 7-40 lowercase hexadecimal characters"))
            normalized_repositories.append({"root": roots[0] if roots else None, "before_head": before, "after_head": after})
        roots = [item["root"] for item in normalized_repositories if item["root"] is not None]
        for root in sorted({root for root in roots if roots.count(root) > 1}):
            findings.append(_finding("repositories", "duplicate-repository", f"duplicate observation repository '{root}'"))
    normalized["repositories"] = sorted(normalized_repositories, key=lambda item: item["root"] or "")

    evidence = observation.get("evidence")
    normalized_evidence = []
    if not isinstance(evidence, list):
        findings.append(_finding("evidence", "expected-array", "expected an array"))
    else:
        for index, item in enumerate(evidence):
            base = f"evidence[{index}]"
            if not _closed_object(item, base, {"kind", "status", "detail"}, findings):
                continue
            kind = _text(item["kind"], base + ".kind", findings)
            status = _text(item["status"], base + ".status", findings)
            detail = _text(item["detail"], base + ".detail", findings)
            if kind is not None and kind not in EVIDENCE:
                findings.append(_finding(base + ".kind", "unknown-evidence", f"unknown evidence '{kind}'"))
            if status is not None and status not in _EVIDENCE_STATUS:
                findings.append(_finding(base + ".status", "unknown-evidence-status", f"unknown evidence status '{status}'"))
            if kind == "secret-lane" and detail is not None:
                _validate_secret_evidence_detail(detail, base + ".detail", findings)
            normalized_evidence.append({"kind": kind, "status": status, "detail": detail})
        kinds = [item["kind"] for item in normalized_evidence if item["kind"] is not None]
        for kind in sorted({kind for kind in kinds if kinds.count(kind) > 1}):
            findings.append(_finding("evidence", "duplicate-evidence", f"duplicate evidence '{kind}'"))
    normalized["evidence"] = sorted(normalized_evidence, key=lambda item: item["kind"] or "")
    return (None if findings else normalized), findings


def build_receipt(manifest, observation):
    """Build a deterministic advisory receipt from declared, self-reported evidence."""
    validation = validate_manifest(manifest)
    normalized_observation, findings = _validate_observation(observation)
    if not validation["valid"]:
        findings = list(validation["findings"]) + findings
    if findings:
        return _receipt_validation(None, findings)

    normalized_manifest = validation["normalized_manifest"]
    decision = evaluate_manifest(normalized_manifest)
    result = normalized_observation["result"]
    findings = []
    if decision["decision"] == "reject" and result == "completed":
        findings.append(_finding("result", "rejected-task-completed", "a policy-rejected task cannot produce a completed receipt"))

    declared_actions = set(normalized_manifest["actions"])
    for action in sorted(set(normalized_observation["actions_observed"]) - declared_actions):
        findings.append(_finding("actions_observed", "undeclared-action", f"observed action '{action}' was not declared"))

    scopes = normalized_manifest["write_paths"]
    for index, path in enumerate(normalized_observation["files_changed"]):
        if not any(_under(path, scope) for scope in scopes):
            findings.append(_finding(f"files_changed[{index}]", "changed-file-outside-scope", f"changed file '{path}' was not declared by the manifest"))

    expected_repositories = {item["root"]: item for item in normalized_manifest["repositories"]}
    observed_repositories = {item["root"]: item for item in normalized_observation["repositories"]}
    for root in sorted(set(expected_repositories) - set(observed_repositories)):
        findings.append(_finding("repositories", "missing-repository-observation", f"missing observation for repository '{root}'"))
    for root in sorted(set(observed_repositories) - set(expected_repositories)):
        findings.append(_finding("repositories", "unexpected-repository", f"unexpected observation repository '{root}'"))
    for root in sorted(set(expected_repositories) & set(observed_repositories)):
        if observed_repositories[root]["before_head"] != expected_repositories[root]["expected_head"]:
            findings.append(_finding("repositories", "stale-before-head", f"repository '{root}' before_head does not match manifest expected_head"))
    if result == "completed" and "git-commit" in normalized_observation["actions_observed"]:
        if not any(item["before_head"] != item["after_head"] for item in normalized_observation["repositories"]):
            findings.append(_finding("repositories", "commit-without-new-head", "completed git-commit must change at least one repository head"))

    evidence = {item["kind"]: item for item in normalized_observation["evidence"]}
    if result == "completed":
        required = set(normalized_manifest["evidence_required"])
        if decision["decision"] == "operator-required":
            required.add("operator-approval")
        if _has_secret_issue(decision):
            required.add("secret-lane")
        for kind in sorted(required):
            item = evidence.get(kind)
            if item is None:
                findings.append(_finding("evidence", "missing-evidence", f"missing required evidence '{kind}'"))
            elif item["status"] != "pass":
                findings.append(_finding("evidence", "failed-evidence", f"required evidence '{kind}' has status '{item['status']}'"))
    elif _has_secret_issue(decision):
        item = evidence.get("secret-lane")
        if item is None:
            findings.append(_finding("evidence", "missing-evidence", "missing required evidence 'secret-lane'"))
        elif item["status"] != "pass":
            findings.append(_finding("evidence", "failed-evidence", f"required evidence 'secret-lane' has status '{item['status']}'"))

    if findings:
        return _receipt_validation(None, findings)
    body = {
        "schema": RECEIPT_SCHEMA,
        "advisory": True,
        "manifest_sha256": validation["manifest_sha256"],
        "policy": decision["policy"],
        "policy_decision": decision["decision"],
        "agent": normalized_manifest["agent"],
        "result": result,
        "repositories": normalized_observation["repositories"],
        "files_changed": normalized_observation["files_changed"],
        "actions_observed": normalized_observation["actions_observed"],
        "evidence": normalized_observation["evidence"],
    }
    body["receipt_sha256"] = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
    return _receipt_validation(body, [])


def _receipt_validation(receipt, findings):
    return {
        "schema": RECEIPT_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "receipt": receipt,
        "findings": _unique_issues(findings),
    }
