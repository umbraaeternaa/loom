#!/usr/bin/env python3
"""Deterministic, advisory task manifests for LOOM Gate phase 1."""

import hashlib
import json
import re
import unicodedata


MANIFEST_SCHEMA = "loom-gate-manifest/v1"
VALIDATION_SCHEMA = "loom-gate-manifest-validation/v1"
AGENTS = frozenset({"codex", "cloud-code", "auditor", "argus", "nostromo", "ci", "operator"})
ROLES = frozenset({"code", "organism", "audit", "night", "trace", "operator"})
ACTIONS = frozenset({
    "read", "write", "test", "process", "network", "git-commit",
    "git-push", "delete", "backup", "memory-write", "dashboard", "report",
})
EVIDENCE = frozenset({
    "syntax", "citadel", "docs-parity", "fuzz", "git-clean", "git-sync",
    "live-site", "backup", "operator-approval", "audit",
})
_TOP_KEYS = frozenset({
    "schema", "agent", "task", "repositories", "read_paths", "write_paths",
    "actions", "evidence_required",
})
_HEX_HEAD = re.compile(r"^[0-9a-f]{7,40}$")


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


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_manifest(manifest):
    """Validate and hash a phase-1 manifest without reading or enforcing host state."""
    findings = []
    if not isinstance(manifest, dict):
        findings.append(_finding("$", "expected-object", "manifest must be an object"))
        return _validation(None, findings)

    for key in sorted(set(manifest) - _TOP_KEYS):
        findings.append(_finding(key, "unknown-field", f"unknown field '{key}'"))
    for key in sorted(_TOP_KEYS - set(manifest)):
        findings.append(_finding(key, "missing-field", f"missing required field '{key}'"))

    normalized = {}
    schema = _text(manifest.get("schema"), "schema", findings)
    if schema is not None and schema != MANIFEST_SCHEMA:
        findings.append(_finding("schema", "unsupported-schema", f"expected '{MANIFEST_SCHEMA}'"))
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
