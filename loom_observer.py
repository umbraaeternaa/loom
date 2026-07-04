#!/usr/bin/env python3
"""Read-only host fact collection for LOOM Gate phase 1."""

import os
from pathlib import Path
import subprocess

import loom_gate


COLLECTION_SCHEMA = "loom-gate-observation-collection/v1"
_TIMEOUT_SECONDS = 5


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _result(observation, findings):
    return {
        "schema": COLLECTION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "read_only": True,
        "observation": observation if not findings else None,
        "findings": loom_gate._unique_issues(findings),
    }


def _git(root, *args):
    env = os.environ.copy()
    env.update({
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "LANG": "C",
    })
    try:
        proc = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", root, *args],
            capture_output=True,
            env=env,
            timeout=_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "git executable not found"
    except subprocess.TimeoutExpired:
        return None, f"git command exceeded {_TIMEOUT_SECONDS}s timeout"
    except OSError as error:
        return None, f"git command unavailable: {error}"
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        return None, detail or f"git exited with status {proc.returncode}"
    return proc.stdout, None


def _decode_paths(data, root, path, findings):
    values = []
    for raw in data.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            findings.append(_finding(path, "non-utf8-git-path", "Git path is not valid UTF-8"))
            continue
        absolute = str((Path(root) / relative).resolve(strict=False))
        if not loom_gate._under(absolute, root):
            findings.append(_finding(path, "changed-path-outside-repository", f"Git reported path outside repository '{root}'"))
            continue
        values.append(absolute)
    return values


def collect_observation(manifest, result, actions_observed, evidence):
    """Collect declared-repository facts without running tasks, tests, hooks, or network."""
    validation = loom_gate.validate_manifest(manifest)
    if not validation["valid"]:
        return _result(None, validation["findings"])

    normalized = validation["normalized_manifest"]
    findings = []
    repositories = []
    changed_files = []
    clean = True

    for index, repository in enumerate(normalized["repositories"]):
        root = repository["root"]
        base = f"repositories[{index}]"
        declared = Path(root)
        if not declared.is_absolute() or not declared.is_dir():
            findings.append(_finding(base + ".root", "repository-unavailable", f"repository root is not an available directory '{root}'"))
            continue

        top_raw, error = _git(root, "rev-parse", "--show-toplevel")
        if error:
            findings.append(_finding(base + ".root", "git-read-failed", error))
            continue
        top = top_raw.decode("utf-8", "replace").strip()
        if top != root or str(declared.resolve()) != root:
            findings.append(_finding(base + ".root", "repository-root-mismatch", f"declared root '{root}' does not match canonical Git root '{top}'"))
            continue

        expected = repository["expected_head"]
        expected_raw, error = _git(root, "rev-parse", "--verify", expected + "^{commit}")
        if error:
            findings.append(_finding(base + ".expected_head", "expected-head-unavailable", error))
            continue
        expected_full = expected_raw.decode("ascii", "replace").strip()

        head_raw, error = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
        if error:
            findings.append(_finding(base + ".root", "head-unavailable", error))
            continue
        head_full = head_raw.decode("ascii", "replace").strip()

        _, ancestor_error = _git(root, "merge-base", "--is-ancestor", expected_full, head_full)
        if ancestor_error:
            findings.append(_finding(base + ".expected_head", "expected-head-not-ancestor", "manifest expected_head is not an ancestor of current HEAD"))
            continue

        short_raw, error = _git(root, "rev-parse", f"--short={len(expected)}", head_full)
        if error:
            findings.append(_finding(base + ".root", "head-unavailable", error))
            continue
        after_head = short_raw.decode("ascii", "replace").strip()

        diff_raw, error = _git(root, "diff", "--no-ext-diff", "--name-only", "-z", expected_full, "--")
        if error:
            findings.append(_finding(base + ".root", "git-diff-failed", error))
            continue
        untracked_raw, error = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
        if error:
            findings.append(_finding(base + ".root", "git-status-failed", error))
            continue
        status_raw, error = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        if error:
            findings.append(_finding(base + ".root", "git-status-failed", error))
            continue

        changed_files.extend(_decode_paths(diff_raw, root, base, findings))
        changed_files.extend(_decode_paths(untracked_raw, root, base, findings))
        repo_clean = not bool(status_raw)
        clean = clean and repo_clean
        repositories.append({"root": root, "before_head": expected, "after_head": after_head})

    supplied_evidence = [item for item in evidence if not (isinstance(item, dict) and item.get("kind") == "git-clean")] if isinstance(evidence, list) else evidence
    if isinstance(supplied_evidence, list):
        supplied_evidence = list(supplied_evidence) + [{
            "kind": "git-clean",
            "status": "pass" if clean and not findings else "fail",
            "detail": "all declared repositories clean" if clean and not findings else "one or more declared repositories dirty or unreadable",
        }]

    observation = {
        "schema": loom_gate.OBSERVATION_SCHEMA,
        "result": result,
        "repositories": repositories,
        "files_changed": sorted(set(changed_files)),
        "actions_observed": actions_observed,
        "evidence": supplied_evidence,
    }
    normalized_observation, observation_findings = loom_gate._validate_observation(observation)
    findings.extend(observation_findings)
    return _result(normalized_observation, findings)
