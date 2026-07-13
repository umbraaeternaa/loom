#!/usr/bin/env python3
"""End-to-end process-only LOOM Gate CLI lifecycle recipe.

This example is intentionally not a shell runner. It shows the JSON-file CLI
handoff a trusted host can use around its own bounded process attempt:

claim -> plan -> host attempt -> process-attempt dry-run -> process-finish
"""

import json
import contextlib
import io
from pathlib import Path

import loom


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True))


def run_cli_json(argv):
    """Run the LOOM CLI in-process and return its JSON verdict."""
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        loom._loom_cli.cli(argv, loom._CLI_FRONTEND)
    return json.loads(stream.getvalue())


def run_process_cli_lifecycle(workdir, manifest, challenge, approval, host_attempt):
    """Run the process-only Gate lifecycle through the public CLI adapter.

    `host_attempt(plan)` is controlled by the trusted host. It must return a
    closed `loom-gate-host-attempt/v1` object. This function writes only JSON
    handoff files inside `workdir`; it never executes the process action.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    manifest_file = workdir / "manifest.json"
    challenge_file = workdir / "challenge.json"
    approval_file = workdir / "approval.json"
    claim_file = workdir / "claim.json"
    plan_file = workdir / "plan.json"
    attempt_file = workdir / "attempt.json"

    write_json(manifest_file, manifest)
    write_json(challenge_file, challenge)
    write_json(approval_file, approval)

    claim_result = run_cli_json([
        "gate-claim",
        str(manifest_file),
        str(challenge_file),
        str(approval_file),
        "--format=json",
    ])
    if not claim_result["valid"]:
        return claim_result
    write_json(claim_file, claim_result["claim"])

    plan_result = run_cli_json([
        "gate-plan",
        str(manifest_file),
        str(challenge_file),
        str(approval_file),
        str(claim_file),
        "process",
        "--format=json",
    ])
    if not plan_result["valid"]:
        return plan_result
    write_json(plan_file, plan_result["plan"])

    attempt = host_attempt(plan_result["plan"])
    write_json(attempt_file, attempt)

    dry_run_result = run_cli_json([
        "gate-process-attempt",
        str(plan_file),
        str(attempt_file),
        "--format=json",
    ])
    if not dry_run_result["valid"]:
        return dry_run_result

    return run_cli_json([
        "gate-process-finish",
        str(manifest_file),
        str(challenge_file),
        str(approval_file),
        str(claim_file),
        str(plan_file),
        str(attempt_file),
        "--format=json",
    ])
