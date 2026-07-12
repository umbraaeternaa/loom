#!/usr/bin/env python3
"""Process-only LOOM Gate lifecycle recipe for trusted hosts.

This example is intentionally not a shell runner. The trusted host supplies the
`host_attempt` callback and keeps real process/tool authority outside LOOM and
outside the agent process.
"""

import loom


def run_process_lifecycle(manifest, challenge, approval, host_attempt):
    """Claim approval, build a process-only plan, and finalize the host result.

    `host_attempt(plan)` is controlled by the trusted host. It should return a
    pair `(result, evidence)`, where result is usually `"completed"` or
    `"failed"` and evidence is a JSON-safe list of receipt evidence items.
    """
    claim_result = loom.claim_operator_approval(manifest, challenge, approval)
    if not claim_result["valid"]:
        return claim_result

    plan_result = loom.plan_process_execution(
        manifest,
        challenge,
        approval,
        claim_result["claim"],
    )
    if not plan_result["valid"]:
        return plan_result

    result, evidence = host_attempt(plan_result["plan"])
    return loom.finish_process_execution(
        manifest,
        challenge,
        approval,
        claim_result["claim"],
        plan_result["plan"],
        result,
        evidence,
    )
