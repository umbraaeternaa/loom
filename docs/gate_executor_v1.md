# LOOM Gate host executor shim v1

Status: bounded host contract; no command execution.

`loom.plan_claimed_execution(manifest, challenge, approval, claim, actions)`
builds a deterministic execution plan for a signed approval that has already
been claimed. The plan is not an executor process and does not run shell,
network, tools, or repository commands. It verifies the signed approval against
the pinned operator public key, checks that the claim matches the manifest and
challenge, and rejects actions that were not declared in the manifest.

The plan contains only bounded host-facing facts:

- manifest, challenge, approval, claim, and plan SHA-256 bindings;
- the exact actions allowed for this execution;
- declared read and write scopes;
- redacted secret-lane metadata, never raw secret paths or values;
- an explicit `no-shell/no-network-by-default` executor boundary.

`loom.finish_claimed_execution(...)` accepts that exact plan after the trusted
host has attempted the bounded action. It collects read-only observation facts,
validates that observed actions are within the plan, and finalizes the already
claimed approval through `loom.finish_claimed_receipt(...)`.

This shim closes a practical integration gap without giving an agent ambient
authority. The agent may request and inspect a plan; the trusted host remains
responsible for keeping underlying credentials, filesystem writes, network, and
tool execution outside the agent process.
