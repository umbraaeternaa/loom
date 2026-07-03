# LOOM Gate manifest v1

Status: advisory, deterministic, and non-enforcing.

`loom.validate_manifest(value)` validates a task declaration without reading or
changing host state. A valid manifest is normalized, serialized as compact JSON
with sorted keys, and identified by the SHA-256 of those UTF-8 bytes.

## Required shape

```json
{
  "schema": "loom-gate-manifest/v1",
  "agent": {"id": "codex", "role": "code"},
  "task": {"summary": "Describe the task", "intent": "Explain why"},
  "repositories": [
    {"root": "/Users/macbook/Projects/loom", "expected_head": "cecfaf8", "require_clean": true}
  ],
  "read_paths": ["/Users/macbook/Projects/loom"],
  "write_paths": ["/Users/macbook/Projects/loom/loom_gate.py"],
  "actions": ["read", "write", "test"],
  "evidence_required": ["citadel", "docs-parity", "git-sync"]
}
```

Objects are closed: unknown and missing fields are findings. Agents, roles,
actions, and evidence names come from closed v1 registries. Git heads are 7-40
lowercase hexadecimal characters. Paths must be absolute and may not contain
`..` or `~`. Duplicate set-like entries are rejected rather than silently
changing the declaration.

## Validation result

The result schema is `loom-gate-manifest-validation/v1`. A valid result carries
the normalized manifest and `manifest_sha256`. An invalid result carries neither
and reports stable `{path, code, message}` findings.

Every v1 result says `"advisory": true`. Validation proves only that the
declaration is unambiguous and content-addressed. It does not inspect Git,
authorize an agent, intercept a command, or confine host tools. Those are later
Gate stages and must not be claimed by this contract.
