# LOOM Gate advisory receipt v1

Status: deterministic, observation-checked, and non-enforcing.

`loom.build_receipt(manifest, observation)` binds a validated manifest, its
advisory policy decision, and a closed self-reported observation into one
content-addressed receipt.

The observation schema is `loom-gate-observation/v1` and contains:

- result: `completed`, `failed`, or `blocked`;
- repository roots with before/after Git heads;
- changed absolute paths;
- observed actions;
- evidence entries `{kind, status, detail}`, where status is `pass`, `fail`,
  or `not-run`.

For a completed result, observed actions must be declared, changed files must
be within a declared write scope, repository roots and before-heads must match
the manifest, a completed commit must change a head, and every required
evidence item must pass. An `operator-required` decision additionally requires
passing `operator-approval` evidence. A rejected task cannot claim completion,
but may produce an honest `blocked` or `failed` receipt.

Successful output embeds `loom-gate-receipt/v1` and `receipt_sha256`, computed
over canonical receipt JSON before the hash field is added. Invalid output uses
`loom-gate-receipt-validation/v1`, contains no receipt, and reports stable
findings.

Every result remains `advisory: true`: v1 verifies the supplied observation but
does not independently read Git, inspect a real diff, run tests, authenticate
operator approval, intercept commands, or write receipt files.
