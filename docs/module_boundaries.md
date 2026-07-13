# LOOM module boundaries

Status: production-readiness contract for keeping `loom.py` as a stable public
facade while implementation code continues moving into focused modules.

## Public facade

`loom.py` remains the compatibility surface imported by users, the playground,
Gate clients, tests, and published docs. Public functions exposed there should
delegate into extracted modules rather than re-growing independent copies of
the same behavior.

## Extracted modules

Current stable boundaries:

| Module | Boundary |
| --- | --- |
| `loom_parse.py` | tokenization, parsing, and source spans |
| `loom_checker.py` | static effect/trust/capability checking |
| `loom_runtime.py` | interpreter runtime and capability contexts |
| `loom_codegen.py` | portable Python and JavaScript backends |
| `loom_wasm.py` | WebAssembly/WAT backend and ABI runtime |
| `loom_cli.py` | CLI and machine-readable verdict surface |
| `loom_gate.py` | Gate manifest, policy, diagnostics, and advisory receipt logic |
| `loom_observer.py` | read-only Git observation collection |
| `loom_evidence.py` | CI evidence collection |
| `loom_approval.py` | signed one-use operator approval lifecycle |
| `loom_executor.py` | claimed execution and process-attempt lifecycle |

## Gate boundary rule

Gate behavior must have one implementation truth in `loom_gate.py`. The public
facade in `loom.py` may expose:

- `validate_manifest`
- `evaluate_manifest`
- `build_gate_diagnostics`
- `build_receipt`

but those functions must delegate to the extracted Gate module and preserve the
same stable schemas:

- `loom-gate-manifest-validation/v1`
- `loom-gate-decision/v1`
- `loom-gate-diagnostics/v1`
- `loom-gate-receipt-validation/v1`
- `loom-gate-receipt/v1`

The standalone browser bundle in `docs/loom.py` may inline the same stable
facade so it can run without development-only module imports in Pyodide.

A future migration may split Gate further, but it must keep the public facade
stable and pin the new boundary before deleting the old one.

## Citadel pin

The citadel pins this contract by checking that development `loom.py` is backed
by the extracted `loom_gate` module and that facade calls match direct module
calls for manifest validation, policy evaluation, redacted diagnostics, and
receipt building. It also checks that the standalone browser bundle preserves
the same public schemas without importing development-only modules.
