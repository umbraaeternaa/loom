# LOOM Windows Bounded Execution Integration v0

Status: certified only when the exact revision passes its native Windows CI
lane and emits a valid revision-bound witness artifact.

Windows Bounded Execution Integration v0 is a fail-closed, test-only fixed
integration profile. It proves that one real LOOM Action Approval v2 can move
through an atomic Windows claim, exact host mediation, native AppContainer and
Job Object execution, and one terminal Result without replay.

The profile is implemented by:

- `loom_windows_execution.py`, which owns the closed Windows lifecycle schemas,
  canonical hashes, atomic SQLite state transitions, and cross-link validation;
- `tools/windows_bounded_execution_conformance.py`, which creates and verifies
  a real RSA-signed Action Approval v2 and drives the complete lifecycle;
- `tools/windows-bounded-execution/bounded_execution_adapter.c`, a fixed native
  adapter built from the independently tested Host Security Substrate code.

## Certified lifecycle

The `verify-windows-bounded-execution` job runs on `windows-2025` with CPython
3.12 and an explicitly captured x64 `cl.exe`. It must prove all six checks:

1. The existing LOOM verifier accepts a cryptographically valid, short-lived
   Action Approval v2 for the exact adapter bytes, argv, working directory,
   environment commitments, canonical stdin, timeout, shell denial, and network
   denial.
2. An atomic SQLite claim consumes the approval once; a second claim is
   refused.
3. Mediation rebinds the built adapter SHA-256, exact environment values and
   exact stdin bytes to the approved Invocation Binding.
4. Two clean `/Brepro` builds are byte-identical, and the fixed native adapter
   proves SID/DACL custody, reparse refusal, a private byte-identical snapshot,
   a zero-capability AppContainer, real loopback-network denial, child-process
   denial, and Job Object containment.
5. Timeout and output limits, exit status, duration, and stdout/stderr hashes
   are committed into a native receipt and a terminal Windows Result.
6. Replaying either the approval claim or terminalization is refused, and
   tampered native isolation evidence invalidates the witness.

The emitted `loom-windows-bounded-execution-ci-witness/v0` artifact carries the
request, test public key, signed approval validation, and every downstream
artifact, so the signature and cross-links are independently checkable. It is
uploaded as `windows-bounded-execution-integration-v0`, revision-bound,
`test_only: true`, and `authorization: none`.

## Trust boundary

This is not a general-purpose Windows executor. The adapter intentionally runs
one repository-owned fixed integration action; it does not accept an arbitrary
program path or command from an agent. The witness demonstrates that the real
Approval-to-Result chain composes with real Windows isolation primitives. It
does not itself authorize a production action.

Native operator presence, production key custody, a handle-relative NT
namespace resolver, arbitrary adapter execution, and Federation v1 remain
outside this profile. Existing POSIX `loom-action-bounded-execution/v0`
artifacts and APIs are unchanged; Windows uses additive schemas instead of
pretending that Unix UID/GID/mode/inode evidence exists on Windows.

## Commands

Portable schema and tamper-refusal self-test:

```console
python3 tools/windows_bounded_execution_conformance.py --self-test
```

Only the pinned GitHub Actions job may run certifying mode:

```console
python tools/windows_bounded_execution_conformance.py \
  --output .windows-bounded-execution-witness/x86_64-pc-windows-msvc.json
```

Outside the exact Windows CI environment, certifying mode fails closed and
must not emit a witness.
