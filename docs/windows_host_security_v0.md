# LOOM Windows Host Security Substrate v0

Status: local candidate pending acceptance by its exact native Windows CI lane.

Windows Host Security Substrate v0 is a fail-closed, test-only proof surface for
host properties that the portable language and Component profiles cannot prove.
The certifying runner is `tools/windows_host_security_conformance.py`; the
repository-owned native probe is
`tools/windows-host-security/host_security_probe.c`.

## Closed native checks

The `verify-windows-host-security` job runs on `windows-2025` with CPython 3.12
and an explicitly captured x64 `cl.exe`. It requires all six checks:

1. Two clean MSVC `/Brepro` builds produce byte-identical probe executables.
2. The private snapshot owner is the current user SID, its DACL gives no broad
   principal write access, and it explicitly contains the AppContainer SID.
3. Every cumulative path component is opened with
   `FILE_FLAG_OPEN_REPARSE_POINT`; a deliberate symbolic-link fixture must be
   refused.
4. The private executable snapshot is byte-identical to the source probe and
   the opened final-handle identity remains stable during inspection.
5. A zero-capability AppContainer token is proved at runtime and cannot connect
   to an active loopback listener. Its child receives a system-only environment
   block, never the parent CI environment.
6. A Job Object enforces one active process and
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates a live child.

The resulting revision-bound artifact is
`loom-windows-host-security-ci-witness/v0`, uploaded as
`windows-host-security-substrate-v0`. It has `test_only: true` and
`authorization: none`.

## Trust boundary

This substrate does **not** certify LOOM Bounded Execution integration, native
operator presence, or Federation v1. It does not turn a CI witness into an
approval and does not grant a capability. The cumulative Win32 component walk
detects reparse points on each opened component, but it is not a handle-relative
NT namespace resolver and therefore does not claim to eliminate every
path-replacement race. Integration requires a later host adapter that reuses
these properties inside the signed Claim/Mediation/Bounded Execution lifecycle.

## Commands

Portable schema and tamper-refusal self-test:

```console
python3 tools/windows_host_security_conformance.py --self-test
```

Only the pinned GitHub Actions job may run certifying mode:

```console
python tools/windows_host_security_conformance.py \
  --output .windows-host-security-witness/x86_64-pc-windows-msvc.json
```

Outside the exact Windows CI environment, certifying mode fails closed and
must not emit a witness.

## Windows primitives

The native profile uses documented Windows primitives:

- [AppContainer isolation](https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation)
- [Launching an AppContainer process](https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer)
- [`CreateAppContainerProfile`](https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
- [`CreateEnvironmentBlock`](https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createenvironmentblock)
- [Job Objects](https://learn.microsoft.com/windows/win32/procthread/job-objects)
- [`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [`FILE_FLAG_OPEN_REPARSE_POINT`](https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew)
