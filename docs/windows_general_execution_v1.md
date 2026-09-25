# Windows General Adapter Execution v1

Status: experimental, additive, test-only native execution profile.

This profile extends the fixed Windows Bounded Execution Integration v0 with
one hash-pinned PE target selected by an exact signed Invocation Binding. It
does not replace v0 and does not grant production authority.

## Closed execution path

1. Action Approval v2 signs the adapter hash, target hash, target arguments,
   exact environment commitments, stdin digest, timeout, and denied
   shell/network policy.
2. The existing atomic Windows ledger consumes the Approval once and records
   Claim, Mediation, and Reservation states.
3. `loom_windows_general.py` independently remeasures the target and encodes a
   length-prefixed binary request. Target identity, arguments, environment,
   stdin, and limits are never passed in adapter command-line arguments.
4. The native adapter rejects reparse points, pins target identity, checks the
   approved SHA-256, and copies the bytes into fresh private AppContainer
   custody.
5. It rechecks snapshot bytes, owner/DACL, and handle identity before launch.
6. The snapshot starts in a zero-capability AppContainer under a Job Object
   with active-process limit `1` and kill-on-close. Only three explicitly
   listed standard-I/O handles are inherited.
7. The adapter supplies only the approved environment plus private
   `LOCALAPPDATA`, `TEMP`, and `TMP` paths. It does not copy the parent
   environment.
8. Stdout and stderr are drained while the process runs. The whole Job Object
   is terminated immediately on timeout or combined output overflow.
9. A bounded native observation is hash-linked into a receipt and atomically
   closes the reserved ledger row as one terminal Execution and Result.

## Native certification

The `verify-windows-general-execution` job is restricted to GitHub Actions
`windows-2025`, Python 3.12, and native x64 MSVC. It requires byte-identical
two-build `/Brepro` results for both adapter and target, then exercises:

- one complete signed Approval-to-Result success;
- one-use Approval replay refusal;
- target hash tamper refusal;
- target reparse-point refusal;
- live loopback network denial;
- child-process denial;
- streaming output-limit termination; and
- wall-clock timeout termination.

The resulting `loom-windows-general-execution-ci-witness/v1` is revision-bound,
test-only, and non-authorizing. Portable hosts may run:

```console
python3 tools/windows_general_execution_conformance.py --self-test
```

That checks schemas, framing, hashes, bounds, and fail-closed routing. It does
not make a Windows-native claim.

## Deliberate bounds and non-claims

- v1 accepts Windows x86_64 PE executables, at most 64 arguments and 64 exact
  environment entries, 64 KiB stdin, 1 MiB combined output, and a five-minute
  timeout.
- Empty argument/environment strings are outside this first closed profile.
- Network and subprocess creation are denied rather than selectively granted.
- The target is a native executable snapshot, not a script, shell command,
  package resolver, installer, or DLL dependency bundle.
- The cumulative component walk and final-handle checks materially reduce path
  substitution risk but are not claimed as an NT-namespace formal proof.
- The CI test key grants no authority, proves no operator presence, and is not
  a production signing identity.
- Successful CI certifies this bounded implementation on the exact revision;
  it does not claim every Windows edition, architecture, executable, or future
  AppContainer policy.
