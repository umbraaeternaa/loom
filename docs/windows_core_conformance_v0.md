# LOOM Windows Core Conformance v0

Status: normative conformance profile for the portable language core. It is not
a Windows host-security or Component Model certification.

## Purpose

Windows Core Conformance v0 answers one narrow question with executable
evidence: does one exact LOOM revision preserve its checked language semantics
on a native Windows runner?

The profile runs on GitHub Actions `windows-2025`, CPython 3.12, and Node.js 22.
It builds and installs the repository wheel before testing. The certifying
runner is `tools/windows_core_conformance.py`; a non-Windows host may use only
its explicit `--self-test` mode, which emits no witness and makes no Windows
claim.

## Required proof surface

The Windows job must complete all of these without a skip or fallback:

1. parse valid source and reject malformed source;
2. accept an honest Pure function and reject hidden `IO`;
3. agree across the interpreter, generated Python, generated JavaScript, and
   binary WebAssembly for recursive scalar code;
4. agree across all four execution backends for strings, lists, records,
   variants, and nested values;
5. agree across all four execution backends when `with` reinterprets `Net`
   through a Pure handler;
6. emit real WASM bytes and WAT with the expected checked ASM lowering;
7. execute the repo-local JSON/text CLI contract;
8. install the wheel and invoke its `loom` console entry point;
9. run all pinned deterministic fuzz seeds with `--require-node`.

Missing Node.js is a failure. `--require-node` and `--no-node` are mutually
exclusive. The Windows job may not turn JavaScript or WebAssembly execution
into compile-only coverage.

Generated JavaScript and the Node WebAssembly harness are executed from a
private temporary `.js` file. They must not be transported through `node -e`:
the complete generated program can exceed the Windows process argument-length
limit even though the same language program is valid.

## Witness

Only certifying mode on the pinned Windows CI environment may write
`.windows-core-witness/x86_64-pc-windows-msvc.json`. The canonical JSON object
uses schema `loom-windows-core-ci-witness/v0` and binds:

- the exact lowercase 40-hex Git commit;
- repository, workflow, job, runner, run ID, and run attempt;
- exact Python and Node versions;
- every required core check and its result;
- an explicit capability scope and SHA-256 of the witness object.

The uploaded artifact is named `windows-core-conformance-v0`. It is
`test_only`, has `authorization: none`, and is not an operator approval,
release signature, SLSA claim, or cross-platform federation result.

## Closed boundary

This profile certifies the parser/checker, interpreter, portable Python and
JavaScript backends, core WASM/WAT, CLI, wheel installation, and deterministic
core fuzzing. It does **not** certify:

- WIT Component construction or Wasmtime Component execution on Windows;
- Gate custody, host mediation, bounded process execution, or secret handling;
- Windows ACL/SID ownership, reparse-point defense, AppContainer, or Job Object
  isolation;
- equality with macOS/Linux Component release witnesses;
- operator presence, authorization, or production deployment.

Those require separate additive Windows Component and Windows Host Security
profiles. Existing macOS/Linux Component Federation v0 remains unchanged until
a later federation version explicitly admits and verifies the Windows witness.

## Commands

Portable non-certifying harness check:

```console
python3 tools/windows_core_conformance.py --self-test
```

The certifying CI invocation is deliberately stricter:

```console
python tools/windows_core_conformance.py \
  --output .windows-core-witness/x86_64-pc-windows-msvc.json
```

A revision may claim Windows Core Conformance v0 only after its own
`verify-windows-core` job succeeds and publishes the exact-revision witness.
