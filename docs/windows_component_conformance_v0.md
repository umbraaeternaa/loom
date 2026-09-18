# LOOM Windows Component Conformance v0

Status: additive native conformance profile for Component Model construction,
execution, refusal, and same-host release reproducibility on Windows. It is
non-authorizing and is not a Windows host-security certification.

## Purpose

Windows Core Conformance v0 proves the portable language core. This profile
closes the next independent question: can one exact LOOM revision build,
verify, execute, and reproducibly rebuild its real WebAssembly Components on a
native `windows-2025` runner without replacing any step with a mock?

The certifying runner is `tools/windows_component_conformance.py`. Its
`--self-test` mode exercises the same Component contracts on a supported local
host but emits no witness and makes no Windows claim.

## Closed toolchain

The CI job downloads official Windows x86_64 archives and checks both archive
and extracted executable SHA-256 identities before use:

- wasm-tools `1.257.1` archive
  `6d9bc36132f25a063dfb5e18bb8a025c7f8b8b01f139eb976a32081cad1c6137`
  and `wasm-tools.exe`
  `51698e3975100f5ee65a72e998eb958fd254e3bed99b9ba2ac3ac0025088a4b8`;
- Wasmtime `48.0.0` archive
  `d6cc742660e9edf35c92b47179808802f01eca3bf60ab4b0ac723c167592131f`
  and `wasmtime.exe`
  `cadcc7480082a372256d6dae7b2855aca3d74edbfa844838b4a33076e5ec40b8`;
- Cargo/rustc `1.93.0` with host `x86_64-pc-windows-msvc` and the MSVC linker
  environment supplied by the pinned runner image.

Missing tools, version drift, hash drift, host drift, absent Cargo registry
sources, or an unavailable linker fails closed.

## Required proof surface

The job completes all of these without a skip or fallback:

1. build the repository-owned Pure Component adapter twice and require exact
   artifact and byte equality;
2. independently verify the Component with pinned wasm-tools and Wasmtime;
3. invoke the real Component under Wasmtime and recover the canonical JSON
   result;
4. reject a byte-tampered Pure Component;
5. repeat deterministic build, independent verification, real execution, and
   tamper refusal for the effectful `IO` Component adapter;
6. build the Pure release builder twice from repository source with Cargo
   `--offline --frozen --release`, isolated target directories, path remapping,
   and exact dependency-source identities;
7. require builder, artifact, and Component byte equality, then independently
   repeat the full two-build release verification.

The Windows implementation uses native `.exe` identities, `TEMP/TMP/TMPDIR`,
an isolated Cargo home backed by a registry-source junction, inherited
MSVC `INCLUDE/LIB/LIBPATH/SystemRoot`, and encoded Rust flags. macOS/Linux keep
their existing restricted POSIX environment.

## Witness

Only the pinned GitHub Actions job may write
`.windows-component-witness/x86_64-pc-windows-msvc.json`. The canonical object
uses schema `loom-windows-component-ci-witness/v0` and binds the exact commit,
workflow run, runner, tool executable hashes, checks, Component identities,
release evidence identity, portable release Component bytes, and its own
SHA-256.

The uploaded artifact is `windows-component-conformance-v0`. It is
`test_only`, carries `authorization: none`, and is not an approval, release
signature, deployment instruction, or SLSA claim.

## Deliberate boundary

This profile does **not** certify Gate custody, ACL/SID ownership, reparse-point
defense, AppContainer, Job Object isolation, secret handling, bounded host
execution, or operator presence.

Windows is intentionally not inserted into
[Component Release Evidence Federation v0](component_release_federation_v0.md).
That schema remains exactly macOS arm64 plus Linux x86_64. A later additive
federation version must explicitly validate this Windows witness and prove
three-platform portable-artifact equality before such a claim is allowed.

## Commands

Portable non-certifying check:

```console
python3 tools/windows_component_conformance.py --self-test
```

Certifying CI invocation:

```console
python tools/windows_component_conformance.py \
  --output .windows-component-witness/x86_64-pc-windows-msvc.json
```

A revision may claim Windows Component Conformance v0 only after its exact
`verify-windows-component` job succeeds and publishes its revision-bound
witness.
