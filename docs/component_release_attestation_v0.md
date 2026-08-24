# LOOM Signed Reproducible Component Release Attestation v0

Status: implemented for the modular host surface, deterministic, externally
signed, independently rebuildable, fail-closed, and non-authorizing.

This contract closes the first builder-provenance gap left by
[Exact Component Adapter Artifact v0](component_adapter_v0.md). A builder
executable hash alone says which binary ran; it does not show that the binary
came reproducibly from the repository-owned Rust source. Component Release
Attestation v0 performs two clean, frozen, offline Cargo builds into separate
target directories, requires byte-identical builder executables, uses each
builder to emit the Component, independently verifies both Components, and
requires byte-identical artifact JSON and Component bytes.

## Public API

```python
loom.build_component_release_reproducibility_v0(
    boundary, source, core_wasm, package, world, exports,
    builder_source_root=builder_source,
    cargo_executable=cargo,
    rustc_executable=rustc,
    cargo_home=cargo_home,
    wasm_tools_executable=wasm_tools,
    wasmtime_executable=wasmtime,
)

loom.verify_component_release_reproducibility_v0(
    evidence, component, boundary, source, core_wasm, package, world, exports,
    builder_source_root=builder_source,
    cargo_executable=cargo,
    rustc_executable=rustc,
    cargo_home=cargo_home,
    wasm_tools_executable=wasm_tools,
    wasmtime_executable=wasmtime,
)

loom.prepare_component_release_attestation_v0(
    evidence, component, release_name, release_version,
    attester_public_key, attested_at_unix_ms,
)

loom.build_component_release_attestation_v0(
    evidence, component, release_name, release_version,
    attester_public_key, attested_at_unix_ms, signature,
)

loom.verify_component_release_attestation_v0(
    envelope, evidence, component, boundary, source, core_wasm,
    package, world, exports, release_name, release_version,
    attester_public_key,
    builder_source_root=builder_source,
    cargo_executable=cargo,
    rustc_executable=rustc,
    cargo_home=cargo_home,
    wasm_tools_executable=wasm_tools,
    wasmtime_executable=wasmtime,
)
```

The source checkout is an explicit input because a wheel cannot honestly
rebuild repository-owned Rust source that it does not contain. All paths are
host evidence inputs; none are serialized as ambient machine paths.

## Reproducibility evidence

The closed object is `loom-component-release-reproducibility/v0`. It binds:

- exact Boundary, LOOM source, ABI v2 core, WIT, builder source tree, and
  `Cargo.lock` SHA-256 identities;
- exact Cargo and rustc executable hashes, release `1.93.0`, upstream commit,
  supported host triple, and exact `/usr/bin/cc` linker hash/version;
- exact build and verification wasm-tools identities plus the Wasmtime
  verifier identity;
- every active host dependency selected by structured, offline, locked Cargo
  metadata, cross-bound to its registry crate SHA-256 in `Cargo.lock`;
- byte equality between each active locked `.crate` archive and the exact
  extracted source tree selected by Cargo;
- two isolated `--offline --frozen --release` observations with
  `CARGO_INCREMENTAL=0` and `SOURCE_DATE_EPOCH=0`;
- an empty build HOME/TMPDIR, a registry-only isolated `CARGO_HOME`, fixed
  linker path, a closed executable search path, and compiler path remapping to
  the stable `/loom-release-build` prefix;
- the linker's content-hash-default metadata mode; random UUID/build-id flags
  are never supplied, and exact output equality remains the final oracle;
- byte equality of the two builders, two Component artifact objects, and two
  Component binaries;
- the complete Component Adapter Artifact v0 and final Component identity.

Verification does not trust those claims. It repeats both clean Cargo builds,
rechecks locked dependency archives and extracted sources, builds two new
Components, runs the independent Component Adapter verifier twice, and then
requires the newly derived evidence and Component bytes to equal the supplied
release evidence exactly.

## Signed statement

Preparation emits canonical JSON for
[`https://in-toto.io/Statement/v1`](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with predicate type:

```text
https://umbraaeternaa.github.io/loom/attestation/component-release/v0
```

Subjects bind the Component, Component Adapter artifact, reproducibility
evidence, and clean-built Rust builder. The payload type is
`application/vnd.in-toto+json`. LOOM returns exact DSSE PAE signing bytes but
never reads or stores a private key. An external release issuer signs those
bytes with the existing pinned RSA PKCS#1 v1.5 SHA-256 public-key contract.

The verifier checks a trusted signature before parsing the payload, rejects
duplicate keys, noncanonical JSON, oversized input, malformed signatures,
subject drift, evidence drift, and clean-rebuild drift. `keyid` is an
untrusted hint; the supplied pinned public key is the trust root.

## Security and claim boundary

Every result is advisory and `authorization: none`. A valid envelope does not
approve execution, grant WASI, authorize publication, transfer key custody, or
replace an operator gate.

v0 proves two clean reproducible builds on one exact supported host and
toolchain. It deliberately records `cross_platform_claim: false` and
`slsa_level_claim: none`. It does not claim:

- that Cargo, rustc, the operating system, linker, or signer is intrinsically
  trustworthy;
- cross-platform builder-binary equality;
- independent organizational builders or a transparency log;
- a SLSA level, in-toto layout, timestamp authority, revocation system, or
  public release service;
- that a signed Component has execution authority.

Those require separate contracts. Linux/macOS evidence federation, threshold
release signatures, transparency publication, and effect-to-WASI capability
mapping remain future work.
