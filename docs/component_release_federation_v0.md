# Cross-platform Component Release Evidence Federation v0

Status: implemented host-only contract. Advisory. It grants no execution authority.

This contract aggregates two independently signed LOOM Component release
statements into one closed cross-platform observation. It does not replace
[`Component Release Attestation v0`](component_release_attestation_v0.md).
Each platform must first build its own same-host reproducibility evidence and
sign the exact in-toto statement. Federation then proves that the two signed
observations agree on the portable release while preserving their different
host tool identities.

## Closed host threshold

v0 accepts exactly one statement for each host:

- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`

The statements must use different pinned RSA attester keys. Their set is
canonicalized by host, so caller ordering cannot change federation bytes. A
missing host, duplicate host, unsupported host, or reused platform key fails
closed.

The optional final federation statement uses a third pinned RSA key. That key
must differ from both platform attester keys. LOOM never reads or stores any
private key; it only returns exact DSSE PAE signing bytes and verifies supplied
signatures. The federation timestamp must be at least as new as both signed
platform timestamps.

## API

```python
loom.build_component_release_federation_v0(
    platform_attestations,
    component_bytes,
    release_name,
    release_version,
)

loom.prepare_component_release_federation_attestation_v0(
    platform_attestations,
    component_bytes,
    release_name,
    release_version,
    federation_public_key,
    federated_at_unix_ms,
)

loom.build_component_release_federation_attestation_v0(
    platform_attestations,
    component_bytes,
    release_name,
    release_version,
    federation_public_key,
    federated_at_unix_ms,
    signature,
)

loom.verify_component_release_federation_attestation_v0(
    envelope,
    platform_attestations,
    component_bytes,
    release_name,
    release_version,
    federation_public_key,
)
```

Each platform item has one closed shape:

```json
{
  "envelope": {"payloadType": "...", "payload": "...", "signatures": []},
  "evidence": {"schema": "loom-component-release-reproducibility/v0"},
  "attester_public_key": {"algorithm": "rsa-pkcs1v15-sha256", "n": "...", "e": 65537}
}
```

The platform envelope must contain exactly one signature whose `keyid` is the
SHA-256 identity of the pinned public key. The signature is verified before
the payload is parsed. The payload must be canonical, duplicate-free UTF-8
JSON and must equal the statement LOOM independently reconstructs from the
supplied evidence.

## What equality means

Federation requires:

- a non-empty final Component byte string;
- byte-identical final WebAssembly Component;
- identical Boundary, source, core-WASM, WIT, builder-source and lockfile
  SHA-256 inputs;
- identical Component Adapter artifact semantics after removing only the
  platform executable hashes for the builder and `wasm-tools`;
- valid closed same-host reproducibility evidence on both sides;
- distinct platform attester key identities.

It deliberately does not require identical native builder bytes, linker
bytes, Cargo/rustc executable bytes, oracle executable bytes, or complete
toolchain evidence. Those identities are retained separately under each host
record and are expected to differ.

The resulting object uses schema
`loom-component-release-federation/v0`. Its scoped claim is exactly:

```text
component-bytes-and-portable-input-concordance
```

It is not a claim that native toolchains are identical.

## Signed federation statement

The federation issuer signs a canonical
[`https://in-toto.io/Statement/v1`](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with predicate type:

```text
https://umbraaeternaa.github.io/loom/attestation/component-release-federation/v0
```

Its subjects bind the final Component, the federation evidence object, and
both exact platform statement hashes. The DSSE payload type remains
`application/vnd.in-toto+json`.

Changing a platform envelope, reproducibility object, source identity,
Component byte, release identity, timestamp, key, threshold member, or
federation field invalidates a signature or makes the independently rebuilt
statement differ.

## CI conformance path

The repository CI has a separate macOS arm64 observation and Linux x86_64
observation. Each host runs the real Citadel and same-host Component release
build, then emits a closed test-only witness. A third job downloads exactly
two witnesses and runs:

```bash
python tools/verify_component_federation_ci.py .federation-witness
```

The aggregator has no private key. It accepts only byte-identical Components
and valid signed platform statements, then emits canonical test-only
federation evidence. Embedded test keys establish protocol conformance only;
they are public fixtures and must never be treated as production issuers.

## Honest boundary

Federation v0 does not claim:

- execution authorization;
- a SLSA level;
- transparency-log inclusion, freshness, revocation, or timestamp authority;
- that a signature alone proves the platform actually ran an independent
  rebuild outside the attester's trust domain;
- behavioral equivalence across arbitrary hosts, WASI implementations, or
  Component runtimes;
- support for hosts outside the exact v0 pair;
- secrecy or production trust for CI test keys.

The required operating sequence is: run the full same-host verifier on each
platform, issue each platform statement with separately controlled keys,
federate the two immutable statements, then optionally sign the federation
with a third separately controlled key. Every returned result remains
`advisory: true` and `authorization: none`.
