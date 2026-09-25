# Cross-Platform General Execution Federation v0

LOOM federates native general-execution evidence from three closed CI hosts:

- macOS arm64 using the Seatbelt network-deny profile;
- Linux x86_64 using a user plus network namespace;
- Windows x86_64 using a zero-capability AppContainer and one-process Job Object.

The federation proves **observable control concordance**, not identical host
implementations. Each native witness must independently prove one signed exact
invocation, a hash-pinned executable, exact argv/environment/stdin, denied
shell access, network isolation, one-use replay refusal, bounded wall-clock
time and output, and a hash-linked terminal result. All three witnesses must
bind the same full Git commit and originate from distinct GitHub Actions jobs.

## Evidence path

The Linux and macOS witnesses are emitted only after the real Bounded
Execution v0 integration in `run_tests.py` has produced and revalidated a
signed `loom-action-capsule-result/v0`. The witness embeds that complete
Approval-to-Result chain and its operator public key. The Windows input is the
existing `loom-windows-general-execution-ci-witness/v1`, including its native
adversarial checks and terminal lifecycle.

Ubuntu runners can apply an AppArmor policy that blocks unprivileged user
namespaces even when the kernel supports them. The Linux CI job explicitly
opens that policy gate on the ephemeral runner, then requires
`/usr/bin/unshare --user --map-root-user --net -- /usr/bin/true` to succeed
before Citadel may emit a Linux witness. This is a real kernel namespace
precondition, not a fallback or simulated pass. A runner that cannot satisfy
it fails closed and contributes no federation input.

`loom_general_federation.py` validates every nested native artifact before it
builds `loom-cross-platform-general-execution-federation/v0`.
`tools/verify_general_execution_federation_ci.py` accepts exactly three JSON
witnesses and fails closed on a missing platform, revision drift, duplicate CI
job, malformed native chain, failed check, unknown field, or hash mismatch.

## CI artifact

The `federate-general-execution-evidence` job downloads only artifacts named
`general-execution-platform-*`, verifies them against `GITHUB_SHA`, and emits
`cross-platform-general-execution-federation-v0`.

The resulting artifact is test-only and non-authorizing. It does not claim
native operator presence, identical executable or toolchain bytes, equivalent
kernel primitives, production sandbox certification, or permission to execute
another action.
