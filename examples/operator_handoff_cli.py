#!/usr/bin/env python3
"""Full LOOM Gate operator handoff transcript using local demo fixtures.

This example stitches the browser/native/trusted-host boundary into one
executable recipe:

gate-request -> pin public key -> native issuer -> claim -> plan -> attempt -> finish

It is intentionally a demo transcript, not production key management. The demo
private key below is public test material and must never be used for real
operator approvals. All Gate verifier state is redirected into the workdir so
running this file does not touch the machine's real pinned key or ledger.
"""

import contextlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom
import loom_approval
from examples import native_issuer
from examples import pin_operator_public_key
from examples import process_lifecycle_cli


DEMO_PRIVATE_KEY = {
    "algorithm": "rsa-pkcs1v15-sha256",
    "n": "9839b5f2780d273a675993740acd545b6081d18edba0e9dffb4b2623faf6143d4b649d8ab89da611a5cae1128a5690607011601bbb94585a477d4e75f3a94f225dfacfc8911a5f68a4c558c7162305d63eb03e46c8c1438f1d6d4cae24e936ef0958756fcd8ea083b3bc262356b9d5b2427711319452b5b9c0f979d8be60571db915b21faa530653a6e92bdbb9d33cbfdc1040f9910a593b055f5e6eee0a189f300b41a63ff7dd9ec5185ebcb58c3927945fbf73014fdaccf1fe1179595b0300f8f80684e2b40508e68c09ef88893b9446149bcb150a5e0a12fed31cdf5eda1d18adb645a089dcf2e845e52f999c2c3939ccf652f92a07d175a5149e8bba81b7",
    "e": 65537,
    "d": "87308eeb37684c5e61f550d9787e6cb1cf937b3869750eea0c3d4132286998054234fe74cf0b08616e8c2ee1a304c853dd333bd7654f943d19205528b6576175740be5b1df5691efad3b010cf8c141d31e4eb200206a58457c2cdadcb835d0c3992e7b9d3f410641f0c2e25bf56434e9e07d3ded24d20f9cad9f8c717676b8e61d7fdbbe4fa8008f088253e843d29a1c01ca9b6d6cbffbb92a77dcac860b9ead5eee8d9ef6b211dd44dd78075d2da309fa68db5c405fd58ccab32042982594495cc1aaab526e0d752f180cd526ab01017dc2ad9b01d354fc22e80b8797faef44e507344ac53b7ae388d65e54299dfbbdeff9be821b0692172736e6de90a2989",
}

DEMO_MANIFEST = {
    "schema": "loom-gate-manifest/v1",
    "agent": {"id": "codex", "role": "code"},
    "task": {
        "summary": "Demo the full LOOM Gate operator handoff",
        "intent": "Show a bounded process-only lifecycle without granting the agent issuer keys or execution authority",
    },
    "repositories": [],
    "read_paths": ["/Users/macbook/Projects/loom"],
    "write_paths": [],
    "actions": ["read", "process"],
    "evidence_required": [],
}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def run_operator_handoff(workdir, manifest=None, private_key=None):
    """Run the full handoff in `workdir` and return the final receipt result."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    manifest = DEMO_MANIFEST if manifest is None else manifest
    private_key = DEMO_PRIVATE_KEY if private_key is None else private_key

    manifest_file = workdir / "manifest.json"
    request_result_file = workdir / "request-result.json"
    request_file = workdir / "request.json"
    challenge_file = workdir / "challenge.json"
    private_key_file = workdir / "operator_private_key.demo.json"
    pinned_key_file = workdir / "gate" / "operator_public_key.json"
    ledger_file = workdir / "gate" / "operator_approvals.sqlite3"
    approval_file = workdir / "approval.json"
    lifecycle_dir = workdir / "trusted-host"

    write_json(manifest_file, manifest)
    write_json(private_key_file, private_key)

    request_result = process_lifecycle_cli.run_cli_json([
        "gate-request",
        str(manifest_file),
        "--nonce",
        "7" * 64,
        "--format=json",
    ])
    if not request_result["valid"]:
        return request_result
    request = request_result["request"]
    write_json(request_result_file, request_result)
    write_json(request_file, request)
    write_json(challenge_file, request["challenge"])

    pin_operator_public_key.main([
        str(private_key_file),
        "--output",
        str(pinned_key_file),
    ])
    native_issuer.main([
        str(request_file),
        str(private_key_file),
        str(approval_file),
        "--yes",
    ])
    approval = json.loads(approval_file.read_text(encoding="utf-8"))

    old_key_path, old_ledger_path = loom_approval._KEY_PATH, loom_approval._LEDGER_PATH
    try:
        loom_approval._KEY_PATH = pinned_key_file
        loom_approval._LEDGER_PATH = ledger_file

        def trusted_host_attempt(plan):
            return {
                "schema": "loom-gate-host-attempt/v1",
                "result": "completed",
                "evidence": [],
            }

        return process_lifecycle_cli.run_process_cli_lifecycle(
            lifecycle_dir,
            manifest,
            request["challenge"],
            approval,
            trusted_host_attempt,
        )
    finally:
        loom_approval._KEY_PATH, loom_approval._LEDGER_PATH = old_key_path, old_ledger_path


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: python3 examples/operator_handoff_cli.py WORKDIR")
        return 2
    result = run_operator_handoff(argv[0])
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
