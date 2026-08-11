#!/usr/bin/env python3
"""Reference operator-side issuer for LOOM Gate approval requests.

This example is intentionally outside the agent/trusted-host path. It validates
the copied request, asks for explicit operator confirmation, and writes only the
signed approval JSON. Claiming, planning, execution, ledger consumption, and
receipt finalization remain separate trusted-host steps.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom_approval
import loom


PRIVATE_KEY_FIELDS = {"algorithm", "n", "e", "d"}
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise SystemExit(f"cannot read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid {label} JSON: {error}") from error


def public_key_from_private(private_key):
    if not isinstance(private_key, dict):
        raise SystemExit("private key must be a JSON object")
    unknown = sorted(set(private_key) - PRIVATE_KEY_FIELDS)
    missing = sorted(PRIVATE_KEY_FIELDS - set(private_key))
    if unknown:
        raise SystemExit("private key has unknown field(s): " + ", ".join(unknown))
    if missing:
        raise SystemExit("private key missing field(s): " + ", ".join(missing))
    public_key = {key: private_key[key] for key in ("algorithm", "n", "e")}
    _, findings = loom_approval._validate_public_key(public_key)
    if findings:
        detail = "; ".join(f"{item['path']}: {item['message']}" for item in findings)
        raise SystemExit("invalid public portion of private key: " + detail)
    d_hex = private_key["d"]
    if not isinstance(d_hex, str) or not loom_approval._HEX.fullmatch(d_hex) or d_hex.startswith("0"):
        raise SystemExit("private key d must be canonical lowercase hexadecimal")
    return public_key, int(d_hex, 16)


def sign_pkcs1v15_sha256(message, private_exponent, modulus):
    size = (modulus.bit_length() + 7) // 8
    digest_info = DIGEST_INFO_SHA256 + hashlib.sha256(message).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        raise SystemExit("RSA modulus is too small for SHA-256 PKCS#1 v1.5 signing")
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    return signature.to_bytes(size, "big").hex()


def build_approval(request, private_key, issued_at_unix_ms=None, ttl_ms=300000):
    schema = request.get("schema") if isinstance(request, dict) else None
    if schema == "loom-action-approval-request/v2":
        validated = loom.validate_action_approval_request_v2(request)
    else:
        validated = loom_approval.validate_approval_request(request)
    if not validated["valid"]:
        detail = "; ".join(f"{item['path']}: {item['message']}" for item in validated["findings"])
        raise SystemExit("approval request refused: " + detail)
    body = validated["request"]
    public_key, private_exponent = public_key_from_private(private_key)
    key_sha256 = loom_approval._key_sha256(public_key)
    challenge = body["challenge"]
    if schema == "loom-action-approval-request/v2":
        if type(issued_at_unix_ms) is not int or issued_at_unix_ms < 0:
            raise SystemExit("issued_at_unix_ms must be a non-negative integer")
        if type(ttl_ms) is not int or not 1 <= ttl_ms <= 900000:
            raise SystemExit("ttl_ms must be an integer from 1 to 900000")
        binding = body["binding"]
        approval = {
            "schema": "loom-action-capsule-approval/v2",
            "request_sha256": body["request_sha256"],
            "challenge_sha256": challenge["challenge_sha256"],
            "binding_sha256": binding["binding_sha256"],
            "capsule_sha256": binding["capsule_sha256"],
            "invocation_sha256": binding["invocation_sha256"],
            "approval_scope": "exact-invocation",
            "approver": "operator",
            "decision": "approve",
            "issued_at_unix_ms": issued_at_unix_ms,
            "expires_at_unix_ms": issued_at_unix_ms + ttl_ms,
            "claim_required": True,
            "key_sha256": key_sha256,
        }
    else:
        approval = {
            "schema": loom_approval.APPROVAL_SCHEMA,
            "challenge_sha256": challenge["challenge_sha256"],
            "manifest_sha256": challenge["manifest_sha256"],
            "approver": "operator",
            "decision": "approve",
            "key_sha256": key_sha256,
        }
    approval["signature"] = sign_pkcs1v15_sha256(
        canonical(approval).encode("utf-8"),
        private_exponent,
        int(public_key["n"], 16),
    )
    return body, approval, public_key


def print_review(request):
    if request["schema"] == "loom-action-approval-request/v2":
        review = request["review"]
        print("LOOM Action Approval v2 issuer review")
        print("request_sha256: " + request["request_sha256"])
        print("binding_sha256: " + request["binding"]["binding_sha256"])
        print("challenge_sha256: " + request["challenge"]["challenge_sha256"])
        print("agent: " + review["agent"]["id"] + " (" + review["agent"]["role"] + ")")
        print("task: " + review["task"]["summary"])
        print("executable_uri: " + review["adapter"]["executable_uri"])
        print("executable_sha256: " + review["adapter"]["artifact_sha256"])
        print("argv: " + json.dumps(review["argv"], ensure_ascii=False))
        print("working_directory_uri: " + review["working_directory_uri"])
        print("environment commitments:")
        for item in review["environment"]:
            print("  " + item["name"] + " sha256=" + item["value_sha256"])
        print("stdin_sha256: " + review["stdin"]["payload_sha256"])
        print("timeout_ms: " + str(review["timeout_ms"]))
        print("shell: " + review["shell"] + " / network: " + review["network"])
        return
    manifest = request["manifest"]
    challenge = request["challenge"]
    print("LOOM native issuer review")
    print("request_sha256: " + request["request_sha256"])
    print("manifest_sha256: " + challenge["manifest_sha256"])
    print("challenge_sha256: " + challenge["challenge_sha256"])
    print("policy_decision: " + challenge["policy_decision"])
    print("actions: " + ", ".join(manifest["actions"]))
    print("agent: " + manifest["agent"]["id"] + " (" + manifest["agent"]["role"] + ")")
    print("task: " + manifest["task"]["summary"])
    print("policy_reasons:")
    for item in request["policy_reasons"]:
        print(f"  [{item['code']}] {item['path']}: {item['message']}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate and sign a LOOM Gate or Action approval request.")
    parser.add_argument("request_json", help="copied LOOM approval request JSON")
    parser.add_argument("private_key_json", help="operator-controlled RSA private key JSON")
    parser.add_argument("approval_json", help="output approval JSON path")
    parser.add_argument("--yes", action="store_true", help="confirm operator approval non-interactively")
    parser.add_argument("--ttl-seconds", type=int, default=300, help="Action Approval v2 validity, 1-900 seconds")
    args = parser.parse_args(argv)

    request = load_json(args.request_json, "approval request")
    private_key = load_json(args.private_key_json, "operator private key")
    issued_at_unix_ms = int(time.time() * 1000)
    reviewed, approval, public_key = build_approval(
        request, private_key, issued_at_unix_ms, args.ttl_seconds * 1000,
    )
    print_review(reviewed)
    print("key_sha256: " + loom_approval._key_sha256(public_key))
    if not args.yes:
        answer = input("Type APPROVE to write approval.json: ")
        if answer != "APPROVE":
            raise SystemExit("approval aborted")
    output = Path(args.approval_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix + ".tmp")
    temp.write_text(json.dumps(approval, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(output)
    print("wrote approval: " + str(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
