#!/usr/bin/env python3
"""Manifest-bound, signed, one-use operator approvals for LOOM Gate."""

import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import stat

import loom_gate


CHALLENGE_SCHEMA = "loom-gate-approval-challenge/v1"
CHALLENGE_VALIDATION_SCHEMA = "loom-gate-approval-challenge-validation/v1"
REQUEST_SCHEMA = "loom-gate-approval-request/v1"
REQUEST_VALIDATION_SCHEMA = "loom-gate-approval-request-validation/v1"
APPROVAL_SCHEMA = "loom-gate-operator-approval/v1"
APPROVAL_VALIDATION_SCHEMA = "loom-gate-operator-approval-validation/v1"
CLAIM_SCHEMA = "loom-gate-approval-claim/v1"
CLAIM_VALIDATION_SCHEMA = "loom-gate-approval-claim-validation/v1"
ALGORITHM = "rsa-pkcs1v15-sha256"
_NONCE = re.compile(r"^[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_KEY_PATH = Path(loom_gate._MEMORY_ROOT) / "gate" / "operator_public_key.json"
_LEDGER_PATH = Path(loom_gate._MEMORY_ROOT) / "gate" / "operator_approvals.sqlite3"
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _challenge_result(challenge, findings):
    return {"schema": CHALLENGE_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "challenge": challenge if not findings else None, "findings": loom_gate._unique_issues(findings)}


def _approval_result(evidence, approval_sha256, findings):
    return {"schema": APPROVAL_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "evidence": evidence if not findings else None, "approval_sha256": approval_sha256 if not findings else None, "findings": loom_gate._unique_issues(findings)}


def _claim_result(claim, findings):
    return {"schema": CLAIM_VALIDATION_SCHEMA, "valid": not findings, "advisory": False, "claim": claim if not findings else None, "findings": loom_gate._unique_issues(findings)}


def _request_result(request, findings):
    return {"schema": REQUEST_VALIDATION_SCHEMA, "valid": not findings, "advisory": True, "request": request if not findings else None, "findings": loom_gate._unique_issues(findings)}


def build_approval_challenge(manifest, nonce):
    """Bind an operator-required manifest to a host-generated 256-bit nonce."""
    validation = loom_gate.validate_manifest(manifest)
    findings = list(validation["findings"])
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        findings.append(_finding("nonce", "invalid-nonce", "nonce must be 64 lowercase hexadecimal characters"))
    decision = loom_gate.evaluate_manifest(manifest)
    if validation["valid"] and decision["decision"] != "operator-required":
        findings.append(_finding("manifest", "approval-not-required", "manifest policy decision must be operator-required"))
    if findings:
        return _challenge_result(None, findings)
    body = {
        "schema": CHALLENGE_SCHEMA,
        "manifest_sha256": validation["manifest_sha256"],
        "policy": decision["policy"],
        "policy_decision": decision["decision"],
        "nonce": nonce,
    }
    body["challenge_sha256"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return _challenge_result(body, [])


def build_approval_request(manifest, challenge):
    """Build the closed, human-reviewable envelope sent to an operator issuer."""
    validation = loom_gate.validate_manifest(manifest)
    findings = list(validation["findings"])
    decision = loom_gate.evaluate_manifest(manifest)
    if validation["valid"] and decision["decision"] != "operator-required":
        findings.append(_finding("manifest", "approval-not-required", "manifest policy decision must be operator-required"))
    if not isinstance(challenge, dict):
        findings.append(_finding("challenge", "expected-object", "challenge must be an object"))
    elif validation["valid"]:
        rebuilt = build_approval_challenge(manifest, challenge.get("nonce"))
        if not rebuilt["valid"]:
            findings.extend(rebuilt["findings"])
        elif challenge != rebuilt["challenge"]:
            findings.append(_finding("challenge", "challenge-mismatch", "challenge does not match manifest and nonce"))
    if findings:
        return _request_result(None, findings)
    body = {
        "schema": REQUEST_SCHEMA,
        "manifest": validation["normalized_manifest"],
        "challenge": challenge,
        "policy_reasons": decision["reasons"],
    }
    body["request_sha256"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return _request_result(body, [])


def validate_approval_request(request):
    """Rebuild and verify an approval envelope at the issuer boundary."""
    if not isinstance(request, dict):
        return _request_result(None, [_finding("request", "expected-object", "approval request must be an object")])
    required = {"schema", "manifest", "challenge", "policy_reasons", "request_sha256"}
    findings = []
    for field in sorted(set(request) - required):
        findings.append(_finding("request." + field, "unknown-field", f"unknown approval request field '{field}'"))
    for field in sorted(required - set(request)):
        findings.append(_finding("request." + field, "missing-field", f"missing approval request field '{field}'"))
    if findings:
        return _request_result(None, findings)
    rebuilt = build_approval_request(request["manifest"], request["challenge"])
    if not rebuilt["valid"]:
        return _request_result(None, rebuilt["findings"])
    if request != rebuilt["request"]:
        return _request_result(None, [_finding("request", "request-mismatch", "approval request does not match its manifest, challenge, policy, and hash")])
    return rebuilt


def _validate_public_key(value):
    findings = []
    required = {"algorithm", "n", "e"}
    if not isinstance(value, dict):
        return None, [_finding("public_key", "expected-object", "operator public key must be an object")]
    for key in sorted(set(value) - required): findings.append(_finding("public_key." + key, "unknown-field", f"unknown public key field '{key}'"))
    for key in sorted(required - set(value)): findings.append(_finding("public_key." + key, "missing-field", f"missing public key field '{key}'"))
    algorithm = value.get("algorithm"); n_hex = value.get("n"); exponent = value.get("e")
    if algorithm != ALGORITHM: findings.append(_finding("public_key.algorithm", "unsupported-algorithm", f"expected '{ALGORITHM}'"))
    if not isinstance(n_hex, str) or not _HEX.fullmatch(n_hex) or n_hex.startswith("0"):
        findings.append(_finding("public_key.n", "invalid-modulus", "RSA modulus must be canonical lowercase hexadecimal")); modulus = None
    else: modulus = int(n_hex, 16)
    if modulus is not None and (not (2048 <= modulus.bit_length() <= 4096) or modulus % 2 == 0): findings.append(_finding("public_key.n", "unsafe-modulus", "RSA modulus must be odd and 2048-4096 bits"))
    if exponent != 65537: findings.append(_finding("public_key.e", "unsafe-exponent", "RSA exponent must be 65537"))
    normalized = {"algorithm": algorithm, "n": n_hex, "e": exponent}
    return (None if findings else normalized), findings


def _key_sha256(public_key):
    return hashlib.sha256(_canonical(public_key).encode("utf-8")).hexdigest()


def _rsa_verify(message, signature_hex, public_key):
    if not isinstance(signature_hex, str) or not _HEX.fullmatch(signature_hex) or len(signature_hex) % 2:
        return False
    modulus = int(public_key["n"], 16); exponent = public_key["e"]; size = (modulus.bit_length() + 7) // 8
    signature = bytes.fromhex(signature_hex)
    if len(signature) != size:
        return False
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        return False
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    actual = pow(signature_int, exponent, modulus).to_bytes(size, "big")
    return hmac.compare_digest(actual, expected)


def _verify(manifest, challenge, approval, public_key_value):
    key, findings = _validate_public_key(public_key_value)
    if not isinstance(challenge, dict): findings.append(_finding("challenge", "expected-object", "challenge must be an object"))
    if not isinstance(approval, dict): findings.append(_finding("approval", "expected-object", "approval must be an object"))
    if findings: return _approval_result(None, None, findings)
    nonce = challenge.get("nonce")
    rebuilt = build_approval_challenge(manifest, nonce)
    if not rebuilt["valid"]: findings.extend(rebuilt["findings"])
    elif challenge != rebuilt["challenge"]: findings.append(_finding("challenge", "challenge-mismatch", "challenge does not match manifest and nonce"))
    required = {"schema", "challenge_sha256", "manifest_sha256", "approver", "decision", "key_sha256", "signature"}
    for field in sorted(set(approval) - required): findings.append(_finding("approval." + field, "unknown-field", f"unknown approval field '{field}'"))
    for field in sorted(required - set(approval)): findings.append(_finding("approval." + field, "missing-field", f"missing approval field '{field}'"))
    if findings: return _approval_result(None, None, findings)
    if approval["schema"] != APPROVAL_SCHEMA: findings.append(_finding("approval.schema", "unsupported-schema", f"expected '{APPROVAL_SCHEMA}'"))
    if approval["challenge_sha256"] != challenge.get("challenge_sha256"): findings.append(_finding("approval.challenge_sha256", "challenge-mismatch", "approval is bound to a different challenge"))
    if approval["manifest_sha256"] != challenge.get("manifest_sha256"): findings.append(_finding("approval.manifest_sha256", "manifest-mismatch", "approval is bound to a different manifest"))
    if approval["approver"] != "operator": findings.append(_finding("approval.approver", "invalid-approver", "approver must be 'operator'"))
    if approval["decision"] != "approve": findings.append(_finding("approval.decision", "not-approved", "operator decision must be 'approve'"))
    if approval["key_sha256"] != _key_sha256(key): findings.append(_finding("approval.key_sha256", "key-mismatch", "approval is signed by a different key"))
    signed = {field: approval[field] for field in sorted(required - {"signature"})}
    if not _rsa_verify(_canonical(signed).encode("utf-8"), approval["signature"], key): findings.append(_finding("approval.signature", "invalid-signature", "operator approval signature is invalid"))
    if findings: return _approval_result(None, None, findings)
    approval_sha = hashlib.sha256(_canonical(approval).encode("utf-8")).hexdigest()
    evidence = [{"kind": "operator-approval", "status": "pass", "detail": f"signed one-use operator approval {approval_sha}"}]
    return _approval_result(evidence, approval_sha, [])


def _load_public_key():
    try:
        if _KEY_PATH.is_symlink() or not _KEY_PATH.is_file(): raise ValueError("operator public key path must be a regular non-symlink file")
        if _KEY_PATH.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("operator public key must not be group/world-writable")
        value = json.loads(_KEY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"operator public key unavailable: {error}") from error
    return value


def verify_operator_approval(manifest, challenge, approval):
    """Verify against the pinned operator public key without consuming the token."""
    try: public_key = _load_public_key()
    except ValueError as error: return _approval_result(None, None, [_finding("public_key", "public-key-unavailable", str(error))])
    return _verify(manifest, challenge, approval, public_key)


def _consume_once(approval_sha, ledger_path):
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger_path.parent.chmod(0o700)
    if ledger_path.is_symlink(): raise ValueError("approval ledger path must not be a symlink")
    if ledger_path.exists() and ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
    connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
    try:
        ledger_path.chmod(0o600)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE IF NOT EXISTS spent (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64))")
        connection.execute("CREATE TABLE IF NOT EXISTS claims (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256)=64), claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), status TEXT NOT NULL CHECK(status IN ('claimed','completed','failed')))")
        if connection.execute("SELECT 1 FROM claims WHERE approval_sha256=?", (approval_sha,)).fetchone():
            connection.execute("ROLLBACK"); raise ValueError("operator approval was already claimed")
        try: connection.execute("INSERT INTO spent(approval_sha256) VALUES (?)", (approval_sha,))
        except sqlite3.IntegrityError as error:
            connection.execute("ROLLBACK"); raise ValueError("operator approval was already consumed") from error
        connection.execute("COMMIT")
    finally:
        connection.close()


def _claim_once(verified, challenge, ledger_path):
    approval_sha = verified["approval_sha256"]
    body = {
        "schema": CLAIM_SCHEMA,
        "approval_sha256": approval_sha,
        "manifest_sha256": challenge["manifest_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "status": "claimed",
    }
    body["claim_sha256"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    ledger_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger_path.parent.chmod(0o700)
    if ledger_path.is_symlink(): raise ValueError("approval ledger path must not be a symlink")
    if ledger_path.exists() and ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
    connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
    try:
        ledger_path.chmod(0o600)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE IF NOT EXISTS spent (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64))")
        connection.execute("CREATE TABLE IF NOT EXISTS claims (approval_sha256 TEXT PRIMARY KEY CHECK(length(approval_sha256)=64), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256)=64), claim_sha256 TEXT UNIQUE NOT NULL CHECK(length(claim_sha256)=64), status TEXT NOT NULL CHECK(status IN ('claimed','completed','failed')))")
        if connection.execute("SELECT 1 FROM spent WHERE approval_sha256=?", (approval_sha,)).fetchone():
            connection.execute("ROLLBACK"); raise ValueError("operator approval was already consumed")
        try:
            connection.execute("INSERT INTO claims VALUES (?,?,?,?,?)", (approval_sha, body["manifest_sha256"], body["challenge_sha256"], body["claim_sha256"], "claimed"))
        except sqlite3.IntegrityError as error:
            connection.execute("ROLLBACK"); raise ValueError("operator approval was already claimed") from error
        connection.execute("COMMIT")
    finally:
        connection.close()
    return body


def _claim_operator_approval(manifest, challenge, approval, public_key, ledger_path):
    verified = _verify(manifest, challenge, approval, public_key)
    if not verified["valid"]: return _claim_result(None, verified["findings"])
    try: claim = _claim_once(verified, challenge, ledger_path)
    except (OSError, sqlite3.Error, ValueError) as error: return _claim_result(None, [_finding("ledger", "approval-claim-failed", str(error))])
    return _claim_result(claim, [])


def claim_operator_approval(manifest, challenge, approval):
    """Claim a signed approval before a trusted host starts the bound action."""
    try: public_key = _load_public_key()
    except ValueError as error: return _claim_result(None, [_finding("public_key", "public-key-unavailable", str(error))])
    return _claim_operator_approval(manifest, challenge, approval, public_key, _LEDGER_PATH)


def _finish_claimed_receipt(manifest, observation, challenge, approval, claim, public_key, ledger_path):
    normalized, findings = loom_gate._validate_observation(observation)
    if findings: return loom_gate._receipt_validation(None, findings)
    if normalized["result"] not in {"completed", "failed"}:
        return loom_gate._receipt_validation(None, [_finding("result", "terminal-result-required", "claimed execution must finish as completed or failed")])
    if any(item["kind"] == "operator-approval" for item in normalized["evidence"]):
        return loom_gate._receipt_validation(None, [_finding("evidence", "supplied-operator-approval", "operator approval evidence must come from the claimed execution")])
    verified = _verify(manifest, challenge, approval, public_key)
    if not verified["valid"]: return loom_gate._receipt_validation(None, verified["findings"])
    expected = {
        "schema": CLAIM_SCHEMA,
        "approval_sha256": verified["approval_sha256"],
        "manifest_sha256": challenge["manifest_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "status": "claimed",
    }
    expected["claim_sha256"] = hashlib.sha256(_canonical(expected).encode("utf-8")).hexdigest()
    if claim != expected:
        return loom_gate._receipt_validation(None, [_finding("claim", "claim-mismatch", "claim does not match the signed manifest and challenge")])
    prepared = dict(normalized)
    prepared["evidence"] = sorted(normalized["evidence"] + verified["evidence"], key=lambda item: item["kind"])
    preflight = loom_gate.build_receipt(manifest, prepared)
    if not preflight["valid"]: return preflight
    connection = None
    try:
        if ledger_path.is_symlink() or not ledger_path.is_file(): raise ValueError("approval ledger must be a regular non-symlink file")
        if ledger_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise ValueError("approval ledger must not be group/world-writable")
        connection = sqlite3.connect(str(ledger_path), timeout=5, isolation_level=None)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT manifest_sha256, challenge_sha256, claim_sha256, status FROM claims WHERE approval_sha256=?", (verified["approval_sha256"],)).fetchone()
        wanted = (expected["manifest_sha256"], expected["challenge_sha256"], expected["claim_sha256"], "claimed")
        if row != wanted:
            connection.execute("ROLLBACK"); raise ValueError("approval claim is absent, mismatched, or already finished")
        connection.execute("UPDATE claims SET status=? WHERE approval_sha256=? AND status='claimed'", (normalized["result"], verified["approval_sha256"]))
        connection.execute("COMMIT")
    except (OSError, sqlite3.Error, ValueError) as error:
        if connection is not None and connection.in_transaction: connection.execute("ROLLBACK")
        return loom_gate._receipt_validation(None, [_finding("ledger", "approval-finalize-failed", str(error))])
    finally:
        if connection is not None: connection.close()
    return preflight


def finish_claimed_receipt(manifest, observation, challenge, approval, claim):
    """Finalize one claimed execution exactly once and return its terminal receipt."""
    try: public_key = _load_public_key()
    except ValueError as error: return loom_gate._receipt_validation(None, [_finding("public_key", "public-key-unavailable", str(error))])
    return _finish_claimed_receipt(manifest, observation, challenge, approval, claim, public_key, _LEDGER_PATH)


def consume_operator_approval(manifest, challenge, approval):
    """Atomically consume a valid signed approval in the fixed local ledger."""
    verified = verify_operator_approval(manifest, challenge, approval)
    if not verified["valid"]: return verified
    try: _consume_once(verified["approval_sha256"], _LEDGER_PATH)
    except (OSError, sqlite3.Error, ValueError) as error: return _approval_result(None, None, [_finding("ledger", "approval-consume-failed", str(error))])
    return verified


def _build_consumed_receipt(manifest, observation, challenge, approval, public_key, ledger_path):
    """Preflight a receipt, then atomically consume and inject signed approval evidence."""
    normalized, findings = loom_gate._validate_observation(observation)
    if findings:
        return loom_gate._receipt_validation(None, findings)
    if normalized["result"] != "completed":
        return loom_gate._receipt_validation(None, [_finding("result", "completed-required", "signed approval consumption requires a completed observation")])
    if any(item["kind"] == "operator-approval" for item in normalized["evidence"]):
        return loom_gate._receipt_validation(None, [_finding("evidence", "supplied-operator-approval", "operator approval evidence must come from signed one-use consumption")])

    verified = _verify(manifest, challenge, approval, public_key)
    if not verified["valid"]:
        return loom_gate._receipt_validation(None, verified["findings"])
    prepared = dict(normalized)
    prepared["evidence"] = sorted(normalized["evidence"] + verified["evidence"], key=lambda item: item["kind"])
    preflight = loom_gate.build_receipt(manifest, prepared)
    if not preflight["valid"]:
        return preflight
    try:
        _consume_once(verified["approval_sha256"], ledger_path)
    except (OSError, sqlite3.Error, ValueError) as error:
        return loom_gate._receipt_validation(None, [_finding("ledger", "approval-consume-failed", str(error))])
    return preflight


def build_consumed_receipt(manifest, observation, challenge, approval):
    """Build a receipt whose operator evidence can only come from one-use consumption."""
    try: public_key = _load_public_key()
    except ValueError as error: return loom_gate._receipt_validation(None, [_finding("public_key", "public-key-unavailable", str(error))])
    return _build_consumed_receipt(manifest, observation, challenge, approval, public_key, _LEDGER_PATH)
