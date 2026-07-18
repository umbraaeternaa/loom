#!/usr/bin/env python3
"""Host-built, content-addressed compiler profiles for LOOM WASM."""

import argparse
import hashlib
import json
from pathlib import Path


COMPILER_PROFILE_SCHEMA = "loom-wasm-compiler-profile/v1"
COMPILER_PROFILE_VALIDATION_SCHEMA = "loom-wasm-compiler-profile-validation/v1"
PACKAGE_VERSION = "0.1.0"
COMPILER_SURFACES = {
    "modular-python": (
        "loom.py",
        "loom_parse.py",
        "loom_checker.py",
        "loom_bounds.py",
        "loom_recursion.py",
        "loom_frontend.py",
        "loom_wasm.py",
    ),
    "standalone-python": ("docs/loom.py",),
}


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _validation(profile, findings):
    return {
        "schema": COMPILER_PROFILE_VALIDATION_SCHEMA,
        "valid": not findings,
        "profile": profile if not findings else None,
        "findings": findings,
    }


def build_compiler_profile(surface, components, wasm_abi_version):
    """Hash exact host-supplied compiler bytes into a closed deterministic profile."""
    findings = []
    expected_paths = COMPILER_SURFACES.get(surface)
    if expected_paths is None:
        findings.append(_finding("surface", "unknown-surface", "expected modular-python or standalone-python"))
    if not isinstance(components, dict):
        findings.append(_finding("components", "expected-object", "components must map canonical paths to exact bytes"))
        components = {}
    if not isinstance(wasm_abi_version, int) or isinstance(wasm_abi_version, bool) or wasm_abi_version < 1:
        findings.append(_finding("wasm_abi_version", "invalid-version", "WASM ABI version must be a positive integer"))
    rows = []
    if expected_paths is not None:
        expected = set(expected_paths)
        for path in sorted(set(components) - expected, key=str):
            findings.append(_finding("components." + str(path), "unknown-component", "component is outside the closed compiler surface"))
        for path in expected_paths:
            if path not in components:
                findings.append(_finding("components." + path, "missing-component", "required compiler component is missing"))
                continue
            payload = components[path]
            if not isinstance(payload, (bytes, bytearray)):
                findings.append(_finding("components." + path, "expected-bytes", "compiler component must be exact bytes or bytearray"))
                continue
            payload = bytes(payload)
            rows.append({
                "path": path,
                "byte_length": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    if findings:
        return _validation(None, findings)
    profile = {
        "schema": COMPILER_PROFILE_SCHEMA,
        "compiler": "loom-wasm",
        "surface": surface,
        "package_version": PACKAGE_VERSION,
        "wasm_abi_version": wasm_abi_version,
        "components": rows,
    }
    profile["profile_sha256"] = hashlib.sha256(_canonical(profile).encode("utf-8")).hexdigest()
    return _validation(profile, [])


def verify_compiler_profile(profile, surface, components, wasm_abi_version):
    """Verify profile closure, self-hash, and exact host-supplied component bytes."""
    findings = []
    expected_result = build_compiler_profile(surface, components, wasm_abi_version)
    findings.extend(expected_result["findings"])
    expected_keys = {
        "schema", "compiler", "surface", "package_version", "wasm_abi_version",
        "components", "profile_sha256",
    }
    if not isinstance(profile, dict):
        findings.append(_finding("profile", "expected-object", "compiler profile must be an object"))
        return _validation(None, findings)
    for key in sorted(set(profile) - expected_keys, key=str):
        findings.append(_finding("profile." + str(key), "unknown-field", "unknown compiler profile field"))
    for key in sorted(expected_keys - set(profile)):
        findings.append(_finding("profile." + key, "missing-field", "missing compiler profile field"))
    if profile.get("schema") != COMPILER_PROFILE_SCHEMA:
        findings.append(_finding("profile.schema", "unsupported-schema", "expected " + COMPILER_PROFILE_SCHEMA))
    if set(profile) >= expected_keys:
        body = {key: profile[key] for key in expected_keys if key != "profile_sha256"}
        try:
            digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            findings.append(_finding("profile", "non-canonical-profile", "profile fields must be canonical JSON values"))
        else:
            if profile.get("profile_sha256") != digest:
                findings.append(_finding("profile.profile_sha256", "profile-hash-mismatch", "profile hash does not match its canonical fields"))
    if expected_result["valid"] and profile != expected_result["profile"]:
        findings.append(_finding("profile", "compiler-profile-mismatch", "profile does not match the supplied compiler surface bytes"))
    return _validation(profile if not findings else None, findings)


def collect_compiler_components(root, surface):
    """Read one closed compiler surface from a trusted host filesystem."""
    paths = COMPILER_SURFACES.get(surface)
    if paths is None:
        raise ValueError("unknown compiler surface: " + str(surface))
    root = Path(root).resolve()
    return {path: root.joinpath(path).read_bytes() for path in paths}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build a content-addressed LOOM WASM compiler profile")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent))
    parser.add_argument("--surface", choices=sorted(COMPILER_SURFACES), default="modular-python")
    parser.add_argument("--wasm-abi-version", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        components = collect_compiler_components(args.root, args.surface)
        result = build_compiler_profile(args.surface, components, args.wasm_abi_version)
    except (OSError, ValueError) as exc:
        result = _validation(None, [_finding("components", "collection-failed", str(exc))])
    print(_canonical(result))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
