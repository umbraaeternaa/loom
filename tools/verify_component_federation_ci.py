#!/usr/bin/env python3
"""Aggregate two real test-only CI platform witnesses into LOOM federation evidence."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom  # noqa: E402


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _load(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read witness {path.name}: {exc}") from exc
    expected = {
        "schema", "host", "release", "component", "platform_attestation",
        "test_only", "authorization",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"witness {path.name} does not have the closed v0 shape")
    if value["schema"] != "loom-component-release-platform-ci-witness/v0":
        raise ValueError(f"witness {path.name} has an unsupported schema")
    if value["test_only"] is not True or value["authorization"] != "none":
        raise ValueError(f"witness {path.name} attempts to escape the test-only boundary")
    try:
        component = base64.b64decode(value["component"].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"witness {path.name} has invalid Component bytes") from exc
    if not component:
        raise ValueError(f"witness {path.name} has an empty Component")
    return value, component


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("witness_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    paths = sorted(args.witness_dir.glob("*.json"))
    if len(paths) != 2:
        raise SystemExit(f"expected exactly two platform witnesses, found {len(paths)}")
    loaded = [_load(path) for path in paths]
    witnesses = [item[0] for item in loaded]
    components = [item[1] for item in loaded]
    if components[0] != components[1]:
        raise SystemExit("platform witnesses contain different Component bytes")
    if witnesses[0]["release"] != witnesses[1]["release"]:
        raise SystemExit("platform witnesses contain different release identities")
    release = witnesses[0]["release"]
    result = loom.build_component_release_federation_v0(
        [item["platform_attestation"] for item in witnesses], components[0],
        release.get("name"), release.get("version"),
    )
    if not result["valid"]:
        raise SystemExit("federation rejected: " + json.dumps(
            result["findings"], ensure_ascii=True, sort_keys=True,
        ))
    federation = result["federation"]
    output = {
        "schema": "loom-component-release-ci-federation/v0",
        "test_only": True,
        "authorization": "none",
        "federation": federation,
    }
    encoded = _canonical(output)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded)
    print(encoded.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
