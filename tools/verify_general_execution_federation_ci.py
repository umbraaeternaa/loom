#!/usr/bin/env python3
"""Aggregate real macOS, Linux, and Windows general-execution witnesses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom_general_federation as federation


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read witness {path.name}: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("witness_dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-commit")
    args = parser.parse_args(argv)
    paths = sorted(args.witness_dir.glob("*.json"))
    if len(paths) != 3:
        raise SystemExit(f"expected exactly three native witnesses, found {len(paths)}")
    witnesses = [_load(path) for path in paths]
    result = federation.build_federation(witnesses, args.expected_commit)
    if not result["valid"]:
        raise SystemExit("general-execution federation rejected: " + json.dumps(
            result["findings"], ensure_ascii=True, sort_keys=True,
        ))
    encoded = federation.canonical_json(result["federation"]) + b"\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded)
    print(encoded.decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
