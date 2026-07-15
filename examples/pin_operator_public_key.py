#!/usr/bin/env python3
"""Pin the LOOM Gate operator public key without storing the private key.

This operator-side helper accepts either a public key JSON (`algorithm`, `n`,
`e`) or the private key JSON used by `native_issuer.py` (`algorithm`, `n`, `e`,
`d`). In both cases it writes only the public portion to the pinned verifier
path, with a private directory and non-world-writable file permissions.
"""

import argparse
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import loom_approval


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise SystemExit(f"cannot read key JSON: {error}") from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid key JSON: {error}") from error


def extract_public_key(value):
    if not isinstance(value, dict):
        raise SystemExit("key JSON must be an object")
    allowed = {"algorithm", "n", "e", "d"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SystemExit("key JSON has unknown field(s): " + ", ".join(unknown))
    public_key = {key: value.get(key) for key in ("algorithm", "n", "e")}
    normalized, findings = loom_approval._validate_public_key(public_key)
    if findings:
        detail = "; ".join(f"{item['path']}: {item['message']}" for item in findings)
        raise SystemExit("invalid public key: " + detail)
    return normalized


def write_pinned_public_key(public_key, output):
    output = Path(output)
    if output.exists() and output.is_symlink():
        raise SystemExit("refusing to write operator public key through a symlink")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.parent.chmod(0o700)
    temp = output.with_suffix(output.suffix + ".tmp")
    temp.write_text(json.dumps(public_key, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(output)
    output.chmod(0o600)
    mode = output.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit("operator public key is group/world-writable after write")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pin a LOOM Gate operator public key.")
    parser.add_argument("key_json", help="operator public key JSON, or private key JSON whose public portion will be pinned")
    parser.add_argument("--output", default=str(loom_approval._KEY_PATH), help="pinned public-key output path")
    args = parser.parse_args(argv)

    public_key = extract_public_key(load_json(args.key_json))
    write_pinned_public_key(public_key, args.output)
    print("pinned operator public key: " + str(Path(args.output)))
    print("key_sha256: " + loom_approval._key_sha256(public_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
