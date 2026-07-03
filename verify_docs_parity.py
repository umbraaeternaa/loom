#!/usr/bin/env python3
"""Verify that the published browser bundle stays semantically aligned."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DOCS_LOOM = ROOT / "docs" / "loom.py"
PLAY_HTML = ROOT / "docs" / "play.html"


def _check_playground_loader() -> None:
    text = PLAY_HTML.read_text()
    if 'fetch("./loom.py")' not in text:
        raise SystemExit("docs parity: play.html no longer fetches ./loom.py")
    required = (
        'id="bWasm"',
        "loom.compile_wasm(",
        "WebAssembly.instantiate(",
        '"findingsByFn"',
        '"globalFindings"',
        "TextDecoder()",
        "k === 6",
        'name: "WASM · checked i31.add"',
        "(asm wasm i31.add 20 22)",
        'name: "WASM · checked i31.sub"',
        "(asm wasm i31.sub 50 8)",
        'name: "WASM · checked i31.mul"',
        "(asm wasm i31.mul 6 7)",
        'name: "WASM · checked i31.eq"',
        "(asm wasm i31.eq 7 7)",
        'name: "WASM · checked i31.lt_s"',
        "(asm wasm i31.lt_s -1 0)",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit("docs parity: play.html lost published WASM runner contract: " + ", ".join(missing))
    forbidden = (
        "loom_parse.py",
        "loom_checker.py",
        "loom_runtime.py",
        "loom_codegen.py",
        "loom_wasm.py",
        "loom_cli.py",
    )
    leaked = [name for name in forbidden if name in text]
    if leaked:
        raise SystemExit("docs parity: play.html references development modules: " + ", ".join(leaked))


def _run_injected_citadel() -> int:
    spec = importlib.util.spec_from_file_location("loom", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load docs/loom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["loom"] = module
    spec.loader.exec_module(module)
    import run_tests

    return run_tests.main()


def main() -> int:
    _check_playground_loader()
    result = _run_injected_citadel()
    if result != 0:
        return result
    print("PASS docs parity — published bundle is standalone and citadel-green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
