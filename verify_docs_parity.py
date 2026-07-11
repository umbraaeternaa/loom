#!/usr/bin/env python3
"""Verify that the published browser bundle stays semantically aligned."""

from __future__ import annotations

import importlib.util
import ast
import builtins
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DOCS_LOOM = ROOT / "docs" / "loom.py"
PLAY_HTML = ROOT / "docs" / "play.html"
WASM_ABI_DOC = ROOT / "docs" / "wasm_abi_v1.md"
QUANTITY_DOC = ROOT / "docs" / "wasm_quantity_mediation.md"


def _check_playground_loader() -> None:
    text = PLAY_HTML.read_text()
    loader_contract = (
        'new URL("./loom.py", location.href)',
        'bundleUrl.searchParams.set("v", "394-tokenize-spans-v1")',
        'fetch(bundleUrl, {cache: "no-store"})',
        'if (!response.ok)',
    )
    missing_loader = [needle for needle in loader_contract if needle not in text]
    if missing_loader or 'fetch("./loom.py")' in text:
        raise SystemExit("docs parity: play.html lost cache-safe LOOM loader contract: " + ", ".join(missing_loader))
    required = (
        'id="bWasm"',
        "loom.compile_wasm(",
        "WebAssembly.instantiate(",
        '"findingsByFn"',
        '"globalFindings"',
        "TextDecoder()",
        "k === 6",
        'name: "WASM · heap meter"',
        'globalValue("loom_heap_limit")',
        'globalValue("loom_heap_used")',
        'globalValue("loom_heap_static_used")',
        'globalValue("loom_heap_records")',
        'globalValue("loom_heap_lists")',
        'globalValue("loom_heap_variants")',
        'globalValue("loom_heap_effects")',
        'globalValue("loom_heap_resources")',
        "heap objects:",
        "bytes reserved",
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
        'name: "WASM · checked i31.gt_s"',
        "(asm wasm i31.gt_s 0 -1)",
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
    tree = ast.parse(DOCS_LOOM.read_text())
    host_only = {"ssl", "sqlite3", "stat", "subprocess", "urllib"}
    imported = set()
    for node in tree.body:
        if isinstance(node, ast.Import): imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module: imported.add(node.module.split(".", 1)[0])
    leaked_imports = sorted(imported & host_only)
    if leaked_imports:
        raise SystemExit("docs parity: standalone bundle has host-only top-level imports: " + ", ".join(leaked_imports))
    bundle_text = DOCS_LOOM.read_text()
    for needle in ("def tokenize_spans", '"line"', '"column"', '"offset"', '"end_offset"'):
        if needle not in bundle_text:
            raise SystemExit("docs parity: standalone bundle lost source-span tokenizer marker: " + needle)


def _check_wasm_abi_doc() -> None:
    text = WASM_ABI_DOC.read_text()
    required = (
        "Static string, kind 6",
        "Raw kind `6`",
        "UTF-8",
        "one 64 KiB page",
        "`memory.grow`",
        "`$reserve`",
        "`seamN K`",
        "`push_caps` / `has_cap`",
        "not a\n  runtime counter",
        "`loom_heap_limit`",
        "`loom_heap_used`",
        "`loom_heap_static_used`",
        "`loom_heap_records`",
        "`loom_heap_lists`",
        "`loom_heap_variants`",
        "`loom_heap_effects`",
        "`loom_heap_resources`",
        "hp + size <= loom_heap_limit",
        "object-family diagnostic counter",
        "memory.size() << 16",
        "General runtime string allocation and string",
        "operations are not part of ABI v1.",
    )
    missing = [needle for needle in required if needle not in text]
    forbidden = (
        "Strings do not yet have a v1 heap kind",
        "not supported by the WASM\n  value boundary",
    )
    stale = [needle for needle in forbidden if needle in text]
    if missing or stale:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if stale:
            details.append("stale: " + ", ".join(stale))
        raise SystemExit("docs parity: wasm ABI doc is out of sync with string/fixed-heap contract: " + "; ".join(details))


def _check_quantity_mediation_doc() -> None:
    text = QUANTITY_DOC.read_text()
    required = (
        "LOOM WASM Quantity Mediation Roadmap",
        "Source quantities",
        "`seamN K`",
        "`loom_heap_limit`",
        "`loom_heap_used`",
        "Do not add `memory.grow` until heap growth is explicitly metered by LOOM.",
        "`push_caps` and `has_cap`",
        "not represented as a binary runtime meter",
        "Capability-use quantity and heap-byte quantity are one runtime-mediation family",
        "ABI v2",
        "No unmetered `memory.grow`.",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit("docs parity: quantity mediation roadmap drift: missing " + ", ".join(missing))


def _run_injected_citadel() -> int:
    spec = importlib.util.spec_from_file_location("loom", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load docs/loom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["loom"] = module
    spec.loader.exec_module(module)
    import run_tests

    return run_tests.main()


def _check_pyodide_import_boundary() -> None:
    real_import = builtins.__import__
    blocked = {"ssl", "sqlite3", "subprocess", "urllib"}
    def guarded_import(name, *args, **kwargs):
        if name.split(".", 1)[0] in blocked:
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)
    spec = importlib.util.spec_from_file_location("loom_pyodide_probe", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not create Pyodide import probe")
    module = importlib.util.module_from_spec(spec)
    try:
        builtins.__import__ = guarded_import
        spec.loader.exec_module(module)
    finally:
        builtins.__import__ = real_import
    if module.run_call("(defx main () (fn () 42))", "(main)") != (42, []):
        raise SystemExit("docs parity: Pyodide import probe loaded but runtime diverged")


def main() -> int:
    _check_playground_loader()
    _check_wasm_abi_doc()
    _check_quantity_mediation_doc()
    _check_pyodide_import_boundary()
    result = _run_injected_citadel()
    if result != 0:
        return result
    print("PASS docs parity — published bundle is standalone and citadel-green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
