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
INDEX_HTML = ROOT / "docs" / "index.html"
PLAY_HTML = ROOT / "docs" / "play.html"
WASM_ABI_DOC = ROOT / "docs" / "wasm_abi_v1.md"
QUANTITY_DOC = ROOT / "docs" / "wasm_quantity_mediation.md"
METER_FRAME_DOC = ROOT / "docs" / "meter_frame_v1.md"
CALL_BUDGET_DOC = ROOT / "docs" / "call_budget_frame_v1.md"
RECURRENCE_DOC = ROOT / "docs" / "quantitative_recurrence_summary_v1.md"
BOUNDS_DOC = ROOT / "docs" / "proven_value_bounds_v1.md"
CONTEXTUAL_BOUNDS_DOC = ROOT / "docs" / "contextual_value_bounds_v2.md"
SECRET_POLICY_DOC = ROOT / "docs" / "secret_credential_policy.md"


def _check_playground_loader() -> None:
    text = PLAY_HTML.read_text()
    loader_contract = (
        'new URL("./loom.py", location.href)',
        'bundleUrl.searchParams.set("v", "488-contextual-value-bounds-v2")',
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
        'typeof abi.value === "number"',
        "k === 6",
        "n++ > 2048",
        'name: "WASM · heap meter"',
        'name: "WASM · call budget"',
        'name: "Proof · quantified recursion"',
        "(seamN 2 (Net) (hit 2))",
        'globalValue("loom_heap_limit")',
        'globalValue("loom_heap_used")',
        'globalValue("loom_heap_static_used")',
        'globalValue("loom_heap_records")',
        'globalValue("loom_heap_lists")',
        'globalValue("loom_heap_variants")',
        'globalValue("loom_heap_effects")',
        'globalValue("loom_heap_resources")',
        "heap objects:",
        "function watSourceMap(wat)",
        "function renderWatSourceMap(wat, src)",
        "function sourceLinePreview(src, row)",
        ";; allocation source map",
        'renderWatSourceMap(wat, $("src").value) +',
        'name: "WASM · source map"',
        "alloc ([^\\n]*?) at (\\d+):(\\d+)",
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
        'id="bGate"',
        "function renderGateDiagnostics(diagnostics)",
        "loom.build_gate_diagnostics(_manifest)",
        "loom-gate-diagnostics/v1",
        "SecretExfil",
        "CredentialAccess",
        "raw paths and secret values are not displayed",
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
    for needle in ("def tokenize_spans", "def parse_spans", "def _wat_at", '"line"', '"column"', '"offset"', '"end_offset"', '"children"', " at "):
        if needle not in bundle_text:
            raise SystemExit("docs parity: standalone bundle lost source-span tokenizer marker: " + needle)
    for needle in ("_gate_secret_class", "secret-read-operator-required", "secret-exfil-forbidden", "secret-write-forbidden", "secret-lane", "unsafe-secret-evidence", "loom-gate-diagnostics/v1", "build_gate_diagnostics"):
        if needle not in bundle_text:
            raise SystemExit("docs parity: standalone bundle lost secret path policy marker: " + needle)


def _check_landing_page_count() -> None:
    text = INDEX_HTML.read_text()
    required = (
        "488 self-verifying checks",
        ">488</div>",
    )
    forbidden = (
        "456 self-verifying checks",
        ">456</div>",
        "415 self-verifying checks",
        "437 self-verifying checks",
        ">437</div>",
        "436 self-verifying checks",
        ">436</div>",
        "433 self-verifying checks",
        ">433</div>",
        "432 self-verifying checks",
        ">432</div>",
        "431 self-verifying checks",
        ">431</div>",
        "430 self-verifying checks",
        ">430</div>",
        "429 self-verifying checks",
        "428 self-verifying checks",
        "417 self-verifying checks",
        "418 self-verifying checks",
        "427 self-verifying checks",
        ">427</div>",
        "426 self-verifying checks",
        ">426</div>",
        "425 self-verifying checks",
        ">425</div>",
        "424 self-verifying checks",
        ">424</div>",
        "423 self-verifying checks",
        ">423</div>",
        "422 self-verifying checks",
        ">422</div>",
        "421 self-verifying checks",
        ">421</div>",
        "420 self-verifying checks",
        ">420</div>",
        "419 self-verifying checks",
        ">415</div>",
        "414 self-verifying checks",
        ">414</div>",
        "413 self-verifying checks",
        ">413</div>",
        "408 self-verifying checks",
        ">408</div>",
    )
    missing = [needle for needle in required if needle not in text]
    stale = [needle for needle in forbidden if needle in text]
    if missing or stale:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if stale:
            details.append("stale: " + ", ".join(stale))
        raise SystemExit("docs parity: landing page check-count drift: " + "; ".join(details))


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
        "`push_caps`",
        "`pop_caps`",
        "`has_cap`",
        "`host_ffi`",
        "source-checked capability presence only",
        "assigned by first\noccurrence of the foreign component name inside one compiled module",
        "Repeated\nuses of the same foreign name in one module use the same raw ID",
        "must not be persisted or compared across\nseparately compiled modules",
        "finite traversal guard",
        "2048 traversed cells",
        "host-visible counter",
        "compiler-emitted linked meter frame for effects\n"
        "inside a metered seam",
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
        "Direct `host_ffi` calls receive a tagged argument list",
        "foreign result remains an opaque\n  boundary for trust/provenance",
        "General runtime string allocation and string operations",
        "are not part of ABI v1.",
        "Compiler state isolation",
        "per-module products of a single compilation",
        "must not be stored in mutable module-global compiler tables",
        "every call to\n`compile_wasm` or `emit_wat` must build a fresh program context",
        "Parallel builds\nof unrelated programs must produce the same bytes and WAT",
    )
    missing = [needle for needle in required if needle not in text]
    forbidden = (
        "Strings do not yet have a v1 heap kind",
        "not supported by the WASM\n  value boundary",
        "The current direct host-call interface accepts integer arguments only.",
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
        "`push_caps`",
        "`has_cap`",
        "internal compiler-emitted linked meter frame for `seamN`",
        "no host\nimports, exports, public object layouts, or host obligations",
        "Capability-use quantity and heap-byte quantity are one runtime-mediation family",
        "ABI v2",
        "No unmetered `memory.grow`.",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit("docs parity: quantity mediation roadmap drift: missing " + ", ".join(missing))


def _check_meter_frame_doc() -> None:
    text = METER_FRAME_DOC.read_text()
    required = (
        "LOOM Portable Meter Frame v1",
        "normative reference semantics",
        "charges every active frame",
        "traps before changing any counter",
        "`IO`, `Net`, `Alloc`, `Rand`, and `FFI`",
        "reference interpreter implements Meter Frame v1",
        "Python and JavaScript generated backends implement the same frame",
        "WASM implements the same active-frame semantics",
        "Checker Meter Summary v1 composes finite statically resolved named calls",
        "Quantitative Recurrence Summary v1",
        "Branching, unknown-input, uncertified, and unresolved\n  higher-order recursion saturate and remain fail-closed",
        "changes no WASM ABI v1 imports, exports, public object layouts",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit("docs parity: portable meter frame contract drift: missing " + ", ".join(missing))


def _check_secret_credential_policy_doc() -> None:
    text = SECRET_POLICY_DOC.read_text()
    required = (
        "LOOM Secret and Credential Safety Policy",
        "defensive design contract",
        "does not grant any capability to collect, extract, or exfiltrate",
        "`SecretRead`",
        "`CredentialAccess`",
        "`WalletKey`",
        "`BankCredential`",
        "`SecretExfil`",
        "No ambient credential access",
        "No silent exfiltration",
        "Operator approval must be manifest-bound",
        "Receipts must not contain the secret",
        "Agents may not self-vouch credential access",
        "`loom-gate-manifest/v2`",
        "`secret_access`",
        "ordinary `read_paths` must not implicitly",
        "No password harvesting",
        "No receipt or dashboard view that prints raw secrets",
        "Implemented in Gate policy v1",
        "Implemented in Gate receipt v1",
        "`secret-lane` evidence",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit("docs parity: secret credential safety policy drift: missing " + ", ".join(missing))


def _check_call_budget_doc() -> None:
    text = CALL_BUDGET_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Call Budget Frame v1",
        "`(depthN K BODY...)`",
        "recursive strongly connected component",
        "checked before any frame is decremented",
        "does not prove that a program terminates",
        "`depthN` charges named recursive call edges",
        "not imported, exported, or part of the public host ABI",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: call budget contract drift: missing " + ", ".join(missing))


def _check_recurrence_doc() -> None:
    text = RECURRENCE_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Quantitative Recurrence Summary v1",
        "normative static-checker contract",
        "adds no source annotation",
        "(prove (descent NAME...))",
        "single spine",
        "integer literal or a source list literal",
        "All additions saturate at `1024`",
        "Fibonacci-style branching",
        "recursion crossing `with`",
        "changes no interpreter behavior",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: quantitative recurrence contract drift: missing " + ", ".join(missing))


def _check_bounds_doc() -> None:
    text = BOUNDS_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Proven Value Bounds v1",
        "normative static-checker contract",
        "adds no source annotation",
        "(\"i31\", lower, upper)",
        "(\"list\", lower, upper)",
        "lexical `let` bindings",
        "canonical signed i31 wraparound",
        "possible overflow or wraparound makes the result unknown",
        "remain fail-closed",
        "No runtime counter, backend lowering, public WASM ABI change",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: proven value bounds contract drift: missing " + ", ".join(missing))


def _check_contextual_bounds_doc() -> None:
    text = CONTEXTUAL_BOUNDS_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Contextual Value Bounds v2",
        "normative static-checker contract",
        "direct calls to named functions with value parameters",
        "callee's value parameters are shadowed and rebound",
        "callable parameters, closures, or unresolved higher-order dispatch",
        "effectful, foreign, random, or otherwise unknown arguments",
        "fixed direct-call depth cap",
        "remains unbounded",
        "No source annotation, runtime counter, backend change, public WASM ABI change",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: contextual value bounds contract drift: missing " + ", ".join(missing))


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
    _check_landing_page_count()
    _check_wasm_abi_doc()
    _check_quantity_mediation_doc()
    _check_meter_frame_doc()
    _check_call_budget_doc()
    _check_recurrence_doc()
    _check_bounds_doc()
    _check_contextual_bounds_doc()
    _check_secret_credential_policy_doc()
    _check_pyodide_import_boundary()
    result = _run_injected_citadel()
    if result != 0:
        return result
    print("PASS docs parity — published bundle is standalone and citadel-green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
