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
WASM_ABI_V2_DOC = ROOT / "docs" / "wasm_abi_v2.md"
QUANTITY_DOC = ROOT / "docs" / "wasm_quantity_mediation.md"
METER_FRAME_DOC = ROOT / "docs" / "meter_frame_v1.md"
CALL_BUDGET_DOC = ROOT / "docs" / "call_budget_frame_v1.md"
RECURRENCE_DOC = ROOT / "docs" / "quantitative_recurrence_summary_v1.md"
BOUNDS_DOC = ROOT / "docs" / "proven_value_bounds_v1.md"
CONTEXTUAL_BOUNDS_DOC = ROOT / "docs" / "contextual_value_bounds_v2.md"
WASM_TRUST_DOC = ROOT / "docs" / "wasm_trust_provenance_v1.md"
WASM_TRUST_V2_DOC = ROOT / "docs" / "wasm_trust_provenance_v2.md"
WASM_EQUIVALENCE_DOC = ROOT / "docs" / "wasm_source_equivalence_v1.md"
WIT_COMPONENT_DOC = ROOT / "docs" / "wit_component_boundary_v0.md"
COMPONENT_BRIDGE_DOC = ROOT / "docs" / "component_bridge_v0.md"
COMPONENT_ADAPTER_DOC = ROOT / "docs" / "component_adapter_v0.md"
COMPILER_PROVENANCE_DOC = ROOT / "docs" / "compiler_provenance_v1.md"
COMPILER_EVIDENCE_DOC = ROOT / "docs" / "gate_compiler_evidence_v1.md"
COMPILER_EVIDENCE_V2_DOC = ROOT / "docs" / "gate_compiler_evidence_v2.md"
COMPILER_RECEIPT_DOC = ROOT / "docs" / "gate_compiler_receipt_v3.md"
COMPILER_RECEIPT_V4_DOC = ROOT / "docs" / "gate_compiler_receipt_v4.md"
ACTION_BINDING_DOC = ROOT / "docs" / "action_binding_v0.md"
ACTION_SEMANTICS_DOC = ROOT / "docs" / "action_semantics_v0.md"
ACTION_CAPSULE_DOC = ROOT / "docs" / "action_capsule_v0.md"
ACTION_INVOCATION_BINDING_DOC = ROOT / "docs" / "action_invocation_binding_v0.md"
ACTION_APPROVAL_V2_DOC = ROOT / "docs" / "action_approval_v2.md"
ACTION_CLAIM_V0_DOC = ROOT / "docs" / "action_claim_v0.md"
ACTION_HOST_MEDIATION_V0_DOC = ROOT / "docs" / "action_host_mediation_v0.md"
ACTION_BOUNDED_EXECUTION_V0_DOC = ROOT / "docs" / "action_bounded_execution_v0.md"
ACTION_CAPSULE_RESULT_V0_DOC = ROOT / "docs" / "action_capsule_result_v0.md"
ACTION_RESULT_ATTESTATION_V0_DOC = ROOT / "docs" / "action_result_attestation_v0.md"
WASM_ARTIFACT_DOC = ROOT / "docs" / "gate_wasm_artifact_v1.md"
SECRET_POLICY_DOC = ROOT / "docs" / "secret_credential_policy.md"


def _check_playground_loader() -> None:
    text = PLAY_HTML.read_text()
    loader_contract = (
        'new URL("./loom.py", location.href)',
        'bundleUrl.searchParams.set("v", "501-component-adapter-v0")',
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
        'globalValue("loom_heap_strings")',
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
        "loom.build_gate_workflow_v3(_manifest)",
        "loom-gate-workflow/v3",
        "compiler lane:",
        "compiler surface:",
        "component input:",
        "trusted-host-exact-bytes",
        "compiler-evidence",
        "compiler-receipt",
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
        "501 self-verifying checks",
        ">501</div>",
    )
    forbidden = (
        "499 self-verifying checks",
        ">499</div>",
        "498 self-verifying checks",
        ">498</div>",
        "496 self-verifying checks",
        ">496</div>",
        "494 self-verifying checks",
        ">494</div>",
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
        "String, kind 6",
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
        "`loom_heap_strings`",
        "hp + size <= loom_heap_limit",
        "object-family diagnostic counter",
        "memory.size() << 16",
        "Direct `host_ffi` calls receive a tagged argument list",
        "foreign result remains an opaque\n  boundary for trust/provenance",
        "general source-level string allocation and string",
        "are not part of ABI v1.",
        "Compiler state isolation",
        "per-module products of a single compilation",
        "must not be stored in mutable module-global compiler tables",
        "every call to\n`compile_wasm` or `emit_wat` must build a fresh program context",
        "Parallel builds\nof unrelated programs must produce the same bytes and WAT",
        "`loom.trust.v2`",
        "Receipt v2",
        "changes no ABI v1 runtime contract",
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


def _check_wasm_abi_v2_doc() -> None:
    text = WASM_ABI_V2_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WebAssembly Tagged Value ABI v2",
        "implemented, normative, opt-in, and additive",
        "`loom_abi_version == 2`",
        "ABI v1 remains the default",
        "Boolean false | Reserved immediate `1`",
        "Empty list | Reserved immediate `3`",
        "Boolean true | Reserved immediate `5`",
        "Empty record | Reserved immediate `7`",
        "valid pointers are at least `9`",
        "kind-2 record chain terminates with the empty-record immediate `7`",
        "closure uses a distinct kind-7 chain",
        "`compile_wasm_v2`",
        "loom.verify_wasm_source_equivalence_abi_v2",
        "loom.verify_wasm_component_bridge_v0_abi_v2",
        "`abi_version=2`",
        "A v1 verifier rejects v2 bytes",
        "introduces no new host import",
        "not itself a Component Model binary",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Tagged Value ABI v2 contract drift: missing " + ", ".join(missing))


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


def _check_wasm_trust_doc() -> None:
    text = WASM_TRUST_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WASM Trust/Provenance Receipt v1",
        "custom section named `loom.trust.v1`",
        "canonical UTF-8 JSON",
        "source-order inventory",
        "source_sha256",
        "not a signature",
        "not a proof certificate, operator approval, or capability grant",
        "Runtime values do not carry provenance tags in ABI v1",
        "Custom sections are ignored by the WebAssembly core runtime",
        "changes no ABI v1 import, export, tagged-value, heap, or effect contract",
        "runtime=transparent-after-static-check",
        "loom.verify_wasm_trust_receipt(source, wasm_bytes)",
        "returns a JSON-like object with `valid`, `receipt`, and `findings`",
        "does not execute the module",
        "does not establish that a producer owns the listed authors",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: WASM trust/provenance receipt contract drift: missing " + ", ".join(missing))


def _check_wasm_trust_v2_doc() -> None:
    text = WASM_TRUST_V2_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WASM Trust/Provenance Receipt v2",
        "custom section named `loom.trust.v2`",
        "Receipt v1 remains unchanged",
        "canonical UTF-8 JSON",
        "source-order inventory",
        "`roles`",
        "`sub`",
        "`needs`",
        "`required` role list",
        "`lower` and `higher` roles",
        "capability `effect` and required `role`",
        "not a signature",
        "Runtime values remain provenance-free in ABI v1",
        "loom.verify_wasm_trust_receipt_v2(source, wasm_bytes)",
        "does not execute the module",
        "run_wasm` verifies both receipt v1 and receipt v2",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: WASM trust/provenance receipt v2 contract drift: missing " + ", ".join(missing))


def _check_wasm_equivalence_doc() -> None:
    text = WASM_EQUIVALENCE_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WASM Source Equivalence v1",
        "normative read-only verification contract",
        "loom.verify_wasm_source_equivalence(source, wasm_bytes)",
        "current deterministic LOOM compiler",
        "complete WASM byte sequence",
        "loom-wasm-source-equivalence/v1",
        "expected_wasm_sha256",
        "actual_wasm_sha256",
        "wasm-source-mismatch",
        "does not execute the supplied module",
        "does not prove that the compiler implementation is semantically correct",
        "changes no WASM ABI v1",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: WASM source equivalence contract drift: missing " + ", ".join(missing))


def _check_wit_component_boundary() -> None:
    text = WIT_COMPONENT_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WIT Component Boundary v0",
        "loom.build_wit_component_boundary_v0(",
        "loom.verify_wit_component_boundary_v0(",
        "loom-wit-component-boundary/v0",
        "loom-wit-component-boundary-validation/v0",
        "loom-canonical-json-utf8/v0",
        "effectful-export-denied",
        "supplied WASM bytes are byte-identical",
        "component_binary",
        '"absent"',
        '"authorization": "none"',
        "does not yet implement the adapter",
        "Effect-to-WASI projection remains a later explicit gate",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: WIT component-boundary contract drift: missing " + ", ".join(missing))

    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_component_standalone", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone WIT component boundary")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    source = '(defx square () (fn (x) (* x x))) (defx inc_value () (fn (x) (+ x 1)))'
    wasm = modular.compile_wasm(source)
    if standalone.compile_wasm(source) != wasm:
        raise SystemExit("docs parity: WIT component fixture WASM diverged")
    modular_result = modular.build_wit_component_boundary_v0(
        source, wasm, "umbra:loom@0.1.0", "verified-kernel", ["square", "inc_value"],
    )
    standalone_result = standalone.build_wit_component_boundary_v0(
        source, wasm, "umbra:loom@0.1.0", "verified-kernel", ["inc_value", "square"],
    )
    if not modular_result["valid"] or modular_result != standalone_result:
        raise SystemExit("docs parity: modular and standalone WIT component boundaries diverged")
    boundary = modular_result["boundary"]
    modular_verify = modular.verify_wit_component_boundary_v0(
        boundary, source, wasm, "umbra:loom@0.1.0", "verified-kernel", ["inc_value", "square"],
    )
    standalone_verify = standalone.verify_wit_component_boundary_v0(
        boundary, source, wasm, "umbra:loom@0.1.0", "verified-kernel", ["square", "inc_value"],
    )
    if not modular_verify["valid"] or modular_verify != standalone_verify:
        raise SystemExit("docs parity: modular and standalone WIT component verifiers diverged")


def _check_component_bridge() -> None:
    text = COMPONENT_BRIDGE_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Component Bridge Extension v0",
        "loom.component-bridge.v0",
        "loom-component-bridge/v0",
        "loom.verify_wasm_component_bridge_v0(source, wasm_bytes)",
        "loom.verify_wasm_component_bridge_v0_abi_v2(source, wasm_bytes)",
        "loom-component-bridge-validation/v0",
        "strict RFC 3629 UTF-8",
        "loom_component_alloc_bytes",
        "loom_component_make_string",
        "loom_component_cons",
        "loom_component_record",
        "loom_component_variant",
        "ABI v1 record chains end at raw `0`",
        "ABI v2 record chains end at empty-record immediate `7`",
        "A verifier for one profile rejects bytes from the other profile",
        "does not produce a WebAssembly Component",
        "does not approve execution",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Component Bridge v0 contract drift: missing " + ", ".join(missing))

    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_bridge_standalone", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone Component Bridge surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    source = (
        '(defx identity () (fn (x) x)) '
        '(defx sample () (fn () (record (alpha 1)))) '
        '(defx tagged () (fn () (variant Some 2)))'
    )
    modular_wasm = modular.compile_wasm(source)
    standalone_wasm = standalone.compile_wasm(source)
    if modular_wasm != standalone_wasm:
        raise SystemExit("docs parity: modular and standalone Component Bridge bytes diverged")
    modular_verify = modular.verify_wasm_component_bridge_v0(source, modular_wasm)
    standalone_verify = standalone.verify_wasm_component_bridge_v0(source, standalone_wasm)
    if not modular_verify["valid"] or modular_verify != standalone_verify:
        raise SystemExit("docs parity: modular and standalone Component Bridge verifiers diverged")


def _check_component_adapter() -> None:
    words = " ".join(COMPONENT_ADAPTER_DOC.read_text().split())
    required = (
        "LOOM Exact Component Adapter Artifact v0",
        "loom.build_component_adapter_artifact_v0(",
        "loom.verify_component_adapter_artifact_v0(",
        "loom-component-adapter-artifact/v0",
        "loom.component-adapter.v0",
        "exactly three independently recoverable core modules",
        "public component import set and WASI import set are both empty",
        "loom-canonical-json-utf8/v0",
        "Each adapter instance is one-shot",
        "authorization` is always `none",
        "host-only and modular-only",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Component Adapter v0 contract drift: missing " + ", ".join(missing))
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_adapter_standalone", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone Component Adapter boundary")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    if not hasattr(modular, "build_component_adapter_artifact_v0"):
        raise SystemExit("docs parity: modular Component Adapter builder is absent")
    if not hasattr(modular, "verify_component_adapter_artifact_v0"):
        raise SystemExit("docs parity: modular Component Adapter verifier is absent")
    if hasattr(standalone, "build_component_adapter_artifact_v0") or hasattr(standalone, "verify_component_adapter_artifact_v0"):
        raise SystemExit("docs parity: host-only Component Adapter leaked into standalone browser bundle")
    for path in (
        ROOT / "loom_component_adapter.py",
        ROOT / "tools" / "loom-component-builder" / "Cargo.toml",
        ROOT / "tools" / "loom-component-builder" / "Cargo.lock",
        ROOT / "tools" / "loom-component-builder" / "src" / "main.rs",
    ):
        if not path.is_file():
            raise SystemExit("docs parity: Component Adapter implementation input is absent: " + str(path))


def _check_compiler_provenance_doc() -> None:
    text = COMPILER_PROVENANCE_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM WASM Compiler Profile v1",
        "normative host-built compiler identity contract",
        "loom.build_wasm_compiler_profile(surface, components)",
        "loom.verify_wasm_compiler_profile(profile, surface, components)",
        "`modular-python` requires exactly",
        "`standalone-python` requires exactly `docs/loom.py`",
        "loom-wasm-compiler-profile-validation/v1",
        "loom-wasm-compiler-profile/v1",
        "profile_sha256",
        "python3 -m loom_provenance --root . --surface modular-python",
        "builds a real wheel",
        "imports the compiler directly from that wheel",
        "content identity, not a signature or publisher identity",
        "Gate compiler-evidence contract",
        "Existing Gate schemas, trust receipts, and WASM ABI v1 are unchanged",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: compiler provenance contract drift: missing " + ", ".join(missing))


def _check_compiler_evidence_doc() -> None:
    text = COMPILER_EVIDENCE_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Gate WASM Compiler Evidence v1",
        "normative read-only compiler-to-artifact evidence contract",
        "loom.build_wasm_compiler_evidence(manifest, source, wasm_bytes, components)",
        "loom.verify_wasm_compiler_evidence(evidence, manifest, source, wasm_bytes, components)",
        "loom-gate-wasm-compiler-evidence-validation/v1",
        "loom-gate-wasm-compiler-evidence/v1",
        "profile_sha256",
        "artifact_binding_sha256",
        "source_equivalence",
        "evidence_sha256",
        "modular verifier can issue only `modular-python` evidence",
        "standalone verifier can issue only `standalone-python` evidence",
        "does not execute the supplied WASM",
        "not a signature, publisher identity, or operator approval",
        "Receipt v3 and Workflow v3 compose this unchanged evidence",
        "Playground issuance is not part of Compiler Evidence v1",
        "Existing Gate manifest, observation, artifact, receipt, workflow, approval, and WASM ABI schemas are unchanged",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: compiler evidence contract drift: missing " + ", ".join(missing))


def _check_compiler_evidence_v2_doc() -> None:
    words = " ".join(COMPILER_EVIDENCE_V2_DOC.read_text().split())
    required = (
        "LOOM Gate WASM Compiler Evidence v2",
        "normative, deterministic, read-only, advisory, and non-authorizing",
        "loom.build_wasm_compiler_evidence_v2(",
        "loom.verify_wasm_compiler_evidence_v2(",
        "loom-gate-wasm-compiler-evidence-validation/v2",
        "loom-gate-wasm-compiler-evidence/v2",
        "builder_profile_sha256",
        "verifier profile",
        "wasm-compiler-drift",
        "do not report `wasm-source-mismatch`",
        "A bare profile hash is never sufficient builder provenance",
        "Cross-surface verification therefore fails",
        "never executes the supplied WASM",
        "Receipt v3 and Workflow v3 continue to compose unchanged Compiler Evidence v1",
        "Existing Gate manifest, observation, artifact, receipt, workflow, approval",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: compiler evidence v2 contract drift: missing " + ", ".join(missing))


def _check_compiler_receipt_doc() -> None:
    text = COMPILER_RECEIPT_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Gate WASM Compiler Receipt v3",
        "normative, deterministic, advisory, and non-authorizing composition contract",
        "loom.build_wasm_compiler_receipt(manifest, observation, source, wasm_bytes, components)",
        "loom.verify_wasm_compiler_receipt(receipt, manifest, observation, source, wasm_bytes, components)",
        "loom.build_gate_workflow_v3(manifest)",
        "loom-gate-receipt-v3-validation/v1",
        "loom-gate-receipt/v3",
        "compiler_evidence",
        "compiler_evidence.artifact_binding == artifact_evidence.binding",
        "compiler_evidence.artifact_binding_sha256 == artifact_evidence.binding_sha256",
        "artifact-evidence -> compiler-evidence -> compiler-receipt",
        "does not collect component bytes",
        "not a signature or publisher identity",
        "Existing manifest v1/v2, observation v1, receipt v1/v2, workflow v1/v2",
        "Playground issuance and a signed in-toto/SLSA envelope are outside this contract",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: compiler receipt v3 contract drift: missing " + ", ".join(missing))


def _check_compiler_receipt_v4_doc() -> None:
    words = " ".join(COMPILER_RECEIPT_V4_DOC.read_text().split())
    required = (
        "LOOM Gate WASM Compiler Receipt v4 and Workflow v4",
        "normative, deterministic, advisory, and non-authorizing",
        "loom.build_wasm_compiler_receipt_v4(",
        "loom.verify_wasm_compiler_receipt_v4(",
        "loom.build_gate_workflow_v4(manifest)",
        "loom-gate-receipt-v4-validation/v1",
        "loom-gate-receipt/v4",
        "compiler_attribution",
        "compiler_evidence_sha256",
        "wasm-compiler-drift",
        "do not add source or generic receipt mismatch",
        "artifact-evidence -> compiler-evidence -> compiler-receipt -> finish",
        "Initial v4 does not add a CLI command or Playground route",
        "performs no filesystem collection",
        "Receipt v1-v3, Workflow v1-v3",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: compiler receipt v4 contract drift: missing " + ", ".join(missing))


def _check_compiler_evidence_surface_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_compiler_evidence", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone compiler evidence surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "auditor", "role": "audit"},
        "task": {"summary": "Compiler evidence parity", "intent": "Pin exact implementation surfaces"},
        "repositories": [],
        "read_paths": [str(ROOT)],
        "write_paths": [],
        "actions": ["read", "audit"],
        "evidence_required": ["audit"],
    }
    source = "(defx main () (fn () (trust 1 (prov human 42))))"
    wasm = modular.compile_wasm(source)
    modular_paths = ("loom.py", "loom_parse.py", "loom_checker.py", "loom_bounds.py", "loom_recursion.py", "loom_frontend.py", "loom_wasm.py")
    modular_components = {path: ROOT.joinpath(path).read_bytes() for path in modular_paths}
    standalone_components = {"docs/loom.py": DOCS_LOOM.read_bytes()}
    modular_result = modular.build_wasm_compiler_evidence(manifest, source, wasm, modular_components)
    standalone_result = standalone.build_wasm_compiler_evidence(manifest, source, wasm, standalone_components)
    if not modular_result["valid"] or not standalone_result["valid"]:
        raise SystemExit("docs parity: compiler evidence surface failed to build")
    modular_evidence = modular_result["evidence"]
    standalone_evidence = standalone_result["evidence"]
    modular_v2_result = modular.build_wasm_compiler_evidence_v2(manifest, source, wasm, modular_components)
    standalone_v2_result = standalone.build_wasm_compiler_evidence_v2(manifest, source, wasm, standalone_components)
    if not modular_v2_result["valid"] or not standalone_v2_result["valid"]:
        raise SystemExit("docs parity: compiler evidence v2 surface failed to build")
    modular_v2 = modular_v2_result["evidence"]
    standalone_v2 = standalone_v2_result["evidence"]
    modular_v2_self = modular.verify_wasm_compiler_evidence_v2(
        modular_v2, manifest, source, wasm,
        "modular-python", modular_components, modular_components,
    )
    standalone_v2_self = standalone.verify_wasm_compiler_evidence_v2(
        standalone_v2, manifest, source, wasm,
        "standalone-python", standalone_components, standalone_components,
    )
    modular_checks_standalone_v2 = modular.verify_wasm_compiler_evidence_v2(
        standalone_v2, manifest, source, wasm,
        "standalone-python", standalone_components, modular_components,
    )
    standalone_checks_modular_v2 = standalone.verify_wasm_compiler_evidence_v2(
        modular_v2, manifest, source, wasm,
        "modular-python", modular_components, standalone_components,
    )
    observation = {
        "schema": "loom-gate-observation/v1",
        "result": "completed",
        "repositories": [],
        "files_changed": [],
        "actions_observed": ["read", "audit"],
        "evidence": [{"kind": "audit", "status": "pass", "detail": "compiler receipt parity"}],
    }
    modular_receipt_result = modular.build_wasm_compiler_receipt(
        manifest, observation, source, wasm, modular_components
    )
    standalone_receipt_result = standalone.build_wasm_compiler_receipt(
        manifest, observation, source, wasm, standalone_components
    )
    modular_workflow = modular.build_gate_workflow_v3(manifest)
    standalone_workflow = standalone.build_gate_workflow_v3(manifest)
    modular_receipt_v4_result = modular.build_wasm_compiler_receipt_v4(
        manifest, observation, source, wasm, modular_components
    )
    standalone_receipt_v4_result = standalone.build_wasm_compiler_receipt_v4(
        manifest, observation, source, wasm, standalone_components
    )
    if not modular_receipt_v4_result["valid"] or not standalone_receipt_v4_result["valid"]:
        raise SystemExit("docs parity: compiler receipt v4 surface failed to build")
    modular_receipt_v4 = modular_receipt_v4_result["receipt"]
    standalone_receipt_v4 = standalone_receipt_v4_result["receipt"]
    modular_receipt_v4_self = modular.verify_wasm_compiler_receipt_v4(
        modular_receipt_v4, manifest, observation, source, wasm,
        "modular-python", modular_components, modular_components,
    )
    standalone_receipt_v4_self = standalone.verify_wasm_compiler_receipt_v4(
        standalone_receipt_v4, manifest, observation, source, wasm,
        "standalone-python", standalone_components, standalone_components,
    )
    modular_checks_standalone_receipt_v4 = modular.verify_wasm_compiler_receipt_v4(
        standalone_receipt_v4, manifest, observation, source, wasm,
        "standalone-python", standalone_components, modular_components,
    )
    standalone_checks_modular_receipt_v4 = standalone.verify_wasm_compiler_receipt_v4(
        modular_receipt_v4, manifest, observation, source, wasm,
        "modular-python", modular_components, standalone_components,
    )
    modular_workflow_v4 = modular.build_gate_workflow_v4(manifest)
    standalone_workflow_v4 = standalone.build_gate_workflow_v4(manifest)
    contract = (
        modular_evidence["surface"] == "modular-python"
        and standalone_evidence["surface"] == "standalone-python"
        and modular_evidence["artifact_binding"] == standalone_evidence["artifact_binding"]
        and modular_evidence["source_equivalence"] == standalone_evidence["source_equivalence"]
        and modular_evidence["profile_sha256"] != standalone_evidence["profile_sha256"]
        and modular_evidence["evidence_sha256"] != standalone_evidence["evidence_sha256"]
        and not modular.build_wasm_compiler_evidence(manifest, source, wasm, standalone_components)["valid"]
        and not standalone.build_wasm_compiler_evidence(manifest, source, wasm, modular_components)["valid"]
        and modular_receipt_result["valid"]
        and standalone_receipt_result["valid"]
        and modular_receipt_result["receipt"]["schema"] == "loom-gate-receipt/v3"
        and standalone_receipt_result["receipt"]["schema"] == "loom-gate-receipt/v3"
        and modular_receipt_result["receipt"]["artifact_evidence"] == standalone_receipt_result["receipt"]["artifact_evidence"]
        and modular_receipt_result["receipt"]["compiler_evidence"] == modular_evidence
        and standalone_receipt_result["receipt"]["compiler_evidence"] == standalone_evidence
        and modular_receipt_result["receipt"]["receipt_sha256"] != standalone_receipt_result["receipt"]["receipt_sha256"]
        and modular.verify_wasm_compiler_receipt(
            modular_receipt_result["receipt"], manifest, observation, source, wasm, modular_components
        )["valid"]
        and standalone.verify_wasm_compiler_receipt(
            standalone_receipt_result["receipt"], manifest, observation, source, wasm, standalone_components
        )["valid"]
        and modular_workflow["schema"] == standalone_workflow["schema"] == "loom-gate-workflow/v3"
        and modular_workflow["compiler_evidence"]["surface"] == "modular-python"
        and standalone_workflow["compiler_evidence"]["surface"] == "standalone-python"
        and modular_v2["builder_surface"] == "modular-python"
        and standalone_v2["builder_surface"] == "standalone-python"
        and modular_v2["artifact_binding"] == standalone_v2["artifact_binding"]
        and modular_v2["builder_source_equivalence"] == standalone_v2["builder_source_equivalence"]
        and modular_v2["builder_profile_sha256"] != standalone_v2["builder_profile_sha256"]
        and modular_v2_self["valid"]
        and standalone_v2_self["valid"]
        and modular_v2_self["attribution"]["relation"] == "same"
        and standalone_v2_self["attribution"]["relation"] == "same"
        and not modular_checks_standalone_v2["valid"]
        and not standalone_checks_modular_v2["valid"]
        and modular_checks_standalone_v2["attribution"]["relation"] == "different"
        and standalone_checks_modular_v2["attribution"]["relation"] == "different"
        and [item["code"] for item in modular_checks_standalone_v2["findings"]] == ["wasm-compiler-drift"]
        and [item["code"] for item in standalone_checks_modular_v2["findings"]] == ["wasm-compiler-drift"]
        and modular_receipt_v4["schema"] == standalone_receipt_v4["schema"] == "loom-gate-receipt/v4"
        and modular_receipt_v4["artifact_evidence"] == standalone_receipt_v4["artifact_evidence"]
        and modular_receipt_v4["compiler_evidence"] == modular_v2
        and standalone_receipt_v4["compiler_evidence"] == standalone_v2
        and modular_receipt_v4["compiler_evidence_sha256"] == modular_v2["evidence_sha256"]
        and standalone_receipt_v4["compiler_evidence_sha256"] == standalone_v2["evidence_sha256"]
        and modular_receipt_v4["receipt_sha256"] != standalone_receipt_v4["receipt_sha256"]
        and modular_receipt_v4_self["valid"]
        and standalone_receipt_v4_self["valid"]
        and modular_receipt_v4_self["compiler_attribution"]["relation"] == "same"
        and standalone_receipt_v4_self["compiler_attribution"]["relation"] == "same"
        and not modular_checks_standalone_receipt_v4["valid"]
        and not standalone_checks_modular_receipt_v4["valid"]
        and modular_checks_standalone_receipt_v4["compiler_attribution"]["relation"] == "different"
        and standalone_checks_modular_receipt_v4["compiler_attribution"]["relation"] == "different"
        and [item["code"] for item in modular_checks_standalone_receipt_v4["findings"]] == ["wasm-compiler-drift"]
        and [item["code"] for item in standalone_checks_modular_receipt_v4["findings"]] == ["wasm-compiler-drift"]
        and modular_workflow_v4["schema"] == standalone_workflow_v4["schema"] == "loom-gate-workflow/v4"
        and modular_workflow_v4["compiler_evidence"]["builder_surface"] == "modular-python"
        and standalone_workflow_v4["compiler_evidence"]["builder_surface"] == "standalone-python"
        and modular_workflow_v4["compiler_evidence"]["verifier_surface"] == "modular-python"
        and standalone_workflow_v4["compiler_evidence"]["verifier_surface"] == "standalone-python"
        and modular_workflow_v4["compiler_evidence"]["receipt_api"] == "build_wasm_compiler_receipt_v4"
        and standalone_workflow_v4["compiler_evidence"]["receipt_api"] == "build_wasm_compiler_receipt_v4"
    )
    if not contract:
        raise SystemExit("docs parity: compiler evidence surface identity drift")


def _check_action_binding_doc() -> None:
    words = " ".join(ACTION_BINDING_DOC.read_text().split())
    required = (
        "LOOM Interface and Tool Binding v0",
        "normative, deterministic, read-only, advisory, and non-authorizing",
        "build_interface_binding(protocol)",
        "verify_interface_binding(binding, protocol)",
        "build_tool_binding(protocol, authority, operation, input_value)",
        "verify_tool_binding(binding, protocol, authority, operation, input_value)",
        "loom-interface-binding/v0",
        "loom-tool-binding/v0",
        "local-process/v1",
        "urn:loom:host:operator-gate",
        "no-shell/no-network-by-default",
        "no duplicate object keys after NFC normalization",
        "not capabilities",
        "Action Capsule v0 and an additive Approval v2",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: action binding v0 contract drift: missing " + ", ".join(missing))


def _check_action_binding_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_action_binding", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone action binding surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    protocol = "local-process/v1"
    authority = "urn:loom:host:operator-gate"
    operation = "process"
    input_value = {"action": "process", "label": "cafe\u0301", "arguments": [1, True, None]}
    modular_interface = modular.build_interface_binding(protocol)
    standalone_interface = standalone.build_interface_binding(protocol)
    modular_tool = modular.build_tool_binding(protocol, authority, operation, input_value)
    standalone_tool = standalone.build_tool_binding(protocol, authority, operation, input_value)
    contract = (
        modular_interface == standalone_interface
        and modular_interface["valid"]
        and modular.verify_interface_binding(modular_interface["binding"], protocol)["valid"]
        and standalone.verify_interface_binding(standalone_interface["binding"], protocol)["valid"]
        and modular_tool == standalone_tool
        and modular_tool["valid"]
        and modular.verify_tool_binding(modular_tool["binding"], protocol, authority, operation, input_value)["valid"]
        and standalone.verify_tool_binding(standalone_tool["binding"], protocol, authority, operation, input_value)["valid"]
    )
    if not contract:
        raise SystemExit("docs parity: modular and standalone action bindings diverged")


def _check_action_semantics_doc() -> None:
    words = " ".join(ACTION_SEMANTICS_DOC.read_text().split())
    required = (
        "LOOM Action Semantics v0",
        "normative, deterministic, pure, advisory, and non-authorizing",
        "build_action_semantics_v0(",
        "verify_action_semantics_v0(",
        "loom-action-semantics-validation/v0",
        "loom-action-semantics/v0",
        "loom-action-source-limits/v0",
        "loom-action-target-mediation/v0",
        "operator-required",
        '(ffi "operator-gate" "<tool-binding-sha256>")',
        "declared == performed == required == capabilities == [FFI]",
        "wasm-compiler-drift",
        "do not add source, manifest, tool-input, semantic, or generic mismatch",
        "performs no filesystem collection",
        "executes no command",
        "Compiler Receipt v4 already exists as a separate stable evidence contract",
        "Existing Gate, Tool/Interface Binding, Compiler Evidence v1/v2",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: action semantics v0 contract drift: missing " + ", ".join(missing))
    if "Receipt v4 remain separate future contracts" in words:
        raise SystemExit("docs parity: action semantics v0 misclassifies stable Compiler Receipt v4 as future")


def _check_action_semantics_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_action_semantics", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone action semantics surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Bind one exact checked process action",
            "intent": "Pin effects, compiler identity, and operator-gated host authority",
        },
        "repositories": [],
        "read_paths": [],
        "write_paths": [],
        "actions": ["process"],
        "evidence_required": [],
    }
    validation = modular.validate_manifest(manifest)
    input_value = {
        "action": "process",
        "manifest_sha256": validation["manifest_sha256"],
    }
    protocol = "local-process/v1"
    authority = "urn:loom:host:operator-gate"
    modular_tool_result = modular.build_tool_binding(
        protocol, authority, "process", input_value
    )
    standalone_tool_result = standalone.build_tool_binding(
        protocol, authority, "process", input_value
    )
    if modular_tool_result != standalone_tool_result or not modular_tool_result["valid"]:
        raise SystemExit("docs parity: action semantics tool fixture diverged")
    tool = modular_tool_result["binding"]
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool["binding_sha256"]}"))))'
    )
    wasm = modular.compile_wasm(source)
    if standalone.compile_wasm(source) != wasm:
        raise SystemExit("docs parity: action semantics WASM fixture diverged")
    modular_paths = (
        "loom.py", "loom_parse.py", "loom_checker.py", "loom_bounds.py",
        "loom_recursion.py", "loom_frontend.py", "loom_wasm.py",
    )
    modular_components = {path: ROOT.joinpath(path).read_bytes() for path in modular_paths}
    standalone_components = {"docs/loom.py": DOCS_LOOM.read_bytes()}
    modular_result = modular.build_action_semantics_v0(
        manifest, tool, input_value, source, wasm, modular_components, "main"
    )
    standalone_result = standalone.build_action_semantics_v0(
        manifest, tool, input_value, source, wasm, standalone_components, "main"
    )
    if not modular_result["valid"] or not standalone_result["valid"]:
        raise SystemExit("docs parity: action semantics surface failed to build")
    modular_semantics = modular_result["semantics"]
    standalone_semantics = standalone_result["semantics"]
    modular_self = modular.verify_action_semantics_v0(
        modular_semantics, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, modular_components, "main",
    )
    standalone_self = standalone.verify_action_semantics_v0(
        standalone_semantics, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, standalone_components, "main",
    )
    modular_checks_standalone = modular.verify_action_semantics_v0(
        standalone_semantics, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, modular_components, "main",
    )
    standalone_checks_modular = standalone.verify_action_semantics_v0(
        modular_semantics, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, standalone_components, "main",
    )
    shared_fields = (
        "schema", "advisory", "manifest_sha256", "policy", "policy_decision",
        "tool_binding", "tool_binding_sha256", "artifact_binding_sha256",
        "entrypoint", "checker_verdict", "checker_verdict_sha256",
        "effect_contract", "source_limits", "target_mediation",
    )
    contract = (
        all(modular_semantics[key] == standalone_semantics[key] for key in shared_fields)
        and modular_semantics["compiler_evidence"]["builder_surface"] == "modular-python"
        and standalone_semantics["compiler_evidence"]["builder_surface"] == "standalone-python"
        and modular_semantics["compiler_evidence_sha256"] != standalone_semantics["compiler_evidence_sha256"]
        and modular_semantics["semantics_sha256"] != standalone_semantics["semantics_sha256"]
        and modular_self["valid"]
        and standalone_self["valid"]
        and modular_self["compiler_attribution"]["relation"] == "same"
        and standalone_self["compiler_attribution"]["relation"] == "same"
        and not modular_checks_standalone["valid"]
        and not standalone_checks_modular["valid"]
        and modular_checks_standalone["compiler_attribution"]["relation"] == "different"
        and standalone_checks_modular["compiler_attribution"]["relation"] == "different"
        and [item["code"] for item in modular_checks_standalone["findings"]] == ["wasm-compiler-drift"]
        and [item["code"] for item in standalone_checks_modular["findings"]] == ["wasm-compiler-drift"]
    )
    if not contract:
        raise SystemExit("docs parity: modular and standalone action semantics diverged")


def _check_action_capsule_doc() -> None:
    words = " ".join(ACTION_CAPSULE_DOC.read_text().split())
    required = (
        "LOOM Action Capsule v0",
        "normative, deterministic, pure, advisory, and non-authorizing",
        "build_action_capsule_v0(",
        "verify_action_capsule_v0(",
        "loom-action-capsule-validation/v0",
        "loom-action-capsule/v0",
        "loom-action-actor-declaration/v0",
        "loom-action-capsule-bindings/v0",
        "loom-action-execution-class/v0",
        "loom-action-capsule-lifecycle/v0",
        'concrete_invocation: "unbound"',
        'authorization: "none"',
        "approval_eligible: false",
        "loom-action-invocation-binding/v0",
        "wasm-compiler-drift",
        "does not add source, manifest, tool-input",
        "execute no command",
        "cannot be approved for execution",
        "Claim v0, and Trusted Host Mediation v0 are also implemented as separate contracts",
        "implemented as a separate additive contract",
        "Compiler Receipt v4 already exists as stable evidence",
        "Existing Gate, Interface/Tool Binding, Action Semantics, Compiler Evidence",
        "No CLI, Playground, MCP, A2A, WASI, identity, or host-executor adapter",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: action capsule v0 contract drift: missing " + ", ".join(missing))
    if "Receipt v4 remain separate future contracts" in words:
        raise SystemExit("docs parity: action capsule v0 misclassifies stable Compiler Receipt v4 as future")


def _check_action_capsule_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_action_capsule", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone Action Capsule surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Compose one exact checked process capsule",
            "intent": "Pin semantics while leaving concrete invocation unbound",
        },
        "repositories": [],
        "read_paths": [],
        "write_paths": [],
        "actions": ["process"],
        "evidence_required": [],
    }
    validation = modular.validate_manifest(manifest)
    input_value = {
        "action": "process",
        "manifest_sha256": validation["manifest_sha256"],
    }
    protocol = "local-process/v1"
    authority = "urn:loom:host:operator-gate"
    modular_tool = modular.build_tool_binding(
        protocol, authority, "process", input_value
    )
    standalone_tool = standalone.build_tool_binding(
        protocol, authority, "process", input_value
    )
    if modular_tool != standalone_tool or not modular_tool["valid"]:
        raise SystemExit("docs parity: Action Capsule tool fixture diverged")
    tool = modular_tool["binding"]
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool["binding_sha256"]}"))))'
    )
    wasm = modular.compile_wasm(source)
    if standalone.compile_wasm(source) != wasm:
        raise SystemExit("docs parity: Action Capsule WASM fixture diverged")
    modular_paths = (
        "loom.py", "loom_parse.py", "loom_checker.py", "loom_bounds.py",
        "loom_recursion.py", "loom_frontend.py", "loom_wasm.py",
    )
    modular_components = {path: ROOT.joinpath(path).read_bytes() for path in modular_paths}
    standalone_components = {"docs/loom.py": DOCS_LOOM.read_bytes()}
    modular_result = modular.build_action_capsule_v0(
        manifest, tool, input_value, source, wasm, modular_components, "main"
    )
    standalone_result = standalone.build_action_capsule_v0(
        manifest, tool, input_value, source, wasm, standalone_components, "main"
    )
    if not modular_result["valid"] or not standalone_result["valid"]:
        raise SystemExit("docs parity: Action Capsule surface failed to build")
    modular_capsule = modular_result["capsule"]
    standalone_capsule = standalone_result["capsule"]
    modular_self = modular.verify_action_capsule_v0(
        modular_capsule, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, modular_components, "main",
    )
    standalone_self = standalone.verify_action_capsule_v0(
        standalone_capsule, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, standalone_components, "main",
    )
    modular_checks_standalone = modular.verify_action_capsule_v0(
        standalone_capsule, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, modular_components, "main",
    )
    standalone_checks_modular = standalone.verify_action_capsule_v0(
        modular_capsule, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, standalone_components, "main",
    )
    shared_fields = (
        "schema", "advisory", "manifest", "manifest_sha256", "gate_decision",
        "declared_actor", "execution_class", "lifecycle",
    )
    contract = (
        all(modular_capsule[key] == standalone_capsule[key] for key in shared_fields)
        and modular_capsule["bindings"]["tool_binding_sha256"] == standalone_capsule["bindings"]["tool_binding_sha256"]
        and modular_capsule["bindings"]["artifact_binding_sha256"] == standalone_capsule["bindings"]["artifact_binding_sha256"]
        and modular_capsule["bindings"]["compiler_evidence_sha256"] != standalone_capsule["bindings"]["compiler_evidence_sha256"]
        and modular_capsule["capsule_sha256"] != standalone_capsule["capsule_sha256"]
        and modular_capsule["execution_class"]["concrete_invocation"] == "unbound"
        and modular_capsule["lifecycle"]["authorization"] == "none"
        and modular_capsule["lifecycle"]["approval_eligible"] is False
        and modular_self["valid"]
        and standalone_self["valid"]
        and modular_self["compiler_attribution"]["relation"] == "same"
        and standalone_self["compiler_attribution"]["relation"] == "same"
        and not modular_checks_standalone["valid"]
        and not standalone_checks_modular["valid"]
        and modular_checks_standalone["compiler_attribution"]["relation"] == "different"
        and standalone_checks_modular["compiler_attribution"]["relation"] == "different"
        and [item["code"] for item in modular_checks_standalone["findings"]] == ["wasm-compiler-drift"]
        and [item["code"] for item in standalone_checks_modular["findings"]] == ["wasm-compiler-drift"]
    )
    if not contract:
        raise SystemExit("docs parity: modular and standalone Action Capsule diverged")


def _check_action_invocation_binding_doc() -> None:
    words = " ".join(ACTION_INVOCATION_BINDING_DOC.read_text().split())
    required = (
        "LOOM Exact Invocation Binding v0",
        "implemented, normative, deterministic, pure, advisory, and non-authorizing",
        "build_action_invocation_binding_v0(",
        "verify_action_invocation_binding_v0(",
        "loom-action-invocation-binding-validation/v0",
        "loom-action-invocation-binding/v0",
        "loom-local-process-invocation/v0",
        "loom-host-adapter-identity/v0",
        "loom-action-invocation-stdin/v0",
        "loom-action-invocation-cross-links/v0",
        "loom-action-invocation-lifecycle/v0",
        '"authorization": "none"',
        '"approval_eligible": true',
        '"approval_subject": "binding_sha256"',
        '"shell": "denied"',
        '"network": "denied"',
        "value commitments, never raw values",
        "wasm-compiler-drift",
        "perform no filesystem lookup",
        "does not approve or execute",
        "implemented as separate stateful contracts",
        "Existing Gate, Interface/Tool Binding, Action Semantics, Action Capsule",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: action invocation binding v0 contract drift: missing " + ", ".join(missing))


def _check_action_invocation_binding_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_action_invocation", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone Invocation Binding surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Bind one exact local process invocation",
            "intent": "Create an immutable Approval v2 subject without authority",
        },
        "repositories": [],
        "read_paths": [],
        "write_paths": [],
        "actions": ["process"],
        "evidence_required": [],
    }
    validation = modular.validate_manifest(manifest)
    input_value = {"action": "process", "manifest_sha256": validation["manifest_sha256"]}
    protocol = "local-process/v1"
    authority = "urn:loom:host:operator-gate"
    modular_tool_result = modular.build_tool_binding(protocol, authority, "process", input_value)
    standalone_tool_result = standalone.build_tool_binding(protocol, authority, "process", input_value)
    if modular_tool_result != standalone_tool_result or not modular_tool_result["valid"]:
        raise SystemExit("docs parity: Invocation Binding tool fixture diverged")
    tool = modular_tool_result["binding"]
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool["binding_sha256"]}"))))'
    )
    wasm = modular.compile_wasm(source)
    if standalone.compile_wasm(source) != wasm:
        raise SystemExit("docs parity: Invocation Binding WASM fixture diverged")
    invocation = {
        "schema": "loom-local-process-invocation/v0",
        "protocol": protocol,
        "authority": authority,
        "operation": "process",
        "foreign_component": "operator-gate",
        "adapter": {
            "schema": "loom-host-adapter-identity/v0",
            "executable_uri": "file:///opt/loom/operator-gate",
            "artifact_sha256": "a" * 64,
            "entrypoint": "process",
        },
        "argv": ["process"],
        "working_directory_uri": "file:///workspace/loom",
        "environment": [{"name": "LOOM_MODE", "value_sha256": "b" * 64}],
        "stdin": {
            "schema": "loom-action-invocation-stdin/v0",
            "encoding": "canonical-json/utf-8",
            "payload_sha256": tool["input_sha256"],
        },
        "timeout_ms": 30000,
        "shell": "denied",
        "network": "denied",
    }
    modular_paths = (
        "loom.py", "loom_parse.py", "loom_checker.py", "loom_bounds.py",
        "loom_recursion.py", "loom_frontend.py", "loom_wasm.py",
    )
    modular_components = {path: ROOT.joinpath(path).read_bytes() for path in modular_paths}
    standalone_components = {"docs/loom.py": DOCS_LOOM.read_bytes()}
    modular_result = modular.build_action_invocation_binding_v0(
        manifest, tool, input_value, source, wasm, modular_components, "main", invocation
    )
    standalone_result = standalone.build_action_invocation_binding_v0(
        manifest, tool, input_value, source, wasm, standalone_components, "main", invocation
    )
    if not modular_result["valid"] or not standalone_result["valid"]:
        raise SystemExit("docs parity: Invocation Binding surface failed to build")
    modular_binding = modular_result["binding"]
    standalone_binding = standalone_result["binding"]
    modular_self = modular.verify_action_invocation_binding_v0(
        modular_binding, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, modular_components, "main", invocation,
    )
    standalone_self = standalone.verify_action_invocation_binding_v0(
        standalone_binding, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, standalone_components, "main", invocation,
    )
    modular_checks_standalone = modular.verify_action_invocation_binding_v0(
        standalone_binding, manifest, tool, input_value, source, wasm,
        "standalone-python", standalone_components, modular_components, "main", invocation,
    )
    standalone_checks_modular = standalone.verify_action_invocation_binding_v0(
        modular_binding, manifest, tool, input_value, source, wasm,
        "modular-python", modular_components, standalone_components, "main", invocation,
    )
    contract = (
        modular_binding["invocation"] == standalone_binding["invocation"]
        and modular_binding["lifecycle"] == standalone_binding["lifecycle"]
        and modular_binding["capsule_sha256"] != standalone_binding["capsule_sha256"]
        and modular_binding["binding_sha256"] != standalone_binding["binding_sha256"]
        and modular_binding["lifecycle"]["authorization"] == "none"
        and modular_binding["lifecycle"]["approval_eligible"] is True
        and modular_self["valid"]
        and standalone_self["valid"]
        and modular_self["compiler_attribution"]["relation"] == "same"
        and standalone_self["compiler_attribution"]["relation"] == "same"
        and not modular_checks_standalone["valid"]
        and not standalone_checks_modular["valid"]
        and modular_checks_standalone["compiler_attribution"]["relation"] == "different"
        and standalone_checks_modular["compiler_attribution"]["relation"] == "different"
        and [item["code"] for item in modular_checks_standalone["findings"]] == ["wasm-compiler-drift"]
        and [item["code"] for item in standalone_checks_modular["findings"]] == ["wasm-compiler-drift"]
    )
    if not contract:
        raise SystemExit("docs parity: modular and standalone Invocation Binding diverged")


def _check_action_approval_v2_doc() -> None:
    words = " ".join(ACTION_APPROVAL_V2_DOC.read_text().split())
    required = (
        "LOOM Exact Action Approval v2",
        "implemented, normative, signed, short-lived, exact-invocation-bound, and claim-required",
        "build_action_approval_request_v2(binding, nonce)",
        "validate_action_approval_request_v2(request)",
        "verify_action_capsule_approval_v2(",
        "loom-action-approval-challenge/v2",
        "loom-action-approval-request/v2",
        "loom-action-approval-review/v2",
        "loom-action-approval-request-lifecycle/v2",
        "loom-action-capsule-approval/v2",
        "loom-action-capsule-approval-validation/v2",
        'authorization: "claim-required"',
        'approval_subject: "binding_sha256"',
        'approval_scope: "exact-invocation"',
        "maximum_ttl_ms",
        "900000 milliseconds",
        "Boolean timestamps",
        "explicit trusted-host input",
        "writes only `approval.json`",
        "cannot be substituted",
        "Capsule Claim v0, Trusted Host Mediation v0, Bounded Execution v0, and terminal Action Capsule Result v0 are implemented as separate additive stateful contracts",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Action Approval v2 contract drift: missing " + ", ".join(missing))


def _check_action_approval_v2_parity() -> None:
    import loom as modular
    spec = importlib.util.spec_from_file_location("loom_docs_action_approval", DOCS_LOOM)
    if spec is None or spec.loader is None:
        raise SystemExit("docs parity: could not load standalone Action Approval surface")
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    manifest = {
        "schema": "loom-gate-manifest/v1",
        "agent": {"id": "codex", "role": "code"},
        "task": {
            "summary": "Approve one exact local process invocation",
            "intent": "Bind operator authority to exact executable and inputs",
        },
        "repositories": [],
        "read_paths": [],
        "write_paths": [],
        "actions": ["process"],
        "evidence_required": [],
    }
    validation = modular.validate_manifest(manifest)
    input_value = {"action": "process", "manifest_sha256": validation["manifest_sha256"]}
    protocol = "local-process/v1"
    authority = "urn:loom:host:operator-gate"
    modular_tool_result = modular.build_tool_binding(protocol, authority, "process", input_value)
    standalone_tool_result = standalone.build_tool_binding(protocol, authority, "process", input_value)
    if modular_tool_result != standalone_tool_result or not modular_tool_result["valid"]:
        raise SystemExit("docs parity: Action Approval tool fixture diverged")
    tool = modular_tool_result["binding"]
    source = (
        '(defx main (FFI!) (fn () (seamN 1 (FFI) '
        f'(ffi "operator-gate" "{tool["binding_sha256"]}"))))'
    )
    wasm = modular.compile_wasm(source)
    if standalone.compile_wasm(source) != wasm:
        raise SystemExit("docs parity: Action Approval WASM fixture diverged")
    invocation = {
        "schema": "loom-local-process-invocation/v0",
        "protocol": protocol,
        "authority": authority,
        "operation": "process",
        "foreign_component": "operator-gate",
        "adapter": {
            "schema": "loom-host-adapter-identity/v0",
            "executable_uri": "file:///opt/loom/operator-gate",
            "artifact_sha256": "a" * 64,
            "entrypoint": "process",
        },
        "argv": ["process", "--canonical-json"],
        "working_directory_uri": "file:///workspace/loom",
        "environment": [{"name": "LOOM_MODE", "value_sha256": "b" * 64}],
        "stdin": {
            "schema": "loom-action-invocation-stdin/v0",
            "encoding": "canonical-json/utf-8",
            "payload_sha256": tool["input_sha256"],
        },
        "timeout_ms": 30000,
        "shell": "denied",
        "network": "denied",
    }
    modular_paths = (
        "loom.py", "loom_parse.py", "loom_checker.py", "loom_bounds.py",
        "loom_recursion.py", "loom_frontend.py", "loom_wasm.py",
    )
    modular_components = {path: ROOT.joinpath(path).read_bytes() for path in modular_paths}
    standalone_components = {"docs/loom.py": DOCS_LOOM.read_bytes()}
    modular_binding = modular.build_action_invocation_binding_v0(
        manifest, tool, input_value, source, wasm, modular_components, "main", invocation,
    )["binding"]
    standalone_binding = standalone.build_action_invocation_binding_v0(
        manifest, tool, input_value, source, wasm, standalone_components, "main", invocation,
    )["binding"]
    nonce = "7" * 64
    modular_result = modular.build_action_approval_request_v2(modular_binding, nonce)
    standalone_result = standalone.build_action_approval_request_v2(standalone_binding, nonce)
    if not modular_result["valid"] or not standalone_result["valid"]:
        raise SystemExit("docs parity: Action Approval request failed to build")
    modular_request = modular_result["request"]
    standalone_request = standalone_result["request"]
    contract = (
        modular.validate_action_approval_request_v2(modular_request) == modular_result
        and standalone.validate_action_approval_request_v2(standalone_request) == standalone_result
        and modular_request["schema"] == standalone_request["schema"] == "loom-action-approval-request/v2"
        and modular_request["challenge"]["schema"] == standalone_request["challenge"]["schema"] == "loom-action-approval-challenge/v2"
        and modular_request["review"] == standalone_request["review"]
        and modular_request["lifecycle"] == standalone_request["lifecycle"]
        and modular_request["binding"]["invocation"] == standalone_request["binding"]["invocation"]
        and modular_request["binding"]["binding_sha256"] != standalone_request["binding"]["binding_sha256"]
        and modular_request["request_sha256"] != standalone_request["request_sha256"]
        and modular_request["lifecycle"]["authorization"] == "none"
        and modular_request["lifecycle"]["claim_required"] is True
    )
    if not contract:
        raise SystemExit("docs parity: modular and standalone Action Approval diverged")


def _check_action_claim_v0_doc() -> None:
    words = " ".join(ACTION_CLAIM_V0_DOC.read_text().split())
    required = (
        "LOOM Capsule Claim v0",
        "implemented, normative, atomic, one-use, exact-invocation-bound, and non-executing",
        "claim_action_capsule_approval_v0(",
        "loom-action-capsule-claim-validation/v0",
        "loom-action-capsule-claim/v0",
        'authorization: "host-mediation-required"',
        "`advisory: false`",
        '"claim_scope": "exact-invocation"',
        "explicit trusted-host input",
        "SQLite `BEGIN IMMEDIATE`",
        "primary key on `approval_sha256`",
        "parent mode to `0700` and ledger mode to `0600`",
        "rejects attached triggers or views",
        "exactly one may insert",
        "Invalid approvals do not create a ledger",
        "Approval v2 cannot be consumed through the v1 API",
        "does not remeasure executable bytes or environment values",
        "imports SQLite only when claim is invoked",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Capsule Claim v0 contract drift: missing " + ", ".join(missing))


def _check_action_host_mediation_v0_doc() -> None:
    words = " ".join(ACTION_HOST_MEDIATION_V0_DOC.read_text().split())
    required = (
        "LOOM Trusted Host Mediation v0",
        "implemented, normative, stateful, one-use, host-measuring, and non-executing",
        "mediate_action_capsule_claim_v0(",
        "validate_action_host_mediation_v0(mediation)",
        "pure structural verifier",
        "loom-action-host-mediation-validation/v0",
        "loom-action-host-mediation/v0",
        "loom-action-host-measurement/v0",
        'authorization: "bounded-execution-required"',
        "explicit trusted-host input",
        "descriptor-relatively with `O_NOFOLLOW`, `O_DIRECTORY`, and `O_CLOEXEC`",
        "at most 64 MiB",
        "stores no raw value",
        "SQLite `BEGIN IMMEDIATE`",
        "exact canonical `action_mediations_v0` schema",
        "exactly one can become `ready`",
        "performs no shell expansion, network access, credential lookup, subprocess creation",
        "does not claim to eliminate the post-measurement TOCTOU window",
        "remeasure its bytes immediately before spawn",
        "imports OS and SQLite facilities only when mediation is invoked",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Trusted Host Mediation v0 contract drift: missing " + ", ".join(missing))


def _check_action_bounded_execution_v0_doc() -> None:
    words = " ".join(ACTION_BOUNDED_EXECUTION_V0_DOC.read_text().split())
    required = (
        "LOOM Bounded Execution v0",
        "process-executing, and fail-closed on missing network isolation",
        "execute_action_host_mediation_v0(",
        "validate_action_bounded_execution_v0(execution)",
        'authorization: "terminal-result-required"',
        "does not treat `shell=False` as network isolation",
        "darwin-seatbelt-network-deny/v0",
        "linux-user-network-namespace/v0",
        "`policy_sha256` binds the exact fixed profile arguments",
        "before ledger reservation and before target execution",
        "private-executable-snapshot",
        "root-owned-immutable-path",
        "path-custody evidence",
        "Same-UID mutation",
        "SQLite `BEGIN IMMEDIATE`",
        "host crash may leave a `reserved` row",
        "completely replaced environment",
        "Timeout kills the complete process group",
        "limited to 1 MiB",
        "No stdout, stderr, environment value, credential, stdin payload",
        "does not itself issue Action Capsule Result v0",
        "recomputes every nested and outer hash",
        "fails closed before reservation",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Bounded Execution v0 contract drift: missing " + ", ".join(missing))


def _check_action_capsule_result_v0_doc() -> None:
    words = " ".join(ACTION_CAPSULE_RESULT_V0_DOC.read_text().split())
    required = (
        "LOOM Action Capsule Result v0",
        "terminal, content-addressed, stateful, one-use, and non-authorizing",
        "finalize_action_capsule_result_v0(",
        "validate_action_capsule_result_v0(result, public_key_value)",
        "loom-action-capsule-result/v0",
        "loom-action-terminal-outcome/v0",
        "loom-action-result-lifecycle/v0",
        "execution start time",
        "contains no stdout, stderr, environment value, credential, stdin payload",
        "SQLite `BEGIN IMMEDIATE`",
        "exact canonical `action_claims_v0`, `action_mediations_v0`, `action_executions_v0`, and `action_results_v0` table schemas",
        "Replay and concurrent finalization",
        'authorization: "none"',
        'replay: "denied"',
        "does not execute this API",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Action Capsule Result v0 contract drift: missing " + ", ".join(missing))


def _check_action_result_attestation_v0_doc() -> None:
    words = " ".join(ACTION_RESULT_ATTESTATION_V0_DOC.read_text().split())
    required = (
        "LOOM Action Result Attestation v0",
        "signed, content-addressed, post-execution, externally issued, and non-authorizing",
        "prepare_action_result_attestation_v0(",
        "build_action_result_attestation_v0(",
        "verify_action_result_attestation_v0(",
        "never reads or receives a private key",
        "https://in-toto.io/Statement/v1",
        "https://umbraaeternaa.github.io/loom/attestation/action-result/v0",
        "application/vnd.in-toto+json",
        "verify the DSSE signature over the exact payload bytes",
        "parse that payload once",
        "reject duplicate keys, NaN or Infinity, excessive depth or node count",
        "The Result status must match the Receipt result",
        'authorization: "none"',
        'execution_repeated: false',
        "Approval v2 remains the only operator-signed pre-execution authority",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: Action Result Attestation v0 contract drift: missing " + ", ".join(missing))


def _check_wasm_artifact_doc() -> None:
    text = WASM_ARTIFACT_DOC.read_text()
    words = " ".join(text.split())
    required = (
        "LOOM Gate WASM artifact binding and evidence v1",
        "loom.build_wasm_artifact_binding(manifest, source, wasm_bytes)",
        "loom-gate-wasm-artifact-validation/v1",
        "loom-gate-wasm-artifact/v1",
        "manifest_sha256",
        "source_sha256",
        "wasm_sha256",
        "trust_receipt_sha256",
        "loom.verify_wasm_artifact_binding(binding, manifest, source, wasm_bytes)",
        "Source Equivalence v1",
        "byte identity with the current deterministic compiler output",
        "loom.build_wasm_artifact_evidence(manifest, source, wasm_bytes)",
        "loom-gate-wasm-artifact-evidence/v1",
        "loom.build_wasm_artifact_receipt(manifest, observation, source, wasm_bytes)",
        "loom-gate-receipt/v2",
        "loom.verify_wasm_artifact_receipt(...)",
        "loom.build_gate_workflow_v2(manifest)",
        "artifact-evidence",
        "content-addressing, not a signature",
        "does not execute WASM",
        "Existing closed Gate manifest v1/v2 schemas are unchanged",
        "Operator signing remains a separate Gate approval contract",
    )
    missing = [needle for needle in required if needle not in words]
    if missing:
        raise SystemExit("docs parity: WASM artifact binding contract drift: missing " + ", ".join(missing))


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
    _check_wasm_abi_v2_doc()
    _check_quantity_mediation_doc()
    _check_meter_frame_doc()
    _check_call_budget_doc()
    _check_recurrence_doc()
    _check_bounds_doc()
    _check_contextual_bounds_doc()
    _check_wasm_trust_doc()
    _check_wasm_trust_v2_doc()
    _check_wasm_equivalence_doc()
    _check_wit_component_boundary()
    _check_component_bridge()
    _check_component_adapter()
    _check_compiler_provenance_doc()
    _check_compiler_evidence_doc()
    _check_compiler_evidence_v2_doc()
    _check_compiler_receipt_doc()
    _check_compiler_receipt_v4_doc()
    _check_compiler_evidence_surface_parity()
    _check_action_binding_doc()
    _check_action_binding_parity()
    _check_action_semantics_doc()
    _check_action_semantics_parity()
    _check_action_capsule_doc()
    _check_action_capsule_parity()
    _check_action_invocation_binding_doc()
    _check_action_invocation_binding_parity()
    _check_action_approval_v2_doc()
    _check_action_approval_v2_parity()
    _check_action_claim_v0_doc()
    _check_action_host_mediation_v0_doc()
    _check_action_bounded_execution_v0_doc()
    _check_action_capsule_result_v0_doc()
    _check_action_result_attestation_v0_doc()
    _check_wasm_artifact_doc()
    _check_secret_credential_policy_doc()
    _check_pyodide_import_boundary()
    result = _run_injected_citadel()
    if result != 0:
        return result
    print("PASS docs parity — published bundle is standalone and citadel-green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
