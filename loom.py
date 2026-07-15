#!/usr/bin/env python3
# LOOM v0 — the unifying core, made REAL. The citadel of ARGUS/plt.
# Effect ROWS {Pure,IO,Net,Alloc,FFI} + SUPERSET rule (declared >= actual) + REQUIRED effects `E!` (two-sided row:
# floor MUST-perform <= actual <= ceiling MAY-perform -> the row IS the D7 synthesis contract) + CHECKED SEAMS (foreign boundary
# declares+checks its contract) + effect HANDLERS: `handle` DISCHARGES an effect (drops it), `with` REINTERPRETS
# it (routes the effect's operation to a handler fn, trading E for the handler's own effect — e.g. mock Net with
# a pure fn => networked code becomes provably pure). Plus control flow (if/let), recursion, and first-class
# functions with ROW-POLYMORPHISM + anonymous LAMBDAS/CLOSURES. A tiny s-expr language + static effect checker
# + interpreter. Grown nightly by the organism, verified by run_tests.py — the language only ever grows GREEN.
EFFECTS = {"Pure", "IO", "Net", "Alloc", "FFI", "Rand"}   # Rand = nondeterminism (randomness / wall-clock)
# checker vocab MUST stay == interpreter (ev) vocab — no form the checker knows that the runtime can't run.
BUILTIN_EFF = {"print": {"IO"}, "net": {"Net"}, "alloc": {"Alloc"}, "rand": {"Rand"}}
PURE_OPS = {"+", "-", "*", "=", "<", ">",          # pure ops the interpreter runs; legitimate heads, zero effect
            "list", "cons", "head", "tail", "empty"}  # pure list primitives (map/fold are then DEFINABLE in LOOM)
OP = {"IO": "print", "Net": "net", "Alloc": "alloc", "Rand": "rand"}   # which builtin operation a `with`-handler reinterprets
_MISS = object()                                        # sentinel for scoped save/restore
INT_BITS = 31
INT_MIN = -(1 << (INT_BITS - 1))
INT_MAX = (1 << (INT_BITS - 1)) - 1
_INT_MOD = 1 << INT_BITS


def _is_symbol(node):
    return isinstance(node, str) and type(node) is not str


def _i31(n):
    """Canonical signed i31 wraparound shared by every LOOM execution backend."""
    return ((n - INT_MIN) % _INT_MOD) + INT_MIN


def _int_literal_errors(nodes):
    errors = []
    def walk(node):
        if isinstance(node, int):
            if node < INT_MIN or node > INT_MAX:
                errors.append(f"integer literal {node} outside LOOM i31 range [{INT_MIN}, {INT_MAX}]")
        elif isinstance(node, list):
            for item in node: walk(item)
    for node in nodes: walk(node)
    return errors


def _check_call_literals(call_ast):
    errors = _int_literal_errors(call_ast)
    if errors: raise LoomError("; ".join(errors))


def plin(p): return p[1] if (isinstance(p, list) and len(p) >= 2 and p[0] == "lin") else None   # (lin r) = LINEAR param
def pname(p):                                                    # a param is `name` (value) · `(name eff..)` (fn) · `(lin r)` (linear)
    if isinstance(p, list): return p[1] if p and p[0] == "lin" else p[0]
    return p
def platent(p):                                                 # fn-param's latent effects; None for value / linear params
    if isinstance(p, list) and p and p[0] == "lin": return None
    return set(p[1:]) if isinstance(p, list) else None
def is_var(e): return _is_symbol(e) and e not in EFFECTS and e[:1].islower()  # lowercase token = effect variable
def is_fn_expr(e, fns, penv):                                    # does this expression denote a function?
    return (isinstance(e, list) and len(e) > 0 and e[0] == "fn") or (_is_symbol(e) and (e in fns or e in penv))


class LoomError(Exception): pass


import loom_parse as _loom_parse
import loom_checker as _loom_checker
import loom_runtime as _loom_runtime
import loom_cli as _loom_cli
import loom_gate as _loom_gate
import loom_observer as _loom_observer
import loom_evidence as _loom_evidence
import loom_approval as _loom_approval
import loom_executor as _loom_executor

_PARSE_FRONTEND = _loom_parse.Frontend(LoomError)

_CHECKER_FRONTEND = _loom_checker.Frontend(
    EFFECTS,
    BUILTIN_EFF,
    PURE_OPS,
    plin,
    pname,
    platent,
    is_var,
    is_fn_expr,
    _int_literal_errors,
    _MISS,
    LoomError,
)


def tokenize(s):
    return _loom_parse.tokenize(_PARSE_FRONTEND, s)


def tokenize_spans(s):
    return _loom_parse.tokenize_spans(_PARSE_FRONTEND, s)


def parse_spans(s):
    return _loom_parse.parse_spans(_PARSE_FRONTEND, s)


def _read(t):
    return _loom_parse._read(_PARSE_FRONTEND, t)


def parse(s):
    return _loom_parse.parse(_PARSE_FRONTEND, s)


def _roleclauses(tail):
    return _loom_checker._roleclauses(tail)


def check(program):
    """Check one program via the extracted checker module while preserving the public facade."""
    return _loom_checker.check(program, _CHECKER_FRONTEND)


Closure = _loom_runtime.Closure
FOREIGN = _loom_runtime.FOREIGN
_RUNTIME_FRONTEND = _loom_runtime.Frontend(parse, check, pname, LoomError, OP, _check_call_literals, _roleclauses, _i31)


def call_fn(val, args, fns, out, handlers):
    return _loom_runtime.call_fn(_RUNTIME_FRONTEND, val, args, fns, out, handlers)


def ev(node, env, fns, out, handlers=None):
    return _loom_runtime.ev(_RUNTIME_FRONTEND, node, env, fns, out, handlers)


def run_call(program_src, call_src):
    """Static-check a program, then evaluate one call against it. Rejects if it fails the effect checker."""
    return _loom_runtime.run_call(program_src, call_src, _RUNTIME_FRONTEND)


# ---- PORTABLE CODEGEN: implementation lives in loom_codegen.py; public facade stays stable. ----
import loom_codegen as _loom_codegen

_CODEGEN_FRONTEND = _loom_codegen.Frontend(parse, check, pname, LoomError, OP, _check_call_literals, INT_MIN, _INT_MOD)

def _emit(node):
    return _loom_codegen._emit(_CODEGEN_FRONTEND, node)

def compile_py(program_src):
    return _loom_codegen.compile_py(program_src, _CODEGEN_FRONTEND)

def run_compiled(program_src, call_src):
    return _loom_codegen.run_compiled(program_src, call_src, _CODEGEN_FRONTEND)

def _emit_js(node):
    return _loom_codegen._emit_js(_CODEGEN_FRONTEND, node)

def compile_js(program_src):
    return _loom_codegen.compile_js(program_src, _CODEGEN_FRONTEND)

def run_js(program_src, call_src):
    return _loom_codegen.run_js(program_src, call_src, _CODEGEN_FRONTEND)

# ---- THIRD TARGET: WebAssembly. The implementation lives in loom_wasm.py;
#      this module supplies the checked LOOM frontend through an explicit dependency boundary. ----
import loom_wasm as _loom_wasm

_WASM_ABI_VERSION = _loom_wasm.WASM_ABI_VERSION
_WASM_FRONTEND = _loom_wasm.Frontend(parse, parse_spans, check, pname, LoomError, OP, _check_call_literals, platent, _roleclauses)

def compile_wasm(program_src):
    return _loom_wasm.compile_wasm(program_src, _WASM_FRONTEND)

def emit_wat(program_src):
    return _loom_wasm.emit_wat(program_src, _WASM_FRONTEND)

def run_wasm(program_src, call_src):
    return _loom_wasm.run_wasm(program_src, call_src, _WASM_FRONTEND)


# ---- CLI: turn the kernel into a usable TOOL. `python3 loom.py <check|run|build|audit> file.loom [call] [--target py|js|wat]` ----
_CLI_FRONTEND = _loom_cli.Frontend(
    parse,
    check,
    run_call,
    compile_py,
    compile_js,
    emit_wat,
    LoomError,
    metadata={
        "citadel_checks": 434,
        "wasm_abi_version": _WASM_ABI_VERSION,
        "i31_bits": INT_BITS,
        "backends": ["interpreter", "python", "javascript", "webassembly", "wat"],
        "commands": [
            "about",
            "release-check",
            "check",
            "run",
            "build",
            "audit",
            "source-map",
            "gate",
            "gate-workflow",
            "gate-request",
            "gate-claim",
            "gate-finish",
            "gate-plan",
            "gate-exec-finish",
            "gate-attempt",
            "gate-process-attempt",
            "gate-process-finish",
        ],
    },
)


def build_verdict(program_src):
    """Return the stable JSON-safe checker verdict used by LOOM Gate clients."""
    return _loom_cli.build_verdict(_CLI_FRONTEND, program_src)


def build_about():
    """Return the stable JSON-safe LOOM implementation capability summary."""
    return _loom_cli.build_about(_CLI_FRONTEND)


def build_gate_workflow(manifest):
    """Return a stable JSON-safe route for a bounded Gate action lifecycle."""
    return _loom_cli.build_gate_workflow(manifest)


def validate_manifest(manifest):
    """Validate and hash a read-only LOOM Gate manifest v1."""
    return _loom_gate.validate_manifest(manifest)


def evaluate_manifest(manifest):
    """Apply advisory operator/Codex/Cloud policy v1 to a task manifest."""
    return _loom_gate.evaluate_manifest(manifest)


def build_gate_diagnostics(manifest):
    """Build redacted operator-facing Gate diagnostics for a task manifest."""
    return _loom_gate.build_gate_diagnostics(manifest)


def build_receipt(manifest, observation):
    """Build a deterministic advisory receipt from a manifest and observation."""
    return _loom_gate.build_receipt(manifest, observation)


def collect_observation(manifest, result, actions_observed, evidence):
    """Collect read-only Git facts for a LOOM Gate observation."""
    return _loom_observer.collect_observation(manifest, result, actions_observed, evidence)


def collect_ci_evidence(manifest, observation, run_id):
    """Collect read-only GitHub CI evidence bound to an observed LOOM head."""
    return _loom_evidence.collect_ci_evidence(manifest, observation, run_id)


def build_approval_challenge(manifest, nonce):
    """Build a manifest-bound operator approval challenge."""
    return _loom_approval.build_approval_challenge(manifest, nonce)


def build_approval_request(manifest, challenge):
    """Build a closed approval envelope for an operator-controlled issuer."""
    return _loom_approval.build_approval_request(manifest, challenge)


def validate_approval_request(request):
    """Validate an approval envelope at the operator issuer boundary."""
    return _loom_approval.validate_approval_request(request)


def verify_operator_approval(manifest, challenge, approval):
    """Verify a signed approval against the pinned operator public key."""
    return _loom_approval.verify_operator_approval(manifest, challenge, approval)


def consume_operator_approval(manifest, challenge, approval):
    """Verify and atomically consume a signed one-use operator approval."""
    return _loom_approval.consume_operator_approval(manifest, challenge, approval)


def claim_operator_approval(manifest, challenge, approval):
    """Claim a signed approval before a trusted host starts its action."""
    return _loom_approval.claim_operator_approval(manifest, challenge, approval)


def finish_claimed_receipt(manifest, observation, challenge, approval, claim):
    """Finalize a claimed action exactly once as completed or failed."""
    return _loom_approval.finish_claimed_receipt(manifest, observation, challenge, approval, claim)


def plan_claimed_execution(manifest, challenge, approval, claim, actions):
    """Build a bounded host execution plan for an already claimed approval."""
    return _loom_executor.plan_claimed_execution(manifest, challenge, approval, claim, actions)


def finish_claimed_execution(manifest, challenge, approval, claim, plan, result, actions_observed, evidence):
    """Collect observation facts and finalize a claimed execution plan."""
    return _loom_executor.finish_claimed_execution(manifest, challenge, approval, claim, plan, result, actions_observed, evidence)


def plan_process_execution(manifest, challenge, approval, claim):
    """Build the narrow process-only trusted host plan."""
    return _loom_executor.plan_process_execution(manifest, challenge, approval, claim)


def finish_process_execution(manifest, challenge, approval, claim, plan, result, evidence=None):
    """Finalize a process-only trusted host plan."""
    return _loom_executor.finish_process_execution(manifest, challenge, approval, claim, plan, result, evidence)


def validate_host_attempt(attempt):
    """Validate the closed trusted-host attempt result contract."""
    return _loom_executor.validate_host_attempt(attempt)


def validate_process_attempt(plan, attempt):
    """Dry-run validate a host attempt against a process-only plan."""
    return _loom_executor.validate_process_attempt(plan, attempt)


def finish_process_attempt(manifest, challenge, approval, claim, plan, attempt):
    """Finalize a process-only plan from a validated host attempt object."""
    return _loom_executor.finish_process_attempt(manifest, challenge, approval, claim, plan, attempt)


def build_consumed_receipt(manifest, observation, challenge, approval):
    """Build a receipt after atomically consuming its signed operator approval."""
    return _loom_approval.build_consumed_receipt(manifest, observation, challenge, approval)


def _cli(argv):
    return _loom_cli.cli(argv, _CLI_FRONTEND)

def main(argv=None):
    import sys
    return _cli(sys.argv[1:] if argv is None else argv)

if __name__ == "__main__":
    import sys
    sys.exit(main())
