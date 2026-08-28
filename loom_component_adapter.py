#!/usr/bin/env python3
"""Deterministic, non-authorizing LOOM Component Adapter Artifact v0."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


SCHEMA = "loom-component-adapter-artifact/v0"
BUILD_SCHEMA = "loom-component-adapter-build/v0"
VALIDATION_SCHEMA = "loom-component-adapter-validation/v0"
EVIDENCE_SECTION = "loom.component-adapter.v0"
EFFECTFUL_SCHEMA = "loom-effectful-component-adapter/v1"
EFFECTFUL_BUILD_SCHEMA = "loom-effectful-component-adapter-build/v1"
EFFECTFUL_VALIDATION_SCHEMA = "loom-effectful-component-adapter-validation/v1"
EFFECTFUL_EVIDENCE_SECTION = "loom.effectful-component-adapter.v1"
HOST_POLICY_SCHEMA = "loom-effectful-component-host-policy/v1"
HOST_POLICY_VALIDATION_SCHEMA = "loom-effectful-component-host-policy-validation/v1"
MAX_ENVELOPE_BYTES = 1 << 20
MAX_DEPTH = 64
MAX_CELLS = 2048
MAX_ARGS = 32
CANONICAL_MEMORY_PAGES = 35
CANONICAL_INPUT_START = 65536
CANONICAL_INPUT_END = CANONICAL_INPUT_START + MAX_ENVELOPE_BYTES
CANONICAL_SCRATCH_START = 1130000
CANONICAL_SCRATCH_END = 1149000
CANONICAL_ARGS_START = 1150000
CANONICAL_NUMBER_END = 1199900
CANONICAL_OUTPUT_START = 1200000
WASM_TOOLS_VERSION = "wasm-tools 1.257.1 (3ef3cefcd 2026-08-19)"
WASMTIME_VERSION = "wasmtime 48.0.0 (f1412a598 2026-08-20)"
WASM_TOOLS_SHA256 = frozenset((
    "0caa33cff1a81fd1acd0a20a6cd955411c9932350ebbbe32ebae70708483e752",  # aarch64 macOS
    "ff4dcf239ce09315e531394c63c7f0e2cbe9856dfbbd1f5b2b4d267b4f09df95",  # x86_64 Linux
))
WASMTIME_SHA256 = frozenset((
    "1b9185f271806517d7f838b7f9446ee870feb0b22ee9a104e4af334b8c52ccdd",  # aarch64 macOS
    "4fcabfd0e346761d32f250d4ce55706acef526495aaefb1eb8e6afe3bb0890c5",  # x86_64 Linux
))
BUILDER_SOURCE_TREE_SHA256 = "8de3766b6a627924aaa62b739c5f45fd83f52e294abc5ea1474651703dfc4ec3"
BUILDER_LOCKFILE_SHA256 = "16a0cfe122acfd6d56ca9b9678714b46a911e48714e8ad52da275910e45b4c13"
EFFECTFUL_BUILDER_SOURCE_TREE_SHA256 = "449de276a592eeae3127184433bf586cbbb1197091f4b7f472937e9f0c7eddcb"
EFFECTFUL_BUILDER_LOCKFILE_SHA256 = "6b0d46b53aa468420e9b711049cb2690bd51d4a40d74f9932b5f599bec84c623"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_POLICY_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ENV_SIGNATURES = (
    ("push_handler", 2), ("pop_handler", 1), ("current_handler", 1),
    ("host_print", 1), ("push_caps", 1), ("pop_caps", 0),
    ("has_cap", 1), ("host_ffi", 3),
)


class Frontend:
    __slots__ = (
        "verify_boundary", "verify_bridge", "verify_mapping", "emit_wat",
        "compile_effectful_wasm",
    )

    def __init__(
        self, verify_boundary, verify_bridge, verify_mapping=None, emit_wat=None,
        compile_effectful_wasm=None,
    ):
        self.verify_boundary = verify_boundary
        self.verify_bridge = verify_bridge
        self.verify_mapping = verify_mapping
        self.emit_wat = emit_wat
        self.compile_effectful_wasm = compile_effectful_wasm


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _result(schema, valid, *, artifact=None, component=None, findings=()):
    result = {"schema": schema, "valid": bool(valid), "findings": list(findings)}
    if schema in (BUILD_SCHEMA, EFFECTFUL_BUILD_SCHEMA):
        result.update({"artifact": artifact if valid else None, "component": component if valid else None})
    else:
        result["artifact"] = artifact if valid else None
    return result


def _run(argv, *, input_bytes=None):
    try:
        return subprocess.run(argv, input=input_bytes, capture_output=True, check=False)
    except OSError as exc:
        raise ValueError(f"cannot execute {argv[0]}: {exc}") from exc


def _tool(path, expected_version, expected_hashes, label):
    if not isinstance(path, (str, os.PathLike)):
        raise ValueError(f"{label} executable path is required")
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} is not an executable file")
    digest = _sha256(resolved.read_bytes())
    if digest not in expected_hashes:
        raise ValueError(f"{label} executable SHA-256 mismatch")
    version = _run([str(resolved), "--version"])
    text = version.stdout.decode("utf-8", "strict").strip()
    if version.returncode or text != expected_version:
        raise ValueError(f"{label} version mismatch: {text!r}")
    return {"version": text, "sha256": digest}, str(resolved)


def _builder_source_identity():
    return {
        "source_tree_sha256": BUILDER_SOURCE_TREE_SHA256,
        "lockfile_sha256": BUILDER_LOCKFILE_SHA256,
    }


def _effectful_builder_source_identity():
    return {
        "source_tree_sha256": EFFECTFUL_BUILDER_SOURCE_TREE_SHA256,
        "lockfile_sha256": EFFECTFUL_BUILDER_LOCKFILE_SHA256,
    }


def _builder_tool(path):
    if not isinstance(path, (str, os.PathLike)):
        raise ValueError("builder executable path is required")
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("builder is not an executable file")
    identity = {"sha256": _sha256(resolved.read_bytes()), **_builder_source_identity()}
    return identity, str(resolved)


def _effectful_builder_tool(path):
    if not isinstance(path, (str, os.PathLike)):
        raise ValueError("effectful builder executable path is required")
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("effectful builder is not an executable file")
    identity = {
        "sha256": _sha256(resolved.read_bytes()),
        **_effectful_builder_source_identity(),
    }
    return identity, str(resolved)


def _wat_data(value):
    return "".join(f"\\{byte:02x}" for byte in value)


def _deny_env_wat():
    funcs = []
    for name, arity in _ENV_SIGNATURES:
        params = " ".join("(param i32)" for _ in range(arity))
        funcs.append(f'  (func (export "{name}") {params} (result i32) unreachable)')
    return "(module\n" + "\n".join(funcs) + "\n)\n"


def _canonical_memory_wat():
    return f'(module (memory (export "memory") {CANONICAL_MEMORY_PAGES} {CANONICAL_MEMORY_PAGES}))\n'


def _effect_env_wat(effects):
    effects = set(effects)
    unknown = effects - {"IO", "Rand", "Alloc"}
    if unknown:
        raise ValueError("effect environment contains unsupported effects: " + ", ".join(sorted(unknown)))
    random_import = (
        '  (import "wasi" "get_random_u64" (func $get-random-u64 (result i64)))\n'
        if "Rand" in effects else ""
    )
    host_rand = (
        "  (func (export \"host_rand\") (result i32)\n"
        "    call $get-random-u64 i32.wrap_i64 i32.const 1073741823 i32.and i32.const 1 i32.shl)\n"
        if "Rand" in effects else
        '  (func (export "host_rand") (result i32) unreachable)\n'
    )
    host_print = (
        "  (func (export \"host_print\") (param $value i32) (result i32)\n"
        "    global.get $print-count i32.const 2048 i32.ge_u if unreachable end\n"
        "    global.get $print-count i32.const 2 i32.shl local.get $value i32.store\n"
        "    global.get $print-count i32.const 1 i32.add global.set $print-count local.get $value)\n"
        if "IO" in effects else
        '  (func (export "host_print") (param i32) (result i32) unreachable)\n'
    )
    return f'''(module
{random_import}  (memory 1)
  (global $cap-depth (mut i32) (i32.const 0))
  (global $print-count (mut i32) (i32.const 0))
  (func $handler-depth-address (param $effect i32) (result i32)
    local.get $effect i32.const 5 i32.ge_u if unreachable end
    i32.const 12288 local.get $effect i32.const 2 i32.shl i32.add)
  (func $handler-slot-address (param $effect i32) (param $depth i32) (result i32)
    i32.const 16384 local.get $effect i32.const 8 i32.shl i32.add
    local.get $depth i32.const 2 i32.shl i32.add)
  (func (export "push_handler") (param $effect i32) (param $handler i32) (result i32)
    (local $depth i32) (local $address i32)
    local.get $effect call $handler-depth-address local.tee $address i32.load local.tee $depth
    i32.const 64 i32.ge_u if unreachable end
    local.get $effect local.get $depth call $handler-slot-address local.get $handler i32.store
    local.get $address local.get $depth i32.const 1 i32.add i32.store i32.const 0)
  (func (export "pop_handler") (param $effect i32) (result i32)
    (local $depth i32) (local $address i32)
    local.get $effect call $handler-depth-address local.tee $address i32.load local.tee $depth
    i32.eqz if unreachable end
    local.get $address local.get $depth i32.const 1 i32.sub i32.store i32.const 0)
  (func (export "current_handler") (param $effect i32) (result i32) (local $depth i32)
    local.get $effect call $handler-depth-address i32.load local.tee $depth
    i32.eqz if i32.const 0 return end
    local.get $effect local.get $depth i32.const 1 i32.sub call $handler-slot-address i32.load)
{host_print}  (func (export "push_caps") (param $mask i32) (result i32)
    global.get $cap-depth i32.const 64 i32.ge_u if unreachable end
    i32.const 8192 global.get $cap-depth i32.const 2 i32.shl i32.add
    local.get $mask i32.store
    global.get $cap-depth i32.const 1 i32.add global.set $cap-depth i32.const 0)
  (func (export "pop_caps") (result i32)
    global.get $cap-depth i32.eqz if unreachable end
    global.get $cap-depth i32.const 1 i32.sub global.set $cap-depth i32.const 0)
  (func (export "has_cap") (param $effect i32) (result i32) (local $mask i32)
    global.get $cap-depth i32.eqz if i32.const 1 return end
    i32.const 8192 global.get $cap-depth i32.const 1 i32.sub i32.const 2 i32.shl i32.add
    i32.load local.set $mask
    local.get $mask i32.const 1 local.get $effect i32.shl i32.and i32.eqz i32.eqz)
  (func (export "host_ffi") (param i32 i32 i32) (result i32) unreachable)
{host_rand}  (func (export "print_count") (result i32) global.get $print-count)
  (func (export "print_at") (param $index i32) (result i32)
    local.get $index global.get $print-count i32.ge_u if unreachable end
    local.get $index i32.const 2 i32.shl i32.load)
  (func (export "clear_prints") i32.const 0 i32.const 0 global.get $print-count i32.const 2 i32.shl memory.fill
    i32.const 0 global.set $print-count)
)
'''


def _host_policy_body(mapping, policy_id):
    if not isinstance(mapping, dict) or not _HEX64.fullmatch(str(mapping.get("mapping_sha256", ""))):
        raise ValueError("mapping must carry a valid mapping_sha256")
    if not isinstance(policy_id, str) or not _POLICY_ID.fullmatch(policy_id):
        raise ValueError("policy_id must be a lowercase kebab identifier")
    projection = mapping.get("capability_projection")
    if not isinstance(projection, dict):
        raise ValueError("mapping capability projection is absent")
    effects = sorted(item.get("effect") for item in projection.get("effects", ()) if isinstance(item, dict))
    if not effects or any(effect not in {"IO", "Rand", "Alloc"} for effect in effects):
        raise ValueError("host policy requires the closed non-empty IO,Rand,Alloc projection")
    imports = projection.get("imports")
    if not isinstance(imports, list) or any(not isinstance(item, str) for item in imports):
        raise ValueError("mapping import set is malformed")
    return {
        "schema": HOST_POLICY_SCHEMA,
        "policy_id": policy_id,
        "mapping_sha256": mapping["mapping_sha256"],
        "wasi_release": projection.get("wasi_release"),
        "allowed_effects": effects,
        "allowed_imports": sorted(imports),
        "bindings": {
            "stdout": "inherited-stdout-only" if "IO" in effects else "absent",
            "random": "wasi-random-u64-modulo-1073741824" if "Rand" in effects else "absent",
            "allocation": "loom-internal-fixed-page" if "Alloc" in effects else "absent",
        },
        "denied_authority": ["environment", "filesystem", "network", "stderr", "stdin"],
        "ambient_authority": False,
        "authorization": "none",
    }


def prepare_effectful_component_host_policy_v1(mapping, policy_id):
    try:
        body = _host_policy_body(mapping, policy_id)
        body["policy_sha256"] = _sha256(_json_bytes(body))
        return {
            "schema": HOST_POLICY_VALIDATION_SCHEMA,
            "valid": True,
            "policy": body,
            "findings": [],
        }
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "schema": HOST_POLICY_VALIDATION_SCHEMA,
            "valid": False,
            "policy": None,
            "findings": [_finding("host_policy", "host-policy-rejected", str(exc))],
        }


def verify_effectful_component_host_policy_v1(policy, mapping, policy_id):
    expected = prepare_effectful_component_host_policy_v1(mapping, policy_id)
    if not expected["valid"]:
        return expected
    findings = []
    if not isinstance(policy, dict):
        findings.append(_finding("host_policy", "expected-object", "host policy must be an object"))
    else:
        body = dict(policy)
        supplied_hash = body.pop("policy_sha256", None)
        if supplied_hash != _sha256(_json_bytes(body)):
            findings.append(_finding("host_policy.policy_sha256", "host-policy-hash-mismatch", "host policy hash does not match canonical policy bytes"))
        if policy != expected["policy"]:
            findings.append(_finding("host_policy", "host-policy-mismatch", "host policy does not match the exact mapping and policy identifier"))
    return {
        "schema": HOST_POLICY_VALIDATION_SCHEMA,
        "valid": not findings,
        "policy": policy if not findings else None,
        "findings": findings,
    }


def _canonical_name_bytes(name):
    encoded = json.dumps(name, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return encoded[1:-1].encode("ascii")


def _data_table(bridge):
    cursor = 64
    items = []
    for family in ("field_ids", "tag_ids"):
        for item in bridge[family]:
            raw = _canonical_name_bytes(item["name"])
            quoted = b'"' + raw + b'"'
            items.append({
                "family": family, "id": item["id"], "name": item["name"],
                "raw": raw, "raw_ptr": cursor,
                "quoted": quoted, "quoted_ptr": cursor + len(raw),
            })
            cursor += len(raw) + len(quoted)
    special = []
    for name in ("$variant", "args"):
        raw = _canonical_name_bytes(name)
        special.append({"name": name, "raw": raw, "raw_ptr": cursor})
        cursor += len(raw)
    literals = {}
    for name, raw in (
        ("ok", b'{"ok":'), ("error", b'{"error":{"code":"invalid-envelope","message":"request rejected"}}'),
        ("variant", b'{"$variant":['), ("true", b"true"), ("false", b"false"),
        ("empty-list", b"[]"), ("empty-record", b"{}"),
    ):
        literals[name] = {"raw": raw, "ptr": cursor}
        cursor += len(raw)
    return items, special, literals, cursor


def _match_cases(items, family):
    lines = []
    for item in items:
        if item["family"] != family:
            continue
        lines += [
            f"    local.get $p local.get $n i32.const {item['raw_ptr']} i32.const {len(item['raw'])} call $span-eq",
            f"    if i32.const {item['id']} return end",
        ]
    lines.append("    i32.const -1")
    return "\n".join(lines)


def _emit_name_cases(items, family):
    lines = []
    for item in sorted((x for x in items if x["family"] == family), key=lambda x: x["name"]):
        lines += [
            f"    local.get $id i32.const {item['id']} i32.eq",
            f"    if i32.const {item['quoted_ptr']} i32.const {len(item['quoted'])} call $emit-static i32.const 1 return end",
        ]
    lines.append("    i32.const 0")
    return "\n".join(lines)


def _import_lines(exports, *, effectful_effects=None):
    effects = set(effectful_effects or ())
    effectful = effectful_effects is not None
    lines = [
        '  (import "loom" "memory" (memory $loom 1))',
        '  (import "loom" "loom_component_alloc_bytes" (func $alloc-bytes (param i32) (result i32)))',
        '  (import "loom" "loom_component_make_string" (func $make-string (param i32 i32) (result i32)))',
        '  (import "loom" "loom_component_cons" (func $cons (param i32 i32) (result i32)))',
        '  (import "loom" "loom_component_record" (func $record (param i32 i32 i32) (result i32)))',
        '  (import "loom" "loom_component_variant" (func $variant (param i32 i32) (result i32)))',
    ]
    if effectful:
        lines += [
            '  (import "canonical" "memory" (memory $canonical 35 35))',
            '  (import "envlog" "print_count" (func $print-count (result i32)))',
            '  (import "envlog" "print_at" (func $print-at (param i32) (result i32)))',
            '  (import "envlog" "clear_prints" (func $clear-prints))',
        ]
        if "IO" in effects:
            lines += [
                '  (import "wasi" "get_stdout" (func $get-stdout (result i32)))',
                '  (import "wasi" "blocking_write_and_flush" (func $blocking-write-and-flush (param i32 i32 i32 i32)))',
                '  (import "wasi" "drop_output_stream" (func $drop-output-stream (param i32)))',
            ]
    for item in exports:
        params = " ".join("(param i32)" for _ in range(item["arity"]))
        lines.append(f'  (import "loom" "{item["loom_name"]}" (func $loom-{item["wit_name"]} {params} (result i32)))')
    return "\n".join(lines)


def _field_rank_cases(items):
    lines = []
    ordered = sorted((x for x in items if x["family"] == "field_ids"), key=lambda x: x["name"])
    for rank, item in enumerate(ordered):
        lines.append(f"    local.get $id i32.const {item['id']} i32.eq if i32.const {rank} return end")
    lines.append("    i32.const -1")
    return "\n".join(lines)


def _parser_wat(items, special, literals):
    variant = next(x for x in special if x["name"] == "$variant")
    args = next(x for x in special if x["name"] == "args")
    return f'''  (func $fail (param $code i32)
    global.get $err i32.eqz if local.get $code global.set $err end)
  (func $peek (result i32)
    global.get $pos global.get $end i32.ge_u
    if (result i32) i32.const -1 else global.get $pos i32.load8_u $canonical end)
  (func $take (result i32) (local $b i32)
    call $peek local.tee $b i32.const 0 i32.lt_s
    if i32.const 1 call $fail else global.get $pos i32.const 1 i32.add global.set $pos end
    local.get $b)
  (func $expect (param $want i32)
    call $take local.get $want i32.ne if i32.const 1 call $fail end)
  (func $hex (param $b i32) (result i32)
    local.get $b i32.const 48 i32.ge_u local.get $b i32.const 57 i32.le_u i32.and
    if (result i32) local.get $b i32.const 48 i32.sub
    else
      local.get $b i32.const 97 i32.ge_u local.get $b i32.const 102 i32.le_u i32.and
      if (result i32) local.get $b i32.const 87 i32.sub else i32.const -1 end
    end)
  (func $read-u4 (result i32) (local $v i32) (local $h i32) (local $i i32)
    loop $digits
      call $take call $hex local.tee $h i32.const 0 i32.lt_s
      if i32.const 2 call $fail i32.const 0 return end
      local.get $v i32.const 4 i32.shl local.get $h i32.or local.set $v
      local.get $i i32.const 1 i32.add local.tee $i i32.const 4 i32.lt_u br_if $digits
    end
    local.get $v)
  (func $scan-string (result i32) (local $b i32) (local $e i32) (local $u i32) (local $lo i32) (local $n i32)
    i32.const 34 call $expect
    global.get $pos global.set $scan-start
    loop $chars
      call $take local.tee $b
      i32.const 34 i32.eq
      if
        global.get $pos i32.const 1 i32.sub global.set $scan-end
        local.get $n global.set $scan-len
        i32.const 1 return
      end
      local.get $b i32.const 32 i32.lt_u local.get $b i32.const 126 i32.gt_u i32.or
      if i32.const 2 call $fail i32.const 0 return end
      local.get $b i32.const 92 i32.eq
      if
        call $take local.tee $e
        i32.const 34 i32.eq local.get $e i32.const 92 i32.eq i32.or
        if local.get $n i32.const 1 i32.add local.set $n br $chars end
        local.get $e i32.const 98 i32.eq local.get $e i32.const 102 i32.eq i32.or
        local.get $e i32.const 110 i32.eq i32.or local.get $e i32.const 114 i32.eq i32.or
        local.get $e i32.const 116 i32.eq i32.or
        if local.get $n i32.const 1 i32.add local.set $n br $chars end
        local.get $e i32.const 117 i32.ne
        if i32.const 2 call $fail i32.const 0 return end
        call $read-u4 local.tee $u
        global.get $err if i32.const 0 return end
        local.get $u i32.const 55296 i32.ge_u local.get $u i32.const 56319 i32.le_u i32.and
        if
          i32.const 92 call $expect i32.const 117 call $expect call $read-u4 local.tee $lo
          local.get $lo i32.const 56320 i32.lt_u local.get $lo i32.const 57343 i32.gt_u i32.or
          if i32.const 2 call $fail i32.const 0 return end
          local.get $n i32.const 4 i32.add local.set $n br $chars
        end
        local.get $u i32.const 56320 i32.ge_u local.get $u i32.const 57343 i32.le_u i32.and
        if i32.const 2 call $fail i32.const 0 return end
        local.get $u i32.const 32 i32.ge_u local.get $u i32.const 127 i32.lt_u i32.and
        if i32.const 2 call $fail i32.const 0 return end
        local.get $u i32.const 8 i32.eq local.get $u i32.const 9 i32.eq i32.or
        local.get $u i32.const 10 i32.eq i32.or local.get $u i32.const 12 i32.eq i32.or
        local.get $u i32.const 13 i32.eq i32.or
        if i32.const 2 call $fail i32.const 0 return end
        local.get $n
        local.get $u i32.const 128 i32.lt_u
        if (result i32) i32.const 1 else local.get $u i32.const 2048 i32.lt_u if (result i32) i32.const 2 else i32.const 3 end end
        i32.add local.set $n br $chars
      end
      local.get $n i32.const 1 i32.add local.set $n
      br $chars
    end
    i32.const 0)
  (func $loom-byte (param $p i32) (param $b i32)
    local.get $p local.get $b i32.store8 $loom)
  (func $put-cp (param $p i32) (param $u i32) (result i32)
    local.get $u i32.const 128 i32.lt_u
    if local.get $p local.get $u call $loom-byte local.get $p i32.const 1 i32.add return end
    local.get $u i32.const 2048 i32.lt_u
    if
      local.get $p local.get $u i32.const 6 i32.shr_u i32.const 192 i32.or call $loom-byte
      local.get $p i32.const 1 i32.add local.get $u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
      local.get $p i32.const 2 i32.add return
    end
    local.get $u i32.const 65536 i32.lt_u
    if
      local.get $p local.get $u i32.const 12 i32.shr_u i32.const 224 i32.or call $loom-byte
      local.get $p i32.const 1 i32.add local.get $u i32.const 6 i32.shr_u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
      local.get $p i32.const 2 i32.add local.get $u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
      local.get $p i32.const 3 i32.add return
    end
    local.get $p local.get $u i32.const 18 i32.shr_u i32.const 240 i32.or call $loom-byte
    local.get $p i32.const 1 i32.add local.get $u i32.const 12 i32.shr_u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
    local.get $p i32.const 2 i32.add local.get $u i32.const 6 i32.shr_u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
    local.get $p i32.const 3 i32.add local.get $u i32.const 63 i32.and i32.const 128 i32.or call $loom-byte
    local.get $p i32.const 4 i32.add)
  (func $decode-string (param $start i32) (param $stop i32) (param $dst i32)
    (local $save i32) (local $b i32) (local $e i32) (local $u i32) (local $lo i32)
    global.get $pos local.set $save local.get $start global.set $pos
    block $done loop $copy
      global.get $pos local.get $stop i32.ge_u br_if $done
      call $take local.tee $b i32.const 92 i32.ne
      if local.get $dst local.get $b call $loom-byte local.get $dst i32.const 1 i32.add local.set $dst br $copy end
      call $take local.tee $e
      i32.const 34 i32.eq if i32.const 34 local.set $u else
      local.get $e i32.const 92 i32.eq if i32.const 92 local.set $u else
      local.get $e i32.const 98 i32.eq if i32.const 8 local.set $u else
      local.get $e i32.const 102 i32.eq if i32.const 12 local.set $u else
      local.get $e i32.const 110 i32.eq if i32.const 10 local.set $u else
      local.get $e i32.const 114 i32.eq if i32.const 13 local.set $u else
      local.get $e i32.const 116 i32.eq if i32.const 9 local.set $u else
        call $read-u4 local.set $u
        local.get $u i32.const 55296 i32.ge_u local.get $u i32.const 56319 i32.le_u i32.and
        if i32.const 92 call $expect i32.const 117 call $expect call $read-u4 local.set $lo
          local.get $u i32.const 55296 i32.sub i32.const 10 i32.shl
          local.get $lo i32.const 56320 i32.sub i32.or i32.const 65536 i32.add local.set $u
        end
      end end end end end end end
      local.get $dst local.get $u call $put-cp local.set $dst br $copy
    end end
    local.get $save global.set $pos)
  (func $parse-string (result i32) (local $p i32)
    call $scan-string drop global.get $err if i32.const 0 return end
    global.get $scan-len call $alloc-bytes local.set $p
    global.get $scan-start global.get $scan-end local.get $p call $decode-string
    local.get $p global.get $scan-len call $make-string)
  (func $span-eq (param $p i32) (param $n i32) (param $q i32) (param $m i32) (result i32)
    (local $i i32)
    local.get $n local.get $m i32.ne if i32.const 0 return end
    block $yes loop $cmp
      local.get $i local.get $n i32.ge_u br_if $yes
      local.get $p local.get $i i32.add i32.load8_u $canonical
      local.get $q local.get $i i32.add i32.load8_u $canonical i32.ne
      if i32.const 0 return end
      local.get $i i32.const 1 i32.add local.set $i br $cmp
    end end i32.const 1)
  (func $match-field (param $p i32) (param $n i32) (result i32)
{_match_cases(items, 'field_ids')})
  (func $match-tag (param $p i32) (param $n i32) (result i32)
{_match_cases(items, 'tag_ids')})
  (func $field-rank (param $id i32) (result i32)
{_field_rank_cases(items)})
  (func $cell
    global.get $cells i32.const 1 i32.add global.set $cells
    global.get $cells i32.const {MAX_CELLS} i32.gt_u
    if i32.const 3 call $fail end)
  (func $enter
    global.get $depth i32.const 1 i32.add global.set $depth
    global.get $depth i32.const {MAX_DEPTH} i32.gt_u
    if i32.const 3 call $fail end)
  (func $leave global.get $depth i32.const 1 i32.sub global.set $depth)
  (func $parse-number (result i32)
    (local $neg i32) (local $digit i32) (local $n i64) (local $count i32)
    call $peek i32.const 45 i32.eq if call $take drop i32.const 1 local.set $neg end
    call $peek local.tee $digit i32.const 48 i32.lt_u local.get $digit i32.const 57 i32.gt_u i32.or
    if i32.const 2 call $fail i32.const 0 return end
    local.get $digit i32.const 48 i32.eq
    if call $take drop i32.const 1 local.set $count
    else
      loop $digits
        call $peek local.tee $digit i32.const 48 i32.lt_u local.get $digit i32.const 57 i32.gt_u i32.or br_if 1
        call $take drop local.get $n i64.const 10 i64.mul local.get $digit i32.const 48 i32.sub i64.extend_i32_u i64.add local.set $n
        local.get $count i32.const 1 i32.add local.set $count br $digits
      end
    end
    local.get $count i32.eqz if i32.const 2 call $fail i32.const 0 return end
    local.get $neg local.get $n i64.eqz i32.and if i32.const 2 call $fail i32.const 0 return end
    local.get $neg
    if (result i32)
      local.get $n i64.const 1073741824 i64.gt_u if i32.const 2 call $fail i32.const 0 return end
      i64.const 0 local.get $n i64.sub i32.wrap_i64 i32.const 1 i32.shl
    else
      local.get $n i64.const 1073741823 i64.gt_u if i32.const 2 call $fail i32.const 0 return end
      local.get $n i32.wrap_i64 i32.const 1 i32.shl
    end)
  (func $literal (param $p i32) (param $n i32) (result i32) (local $i i32)
    block $done loop $loop
      local.get $i local.get $n i32.ge_u br_if $done
      call $take local.get $p local.get $i i32.add i32.load8_u $canonical i32.ne
      if i32.const 2 call $fail i32.const 0 return end
      local.get $i i32.const 1 i32.add local.set $i br $loop
    end end i32.const 1)
  (func $parse-list (result i32) (local $base i32) (local $v i32) (local $tail i32)
    i32.const 91 call $expect global.get $scratch local.set $base
    call $peek i32.const 93 i32.eq if call $take drop i32.const 3 return end
    loop $items
      call $parse-value local.set $v global.get $err if local.get $base global.set $scratch i32.const 0 return end
      global.get $scratch i32.const 4 i32.add i32.const {CANONICAL_SCRATCH_END} i32.gt_u
      if i32.const 3 call $fail local.get $base global.set $scratch i32.const 0 return end
      global.get $scratch local.get $v i32.store $canonical
      global.get $scratch i32.const 4 i32.add global.set $scratch
      call $peek i32.const 44 i32.eq if call $take drop br $items end
    end
    i32.const 93 call $expect i32.const 3 local.set $tail
    block $built loop $build
      global.get $scratch local.get $base i32.le_u br_if $built
      global.get $scratch i32.const 4 i32.sub global.set $scratch
      global.get $scratch i32.load $canonical local.get $tail call $cons local.set $tail br $build
    end end
    local.get $base global.set $scratch local.get $tail)
  (func $parse-object (result i32)
    (local $base i32) (local $field i32) (local $rank i32) (local $prev i32)
    (local $value i32) (local $tail i32) (local $tag i32)
    i32.const 123 call $expect
    call $peek i32.const 125 i32.eq if call $take drop i32.const 7 return end
    global.get $scratch local.set $base i32.const -1 local.set $prev
    loop $fields
      call $scan-string drop global.get $err if local.get $base global.set $scratch i32.const 0 return end
      global.get $scan-start global.get $scan-end global.get $scan-start i32.sub
      i32.const {variant['raw_ptr']} i32.const {len(variant['raw'])} call $span-eq
      if
        local.get $base global.get $scratch i32.ne if i32.const 2 call $fail i32.const 0 return end
        i32.const 58 call $expect i32.const 91 call $expect call $scan-string drop
        global.get $scan-start global.get $scan-end global.get $scan-start i32.sub call $match-tag local.tee $tag i32.const 0 i32.lt_s
        if i32.const 2 call $fail i32.const 0 return end
        i32.const 44 call $expect call $parse-value local.set $value
        i32.const 93 call $expect i32.const 125 call $expect
        local.get $tag local.get $value call $variant return
      end
      global.get $scan-start global.get $scan-end global.get $scan-start i32.sub call $match-field local.tee $field
      i32.const 0 i32.lt_s if i32.const 2 call $fail local.get $base global.set $scratch i32.const 0 return end
      local.get $field call $field-rank local.tee $rank local.get $prev i32.le_s
      if i32.const 2 call $fail local.get $base global.set $scratch i32.const 0 return end
      local.get $rank local.set $prev i32.const 58 call $expect call $parse-value local.set $value
      global.get $scratch i32.const 8 i32.add i32.const {CANONICAL_SCRATCH_END} i32.gt_u
      if i32.const 3 call $fail local.get $base global.set $scratch i32.const 0 return end
      global.get $scratch local.get $field i32.store $canonical
      global.get $scratch local.get $value i32.store $canonical offset=4
      global.get $scratch i32.const 8 i32.add global.set $scratch
      call $peek i32.const 44 i32.eq if call $take drop br $fields end
    end
    i32.const 125 call $expect i32.const 7 local.set $tail
    block $built loop $build
      global.get $scratch local.get $base i32.le_u br_if $built
      global.get $scratch i32.const 8 i32.sub global.set $scratch
      global.get $scratch i32.load $canonical
      global.get $scratch i32.load $canonical offset=4 local.get $tail call $record local.set $tail br $build
    end end
    local.get $base global.set $scratch local.get $tail)
  (func $parse-value (result i32) (local $b i32) (local $v i32)
    call $cell call $enter global.get $err if i32.const 0 return end
    call $peek local.set $b
    local.get $b i32.const 34 i32.eq if call $parse-string local.set $v else
    local.get $b i32.const 91 i32.eq if call $parse-list local.set $v else
    local.get $b i32.const 123 i32.eq if call $parse-object local.set $v else
    local.get $b i32.const 116 i32.eq if i32.const {literals['true']['ptr']} i32.const 4 call $literal drop i32.const 5 local.set $v else
    local.get $b i32.const 102 i32.eq if i32.const {literals['false']['ptr']} i32.const 5 call $literal drop i32.const 1 local.set $v else
    local.get $b i32.const 45 i32.eq local.get $b i32.const 48 i32.ge_u local.get $b i32.const 57 i32.le_u i32.and i32.or
    if call $parse-number local.set $v else i32.const 2 call $fail end
    end end end end end
    call $leave local.get $v)
  (func $parse-request (param $arity i32) (result i32) (local $count i32) (local $v i32)
    i32.const 123 call $expect call $scan-string drop
    global.get $scan-start global.get $scan-end global.get $scan-start i32.sub
    i32.const {args['raw_ptr']} i32.const {len(args['raw'])} call $span-eq i32.eqz if i32.const 2 call $fail end
    i32.const 58 call $expect i32.const 91 call $expect
    call $peek i32.const 93 i32.ne
    if
      loop $args
        call $parse-value local.set $v
        local.get $count i32.const {MAX_ARGS} i32.ge_u if i32.const 2 call $fail else
          i32.const {CANONICAL_ARGS_START} local.get $count i32.const 4 i32.mul i32.add local.get $v i32.store $canonical
        end
        local.get $count i32.const 1 i32.add local.set $count
        call $peek i32.const 44 i32.eq if call $take drop br $args end
      end
    end
    i32.const 93 call $expect i32.const 125 call $expect
    global.get $pos global.get $end i32.ne if i32.const 2 call $fail end
    local.get $count local.get $arity i32.ne if i32.const 2 call $fail end
    global.get $err i32.eqz)
'''


def _record_emit_cases(items):
    lines = []
    for item in sorted((x for x in items if x["family"] == "field_ids"), key=lambda x: x["name"]):
        lines += [
            f"    local.get $head i32.const {item['id']} call $record-find local.set $value",
            "    global.get $found",
            "    if",
            "      local.get $emitted i32.eqz i32.eqz if i32.const 44 call $emit end",
            f"      i32.const {item['quoted_ptr']} i32.const {len(item['quoted'])} call $emit-static",
            "      i32.const 58 call $emit local.get $value call $serialize",
            "      local.get $emitted i32.const 1 i32.add local.set $emitted",
            "    end",
        ]
    return "\n".join(lines)


def _serializer_wat(items, literals):
    return f'''  (func $valid-loom (param $p i32) (param $n i32) (result i32)
    local.get $p i32.const 8 i32.ge_u
    local.get $p local.get $n i32.add local.get $p i32.ge_u i32.and
    local.get $p local.get $n i32.add memory.size $loom i32.const 16 i32.shl i32.le_u i32.and)
  (func $emit (param $b i32)
    global.get $out global.get $out-start i32.const {MAX_ENVELOPE_BYTES} i32.add i32.ge_u
    if i32.const 4 call $fail return end
    global.get $out local.get $b i32.store8 $canonical
    global.get $out i32.const 1 i32.add global.set $out)
  (func $emit-static (param $p i32) (param $n i32) (local $i i32)
    block $done loop $copy
      local.get $i local.get $n i32.ge_u br_if $done
      local.get $p local.get $i i32.add i32.load8_u $canonical call $emit
      local.get $i i32.const 1 i32.add local.set $i br $copy
    end end)
  (func $emit-hex (param $n i32)
    local.get $n i32.const 10 i32.lt_u
    if local.get $n i32.const 48 i32.add call $emit
    else local.get $n i32.const 87 i32.add call $emit end)
  (func $emit-u4 (param $u i32)
    i32.const 92 call $emit i32.const 117 call $emit
    local.get $u i32.const 12 i32.shr_u i32.const 15 i32.and call $emit-hex
    local.get $u i32.const 8 i32.shr_u i32.const 15 i32.and call $emit-hex
    local.get $u i32.const 4 i32.shr_u i32.const 15 i32.and call $emit-hex
    local.get $u i32.const 15 i32.and call $emit-hex)
  (func $emit-number (param $n i32) (local $neg i32) (local $u i64) (local $p i32) (local $d i32)
    local.get $n i32.const 0 i32.lt_s local.set $neg
    local.get $neg if i32.const 45 call $emit i64.const 0 local.get $n i64.extend_i32_s i64.sub local.set $u
    else local.get $n i64.extend_i32_u local.set $u end
    i32.const {CANONICAL_NUMBER_END} local.set $p
    local.get $u i64.eqz if i32.const 48 call $emit return end
    block $ready loop $digits
      local.get $u i64.eqz br_if $ready
      local.get $u i64.const 10 i64.rem_u i32.wrap_i64 local.set $d
      local.get $p i32.const 1 i32.sub local.tee $p local.get $d i32.store8 $canonical
      local.get $u i64.const 10 i64.div_u local.set $u br $digits
    end end
    block $done loop $write
      local.get $p i32.const {CANONICAL_NUMBER_END} i32.ge_u br_if $done
      local.get $p i32.load8_u $canonical i32.const 48 i32.add call $emit
      local.get $p i32.const 1 i32.add local.set $p br $write
    end end)
  (func $emit-json-string (param $p i32) (param $n i32)
    (local $i i32) (local $b i32) (local $b2 i32) (local $b3 i32) (local $b4 i32) (local $u i32)
    local.get $p local.get $n call $valid-loom i32.eqz if i32.const 5 call $fail return end
    i32.const 34 call $emit
    block $done loop $bytes
      local.get $i local.get $n i32.ge_u br_if $done
      local.get $p local.get $i i32.add i32.load8_u $loom local.set $b
      local.get $b i32.const 128 i32.lt_u
      if
        local.get $b i32.const 32 i32.ge_u local.get $b i32.const 34 i32.ne i32.and local.get $b i32.const 92 i32.ne i32.and
        if local.get $b call $emit else
          i32.const 92 call $emit
          local.get $b i32.const 34 i32.eq if i32.const 34 call $emit else
          local.get $b i32.const 92 i32.eq if i32.const 92 call $emit else
          local.get $b i32.const 8 i32.eq if i32.const 98 call $emit else
          local.get $b i32.const 9 i32.eq if i32.const 116 call $emit else
          local.get $b i32.const 10 i32.eq if i32.const 110 call $emit else
          local.get $b i32.const 12 i32.eq if i32.const 102 call $emit else
          local.get $b i32.const 13 i32.eq if i32.const 114 call $emit else
            i32.const 117 call $emit i32.const 0 call $emit-hex i32.const 0 call $emit-hex
            local.get $b i32.const 4 i32.shr_u call $emit-hex local.get $b i32.const 15 i32.and call $emit-hex
          end end end end end end end
        end
        local.get $i i32.const 1 i32.add local.set $i br $bytes
      end
      local.get $b i32.const 194 i32.ge_u local.get $b i32.const 223 i32.le_u i32.and
      if
        local.get $i i32.const 1 i32.add local.get $n i32.ge_u if i32.const 5 call $fail return end
        local.get $p local.get $i i32.const 1 i32.add i32.add i32.load8_u $loom local.tee $b2
        i32.const 192 i32.and i32.const 128 i32.ne if i32.const 5 call $fail return end
        local.get $b i32.const 31 i32.and i32.const 6 i32.shl local.get $b2 i32.const 63 i32.and i32.or local.set $u
        local.get $u call $emit-u4 local.get $i i32.const 2 i32.add local.set $i br $bytes
      end
      local.get $b i32.const 224 i32.ge_u local.get $b i32.const 239 i32.le_u i32.and
      if
        local.get $i i32.const 2 i32.add local.get $n i32.ge_u if i32.const 5 call $fail return end
        local.get $p local.get $i i32.const 1 i32.add i32.add i32.load8_u $loom local.set $b2
        local.get $p local.get $i i32.const 2 i32.add i32.add i32.load8_u $loom local.set $b3
        local.get $b2 i32.const 192 i32.and i32.const 128 i32.ne local.get $b3 i32.const 192 i32.and i32.const 128 i32.ne i32.or
        if i32.const 5 call $fail return end
        local.get $b i32.const 15 i32.and i32.const 12 i32.shl local.get $b2 i32.const 63 i32.and i32.const 6 i32.shl i32.or local.get $b3 i32.const 63 i32.and i32.or local.set $u
        local.get $u i32.const 2048 i32.lt_u local.get $u i32.const 55296 i32.ge_u local.get $u i32.const 57343 i32.le_u i32.and i32.or
        if i32.const 5 call $fail return end
        local.get $u call $emit-u4 local.get $i i32.const 3 i32.add local.set $i br $bytes
      end
      local.get $b i32.const 240 i32.ge_u local.get $b i32.const 244 i32.le_u i32.and
      if
        local.get $i i32.const 3 i32.add local.get $n i32.ge_u if i32.const 5 call $fail return end
        local.get $p local.get $i i32.const 1 i32.add i32.add i32.load8_u $loom local.set $b2
        local.get $p local.get $i i32.const 2 i32.add i32.add i32.load8_u $loom local.set $b3
        local.get $p local.get $i i32.const 3 i32.add i32.add i32.load8_u $loom local.set $b4
        local.get $b2 i32.const 192 i32.and i32.const 128 i32.ne local.get $b3 i32.const 192 i32.and i32.const 128 i32.ne i32.or
        local.get $b4 i32.const 192 i32.and i32.const 128 i32.ne i32.or if i32.const 5 call $fail return end
        local.get $b i32.const 7 i32.and i32.const 18 i32.shl local.get $b2 i32.const 63 i32.and i32.const 12 i32.shl i32.or
        local.get $b3 i32.const 63 i32.and i32.const 6 i32.shl i32.or local.get $b4 i32.const 63 i32.and i32.or local.set $u
        local.get $u i32.const 65536 i32.lt_u local.get $u i32.const 1114111 i32.gt_u i32.or if i32.const 5 call $fail return end
        local.get $u i32.const 65536 i32.sub local.set $u
        local.get $u i32.const 10 i32.shr_u i32.const 55296 i32.add call $emit-u4
        local.get $u i32.const 1023 i32.and i32.const 56320 i32.add call $emit-u4
        local.get $i i32.const 4 i32.add local.set $i br $bytes
      end
      i32.const 5 call $fail return
    end end i32.const 34 call $emit)
  (func $record-find (param $head i32) (param $id i32) (result i32)
    (local $q i32) (local $p i32) (local $n i32) (local $value i32)
    i32.const 0 global.set $found local.get $head local.set $q
    block $done loop $scan
      local.get $q i32.const 7 i32.eq br_if $done
      local.get $q i32.const 1 i32.and i32.eqz if i32.const 5 call $fail br $done end
      local.get $q i32.const -2 i32.and local.tee $p i32.const 16 call $valid-loom i32.eqz
      if i32.const 5 call $fail br $done end
      local.get $p i32.load $loom i32.const 2 i32.ne if i32.const 5 call $fail br $done end
      local.get $p i32.load $loom offset=4 local.get $id i32.eq
      if
        global.get $found if i32.const 5 call $fail br $done end
        i32.const 1 global.set $found local.get $p i32.load $loom offset=8 local.set $value
      end
      local.get $p i32.load $loom offset=12 local.set $q
      local.get $n i32.const 1 i32.add local.tee $n i32.const {MAX_CELLS} i32.gt_u
      if i32.const 5 call $fail br $done end br $scan
    end end local.get $value)
  (func $record-count (param $head i32) (result i32)
    (local $q i32) (local $p i32) (local $n i32)
    local.get $head local.set $q
    block $done loop $scan
      local.get $q i32.const 7 i32.eq br_if $done
      local.get $q i32.const 1 i32.and i32.eqz if i32.const 5 call $fail br $done end
      local.get $q i32.const -2 i32.and local.tee $p i32.const 16 call $valid-loom i32.eqz if i32.const 5 call $fail br $done end
      local.get $p i32.load $loom i32.const 2 i32.ne if i32.const 5 call $fail br $done end
      local.get $p i32.load $loom offset=12 local.set $q
      local.get $n i32.const 1 i32.add local.tee $n i32.const {MAX_CELLS} i32.gt_u if i32.const 5 call $fail br $done end
      br $scan
    end end local.get $n)
  (func $emit-field-name (param $id i32) (result i32)
{_emit_name_cases(items, 'field_ids')})
  (func $emit-tag-name (param $id i32) (result i32)
{_emit_name_cases(items, 'tag_ids')})
  (func $serialize-record (param $head i32) (local $count i32) (local $emitted i32) (local $value i32)
    local.get $head call $record-count local.set $count i32.const 123 call $emit
{_record_emit_cases(items)}
    local.get $emitted local.get $count i32.ne if i32.const 5 call $fail end i32.const 125 call $emit)
  (func $serialize (param $v i32)
    (local $p i32) (local $kind i32) (local $q i32) (local $n i32) (local $first i32) (local $tag i32)
    call $cell call $enter global.get $err if return end
    local.get $v i32.const 1 i32.and i32.eqz if local.get $v i32.const 1 i32.shr_s call $emit-number call $leave return end
    local.get $v i32.const 1 i32.eq if i32.const {literals['false']['ptr']} i32.const {len(literals['false']['raw'])} call $emit-static call $leave return end
    local.get $v i32.const 5 i32.eq if i32.const {literals['true']['ptr']} i32.const {len(literals['true']['raw'])} call $emit-static call $leave return end
    local.get $v i32.const 7 i32.eq if i32.const {literals['empty-record']['ptr']} i32.const 2 call $emit-static call $leave return end
    local.get $v i32.const 3 i32.eq if i32.const {literals['empty-list']['ptr']} i32.const 2 call $emit-static call $leave return end
    local.get $v i32.const -2 i32.and local.tee $p i32.const 12 call $valid-loom i32.eqz
    if i32.const 5 call $fail call $leave return end
    local.get $p i32.load $loom local.set $kind
    local.get $kind i32.const 6 i32.eq
    if local.get $p i32.load $loom offset=8 local.get $p i32.load $loom offset=4 call $emit-json-string call $leave return end
    local.get $kind i32.const 1 i32.eq
    if
      i32.const 91 call $emit i32.const 1 local.set $first local.get $v local.set $q
      block $done loop $list
        local.get $q i32.const 3 i32.eq br_if $done
        local.get $q i32.const 1 i32.and i32.eqz if i32.const 5 call $fail br $done end
        local.get $q i32.const -2 i32.and local.tee $p i32.const 12 call $valid-loom i32.eqz if i32.const 5 call $fail br $done end
        local.get $p i32.load $loom i32.const 1 i32.ne if i32.const 5 call $fail br $done end
        local.get $first i32.eqz if i32.const 44 call $emit end i32.const 0 local.set $first
        local.get $p i32.load $loom offset=4 call $serialize local.get $p i32.load $loom offset=8 local.set $q
        local.get $n i32.const 1 i32.add local.tee $n i32.const {MAX_CELLS} i32.gt_u if i32.const 5 call $fail br $done end br $list
      end end i32.const 93 call $emit call $leave return
    end
    local.get $kind i32.const 2 i32.eq if local.get $v call $serialize-record call $leave return end
    local.get $kind i32.const 3 i32.eq
    if
      i32.const {literals['variant']['ptr']} i32.const {len(literals['variant']['raw'])} call $emit-static
      local.get $p i32.load $loom offset=4 local.tee $tag call $emit-tag-name i32.eqz if i32.const 5 call $fail end
      i32.const 44 call $emit local.get $p i32.load $loom offset=8 call $serialize i32.const 93 call $emit i32.const 125 call $emit call $leave return
    end
    i32.const 5 call $fail call $leave)
'''


def _invoke_wat(item, literals, *, flush_prints=False):
    args = "\n".join(
        f"    i32.const {CANONICAL_ARGS_START + index * 4} i32.load $canonical"
        for index in range(item["arity"])
    )
    return f'''  (func (export "cm32p2||{item['wit_name']}") (param $request i32) (param $length i32) (result i32)
    (local $value i32)
    local.get $request local.get $length i32.const {item['arity']} call $prepare
    if (result i32)
{args}
      call $loom-{item['wit_name']} local.set $value
{('      call $flush-prints' + chr(10)) if flush_prints else ''}\
      global.get $out-start global.set $out
      i32.const {literals['ok']['ptr']} i32.const {len(literals['ok']['raw'])} call $emit-static
      local.get $value call $serialize i32.const 125 call $emit
      global.get $err if (result i32) call $finish-error else i32.const 0 call $finish end
    else call $finish-error end)
  (func (export "cm32p2||{item['wit_name']}_post") (param i32))'''


def _adapter_wat(boundary, bridge, *, effectful_effects=None):
    effects = set(effectful_effects or ())
    effectful = effectful_effects is not None
    exports = boundary["exports"]
    for item in exports:
        arity = item.get("arity")
        if isinstance(arity, bool) or not isinstance(arity, int) or not 0 <= arity <= MAX_ARGS:
            raise ValueError(f"component adapter export arity must be 0..{MAX_ARGS}")
    items, special, literals, static_end = _data_table(bridge)
    if static_end > 60000:
        raise ValueError("component adapter static name table exceeds its closed 60,000-byte limit")
    data = []
    for item in items:
        data.append(f'  (data (memory $canonical) (i32.const {item["raw_ptr"]}) "{_wat_data(item["raw"])}")')
        data.append(f'  (data (memory $canonical) (i32.const {item["quoted_ptr"]}) "{_wat_data(item["quoted"])}")')
    for item in special:
        data.append(f'  (data (memory $canonical) (i32.const {item["raw_ptr"]}) "{_wat_data(item["raw"])}")')
    for item in literals.values():
        data.append(f'  (data (memory $canonical) (i32.const {item["ptr"]}) "{_wat_data(item["raw"])}")')
    invokes = "\n".join(_invoke_wat(item, literals, flush_prints="IO" in effects) for item in exports)
    memory = "" if effectful else f"  (memory $canonical {CANONICAL_MEMORY_PAGES})\n"
    flush = ""
    if "IO" in effects:
        flush = f'''  (func $flush-prints (local $i i32) (local $n i32) (local $stream i32)
    call $print-count local.set $n
    block $done loop $each
      local.get $i local.get $n i32.ge_u br_if $done
      i32.const 0 global.set $err i32.const 0 global.set $cells i32.const 0 global.set $depth
      i32.const {CANONICAL_OUTPUT_START} global.set $out-start
      i32.const {CANONICAL_OUTPUT_START} global.set $out
      local.get $i call $print-at call $serialize
      global.get $err if unreachable end
      call $get-stdout local.set $stream
      local.get $stream i32.const {CANONICAL_OUTPUT_START}
      global.get $out i32.const {CANONICAL_OUTPUT_START} i32.sub
      i32.const {CANONICAL_SCRATCH_START} call $blocking-write-and-flush
      local.get $stream call $drop-output-stream
      i32.const {CANONICAL_SCRATCH_START} i32.load $canonical if unreachable end
      local.get $i i32.const 1 i32.add local.set $i br $each
    end end call $clear-prints)
'''
    return f'''(module
{_import_lines(exports, effectful_effects=effectful_effects)}
{memory}\
  (global $used (mut i32) (i32.const 0))
  (global $heap (mut i32) (i32.const {CANONICAL_INPUT_START}))
  (global $pos (mut i32) (i32.const 0))
  (global $end (mut i32) (i32.const 0))
  (global $err (mut i32) (i32.const 0))
  (global $cells (mut i32) (i32.const 0))
  (global $depth (mut i32) (i32.const 0))
  (global $scan-start (mut i32) (i32.const 0))
  (global $scan-end (mut i32) (i32.const 0))
  (global $scan-len (mut i32) (i32.const 0))
  (global $scratch (mut i32) (i32.const {CANONICAL_SCRATCH_START}))
  (global $out-start (mut i32) (i32.const {CANONICAL_OUTPUT_START}))
  (global $out (mut i32) (i32.const {CANONICAL_OUTPUT_START}))
  (global $found (mut i32) (i32.const 0))
{chr(10).join(data)}
{_parser_wat(items, special, literals)}
{_serializer_wat(items, literals)}
{flush}\
  (func $prepare (param $request i32) (param $length i32) (param $arity i32) (result i32)
    global.get $used if unreachable end i32.const 1 global.set $used
    i32.const 0 global.set $err i32.const 0 global.set $cells i32.const 0 global.set $depth
    i32.const {CANONICAL_SCRATCH_START} global.set $scratch i32.const {CANONICAL_OUTPUT_START} global.set $out-start i32.const {CANONICAL_OUTPUT_START} global.set $out
    local.get $length i32.const {MAX_ENVELOPE_BYTES} i32.gt_u
    local.get $request local.get $length i32.add local.get $request i32.lt_u i32.or
    local.get $request local.get $length i32.add memory.size $canonical i32.const 16 i32.shl i32.gt_u i32.or
    if i32.const 1 call $fail else local.get $request global.set $pos local.get $request local.get $length i32.add global.set $end
      local.get $arity call $parse-request drop
    end
    global.get $err i32.eqz)
  (func $finish (param $discriminant i32) (result i32)
    i32.const 0 local.get $discriminant i32.store $canonical
    i32.const 4 global.get $out-start i32.store $canonical
    i32.const 8 global.get $out global.get $out-start i32.sub i32.store $canonical
    i32.const 0)
  (func $finish-error (result i32)
    global.get $out-start global.set $out
    i32.const {literals['error']['ptr']} i32.const {len(literals['error']['raw'])} call $emit-static
    i32.const 1 call $finish)
  (func (export "cm32p2_realloc")
    (param $old i32) (param $old-len i32) (param $align i32) (param $new-len i32) (result i32)
    (local $p i32) (local $endp i32)
    local.get $new-len i32.eqz if i32.const 0 return end
    local.get $align i32.eqz local.get $align i32.const 16 i32.gt_u i32.or
    local.get $align i32.const 1 i32.sub local.get $align i32.and i32.eqz i32.eqz i32.or
    if unreachable end
    global.get $heap local.get $align i32.const 1 i32.sub i32.add
    local.get $align i32.const 1 i32.sub i32.const -1 i32.xor i32.and local.tee $p
    local.get $new-len i32.add local.tee $endp local.get $p i32.lt_u if unreachable end
    local.get $endp i32.const {CANONICAL_INPUT_END} i32.gt_u if unreachable end
    local.get $endp global.set $heap local.get $p)
  (func (export "cm32p2_initialize"))
{invokes}
  (export "cm32p2_memory" (memory $canonical))
)\n'''


def _parse_wat(wasm_tools, wat_text, output_path):
    result = _run([wasm_tools, "parse", "-", "-o", str(output_path)], input_bytes=wat_text.encode("utf-8"))
    if result.returncode:
        raise ValueError("wasm-tools parse rejected generated WAT: " + result.stderr.decode("utf-8", "replace").strip())
    return output_path.read_bytes()


def _closed_boundary(frontend, boundary, source, core_wasm, package, world, exports):
    verified = frontend.verify_boundary(boundary, source, core_wasm, package, world, exports, abi_version=2)
    if not verified.get("valid"):
        raise ValueError("WIT boundary verification failed: " + "; ".join(x.get("message", "") for x in verified.get("findings", ())))
    bridge_result = frontend.verify_bridge(source, core_wasm)
    if not bridge_result.get("valid"):
        raise ValueError("Component Bridge v0 verification failed: " + "; ".join(bridge_result.get("findings", ())))
    bridge = bridge_result.get("bridge")
    if boundary.get("core_module", {}).get("loom_abi_version") != 2:
        raise ValueError("Component Adapter v0 requires LOOM ABI v2")
    return bridge


def build_component_adapter_artifact_v0(
    frontend, boundary, source, core_wasm, package, world, exports=None, *,
    builder_executable, wasm_tools_executable,
):
    findings = []
    try:
        bridge = _closed_boundary(frontend, boundary, source, core_wasm, package, world, exports)
        wasm_tools_id, wasm_tools = _tool(
            wasm_tools_executable, WASM_TOOLS_VERSION, WASM_TOOLS_SHA256, "wasm-tools",
        )
        builder_id, builder = _builder_tool(builder_executable)
        deny_wat = _deny_env_wat()
        adapter_wat = _adapter_wat(boundary, bridge)
        with tempfile.TemporaryDirectory(prefix="loom-component-v0-") as raw_tmp:
            tmp = Path(raw_tmp)
            deny_path, core_path = tmp / "deny.wasm", tmp / "loom.wasm"
            adapter_path, evidence_path = tmp / "adapter.wasm", tmp / "evidence.json"
            output_path = tmp / "component.wasm"
            deny = _parse_wat(wasm_tools, deny_wat, deny_path)
            adapter = _parse_wat(wasm_tools, adapter_wat, adapter_path)
            core_path.write_bytes(bytes(core_wasm))
            evidence = {
                "schema": "loom-component-adapter-evidence/v0",
                "boundary_sha256": boundary["boundary_sha256"],
                "bridge_sha256": _sha256(_json_bytes(bridge)),
                "core_sha256": _sha256(bytes(core_wasm)),
                "deny_env_sha256": _sha256(deny),
                "adapter_core_sha256": _sha256(adapter),
                "wit_source": boundary["wit"]["source"],
                "wit_sha256": boundary["wit"]["sha256"],
                "authorization": "none",
            }
            evidence_path.write_bytes(_json_bytes(evidence))
            argv = [builder, str(deny_path), str(core_path), str(adapter_path), str(evidence_path), str(output_path)]
            argv += [f"{item['loom_name']}={item['wit_name']}" for item in boundary["exports"]]
            built = _run(argv)
            if built.returncode:
                raise ValueError("component builder failed: " + built.stderr.decode("utf-8", "replace").strip())
            component = output_path.read_bytes()
            structural = _run([wasm_tools, "validate", "--features", "component-model", str(output_path)])
            if structural.returncode:
                raise ValueError("wasm-tools rejected final component: " + structural.stderr.decode("utf-8", "replace").strip())
        body = {
            "schema": SCHEMA,
            "boundary": {"schema": boundary["schema"], "sha256": boundary["boundary_sha256"]},
            "source_sha256": _sha256(source.encode("utf-8")),
            "core_module": {"sha256": _sha256(bytes(core_wasm)), "loom_abi_version": 2},
            "bridge_sha256": _sha256(_json_bytes(bridge)),
            "deny_env_core_sha256": _sha256(deny),
            "adapter_core_sha256": _sha256(adapter),
            "component": {"sha256": _sha256(component), "byte_length": len(component), "imports": [], "wasi_imports": []},
            "wit": {"source": boundary["wit"]["source"], "sha256": boundary["wit"]["sha256"]},
            "exports": boundary["exports"],
            "transport": {
                "schema": boundary["transport"]["schema"], "max_envelope_bytes": MAX_ENVELOPE_BYTES,
                "max_depth": MAX_DEPTH, "max_cells": MAX_CELLS, "max_args": MAX_ARGS,
            },
            "lifecycle": {"one_shot": True, "instantiable": "requires-runtime-verification", "authorization": "none"},
            "toolchain": {"builder": builder_id, "wasm_tools": wasm_tools_id},
        }
        body["artifact_sha256"] = _sha256(_json_bytes(body))
        return _result(BUILD_SCHEMA, True, artifact=body, component=component)
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        findings.append(_finding("build", "component-build-rejected", str(exc)))
        return _result(BUILD_SCHEMA, False, findings=findings)


def _read_uleb(data, offset):
    value = 0
    shift = 0
    start = offset
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if data[start:offset] != _uleb(value):
                raise ValueError("non-canonical unsigned LEB128")
            return value, offset
        shift += 7
    raise ValueError("truncated unsigned LEB128")


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _component_custom(data, wanted):
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:8]) != b"\x00asm\x0d\x00\x01\x00":
        raise ValueError("invalid WebAssembly Component header")
    found = []
    pos = 8
    raw = bytes(data)
    while pos < len(raw):
        section_id = raw[pos]
        size, body = _read_uleb(raw, pos + 1)
        end = body + size
        if end > len(raw):
            raise ValueError("truncated component section")
        if section_id == 0:
            name_len, name_start = _read_uleb(raw, body)
            name_end = name_start + name_len
            if name_end > end:
                raise ValueError("truncated component custom-section name")
            if raw[name_start:name_end] == wanted.encode("utf-8"):
                found.append(raw[name_end:end])
        pos = end
    if len(found) != 1:
        raise ValueError(f"expected exactly one {wanted} custom section, found {len(found)}")
    return found[0]


def _expected_wit_json(boundary, document):
    worlds = document.get("worlds") if isinstance(document, dict) else None
    if not isinstance(worlds, list) or len(worlds) != 1:
        return False
    world = worlds[0]
    if world.get("imports") != {} or set(world.get("exports", {})) != {x["wit_name"] for x in boundary["exports"]}:
        return False
    types = document.get("types")
    if types != [
        {"name": None, "kind": {"list": "u8"}, "owner": None},
        {"name": None, "kind": {"result": {"ok": 0, "err": 0}}, "owner": None},
    ]:
        return False
    for name, export in world["exports"].items():
        fn = export.get("function", {})
        if fn.get("name") != name or fn.get("kind") != "freestanding":
            return False
        if fn.get("params") != [{"name": "request", "type": 0}] or fn.get("result") != 1:
            return False
    return True


def _wasmtime_invalid_probe(wasmtime, component_path, wit_name):
    request = b'{ "args":[]}'
    wave = "[" + ",".join(str(byte) for byte in request) + "]"
    result = _run([wasmtime, "run", "--invoke", f"{wit_name}({wave})", str(component_path)])
    if result.returncode:
        raise ValueError("Wasmtime could not instantiate/invoke component: " + result.stderr.decode("utf-8", "replace").strip())
    output = result.stdout.decode("utf-8", "strict").strip()
    expected = b'{"error":{"code":"invalid-envelope","message":"request rejected"}}'
    expected_wave = "err([" + ", ".join(str(byte) for byte in expected) + "])"
    if output != expected_wave:
        raise ValueError(f"Wasmtime refusal probe mismatch: {output!r}")
    return {"engine": WASMTIME_VERSION, "no_wasi_linker": True, "invalid_envelope_refused": True}


def verify_component_adapter_artifact_v0(
    frontend, artifact, component_bytes, boundary, source, core_wasm, package, world,
    exports=None, *, wasm_tools_executable, wasmtime_executable,
):
    findings = []
    try:
        bridge = _closed_boundary(frontend, boundary, source, core_wasm, package, world, exports)
        wasm_tools_id, wasm_tools = _tool(
            wasm_tools_executable, WASM_TOOLS_VERSION, WASM_TOOLS_SHA256, "wasm-tools",
        )
        wasmtime_id, wasmtime = _tool(
            wasmtime_executable, WASMTIME_VERSION, WASMTIME_SHA256, "wasmtime",
        )
        if not isinstance(artifact, dict):
            raise ValueError("artifact must be an object")
        expected_keys = {
            "schema", "boundary", "source_sha256", "core_module", "bridge_sha256",
            "deny_env_core_sha256", "adapter_core_sha256", "component", "wit",
            "exports", "transport", "lifecycle", "toolchain", "artifact_sha256",
        }
        if set(artifact) != expected_keys or artifact.get("schema") != SCHEMA:
            raise ValueError("artifact schema has unknown or missing fields")
        body = dict(artifact)
        supplied_artifact_hash = body.pop("artifact_sha256", None)
        if supplied_artifact_hash != _sha256(_json_bytes(body)):
            raise ValueError("artifact SHA-256 mismatch")
        component = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else b""
        if artifact["component"] != {
            "sha256": _sha256(component), "byte_length": len(component), "imports": [], "wasi_imports": [],
        }:
            raise ValueError("component identity or import claim mismatch")
        if artifact["boundary"] != {"schema": boundary["schema"], "sha256": boundary["boundary_sha256"]}:
            raise ValueError("boundary identity mismatch")
        if artifact["source_sha256"] != _sha256(source.encode("utf-8")):
            raise ValueError("source identity mismatch")
        if artifact["core_module"] != {"sha256": _sha256(bytes(core_wasm)), "loom_abi_version": 2}:
            raise ValueError("core module identity mismatch")
        if artifact["bridge_sha256"] != _sha256(_json_bytes(bridge)):
            raise ValueError("bridge identity mismatch")
        if artifact["wit"] != {"source": boundary["wit"]["source"], "sha256": boundary["wit"]["sha256"]}:
            raise ValueError("exact WIT evidence mismatch")
        if artifact["exports"] != boundary["exports"]:
            raise ValueError("export map mismatch")
        if artifact["transport"] != {
            "schema": boundary["transport"]["schema"], "max_envelope_bytes": MAX_ENVELOPE_BYTES,
            "max_depth": MAX_DEPTH, "max_cells": MAX_CELLS, "max_args": MAX_ARGS,
        }:
            raise ValueError("transport policy mismatch")
        if artifact["lifecycle"] != {
            "one_shot": True, "instantiable": "requires-runtime-verification", "authorization": "none",
        }:
            raise ValueError("lifecycle or authorization claim mismatch")
        artifact_wasm_tools = artifact["toolchain"].get("wasm_tools")
        if (
            not isinstance(artifact_wasm_tools, dict)
            or set(artifact_wasm_tools) != {"version", "sha256"}
            or artifact_wasm_tools.get("version") != WASM_TOOLS_VERSION
            or artifact_wasm_tools.get("sha256") not in WASM_TOOLS_SHA256
        ):
            raise ValueError("build wasm-tools artifact identity mismatch")
        builder_id = artifact["toolchain"].get("builder")
        if not isinstance(builder_id, dict) or set(builder_id) != {"sha256", "source_tree_sha256", "lockfile_sha256"}:
            raise ValueError("builder identity is malformed")
        for key, value in builder_id.items():
            if not _HEX64.fullmatch(str(value)):
                raise ValueError(f"builder {key} is malformed")
        local_builder_id = _builder_source_identity()
        if builder_id["source_tree_sha256"] != local_builder_id["source_tree_sha256"] or builder_id["lockfile_sha256"] != local_builder_id["lockfile_sha256"]:
            raise ValueError("builder source tree or lockfile identity mismatch")

        with tempfile.TemporaryDirectory(prefix="loom-component-verify-v0-") as raw_tmp:
            tmp = Path(raw_tmp)
            component_path = tmp / "component.wasm"
            component_path.write_bytes(component)
            valid = _run([wasm_tools, "validate", "--features", "component-model", str(component_path)])
            if valid.returncode:
                raise ValueError("wasm-tools structural validation failed: " + valid.stderr.decode("utf-8", "replace").strip())
            wit_json = _run([wasm_tools, "component", "wit", "--json", str(component_path)])
            if wit_json.returncode:
                raise ValueError("wasm-tools WIT extraction failed")
            if not _expected_wit_json(boundary, json.loads(wit_json.stdout.decode("utf-8", "strict"))):
                raise ValueError("extracted WIT semantic identity mismatch")
            module_dir = tmp / "modules"
            module_dir.mkdir()
            unbundled = _run([
                wasm_tools, "component", "unbundle", "--threshold", "0", "--module-dir", str(module_dir),
                "-o", str(tmp / "unbundled.wasm"), str(component_path),
            ])
            if unbundled.returncode:
                raise ValueError("wasm-tools component unbundle failed")
            modules = sorted(path.read_bytes() for path in module_dir.glob("*.wasm"))
            if len(modules) != 3:
                raise ValueError(f"component must embed exactly three core modules, found {len(modules)}")
            deny_path, adapter_path = tmp / "expected-deny.wasm", tmp / "expected-adapter.wasm"
            expected_deny = _parse_wat(wasm_tools, _deny_env_wat(), deny_path)
            expected_adapter = _parse_wat(wasm_tools, _adapter_wat(boundary, bridge), adapter_path)
            expected_hashes = sorted((_sha256(expected_deny), _sha256(bytes(core_wasm)), _sha256(expected_adapter)))
            if sorted(_sha256(module) for module in modules) != expected_hashes:
                raise ValueError("embedded core module set mismatch")
            if artifact["deny_env_core_sha256"] != _sha256(expected_deny):
                raise ValueError("deny-env core identity mismatch")
            if artifact["adapter_core_sha256"] != _sha256(expected_adapter):
                raise ValueError("adapter core identity mismatch")
            evidence = {
                "schema": "loom-component-adapter-evidence/v0",
                "boundary_sha256": boundary["boundary_sha256"],
                "bridge_sha256": _sha256(_json_bytes(bridge)),
                "core_sha256": _sha256(bytes(core_wasm)),
                "deny_env_sha256": _sha256(expected_deny),
                "adapter_core_sha256": _sha256(expected_adapter),
                "wit_source": boundary["wit"]["source"],
                "wit_sha256": boundary["wit"]["sha256"],
                "authorization": "none",
            }
            if _component_custom(component, EVIDENCE_SECTION) != _json_bytes(evidence):
                raise ValueError("exact component evidence custom section mismatch")
            runtime = _wasmtime_invalid_probe(wasmtime, component_path, boundary["exports"][0]["wit_name"])
        result = _result(VALIDATION_SCHEMA, True, artifact=artifact)
        result["evidence"] = {
            "structural_validation": "wasm-tools:accepted",
            "component_imports": [], "wasi_imports": [], "embedded_core_modules": 3,
            "runtime": runtime, "wasm_tools": wasm_tools_id, "wasmtime": wasmtime_id,
            "authorization": "none",
        }
        return result
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append(_finding("verification", "component-artifact-rejected", str(exc)))
        return _result(VALIDATION_SCHEMA, False, findings=findings)


def _closed_effectful_inputs(
    frontend, mapping, host_policy, source, core_wasm, package, world, exports,
):
    if frontend.verify_mapping is None or frontend.compile_effectful_wasm is None:
        raise ValueError("Effectful Component Adapter v1 frontend is incomplete")
    verified = frontend.verify_mapping(
        mapping, source, core_wasm, package, world, exports,
    )
    if not verified.get("valid"):
        raise ValueError(
            "Typed WASI mapping verification failed: "
            + "; ".join(item.get("message", "") for item in verified.get("findings", ()))
        )
    policy_id = host_policy.get("policy_id") if isinstance(host_policy, dict) else None
    policy_result = verify_effectful_component_host_policy_v1(
        host_policy, mapping, policy_id,
    )
    if not policy_result["valid"]:
        raise ValueError(
            "host policy verification failed: "
            + "; ".join(item.get("message", "") for item in policy_result["findings"])
        )
    bridge_result = frontend.verify_bridge(source, core_wasm)
    if not bridge_result.get("valid"):
        raise ValueError(
            "Component Bridge v0 verification failed: "
            + "; ".join(bridge_result.get("findings", ()))
        )
    if mapping.get("core_module", {}).get("loom_abi_version") != 2:
        raise ValueError("Effectful Component Adapter v1 requires LOOM ABI v2")
    projection = mapping.get("capability_projection", {})
    effects = sorted(
        item.get("effect") for item in projection.get("effects", ())
        if isinstance(item, dict)
    )
    if not effects or any(effect not in {"IO", "Rand", "Alloc"} for effect in effects):
        raise ValueError("effect projection is outside the closed IO,Rand,Alloc set")
    if host_policy.get("allowed_effects") != effects:
        raise ValueError("host policy effect set differs from the mapping")
    return bridge_result["bridge"], effects


def _effectful_evidence(
    mapping, host_policy, source, core_wasm, bridge, effects,
    canonical_memory, effect_env, linked_core, adapter,
):
    return {
        "schema": "loom-effectful-component-adapter-evidence/v1",
        "mapping_sha256": mapping["mapping_sha256"],
        "host_policy_sha256": host_policy["policy_sha256"],
        "source_sha256": _sha256(source.encode("utf-8")),
        "source_core_sha256": _sha256(bytes(core_wasm)),
        "bridge_sha256": _sha256(_json_bytes(bridge)),
        "effects": list(effects),
        "canonical_memory_core_sha256": _sha256(canonical_memory),
        "effect_env_core_sha256": _sha256(effect_env),
        "linked_core_sha256": _sha256(linked_core),
        "adapter_core_sha256": _sha256(adapter),
        "wit_source": mapping["wit"]["source"],
        "wit_sha256": mapping["wit"]["sha256"],
        "ambient_authority": False,
        "authorization": "none",
    }


def build_effectful_component_adapter_v1(
    frontend, mapping, host_policy, source, core_wasm, package, world, exports=None, *,
    builder_executable, wasm_tools_executable,
):
    findings = []
    try:
        bridge, effects = _closed_effectful_inputs(
            frontend, mapping, host_policy, source, core_wasm, package, world, exports,
        )
        wasm_tools_id, wasm_tools = _tool(
            wasm_tools_executable, WASM_TOOLS_VERSION, WASM_TOOLS_SHA256, "wasm-tools",
        )
        builder_id, builder = _effectful_builder_tool(builder_executable)
        linked_core = frontend.compile_effectful_wasm(source)
        memory_wat = _canonical_memory_wat()
        env_wat = _effect_env_wat(effects)
        adapter_wat = _adapter_wat(mapping, bridge, effectful_effects=effects)
        with tempfile.TemporaryDirectory(prefix="loom-effectful-component-v1-") as raw_tmp:
            tmp = Path(raw_tmp)
            memory_path = tmp / "canonical-memory.wasm"
            env_path = tmp / "effect-env.wasm"
            linked_path = tmp / "loom-linked.wasm"
            adapter_path = tmp / "adapter.wasm"
            evidence_path = tmp / "evidence.json"
            output_path = tmp / "component.wasm"
            canonical_memory = _parse_wat(wasm_tools, memory_wat, memory_path)
            effect_env = _parse_wat(wasm_tools, env_wat, env_path)
            linked_path.write_bytes(linked_core)
            adapter = _parse_wat(wasm_tools, adapter_wat, adapter_path)
            evidence = _effectful_evidence(
                mapping, host_policy, source, core_wasm, bridge, effects,
                canonical_memory, effect_env, linked_core, adapter,
            )
            evidence_path.write_bytes(_json_bytes(evidence))
            argv = [
                builder, str(memory_path), str(env_path), str(linked_path),
                str(adapter_path), str(evidence_path), str(output_path),
                ",".join(effects),
            ]
            argv += [f"{item['loom_name']}={item['wit_name']}" for item in mapping["exports"]]
            built = _run(argv)
            if built.returncode:
                raise ValueError(
                    "effectful component builder failed: "
                    + built.stderr.decode("utf-8", "replace").strip()
                )
            component = output_path.read_bytes()
            structural = _run([
                wasm_tools, "validate", "--features", "component-model", str(output_path),
            ])
            if structural.returncode:
                raise ValueError(
                    "wasm-tools rejected final effectful component: "
                    + structural.stderr.decode("utf-8", "replace").strip()
                )
        imports = sorted(mapping["capability_projection"]["imports"])
        body = {
            "schema": EFFECTFUL_SCHEMA,
            "mapping": {
                "schema": mapping["schema"], "sha256": mapping["mapping_sha256"],
            },
            "host_policy": {
                "schema": host_policy["schema"], "policy_id": host_policy["policy_id"],
                "sha256": host_policy["policy_sha256"],
            },
            "source_sha256": _sha256(source.encode("utf-8")),
            "source_core": {"sha256": _sha256(bytes(core_wasm)), "loom_abi_version": 2},
            "linked_core": {
                "sha256": _sha256(linked_core),
                "lowering": "typed-wasi-effect-lowering/v1",
            },
            "bridge_sha256": _sha256(_json_bytes(bridge)),
            "canonical_memory_core_sha256": _sha256(canonical_memory),
            "effect_env_core_sha256": _sha256(effect_env),
            "adapter_core_sha256": _sha256(adapter),
            "component": {
                "sha256": _sha256(component), "byte_length": len(component),
                "imports": imports, "wasi_imports": imports,
            },
            "wit": {"source": mapping["wit"]["source"], "sha256": mapping["wit"]["sha256"]},
            "exports": mapping["exports"],
            "effects": effects,
            "transport": {
                "schema": mapping["transport"]["schema"],
                "max_envelope_bytes": MAX_ENVELOPE_BYTES,
                "max_depth": MAX_DEPTH, "max_cells": MAX_CELLS, "max_args": MAX_ARGS,
            },
            "lifecycle": {
                "one_shot": True,
                "instantiable": "requires-runtime-verification-and-host-policy",
                "host_policy_bound": True,
                "authorization": "none",
            },
            "toolchain": {"builder": builder_id, "wasm_tools": wasm_tools_id},
        }
        body["artifact_sha256"] = _sha256(_json_bytes(body))
        return _result(EFFECTFUL_BUILD_SCHEMA, True, artifact=body, component=component)
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        findings.append(_finding("build", "effectful-component-build-rejected", str(exc)))
        return _result(EFFECTFUL_BUILD_SCHEMA, False, findings=findings)


def _wasmtime_effectful_invalid_probe(wasmtime, component_path, wit_name, imports):
    request = b'{ "args":[]}'
    wave = "[" + ",".join(str(byte) for byte in request) + "]"
    result = _run([
        wasmtime, "run", "--invoke", f"{wit_name}({wave})", str(component_path),
    ])
    if result.returncode:
        raise ValueError(
            "Wasmtime could not bind/invoke the effectful component: "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    output = result.stdout.decode("utf-8", "strict").strip()
    expected = b'{"error":{"code":"invalid-envelope","message":"request rejected"}}'
    expected_wave = "err([" + ", ".join(str(byte) for byte in expected) + "])"
    if output != expected_wave:
        raise ValueError(f"Wasmtime effectful refusal probe mismatch: {output!r}")
    return {
        "engine": WASMTIME_VERSION,
        "wasi_imports_bound": list(imports),
        "invalid_envelope_refused": True,
    }


def _expected_effectful_wit_json(mapping, document):
    worlds = document.get("worlds") if isinstance(document, dict) else None
    interfaces = document.get("interfaces") if isinstance(document, dict) else None
    packages = document.get("packages") if isinstance(document, dict) else None
    types = document.get("types") if isinstance(document, dict) else None
    if not all(isinstance(item, list) for item in (worlds, interfaces, packages, types)):
        return False
    if len(worlds) != 1:
        return False
    world = worlds[0]
    imports = []
    for value in world.get("imports", {}).values():
        try:
            interface = interfaces[value["interface"]["id"]]
            package = packages[interface["package"]]["name"]
            base, version = package.rsplit("@", 1)
            imports.append(f"{base}/{interface['name']}@{version}")
        except (KeyError, IndexError, TypeError, ValueError):
            return False
    if sorted(imports) != sorted(mapping["capability_projection"]["imports"]):
        return False
    exports = world.get("exports")
    expected_names = {item["wit_name"] for item in mapping["exports"]}
    if not isinstance(exports, dict) or set(exports) != expected_names:
        return False
    for name, value in exports.items():
        function = value.get("function") if isinstance(value, dict) else None
        if not isinstance(function, dict):
            return False
        params = function.get("params")
        result_index = function.get("result")
        if (
            function.get("name") != name or function.get("kind") != "freestanding"
            or not isinstance(params, list) or len(params) != 1
            or params[0].get("name") != "request"
            or not isinstance(params[0].get("type"), int)
            or not isinstance(result_index, int)
        ):
            return False
        param_index = params[0]["type"]
        try:
            if types[param_index].get("kind") != {"list": "u8"}:
                return False
            if types[result_index].get("kind") != {
                "result": {"ok": param_index, "err": param_index},
            }:
                return False
        except (IndexError, TypeError, AttributeError):
            return False
    expected_functions = {
        "wasi:io/error@0.2.8": set(),
        "wasi:io/streams@0.2.8": {"[method]output-stream.blocking-write-and-flush"},
        "wasi:cli/stdout@0.2.8": {"get-stdout"},
        "wasi:random/random@0.2.8": {"get-random-u64"},
    }
    for interface in interfaces:
        try:
            package = packages[interface["package"]]["name"]
            base, version = package.rsplit("@", 1)
            identity = f"{base}/{interface['name']}@{version}"
        except (KeyError, IndexError, TypeError, ValueError):
            return False
        if identity in expected_functions:
            functions = interface.get("functions", {})
            if not isinstance(functions, dict) or set(functions) != expected_functions[identity]:
                return False
    return True


def verify_effectful_component_adapter_v1(
    frontend, artifact, component_bytes, mapping, host_policy, source, core_wasm,
    package, world, exports=None, *, wasm_tools_executable, wasmtime_executable,
):
    findings = []
    try:
        bridge, effects = _closed_effectful_inputs(
            frontend, mapping, host_policy, source, core_wasm, package, world, exports,
        )
        wasm_tools_id, wasm_tools = _tool(
            wasm_tools_executable, WASM_TOOLS_VERSION, WASM_TOOLS_SHA256, "wasm-tools",
        )
        wasmtime_id, wasmtime = _tool(
            wasmtime_executable, WASMTIME_VERSION, WASMTIME_SHA256, "wasmtime",
        )
        if not isinstance(artifact, dict):
            raise ValueError("artifact must be an object")
        expected_keys = {
            "schema", "mapping", "host_policy", "source_sha256", "source_core",
            "linked_core", "bridge_sha256", "canonical_memory_core_sha256",
            "effect_env_core_sha256", "adapter_core_sha256", "component", "wit",
            "exports", "effects", "transport", "lifecycle", "toolchain", "artifact_sha256",
        }
        if set(artifact) != expected_keys or artifact.get("schema") != EFFECTFUL_SCHEMA:
            raise ValueError("effectful artifact schema has unknown or missing fields")
        body = dict(artifact)
        supplied_hash = body.pop("artifact_sha256", None)
        if supplied_hash != _sha256(_json_bytes(body)):
            raise ValueError("effectful artifact SHA-256 mismatch")
        component = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else b""
        imports = sorted(mapping["capability_projection"]["imports"])
        expected_component = {
            "sha256": _sha256(component), "byte_length": len(component),
            "imports": imports, "wasi_imports": imports,
        }
        if artifact["component"] != expected_component:
            raise ValueError("effectful component identity or import claim mismatch")
        if artifact["mapping"] != {"schema": mapping["schema"], "sha256": mapping["mapping_sha256"]}:
            raise ValueError("Typed WASI mapping identity mismatch")
        if artifact["host_policy"] != {
            "schema": host_policy["schema"], "policy_id": host_policy["policy_id"],
            "sha256": host_policy["policy_sha256"],
        }:
            raise ValueError("host policy identity mismatch")
        if artifact["source_sha256"] != _sha256(source.encode("utf-8")):
            raise ValueError("source identity mismatch")
        if artifact["source_core"] != {"sha256": _sha256(bytes(core_wasm)), "loom_abi_version": 2}:
            raise ValueError("source core identity mismatch")
        if artifact["bridge_sha256"] != _sha256(_json_bytes(bridge)):
            raise ValueError("Component Bridge identity mismatch")
        if artifact["wit"] != {"source": mapping["wit"]["source"], "sha256": mapping["wit"]["sha256"]}:
            raise ValueError("exact WIT evidence mismatch")
        if artifact["exports"] != mapping["exports"] or artifact["effects"] != effects:
            raise ValueError("export or effect projection mismatch")
        if artifact["transport"] != {
            "schema": mapping["transport"]["schema"], "max_envelope_bytes": MAX_ENVELOPE_BYTES,
            "max_depth": MAX_DEPTH, "max_cells": MAX_CELLS, "max_args": MAX_ARGS,
        }:
            raise ValueError("transport policy mismatch")
        if artifact["lifecycle"] != {
            "one_shot": True,
            "instantiable": "requires-runtime-verification-and-host-policy",
            "host_policy_bound": True,
            "authorization": "none",
        }:
            raise ValueError("lifecycle or authorization claim mismatch")
        artifact_wasm_tools = artifact["toolchain"].get("wasm_tools")
        if (
            not isinstance(artifact_wasm_tools, dict)
            or set(artifact_wasm_tools) != {"version", "sha256"}
            or artifact_wasm_tools.get("version") != WASM_TOOLS_VERSION
            or artifact_wasm_tools.get("sha256") not in WASM_TOOLS_SHA256
        ):
            raise ValueError("build wasm-tools artifact identity mismatch")
        builder_id = artifact["toolchain"].get("builder")
        if not isinstance(builder_id, dict) or set(builder_id) != {"sha256", "source_tree_sha256", "lockfile_sha256"}:
            raise ValueError("effectful builder identity is malformed")
        if any(not _HEX64.fullmatch(str(value)) for value in builder_id.values()):
            raise ValueError("effectful builder identity hash is malformed")
        local_builder_id = _effectful_builder_source_identity()
        if (
            builder_id["source_tree_sha256"] != local_builder_id["source_tree_sha256"]
            or builder_id["lockfile_sha256"] != local_builder_id["lockfile_sha256"]
        ):
            raise ValueError("effectful builder source tree or lockfile identity mismatch")

        expected_linked_core = frontend.compile_effectful_wasm(source)
        with tempfile.TemporaryDirectory(prefix="loom-effectful-component-verify-v1-") as raw_tmp:
            tmp = Path(raw_tmp)
            component_path = tmp / "component.wasm"
            component_path.write_bytes(component)
            valid = _run([wasm_tools, "validate", "--features", "component-model", str(component_path)])
            if valid.returncode:
                raise ValueError("wasm-tools structural validation failed")
            wit_json = _run([wasm_tools, "component", "wit", "--json", str(component_path)])
            if wit_json.returncode:
                raise ValueError("wasm-tools effectful WIT extraction failed")
            document = json.loads(wit_json.stdout.decode("utf-8", "strict"))
            if not _expected_effectful_wit_json(mapping, document):
                raise ValueError("effectful Component WIT semantic identity mismatch")
            module_dir = tmp / "modules"
            module_dir.mkdir()
            unbundled = _run([
                wasm_tools, "component", "unbundle", "--threshold", "0",
                "--module-dir", str(module_dir), "-o", str(tmp / "unbundled.wasm"),
                str(component_path),
            ])
            if unbundled.returncode:
                raise ValueError("wasm-tools effectful component unbundle failed")
            modules = sorted(path.read_bytes() for path in module_dir.glob("*.wasm"))
            if len(modules) != 4:
                raise ValueError(f"effectful component must embed exactly four core modules, found {len(modules)}")
            memory = _parse_wat(wasm_tools, _canonical_memory_wat(), tmp / "expected-memory.wasm")
            env_core = _parse_wat(wasm_tools, _effect_env_wat(effects), tmp / "expected-env.wasm")
            linked = bytes(expected_linked_core)
            adapter = _parse_wat(
                wasm_tools, _adapter_wat(mapping, bridge, effectful_effects=effects),
                tmp / "expected-adapter.wasm",
            )
            expected_hashes = sorted(_sha256(item) for item in (memory, env_core, linked, adapter))
            if sorted(_sha256(module) for module in modules) != expected_hashes:
                raise ValueError("embedded effectful core module set mismatch")
            identities = {
                "canonical_memory_core_sha256": _sha256(memory),
                "effect_env_core_sha256": _sha256(env_core),
                "adapter_core_sha256": _sha256(adapter),
            }
            for key, value in identities.items():
                if artifact[key] != value:
                    raise ValueError(f"{key} mismatch")
            if artifact["linked_core"] != {
                "sha256": _sha256(linked), "lowering": "typed-wasi-effect-lowering/v1",
            }:
                raise ValueError("effect-linked core identity mismatch")
            evidence = _effectful_evidence(
                mapping, host_policy, source, core_wasm, bridge, effects,
                memory, env_core, linked, adapter,
            )
            if _component_custom(component, EFFECTFUL_EVIDENCE_SECTION) != _json_bytes(evidence):
                raise ValueError("exact effectful component evidence custom section mismatch")
            runtime = _wasmtime_effectful_invalid_probe(
                wasmtime, component_path, mapping["exports"][0]["wit_name"], imports,
            )
        result = _result(EFFECTFUL_VALIDATION_SCHEMA, True, artifact=artifact)
        result["evidence"] = {
            "structural_validation": "wasm-tools:accepted",
            "component_imports": imports,
            "wasi_imports": imports,
            "embedded_core_modules": 4,
            "runtime": runtime,
            "wasm_tools": wasm_tools_id,
            "wasmtime": wasmtime_id,
            "host_policy_sha256": host_policy["policy_sha256"],
            "authorization": "none",
        }
        return result
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append(_finding("verification", "effectful-component-rejected", str(exc)))
        return _result(EFFECTFUL_VALIDATION_SCHEMA, False, findings=findings)
