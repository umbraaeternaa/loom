#!/usr/bin/env python3
"""CLI orchestration and structured verdicts for the LOOM kernel."""

import hashlib
import json
import re
from pathlib import Path

from loom_frontend import CliFrontend as _CliFrontend


class Frontend(_CliFrontend):
    __slots__ = ()


def _parse_flags(argv):
    flags, pos, index = {}, [], 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--target" and index + 1 < len(argv):
            flags["target"] = argv[index + 1]
            index += 2
        elif arg.startswith("--target="):
            flags["target"] = arg.split("=", 1)[1]
            index += 1
        elif arg == "--format" and index + 1 < len(argv):
            flags["format"] = argv[index + 1]
            index += 2
        elif arg.startswith("--format="):
            flags["format"] = arg.split("=", 1)[1]
            index += 1
        else:
            pos.append(arg)
            index += 1
    return flags, pos


def _partition_findings(fns, errs):
    findings, global_findings = {}, []
    for err in errs:
        key = err.split(": ", 1)[0]
        if key in fns:
            findings.setdefault(key, []).append(err)
        else:
            global_findings.append(err)
    return findings, global_findings


def build_verdict(frontend, src):
    """Return the deterministic, JSON-safe checker verdict used by Gate clients."""
    try:
        fns, errs = frontend.check(frontend.parse(src))
    except frontend.error as err:
        fns, errs = {}, ["parse: " + str(err)]
    findings, global_findings = _partition_findings(fns, errs)
    sensitive = {"Net", "IO", "FFI", "Alloc", "Rand"}
    functions = []
    for name, info in fns.items():
        declared = set(info["decl"])
        performed = set(info["eff"]) - {"?"}
        own_findings = findings.get(name, [])
        lies = bool(own_findings) or bool(performed - declared) or ("?" in info["eff"]) or bool(set(info.get("req", set())) - performed)
        capabilities = sorted(performed & sensitive)
        functions.append({
            "name": name,
            "declared_effects": sorted(declared),
            "performed_effects": sorted(performed),
            "required_effects": sorted(info.get("req", set())),
            "capabilities": capabilities,
            "status": "lie" if lies else ("review" if capabilities else "clean"),
            "findings": list(own_findings),
        })
    return {
        "schema": "loom-verdict/v1",
        "verdict": "reject" if errs else "accept",
        "advisory": True,
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "function_count": len(functions),
        "functions": functions,
        "global_findings": list(global_findings),
        "finding_count": len(errs),
    }


def _emit_json(verdict):
    print(json.dumps(verdict, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def allocation_source_map_lines(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    if not rows:
        return ["allocation source map: no heap allocation sites"]
    return ["allocation source map"] + [f"  {line}:{column}  {label}" for line, column, label in rows]


def allocation_source_map_entries(wat):
    rows = sorted({
        (int(line), int(column), label.strip())
        for label, line, column in re.findall(r";; alloc ([^\n]*?) at (\d+):(\d+)", wat)
    })
    return [{"line": line, "column": column, "label": label} for line, column, label in rows]


def build_source_map_verdict(frontend, src):
    """Return the deterministic JSON-safe WAT allocation source-map verdict."""
    try:
        allocations = allocation_source_map_entries(frontend.emit_wat(src))
    except frontend.error as err:
        return {
            "schema": "loom-source-map/v1",
            "verdict": "reject",
            "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
            "allocation_count": 0,
            "allocations": [],
            "error": str(err),
        }
    return {
        "schema": "loom-source-map/v1",
        "verdict": "accept",
        "source_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
        "allocation_count": len(allocations),
        "allocations": allocations,
    }


def _audit(frontend, src, output_format="text"):
    verdict = build_verdict(frontend, src)
    if output_format == "json":
        _emit_json(verdict)
        return 1 if verdict["verdict"] == "reject" else 0
    print("LOOM AUDIT - capability surface of AI-written code (DECLARED vs actually PERFORMED)")
    for item in verdict["functions"]:
        tag = {"lie": "LIE   ", "review": "REVIEW", "clean": "clean "}[item["status"]]
        declared_text = " ".join(item["declared_effects"]) or "Pure"
        performed_text = " ".join(item["performed_effects"]) or "Pure"
        extra = ("  <- holds: " + ", ".join(item["capabilities"])) if (item["capabilities"] and item["status"] != "lie") else ""
        print(f"  [{tag}] {item['name']}: declared ({declared_text}) | performs ({performed_text}){extra}")
        for err in item["findings"]:
            print("           ! " + err)
    if verdict["finding_count"]:
        print(f"-- FINDINGS ({verdict['finding_count']}), every violation verbatim:")
        for item in verdict["functions"]:
            for err in item["findings"]:
                print("   ! " + err)
        for err in verdict["global_findings"]:
            print("   ! " + err)
        if verdict["global_findings"]:
            print("-- global findings:")
            for err in verdict["global_findings"]:
                print("   ! " + err)
    else:
        print("-- no violations; review every non-Pure capability above")
    return 1 if verdict["verdict"] == "reject" else 0


def _check(frontend, src, output_format="text"):
    verdict = build_verdict(frontend, src)
    if output_format == "json":
        _emit_json(verdict)
        return 1 if verdict["verdict"] == "reject" else 0
    if verdict["verdict"] == "accept":
        print(f"OK — checked, all effects honest ({verdict['function_count']} function(s))")
        return 0
    touched = sum(bool(item["findings"]) for item in verdict["functions"]) + (1 if verdict["global_findings"] else 0)
    print(f"REJECTED — {verdict['finding_count']} finding(s) across {touched} scope(s)")
    for item in verdict["functions"]:
        if not item["findings"]:
            continue
        print(f"  [{item['name']}] {len(item['findings'])} finding(s)")
        for err in item["findings"]:
            print("    - " + err)
    if verdict["global_findings"]:
        print(f"  [global] {len(verdict['global_findings'])} finding(s)")
        for err in verdict["global_findings"]:
            print("    - " + err)
    return 1


def cli(argv, frontend):
    flags, pos = _parse_flags(argv)
    if len(pos) < 2:
        print("usage: python3 loom.py <check|run|build|audit|source-map> FILE [call] [--target py|js|wat] [--format text|json]")
        return 2
    cmd, path = pos[0], pos[1]
    call = pos[2] if len(pos) > 2 else "(main)"
    try:
        src = Path(path).read_text()
    except OSError as err:
        print("cannot read file: " + str(err))
        return 2
    output_format = flags.get("format", "text")
    if output_format not in ("text", "json"):
        print("unsupported format: " + output_format)
        return 2
    if cmd == "check":
        return _check(frontend, src, output_format)
    if cmd == "run":
        try:
            value, out = frontend.run_call(src, call)
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        for line in out:
            print(line)
        print("=> " + repr(value))
        return 0
    if cmd == "build":
        target = flags.get("target", "py")
        try:
            print(frontend.emit_wat(src) if target == "wat" else (frontend.compile_js(src) if target == "js" else frontend.compile_py(src)))
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        return 0
    if cmd == "source-map":
        if output_format == "json":
            verdict = build_source_map_verdict(frontend, src)
            _emit_json(verdict)
            return 1 if verdict["verdict"] == "reject" else 0
        try:
            lines = allocation_source_map_lines(frontend.emit_wat(src))
        except frontend.error as err:
            print("REJECTED: " + str(err))
            return 1
        for line in lines:
            print(line)
        return 0
    if cmd == "audit":
        return _audit(frontend, src, output_format)
    print("unknown command: " + cmd)
    return 2
