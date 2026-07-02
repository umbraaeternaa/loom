#!/usr/bin/env python3
"""CLI orchestration for the LOOM kernel."""

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


def _audit(frontend, src):
    fns, errs = frontend.check(frontend.parse(src))
    findings, global_findings = _partition_findings(fns, errs)
    sensitive = {"Net", "IO", "FFI", "Alloc"}
    print("LOOM AUDIT - capability surface of AI-written code (DECLARED vs actually PERFORMED)")
    for name, info in fns.items():
        declared = set(info["decl"])
        performed = set(info["eff"]) - {"?"}
        own_findings = findings.get(name, [])
        lies = bool(own_findings) or bool(performed - declared) or ("?" in info["eff"]) or bool(set(info.get("req", set())) - performed)
        caps = sorted(performed & sensitive)
        tag = "LIE   " if lies else ("REVIEW" if caps else "clean ")
        declared_text = " ".join(sorted(declared)) or "Pure"
        performed_text = " ".join(sorted(performed)) or "Pure"
        extra = ("  <- holds: " + ", ".join(caps)) if (caps and not lies) else ""
        print(f"  [{tag}] {name}: declared ({declared_text}) | performs ({performed_text}){extra}")
        for err in own_findings:
            print("           ! " + err)
    if errs:
        print(f"-- FINDINGS ({len(errs)}), every violation verbatim:")
        for err in errs:
            print("   ! " + err)
        if global_findings:
            print("-- global findings:")
            for err in global_findings:
                print("   ! " + err)
    else:
        print("-- no violations; review every non-Pure capability above")
    return 1 if errs else 0


def _check(frontend, src):
    fns, errs = frontend.check(frontend.parse(src))
    if not errs:
        print(f"OK — checked, all effects honest ({len(fns)} function(s))")
        return 0
    findings, global_findings = _partition_findings(fns, errs)
    touched = len(findings) + (1 if global_findings else 0)
    print(f"REJECTED — {len(errs)} finding(s) across {touched} scope(s)")
    for name in fns:
        own_findings = findings.get(name, [])
        if not own_findings:
            continue
        print(f"  [{name}] {len(own_findings)} finding(s)")
        for err in own_findings:
            print("    - " + err)
    if global_findings:
        print(f"  [global] {len(global_findings)} finding(s)")
        for err in global_findings:
            print("    - " + err)
    return 1


def cli(argv, frontend):
    flags, pos = _parse_flags(argv)
    if len(pos) < 2:
        print("usage: python3 loom.py <check|run|build|audit> FILE [call] [--target py|js]")
        return 2
    cmd, path = pos[0], pos[1]
    call = pos[2] if len(pos) > 2 else "(main)"
    try:
        src = Path(path).read_text()
    except OSError as err:
        print("cannot read file: " + str(err))
        return 2
    if cmd == "check":
        return _check(frontend, src)
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
    if cmd == "audit":
        return _audit(frontend, src)
    print("unknown command: " + cmd)
    return 2
