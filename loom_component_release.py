#!/usr/bin/env python3
"""Reproducible, externally signed LOOM Component release evidence v0."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


REPRO_SCHEMA = "loom-component-release-reproducibility/v0"
REPRO_BUILD_SCHEMA = "loom-component-release-reproducibility-build/v0"
REPRO_VALIDATION_SCHEMA = "loom-component-release-reproducibility-validation/v0"
ATTESTATION_VALIDATION_SCHEMA = "loom-component-release-attestation-validation/v0"
PREDICATE_SCHEMA = "loom-component-release-attestation-predicate/v0"
LIFECYCLE_SCHEMA = "loom-component-release-attestation-lifecycle/v0"
FEDERATION_SCHEMA = "loom-component-release-federation/v0"
FEDERATION_BUILD_SCHEMA = "loom-component-release-federation-build/v0"
FEDERATION_ATTESTATION_VALIDATION_SCHEMA = "loom-component-release-federation-attestation-validation/v0"
FEDERATION_PREDICATE_SCHEMA = "loom-component-release-federation-predicate/v0"
FEDERATION_LIFECYCLE_SCHEMA = "loom-component-release-federation-lifecycle/v0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://umbraaeternaa.github.io/loom/attestation/component-release/v0"
FEDERATION_PREDICATE_TYPE = "https://umbraaeternaa.github.io/loom/attestation/component-release-federation/v0"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_SIGNATURE_BYTES = 8192
MAX_SIGNATURES = 16
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 65536
MAX_SAFE_INTEGER = (1 << 53) - 1
CARGO_RELEASE = "1.93.0"
CARGO_COMMIT = "083ac5135f967fd9dc906ab057a2315861c7a80d"
RUSTC_RELEASE = "1.93.0"
RUSTC_COMMIT = "254b59607d4417e9dffbc307138ae5c86280fe4c"
SUPPORTED_HOSTS = frozenset(("aarch64-apple-darwin", "x86_64-unknown-linux-gnu"))
FEDERATION_HOSTS = tuple(sorted(SUPPORTED_HOSTS))
_RELEASE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Frontend:
    __slots__ = (
        "build_component", "verify_component", "builder_source_identity",
        "validate_public_key", "rsa_verify",
    )

    def __init__(
        self, build_component, verify_component, builder_source_identity,
        validate_public_key, rsa_verify,
    ):
        self.build_component = build_component
        self.verify_component = verify_component
        self.builder_source_identity = builder_source_identity
        self.validate_public_key = validate_public_key
        self.rsa_verify = rsa_verify


def _json_bytes(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _finding(path, code, message):
    return {"path": path, "code": code, "message": message}


def _repro_result(schema, valid, *, evidence=None, artifact=None, component=None, findings=()):
    result = {
        "schema": schema,
        "valid": bool(valid),
        "advisory": True,
        "authorization": "none",
        "evidence": evidence if valid else None,
        "artifact": artifact if valid else None,
        "findings": list(findings),
    }
    if schema == REPRO_BUILD_SCHEMA:
        result["component"] = component if valid else None
    return result


def _attestation_result(statement, envelope, key_sha256, findings):
    return {
        "schema": ATTESTATION_VALIDATION_SCHEMA,
        "valid": not findings,
        "advisory": True,
        "authorization": "none",
        "statement": statement if not findings else None,
        "envelope": envelope if not findings else None,
        "attester_key_sha256": key_sha256 if not findings else None,
        "findings": list(findings),
    }


def _federation_result(schema, valid, *, federation=None, statement=None, envelope=None, key_sha256=None, findings=()):
    result = {
        "schema": schema,
        "valid": bool(valid),
        "advisory": True,
        "authorization": "none",
        "findings": list(findings),
    }
    if schema == FEDERATION_BUILD_SCHEMA:
        result["federation"] = federation if valid else None
    else:
        result.update({
            "statement": statement if valid else None,
            "envelope": envelope if valid else None,
            "federation_key_sha256": key_sha256 if valid else None,
        })
    return result


def _run(argv, *, env=None, input_bytes=None, cwd=None):
    try:
        return subprocess.run(
            argv, env=env, input=input_bytes, cwd=cwd,
            capture_output=True, check=False, timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot execute {argv[0]}: {exc}") from exc


def _executable(path, label):
    if not isinstance(path, (str, os.PathLike)):
        raise ValueError(f"{label} executable path is required")
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} is not an executable file")
    return resolved


def _verbose_identity(path, label, release, commit):
    resolved = _executable(path, label)
    result = _run([str(resolved), "--version", "--verbose"])
    if result.returncode:
        raise ValueError(f"{label} version probe failed")
    text = result.stdout.decode("utf-8", "strict").strip()
    fields = {}
    first = None
    for index, line in enumerate(text.splitlines()):
        if index == 0:
            first = line
        elif ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value
    if not first or not first.startswith(label + " " + release + " "):
        raise ValueError(f"{label} release mismatch")
    if fields.get("commit-hash") != commit:
        raise ValueError(f"{label} commit mismatch")
    host = fields.get("host")
    if host not in SUPPORTED_HOSTS:
        raise ValueError(f"{label} host is outside the closed release contract")
    return {
        "version": text,
        "release": release,
        "commit": commit,
        "host": host,
        "sha256": _sha256(resolved.read_bytes()),
    }, str(resolved)


def _linker_identity():
    linker = _executable("/usr/bin/cc", "linker")
    result = _run([str(linker), "--version"])
    if result.returncode:
        raise ValueError("linker version probe failed")
    version = (result.stdout + result.stderr).decode("utf-8", "strict").strip()
    if not version:
        raise ValueError("linker version probe returned no identity")
    return {"version": version, "sha256": _sha256(linker.read_bytes())}, str(linker)


def _source_tree_identity(root):
    root = Path(root).resolve(strict=True)
    expected = {"Cargo.toml", "Cargo.lock", "src/main.rs"}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.parts and "target" not in path.parts
    }
    if actual != expected:
        raise ValueError("builder source tree has unknown or missing files")
    sources = {
        name: _sha256((root / name).read_bytes())
        for name in ("Cargo.toml", "src/main.rs")
    }
    return root, {
        "source_tree_sha256": _sha256(_json_bytes(sources)),
        "lockfile_sha256": _sha256((root / "Cargo.lock").read_bytes()),
        "files": sources,
    }


def _lock_packages(lock_text):
    packages = []
    current = None
    for raw_line in lock_text.splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
        elif current is not None and " = " in line:
            key, raw_value = line.split(" = ", 1)
            if key in {"name", "version", "source", "checksum"} and raw_value.startswith('"'):
                current[key] = json.loads(raw_value)
    if current is not None:
        packages.append(current)
    return packages


def _dependency_snapshot(source_root, cargo_home, cargo, rustc, host):
    source_root = Path(source_root)
    cargo_home = Path(cargo_home).resolve(strict=True)
    registry_root = cargo_home / "registry" / "src"
    registries = sorted(path for path in registry_root.iterdir() if path.is_dir())
    cache_root = cargo_home / "registry" / "cache"
    caches = sorted(path for path in cache_root.iterdir() if path.is_dir())
    if not registries or not caches:
        raise ValueError("Cargo registry source cache is absent")
    locked = {}
    for package in _lock_packages((source_root / "Cargo.lock").read_text(encoding="utf-8")):
        source = package.get("source")
        if source is None:
            continue
        if not str(source).startswith("registry+"):
            raise ValueError("non-registry dependency is outside Component release v0")
        required = {"name", "version", "source", "checksum"}
        if set(package) != required:
            raise ValueError("Cargo.lock registry package is missing an exact checksum identity")
        key = (package["name"], package["version"], package["source"])
        if key in locked:
            raise ValueError("Cargo.lock contains a duplicate registry package identity")
        locked[key] = package
    with tempfile.TemporaryDirectory(prefix="loom-release-metadata-v0-") as raw_tmp:
        metadata_env = {
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "HOME": raw_tmp,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": str(Path(rustc).parent) + os.pathsep + "/usr/bin:/bin",
            "RUSTC": rustc,
            "TMPDIR": raw_tmp,
        }
        metadata_result = _run([
            cargo, "metadata", "--offline", "--locked", "--format-version", "1",
            "--filter-platform", host,
            "--manifest-path", str(source_root / "Cargo.toml"),
        ], env=metadata_env, cwd=source_root)
    if metadata_result.returncode:
        detail = metadata_result.stderr.decode("utf-8", "replace").strip()
        raise ValueError("locked offline Cargo metadata failed: " + detail)
    try:
        metadata = json.loads(metadata_result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Cargo metadata is not valid JSON") from exc
    packages = metadata.get("packages") if isinstance(metadata, dict) else None
    resolve = metadata.get("resolve") if isinstance(metadata, dict) else None
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    if not isinstance(packages, list) or not isinstance(nodes, list):
        raise ValueError("Cargo metadata has no resolved dependency graph")
    by_id = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise ValueError("Cargo metadata package identity is malformed")
        if package["id"] in by_id:
            raise ValueError("Cargo metadata package identity is duplicated")
        by_id[package["id"]] = package
    active_ids = []
    for node in nodes:
        package_id = node.get("id") if isinstance(node, dict) else None
        if not isinstance(package_id, str) or package_id not in by_id:
            raise ValueError("Cargo metadata resolve node is malformed")
        active_ids.append(package_id)
    if len(active_ids) != len(set(active_ids)):
        raise ValueError("Cargo metadata resolve node is duplicated")
    snapshot = []
    root_manifest = (source_root / "Cargo.toml").resolve(strict=True)
    registry_paths = [path.resolve(strict=True) for path in registries]
    for package_id in sorted(active_ids):
        metadata_package = by_id[package_id]
        source = metadata_package.get("source")
        if source is None:
            manifest = Path(metadata_package.get("manifest_path", "")).resolve(strict=True)
            if manifest != root_manifest:
                raise ValueError("active local dependency is outside Component release v0")
            continue
        if not str(source).startswith("registry+"):
            raise ValueError("non-registry dependency is outside Component release v0")
        name = metadata_package.get("name")
        version = metadata_package.get("version")
        key = (name, version, source)
        package = locked.get(key)
        if package is None:
            raise ValueError("active Cargo package is not bound by Cargo.lock")
        package_root = Path(metadata_package.get("manifest_path", "")).resolve(strict=True).parent
        if not any(
            package_root == registry or registry in package_root.parents
            for registry in registry_paths
        ):
            raise ValueError(f"active registry source is outside Cargo home for {name}")
        archives = [
            cache / f"{name}-{version}.crate"
            for cache in caches
            if (cache / f"{name}-{version}.crate").is_file()
        ]
        if not archives or any(
            _sha256(archive.read_bytes()) != package["checksum"] for archive in archives
        ):
            raise ValueError(f"registry crate checksum mismatch for {name}")
        archive_files = {}
        prefix = f"{name}-{version}/"
        with tarfile.open(archives[0], mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if not member.isfile() or not member.name.startswith(prefix):
                    raise ValueError(f"registry crate has an unsafe member for {name}")
                relative = member.name[len(prefix):]
                stream = archive.extractfile(member)
                if not relative or stream is None or relative in archive_files:
                    raise ValueError(f"registry crate has an invalid member for {name}")
                archive_files[relative] = _sha256(stream.read())
        source_files = {
            path.relative_to(package_root).as_posix(): _sha256(path.read_bytes())
            for path in package_root.rglob("*")
            if path.is_file() and path.name != ".cargo-ok"
        }
        if source_files != archive_files:
            raise ValueError(f"extracted registry source differs from the locked crate for {name}")
        snapshot.append({
            "name": name,
            "version": version,
            "source": source,
            "crate_sha256": package["checksum"],
            "source_tree_sha256": _sha256(_json_bytes(source_files)),
            "files": len(source_files),
        })
    return sorted(snapshot, key=lambda item: (item["name"], item["version"], item["source"]))


def _link_metadata_mode(host):
    return "content-hash-default"


def _build_environment(cargo_home, rustc, linker, host, home, tmpdir):
    return {
        "CARGO_HOME": str(Path(cargo_home).resolve(strict=True)),
        "CARGO_INCREMENTAL": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": str(Path(rustc).parent) + os.pathsep + "/usr/bin:/bin",
        "RUSTC": rustc,
        "RUSTFLAGS": (
            "-Clinker=" + linker
            + " --remap-path-prefix=" + str(home.parent.resolve(strict=True))
            + "=/loom-release-build"
        ),
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": str(tmpdir),
    }


def _clean_builder(cargo, rustc, linker, host, cargo_home, source_root, target_root, home, tmpdir, workdir):
    env = _build_environment(cargo_home, rustc, linker, host, home, tmpdir)
    env["CARGO_TARGET_DIR"] = str(target_root)
    command = [
        cargo, "build", "--offline", "--frozen", "--release",
        "--manifest-path", str(source_root / "Cargo.toml"),
    ]
    result = _run(command, env=env, cwd=workdir)
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError("clean frozen Cargo build failed: " + detail)
    name = "loom-component-builder.exe" if os.name == "nt" else "loom-component-builder"
    output = target_root / "release" / name
    if not output.is_file():
        raise ValueError("clean Cargo build did not emit the expected builder")
    return output.read_bytes(), output


def _static_reproducibility(evidence, component_bytes):
    findings = []
    if not isinstance(evidence, dict):
        return [_finding("evidence", "expected-object", "reproducibility evidence must be an object")]
    expected = {
        "schema", "inputs", "toolchain", "dependency_sources", "builds", "equality",
        "artifact", "component", "lifecycle", "evidence_sha256",
    }
    if set(evidence) != expected or evidence.get("schema") != REPRO_SCHEMA:
        return [_finding("evidence", "invalid-schema", "reproducibility evidence has unknown or missing fields")]
    body = dict(evidence)
    supplied = body.pop("evidence_sha256", None)
    if supplied != _sha256(_json_bytes(body)):
        findings.append(_finding("evidence.evidence_sha256", "evidence-hash-mismatch", "reproducibility evidence hash mismatch"))
    component = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else b""
    if evidence.get("component") != {"sha256": _sha256(component), "byte_length": len(component)}:
        findings.append(_finding("evidence.component", "component-identity-mismatch", "component bytes do not match reproducibility evidence"))
    artifact = evidence.get("artifact")
    builds = evidence.get("builds")
    inputs = evidence.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "boundary_sha256", "source_sha256", "core_sha256", "wit_sha256",
        "builder_source_tree_sha256", "builder_lockfile_sha256",
    } or any(not _HEX64.fullmatch(str(value)) for value in inputs.values()):
        findings.append(_finding("evidence.inputs", "invalid-input-identities", "release inputs must be six exact SHA-256 identities"))
    toolchain = evidence.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "cargo", "rustc", "linker", "build_wasm_tools", "verify_wasm_tools", "wasmtime", "environment",
    }:
        findings.append(_finding("evidence.toolchain", "invalid-toolchain", "release toolchain shape is not closed"))
    else:
        for label in ("cargo", "rustc"):
            identity = toolchain[label]
            if not isinstance(identity, dict) or set(identity) != {"version", "release", "commit", "host", "sha256"} or not _HEX64.fullmatch(str(identity.get("sha256"))):
                findings.append(_finding("evidence.toolchain." + label, "invalid-toolchain", label + " identity is malformed"))
        if (
            toolchain["cargo"].get("release") != CARGO_RELEASE
            or toolchain["cargo"].get("commit") != CARGO_COMMIT
            or toolchain["rustc"].get("release") != RUSTC_RELEASE
            or toolchain["rustc"].get("commit") != RUSTC_COMMIT
            or toolchain["cargo"].get("host") != toolchain["rustc"].get("host")
            or toolchain["rustc"].get("host") not in SUPPORTED_HOSTS
        ):
            findings.append(_finding("evidence.toolchain", "unsupported-toolchain", "Cargo/rustc release, commit, or host is outside v0"))
        for label in ("linker", "build_wasm_tools", "verify_wasm_tools", "wasmtime"):
            identity = toolchain[label]
            if not isinstance(identity, dict) or set(identity) != {"version", "sha256"} or not _HEX64.fullmatch(str(identity.get("sha256"))):
                findings.append(_finding("evidence.toolchain." + label, "invalid-toolchain", label + " identity is malformed"))
        if toolchain["environment"] != {
            "cargo_incremental": "0", "source_date_epoch": "0", "profile": "release",
            "path_remap": "/loom-release-build",
            "link_metadata": _link_metadata_mode(toolchain["rustc"].get("host")),
        }:
            findings.append(_finding("evidence.toolchain.environment", "invalid-build-environment", "reproducible build environment mismatch"))
    dependencies = evidence.get("dependency_sources")
    if not isinstance(dependencies, list) or not dependencies:
        findings.append(_finding("evidence.dependency_sources", "invalid-dependency-snapshot", "locked dependency source snapshot is required"))
    else:
        if dependencies != sorted(dependencies, key=lambda item: (item.get("name", ""), item.get("version", ""), item.get("source", "")) if isinstance(item, dict) else ("", "", "")):
            findings.append(_finding("evidence.dependency_sources", "invalid-dependency-snapshot", "dependency snapshot must be canonically ordered"))
        seen_dependencies = set()
        for item in dependencies:
            if not isinstance(item, dict) or set(item) != {"name", "version", "source", "crate_sha256", "source_tree_sha256", "files"} or not _HEX64.fullmatch(str(item.get("crate_sha256"))) or not _HEX64.fullmatch(str(item.get("source_tree_sha256"))) or type(item.get("files")) is not int or item["files"] <= 0:
                findings.append(_finding("evidence.dependency_sources", "invalid-dependency-snapshot", "dependency source identity is malformed"))
                break
            dependency_key = (item["name"], item["version"], item["source"])
            if dependency_key in seen_dependencies:
                findings.append(_finding("evidence.dependency_sources", "invalid-dependency-snapshot", "dependency source identity is duplicated"))
                break
            seen_dependencies.add(dependency_key)
    if (
        not isinstance(artifact, dict)
        or artifact.get("artifact_sha256") is None
        or not isinstance(builds, list) or len(builds) != 2
    ):
        findings.append(_finding("evidence.builds", "invalid-build-observations", "exactly two closed build observations are required"))
    else:
        artifact_body = dict(artifact)
        artifact_hash = artifact_body.pop("artifact_sha256", None)
        if artifact_hash != _sha256(_json_bytes(artifact_body)):
            findings.append(_finding("evidence.artifact", "artifact-hash-mismatch", "Component artifact object hash mismatch"))
        if isinstance(inputs, dict) and (
            artifact.get("boundary", {}).get("sha256") != inputs.get("boundary_sha256")
            or artifact.get("source_sha256") != inputs.get("source_sha256")
            or artifact.get("core_module", {}).get("sha256") != inputs.get("core_sha256")
            or artifact.get("wit", {}).get("sha256") != inputs.get("wit_sha256")
            or artifact.get("toolchain", {}).get("builder", {}).get("source_tree_sha256")
            != inputs.get("builder_source_tree_sha256")
            or artifact.get("toolchain", {}).get("builder", {}).get("lockfile_sha256")
            != inputs.get("builder_lockfile_sha256")
        ):
            findings.append(_finding("evidence.artifact", "artifact-input-mismatch", "Component artifact does not bind the exact release inputs"))
        expected_ordinals = [1, 2]
        if [item.get("ordinal") for item in builds if isinstance(item, dict)] != expected_ordinals:
            findings.append(_finding("evidence.builds", "invalid-build-observations", "build observations must be ordered 1 and 2"))
        for item in builds:
            if not isinstance(item, dict) or set(item) != {
                "ordinal", "builder_sha256", "artifact_sha256", "component_sha256",
            }:
                findings.append(_finding("evidence.builds", "invalid-build-observations", "build observation shape is not closed"))
                break
            if (
                item["artifact_sha256"] != artifact.get("artifact_sha256")
                or item["component_sha256"] != _sha256(component)
                or item["builder_sha256"] != artifact.get("toolchain", {}).get("builder", {}).get("sha256")
            ):
                findings.append(_finding("evidence.builds", "reproducibility-link-mismatch", "build observation does not bind the release artifact"))
                break
    if evidence.get("equality") != {
        "builder_bytes": True, "artifact_json": True, "component_bytes": True,
    }:
        findings.append(_finding("evidence.equality", "reproducibility-not-proven", "all three byte-equality observations must be true"))
    if evidence.get("lifecycle") != {
        "clean_builds": 2,
        "network": "offline",
        "cargo_lock": "frozen",
        "cross_platform_claim": False,
        "slsa_level_claim": "none",
        "authorization": "none",
    }:
        findings.append(_finding("evidence.lifecycle", "invalid-lifecycle", "release evidence lifecycle or claim boundary mismatch"))
    return findings


def _first_difference(left, right, path="evidence"):
    if type(left) is not type(right):
        return path
    if isinstance(left, dict):
        if set(left) != set(right):
            return path
        for key in sorted(left):
            different = _first_difference(left[key], right[key], path + "." + str(key))
            if different:
                return different
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return path
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            different = _first_difference(left_item, right_item, path + f"[{index}]")
            if different:
                return different
        return None
    return None if left == right else path


def build_component_release_reproducibility_v0(
    frontend, boundary, source, core_wasm, package, world, exports=None, *,
    builder_source_root, cargo_executable, rustc_executable, cargo_home,
    wasm_tools_executable, wasmtime_executable,
):
    try:
        source_root, source_id = _source_tree_identity(builder_source_root)
        if {
            "source_tree_sha256": source_id["source_tree_sha256"],
            "lockfile_sha256": source_id["lockfile_sha256"],
        } != frontend.builder_source_identity():
            raise ValueError("builder source tree does not match Component Adapter v0")
        cargo_id, cargo = _verbose_identity(
            cargo_executable, "cargo", CARGO_RELEASE, CARGO_COMMIT,
        )
        rustc_id, rustc = _verbose_identity(
            rustc_executable, "rustc", RUSTC_RELEASE, RUSTC_COMMIT,
        )
        linker_id, linker = _linker_identity()
        if cargo_id["host"] != rustc_id["host"]:
            raise ValueError("Cargo and rustc host identities differ")
        dependencies = _dependency_snapshot(
            source_root, cargo_home, cargo, rustc, rustc_id["host"],
        )
        with tempfile.TemporaryDirectory(prefix="loom-release-repro-v0-") as raw_tmp:
            tmp = Path(raw_tmp)
            isolated_cargo = tmp / "cargo-home"
            isolated_home = tmp / "home"
            isolated_tmp = tmp / "tmp"
            workdir = tmp / "work"
            for path in (isolated_cargo, isolated_home, isolated_tmp, workdir):
                path.mkdir()
            (isolated_cargo / "registry").symlink_to(
                Path(cargo_home).resolve(strict=True) / "registry", target_is_directory=True,
            )
            builder_a, builder_a_path = _clean_builder(
                cargo, rustc, linker, rustc_id["host"], isolated_cargo, source_root, tmp / "target-a",
                isolated_home, isolated_tmp, workdir,
            )
            builder_b, builder_b_path = _clean_builder(
                cargo, rustc, linker, rustc_id["host"], isolated_cargo, source_root, tmp / "target-b",
                isolated_home, isolated_tmp, workdir,
            )
            if builder_a != builder_b:
                raise ValueError("two clean builder outputs are not byte-identical")
            builds = []
            results = []
            validations = []
            for ordinal, builder_path in ((1, builder_a_path), (2, builder_b_path)):
                built = frontend.build_component(
                    boundary, source, core_wasm, package, world, exports,
                    builder_executable=str(builder_path),
                    wasm_tools_executable=wasm_tools_executable,
                )
                if not built.get("valid"):
                    raise ValueError(f"Component build {ordinal} failed")
                verified = frontend.verify_component(
                    built["artifact"], built["component"], boundary, source, core_wasm,
                    package, world, exports,
                    wasm_tools_executable=wasm_tools_executable,
                    wasmtime_executable=wasmtime_executable,
                )
                if not verified.get("valid"):
                    raise ValueError(f"Component build {ordinal} failed independent verification")
                results.append(built)
                validations.append(verified)
                builds.append({
                    "ordinal": ordinal,
                    "builder_sha256": _sha256(builder_path.read_bytes()),
                    "artifact_sha256": built["artifact"]["artifact_sha256"],
                    "component_sha256": _sha256(built["component"]),
                })
        if results[0]["artifact"] != results[1]["artifact"]:
            raise ValueError("two clean Component artifact objects are not identical")
        if results[0]["component"] != results[1]["component"]:
            raise ValueError("two clean Component binaries are not byte-identical")
        artifact = results[0]["artifact"]
        component = results[0]["component"]
        body = {
            "schema": REPRO_SCHEMA,
            "inputs": {
                "boundary_sha256": boundary["boundary_sha256"],
                "source_sha256": _sha256(source.encode("utf-8")),
                "core_sha256": _sha256(bytes(core_wasm)),
                "wit_sha256": boundary["wit"]["sha256"],
                "builder_source_tree_sha256": source_id["source_tree_sha256"],
                "builder_lockfile_sha256": source_id["lockfile_sha256"],
            },
            "toolchain": {
                "cargo": cargo_id,
                "rustc": rustc_id,
                "linker": linker_id,
                "build_wasm_tools": artifact["toolchain"]["wasm_tools"],
                "verify_wasm_tools": validations[0]["evidence"]["wasm_tools"],
                "wasmtime": validations[0]["evidence"]["wasmtime"],
                "environment": {
                    "cargo_incremental": "0",
                    "source_date_epoch": "0",
                    "profile": "release",
                    "path_remap": "/loom-release-build",
                    "link_metadata": _link_metadata_mode(rustc_id["host"]),
                },
            },
            "dependency_sources": dependencies,
            "builds": builds,
            "equality": {
                "builder_bytes": True,
                "artifact_json": True,
                "component_bytes": True,
            },
            "artifact": artifact,
            "component": {"sha256": _sha256(component), "byte_length": len(component)},
            "lifecycle": {
                "clean_builds": 2,
                "network": "offline",
                "cargo_lock": "frozen",
                "cross_platform_claim": False,
                "slsa_level_claim": "none",
                "authorization": "none",
            },
        }
        body["evidence_sha256"] = _sha256(_json_bytes(body))
        findings = _static_reproducibility(body, component)
        if findings:
            return _repro_result(REPRO_BUILD_SCHEMA, False, findings=findings)
        return _repro_result(
            REPRO_BUILD_SCHEMA, True, evidence=body, artifact=artifact,
            component=component,
        )
    except (KeyError, OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return _repro_result(
            REPRO_BUILD_SCHEMA, False,
            findings=[_finding("build", "component-release-build-rejected", str(exc))],
        )


def verify_component_release_reproducibility_v0(
    frontend, evidence, component_bytes, boundary, source, core_wasm, package, world,
    exports=None, *, builder_source_root, cargo_executable, rustc_executable,
    cargo_home, wasm_tools_executable, wasmtime_executable,
):
    findings = _static_reproducibility(evidence, component_bytes)
    if findings:
        return _repro_result(REPRO_VALIDATION_SCHEMA, False, findings=findings)
    rebuilt = build_component_release_reproducibility_v0(
        frontend, boundary, source, core_wasm, package, world, exports,
        builder_source_root=builder_source_root,
        cargo_executable=cargo_executable,
        rustc_executable=rustc_executable,
        cargo_home=cargo_home,
        wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )
    if not rebuilt["valid"]:
        return _repro_result(REPRO_VALIDATION_SCHEMA, False, findings=rebuilt["findings"])
    if evidence != rebuilt["evidence"] or bytes(component_bytes) != rebuilt["component"]:
        drift_path = _first_difference(evidence, rebuilt["evidence"])
        if drift_path is None:
            drift_path = "component"
        return _repro_result(
            REPRO_VALIDATION_SCHEMA, False,
            findings=[_finding(
                "evidence", "reproducibility-rebuild-mismatch",
                "independent clean rebuild differs at " + drift_path,
            )],
        )
    return _repro_result(
        REPRO_VALIDATION_SCHEMA, True, evidence=evidence,
        artifact=evidence["artifact"],
    )


def _pae(payload_type, payload):
    kind = payload_type.encode("utf-8")
    return (
        b"DSSEv1 " + str(len(kind)).encode("ascii") + b" " + kind
        + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )


def _decode_base64(value, path, maximum):
    if not isinstance(value, str):
        return None, [_finding(path, "expected-base64", "expected a Base64 string")]
    if len(value) > ((maximum + 2) // 3) * 4 + 4:
        return None, [_finding(path, "base64-too-large", "Base64 value exceeds the release attestation bound")]
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        return None, [_finding(path, "invalid-base64", "invalid standard or URL-safe Base64")]
    if len(decoded) > maximum:
        return None, [_finding(path, "base64-too-large", "decoded value exceeds the release attestation bound")]
    return decoded, []


def _statement_json(payload):
    def closed(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError("non-finite number")

    try:
        statement = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=closed,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None, [_finding("envelope.payload", "invalid-statement-json", "payload must be strict duplicate-free JSON")]
    nodes = 0

    def walk(value, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise OverflowError("nodes")
        if depth > MAX_JSON_DEPTH:
            raise RecursionError("depth")
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("key")
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)
        elif value is not None and type(value) not in (str, int, bool):
            raise TypeError("value")

    try:
        walk(statement, 0)
        canonical = _json_bytes(statement)
    except OverflowError:
        return None, [_finding("envelope.payload", "statement-too-large", "statement exceeds the JSON node bound")]
    except RecursionError:
        return None, [_finding("envelope.payload", "statement-too-deep", "statement exceeds the JSON depth bound")]
    except (TypeError, ValueError):
        return None, [_finding("envelope.payload", "non-canonical-statement", "statement contains non-canonical values")]
    if canonical != payload:
        return None, [_finding("envelope.payload", "non-canonical-statement", "statement must use canonical UTF-8 JSON")]
    return statement, []


def prepare_component_release_attestation_v0(
    frontend, evidence, component_bytes, release_name, release_version,
    attester_public_key, attested_at_unix_ms,
):
    findings = _static_reproducibility(evidence, component_bytes)
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    findings.extend(
        _finding("attester_public_key." + item.get("path", ""), item.get("code", "invalid-key"), item.get("message", "invalid public key"))
        for item in key_findings
    )
    if not isinstance(release_name, str) or not _RELEASE_TOKEN.fullmatch(release_name):
        findings.append(_finding("release_name", "invalid-release-name", "release name must be a closed portable token"))
    if not isinstance(release_version, str) or not _RELEASE_TOKEN.fullmatch(release_version):
        findings.append(_finding("release_version", "invalid-release-version", "release version must be a closed portable token"))
    if type(attested_at_unix_ms) is not int or not 0 <= attested_at_unix_ms <= MAX_SAFE_INTEGER:
        findings.append(_finding("attested_at_unix_ms", "invalid-attestation-time", "attestation time must be a non-negative portable integer"))
    if findings:
        return _attestation_result(None, None, None, findings)
    key_sha256 = _sha256(_json_bytes(public_key))
    artifact = evidence["artifact"]
    component_hash = evidence["component"]["sha256"]
    predicate = {
        "schema": PREDICATE_SCHEMA,
        "release": {"name": release_name, "version": release_version},
        "reproducibility": evidence,
        "reproducibility_sha256": evidence["evidence_sha256"],
        "attester": {
            "role": "component-release-attester",
            "algorithm": public_key["algorithm"],
            "key_sha256": key_sha256,
        },
        "attested_at_unix_ms": attested_at_unix_ms,
        "lifecycle": {
            "schema": LIFECYCLE_SCHEMA,
            "evidence": "signed-reproducible-component-release",
            "clean_builds": 2,
            "authorization": "none",
            "cross_platform_claim": False,
            "slsa_level_claim": "none",
        },
    }
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": release_name + "-" + release_version + ".component.wasm", "digest": {"sha256": component_hash}},
            {"name": "loom-component-adapter-artifact-v0.json", "digest": {"sha256": artifact["artifact_sha256"]}},
            {"name": "loom-component-release-reproducibility-v0.json", "digest": {"sha256": evidence["evidence_sha256"]}},
            {"name": "loom-component-builder", "digest": {"sha256": evidence["builds"][0]["builder_sha256"]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    payload = _json_bytes(statement)
    signing = _pae(PAYLOAD_TYPE, payload)
    result = _attestation_result(statement, None, key_sha256, [])
    result.update({
        "payload_type": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signing_bytes": base64.b64encode(signing).decode("ascii"),
        "signing_bytes_sha256": _sha256(signing),
    })
    return result


def build_component_release_attestation_v0(
    frontend, evidence, component_bytes, release_name, release_version,
    attester_public_key, attested_at_unix_ms, signature,
):
    prepared = prepare_component_release_attestation_v0(
        frontend, evidence, component_bytes, release_name, release_version,
        attester_public_key, attested_at_unix_ms,
    )
    if not prepared["valid"]:
        return prepared
    signature_bytes, findings = _decode_base64(signature, "signature", MAX_SIGNATURE_BYTES)
    if findings:
        return _attestation_result(None, None, None, findings)
    signing, _ = _decode_base64(
        prepared["signing_bytes"], "signing_bytes", MAX_PAYLOAD_BYTES + 1024,
    )
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    if key_findings or not frontend.rsa_verify(signing, signature_bytes.hex(), public_key):
        return _attestation_result(None, None, None, [
            _finding("signature", "invalid-release-signature", "DSSE signature is invalid for the release attester key"),
        ])
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": prepared["payload"],
        "signatures": [{
            "keyid": prepared["attester_key_sha256"],
            "sig": base64.b64encode(signature_bytes).decode("ascii"),
        }],
    }
    return _attestation_result(
        prepared["statement"], envelope, prepared["attester_key_sha256"], [],
    )


def verify_component_release_attestation_v0(
    frontend, envelope, evidence, component_bytes, boundary, source, core_wasm,
    package, world, exports, release_name, release_version, attester_public_key, *,
    builder_source_root, cargo_executable, rustc_executable, cargo_home,
    wasm_tools_executable, wasmtime_executable,
):
    if not isinstance(envelope, dict):
        return _attestation_result(None, None, None, [
            _finding("envelope", "expected-object", "DSSE envelope must be an object"),
        ])
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return _attestation_result(None, None, None, [
            _finding("envelope.payloadType", "unsupported-payload-type", "expected application/vnd.in-toto+json"),
        ])
    payload, findings = _decode_base64(
        envelope.get("payload"), "envelope.payload", MAX_PAYLOAD_BYTES,
    )
    if findings:
        return _attestation_result(None, None, None, findings)
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= MAX_SIGNATURES:
        return _attestation_result(None, None, None, [
            _finding("envelope.signatures", "invalid-signature-set", "DSSE envelope requires 1 to 16 signatures"),
        ])
    public_key, key_findings = frontend.validate_public_key(attester_public_key)
    if key_findings:
        return _attestation_result(None, None, None, [
            _finding("attester_public_key", "invalid-public-key", "release attester key is invalid"),
        ])
    signing = _pae(PAYLOAD_TYPE, payload)
    valid_signature = False
    for item in signatures:
        if not isinstance(item, dict):
            continue
        raw, signature_findings = _decode_base64(
            item.get("sig"), "envelope.signatures.sig", MAX_SIGNATURE_BYTES,
        )
        if not signature_findings and frontend.rsa_verify(signing, raw.hex(), public_key):
            valid_signature = True
            break
    if not valid_signature:
        return _attestation_result(None, None, None, [
            _finding("envelope.signatures", "invalid-release-signature", "no DSSE signature verifies with the trusted release key"),
        ])
    statement, findings = _statement_json(payload)
    if findings:
        return _attestation_result(None, None, None, findings)
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    attested_at = predicate.get("attested_at_unix_ms") if isinstance(predicate, dict) else None
    prepared = prepare_component_release_attestation_v0(
        frontend, evidence, component_bytes, release_name, release_version,
        attester_public_key, attested_at,
    )
    if not prepared["valid"]:
        return prepared
    if statement != prepared["statement"]:
        return _attestation_result(None, None, None, [
            _finding("statement", "release-statement-mismatch", "signed statement does not match the exact release evidence"),
        ])
    reproduced = verify_component_release_reproducibility_v0(
        frontend, evidence, component_bytes, boundary, source, core_wasm,
        package, world, exports,
        builder_source_root=builder_source_root,
        cargo_executable=cargo_executable,
        rustc_executable=rustc_executable,
        cargo_home=cargo_home,
        wasm_tools_executable=wasm_tools_executable,
        wasmtime_executable=wasmtime_executable,
    )
    if not reproduced["valid"]:
        return _attestation_result(None, None, None, reproduced["findings"])
    return _attestation_result(
        statement, envelope, prepared["attester_key_sha256"], [],
    )


def _validated_key(frontend, value, path):
    public_key, key_findings = frontend.validate_public_key(value)
    findings = [
        _finding(
            path + ("." + item.get("path", "") if item.get("path") else ""),
            item.get("code", "invalid-key"), item.get("message", "invalid public key"),
        )
        for item in key_findings
    ]
    if findings:
        return None, None, findings
    return public_key, _sha256(_json_bytes(public_key)), []


def _strict_platform_attestation(
    frontend, item, component_bytes, release_name, release_version, index,
):
    path = f"platform_attestations[{index}]"
    if not isinstance(item, dict) or set(item) != {
        "envelope", "evidence", "attester_public_key",
    }:
        return None, [_finding(
            path, "invalid-platform-attestation",
            "platform attestation must contain only envelope, evidence, and attester_public_key",
        )]
    evidence = item["evidence"]
    findings = _static_reproducibility(evidence, component_bytes)
    if findings:
        return None, [
            _finding(path + "." + finding["path"], finding["code"], finding["message"])
            for finding in findings
        ]
    host = evidence["toolchain"]["rustc"]["host"]
    if evidence["toolchain"]["cargo"]["host"] != host or host not in SUPPORTED_HOSTS:
        return None, [_finding(
            path + ".evidence.toolchain", "unsupported-platform-host",
            "platform attestation host is outside the closed federation host set",
        )]
    public_key, key_sha256, findings = _validated_key(
        frontend, item["attester_public_key"], path + ".attester_public_key",
    )
    if findings:
        return None, findings
    envelope = item["envelope"]
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType", "payload", "signatures",
    }:
        return None, [_finding(
            path + ".envelope", "invalid-platform-envelope",
            "platform DSSE envelope shape is not closed",
        )]
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return None, [_finding(
            path + ".envelope.payloadType", "unsupported-payload-type",
            "expected application/vnd.in-toto+json",
        )]
    payload, findings = _decode_base64(
        envelope.get("payload"), path + ".envelope.payload", MAX_PAYLOAD_BYTES,
    )
    if findings:
        return None, findings
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return None, [_finding(
            path + ".envelope.signatures", "invalid-platform-signature-set",
            "federation requires exactly one unambiguous platform signature",
        )]
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) != {"keyid", "sig"}:
        return None, [_finding(
            path + ".envelope.signatures[0]", "invalid-platform-signature",
            "platform signature shape is not closed",
        )]
    if signature.get("keyid") != key_sha256:
        return None, [_finding(
            path + ".envelope.signatures[0].keyid", "platform-keyid-mismatch",
            "platform signature keyid does not bind the pinned attester key",
        )]
    raw_signature, findings = _decode_base64(
        signature.get("sig"), path + ".envelope.signatures[0].sig", MAX_SIGNATURE_BYTES,
    )
    if findings:
        return None, findings
    signing = _pae(PAYLOAD_TYPE, payload)
    if not frontend.rsa_verify(signing, raw_signature.hex(), public_key):
        return None, [_finding(
            path + ".envelope.signatures[0]", "invalid-platform-signature",
            "platform DSSE signature does not verify with the pinned attester key",
        )]
    statement, findings = _statement_json(payload)
    if findings:
        return None, [
            _finding(path + "." + finding["path"], finding["code"], finding["message"])
            for finding in findings
        ]
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    attested_at = predicate.get("attested_at_unix_ms") if isinstance(predicate, dict) else None
    prepared = prepare_component_release_attestation_v0(
        frontend, evidence, component_bytes, release_name, release_version,
        item["attester_public_key"], attested_at,
    )
    if not prepared["valid"]:
        return None, [
            _finding(path + "." + finding["path"], finding["code"], finding["message"])
            for finding in prepared["findings"]
        ]
    if statement != prepared["statement"]:
        return None, [_finding(
            path + ".statement", "platform-statement-mismatch",
            "signed platform statement does not match its exact reproducibility evidence",
        )]
    artifact = evidence["artifact"]
    portable_artifact = json.loads(_json_bytes(artifact).decode("ascii"))
    portable_artifact.pop("artifact_sha256", None)
    portable_artifact["toolchain"]["builder"].pop("sha256", None)
    portable_artifact["toolchain"]["wasm_tools"].pop("sha256", None)
    return {
        "host": host,
        "attested_at_unix_ms": attested_at,
        "attester_key_sha256": key_sha256,
        "statement_sha256": _sha256(_json_bytes(statement)),
        "envelope_sha256": _sha256(_json_bytes(envelope)),
        "reproducibility_sha256": evidence["evidence_sha256"],
        "artifact_sha256": artifact["artifact_sha256"],
        "builder_sha256": evidence["builds"][0]["builder_sha256"],
        "toolchain_sha256": _sha256(_json_bytes(evidence["toolchain"])),
        "dependency_sources_sha256": _sha256(_json_bytes(evidence["dependency_sources"])),
        "inputs": evidence["inputs"],
        "portable_artifact_sha256": _sha256(_json_bytes(portable_artifact)),
    }, []


def build_component_release_federation_v0(
    frontend, platform_attestations, component_bytes, release_name, release_version,
):
    if not isinstance(component_bytes, (bytes, bytearray)) or not component_bytes:
        return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
            "component_bytes", "invalid-component-bytes",
            "federation requires a non-empty WebAssembly Component byte string",
        )])
    if not isinstance(platform_attestations, list) or len(platform_attestations) != len(FEDERATION_HOSTS):
        return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
            "platform_attestations", "invalid-platform-set",
            "federation requires exactly one attestation for each closed v0 host",
        )])
    records = []
    findings = []
    for index, item in enumerate(platform_attestations):
        record, item_findings = _strict_platform_attestation(
            frontend, item, component_bytes, release_name, release_version, index,
        )
        findings.extend(item_findings)
        if record is not None:
            records.append(record)
    if findings:
        return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=findings)
    records.sort(key=lambda record: record["host"])
    if tuple(record["host"] for record in records) != FEDERATION_HOSTS:
        return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
            "platform_attestations", "incomplete-platform-set",
            "federation must cover macOS arm64 and Linux x86_64 exactly once",
        )])
    if len({record["attester_key_sha256"] for record in records}) != len(records):
        return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
            "platform_attestations", "non-independent-platform-keys",
            "each platform statement must use a distinct pinned attester key",
        )])
    first = records[0]
    for record in records[1:]:
        if record["inputs"] != first["inputs"]:
            return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
                "platform_attestations", "portable-input-mismatch",
                "platform statements do not bind identical source, core, WIT, and builder inputs",
            )])
        if record["portable_artifact_sha256"] != first["portable_artifact_sha256"]:
            return _federation_result(FEDERATION_BUILD_SCHEMA, False, findings=[_finding(
                "platform_attestations", "portable-artifact-mismatch",
                "platform Component adapter semantics differ after removing host executable identities",
            )])
    component = bytes(component_bytes) if isinstance(component_bytes, (bytes, bytearray)) else b""
    body = {
        "schema": FEDERATION_SCHEMA,
        "release": {"name": release_name, "version": release_version},
        "component": {"sha256": _sha256(component), "byte_length": len(component)},
        "portable_inputs": first["inputs"],
        "portable_artifact_sha256": first["portable_artifact_sha256"],
        "platforms": [{key: value for key, value in record.items() if key not in {"inputs", "portable_artifact_sha256"}} for record in records],
        "threshold": {
            "required_hosts": list(FEDERATION_HOSTS),
            "minimum_platforms": len(FEDERATION_HOSTS),
            "distinct_attester_keys": True,
        },
        "equality": {
            "component_bytes": True,
            "portable_inputs": True,
            "portable_adapter_semantics": True,
            "builder_bytes": False,
            "toolchain_bytes": False,
        },
        "lifecycle": {
            "schema": FEDERATION_LIFECYCLE_SCHEMA,
            "platform_statements": len(FEDERATION_HOSTS),
            "cross_platform_claim": "component-bytes-and-portable-input-concordance",
            "same_host_rebuild_verification": "required-before-platform-attestation",
            "authorization": "none",
            "slsa_level_claim": "none",
        },
    }
    body["federation_sha256"] = _sha256(_json_bytes(body))
    return _federation_result(FEDERATION_BUILD_SCHEMA, True, federation=body)


def prepare_component_release_federation_attestation_v0(
    frontend, platform_attestations, component_bytes, release_name, release_version,
    federation_public_key, federated_at_unix_ms,
):
    built = build_component_release_federation_v0(
        frontend, platform_attestations, component_bytes, release_name, release_version,
    )
    if not built["valid"]:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=built["findings"],
        )
    public_key, key_sha256, findings = _validated_key(
        frontend, federation_public_key, "federation_public_key",
    )
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    federation = built["federation"]
    platform_keys = {record["attester_key_sha256"] for record in federation["platforms"]}
    if key_sha256 in platform_keys:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "federation_public_key", "non-independent-federation-key",
            "federation issuer key must differ from every platform attester key",
        )])
    if type(federated_at_unix_ms) is not int or not 0 <= federated_at_unix_ms <= MAX_SAFE_INTEGER:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "federated_at_unix_ms", "invalid-federation-time",
            "federation time must be a non-negative portable integer",
        )])
    if federated_at_unix_ms < max(record["attested_at_unix_ms"] for record in federation["platforms"]):
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "federated_at_unix_ms", "federation-predates-platform-attestation",
            "federation time cannot precede either signed platform observation",
        )])
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": release_name + "-" + release_version + ".component.wasm",
                "digest": {"sha256": federation["component"]["sha256"]},
            },
            {
                "name": "loom-component-release-federation-v0.json",
                "digest": {"sha256": federation["federation_sha256"]},
            },
        ] + [
            {
                "name": "loom-component-release-" + record["host"] + ".intoto.json",
                "digest": {"sha256": record["statement_sha256"]},
            }
            for record in federation["platforms"]
        ],
        "predicateType": FEDERATION_PREDICATE_TYPE,
        "predicate": {
            "schema": FEDERATION_PREDICATE_SCHEMA,
            "federation": federation,
            "federation_sha256": federation["federation_sha256"],
            "issuer": {
                "role": "component-release-federation-issuer",
                "algorithm": public_key["algorithm"],
                "key_sha256": key_sha256,
            },
            "federated_at_unix_ms": federated_at_unix_ms,
            "lifecycle": federation["lifecycle"],
        },
    }
    payload = _json_bytes(statement)
    signing = _pae(PAYLOAD_TYPE, payload)
    result = _federation_result(
        FEDERATION_ATTESTATION_VALIDATION_SCHEMA, True, statement=statement,
        key_sha256=key_sha256,
    )
    result.update({
        "payload_type": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signing_bytes": base64.b64encode(signing).decode("ascii"),
        "signing_bytes_sha256": _sha256(signing),
    })
    return result


def build_component_release_federation_attestation_v0(
    frontend, platform_attestations, component_bytes, release_name, release_version,
    federation_public_key, federated_at_unix_ms, signature,
):
    prepared = prepare_component_release_federation_attestation_v0(
        frontend, platform_attestations, component_bytes, release_name, release_version,
        federation_public_key, federated_at_unix_ms,
    )
    if not prepared["valid"]:
        return prepared
    signature_bytes, findings = _decode_base64(signature, "signature", MAX_SIGNATURE_BYTES)
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    signing, _ = _decode_base64(
        prepared["signing_bytes"], "signing_bytes", MAX_PAYLOAD_BYTES + 1024,
    )
    public_key, key_sha256, findings = _validated_key(
        frontend, federation_public_key, "federation_public_key",
    )
    if findings or not frontend.rsa_verify(signing, signature_bytes.hex(), public_key):
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "signature", "invalid-federation-signature",
            "DSSE signature is invalid for the federation issuer key",
        )])
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": prepared["payload"],
        "signatures": [{
            "keyid": key_sha256,
            "sig": base64.b64encode(signature_bytes).decode("ascii"),
        }],
    }
    return _federation_result(
        FEDERATION_ATTESTATION_VALIDATION_SCHEMA, True,
        statement=prepared["statement"], envelope=envelope, key_sha256=key_sha256,
    )


def verify_component_release_federation_attestation_v0(
    frontend, envelope, platform_attestations, component_bytes, release_name,
    release_version, federation_public_key,
):
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType", "payload", "signatures",
    }:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "envelope", "invalid-federation-envelope", "federation DSSE envelope shape is not closed",
        )])
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "envelope.payloadType", "unsupported-payload-type", "expected application/vnd.in-toto+json",
        )])
    payload, findings = _decode_base64(
        envelope.get("payload"), "envelope.payload", MAX_PAYLOAD_BYTES,
    )
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    public_key, key_sha256, findings = _validated_key(
        frontend, federation_public_key, "federation_public_key",
    )
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "envelope.signatures", "invalid-federation-signature-set",
            "federation envelope requires exactly one issuer signature",
        )])
    signature = signatures[0]
    if (
        not isinstance(signature, dict) or set(signature) != {"keyid", "sig"}
        or signature.get("keyid") != key_sha256
    ):
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "envelope.signatures[0]", "federation-keyid-mismatch",
            "federation signature does not bind the pinned issuer key",
        )])
    raw_signature, findings = _decode_base64(
        signature.get("sig"), "envelope.signatures[0].sig", MAX_SIGNATURE_BYTES,
    )
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    if not frontend.rsa_verify(_pae(PAYLOAD_TYPE, payload), raw_signature.hex(), public_key):
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "envelope.signatures[0]", "invalid-federation-signature",
            "federation DSSE signature does not verify with the pinned issuer key",
        )])
    statement, findings = _statement_json(payload)
    if findings:
        return _federation_result(
            FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=findings,
        )
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    federated_at = predicate.get("federated_at_unix_ms") if isinstance(predicate, dict) else None
    prepared = prepare_component_release_federation_attestation_v0(
        frontend, platform_attestations, component_bytes, release_name, release_version,
        federation_public_key, federated_at,
    )
    if not prepared["valid"]:
        return prepared
    if statement != prepared["statement"]:
        return _federation_result(FEDERATION_ATTESTATION_VALIDATION_SCHEMA, False, findings=[_finding(
            "statement", "federation-statement-mismatch",
            "signed federation statement does not match the exact platform set",
        )])
    return _federation_result(
        FEDERATION_ATTESTATION_VALIDATION_SCHEMA, True, statement=statement,
        envelope=envelope, key_sha256=key_sha256,
    )
