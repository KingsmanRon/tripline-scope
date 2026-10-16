#!/usr/bin/env python3
"""CycloneDX SBOM for the runtime closure, and the check that it covers every locked dependency.

    sbom.py generate --python VENV/bin/python --wheels WHEELS --lock requirements/runtime.txt \
                     [--native-audit requirements/native-audit.json] --out sbom.cdx.json
    sbom.py check    --sbom sbom.cdx.json --lock requirements/runtime.txt

``generate`` runs ``cyclonedx-py environment`` against a clean virtualenv installed offline from the bundle's
wheels (so licences come from the installed metadata), then adds to every component the SHA-256 of the exact
wheel shipped in the bundle (which must be one of the lock's hashes) and the bundle path of that wheel. Rust
crates proven linked into native extensions (from the native audit) and shared libraries bundled inside
wheels are added as nested components. ``check`` fails unless every runtime dependency in the lock appears
with the locked version, a pkg:pypi purl and a SHA-256 hash listed in the lock, both first-party packages are
present with hashes, and nothing outside the lock is listed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_licences import FIRST_PARTY, normalize_name, parse_lock  # noqa: E402


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _wheel_index(wheels: Path) -> dict[tuple[str, str], Path]:
    out = {}
    for w in wheels.glob("*.whl"):
        name, version = w.name.split("-")[:2]
        out[(normalize_name(name), version)] = w
    return out


def _cyclonedx_cmd() -> list[str]:
    exe = shutil.which("cyclonedx-py") or str(Path(sys.executable).with_name("cyclonedx-py"))
    return [exe] if Path(exe).exists() else [sys.executable, "-m", "cyclonedx_py"]


def generate(python: Path, wheels: Path, lock_path: Path, pyproject: Path, out: Path,
             native_audit: Path | None) -> dict:
    lock = parse_lock(lock_path)
    with tempfile.TemporaryDirectory() as td:
        raw = Path(td) / "env.cdx.json"
        env = dict(os.environ, SOURCE_DATE_EPOCH=os.environ.get("SOURCE_DATE_EPOCH", "0"))
        subprocess.run(_cyclonedx_cmd() + ["environment", "--pyproject", str(pyproject), "--mc-type", "application",
                                           "--output-reproducible", "--of", "JSON", "-o", str(raw), str(python)],
                       check=True, env=env)
        bom = json.loads(raw.read_text())
    index = _wheel_index(wheels)
    audit = json.loads(native_audit.read_text()) if native_audit else {"packages": {}}
    audit_by_key = {normalize_name(k): v for k, v in (audit.get("packages") or {}).items()}
    problems = []
    root = (bom.get("metadata") or {}).get("component")
    for comp in bom.get("components", []) + ([root] if root else []):
        key = normalize_name(comp["name"])
        wheel = index.get((key, comp.get("version")))
        if wheel is None:
            problems.append(f"no shipped wheel for {comp['name']} {comp.get('version')}")
            continue
        digest = _sha256(wheel)
        if key in lock and f"sha256:{digest}" not in lock[key]["hashes"]:
            problems.append(f"{wheel.name}: SHA-256 is not one of the lock's hashes")
        comp["hashes"] = [{"alg": "SHA-256", "content": digest}]
        props = comp.setdefault("properties", [])
        props.append({"name": "tripline:bundle-file", "value": f"wheels/{wheel.name}"})
        props.append({"name": "tripline:origin", "value": "first-party, built from this repository"
                      if key in FIRST_PARTY else "PyPI, pinned by hash in requirements.txt"})
        nested = _native_components(comp, audit_by_key.get(key))
        if nested:
            comp["components"] = nested
    if problems:
        raise SystemExit("SBOM generation failed:\n  " + "\n  ".join(problems))
    meta = bom.setdefault("metadata", {})
    meta.setdefault("properties", []).extend([
        {"name": "tripline:lock-sha256", "value": _sha256(lock_path)},
        {"name": "tripline:target", "value": "CPython 3.12, x86_64 Linux (manylinux, glibc >= 2.28)"},
        {"name": "tripline:scope", "value": "runtime closure installed from the offline bundle; container base "
                                            "images are listed in images/IMAGES.txt"},
    ])
    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    return bom


def _native_components(comp: dict, audit: dict | None) -> list[dict]:
    if not audit:
        return []
    nested = []
    for lib in audit.get("bundled_shared_libraries", []):
        nested.append({"type": "library", "name": lib.split("-")[0].removesuffix(".so"), "bom-ref":
                       f"{comp.get('bom-ref', comp['name'])}/{lib}", "properties": [
                           {"name": "tripline:bundled-file", "value": lib},
                           {"name": "tripline:licence-source", "value": "licence files shipped in the wheel"}]})
    for crate in (audit.get("rust") or {}).get("crates", []):
        if "binary" not in crate.get("evidence", []):
            continue
        c = {"type": "library", "name": crate["name"], "version": crate["version"],
             "purl": f"pkg:cargo/{crate['name']}@{crate['version']}",
             "bom-ref": f"{comp.get('bom-ref', comp['name'])}/cargo:{crate['name']}@{crate['version']}",
             "properties": [{"name": "tripline:linkage", "value": "statically linked (Rust)"}]}
        if crate.get("license"):
            c["licenses"] = [{"expression": crate["license"].replace("/", " OR ")}]
        nested.append(c)
    return nested


def check(sbom_path: Path, lock_path: Path) -> list[str]:
    bom = json.loads(sbom_path.read_text())
    lock = parse_lock(lock_path)
    errors = []
    comps = {normalize_name(c["name"]): c for c in bom.get("components", [])}
    root = (bom.get("metadata") or {}).get("component")
    if root:
        comps.setdefault(normalize_name(root["name"]), root)
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("not a CycloneDX document")
    for key, e in sorted(lock.items()):
        c = comps.get(key)
        if c is None:
            errors.append(f"{e['name']}: missing from SBOM")
            continue
        if c.get("version") != e["version"]:
            errors.append(f"{e['name']}: SBOM version {c.get('version')} != lock {e['version']}")
        purl = c.get("purl", "")
        if not purl.startswith(f"pkg:pypi/{key}@{e['version']}") and not purl.startswith(
                f"pkg:pypi/{key.replace('-', '_')}@{e['version']}"):
            errors.append(f"{e['name']}: purl {purl!r} does not identify pkg:pypi/{key}@{e['version']}")
        hashes = {h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"}
        if not hashes:
            errors.append(f"{e['name']}: no SHA-256 hash in SBOM")
        elif not any(f"sha256:{h}" in e["hashes"] for h in hashes):
            errors.append(f"{e['name']}: SBOM hash is not one of the lock's hashes")
        if not c.get("licenses"):
            errors.append(f"{e['name']}: no licence recorded in SBOM")
    for fp in FIRST_PARTY:
        c = comps.get(fp)
        if c is None:
            errors.append(f"first-party {fp} missing from SBOM")
        elif not c.get("hashes"):
            errors.append(f"first-party {fp} has no hash in SBOM")
    for key, c in comps.items():
        if key not in lock and key not in FIRST_PARTY:
            errors.append(f"{c['name']} {c.get('version')}: in SBOM but not in the runtime lock")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--python", type=Path, required=True, help="python of a clean venv installed from the lock")
    g.add_argument("--wheels", type=Path, required=True)
    g.add_argument("--lock", type=Path, required=True)
    g.add_argument("--pyproject", type=Path, default=Path(__file__).resolve().parent.parent / "pyproject.toml")
    g.add_argument("--native-audit", type=Path)
    g.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("check")
    c.add_argument("--sbom", type=Path, required=True)
    c.add_argument("--lock", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.cmd == "generate":
        bom = generate(args.python, args.wheels, args.lock, args.pyproject, args.out, args.native_audit)
        print(f"SBOM: {len(bom.get('components', []))} components -> {args.out}")
        return 0
    errors = check(args.sbom, args.lock)
    for e in errors:
        print(f"FAIL {e}")
    print(f"SBOM check: {'PASS' if not errors else 'FAIL'} ({args.sbom})")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
