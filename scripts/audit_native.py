#!/usr/bin/env python3
"""Inventory of native components inside the runtime wheels (build machine; needs network for new entries).

For every locked wheel that is not pure Python it records the extension modules, the shared libraries
bundled by auditwheel (``<pkg>.libs/``) and the licence files shipped. For packages built from Rust it
downloads the sdist from PyPI (verified against the lock's SHA-256), reads every ``Cargo.lock`` and records
each crates.io crate with the licence declared on crates.io. ``Cargo.lock`` lists every crate for every
target and feature, so the list is a superset of what is statically linked into the Linux wheel.

The output (requirements/native-audit.json) is committed; ``check_licences.py --native-audit`` evaluates it
and fails when it is stale for the locked versions. Previously recorded crate licences are reused, so a
re-run only queries crates.io for new crate versions.

    audit_native.py --lock requirements/runtime.txt --wheels build/wheelhouse --out requirements/native-audit.json
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import time
import tomllib
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_licences import _is_licence_file, normalize_name, parse_lock  # noqa: E402

SCHEMA = "tripline.native-audit/v1"
UA = {"User-Agent": "tripline-scope-licence-audit (offline product build; contact: release engineering)"}


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url}")
    req = urllib.request.Request(url, headers=UA)  # noqa: S310 - https only, checked above
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
        return r.read()


def wheel_inventory(path: Path) -> dict:
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
    return {
        "wheel": path.name,
        "extension_modules": sorted(n for n in names if n.endswith(".so") and ".libs/" not in n),
        "bundled_shared_libraries": sorted(n.rsplit("/", 1)[-1] for n in names if ".libs/" in n),
        "vendored_shared_libraries": sorted(n for n in names if re.search(r"/lib[^/]+\.so(\.\d+)*$", n)
                                            and ".libs/" not in n),
        "licence_files": sorted(n for n in names if _is_licence_file(n)),
    }


def sdist_cargo_locks(name: str, version: str, hashes: list[str]) -> list[tuple[str, dict]]:
    meta = json.loads(_get(f"https://pypi.org/pypi/{name}/{version}/json"))
    sdists = [u for u in meta["urls"] if u["packagetype"] == "sdist"]
    if not sdists:
        return []
    data = _get(sdists[0]["url"])
    digest = hashlib.sha256(data).hexdigest()
    if f"sha256:{digest}" not in hashes:
        raise SystemExit(f"{name} {version}: sdist hash {digest} not in the lock")
    return _cargo_locks(data, f"PyPI sdist {sdists[0]['filename']} (SHA-256 matches the lock)")


def crate_cargo_lock(crate: str, version: str) -> list[tuple[str, dict]]:
    """Cargo.lock packaged in a crates.io crate archive (verified against the crates.io checksum)."""
    info = json.loads(_get(f"https://crates.io/api/v1/crates/{crate}/{version}"))
    data = _get(f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate")
    if hashlib.sha256(data).hexdigest() != info["version"]["checksum"]:
        raise SystemExit(f"crate {crate} {version}: checksum mismatch")
    return _cargo_locks(data, f"crates.io {crate}-{version}.crate (checksum verified)")


def _cargo_locks(data: bytes, origin: str) -> list[tuple[str, dict]]:
    out = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for m in tar.getmembers():
            if m.isfile() and m.name.endswith("/Cargo.lock"):
                raw = tar.extractfile(m).read()
                out.append((m.name.split("/", 1)[1], {"sha256": hashlib.sha256(raw).hexdigest(), "origin": origin,
                                                       "lock": tomllib.loads(raw.decode())}))
    return out


_CRATE_PATH = re.compile(rb"(?:index\.crates\.io-[0-9a-f]+|crates\.io-[0-9a-f]+)/([A-Za-z0-9_\-]+?)-"
                         rb"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/")


def binary_crates(path: Path) -> set[tuple[str, str]]:
    """Crates whose source paths are embedded in the extension modules: evidence of what is linked (a lower
    bound: crates without panic locations or debug strings leave no trace)."""
    found = set()
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith(".so") and ".libs/" not in n:
                found |= {(m.group(1).decode(), m.group(2).decode()) for m in _CRATE_PATH.finditer(z.read(n))}
    return found


# Python distributions published without an sdist: the Rust crate whose packaged Cargo.lock describes them.
NO_SDIST_CRATE = {"evtx": "evtx"}


def crate_licence(name: str, version: str, cache: dict) -> str | None:
    key = f"{name}@{version}"
    if key in cache:
        return cache[key]
    time.sleep(1.0)  # crates.io crawler policy: at most one request per second
    try:
        info = json.loads(_get(f"https://crates.io/api/v1/crates/{name}/{version}"))
        lic = info["version"].get("license")
    except Exception as exc:  # noqa: BLE001 - recorded as unknown, which the gate fails
        print(f"warning: {key}: {type(exc).__name__}", file=sys.stderr)
        lic = None
    cache[key] = lic
    return lic


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", type=Path, required=True)
    ap.add_argument("--wheels", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    lock = parse_lock(args.lock)
    previous = json.loads(args.out.read_text()) if args.out.exists() else {}
    cache = {f"{c['name']}@{c['version']}": c.get("license")
             for p in (previous.get("packages") or {}).values() for c in (p.get("rust") or {}).get("crates", [])}
    packages = {}
    for whl in sorted(args.wheels.glob("*.whl")):
        if whl.name.endswith("-none-any.whl"):
            continue
        dist, version = whl.name.split("-")[:2]
        entry = lock.get(normalize_name(dist))
        if entry is None:
            continue
        inv = wheel_inventory(whl)
        if not inv["extension_modules"]:
            continue
        name = entry["name"]
        print(f"auditing {name} {version}", file=sys.stderr)
        rec = {"version": version, **inv}
        linked = binary_crates(whl)
        locks = sdist_cargo_locks(name, version, entry["hashes"])
        if not locks and normalize_name(name) in NO_SDIST_CRATE:
            crate = NO_SDIST_CRATE[normalize_name(name)]
            embedded = sorted(v for n, v in linked if n == crate)
            if embedded:
                locks = crate_cargo_lock(crate, embedded[-1])
        if locks or linked:
            crates: dict[tuple[str, str], set[str]] = {}
            for nv in linked:
                crates.setdefault(nv, set()).add("binary")
            for _path, cl in locks:
                for pkg in cl["lock"].get("package", []):
                    if str(pkg.get("source", "")).startswith("registry+"):
                        crates.setdefault((pkg["name"], pkg["version"]), set()).add("Cargo.lock")
            rec["rust"] = {
                "cargo_locks": [{"path": p, "sha256": cl["sha256"], "origin": cl["origin"]} for p, cl in locks],
                "note": "evidence 'binary': source path embedded in the shipped extension (linked; a lower bound). "
                        "'Cargo.lock': listed in the build lock for all targets and features (a superset).",
                "crates": [{"name": n, "version": v, "evidence": sorted(ev), "license": crate_licence(n, v, cache)}
                           for (n, v), ev in sorted(crates.items())],
            }
        packages[name] = rec
    doc = {"schema": SCHEMA, "lock_sha256": hashlib.sha256(args.lock.read_bytes()).hexdigest(),
           "packages": packages}
    args.out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    n_crates = sum(len((p.get("rust") or {}).get("crates", [])) for p in packages.values())
    print(f"native audit: {len(packages)} native packages, {n_crates} Rust crates -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
