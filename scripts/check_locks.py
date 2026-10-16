#!/usr/bin/env python3
"""Check the hashed lock files: every entry pinned with == and at least one --hash, the runtime lock covers
every dependency of pyproject.toml and verify/pyproject.toml (except the first-party verifier, which is built
from source), first-party packages are never resolved from an index, and no telemetry SDK is locked.

Exit 0 when every check passes, 1 otherwise. Stdlib only (``packaging`` is used for specifier checks when
available).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_licences import FIRST_PARTY, forbidden, normalize_name, parse_lock  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _deps(pyproject: Path, extras: tuple[str, ...] = ()) -> list[str]:
    proj = tomllib.loads(pyproject.read_text())["project"]
    out = list(proj.get("dependencies", []))
    for e in extras:
        out += proj.get("optional-dependencies", {}).get(e, [])
    return out


def _name(req: str) -> str:
    return normalize_name(re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", req).group(1))


def check_lock_file(path: Path, *, required: list[str], first_party_allowed: bool = False) -> list[str]:
    errors = []
    lock = parse_lock(path)
    if not lock:
        return [f"{path.name}: no requirements found"]
    for key, e in lock.items():
        if not e["pinned"]:
            errors.append(f"{path.name}: {e['name']} is not pinned with ==")
        if not e["hashes"]:
            errors.append(f"{path.name}: {e['name']} has no --hash")
        if any(not re.fullmatch(r"[0-9a-f]{64}", h.removeprefix("sha256:")) or not h.startswith("sha256:")
               for h in e["hashes"]):
            errors.append(f"{path.name}: {e['name']} has a non-SHA-256 hash")
        if key in FIRST_PARTY and not first_party_allowed:
            errors.append(f"{path.name}: first-party {e['name']} must be built from source, not locked from an index")
        if forbidden(key):
            errors.append(f"{path.name}: forbidden telemetry package {e['name']}")
    try:
        from packaging.requirements import Requirement
    except ImportError:  # pragma: no cover - specifier checks are best-effort without packaging
        Requirement = None
    for req in required:
        key = _name(req)
        if key in FIRST_PARTY:
            continue
        if key not in lock:
            errors.append(f"{path.name}: dependency {req!r} is not in the lock (run make lock)")
            continue
        if Requirement is not None:
            r = Requirement(req)
            if r.specifier and not r.specifier.contains(lock[key]["version"], prereleases=True):
                errors.append(f"{path.name}: {lock[key]['name']}=={lock[key]['version']} does not satisfy {req!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    root = args.root
    runtime_deps = _deps(root / "pyproject.toml") + _deps(root / "verify" / "pyproject.toml")
    dev_deps = runtime_deps + _deps(root / "pyproject.toml", ("dev",))
    errors = check_lock_file(root / "requirements" / "runtime.txt", required=runtime_deps)
    errors += check_lock_file(root / "requirements" / "dev.txt", required=dev_deps)
    errors += check_lock_file(root / "requirements" / "build.txt", required=["pip", "setuptools", "wheel"])
    runtime = parse_lock(root / "requirements" / "runtime.txt")
    dev = parse_lock(root / "requirements" / "dev.txt")
    for key, e in runtime.items():
        if key in dev and dev[key]["version"] != e["version"]:
            errors.append(f"dev.txt pins {e['name']}=={dev[key]['version']} but runtime.txt pins {e['version']}")
    for e in errors:
        print(f"FAIL {e}")
    print(f"locks: runtime={len(runtime)} dev={len(dev)} -> {'PASS' if not errors else 'FAIL'}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
