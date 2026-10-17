"""Synthetic-origin registry: proof, for the manual model bridge, that a case contains only generated data.

A ``synthetic=true`` flag is never accepted. Instead, the repository's synthetic generators (``tscope synth``,
the Module A estate, the Module B incident logs and the demo ``.bak`` builder), when run with ``--attest``,
hash every file they have just written and record the hashes in ``<home>/synthetic_registry.json`` together with
the generator name and parameters. The registry is authenticated with an HMAC under a key derived from the
hospital KEK, so it cannot be extended by editing the file.

:func:`case_is_synthetic` then requires every file of every registered case source (each file of a directory
source, from its custody tree) to be in the registry. Real data cannot match a registered hash, so a case that
mixes in any real or unverified source is refused.

Limits (documented in AI_INVESTIGATOR.md): the registry proves that the files were produced by these generators
on this installation; an administrator who holds the KEK and deliberately calls :func:`attest_outputs` on other
files defeats it. ``.bak`` files are attested by the builder that produced them from attested synthetic data,
not by reproducing their bytes (SQL Server backups are not byte-reproducible).
"""

from __future__ import annotations

import fcntl
import hmac
import json
import os
from contextlib import contextmanager
from pathlib import Path

from tripline_scope.core import crypto
from tripline_scope.core.canonical import canonical_bytes, sha256_file, sha256_hex
from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.core.timeutil import now_iso

SCHEMA = "tripline.synthetic-registry/v1"
GENERATORS = {"synth", "exposure-estate", "paths-logs", "lab-bak"}
_FILE = "synthetic_registry.json"


def _path(home) -> Path:
    return Path(home.root) / _FILE


def _key(home) -> bytes:
    return crypto.hkdf(home.kek(), b"tripline-synthetic-registry")


def _mac(home, entries: dict) -> str:
    return hmac.new(_key(home), canonical_bytes(entries), "sha256").hexdigest()


@contextmanager
def _locked(home):
    fd = os.open(Path(home.root) / "synthetic_registry.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def registered(home) -> dict[str, dict]:
    """``{sha256: {generator, params_sha256, attested_at}}``; raises IntegrityError if the file was altered."""
    p = _path(home)
    if not p.exists():
        return {}
    doc = json.loads(p.read_bytes())
    entries = doc.get("entries") or {}
    if doc.get("schema") != SCHEMA or not hmac.compare_digest(str(doc.get("mac", "")), _mac(home, entries)):
        raise IntegrityError("synthetic registry failed its integrity check")
    return entries


def _files(paths) -> list[Path]:
    out = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file() and not f.is_symlink())
    return out


def attest_outputs(home, generator: str, params: dict, paths) -> int:
    """Record the hashes of files a synthetic generator has just written. Returns the number of files."""
    if generator not in GENERATORS:
        raise ConfigError(f"unknown synthetic generator {generator!r}")
    files = _files(paths)
    psha = sha256_hex(canonical_bytes({"generator": generator, "params": params}))
    with _locked(home):
        entries = registered(home)
        at = now_iso()
        for f in files:
            entries.setdefault(sha256_file(f), {"generator": generator, "params_sha256": psha, "attested_at": at})
        doc = {"schema": SCHEMA, "entries": entries, "mac": _mac(home, entries)}
        tmp = _path(home).with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(canonical_bytes(doc))
        os.replace(tmp, _path(home))
    return len(files)


def _source_hashes(case, store, src: dict) -> list[tuple[str, str | None]]:
    """(label, sha256) for every file of a source; sha256 None when it cannot be established."""
    out = []
    for f in src.get("files", []):
        if f.get("kind") == "directory":
            rel = f"sources/{src['source_id']}/tree.json"
            tree = store.read_json(rel).get("files", []) if store.exists(rel) else None
            if tree is None:
                out.append((f"{src['source_id']}/{f.get('name')}", None))
                continue
            for t in tree:
                out.append((f"{src['source_id']}/{t.get('name')}", None if t.get("symlink") else t.get("sha256")))
        else:
            out.append((f"{src['source_id']}/{f.get('name')}", f.get("sha256")))
    return out


def case_is_synthetic(case, home, store) -> tuple[bool, list[str]]:
    """True only if the case has sources and every file of every source is registered synthetic output.

    Returns (ok, problems) where problems name source ids/file names only (never contents)."""
    entries = registered(home)
    problems = []
    sources = case.sources()
    if not sources:
        return False, ["case has no registered sources"]
    for src in sources:
        hashes = _source_hashes(case, store, src)
        if not hashes:
            problems.append(f"{src['source_id']}: no files recorded")
        for label, h in hashes:
            if h is None or h not in entries:
                problems.append(f"{label}: not produced by an attested synthetic generator")
    return (not problems), problems[:50]
