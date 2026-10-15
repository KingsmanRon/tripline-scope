"""Chain of custody for sources, and the guarantee that nothing writes to a source.

Two registration modes:

* ``reference`` (default): the original stays where the hospital put it (ideally a read-only mount); the case
  gets a symlink under ``sources/<id>/`` plus a manifest with SHA-256, size, ``supplied_by``, ``received_at``
  and legal basis. The product never modifies, chmods or touches the original.
* ``encrypted_copy``: the bytes are copied into ``sources/<id>/`` as an authenticated envelope under the case
  key (for leak samples or exports received by e-mail). The custody hash is of the original plaintext.

Every command verifies a quick fingerprint (size + mtime) of each reference file before and after it runs, and
``tscope source verify --full`` (also run at ingest and at close) re-hashes everything. In addition a
process-wide audit hook refuses any write-mode open, rename, delete, chmod or truncate of a path under a
registered source root.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
from pathlib import Path

from .canonical import canonical_bytes, sha256_file, sha256_hex
from .case import Case
from .errors import ConfigError, SourceModified
from .timeutil import now_iso, parse_utc

SOURCE_KINDS = {
    "mssql_bak", "pg_dump", "csv", "tsv", "xlsx", "jsonl", "json",
    "live_mssql", "live_pg", "directory", "log", "catalog_export", "directory_export",
}
EVIDENCE_ROLES = {
    "system_copy",      # backup / restored copy of a system that may have been accessed
    "leak_sample",      # data published or received from outside: independently confirmed external copy
    "export_found",     # an export / staged dataset found inside the hospital
    "log",              # logs for access-path analysis
    "readiness_copy",   # read-only copy for readiness scanning
    "reference_data",   # directory/supplier exports, catalogue exports, indicators
}

# ---------------------------------------------------------------------------- write guard
_protected: set[str] = set()
_guard_lock = threading.Lock()
_guard_installed = False
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _under_protected(path, *, follow_final: bool = True) -> bool:
    """True when ``path`` is (or is inside) a protected source. ``follow_final=False`` is used for operations
    that act on a directory entry itself (unlink, rename), where a symlink is not followed."""
    if not _protected or path is None or isinstance(path, int):
        return False
    try:
        raw = os.fsdecode(path)
        if follow_final:
            p = os.path.realpath(raw)
        else:
            p = os.path.join(os.path.realpath(os.path.dirname(os.path.abspath(raw))), os.path.basename(raw))
    except (TypeError, ValueError):
        return False
    return any(p == r or p.startswith(r + os.sep) for r in _protected)


def _hook(event: str, args) -> None:
    if not _protected:
        return
    if event == "open":
        path, mode, flags = (list(args) + [None, None, None])[:3]
        writing = False
        if isinstance(mode, str) and any(c in mode for c in "wax+"):
            writing = True
        if isinstance(flags, int) and flags & _WRITE_FLAGS:
            writing = True
        if writing and _under_protected(path):
            raise PermissionError("write to a registered source is forbidden")
    elif event in ("os.truncate", "os.chmod", "os.chown", "os.utime"):
        if args and _under_protected(args[0]):
            raise PermissionError("modifying a registered source is forbidden")
    elif event in ("os.remove", "os.rmdir", "shutil.rmtree"):
        if args and _under_protected(args[0], follow_final=False):
            raise PermissionError("modifying a registered source is forbidden")
    elif event in ("os.rename", "os.replace", "os.link"):
        if any(_under_protected(a, follow_final=False) for a in args[:2]):
            raise PermissionError("modifying a registered source is forbidden")


def protect(paths) -> None:
    """Register source paths with the process-wide write guard (installed once, cannot be removed)."""
    global _guard_installed
    with _guard_lock:
        if not _guard_installed:
            sys.addaudithook(_hook)
            _guard_installed = True
        for p in paths:
            _protected.add(os.path.realpath(os.fspath(p)))


def protected_roots() -> set[str]:
    return set(_protected)


# ---------------------------------------------------------------------------- registration
def _next_source_id(case: Case) -> str:
    n = len(case.config.get("sources", [])) + 1
    return f"SRC-{n:03d}"


def _file_entry(path: Path, name: str) -> dict:
    st = path.stat()
    return {"name": name, "sha256": sha256_file(path), "size": st.st_size, "mtime_ns": str(st.st_mtime_ns)}


def _walk_tree(root: Path) -> list[dict]:
    """Per-file custody list for a directory source. Symlinks are recorded, never followed."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames) + sorted(d for d in dirnames if os.path.islink(os.path.join(dirpath, d))):
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out.append({"name": rel, "symlink": True, "target_hash": sha256_hex(os.readlink(p).encode())})
                continue
            if not p.is_file():
                continue
            out.append(_file_entry(p, rel))
    return out


def add_source(
    case: Case,
    store,
    *,
    kind: str,
    paths: list[Path] | None,
    label: str,
    evidence_role: str,
    legal_basis: str,
    supplied_by: str,
    received_at: str,
    registered_by: str,
    mode: str = "reference",
    extra: dict | None = None,
) -> dict:
    case.require_open()
    if kind not in SOURCE_KINDS:
        raise ConfigError(f"unknown source kind {kind}")
    if evidence_role not in EVIDENCE_ROLES:
        raise ConfigError(f"unknown evidence role {evidence_role}")
    if not legal_basis.strip():
        raise ConfigError("every source needs a recorded legal basis")
    if not supplied_by.strip():
        raise ConfigError("chain of custody needs supplied_by")
    parse_utc(received_at)
    if mode not in ("reference", "encrypted_copy", "live"):
        raise ConfigError("mode must be reference, encrypted_copy or live")
    if kind.startswith("live_"):
        mode = "live"
    sid = _next_source_id(case)
    sdir = case.dir("sources") / sid
    sdir.mkdir()
    files: list[dict] = []
    tree_root_hash = None
    writable_warning = False
    for raw in paths or []:
        p = Path(raw).resolve()
        if not p.exists():
            raise ConfigError("source path does not exist")
        if os.access(p, os.W_OK):
            writable_warning = True
        if p.is_dir():
            if kind not in ("directory", "log", "directory_export", "catalog_export"):
                raise ConfigError(f"{kind} sources must be files")
            tree = _walk_tree(p)
            tree_root_hash = sha256_hex(canonical_bytes(tree))
            if mode == "encrypted_copy":
                raise ConfigError("directory sources are registered by reference (read-only mount)")
            store.write_json(f"sources/{sid}/tree.json", {"root_hash": tree_root_hash, "files": tree})
            (sdir / p.name).symlink_to(p, target_is_directory=True)
            files.append({"name": p.name, "kind": "directory", "tree_sha256": tree_root_hash,
                          "file_count": len(tree), "size": sum(e.get("size", 0) for e in tree),
                          "path": str(p)})
            continue
        entry = _file_entry(p, p.name)
        if mode == "encrypted_copy":
            with open(p, "rb") as src, store.open_write(f"sources/{sid}/{p.name}") as w:
                while chunk := src.read(1 << 20):
                    w.write(chunk)
            enc = store.path(f"sources/{sid}/{p.name}")
            os.chmod(enc, stat.S_IRUSR)
            entry["encrypted_copy"] = enc.relative_to(case.root).as_posix()
            entry["encrypted_sha256"] = sha256_file(enc)
            entry["path"] = None
        else:
            (sdir / p.name).symlink_to(p)
            entry["path"] = str(p)
        files.append(entry)
    record = {
        "source_id": sid,
        "kind": kind,
        "label": label[:120],
        "evidence_role": evidence_role,
        "legal_basis": legal_basis[:300],
        "supplied_by": supplied_by[:120],
        "received_at": received_at,
        "registered_at": now_iso(),
        "registered_by": registered_by,
        "mode": mode,
        "files": files,
        "read_only_media": not writable_warning,
    }
    if extra:
        record.update(extra)
    manifest = canonical_bytes(record)
    (sdir / "manifest.json").write_bytes(manifest)
    os.chmod(sdir / "manifest.json", stat.S_IRUSR | stat.S_IRGRP)
    record["manifest_sha256"] = sha256_hex(manifest)
    case.config.setdefault("sources", []).append(record)
    case.save()
    protect([f["path"] for f in files if f.get("path")])
    return record


def protect_case_sources(case: Case) -> None:
    roots = []
    for s in case.sources():
        for f in s.get("files", []):
            if f.get("path"):
                roots.append(f["path"])
    if roots:
        protect(roots)


# ---------------------------------------------------------------------------- verification
def quick_check(case: Case) -> list[str]:
    """Cheap per-command check: size and mtime of every reference file are unchanged."""
    problems = []
    for s in case.sources():
        for f in s.get("files", []):
            path = f.get("path")
            if not path or f.get("kind") == "directory":
                continue
            try:
                st = os.stat(path)
            except FileNotFoundError:
                problems.append(f"{s['source_id']}/{f['name']}: original not reachable")
                continue
            if st.st_size != f["size"] or str(st.st_mtime_ns) != str(f["mtime_ns"]):
                problems.append(f"{s['source_id']}/{f['name']}: size or modification time changed")
    return problems


def full_check(case: Case, store=None) -> dict[str, str]:
    """Re-hash every source. Returns {source_id/name: sha256}; raises SourceModified on any mismatch."""
    hashes = {}
    bad = []
    for s in case.sources():
        sid = s["source_id"]
        for f in s.get("files", []):
            key = f"{sid}/{f['name']}"
            if f.get("kind") == "directory":
                tree = _walk_tree(Path(f["path"]))
                h = sha256_hex(canonical_bytes(tree))
                if h != f["tree_sha256"]:
                    bad.append(key)
                hashes[key] = h
            elif f.get("path"):
                if not os.path.exists(f["path"]):
                    bad.append(key + " (unreachable)")
                    continue
                h = sha256_file(f["path"])
                if h != f["sha256"]:
                    bad.append(key)
                hashes[key] = h
            elif f.get("encrypted_copy"):
                enc = case.root / f["encrypted_copy"]
                if not enc.exists():
                    bad.append(key + " (encrypted copy missing)")
                    continue
                if sha256_file(enc) != f["encrypted_sha256"]:
                    bad.append(key)
                hashes[key] = f["sha256"]
    if bad:
        raise SourceModified("source integrity check failed: " + ", ".join(sorted(bad)))
    return hashes


def source_files(case: Case, source_id: str) -> list[dict]:
    return case.source(source_id).get("files", [])


def open_source_file(case: Case, store, source_id: str, name: str):
    """Open a source file read-only (binary). Encrypted copies are decrypted as a stream."""
    for f in source_files(case, source_id):
        if f["name"] == name:
            if f.get("encrypted_copy"):
                return store.open_read(f["encrypted_copy"])
            return open(f["path"], "rb")  # noqa: SIM115
    raise ConfigError("unknown source file")


def reference_path(case: Case, source_id: str, name: str | None = None) -> Path:
    """Filesystem path of a reference-mode source file (for tools such as pg_restore or SQL Server RESTORE)."""
    for f in source_files(case, source_id):
        if name is None or f["name"] == name:
            if not f.get("path"):
                raise ConfigError("source is an encrypted copy; tools needing a path require reference mode")
            return Path(f["path"])
    raise ConfigError("unknown source file")
