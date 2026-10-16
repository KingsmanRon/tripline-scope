"""Case closure: drop restores, delete managed working data, destroy the case key, sign a destruction certificate.

What the certificate can honestly claim (and what it says it cannot):

* the wrapped case key was overwritten and unlinked from the hospital keystore, and no other copy of the case
  key was created by the product, so every encrypted working file of the case is cryptographically unreadable
  even where its blocks survive;
* managed files were deleted from the case filesystem (logical deletion; physical erasure of SSD blocks,
  filesystem snapshots or storage-array copies is **not** claimed);
* restored databases were dropped on the named instances (and the drop was checked);
* what was retained: signed reports, source custody manifests, the audit log, original evidence media held by
  the hospital, and any declared external backups (for example keystore backups made before closure).
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path

from tscope_verify import formats as F

from .auth import Identity
from .canonical import canonical_bytes, sha256_file, sha256_hex
from .case import SUBDIRS, Case
from .custody import _walk_tree
from .errors import CaseClosed, LegalHoldActive, PermissionDenied
from .home import Home
from .keys import Signer
from .reports import ReportStore
from .timeutil import now_iso

ClosureHook = Callable[[Case, object, Home], list[dict]]
_closure_hooks: dict[str, ClosureHook] = {}


def register_closure_hook(name: str, fn: ClosureHook) -> None:
    """Modules register cleanup that needs case context (e.g. dropping restored databases)."""
    _closure_hooks[name] = fn


def _destroy_file(p: Path) -> None:
    size = p.stat().st_size
    with open(p, "r+b") as fh:
        fh.write(os.urandom(size))
        fh.flush()
        os.fsync(fh.fileno())
    p.unlink()


def close_case(
    case: Case,
    home: Home,
    store,
    *,
    approver: Identity,
    hospital: Signer,
    external_backups: list[str] | None = None,
    retain_reports_until: str | None = None,
) -> Path:
    if case.is_closed:
        raise CaseClosed("case already closed")
    if case.legal_hold.get("active"):
        raise LegalHoldActive("a legal hold is active on this case; closure is refused until counsel lifts it")
    if "approver" not in case.roles_of(approver.username):
        raise PermissionDenied("closing a case requires a case approver")
    if approver.username in case.audit.actors_with_role("operator", case.case_id):
        raise PermissionDenied("separation of duties: the approver has acted as operator on this case")

    started = now_iso()
    # 1. module hooks (restored databases etc.) while the key is still available
    hook_results = {}
    for name, fn in sorted(_closure_hooks.items()):
        hook_results[name] = fn(case, store, home)

    # 2. managed working data
    managed: list[Path] = []
    for sub in ("work", "review", "notify"):
        managed += [p for p in case.dir(sub).rglob("*") if p.is_file() or p.is_symlink()]
    for p in case.dir("sources").rglob("*"):
        if p.is_file() and not p.is_symlink() and p.name.endswith(".tse"):
            managed.append(p)
    rels = sorted(p.relative_to(case.root).as_posix() for p in managed)
    total_bytes = sum(p.stat().st_size for p in managed if p.is_file() and not p.is_symlink())
    for p in managed:
        if p.is_symlink():
            p.unlink()
        else:
            os.chmod(p, 0o600)
            p.unlink()
    for sub in ("work", "review", "notify"):
        for d in sorted(case.dir(sub).rglob("*"), reverse=True):
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
    remaining = [p for sub in ("work", "review", "notify") for p in case.dir(sub).rglob("*")]

    # 3. the case key
    wrapped = home.wrapped_dek_path(case.case_id)
    key_existed = wrapped.exists()
    if key_existed:
        _destroy_file(wrapped)
    case.forget_key()
    key_destroyed_at = now_iso()

    # 4. what is retained
    reports = ReportStore(case)
    retained_reports = []
    for kind in sorted(p.name for p in case.dir("reports").iterdir() if p.is_dir() and p.name != "closure"):
        try:
            for n, vdir in reports.versions(kind):
                retained_reports.append({"kind": kind, "version": n, "report_sha256": sha256_file(vdir / F.REPORT_FILE)})
        except Exception:  # noqa: BLE001 - unknown kinds are listed by name only
            retained_reports.append({"kind": kind, "version": None, "report_sha256": None})
        drafts = case.dir("reports") / kind / "drafts"
        if drafts.exists():
            shutil.rmtree(drafts)
    originals = []
    for s in case.sources():
        sdir = case.dir("sources") / s["source_id"]
        for f in s.get("files", []):
            if f.get("path"):
                reachable = os.path.exists(f["path"])
                if f.get("kind") == "directory":
                    now_hash = sha256_hex(canonical_bytes(_walk_tree(Path(f["path"])))) if reachable else None
                    unchanged = now_hash == f.get("tree_sha256") if reachable else None
                else:
                    unchanged = (sha256_file(f["path"]) == f["sha256"]) if reachable else None
                originals.append({
                    "source_id": s["source_id"], "name": f["name"], "custodian": s["supplied_by"],
                    "sha256": f.get("sha256") or f.get("tree_sha256"), "unchanged_at_close": unchanged,
                    "note": "original evidence media retained by the hospital under chain of custody; not destroyed by this product",
                })
        for link in sdir.glob("*"):
            if link.is_symlink():
                link.unlink()
    seq, head = case.audit.head()
    cert = {
        "schema": F.CERTIFICATE_SCHEMA,
        "case_id": case.case_id,
        "installation_id": case.config.get("installation_id"),
        "closure_started_at": started,
        "closed_at": now_iso(),
        "closed_by": {"approver": approver.username, "authentication": approver.auth_method},
        "legal_hold": {"active": False, "history": case.legal_hold},
        "destroyed": {
            "case_key": {
                "dek_id": case.config["case_key"]["dek_id"],
                "wrapped_key_file": str(wrapped),
                "existed_before_closure": key_existed,
                "destroyed_at": key_destroyed_at,
                "method": "wrapped case key overwritten with random bytes, fsynced and unlinked from the hospital keystore; "
                          "the product never stores the unwrapped key on disk",
            },
            "working_files": {
                "count": len(rels),
                "bytes": total_bytes,
                "paths_sha256": sha256_hex(canonical_bytes(rels)),
                "remaining_after_deletion": len(remaining),
                "method": "logical deletion from the case filesystem; all were AES-256-GCM envelopes under the destroyed case key",
            },
            **{name: items for name, items in hook_results.items()},
        },
        "retained": {
            "signed_reports": retained_reports,
            "source_manifests": [{"source_id": s["source_id"], "manifest_sha256": s.get("manifest_sha256")}
                                 for s in case.sources()],
            "audit_log": {"entries": seq, "head_sha256": head},
            "original_media": originals,
            "external_backups": [b[:300] for b in (external_backups or [])],
            "retain_reports_until": retain_reports_until or (case.config.get("retention") or {}).get("retain_reports_until"),
        },
        "limitations": [
            "Physical erasure of SSD blocks, filesystem snapshots, storage-array replicas or hypervisor snapshots is not claimed.",
            "Copies of the hospital keystore made before closure (e.g. backups) still contain the wrapped case key until those "
            "backups expire; they are listed under retained.external_backups when declared.",
            "Original evidence media are retained by the hospital and are outside the scope of this certificate.",
            "Restored database files are dropped through the database engine; reuse of freed storage blocks is controlled by "
            "that engine and the storage layer.",
        ],
    }
    cb = canonical_bytes(cert)
    out_dirs = [case.dir("reports") / "closure", home.certificates_dir / case.case_id]
    sig = canonical_bytes({"schema": F.SIGNATURES_SCHEMA,
                           "signatures": [hospital.signature_entry(F.CERTIFICATE_FILE, cb)]})
    for d in out_dirs:
        d.mkdir(parents=True, exist_ok=True)
        (d / F.CERTIFICATE_FILE).write_bytes(cb)
        (d / F.CERTIFICATE_SIG_FILE).write_bytes(sig)
    (case.root / "state.json").write_bytes(canonical_bytes({"status": "closed", "closed_at": cert["closed_at"]}))
    for sub in SUBDIRS:
        case.dir(sub).mkdir(exist_ok=True)
    return out_dirs[0] / F.CERTIFICATE_FILE
