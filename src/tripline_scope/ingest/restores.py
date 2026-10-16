"""Registry of restored databases (``work/restores.json``, encrypted) and the closure hook that drops them.

Each entry: ``source_id, engine, instance_ref`` (opaque), ``database`` (derived from case + source ids),
``original_database`` (name in the backup header), ``restored_at``, ``source_sha256``, transfer details and
``status`` (``restored`` | ``dropped``). Host names, logins and passwords are never recorded.
"""

from __future__ import annotations

from tripline_scope.core.closure import register_closure_hook
from tripline_scope.core.errors import IntegrityError
from tripline_scope.core.timeutil import now_iso

REL = "work/restores.json"
SCHEMA = "tripline.restores/v1"


def load(store) -> dict:
    if store is None or not store.exists(REL):
        return {"schema": SCHEMA, "restores": []}
    doc = store.read_json(REL)
    if doc.get("schema") != SCHEMA:
        raise IntegrityError("unrecognised restores registry")
    return doc


def save(store, doc: dict) -> str:
    doc["restores"].sort(key=lambda e: (e["source_id"], e["database"]))
    return store.write_json(REL, doc)


def active(store, source_id: str) -> dict | None:
    for e in load(store)["restores"]:
        if e["source_id"] == source_id and e["status"] == "restored":
            return e
    return None


def record(store, entry: dict) -> None:
    doc = load(store)
    doc["restores"] = [e for e in doc["restores"]
                       if not (e["source_id"] == entry["source_id"] and e["database"] == entry["database"])]
    doc["restores"].append(entry)
    save(store, doc)


def update(store, source_id: str, database: str, **changes) -> dict:
    doc = load(store)
    for e in doc["restores"]:
        if e["source_id"] == source_id and e["database"] == database:
            e.update(changes)
            save(store, doc)
            return e
    raise IntegrityError("restore not found in the registry")


def begin(store, entry: dict) -> None:
    """Record a restore before any data reaches the target (status ``restoring``)."""
    record(store, dict(entry, status="restoring"))


def abandon(home, store, entry: dict) -> None:
    """A restore failed: drop whatever reached the target and record the outcome (never raises)."""
    try:
        drop_entry(home, store, dict(entry, status="restoring"))
    except Exception:  # noqa: BLE001, S110 - closure retries any entry not verified absent
        pass


def cleanup_interrupted(home, store, source_id: str) -> None:
    """Drop restores of this source that were interrupted (``restoring``) or whose drop failed."""
    for e in load(store)["restores"]:
        if e["source_id"] == source_id and e["status"] in ("restoring", "drop_failed"):
            e = drop_entry(home, store, e)
            if not e.get("verified_absent"):
                raise IntegrityError("an interrupted restore of this source could not be dropped; check the target")


def drop_entry(home, store, entry: dict) -> dict:
    """Drop one restored database (and any leftover transferred backup copy) and verify it is gone."""
    from .config import target_for

    target = target_for(home, entry["engine"])
    if target.instance_ref != entry["instance_ref"]:
        raise IntegrityError("the configured restore target is not the instance this database was restored to; "
                             "restore the original restore_targets settings before dropping")
    if entry["engine"] == "mssql":
        from . import mssql as eng
    else:
        from . import postgres as eng
    absent = eng.drop_database(target, entry["database"])
    copy_removed = entry.get("transfer_copy_removed", True)
    if not copy_removed and entry["engine"] == "mssql":
        copy_removed = eng.remove_transfer_copy(target, entry.get("transfer_copy"))
    return update(store, entry["source_id"], entry["database"], status="dropped" if absent else "drop_failed",
                  dropped_at=now_iso(), verified_absent=bool(absent), transfer_copy_removed=bool(copy_removed))


def closure_hook(case, store, home) -> list[dict]:
    """Drop every restored database recorded for the case; refuse closure if any cannot be verified absent."""
    doc = load(store)
    out = []
    failed = 0
    for e in list(doc["restores"]):
        if e["status"] != "dropped":
            try:
                e = drop_entry(home, store, e)
            except Exception as exc:  # noqa: BLE001 - reported below without details that could hold secrets
                e = dict(e, status="drop_failed", verified_absent=False, error_class=type(exc).__name__)
        if not e.get("verified_absent"):
            failed += 1
        out.append({
            "source_id": e["source_id"],
            "engine": e["engine"],
            "instance_ref": e["instance_ref"],
            "database": e["database"],
            "original_database": e.get("original_database"),
            "restored_at": e.get("restored_at"),
            "dropped_at": e.get("dropped_at"),
            "verified_absent": bool(e.get("verified_absent")),
            "transfer_copy_removed": bool(e.get("transfer_copy_removed", True)),
        })
    if failed:
        raise IntegrityError(f"{failed} restored database(s) could not be dropped and verified absent; closure "
                             "stopped before anything was destroyed (check the restore target and retry)")
    return out


register_closure_hook("restored_databases", closure_hook)
