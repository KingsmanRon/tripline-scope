"""Ingest orchestration: source -> reader (restore if needed) -> discovery -> extraction.

Every function here runs inside a ``core.context.command`` (the caller's ``ctx``), so it is authorised, audited
and wrapped by the source write guard and size/mtime checks; :func:`verify_sources` adds the full SHA-256
check before and after.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

from tripline_scope.core import custody
from tripline_scope.core.errors import ConfigError, SourceModified
from tripline_scope.discovery.engine import discover

from . import restores
from .config import IngestLimits
from .config import limits as load_limits
from .extract import extract_source
from .files import FILE_KINDS, FileReader

DB_KINDS = ("mssql_bak", "pg_dump")
LIVE_KINDS = ("live_mssql", "live_pg")
INGESTIBLE = tuple(FILE_KINDS) + DB_KINDS + LIVE_KINDS


def discovery_rel(source_id: str) -> str:
    return f"work/discovery/{source_id}.json"


def manifest_rel(source_id: str) -> str:
    return f"work/extract/{source_id}/manifest.json"


def status_rel(source_id: str) -> str:
    return f"work/ingest/{source_id}.json"


def select_sources(case, source_ids: list[str] | None) -> list[dict]:
    if source_ids:
        return [case.source(s) for s in source_ids]
    return [s for s in case.sources() if s["kind"] in INGESTIBLE]


def verify_sources(ctx, label: str) -> dict[str, str]:
    """Full SHA-256 of every source against its custody record (raises SourceModified on any change)."""
    hashes = custody.full_check(ctx.case, ctx.store)
    if label == "before":
        for k, v in hashes.items():
            ctx.input(f"source:{k}", v)
    return hashes


def check_unchanged(before: dict[str, str], after: dict[str, str]) -> None:
    if before != after:
        raise SourceModified("source checksums differ before and after the command")


def warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr)


@contextmanager
def open_reader(ctx, source: dict, lim: IngestLimits) -> Iterator[object]:
    kind = source["kind"]
    case, store, home = ctx.case, ctx.store, ctx.home
    if kind not in INGESTIBLE:
        raise ConfigError(f"source kind {kind} is not ingested by this command")
    if kind in FILE_KINDS:
        reader = FileReader(case, store, source, lim)
    elif kind == "mssql_bak":
        from .config import mssql_target
        from .mssql import MSSQLReader, ensure_restored

        entry = ensure_restored(case, store, home, source, lim, warn)
        reader = MSSQLReader(mssql_target(home), entry["database"], display_database=entry.get("original_database"),
                             limits=lim)
    elif kind == "pg_dump":
        from .config import pg_target
        from .postgres import PGReader
        from .postgres import ensure_restored as pg_restore

        entry = pg_restore(case, store, home, source, lim, warn)
        reader = PGReader(pg_target(home), entry["database"], display_database=entry.get("original_database"),
                          limits=lim)
    else:
        from .live import open_live_reader

        reader = open_live_reader(ctx, source, lim, warn)
    try:
        yield reader
    finally:
        reader.close()


def run_discovery(ctx, source: dict, lim: IngestLimits, *, tables: list[str] | None, sample_rows: int,
                  batch_rows: int, reader=None) -> dict:
    sid = source["source_id"]

    def _run(r):
        return discover(r, source_id=sid, case_config=ctx.case.config, sample_rows=sample_rows,
                        batch_rows=batch_rows, tables_filter=tables, key_cap=lim.key_set_cap,
                        max_rows=lim.max_rows_per_table)

    if reader is not None:
        doc = _run(reader)
    else:
        with open_reader(ctx, source, lim) as r:
            doc = _run(r)
    ctx.output(f"discovery/{sid}", ctx.store.write_json(discovery_rel(sid), doc))
    return doc


def ingest_source(ctx, source: dict, lim: IngestLimits, *, tables: list[str] | None, sample_rows: int,
                  batch_rows: int) -> dict:
    sid = source["source_id"]
    t0 = time.monotonic()
    with open_reader(ctx, source, lim) as reader:
        t1 = time.monotonic()
        doc = run_discovery(ctx, source, lim, tables=tables, sample_rows=sample_rows, batch_rows=batch_rows,
                            reader=reader)
        t2 = time.monotonic()
        manifest = extract_source(reader, ctx.store, doc, source_id=sid, batch_rows=batch_rows,
                                  part_rows=lim.part_rows)
        t3 = time.monotonic()
    ctx.output(f"extract/{sid}/manifest", ctx.store.file_sha256(manifest_rel(sid)))
    rows = doc["totals"]["rows"]
    status = {
        "source_id": sid,
        "kind": source["kind"],
        "engine": doc["engine"],
        "tables": doc["totals"]["tables"],
        "tables_scanned": doc["totals"]["tables_scanned"],
        "tables_extracted": manifest["totals"]["extracted_tables"],
        "rows": rows,
        "extracted_rows": manifest["totals"]["extracted_rows"],
        "malformed_rows": sum((t.get("reader") or {}).get("malformed_rows", 0) for t in doc["tables"]),
        "timings_s": {"open_or_restore": round(t1 - t0, 3), "discovery": round(t2 - t1, 3),
                      "extraction": round(t3 - t2, 3)},
        "rows_per_s": {"discovery": round(rows / (t2 - t1), 1) if t2 > t1 else None,
                       "extraction": round(manifest["totals"]["extracted_rows"] / (t3 - t2), 1) if t3 > t2 else None},
        "restored": restores.active(ctx.store, sid) is not None,
    }
    ctx.store.write_json(status_rel(sid), status)
    return status


def category_counts(doc: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in doc["tables"]:
        for c in t["columns"]:
            if t["scanned"]:
                out[c["category"]] = out.get(c["category"], 0) + 1
    return dict(sorted(out.items()))


def load_limits_for(home) -> IngestLimits:
    return load_limits(home)
