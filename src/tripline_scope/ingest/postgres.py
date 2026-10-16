"""PostgreSQL: restore custom/tar or plain dumps into a fresh case-specific database and read it in batches.

* Format detection by content: ``PGDMP`` (custom), ``ustar`` (tar), gzip-wrapped or bare SQL text (plain).
* Custom/tar dumps are restored with ``pg_restore --no-owner --no-privileges`` (reading the evidence file in
  place, or the decrypted stream of an encrypted copy on stdin); plain dumps run through the in-process
  executor in :mod:`pgplain` (never ``psql``, so dump content cannot run client-side commands).
* The restore login should hold ``CREATEDB`` only; a superuser login is refused for plain dumps and warned about
  otherwise. The new database is closed to ``PUBLIC`` and set ``default_transaction_read_only`` afterwards.
* ``pg_restore`` messages are counted, never shown (they can quote data).
* Reads use a server-side cursor (``DECLARE ... NO SCROLL CURSOR`` inside a read-only transaction) with
  ``ORDER BY`` the primary key, or every orderable column, so row order is deterministic.
"""

from __future__ import annotations

import gzip
import io
import itertools
import os
import re
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path, PurePath

import pyarrow as pa

from tripline_scope.core import custody
from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.core.timeutil import now_iso

from . import pgplain, restores
from .config import IngestLimits, Target, pg_target, restored_db_name
from .model import ColumnInfo, TableRef, batch_from_columns, empty_batch

APP_NAME = "tripline-scope"
_NUMERIC = {"int2", "int4", "int8", "numeric", "float4", "float8", "money", "oid"}
_UNREADABLE = {"bytea"}
_UNORDERABLE = {"json", "xml", "point", "line", "lseg", "box", "path", "polygon", "circle", "bytea", "tsvector",
                "tsquery", "txid_snapshot", "pg_snapshot"}
_counter = itertools.count(1)


def qi(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def connect(target: Target, database: str, *, timeout: float | None = 300, startup: dict | None = None):
    import pg8000.native as pgn

    ctx = None
    if target.tls:
        ctx = ssl.create_default_context(cafile=target.tls_cafile) if target.tls_cafile else ssl.create_default_context()
    try:
        return pgn.Connection(target.login, host=target.host, port=target.port, database=database,
                              password=target.password(), ssl_context=ctx, timeout=timeout,
                              application_name=APP_NAME, startup_params=startup)
    except Exception as exc:  # noqa: BLE001 - never echo driver messages (may include host/login)
        raise ConfigError(f"cannot connect to the PostgreSQL {target.name} target ({type(exc).__name__})") from None


# ------------------------------------------------------------------------------------------ formats
def detect_format(head: bytes) -> str:
    if head.startswith(b"PGDMP"):
        return "custom"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"\x1f\x8b"):
        return "plain_gzip"
    try:
        text = head[:4096].decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if re.search(r"(?m)^(--|SET |CREATE |\\restrict |SELECT pg_catalog)", text):
        return "plain"
    raise ConfigError("unrecognised PostgreSQL dump format (expected custom, tar or plain SQL from pg_dump)")


def _open_source(case, store, source: dict):
    f = source["files"][0]
    return custody.open_source_file(case, store, source["source_id"], f["name"])


def _bin(target: Target, name: str) -> str:
    if target.bin_dir:
        p = Path(target.bin_dir) / name
        if not p.exists():
            raise ConfigError(f"{name} not found in restore_targets.postgres.bin_dir")
        return str(p)
    return name


def _env(target: Target) -> dict:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "HOME", "TZ")}
    env.update({"PGPASSWORD": target.password(), "PGAPPNAME": APP_NAME, "PGCONNECT_TIMEOUT": str(target.login_timeout_s)})
    if target.tls:
        env["PGSSLMODE"] = "verify-full" if target.tls_cafile else "require"
        if target.tls_cafile:
            env["PGSSLROOTCERT"] = target.tls_cafile
    return env


def _dump_dbname(target: Target, path: str | None, data: bytes | None) -> str | None:
    """Database name recorded in a custom/tar archive's TOC (``pg_restore --list``); output is parsed for that
    single header line and otherwise discarded."""
    args = [_bin(target, "pg_restore"), "--list"]
    args.append(path if path else "-")
    try:
        res = subprocess.run(args, input=data, capture_output=True, timeout=600, check=False, env=_env(target))
    except FileNotFoundError:
        raise ConfigError("pg_restore not found (set restore_targets.postgres.bin_dir)") from None
    m = re.search(rb"(?m)^;\s+dbname:\s*([A-Za-z0-9_\-.]{1,63})\s*$", res.stdout)
    return m.group(1).decode() if m else None


def _run_pg_restore(target: Target, db: str, path: str | None, stream, limits: IngestLimits) -> dict:
    args = [_bin(target, "pg_restore"), "--no-owner", "--no-privileges", "--no-tablespaces", "--no-comments",
            "--no-publications", "--no-subscriptions", "--no-security-labels",
            "-h", target.host, "-p", str(target.port), "-U", target.login, "-d", db]
    args.append(path if path else "-")
    errors = {"lines": 0}
    proc = subprocess.Popen(args, stdin=subprocess.PIPE if stream is not None else subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=_env(target))

    def _count_stderr():
        for line in proc.stderr:
            if b"error:" in line:
                errors["lines"] += 1

    t = threading.Thread(target=_count_stderr, daemon=True)
    t.start()
    try:
        if stream is not None:
            try:
                while chunk := stream.read(1 << 20):
                    proc.stdin.write(chunk)
            finally:
                proc.stdin.close()
        rc = proc.wait(timeout=limits.restore_timeout_s)
    except BaseException:
        proc.kill()
        raise
    t.join(timeout=30)
    return {"tool_exit": rc, "errors": errors["lines"]}


# ------------------------------------------------------------------------------------------ restore
def _exists(con, name: str) -> bool:
    return bool(con.run("SELECT 1 FROM pg_database WHERE datname = :n", n=name))


def ensure_restored(case, store, home, source: dict, limits: IngestLimits, warn=None) -> dict:
    target = pg_target(home)
    sid = source["source_id"]
    db = restored_db_name(target.database_prefix, case.case_id, sid)
    files = source.get("files", [])
    if len(files) != 1:
        raise ConfigError("a pg_dump source must be exactly one dump file (directory-format dumps: use pg_dump -Fc)")
    restores.cleanup_interrupted(home, store, sid)
    entry = restores.active(store, sid)
    con = connect(target, target.maintenance_db, timeout=limits.query_timeout_s)
    try:
        if entry is not None:
            if entry["instance_ref"] != target.instance_ref:
                raise IntegrityError("this source was restored to a different PostgreSQL instance")
            if _exists(con, entry["database"]):
                return entry
            restores.update(store, sid, entry["database"], status="dropped", dropped_at=now_iso(),
                            verified_absent=True, note="found absent before re-restore")
        if _exists(con, db):
            raise IntegrityError("a database with the case-specific restore name already exists on the target but is "
                                 "not recorded for this case; refusing to replace it")
        superuser = bool(con.run("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")[0][0])
        with _open_source(case, store, source) as fh:
            head = fh.read(8192)
        fmt = detect_format(head)
        if superuser:
            if fmt.startswith("plain"):
                raise ConfigError("refusing to run a plain SQL dump as a superuser; configure a restore login with "
                                  "CREATEDB only (see docs/INGEST.md)")
            if warn:
                warn("the PostgreSQL restore login is a superuser; use a CREATEDB-only login (docs/INGEST.md)")
        entry = {
            "source_id": sid,
            "engine": "postgres",
            "instance_ref": target.instance_ref,
            "database": db,
            "original_database": PurePath(files[0]["name"]).stem,
            "restored_at": None,
            "source_sha256": files[0].get("sha256"),
            "dump_format": fmt,
            "transfer": "local_read",
            "transfer_copy_removed": True,
            "read_only": False,
        }
        restores.begin(store, entry)      # recorded before any data lands, so closure can always drop it
        con.run(f"CREATE DATABASE {qi(db)} TEMPLATE template0 ENCODING 'UTF8'")
        con.run(f"REVOKE ALL ON DATABASE {qi(db)} FROM PUBLIC")
    finally:
        con.close()
    try:
        stats, original = _restore_into(case, store, source, target, db, fmt, limits)
        con = connect(target, target.maintenance_db, timeout=limits.query_timeout_s)
        try:
            if not _exists(con, db):
                raise IntegrityError("restore did not produce the database")
            con.run(f"ALTER DATABASE {qi(db)} SET default_transaction_read_only = on")
        finally:
            con.close()
    except BaseException:
        restores.abandon(home, store, entry)
        raise
    failed = int(stats.get("errors") or stats.get("statements_failed") or 0)
    if failed and warn:
        warn(f"{failed} restore statement(s) failed for {sid} (details are not shown because they can quote data)")
    return restores.update(store, sid, db, status="restored", restored_at=now_iso(), restore_stats=stats,
                           read_only=True, original_database=original or entry["original_database"])


def _restore_into(case, store, source: dict, target: Target, db: str, fmt: str, limits: IngestLimits):
    files = source["files"]
    path = None if files[0].get("encrypted_copy") else str(custody.reference_path(case, source["source_id"]))
    original = None
    if fmt in ("custom", "tar"):
        if path:
            original = _dump_dbname(target, path, None)
            stats = _run_pg_restore(target, db, path, None, limits)
        else:
            with _open_source(case, store, source) as fh:
                data = fh.read()          # TOC listing needs the archive; held in memory only
            original = _dump_dbname(target, None, data)
            stats = _run_pg_restore(target, db, None, io.BytesIO(data), limits)
            del data
        return stats, original
    dcon = connect(target, db, timeout=limits.restore_timeout_s)
    try:
        with _open_source(case, store, source) as fh:
            raw = gzip.GzipFile(fileobj=fh) if fmt == "plain_gzip" else fh
            text = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", newline="")
            return pgplain.execute(dcon, iter(text.readline, "")), None
    finally:
        dcon.close()


def drop_database(target: Target, name: str) -> bool:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name):
        raise IntegrityError("refusing to drop a database whose name was not derived by this product")
    con = connect(target, target.maintenance_db, timeout=600)
    try:
        if _exists(con, name):
            con.run(f"DROP DATABASE {qi(name)} WITH (FORCE)")
        return not _exists(con, name)
    finally:
        con.close()


# ------------------------------------------------------------------------------------------ reading
class PGReader:
    engine = "postgres"

    def __init__(self, target: Target, database: str, *, display_database: str | None, limits: IngestLimits,
                 allowed_tables: list[str] | None = None, max_rows: int | None = None,
                 statement_timeout_s: int | None = None, lock_timeout_s: int | None = None, connection=None):
        self.target, self.database, self.display = target, database, display_database or database
        self.limits = limits
        self.allowed = [t.lower() for t in allowed_tables] if allowed_tables else None
        self.max_rows = max_rows
        st = statement_timeout_s or limits.query_timeout_s
        lt = lock_timeout_s or 30
        self._con = connection or connect(target, database, timeout=limits.query_timeout_s + 30)
        self._con.run("SET default_transaction_read_only = on")
        self._con.run(f"SET statement_timeout = '{int(st)}s'")
        self._con.run(f"SET lock_timeout = '{int(lt)}s'")
        self._con.run("SET idle_in_transaction_session_timeout = '600s'")
        self._tables: list[TableRef] | None = None

    def close(self) -> None:
        try:
            self._con.close()
        except Exception:  # noqa: BLE001, S110
            pass

    def tables(self) -> list[TableRef]:
        if self._tables is not None:
            return list(self._tables)
        rows = self._con.run("""
            SELECT c.oid, n.nspname, c.relname, c.reltuples::bigint
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
              AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
              AND n.nspname NOT LIKE 'pg_temp%'
            ORDER BY n.nspname, c.relname""")
        cols = self._con.run("""
            SELECT a.attrelid, a.attnum, a.attname, t.typname, t.typcategory
            FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
            JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY a.attrelid, a.attnum""")
        pks = self._con.run("""
            SELECT i.indrelid, a.attname, k.ord
            FROM pg_index i
            CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
            WHERE i.indisprimary
            ORDER BY i.indrelid, k.ord""")
        by_rel: dict[int, list] = {}
        for oid, _num, name, typ, cat in cols:
            by_rel.setdefault(oid, []).append((name, typ, cat))
        pk_by: dict[int, list[str]] = {}
        for oid, name, _ord in pks:
            pk_by.setdefault(oid, []).append(name)
        out = []
        for oid, schema, name, est in rows:
            q = f"{schema}.{name}".lower()
            if self.allowed is not None and q not in self.allowed and name.lower() not in self.allowed:
                continue
            ci, types = [], {}
            for cname, typ, cat in by_rel.get(oid, []):
                types[cname] = (typ, cat)
                ci.append(ColumnInfo(cname, typ, numeric=typ in _NUMERIC or cat == "N",
                                     readable=typ not in _UNREADABLE))
            out.append(TableRef(name, ci, database=self.display, schema=schema, key=pk_by.get(oid, []),
                                estimated_rows=max(int(est or 0), 0), handle={"types": types}))
        self._tables = out
        return list(out)

    def count_rows(self, table: TableRef) -> int | None:
        return int(self._con.run(f"SELECT count(*) FROM {qi(table.schema)}.{qi(table.name)}")[0][0])

    def iter_batches(self, table: TableRef, batch_rows: int, limit: int | None = None) -> Iterator[pa.RecordBatch]:
        types = table.handle["types"]
        sel = ", ".join(f"{qi(c.name)}::text" if c.readable else "NULL::text" for c in table.columns) or "1"
        if table.key:
            order = ", ".join(qi(k) for k in table.key)
        else:
            order = ", ".join(qi(c.name) for c in table.columns
                              if types.get(c.name, ("", ""))[0] not in _UNORDERABLE
                              and types.get(c.name, ("", ""))[1] not in ("A", "U")) or "ctid"
        cap = limit
        if self.max_rows is not None:
            cap = min(cap, self.max_rows) if cap is not None else self.max_rows
        cur = f"tscope_c{next(_counter)}"
        ncols = len(table.columns)
        self._con.run("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        try:
            self._con.run(f"DECLARE {cur} NO SCROLL CURSOR FOR SELECT {sel} FROM {qi(table.schema)}.{qi(table.name)} "
                          f"ORDER BY {order}")
            done = 0
            while True:
                n = batch_rows if cap is None else min(batch_rows, cap - done)
                if n <= 0:
                    break
                rows = self._con.run(f"FETCH FORWARD {int(n)} FROM {cur}")
                if not rows:
                    if done == 0:
                        yield empty_batch(table)
                    break
                cols: list[list[str | None]] = [[] for _ in range(ncols)]
                for r in rows:
                    for i in range(ncols):
                        v = r[i]
                        cols[i].append(v if v is not None and v.strip() != "" else None)
                done += len(rows)
                yield batch_from_columns(cols, ncols)
                if len(rows) < n:
                    break
        finally:
            try:
                self._con.run("ROLLBACK")
            except Exception:  # noqa: BLE001, S110
                pass
