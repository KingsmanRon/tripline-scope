"""SQL Server: restore ``.bak`` sources into a case-specific database and read tables in bounded batches.

Licensing: SQL Server Developer Edition is for development and tests only. Real cases restore to an instance
the hospital provides and licenses (typically its restore / test server), configured as
``restore_targets.mssql``.

Restore flow (the source ``.bak`` is only ever read):

1. make the backup visible to the server: ``shared_path`` (the server reads the evidence file in place, through
   a read-only share) or ``docker_cp`` (demo/test containers: copied in, then deleted after the restore);
2. ``RESTORE HEADERONLY`` / ``FILELISTONLY``; ``RESTORE DATABASE [tscope_<case>_<src>] ... WITH MOVE ...,
   RECOVERY`` into the case-specific name (an existing database of that name is never replaced);
3. the restored copy is set ``READ_ONLY`` and recorded in ``work/restores.json``; closure drops it.

Reads use deterministic order: keyset pagination on an integer primary key, otherwise ``ORDER BY`` the key (or
every orderable column) with ``OFFSET/FETCH``; every query has a timeout.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator

import pyarrow as pa

from tripline_scope.core import custody
from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.core.timeutil import now_iso

from . import restores
from .config import IngestLimits, Target, mssql_target, restored_db_name, server_path, shared_server_path
from .model import ColumnInfo, TableRef, batch_from_rows, empty_batch

APP_NAME = "tripline-scope"
_INT_TYPES = {"int", "bigint", "smallint", "tinyint"}
_NUMERIC_TYPES = _INT_TYPES | {"decimal", "numeric", "float", "real", "money", "smallmoney"}
_UNREADABLE = {"image", "varbinary", "binary", "timestamp", "rowversion", "geography", "geometry", "hierarchyid"}
_UNORDERABLE = {"text", "ntext", "image", "xml", "geography", "geometry", "varbinary", "binary"}
_CAST_NVARCHAR = {"xml", "sql_variant", "datetimeoffset"}


def quote(name: str) -> str:
    return "[" + str(name).replace("]", "]]") + "]"


def literal(s: str) -> str:
    return "N'" + str(s).replace("'", "''") + "'"


def _safe_server_path(p: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_\-./: \\]{1,400}", p) or ".." in re.split(r"[\\/]", p):
        raise ConfigError("unsafe server path")
    return p


def connect(target: Target, database: str = "master", *, timeout: float | None = 300, readonly: bool = False):
    import pytds

    if target.encryption:
        from pytds import tls

        if not tls.OPENSSL_AVAILABLE:
            raise ConfigError("encryption: true needs pyOpenSSL for python-tds, which this bundle does not ship; "
                              "keep the restore server on an isolated segment or add pyOpenSSL (Apache-2.0)")
    try:
        return pytds.connect(dsn=target.host, port=target.port, database=database, user=target.login,
                             password=target.password(), autocommit=True, login_timeout=target.login_timeout_s,
                             timeout=timeout, appname=APP_NAME, readonly=readonly, bytes_to_unicode=True,
                             disable_connect_retry=True)
    except Exception as exc:  # noqa: BLE001 - never echo driver messages (may include host/login)
        raise ConfigError(f"cannot connect to the SQL Server {target.name} target ({type(exc).__name__})") from None


def _rows(cur) -> list[dict]:
    cols = [d[0] for d in cur.description or []]
    return [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]


def _drain(cur) -> None:
    try:
        while cur.nextset():
            pass
    except Exception:  # noqa: BLE001, S110
        pass


# ------------------------------------------------------------------------------------------ transfer
def _docker(args: list[str], timeout: int = 3600) -> None:
    try:
        res = subprocess.run(["docker", *args], capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise ConfigError("docker_cp transfer needs the docker CLI") from None
    if res.returncode != 0:
        raise ConfigError(f"docker {args[0]} failed (exit {res.returncode})")


def _transfer(target: Target, src_path: str, db: str) -> tuple[str, str | None]:
    """Return (path the server reads, transfer copy to delete afterwards or None)."""
    if target.backup_transfer == "shared_path":
        return _safe_server_path(shared_server_path(target, src_path)), None
    dest = _safe_server_path(server_path(target, f"{db}.bak"))
    base = _safe_server_path(target.server_backup_dir)
    c = target.container
    _docker(["exec", "-u", "root", c, "mkdir", "-p", base])
    _docker(["exec", "-u", "root", c, "chown", "mssql", base])
    _docker(["exec", "-u", "root", c, "chmod", "0700", base])
    _docker(["cp", src_path, f"{c}:{dest}"])
    _docker(["exec", "-u", "root", c, "chown", "mssql", dest])
    _docker(["exec", "-u", "root", c, "chmod", "0400", dest])
    return dest, dest


def remove_transfer_copy(target: Target, path: str | None) -> bool:
    if not path:
        return True
    if target.backup_transfer != "docker_cp":
        return True
    try:
        _docker(["exec", "-u", "root", target.container, "rm", "-f", _safe_server_path(path)])
        return True
    except ConfigError:
        return False


# ------------------------------------------------------------------------------------------ restore
def database_exists(cur, name: str) -> bool:
    cur.execute("SELECT DB_ID(%(n)s)", {"n": name})
    return cur.fetchone()[0] is not None


def ensure_restored(case, store, home, source: dict, limits: IngestLimits, warn=None) -> dict:
    """Restore the source's .bak (once) and return its registry entry."""
    target = mssql_target(home)
    sid = source["source_id"]
    db = restored_db_name(target.database_prefix, case.case_id, sid)
    files = [f for f in source.get("files", [])]
    if len(files) != 1:
        raise ConfigError("an mssql_bak source must be exactly one .bak file")
    if files[0].get("encrypted_copy") or not files[0].get("path"):
        raise ConfigError("SQL Server restores read the .bak from its path: register the source by reference "
                          "(not --copy) on storage the restore server can read")
    src_path = str(custody.reference_path(case, sid))
    restores.cleanup_interrupted(home, store, sid)
    entry = restores.active(store, sid)
    con = connect(target, timeout=limits.query_timeout_s)
    try:
        cur = con.cursor()
        if entry is not None:
            if entry["instance_ref"] != target.instance_ref:
                raise IntegrityError("this source was restored to a different SQL Server instance")
            if database_exists(cur, entry["database"]):
                return entry
            restores.update(store, sid, entry["database"], status="dropped", dropped_at=now_iso(),
                            verified_absent=True, note="found absent before re-restore")
        if database_exists(cur, db):
            raise IntegrityError("a database with the case-specific restore name already exists on the target but is "
                                 "not recorded for this case; refusing to replace it")
    finally:
        con.close()
    entry = {
        "source_id": sid,
        "engine": "mssql",
        "instance_ref": target.instance_ref,
        "database": db,
        "original_database": None,
        "restored_at": None,
        "source_sha256": files[0].get("sha256"),
        "transfer": target.backup_transfer,
        "transfer_copy": server_path(target, f"{db}.bak") if target.backup_transfer == "docker_cp" else None,
        "transfer_copy_removed": target.backup_transfer != "docker_cp",
        "read_only": False,
    }
    restores.begin(store, entry)      # recorded before any data reaches the server, so closure can drop it
    copy = None
    try:
        server_file, copy = _transfer(target, src_path, db)
        original = _restore(target, db, server_file, limits)
    except BaseException:
        if copy:
            remove_transfer_copy(target, copy)
        restores.abandon(home, store, entry)
        raise
    copy_removed = remove_transfer_copy(target, copy) if copy else True
    return restores.update(store, sid, db, status="restored", restored_at=now_iso(), original_database=original,
                           read_only=True, transfer_copy_removed=copy_removed)


def _restore(target: Target, db: str, server_file: str, limits: IngestLimits) -> str:
    con = connect(target, timeout=limits.restore_timeout_s)
    try:
        cur = con.cursor()
        lit = literal(server_file)
        cur.execute(f"RESTORE HEADERONLY FROM DISK = {lit}")
        headers = _rows(cur)
        _drain(cur)
        if not headers:
            raise IntegrityError("backup file holds no backup sets")
        full = [h for h in headers if int(h.get("BackupType") or 0) == 1] or headers
        position = int(full[-1].get("Position") or 1)
        original = str(full[-1].get("DatabaseName") or "")
        cur.execute(f"RESTORE FILELISTONLY FROM DISK = {lit} WITH FILE = {position}")
        filelist = _rows(cur)
        _drain(cur)
        cur.execute("SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(400)), "
                    "CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(400))")
        ddata, dlog = cur.fetchone()
        data_dir = _safe_server_path((target.data_dir or ddata or "").rstrip("/\\"))
        log_dir = _safe_server_path((target.log_dir or target.data_dir or dlog or ddata or "").rstrip("/\\"))
        sep = "\\" if re.match(r"^[A-Za-z]:\\", data_dir) else "/"
        moves, seen_data = [], False
        for f in filelist:
            fid = int(f.get("FileID") or len(moves) + 1)
            ftype = str(f.get("Type") or "D")
            if ftype == "L":
                phys = f"{log_dir}{sep}{db}_{fid}.ldf"
            elif ftype == "D":
                phys = f"{data_dir}{sep}{db}_{fid}.{'ndf' if seen_data else 'mdf'}"
                seen_data = True
            else:
                phys = f"{data_dir}{sep}{db}_{fid}"
            moves.append(f"MOVE {literal(str(f['LogicalName']))} TO {literal(_safe_server_path(phys))}")
        cur.execute(f"RESTORE DATABASE {quote(db)} FROM DISK = {lit} WITH FILE = {position}, "
                    f"{', '.join(moves)}, RECOVERY, NOUNLOAD")
        _drain(cur)
        if not database_exists(cur, db):
            raise IntegrityError("restore did not produce the database")
        cur.execute(f"ALTER DATABASE {quote(db)} SET READ_ONLY WITH ROLLBACK IMMEDIATE")
        _drain(cur)
        return original
    finally:
        con.close()


def drop_database(target: Target, name: str) -> bool:
    """Drop ``name`` if present and return True when it is verifiably absent afterwards."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name):
        raise IntegrityError("refusing to drop a database whose name was not derived by this product")
    con = connect(target, timeout=600)
    try:
        cur = con.cursor()
        if database_exists(cur, name):
            cur.execute(f"ALTER DATABASE {quote(name)} SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
            _drain(cur)
            cur.execute(f"DROP DATABASE {quote(name)}")
            _drain(cur)
        return not database_exists(cur, name)
    finally:
        con.close()


# ------------------------------------------------------------------------------------------ reading
class MSSQLReader:
    engine = "mssql"

    def __init__(self, target: Target, database: str, *, display_database: str | None, limits: IngestLimits,
                 readonly: bool = False, allowed_tables: list[str] | None = None, max_rows: int | None = None,
                 session_sql: list[str] | None = None, connection=None):
        self.target, self.database, self.display = target, database, display_database or database
        self.limits = limits
        self.allowed = [t.lower() for t in allowed_tables] if allowed_tables else None
        self.max_rows = max_rows
        self._con = connection or connect(target, database, timeout=limits.query_timeout_s, readonly=readonly)
        self._tables: list[TableRef] | None = None
        for stmt in session_sql or []:
            self._con.cursor().execute(stmt)

    def close(self) -> None:
        try:
            self._con.close()
        except Exception:  # noqa: BLE001, S110
            pass

    def _cur(self):
        return self._con.cursor()

    def tables(self) -> list[TableRef]:
        if self._tables is not None:
            return list(self._tables)
        cur = self._cur()
        cur.execute("""
            SELECT s.name AS schema_name, t.name AS table_name, t.object_id,
                   (SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = t.object_id AND p.index_id IN (0, 1))
                       AS est_rows
            FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name""")
        tabs = _rows(cur)
        cur.execute("""
            SELECT c.object_id, c.column_id, c.name AS column_name, ty.name AS type_name
            FROM sys.columns c JOIN sys.types ty ON ty.user_type_id = c.user_type_id
            JOIN sys.tables t ON t.object_id = c.object_id
            WHERE t.is_ms_shipped = 0
            ORDER BY c.object_id, c.column_id""")
        cols_by: dict[int, list[dict]] = {}
        for r in _rows(cur):
            cols_by.setdefault(r["object_id"], []).append(r)
        cur.execute("""
            SELECT i.object_id, c.name AS column_name, ic.key_ordinal
            FROM sys.indexes i
            JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE i.is_primary_key = 1
            ORDER BY i.object_id, ic.key_ordinal""")
        pk_by: dict[int, list[str]] = {}
        for r in _rows(cur):
            pk_by.setdefault(r["object_id"], []).append(r["column_name"])
        out = []
        for t in tabs:
            q = f"{t['schema_name']}.{t['table_name']}".lower()
            if self.allowed is not None and q not in self.allowed and t["table_name"].lower() not in self.allowed:
                continue
            cols, types = [], {}
            for c in cols_by.get(t["object_id"], []):
                ty = str(c["type_name"]).lower()
                types[c["column_name"]] = ty
                cols.append(ColumnInfo(c["column_name"], ty, numeric=ty in _NUMERIC_TYPES, readable=ty not in _UNREADABLE))
            out.append(TableRef(t["table_name"], cols, database=self.display, schema=t["schema_name"],
                                key=pk_by.get(t["object_id"], []), estimated_rows=int(t["est_rows"] or 0),
                                handle={"types": types}))
        self._tables = out
        return list(out)

    def count_rows(self, table: TableRef) -> int | None:
        cur = self._cur()
        cur.execute(f"SELECT COUNT_BIG(*) FROM {quote(table.schema)}.{quote(table.name)}")
        return int(cur.fetchone()[0])

    def _select_list(self, table: TableRef) -> tuple[str, list[int]]:
        types = table.handle["types"]
        parts, idx = [], []
        for i, c in enumerate(table.columns):
            if not c.readable:
                continue
            ty = types.get(c.name, "")
            expr = quote(c.name)
            if ty in _CAST_NVARCHAR:
                expr = f"CAST({expr} AS nvarchar(max))"
            parts.append(expr)
            idx.append(i)
        return ", ".join(parts) or "1", idx

    def iter_batches(self, table: TableRef, batch_rows: int, limit: int | None = None) -> Iterator[pa.RecordBatch]:
        types = table.handle["types"]
        sel, idx = self._select_list(table)
        src = f"{quote(table.schema)}.{quote(table.name)}"
        cap = limit
        if self.max_rows is not None:
            cap = min(cap, self.max_rows) if cap is not None else self.max_rows
        key = [k for k in table.key if types.get(k) in _INT_TYPES]
        keyset = bool(table.key) and len(key) == len(table.key)
        if keyset:
            order = ", ".join(quote(k) for k in key)
            sel_full = ", ".join([sel] + [f"{quote(k)} AS {quote('__k' + str(j))}" for j, k in enumerate(key)])
        else:
            order_cols = table.key or [c.name for c in table.columns if types.get(c.name, "") not in _UNORDERABLE]
            order = ", ".join(quote(c) for c in order_cols) or "(SELECT NULL)"
            sel_full = sel
        done = 0
        last: list | None = None
        while True:
            n = batch_rows if cap is None else min(batch_rows, cap - done)
            if n <= 0:
                return
            cur = self._cur()
            if keyset:
                params: dict = {"n": n}
                where = ""
                if last is not None:
                    ors = []
                    for j in range(len(key)):
                        eqs = [f"{quote(key[i])} = %(k{i})s" for i in range(j)]
                        ors.append("(" + " AND ".join(eqs + [f"{quote(key[j])} > %(k{j})s"]) + ")")
                        params[f"k{j}"] = last[j]
                    where = "WHERE " + " OR ".join(ors)
                cur.execute(f"SELECT TOP (%(n)s) {sel_full} FROM {src} {where} ORDER BY {order}", params)
            else:
                cur.execute(f"SELECT {sel_full} FROM {src} ORDER BY {order} "
                            f"OFFSET %(o)s ROWS FETCH NEXT %(n)s ROWS ONLY", {"o": done, "n": n})
            rows = cur.fetchall()
            if not rows:
                if done == 0:
                    yield empty_batch(table)
                return
            nsel = len(idx)
            if keyset:
                last = list(rows[-1][nsel:])
            full = []
            ncols = len(table.columns)
            for r in rows:
                row = [None] * ncols
                for j, i in enumerate(idx):
                    row[i] = r[j]
                full.append(row)
            yield batch_from_rows(full, table)
            done += len(rows)
            if len(rows) < n:
                return
