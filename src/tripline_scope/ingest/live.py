"""Optional read-only live connections to SQL Server or PostgreSQL (off by default).

A live source (``live_mssql`` / ``live_pg``) is read only when **all** of these hold:

1. a case approver enabled it with ``tscope ingest live-enable`` (``case.yaml live_access.<SRC>.live: true``,
   matched by an ``ok`` audit entry from that approver, so hand-editing ``case.yaml`` is not enough);
2. the installation names the connection under ``live_connections`` (host, port, login, password env var);
3. the login passes the permission checks below — any write, DDL, ownership, execute or administrative right
   refuses the connection;
4. the session is forced read-only, with statement and lock timeouts; only the approved database and tables are
   queried, every table has a row cap and reads are bounded batches.

Every live read prints a warning to stderr and records a note in the audit log.
"""

from __future__ import annotations

from tripline_scope.core.errors import ConfigError, PermissionDenied

from .config import IngestLimits, Target, live_connection

# ---------------------------------------------------------------------------- SQL Server allow-lists
MSSQL_SERVER_ROLES = ("sysadmin", "serveradmin", "securityadmin", "dbcreator", "bulkadmin", "diskadmin",
                      "processadmin", "setupadmin")
MSSQL_DB_ROLES = ("db_owner", "db_datawriter", "db_ddladmin", "db_securityadmin", "db_accessadmin",
                  "db_backupoperator")
_SERVER_OK = {"CONNECT SQL", "VIEW ANY DATABASE", "VIEW ANY DEFINITION", "VIEW SERVER STATE",
              "VIEW SERVER PERFORMANCE STATE", "VIEW SERVER SECURITY STATE", "CONNECT ANY DATABASE",
              "SELECT ALL USER SECURABLES", "VIEW ANY SECURITY DEFINITION", "VIEW ANY PERFORMANCE DEFINITION",
              "VIEW ANY ERROR LOG", "VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION"}
_DB_OK_PREFIX = ("VIEW ", "CONNECT", "SHOWPLAN")
_DB_OK = {"SELECT", "REFERENCES"}
_OBJ_OK = {"SELECT", "VIEW DEFINITION", "REFERENCES", "VIEW CHANGE TRACKING"}


def check_mssql(con, database: str, tables: list[str] | None) -> list[str]:
    """Problems that make the login unsuitable for read-only access (empty list = acceptable)."""
    cur = con.cursor()
    problems: list[str] = []
    for role in MSSQL_SERVER_ROLES:
        cur.execute(f"SELECT IS_SRVROLEMEMBER('{role}')")
        if (cur.fetchone()[0] or 0) == 1:
            problems.append(f"server role {role}")
    cur.execute("SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER')")
    problems += [f"server permission {p}" for (p,) in cur.fetchall() if p not in _SERVER_OK]
    cur.execute("SELECT DB_NAME()")
    if cur.fetchone()[0] != database:
        problems.append("connected to an unexpected database")
    for role in MSSQL_DB_ROLES:
        cur.execute(f"SELECT IS_ROLEMEMBER('{role}')")
        if (cur.fetchone()[0] or 0) == 1:
            problems.append(f"database role {role}")
    cur.execute("SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE')")
    problems += [f"database permission {p}" for (p,) in cur.fetchall()
                 if p not in _DB_OK and not p.startswith(_DB_OK_PREFIX)]
    cur.execute("SELECT s.name, t.name FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id "
                "WHERE t.is_ms_shipped = 0")
    visible = [(s, t) for s, t in cur.fetchall()]
    wanted = {x.lower() for x in tables} if tables else None
    approved = [(s, t) for s, t in visible
                if wanted is None or f"{s}.{t}".lower() in wanted or t.lower() in wanted]
    if wanted is not None and len(approved) < len(wanted):
        problems.append("an approved table is not visible to the login")
    for schema in sorted({s for s, _ in visible}):
        cur.execute("SELECT DISTINCT permission_name FROM fn_my_permissions(%(o)s, 'SCHEMA')", {"o": f"[{schema}]"})
        problems += [f"schema permission {p}" for (p,) in cur.fetchall() if p not in _OBJ_OK]
    for s, t in visible:
        cur.execute("SELECT DISTINCT permission_name FROM fn_my_permissions(%(o)s, 'OBJECT')",
                    {"o": f"[{s.replace(']', ']]')}].[{t.replace(']', ']]')}]"})
        perms = {p for (p,) in cur.fetchall()}
        bad = sorted(perms - _OBJ_OK)
        if bad:
            problems.append(f"table permission {', '.join(bad)}")
        if (s, t) in approved and "SELECT" not in perms:
            problems.append("missing SELECT on an approved table")
    cur.execute("SELECT COUNT(*) FROM sys.objects o CROSS APPLY fn_my_permissions(QUOTENAME(SCHEMA_NAME(o.schema_id)) "
                "+ '.' + QUOTENAME(o.name), 'OBJECT') p WHERE o.type IN ('P', 'PC', 'X', 'FN', 'IF', 'TF') "
                "AND o.is_ms_shipped = 0 AND p.permission_name IN ('EXECUTE', 'ALTER', 'CONTROL')")
    if cur.fetchone()[0]:
        problems.append("EXECUTE/ALTER on stored procedures or functions")
    return list(dict.fromkeys(problems))


# ---------------------------------------------------------------------------- PostgreSQL
_PG_WRITE_ROLES = ("pg_write_all_data", "pg_write_server_files", "pg_execute_server_program", "pg_signal_backend",
                   "pg_checkpoint", "pg_create_subscription", "pg_use_reserved_connections")


def check_pg(con, tables: list[str] | None) -> list[str]:
    problems: list[str] = []
    r = con.run("SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles WHERE rolname = current_user")
    for flag, name in zip(r[0], ("superuser", "CREATEROLE", "CREATEDB", "REPLICATION"), strict=True):
        if flag:
            problems.append(f"role attribute {name}")
    for (role,) in con.run("SELECT rolname FROM pg_roles WHERE rolname = ANY(:r) AND "
                           "pg_has_role(current_user, oid, 'MEMBER')", r=list(_PG_WRITE_ROLES)):
        problems.append(f"member of {role}")
    n = con.run("""
        SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
          AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE')
               OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE')
               OR has_table_privilege(c.oid, 'TRIGGER') OR pg_has_role(c.relowner, 'USAGE'))""")[0][0]
    if n:
        problems.append(f"INSERT/UPDATE/DELETE/TRUNCATE/TRIGGER or ownership on {n} table(s)")
    n = con.run("""
        SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND (has_sequence_privilege(c.oid, 'UPDATE') OR pg_has_role(c.relowner, 'USAGE'))""")[0][0]
    if n:
        problems.append(f"UPDATE or ownership on {n} sequence(s)")
    n = con.run("""
        SELECT count(*) FROM pg_namespace
        WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
          AND (has_schema_privilege(oid, 'CREATE') OR pg_has_role(nspowner, 'USAGE'))""")[0][0]
    if n:
        problems.append(f"CREATE or ownership on {n} schema(s)")
    r = con.run("SELECT has_database_privilege(current_database(), 'CREATE'), "
                "pg_has_role((SELECT datdba FROM pg_database WHERE datname = current_database()), 'USAGE')")[0]
    if r[0]:
        problems.append("CREATE on the database")
    if r[1]:
        problems.append("owns the database")
    if tables:
        for t in tables:
            parts = t.split(".", 1)
            schema, name = (parts[0], parts[1]) if len(parts) == 2 else ("public", parts[0])
            ok = con.run("SELECT has_table_privilege(c.oid, 'SELECT') FROM pg_class c JOIN pg_namespace n "
                         "ON n.oid = c.relnamespace WHERE n.nspname = :s AND c.relname = :t", s=schema, t=name)
            if not ok or not ok[0][0]:
                problems.append("missing SELECT on an approved table")
    if con.run("SHOW transaction_read_only")[0][0] != "on":
        problems.append("session could not be forced read-only")
    return list(dict.fromkeys(problems))


# ---------------------------------------------------------------------------- approval and readers
def _approval(ctx, sid: str) -> dict:
    case = ctx.case
    live = ((case.config.get("live_access") or {}).get(sid)) or {}
    if not live.get("live"):
        raise PermissionDenied("live access is off for this source; a case approver must run "
                               "'tscope ingest live-enable' first")
    approver = live.get("approved_by")
    if not approver or "approver" not in case.roles_of(approver):
        raise PermissionDenied("live access was not approved by a current case approver")
    for e in case.audit.entries():
        if (e.get("command") == "ingest live-enable" and e.get("outcome") == "ok" and e.get("actor") == approver
                and (e.get("params") or {}).get("source") == sid):
            return live
    raise PermissionDenied("live access approval has no matching audit entry (case.yaml edited by hand?)")


class CappedReader:
    """Refuses tables larger than the approved live row cap instead of reading a truncated table."""

    def __init__(self, inner, cap: int):
        self._inner, self._cap = inner, cap
        self.engine = inner.engine

    def tables(self):
        return self._inner.tables()

    def count_rows(self, table):
        return self._inner.count_rows(table)

    def iter_batches(self, table, batch_rows: int, limit: int | None = None):
        if limit is None:
            n = self._inner.count_rows(table)
            if n is not None and n > self._cap:
                raise ConfigError(f"table {table.slug or table.name} has more rows than the approved live row cap; "
                                  "raise --max-rows with the approver or use a backup restore")
        yield from self._inner.iter_batches(table, batch_rows, limit)

    def close(self):
        self._inner.close()


def open_live_reader(ctx, source: dict, lim: IngestLimits, warn) -> object:
    sid = source["source_id"]
    live = _approval(ctx, sid)
    target: Target = live_connection(ctx.home, live["connection"])
    if (target.engine == "mssql") != (source["kind"] == "live_mssql"):
        raise ConfigError("live connection engine does not match the source kind")
    dbs = live.get("databases") or []
    if len(dbs) != 1:
        raise ConfigError("approve exactly one database per live source (register one source per database)")
    db = dbs[0]
    tables = live.get("tables") or None
    cap = int(live.get("max_rows_per_table") or lim.live_max_rows_per_table)
    msg = (f"LIVE read-only connection to a production database for {sid} (approved by "
           f"{live.get('approved_by')}); bounded reads, row cap {cap} per table")
    warn(msg)
    ctx.note(msg)
    if target.engine == "mssql":
        from .mssql import MSSQLReader
        from .mssql import connect as mconnect

        con = mconnect(target, db, timeout=lim.live_statement_timeout_s, readonly=True)
        try:
            cur = con.cursor()
            cur.execute(f"SET LOCK_TIMEOUT {int(lim.live_lock_timeout_s) * 1000}")
            cur.execute("SET DEADLOCK_PRIORITY LOW")
            cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            problems = check_mssql(con, db, tables)
        except BaseException:
            con.close()
            raise
        if problems:
            con.close()
            raise PermissionDenied("refusing live access: the login can change data or the server ("
                                   + "; ".join(problems[:8]) + ")")
        reader = MSSQLReader(target, db, display_database=db, limits=lim, allowed_tables=tables, max_rows=cap,
                             connection=con)
    else:
        from .postgres import PGReader
        from .postgres import connect as pconnect

        startup = {"default_transaction_read_only": "on",
                   "statement_timeout": f"{int(lim.live_statement_timeout_s)}s",
                   "lock_timeout": f"{int(lim.live_lock_timeout_s)}s"}
        con = pconnect(target, db, timeout=lim.live_statement_timeout_s + 30, startup=startup)
        try:
            problems = check_pg(con, tables)
        except BaseException:
            con.close()
            raise
        if problems:
            con.close()
            raise PermissionDenied("refusing live access: the login can change data or the server ("
                                   + "; ".join(problems[:8]) + ")")
        reader = PGReader(target, db, display_database=db, limits=lim, allowed_tables=tables, max_rows=cap,
                          statement_timeout_s=lim.live_statement_timeout_s, lock_timeout_s=lim.live_lock_timeout_s,
                          connection=con)
    return CappedReader(reader, cap)
