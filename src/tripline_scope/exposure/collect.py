"""Metadata-only catalogue collection over a read-only login (PostgreSQL via pg8000, SQL Server via python-tds).

Used by ``tscope exposure collect-catalog`` (the DBA writes a JSON export) and by scans that declare
``mode: live_metadata`` for a **restored copy**. Before any catalogue query the login is checked: if it can write
data, change schema, administer the server or reach the server's file system/shell, collection is refused.
Every query is a catalogue ``SELECT`` wrapped with a row limit and run under a statement timeout (PostgreSQL also
in read-only transactions). Error messages are kept short and scrubbed; credentials are never logged.
"""

from __future__ import annotations

import datetime as dt
import decimal

from tripline_scope.core.errors import ConfigError, PermissionDenied
from tripline_scope.core.redact import scrub_text

from .catalog_sql import CATALOG_SCHEMA, QUERIES

_PG_WRITE_CHECKS = {
    "superuser": "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
    "database_create": "SELECT has_database_privilege(current_database(), 'CREATE')",
    "schema_create": ("SELECT count(*) > 0 FROM pg_namespace n WHERE has_schema_privilege(n.oid, 'CREATE') "
                      "AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'"),
    "table_write": ("SELECT count(*) > 0 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT LIKE 'pg\\_%' "
                    "AND n.nspname <> 'information_schema' AND (has_table_privilege(c.oid, 'INSERT') "
                    "OR has_table_privilege(c.oid, 'UPDATE') OR has_table_privilege(c.oid, 'DELETE') "
                    "OR has_table_privilege(c.oid, 'TRUNCATE'))"),
    "owns_objects": ("SELECT count(*) > 0 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                     "WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema' "
                     "AND pg_has_role(c.relowner, 'USAGE')"),
    "server_programs_or_files": ("SELECT pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER') "
                                 "OR pg_has_role(current_user, 'pg_write_server_files', 'MEMBER') "
                                 "OR pg_has_role(current_user, 'pg_write_all_data', 'MEMBER')"),
    "role_admin": "SELECT rolcreaterole OR rolcreatedb OR rolreplication FROM pg_roles WHERE rolname = current_user",
}
_MSSQL_WRITE_CHECKS = {
    "sysadmin": "SELECT IS_SRVROLEMEMBER('sysadmin')",
    "control_server": "SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER')",
    "server_admin": ("SELECT CASE WHEN HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN') = 1 "
                     "OR HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER SETTINGS') = 1 "
                     "OR HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LINKED SERVER') = 1 "
                     "OR HAS_PERMS_BY_NAME(NULL, NULL, 'ADMINISTER BULK OPERATIONS') = 1 THEN 1 ELSE 0 END"),
    "db_roles": ("SELECT CASE WHEN IS_MEMBER('db_owner') = 1 OR IS_MEMBER('db_datawriter') = 1 "
                 "OR IS_MEMBER('db_ddladmin') = 1 OR IS_MEMBER('db_securityadmin') = 1 THEN 1 ELSE 0 END"),
    "db_perms": ("SELECT CASE WHEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'INSERT') = 1 "
                 "OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'UPDATE') = 1 "
                 "OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'DELETE') = 1 "
                 "OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'ALTER') = 1 "
                 "OR HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE') = 1 THEN 1 ELSE 0 END"),
    "object_write": ("SELECT COUNT(*) FROM sys.objects o WHERE o.type IN ('U', 'V') AND ("
                     "HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name), 'OBJECT', 'INSERT') = 1 "
                     "OR HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name), 'OBJECT', 'UPDATE') = 1 "
                     "OR HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name), 'OBJECT', 'DELETE') = 1)"),
}


def _jsonable(v):
    if v is None or isinstance(v, bool | int | str):
        return v
    if isinstance(v, float | decimal.Decimal):
        return str(v)
    if isinstance(v, dt.datetime | dt.date):
        return v.isoformat()
    if isinstance(v, bytes | bytearray | memoryview):
        return "0x" + bytes(v).hex()
    if isinstance(v, list | tuple):
        return ",".join(str(x) for x in v)
    return str(v)


def _err(exc: Exception) -> str:
    a = exc.args[0] if exc.args else ""
    msg = a.get("M") if isinstance(a, dict) else str(a)
    return scrub_text(f"{type(exc).__name__}: {msg}")[:160]


def _run(cur, sql: str, max_rows: int) -> tuple[list[dict], bool]:
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    rows = cur.fetchmany(max_rows + 1)
    truncated = len(rows) > max_rows
    return [{c: _jsonable(v) for c, v in zip(cols, r, strict=False)} for r in rows[:max_rows]], truncated


def _refuse(failed: list[str]) -> None:
    raise PermissionDenied("the catalogue login can write or administer (" + ", ".join(failed) + "): refused. Use a "
                           "metadata-only login (see 'tscope exposure catalog-sql').")


def collect_postgres(*, host, port, user, password, database, timeout_s=30, max_rows=200_000) -> dict:
    import pg8000.dbapi

    conn = pg8000.dbapi.connect(user=user, password=password, host=host, port=int(port), database=database,
                                timeout=timeout_s, application_name="tripline-exposure-metadata")
    try:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(f"SET statement_timeout = {int(timeout_s) * 1000}")
        cur.execute("SET default_transaction_read_only = on")
        cur.execute("SET lock_timeout = 5000")
        failed = []
        for name, sql in _PG_WRITE_CHECKS.items():
            cur.execute(sql)
            row = cur.fetchone()
            if row and row[0]:
                failed.append(name)
        if failed:
            _refuse(failed)
        queries, errors, truncated = {}, {}, []
        for name, (_scope, sql) in QUERIES["postgres"].items():
            try:
                rows, trunc = _run(cur, f"SELECT * FROM ({sql.strip()}) AS q LIMIT {int(max_rows) + 1}", max_rows)
                queries[name] = rows
                if trunc:
                    truncated.append(name)
            except Exception as exc:  # noqa: BLE001 - recorded as an unavailable query
                errors[name] = _err(exc)
        return {"schema": CATALOG_SCHEMA, "engine": "postgres", "server": host, "database": database,
                "queries": queries, "errors": errors, "truncated": truncated,
                "collector": {"login_checked_read_only": True, "statement_timeout_s": timeout_s, "max_rows": max_rows}}
    finally:
        conn.close()


def collect_mssql(*, host, port, user, password, database, timeout_s=30, max_rows=200_000) -> dict:
    import pytds

    conn = pytds.connect(dsn=host, port=int(port), user=user, password=password, database=database,
                         login_timeout=timeout_s, timeout=timeout_s, autocommit=True, appname="tripline-exposure-metadata")
    try:
        cur = conn.cursor()
        cur.execute("SET LOCK_TIMEOUT 5000")
        failed = []
        for name, sql in _MSSQL_WRITE_CHECKS.items():
            cur.execute(sql)
            row = cur.fetchone()
            if row and row[0]:
                failed.append(name)
        if failed:
            _refuse(failed)
        queries, errors, truncated = {}, {}, []
        for name, (_scope, sql) in QUERIES["mssql"].items():
            try:
                rows, trunc = _run(cur, f"SELECT TOP ({int(max_rows) + 1}) * FROM ({sql.strip()}) AS q", max_rows)
                queries[name] = rows
                if trunc:
                    truncated.append(name)
            except Exception as exc:  # noqa: BLE001 - recorded as an unavailable query
                errors[name] = _err(exc)
        return {"schema": CATALOG_SCHEMA, "engine": "mssql", "server": host, "database": database,
                "queries": queries, "errors": errors, "truncated": truncated,
                "collector": {"login_checked_read_only": True, "query_timeout_s": timeout_s, "max_rows": max_rows}}
    finally:
        conn.close()


def collect(engine: str, **kw) -> dict:
    if engine == "postgres":
        return collect_postgres(**kw)
    if engine == "mssql":
        return collect_mssql(**kw)
    raise ConfigError(f"live metadata collection is not supported for engine {engine}")
