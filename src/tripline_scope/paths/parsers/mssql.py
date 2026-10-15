"""SQL Server Audit exports: rows of ``sys.fn_get_audit_file`` saved as CSV or JSON by the hospital's own
licensed SQL Server (sqlcmd / bcp / PowerShell; procedure in ``docs/ACCESS_PATHS.md``). Native ``.sqlaudit``
files are refused: they must be read by SQL Server itself.

Columns used (case-insensitive; absent columns are simply unknown): ``event_time`` (UTC), ``sequence_number``,
``action_id``, ``succeeded``, ``session_id``, ``connection_id``, ``server_principal_name``,
``session_server_principal_name``, ``target_server_principal_name``, ``target_database_principal_name``,
``server_instance_name``, ``database_name``, ``schema_name``, ``object_name``, ``statement`` (reduced, never
stored), ``client_ip``, ``host_name``, ``application_name``, ``response_rows``, ``affected_rows``,
``session_context`` (only a request id is extracted, by ``options.request_id_regex``).
"""

from __future__ import annotations

import csv
import json
import re

from .base import ParseContext, apply_sql, blank, clean_ip, text_stream, to_int

VERSION = "1.0"

ACTIONS = {
    "SL": ("select", "select"), "IN": ("insert", "modify"), "UP": ("update", "modify"), "DL": ("delete", "modify"),
    "MG": ("merge", "modify"), "EX": ("execute", "execute"), "RF": ("references", "other"),
    "LGIS": ("login_success", "login_success"), "LGIF": ("login_failure", "login_failure"),
    "LGO": ("logout", "logoff"), "LGOF": ("logout", "logoff"),
    "BA": ("backup_database", "dump_export"), "BAL": ("backup_log", "dump_export"),
    "G": ("grant", "privilege_change"), "GWG": ("grant_with_grant", "privilege_change"),
    "R": ("revoke", "privilege_revoke"), "D": ("deny", "privilege_revoke"),
    "APRL": ("role_member_add", "privilege_change"), "ADSR": ("server_role_member_add", "privilege_change"),
    "DPRL": ("role_member_drop", "privilege_revoke"),
    "AUSC": ("audit_session_changed", "auditing_state_changed"), "AUSF": ("audit_shutdown_on_failure", "auditing_disabled"),
    "CR": ("create", "ddl"), "AL": ("alter", "ddl"), "DR": ("drop", "ddl"),
}
_DEFAULT_REQ = r"request_id[\"']?\s*[=:,]\s*[\"']?([A-Za-z0-9\-]{8,64})"


def _rows(stream, fmt: str):
    if fmt == "csv":
        reader = csv.reader(text_stream(stream))
        header = None
        for row in reader:
            if header is None:
                if not row:
                    continue
                header = [h.strip().lower().lstrip("﻿") for h in row]
                continue
            if not row:
                continue
            yield reader.line_num, dict(zip(header, row, strict=False)), row
        return
    text = text_stream(stream).read()
    stripped = text.lstrip()
    if fmt == "json" and stripped.startswith(("[", "{")):
        doc = json.loads(stripped)
        items = doc.get("value", doc.get("rows", [])) if isinstance(doc, dict) else doc
        for i, item in enumerate(items, 1):
            if isinstance(item, dict):
                yield i, {str(k).lower(): v for k, v in item.items()}, item
            else:
                yield i, None, item
        return
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            yield i, None, line
            continue
        yield i, ({str(k).lower(): v for k, v in item.items()} if isinstance(item, dict) else None), item


def parse(ctx: ParseContext, stream, relname: str):
    req_re = re.compile(ctx.options.get("request_id_regex") or _DEFAULT_REQ)
    for n, row, raw in _rows(stream, ctx.fmt):
        loc = f"{relname}:{n}" if ctx.fmt == "csv" else f"{relname}#{n}"
        raw_repr = raw if not isinstance(raw, list) else "\x1f".join(raw)
        if row is None or "event_time" not in row:
            ctx.fail(loc, "record is not an audit row (missing event_time)")
            continue
        from ..timenorm import parse_iso

        ts, prec, abbr = parse_iso(str(row.get("event_time") or ""))
        if ts is None:
            ctx.fail(loc, "unparseable event_time")
            continue
        action = (blank(row.get("action_id")) or "").strip().upper()
        op, obs = ACTIONS.get(action, (f"action_{action.lower() or 'unknown'}", "other"))
        succeeded = blank(row.get("succeeded"))
        outcome = "unknown"
        if succeeded is not None:
            outcome = "success" if str(succeeded).lower() in ("1", "true", "yes") else "failure"
        db = blank(row.get("database_name"))
        schema = blank(row.get("schema_name"))
        obj = blank(row.get("object_name"))
        conn = blank(row.get("connection_id"))
        if conn and set(conn.replace("-", "")) == {"0"}:
            conn = None
        spid = blank(row.get("session_id"))
        session = f"conn:{conn.lower()}" if conn else (f"spid:{spid}" if spid and spid != "0" else None)
        principal = blank(row.get("session_server_principal_name")) or blank(row.get("server_principal_name"))
        acting = blank(row.get("server_principal_name"))
        flags = []
        target = blank(row.get("target_server_principal_name")) or blank(row.get("target_database_principal_name"))
        if acting and principal and acting.lower() != principal.lower():
            flags.append("impersonation")
            target = target or acting
        rows_val = to_int(row.get("response_rows"))
        affected = to_int(row.get("affected_rows"))
        if obs == "modify" and affected is not None:
            rows_val = affected
        elif rows_val is None and affected is not None and obs != "select":
            rows_val = affected
        ctxt = row.get("session_context")
        request_id = None
        if ctxt:
            m = req_re.search(str(ctxt))
            request_id = m.group(1) if m else None
        rec = {
            "_raw": raw_repr, "_loc": loc, "_ts": (ts, prec, abbr),
            "host": blank(row.get("server_instance_name")) or ctx.host,
            "account": principal, "target_account": target,
            "application": blank(row.get("application_name")),
            "session_id": session, "request_id": request_id,
            "remote_ip": clean_ip(blank(row.get("client_ip"))),
            "client_host": blank(row.get("host_name")),
            "operation": op, "observation_type": obs, "event_code": action or None,
            "database": db, "outcome": outcome, "rows": rows_val, "flags": flags,
        }
        if obj and obs not in ("login_success", "login_failure", "logoff"):
            full = ".".join(p for p in (db, schema, obj) if p)
            rec["objects"] = [full]
            rec["object_name"] = full
        stmt = row.get("statement")
        if stmt:
            before = rec["observation_type"]
            apply_sql(rec, str(stmt), ctx, database=db, default_schema="dbo")
            if before in ("login_success", "login_failure", "logoff"):
                rec["observation_type"], rec["operation"] = before, op
            elif rec["observation_type"] in ("other", "ddl") and before not in ("other", "ddl"):
                rec["observation_type"], rec["operation"] = before, op
        if rec["observation_type"] == "auditing_state_changed":
            rec["flags"] = sorted(set(rec["flags"]) | {"audit_state_unknown"})
        if rec.get("objects") and not rec.get("object_name"):
            rec["object_name"] = rec["objects"][0]
        yield rec
