"""PostgreSQL server logs: ``csvlog``, ``jsonlog`` (PG 15+) and ``stderr`` with the server's ``log_line_prefix``,
including pgAudit ``AUDIT:`` lines.

Message text is never stored. Recognised messages: ``connection received``, ``connection authorized``,
``replication connection authorized``, ``disconnection``, ``password authentication failed``, ``statement:``,
``execute <name>:``, ``duration: ... statement:``, ``parameter "pgaudit.log"|"log_statement" changed to``, and
pgAudit ``AUDIT: <type>,<stmt id>,<substmt id>,<class>,<command>,<object type>,<object name>,[<rows>,]
<statement>,<parameter>`` (``options.pgaudit_log_rows: true`` when ``pgaudit.log_rows`` is on). Everything else
becomes an ``other`` event with only its severity and SQLSTATE.
"""

from __future__ import annotations

import csv
import io
import json
import re

from ..timenorm import parse_epoch, parse_iso
from .base import ParseContext, apply_sql, blank, clean_ip, text_stream, to_int

VERSION = "1.0"

CSV_COLUMNS = ["log_time", "user_name", "database_name", "process_id", "connection_from", "session_id",
               "session_line_num", "command_tag", "session_start_time", "virtual_transaction_id", "transaction_id",
               "error_severity", "sql_state_code", "message", "detail", "hint", "internal_query",
               "internal_query_pos", "context", "query", "query_pos", "location", "application_name",
               "backend_type", "leader_pid", "query_id"]

_PREFIX_ESCAPES = {
    "a": r"(?P<app>.*?)", "u": r"(?P<user>[^\s@\[\]]*?)", "d": r"(?P<db>[^\s@\[\]]*?)",
    "r": r"(?P<remote>[^\s\[\]]*?)", "h": r"(?P<remote>[^\s\[\]]*?)", "b": r"(?P<backend>[^\[\]]*?)",
    "p": r"(?P<pid>\d+)", "P": r"(?P<leader>\d*)", "t": r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: [A-Za-z+\-0-9:]+)?)",
    "m": r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+(?: [A-Za-z+\-0-9:]+)?)", "n": r"(?P<epoch>\d+\.\d+)",
    "i": r"(?P<tag>[^\[\]]*?)", "e": r"(?P<sqlstate>[0-9A-Z]{5})", "c": r"(?P<session>[0-9a-f]+\.[0-9a-f]+)",
    "l": r"(?P<line>\d+)", "s": r"(?P<sstart>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: [A-Za-z+\-0-9:]+)?)",
    "v": r"(?P<vxid>[0-9/\-]*)", "x": r"(?P<txid>\d*)", "Q": r"(?P<queryid>-?\d*)",
}
_SEVERITY = r"(?P<sev>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG[1-5]?|STATEMENT|DETAIL|HINT|CONTEXT|QUERY|LOCATION):\s+(?P<msg>.*)$"
_RE_RECEIVED = re.compile(r"^connection received: host=(?P<host>\S+)(?: port=(?P<port>\d+))?")
_RE_AUTHORIZED = re.compile(r"^(?P<repl>replication )?connection authorized: user=(?P<user>\S+)(?: database=(?P<db>\S+))?"
                            r"(?: application_name=(?P<app>\S+))?")
_RE_DISCONNECT = re.compile(r"^disconnection: session time: \S+ user=(?P<user>\S+) database=(?P<db>\S+) host=(?P<host>\S+)")
_RE_AUTHFAIL = re.compile(r'^password authentication failed for user "(?P<user>[^"]*)"')
_RE_STATEMENT = re.compile(r"^(?:duration: [\d.]+ ms\s+)?(?:statement|execute [^:]*):\s?(?P<sql>.*)$", re.S)
_RE_PARAM = re.compile(r'^parameter "(?P<name>pgaudit\.log|log_statement)" changed to "(?P<value>[^"]*)"')
_DUMP_APPS = {"pg_dump", "pg_dumpall", "pg_basebackup"}


def compile_prefix(prefix: str) -> re.Pattern:
    """Regex for one stderr line from the server's ``log_line_prefix`` (padding such as ``%-10u`` allowed)."""
    out, i, optional_from = [], 0, None
    while i < len(prefix):
        c = prefix[i]
        if c == "%" and i + 1 < len(prefix):
            j = i + 1
            while j < len(prefix) and (prefix[j] == "-" or prefix[j].isdigit()):
                j += 1
            padded = j > i + 1
            e = prefix[j] if j < len(prefix) else ""
            i = j + 1
            if e == "%":
                out.append("%")
            elif e == "q":
                optional_from = len(out)
            elif e in _PREFIX_ESCAPES:
                pat = _PREFIX_ESCAPES[e]
                name = re.search(r"\?P<(\w+)>", pat)
                if name and any(f"?P<{name.group(1)}>" in p for p in out):
                    pat = re.sub(r"\?P<\w+>", "?:", pat)
                out.append(rf"\s*{pat}\s*" if padded else pat)
            else:
                out.append(".*?")
            continue
        out.append(re.escape(c))
        i += 1
    if optional_from is not None:
        out = out[:optional_from] + ["(?:" + "".join(out[optional_from:]) + ")?"]
    return re.compile("^" + "".join(out) + _SEVERITY, re.S)


class _Sessions:
    """Per-backend state from connection lines, keyed by pid (exact while the backend lives; log order)."""

    def __init__(self):
        self.by_pid: dict[str, dict] = {}
        self.counter = 0

    def received(self, pid, host):
        self.counter += 1
        self.by_pid[pid] = {"remote": host, "sid": f"pid{pid}.{self.counter}"}

    def get(self, pid):
        return self.by_pid.get(pid) if pid else None


def _handle(ctx: ParseContext, rec: dict, sev: str, msg: str, *, db: str | None, sessions: _Sessions | None,
            pid: str | None, log_rows: bool) -> None:
    sev = (sev or "").upper()
    rec["event_code"] = rec.get("event_code") or sev or None
    if sev in ("ERROR", "FATAL", "PANIC"):
        rec["outcome"] = "failure"
    m = _RE_RECEIVED.match(msg)
    if m:
        rec.update(operation="connection_received", observation_type="connection")
        rec["remote_ip"] = rec.get("remote_ip") or clean_ip(m.group("host"))
        if sessions is not None and pid:
            sessions.received(pid, rec["remote_ip"])
        return
    m = _RE_AUTHORIZED.match(msg)
    if m:
        rec.update(operation="replication_connection" if m.group("repl") else "connection_authorized",
                   observation_type="login_success", outcome="success")
        rec["account"] = rec.get("account") or m.group("user")
        rec["database"] = rec.get("database") or m.group("db")
        if m.group("app"):
            rec["application"] = rec.get("application") or m.group("app")
        if sessions is not None and pid:
            st = sessions.by_pid.setdefault(pid, {"sid": f"pid{pid}.{sessions.counter + 1}"})
            st.update(user=rec["account"], db=rec["database"], app=rec.get("application"))
        if (rec.get("application") or "").lower() in _DUMP_APPS or m.group("repl"):
            rec["flags"] = sorted(set(rec.get("flags") or []) | {"dump_tool_session"})
        return
    m = _RE_DISCONNECT.match(msg)
    if m:
        rec.update(operation="disconnection", observation_type="logoff")
        rec["account"] = rec.get("account") or m.group("user")
        rec["database"] = rec.get("database") or m.group("db")
        if sessions is not None and pid:
            sessions.by_pid.pop(pid, None)
        return
    m = _RE_AUTHFAIL.match(msg)
    if m:
        rec.update(operation="password_authentication_failed", observation_type="login_failure", outcome="failure")
        rec["account"] = rec.get("account") or m.group("user")
        return
    m = _RE_PARAM.match(msg)
    if m:
        off = m.group("value").strip().lower() in ("none", "")
        rec.update(operation=f"set_{m.group('name').replace('.', '_')}",
                   observation_type="auditing_disabled" if off else "auditing_enabled")
        return
    if msg.startswith("AUDIT: "):
        _audit(ctx, rec, msg[7:], db=db, log_rows=log_rows)
        return
    m = _RE_STATEMENT.match(msg)
    if m and sev in ("LOG", "STATEMENT"):
        if sev == "STATEMENT":
            rec["outcome"] = "failure"
            rec["flags"] = sorted(set(rec.get("flags") or []) | {"statement_of_failed_command"})
        apply_sql(rec, m.group("sql"), ctx, database=db, default_schema="public")
        if (rec.get("application") or "").lower() in _DUMP_APPS and rec.get("observation_type") == "select":
            rec["flags"] = sorted(set(rec.get("flags") or []) | {"dump_tool_session"})
        return
    rec.update(operation=f"message_{sev.lower() or 'unknown'}", observation_type="other")


def _audit(ctx: ParseContext, rec: dict, payload: str, *, db: str | None, log_rows: bool) -> None:
    try:
        fields = next(csv.reader(io.StringIO(payload)))
    except (csv.Error, StopIteration):
        fields = []
    if len(fields) < 7:
        rec.update(operation="pgaudit_unparsed", observation_type="other")
        rec["flags"] = ["pgaudit_unparsed"]
        return
    audit_type, cls, command, obj_type, obj_name = fields[0], fields[3].upper(), fields[4], fields[5], fields[6]
    rest = fields[7:]
    rows = None
    if log_rows and rest:
        rows = to_int(rest[0])
        rest = rest[1:]
    statement = rest[0] if rest else ""
    rec["operation"] = command.lower().replace(" ", "_") or "unknown"
    rec["event_code"] = f"pgaudit:{audit_type}:{cls}"
    rec["rows"] = rows
    obs = {"READ": "select", "WRITE": "modify", "ROLE": "privilege_change", "DDL": "ddl",
           "FUNCTION": "execute", "MISC": "other", "MISC_SET": "other"}.get(cls, "other")
    rec["observation_type"] = obs
    if obj_name:
        from ..sqlops import qualify

        rec["objects"] = [qualify(obj_name, db, "public")]
    if statement and statement not in ("<not logged>", "<previously logged>"):
        before = obs
        apply_sql(rec, statement, ctx, database=db, default_schema="public")
        if rec["observation_type"] in ("other", "ddl") and before not in ("other", "ddl"):
            rec["observation_type"] = before
        if cls == "ROLE" and rec["observation_type"] not in ("privilege_change", "account_change", "privilege_revoke"):
            rec["observation_type"] = "privilege_change"
    if cls == "READ" and rec["observation_type"] == "bulk_import":
        rec["observation_type"] = "select"
    rec["flags"] = sorted(set(rec.get("flags") or []) | {"pgaudit"})
    if obj_type:
        rec["flags"] = sorted(set(rec["flags"]) | {f"object_type:{obj_type.lower().replace(' ', '_')}"})


def _remote(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if v.startswith("[") or v.count(":") > 1 and "(" not in v:
        return clean_ip(v.split("]")[0].strip("["))
    v = re.sub(r"\(\d+\)$", "", v)
    if v.count(":") == 1:
        v = v.split(":")[0]
    return clean_ip(v)


def _parse_csvlog(ctx, stream, relname, log_rows):
    reader = csv.reader(text_stream(stream))
    for row in reader:
        if not row:
            continue
        n = reader.line_num
        loc = f"{relname}:{n}"
        if len(row) < 23:
            ctx.fail(loc, f"csvlog row has {len(row)} columns (expected 23-26)")
            continue
        d = dict(zip(CSV_COLUMNS, row, strict=False))
        ts, prec, abbr = parse_iso(d["log_time"])
        if ts is None:
            ctx.fail(loc, "unparseable log_time")
            continue
        db = blank(d["database_name"])
        rec = {"_raw": "\x1f".join(row), "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host,
               "account": blank(d["user_name"]), "database": db, "session_id": blank(d["session_id"]),
               "remote_ip": _remote(blank(d["connection_from"])), "application": blank(d["application_name"]),
               "event_code": blank(d["sql_state_code"]), "outcome": "success", "flags": []}
        _handle(ctx, rec, d["error_severity"], d["message"] or "", db=db, sessions=None, pid=None, log_rows=log_rows)
        yield rec


def _parse_jsonlog(ctx, stream, relname, log_rows):
    for n, line in enumerate(text_stream(stream), 1):
        line = line.strip()
        if not line:
            continue
        loc = f"{relname}:{n}"
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            ctx.fail(loc, "not a JSON object")
            continue
        if not isinstance(d, dict) or "timestamp" not in d:
            ctx.fail(loc, "jsonlog record without timestamp")
            continue
        ts, prec, abbr = parse_iso(str(d["timestamp"]))
        if ts is None:
            ctx.fail(loc, "unparseable timestamp")
            continue
        db = blank(d.get("dbname"))
        rec = {"_raw": line, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host,
               "account": blank(d.get("user")), "database": db, "session_id": blank(d.get("session_id")),
               "remote_ip": clean_ip(blank(d.get("remote_host"))), "application": blank(d.get("application_name")),
               "event_code": blank(d.get("state_code")), "outcome": "success", "flags": []}
        msg = d.get("message") or ""
        if not msg.startswith(("statement:", "AUDIT:", "execute ", "duration:")) and d.get("statement") \
                and str(d.get("error_severity", "")).upper() in ("ERROR", "FATAL"):
            rec["flags"] = ["error_with_statement"]
        _handle(ctx, rec, str(d.get("error_severity") or ""), msg, db=db, sessions=None, pid=None, log_rows=log_rows)
        yield rec


def _parse_stderr(ctx, stream, relname, log_rows):
    rx = compile_prefix(ctx.options["log_line_prefix"])
    sessions = _Sessions()
    pending = None

    def finish(p):
        g, raw, loc = p
        sev, msg = g["sev"], g["msg"]
        if g.get("ts"):
            ts, prec, abbr = parse_iso(g["ts"])
        elif g.get("epoch"):
            ts, prec = parse_epoch(g["epoch"])
            abbr = None
        else:
            ts, prec, abbr = None, "unknown", None
        if ts is None:
            ctx.fail(loc, "no parseable timestamp in log_line_prefix")
            return None
        pid = g.get("pid")
        st = sessions.get(pid) or {}
        user = blank(g.get("user")) or st.get("user")
        if user == "[unknown]":
            user = None
        db = blank(g.get("db")) or st.get("db")
        if db == "[unknown]":
            db = None
        sid = blank(g.get("session")) or (st.get("sid") if st else None)
        rec = {"_raw": raw, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host, "account": user,
               "database": db, "session_id": sid, "remote_ip": _remote(g.get("remote")) or st.get("remote"),
               "application": blank(g.get("app")) or st.get("app"), "event_code": blank(g.get("sqlstate")),
               "outcome": "success", "flags": [] if g.get("session") or not st else ["session_from_pid_tracking"]}
        if not g.get("session") and not st:
            rec["session_id"] = None
        _handle(ctx, rec, sev, msg, db=db, sessions=sessions, pid=pid, log_rows=log_rows)
        if rec.get("operation") == "connection_received" and not g.get("session"):
            rec["session_id"] = sessions.get(pid)["sid"] if sessions.get(pid) else None
        return rec

    for n, line in enumerate(text_stream(stream), 1):
        line = line.rstrip("\r\n")
        m = rx.match(line)
        if m:
            if pending is not None:
                r = finish(pending)
                if r is not None:
                    yield r
            pending = (m.groupdict(), line, f"{relname}:{n}")
        elif pending is not None and (line.startswith(("\t", " ")) or not line):
            g, raw, loc = pending
            g = dict(g)
            g["msg"] = g["msg"] + "\n" + line.strip()
            pending = (g, raw + "\n" + line, loc)
        elif line.strip():
            ctx.fail(f"{relname}:{n}", "line does not match log_line_prefix")
    if pending is not None:
        r = finish(pending)
        if r is not None:
            yield r


def parse(ctx: ParseContext, stream, relname: str):
    log_rows = bool(ctx.options.get("pgaudit_log_rows"))
    if ctx.fmt == "csvlog":
        yield from _parse_csvlog(ctx, stream, relname, log_rows)
    elif ctx.fmt == "jsonlog":
        yield from _parse_jsonlog(ctx, stream, relname, log_rows)
    else:
        yield from _parse_stderr(ctx, stream, relname, log_rows)
