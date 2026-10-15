"""Reduce a SQL statement to an operation, object names and a literal-free normalised form.

The statement text never leaves this module: callers store only ``operation``, ``observation_type``,
``objects`` (identifiers that follow FROM/JOIN/INTO/UPDATE/TABLE/COPY/DATABASE...) and a keyed fingerprint of
the normalised form (literals and numbers replaced by ``?``), computed with the case key
(``store.fingerprinter("paths-sql")``). String literals are inspected in exactly two places — the command of
``xp_cmdshell`` (to recognise ``bcp ... out|queryout`` / ``sqlcmd -o`` exports) and the value assigned to
audit settings (``pgaudit.log``/``log_statement``) — and are never returned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<lc>--[^\n]*)
  | (?P<bc>/\*.*?(?:\*/|\Z))
  | (?P<str>[NnEeBbXx]?'(?:[^']|'')*'?)
  | (?P<dollar>\$(?P<tag>[A-Za-z_]\w*)?\$.*?(?:\$(?P=tag)?\$|\Z))
  | (?P<br>\[[^\]]*\]?)
  | (?P<dq>"(?:[^"]|"")*"?)
  | (?P<bt>`[^`]*`?)
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<word>[A-Za-z_#@][\w$#@]*)
  | (?P<p>.)
    """,
    re.S | re.X,
)

_KEYWORDS = {
    "select", "from", "where", "join", "inner", "left", "right", "full", "outer", "cross", "on", "and", "or",
    "not", "in", "is", "null", "as", "into", "insert", "update", "delete", "merge", "values", "set", "group",
    "by", "order", "having", "union", "all", "distinct", "top", "with", "exec", "execute", "backup", "restore",
    "database", "log", "to", "disk", "url", "copy", "grant", "revoke", "deny", "alter", "create", "drop",
    "table", "truncate", "bulk", "limit", "offset", "case", "when", "then", "else", "end", "like", "between",
    "exists", "apply", "using", "returning", "stdout", "stdin", "program", "csv", "header", "format", "server",
    "audit", "specification", "state", "role", "member", "add", "login", "user", "system", "nolock", "option",
    "fetch", "next", "rows", "only", "over", "partition", "asc", "desc", "for", "xml", "json", "path", "if",
    "begin", "commit", "rollback", "transaction", "tran", "declare", "openrowset", "opendatasource", "lateral",
    "tablesample", "superuser", "replication", "bypassrls", "public", "schema", "view", "procedure",
}
_NAME_STOP = _KEYWORDS - {"public", "user", "log", "path", "state", "role", "server", "system", "audit"}
_JOIN_NAME_KW = {"from", "join", "update", "into", "table", "using"}


@dataclass
class SqlInfo:
    operation: str
    observation_type: str
    objects: list[str] = field(default_factory=list)
    normalised: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass
class _Tok:
    kind: str
    value: str          # literal content is kept only in-process for the two documented checks

    @property
    def low(self) -> str:
        return self.value.lower() if self.kind == "word" else ""


def _tokens(sql: str) -> list[_Tok]:
    out: list[_Tok] = []
    for m in _TOKEN.finditer(sql):
        kind = m.lastgroup
        if kind in ("ws", "lc", "bc"):
            continue
        v = m.group(0)
        if kind == "tag":  # pragma: no cover - named sub-group never last
            continue
        if kind == "str":
            body = v[1:] if v[0] in "NnEeBbXx" and len(v) > 1 and v[1] == "'" else v
            out.append(_Tok("str", body.strip("'").replace("''", "'")))
        elif kind == "dollar":
            out.append(_Tok("str", ""))
        elif kind in ("br", "dq", "bt"):
            out.append(_Tok("ident", v.strip('[]"`').replace('""', '"')))
        elif kind == "num":
            out.append(_Tok("num", v))
        elif kind == "word":
            out.append(_Tok("word", v))
        else:
            out.append(_Tok("p", v))
    return out


def _split_statements(toks: list[_Tok]) -> list[list[_Tok]]:
    stmts, cur, depth = [], [], 0
    for t in toks:
        if t.kind == "p" and t.value == "(":
            depth += 1
        elif t.kind == "p" and t.value == ")":
            depth = max(0, depth - 1)
        if t.kind == "p" and t.value == ";" and depth == 0:
            if cur:
                stmts.append(cur)
            cur = []
            continue
        if t.kind == "word" and t.low == "go" and depth == 0:
            if cur:
                stmts.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        stmts.append(cur)
    return stmts


def _normalised(toks: list[_Tok]) -> str:
    parts = []
    for t in toks:
        if t.kind in ("str", "num"):
            parts.append("?")
        elif t.kind == "word":
            parts.append(t.value.upper() if t.low in _KEYWORDS else t.value.lower())
        elif t.kind == "ident":
            parts.append(t.value.lower())
        else:
            parts.append(t.value)
    text = " ".join(parts)
    text = re.sub(r"\?(?:\s*,\s*\?)+", "?", text)  # IN (?, ?, ?) -> IN (?)
    return text


def _read_name(toks: list[_Tok], i: int) -> tuple[str | None, int]:
    """Qualified name starting at ``i`` (``a.b.c``, ``[a].[b]``, ``"a"."b"``). Returns (name, next index)."""
    parts: list[str] = []
    j = i
    while j < len(toks):
        t = toks[j]
        if t.kind in ("word", "ident") and not (t.kind == "word" and t.low in _NAME_STOP and not parts):
            parts.append(t.value)
            j += 1
            if j < len(toks) and toks[j].kind == "p" and toks[j].value == ".":
                j += 1
                # tolerate empty parts: db..table
                while j < len(toks) and toks[j].kind == "p" and toks[j].value == ".":
                    parts.append("")
                    j += 1
                continue
            break
        break
    parts = [p for p in parts if p != ""] if parts else parts
    if not parts:
        return None, i
    return ".".join(parts), j


def _skip_alias(toks: list[_Tok], j: int) -> int:
    if j < len(toks) and toks[j].kind == "word" and toks[j].low == "as":
        j += 1
        if j < len(toks) and toks[j].kind in ("word", "ident"):
            j += 1
        return j
    if j < len(toks) and (toks[j].kind == "ident" or (toks[j].kind == "word" and toks[j].low not in _KEYWORDS)):
        return j + 1
    return j


def _objects(toks: list[_Tok], cte_names: set[str]) -> tuple[list[str], list[str]]:
    objs: list[str] = []
    flags: list[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind == "word" and t.low in _JOIN_NAME_KW:
            j = i + 1
            if t.low == "delete" or (j < len(toks) and toks[j].kind == "word" and toks[j].low in ("only", "table")):
                j += 1
            while True:
                if j < len(toks) and toks[j].kind == "p" and toks[j].value == "(":
                    break
                if j < len(toks) and toks[j].low in ("openrowset", "opendatasource", "openquery"):
                    flags.append(toks[j].low)
                    break
                name, k = _read_name(toks, j)
                if not name:
                    break
                if k < len(toks) and toks[k].kind == "p" and toks[k].value == "(":
                    if name.lower() in ("openrowset", "opendatasource", "openquery"):
                        flags.append(name.lower())
                    break  # table-valued function, not a table
                base = name.split(".")[-1]
                if not base.startswith(("#", "@")) and name.lower() not in cte_names:
                    objs.append(name)
                elif base.startswith("#"):
                    flags.append("temp_table")
                j = _skip_alias(toks, k)
                if t.low == "from" and j < len(toks) and toks[j].kind == "p" and toks[j].value == ",":
                    j += 1
                    continue
                break
            i = max(j, i + 1)
            continue
        i += 1
    return objs, flags


def _cte_names(toks: list[_Tok]) -> set[str]:
    names = set()
    if toks and toks[0].low == "with":
        for a, b in zip(toks, toks[1:], strict=False):
            if a.kind in ("word", "ident") and b.kind == "word" and b.low == "as":
                names.add(a.value.lower())
    return names


def _setting(toks: list[_Tok], start: int) -> tuple[str, str]:
    """(setting name, assigned value) for ``SET a.b = 'v'`` / ``SET a.b TO v`` (configuration values only)."""
    parts, k = [], start
    while k < len(toks) and not (toks[k].kind == "p" and toks[k].value == "=") and toks[k].low != "to":
        if toks[k].kind in ("word", "ident"):
            parts.append(toks[k].value.lower())
        k += 1
    value = toks[k + 1].value.lower().strip() if k + 1 < len(toks) and toks[k + 1].kind in ("str", "word") else ""
    return ".".join(parts), value


def _main_verb(toks: list[_Tok]) -> tuple[str, int]:
    if not toks:
        return "", 0
    first = toks[0].low
    if first != "with":
        return first, 0
    depth = 0
    for idx, t in enumerate(toks):
        if t.kind == "p" and t.value == "(":
            depth += 1
        elif t.kind == "p" and t.value == ")":
            depth -= 1
        elif depth == 0 and t.low in ("select", "insert", "update", "delete", "merge"):
            return t.low, idx
    return "with", 0


_PRIORITY = ["auditing_disabled", "dump_export", "select_into", "privilege_change", "account_change",
             "bulk_import", "modify", "select", "execute", "auditing_enabled", "privilege_revoke", "ddl", "other"]


def _classify_one(toks: list[_Tok]) -> SqlInfo:
    words = [t.low for t in toks if t.kind == "word"]
    verb, vi = _main_verb(toks)
    cte = _cte_names(toks)
    objs, flags = _objects(toks, cte)
    wset = set(words)
    op, obs = verb or "unknown", "other"

    if verb == "select":
        obs = "select"
        depth = 0
        for k in range(vi, len(toks)):
            t = toks[k]
            if t.kind == "p" and t.value == "(":
                depth += 1
            elif t.kind == "p" and t.value == ")":
                depth -= 1
            elif depth == 0 and t.low == "into":
                nxt = toks[k + 1] if k + 1 < len(toks) else None
                if nxt is not None and nxt.low in ("outfile", "dumpfile"):
                    op, obs = "select_into_outfile", "dump_export"
                elif nxt is not None and nxt.kind in ("word", "ident") and not nxt.value.startswith(("#", "@")):
                    op, obs = "select_into", "select_into"
                break
            elif depth == 0 and t.low == "from":
                break
    elif verb in ("insert", "update", "delete", "merge"):
        obs = "modify"
        if verb == "insert" and ("openrowset" in flags or "opendatasource" in flags):
            op, obs = "export_to_file", "dump_export"
        elif verb == "insert" and "select" in wset:
            flags.append("insert_from_select")
    elif verb == "truncate":
        obs = "modify"
    elif verb == "bulk" and "insert" in wset:
        op, obs = "bulk_insert", "bulk_import"
    elif verb == "backup":
        kind = words[1] if len(words) > 1 else ""
        op = "backup_log" if kind == "log" else "backup_database"
        obs = "dump_export"
        if len(toks) > 2:
            name, _ = _read_name(toks, 2)
            if name:
                objs = [name]
        for a, b in zip(words, words[1:], strict=False):
            if a == "to" and b == "url":
                flags.append("backup_to_url")
    elif verb == "restore":
        op, obs = "restore", "other"
    elif verb == "copy":
        to_idx, depth = None, 0
        for k, t in enumerate(toks):
            if t.kind == "p" and t.value == "(":
                depth += 1
            elif t.kind == "p" and t.value == ")":
                depth -= 1
            elif depth == 0 and k > 0 and t.low in ("to", "from"):
                to_idx = k
                break
        direction = toks[to_idx].low if to_idx is not None else ""
        if direction == "to":
            nxt = toks[to_idx + 1] if to_idx + 1 < len(toks) else None
            dest = "stdout" if nxt is not None and nxt.low == "stdout" else (
                "program" if nxt is not None and nxt.low == "program" else "file")
            op, obs = f"copy_to_{dest}", "dump_export"
            if len(toks) > 1 and toks[1].kind in ("word", "ident"):
                name, _ = _read_name(toks, 1)
                if name and name.lower() not in objs:
                    objs.insert(0, name)
        elif direction == "from":
            op, obs = "copy_from", "bulk_import"
            name, _ = _read_name(toks, 1)
            objs = [name] if name else objs
    elif verb in ("exec", "execute"):
        name, k = _read_name(toks, 1)
        proc = (name or "").lower().split(".")[-1]
        op, obs = "execute", "execute"
        if proc == "xp_cmdshell":
            op = "xp_cmdshell"
            flags.append("xp_cmdshell")
            raw_cmd = " ".join(t.value for t in toks[k:] if t.kind == "str")
            cmd = raw_cmd.lower()
            if re.search(r"\bbcp(?:\.exe)?\b", cmd) and re.search(r"\b(?:out|queryout)\b", cmd):
                op, obs = "bcp_export", "dump_export"
                q = re.search(r"\bbcp(?:\.exe)?\s+\"(.+?)\"\s+queryout\b", raw_cmd, re.I | re.S)
                if q:
                    objs = classify(q.group(1)).objects or objs
                else:
                    t = re.search(r"\bbcp(?:\.exe)?\s+([\w\[\]\.]+)\s+out\b", raw_cmd, re.I)
                    objs = [t.group(1).replace("[", "").replace("]", "")] if t else objs
            elif re.search(r"\bsqlcmd(?:\.exe)?\b", cmd) and re.search(r"\s-o\s", cmd):
                op, obs = "sqlcmd_export", "dump_export"
        elif proc in ("sp_addrolemember", "sp_addsrvrolemember", "sp_grantdbaccess", "sp_grantlogin"):
            op, obs = proc, "privilege_change"
        elif proc in ("sp_addlogin", "sp_adduser"):
            op, obs = proc, "account_change"
        elif proc in ("sp_configure",):
            op, obs = proc, "other"
            setting = next((t.value.lower() for t in toks[k:] if t.kind == "str"), "")
            if setting in ("xp_cmdshell", "ole automation procedures"):
                flags.append("dangerous_option_change")
        elif name:
            objs = [name] + [o for o in objs if o != name]
    elif verb == "grant":
        op, obs = "grant", "privilege_change"
        on = next((k for k, t in enumerate(toks) if t.low == "on"), None)
        if on is not None:
            k = on + 1
            if k < len(toks) and toks[k].low in ("object", "schema", "database", "table") and k + 1 < len(toks) \
                    and toks[k + 1].kind == "p" and toks[k + 1].value == ":":
                k += 3
            elif k < len(toks) and toks[k].low in ("table", "all") and k + 1 < len(toks) and toks[k + 1].kind != "p":
                k += 1
                if toks[k - 1].low == "all":
                    k += 2
            name, _ = _read_name(toks, k)
            objs = [name] if name else []
        else:
            objs = []
    elif verb in ("revoke", "deny"):
        op, obs, objs = verb, "privilege_revoke", []
    elif verb == "set" and len(toks) > 1:
        setting, value = _setting(toks, 1)
        if setting.startswith(("pgaudit.log", "log_statement")):
            op = "set_audit_setting"
            obs = "auditing_disabled" if value == "none" else "auditing_enabled"
        else:
            op, obs = "set", "other"
        objs = []
    elif verb in ("alter", "drop", "create"):
        objs_kw = words[1:4]
        if "audit" in objs_kw:
            op = f"{verb}_audit"
            if verb == "drop":
                obs = "auditing_disabled"
            else:
                state = None
                for k, t in enumerate(toks):
                    if t.low == "state":
                        rest = [x for x in toks[k + 1:k + 4] if x.kind == "word"]
                        if rest:
                            state = rest[0].low
                obs = {"off": "auditing_disabled", "on": "auditing_enabled"}.get(state or "", "ddl")
            objs = []
        elif verb == "alter" and len(words) > 1 and words[1] == "system":
            setting, value = _setting(toks, 3)
            op = "alter_system"
            if setting.startswith(("pgaudit.log", "log_statement")):
                obs = "auditing_disabled" if value == "none" else "auditing_enabled"
            else:
                obs = "ddl"
            objs = []
        elif verb == "alter" and "role" in objs_kw and ("member" in wset or "superuser" in wset
                                                       or "bypassrls" in wset or "createrole" in wset):
            op, obs, objs = "role_membership_or_attribute", "privilege_change", []
        elif verb == "alter" and "user" in objs_kw and "superuser" in wset:
            op, obs, objs = "user_superuser", "privilege_change", []
        elif verb == "create" and ({"login", "user", "role"} & set(objs_kw)):
            op, obs, objs = "create_principal", "account_change", []
        elif verb == "alter" and ({"login", "user"} & set(objs_kw)):
            op, obs, objs = "alter_principal", "account_change", []
        else:
            op, obs = f"{verb}_{words[1] if len(words) > 1 else 'object'}", "ddl"
            objs = objs[:1]
    elif verb == "with":
        op, obs = "with", "other"
    if obs in ("select", "modify", "execute") and not objs:
        flags.append("no_objects")
    return SqlInfo(op, obs, objs, _normalised(toks), sorted(set(flags)))


def classify(sql: str | None) -> SqlInfo:
    """Classify a statement or batch. Never raises; returns operation ``unparsed`` on failure."""
    if not sql or not sql.strip():
        return SqlInfo("none", "other")
    try:
        toks = _tokens(sql[:200_000])
        stmts = _split_statements(toks)
        if not stmts:
            return SqlInfo("none", "other")
        infos = [_classify_one(s) for s in stmts[:200]]
    except Exception:  # noqa: BLE001 - a hostile statement must not stop ingest
        return SqlInfo("unparsed", "other", [], "", ["unparsed"])
    best = min(infos, key=lambda x: _PRIORITY.index(x.observation_type) if x.observation_type in _PRIORITY else 99)
    objs: list[str] = []
    for x in infos:
        for o in x.objects:
            if o not in objs:
                objs.append(o)
    flags = sorted({f for x in infos for f in x.flags})
    if len(infos) > 1:
        flags.append("batch")
    return SqlInfo(best.operation, best.observation_type, objs[:25], " ; ".join(x.normalised for x in infos), flags)


def qualify(name: str, database: str | None = None, default_schema: str | None = None) -> str:
    """``db.schema.table`` from a 1-3 part name, filling database/schema when known (case preserved)."""
    parts = [p for p in name.replace("[", "").replace("]", "").replace('"', "").split(".") if p]
    if len(parts) >= 3:
        return ".".join(parts[-3:])
    if len(parts) == 2:
        return f"{database}.{parts[0]}.{parts[1]}" if database else ".".join(parts)
    if len(parts) == 1:
        if database and default_schema:
            return f"{database}.{default_schema}.{parts[0]}"
        return parts[0]
    return name
