"""Execute a plain-format (SQL text) PostgreSQL dump without ``psql``.

``psql`` honours client-side meta-commands (``\\!`` runs a shell, ``\\o``/``\\w``/``\\copy ... to`` write files), so
a crafted dump could act on this host. Instead the dump is split into statements by a small lexer that
understands quotes, ``E''`` strings, dollar quoting, quoted identifiers, comments and ``COPY ... FROM stdin``
data blocks, and each statement is sent through pg8000 to the case-specific database:

* ``\\restrict`` / ``\\unrestrict`` (pg_dump >= 16.10) and ``\\connect`` lines are skipped; any other meta-command
  refuses the dump;
* ownership, privilege, role-switching and database-level statements are skipped (as ``pg_restore
  --no-owner --no-privileges``); ``COPY`` to or from programs or server files is refused;
* failing statements are counted (their messages, which may quote data, are never shown or stored).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from tripline_scope.core.errors import ConfigError

_IDENT = re.compile(r"[A-Za-z0-9_$\x80-￿]")
_DOLLAR = re.compile(r"\$([A-Za-z_\x80-￿][A-Za-z0-9_\x80-￿]*)?\$")
_COPY_STDIN = re.compile(r"^\s*COPY\s+.+\s+FROM\s+stdin\b", re.I | re.S)
_COPY_ANY = re.compile(r"^\s*COPY\b", re.I)
_SKIP = [
    re.compile(r"^\s*(CREATE|ALTER|DROP)\s+DATABASE\b", re.I),
    re.compile(r"^\s*ALTER\s+.+\s+OWNER\s+TO\s", re.I | re.S),
    re.compile(r"^\s*(GRANT|REVOKE)\s", re.I),
    re.compile(r"^\s*SET\s+(SESSION\s+AUTHORIZATION|ROLE)\b", re.I),
    re.compile(r"^\s*RESET\s+(SESSION\s+AUTHORIZATION|ROLE)\b", re.I),
    re.compile(r"^\s*COMMENT\s+ON\s+(EXTENSION|DATABASE)\b", re.I),
    re.compile(r"^\s*SECURITY\s+LABEL\b", re.I),
    re.compile(r"^\s*(CREATE|ALTER)\s+(PUBLICATION|SUBSCRIPTION)\b", re.I),
]
_ALLOWED_META = ("\\connect", "\\restrict", "\\unrestrict")


def _strip_comments(sql: str) -> str:
    return re.sub(r"^(\s*(--[^\n]*\n|/\*.*?\*/))*\s*", "", sql, flags=re.S)


class PlainDump:
    """Statement iterator over a text stream (lines read lazily; never the whole file in memory)."""

    def __init__(self, lines: Iterator[str], max_statement_bytes: int = 64 * 1024 * 1024):
        self._lines = iter(lines)
        self._max = max_statement_bytes
        self.skipped = 0
        self.meta_skipped = 0
        self.line_no = 0
        self.std_strings = True

    def _next_line(self) -> str | None:
        try:
            line = next(self._lines)
        except StopIteration:
            return None
        self.line_no += 1
        return line

    def copy_data(self) -> CopyData:
        return CopyData(self)

    def statements(self) -> Iterator[tuple[str, str]]:
        """Yield ``(kind, sql)`` with kind ``sql`` or ``copy``. After a ``copy`` item the caller must consume
        (or :meth:`CopyData.drain`) :meth:`copy_data` before asking for the next statement."""
        buf: list[str] = []
        size = 0
        state = "normal"
        esc = False
        tag = ""
        depth = 0
        has_code = False
        while True:
            line = self._next_line()
            if line is None:
                if has_code:
                    raise ConfigError("plain dump ends inside an unterminated statement")
                return
            if state == "normal" and not has_code and line.lstrip().startswith("\\"):
                word = line.strip().split()[0] if line.strip() else ""
                if word in _ALLOWED_META:
                    self.meta_skipped += 1
                    buf, size = [], 0
                    continue
                raise ConfigError(f"plain dump contains a client meta-command at line {self.line_no}; refused "
                                  "(only pg_dump output is accepted)")
            i, n = 0, len(line)
            start = 0
            while i < n:
                ch = line[i]
                if state == "normal":
                    if ch == "-" and line.startswith("--", i):
                        break
                    if ch == "/" and line.startswith("/*", i):
                        state, depth = "block", 1
                        i += 2
                        continue
                    if ch == "'":
                        prev = line[i - 1] if i > 0 else ""
                        prev2 = line[i - 2] if i > 1 else ""
                        esc = (prev != "" and prev in "Ee" and not _IDENT.match(prev2 or " ")) or not self.std_strings
                        state = "squote"
                    elif ch == '"':
                        state = "dquote"
                        has_code = True
                    elif ch == "$" and not (i > 0 and _IDENT.match(line[i - 1])):
                        m = _DOLLAR.match(line, i)
                        if m:
                            tag = m.group(0)
                            state = "dollar"
                            has_code = True
                            i += len(tag)
                            continue
                        has_code = True
                    elif ch == ";":
                        buf.append(line[start:i + 1])
                        stmt = "".join(buf)
                        buf, size = [], 0
                        start = i + 1
                        if has_code:
                            has_code = False
                            kind = self._classify(stmt)
                            m = re.match(r"\s*SET\s+standard_conforming_strings\s*=\s*'?(on|off)'?",
                                         _strip_comments(stmt), re.I)
                            if m:
                                self.std_strings = m.group(1).lower() == "on"
                            if kind == "copy":
                                yield kind, stmt
                                break       # data starts on the next line; rest of this line is ignored
                            if kind == "sql":
                                yield kind, stmt
                            else:
                                self.skipped += 1
                        i += 1
                        continue
                    elif ch == "\\":
                        raise ConfigError(f"plain dump has a backslash outside quotes at line {self.line_no}; refused")
                    elif not ch.isspace():
                        has_code = True
                    if state == "squote":
                        has_code = True
                elif state == "squote":
                    if esc and ch == "\\":
                        i += 2
                        continue
                    if ch == "'":
                        if i + 1 < n and line[i + 1] == "'":
                            i += 2
                            continue
                        state = "normal"
                elif state == "dquote":
                    if ch == '"':
                        if i + 1 < n and line[i + 1] == '"':
                            i += 2
                            continue
                        state = "normal"
                elif state == "dollar":
                    if ch == "$" and line.startswith(tag, i):
                        state = "normal"
                        i += len(tag)
                        continue
                elif state == "block":
                    if line.startswith("/*", i):
                        depth += 1
                        i += 2
                        continue
                    if line.startswith("*/", i):
                        depth -= 1
                        i += 2
                        if depth == 0:
                            state = "normal"
                        continue
                i += 1
            else:
                if start < n:
                    buf.append(line[start:])
                    size += n - start
                if size > self._max:
                    raise ConfigError("plain dump statement exceeds the size limit; refused")
                continue
            # loop left by break: either a line comment (keep the line for context) or a COPY statement
            if state == "normal" and not has_code and not buf and line.startswith("--", i):
                continue
            if i < n and line.startswith("--", i):
                buf.append(line[start:i] + "\n")
                continue

    @staticmethod
    def _classify(stmt: str) -> str:
        body = _strip_comments(stmt)
        for rx in _SKIP:
            if rx.match(body):
                return "skip"
        if _COPY_ANY.match(body):
            if re.search(r"\b(PROGRAM)\b", body, re.I) or re.search(r"\bTO\b\s+'", body, re.I) \
                    or re.search(r"\bFROM\b\s+'", body, re.I):
                raise ConfigError("plain dump uses COPY with a program or server file; refused")
            if _COPY_STDIN.match(body):
                return "copy"
            raise ConfigError("plain dump uses an unsupported COPY form; refused")
        return "sql"


class CopyData:
    """Iterable of COPY data chunks up to (not including) the ``\\.`` terminator line."""

    def __init__(self, dump: PlainDump, chunk_lines: int = 2000):
        self._dump = dump
        self._chunk = chunk_lines
        self._done = False
        self.rows = 0

    def __iter__(self) -> Iterator[str]:
        acc: list[str] = []
        while not self._done:
            line = self._dump._next_line()
            if line is None:
                self._done = True
                raise ConfigError("plain dump ends inside COPY data")
            if line.rstrip("\r\n") == "\\.":
                self._done = True
                break
            acc.append(line if line.endswith("\n") else line + "\n")
            self.rows += 1
            if len(acc) >= self._chunk:
                yield "".join(acc)
                acc = []
        if acc:
            yield "".join(acc)

    def drain(self) -> None:
        for _ in self:
            pass


def execute(con, lines: Iterator[str]) -> dict:
    """Run a plain dump on pg8000 native connection ``con`` (autocommit). Returns counts only."""
    dump = PlainDump(lines)
    ok = failed = copied = 0
    for kind, sql in dump.statements():
        if kind == "copy":
            data = dump.copy_data()
            try:
                con.run(sql, stream=data)
                ok += 1
                copied += data.rows
            except Exception:  # noqa: BLE001 - driver messages may quote data; count only
                failed += 1
                _rollback_quietly(con)
            data.drain()
            continue
        try:
            con.run(sql)
            ok += 1
        except Exception:  # noqa: BLE001
            failed += 1
            _rollback_quietly(con)
    return {"statements_ok": ok, "statements_failed": failed, "statements_skipped": dump.skipped,
            "meta_lines_skipped": dump.meta_skipped, "rows_copied": copied}


def _rollback_quietly(con) -> None:
    try:
        con.run("ROLLBACK")
    except Exception:  # noqa: BLE001, S110
        pass
