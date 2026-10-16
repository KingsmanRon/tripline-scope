"""Shared parser plumbing: parse context, text decoding, record helpers and safe value reduction.

Parsers are generators ``parse(ctx, stream, relname)`` yielding record dicts whose keys are event-schema
columns plus three private keys:

* ``_raw`` -- the record's original text (or canonical JSON for structured records), hashed into
  ``raw_sha256`` and then discarded;
* ``_loc`` -- a locator for forensic hand-off (``file:line`` or ``file#record``);
* ``_ts`` -- ``(datetime-or-None, precision, zone-abbreviation-or-None)``.

Parsers must not put statements, query strings, command lines, passwords, tokens or free-text messages in any
column. SQL goes through :func:`apply_sql`; URLs through :func:`safe_url_path`; file paths through
:meth:`ParseContext.file_ref`.
"""

from __future__ import annotations

import codecs
import hashlib
import io
import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from tripline_scope.core.canonical import canonical_bytes

from ..sqlops import classify, qualify

MAX_FAILURE_SAMPLES = 50


@dataclass
class ParseContext:
    source_id: str
    family: str
    fmt: str
    host: str | None
    options: dict
    mapping: dict | None
    sql_fp: Callable[[str], str]
    file_fp: Callable[[str], str]
    parser: str = ""
    failures: int = 0
    failure_samples: list[dict] = field(default_factory=list)
    notes: set[str] = field(default_factory=set)
    rejected: list[dict] = field(default_factory=list)   # indicators rejected (id + reason, no values)

    def fail(self, locator: str, reason: str) -> None:
        self.failures += 1
        if len(self.failure_samples) < MAX_FAILURE_SAMPLES:
            self.failure_samples.append({"locator": locator, "reason": reason[:120]})

    def file_ref(self, path: str | None) -> str | None:
        """Opaque reference for a file path: extension + keyed fingerprint (names may contain identifiers)."""
        if not path:
            return None
        p = path.replace("/", "\\").rstrip("\\")
        base = p.rsplit("\\", 1)[-1]
        ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
        ext = ext if re.fullmatch(r"[a-z0-9]{1,8}", ext) else ""
        return f"file:{ext or '-'}:{self.file_fp(p.lower())[:16]}"


# ---------------------------------------------------------------------------------------------- text
def text_stream(stream) -> io.TextIOBase:
    """Decode a binary stream, honouring UTF-8/UTF-16 byte-order marks (PowerShell exports use them)."""
    buffered = stream if isinstance(stream, io.BufferedReader) else io.BufferedReader(stream, 1 << 20)
    head = buffered.peek(4)[:4]
    if head.startswith(codecs.BOM_UTF8):
        enc = "utf-8-sig"
    elif head.startswith(codecs.BOM_UTF16_LE) or head.startswith(codecs.BOM_UTF16_BE):
        enc = "utf-16"
    else:
        enc = "utf-8"
    return io.TextIOWrapper(buffered, encoding=enc, errors="replace", newline="")


def iter_lines(stream) -> Iterator[tuple[int, str]]:
    """(1-based line number, line without terminator)."""
    for n, line in enumerate(text_stream(stream), 1):
        yield n, line.rstrip("\r\n")


def raw_hash(raw) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    elif not isinstance(raw, bytes | bytearray):
        raw = canonical_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------------------------- values
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXRUN = re.compile(r"^[0-9a-fA-F]{16,}$")
_DIGITS = re.compile(r"\d{4,}")
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-+=]{24,}$")


def safe_url_path(url: str | None) -> tuple[str | None, bool]:
    """Path only (no scheme/host/query/fragment/matrix params), identifier-like segments templated.

    Returns (path, query_was_present)."""
    if not url or url == "-":
        return None, False
    u = url.strip()
    had_query = "?" in u or "#" in u
    u = u.split("?", 1)[0].split("#", 1)[0]
    if "://" in u:
        u = "/" + u.split("://", 1)[1].split("/", 1)[-1] if "/" in u.split("://", 1)[1] else "/"
    segs = []
    for seg in u.split("/"):
        seg = seg.split(";", 1)[0]
        if not seg:
            segs.append(seg)
            continue
        if "@" in seg or "%40" in seg.lower():
            segs.append("{email}")
        elif _GUID.match(seg):
            segs.append("{guid}")
        elif _HEXRUN.match(seg):
            segs.append("{hex}")
        elif _TOKENISH.match(seg) and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            segs.append("{token}")
        elif _DIGITS.search(seg):
            segs.append(_DIGITS.sub("{n}", seg))
        else:
            segs.append(seg[:80])
    return "/".join(segs)[:300] or "/", had_query


def clean_ip(value: str | None) -> str | None:
    if value is None:
        return None
    v = str(value).strip().strip("[]")
    if not v or v in ("-", "::1", "0.0.0.0", "::"):  # noqa: S104 - comparing, not binding
        return None if v in ("", "-") else v
    if v.lower().startswith("::ffff:"):
        v = v[7:]
    if v.count(":") == 1 and "." in v:          # host:port
        v = v.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v[:255]


def to_int(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s or s in ("-", "null", "NULL", "None"):
        return None
    try:
        return int(float(s))
    except ValueError:
        return None


def blank(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return None if s in ("", "-", "NULL", "null", "None", "N/A") else s


def apply_sql(rec: dict, sql: str | None, ctx: ParseContext, *, database: str | None,
              default_schema: str | None) -> None:
    """Reduce ``sql`` into operation/observation/objects/fingerprint on ``rec``. The text is not kept."""
    info = classify(sql)
    if info.operation not in ("none",):
        rec.setdefault("operation", info.operation)
        if info.observation_type != "other" or "observation_type" not in rec:
            rec["observation_type"] = info.observation_type
            rec["operation"] = info.operation
    if info.normalised:
        rec["statement_fp"] = ctx.sql_fp(info.normalised)
    objs = list(rec.get("objects") or [])
    assumed = False
    for o in info.objects:
        q = qualify(o, database, default_schema)
        if q.count(".") < 2 and database and default_schema:
            assumed = True
        if len(o.split(".")) == 1 and default_schema:
            assumed = True
        if q not in objs:
            objs.append(q)
    rec["objects"] = objs[:25]
    flags = set(rec.get("flags") or []) | set(info.flags)
    if assumed:
        flags.add("schema_assumed")
    rec["flags"] = sorted(flags)
