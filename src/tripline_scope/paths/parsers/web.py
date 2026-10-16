"""Web server access logs.

* IIS W3C extended (``#Fields:`` directive; times are UTC by the W3C/IIS definition). Query strings
  (``cs-uri-query``) are dropped unread; a request id is taken from ``options.request_id_field`` or a field
  such as ``cs(X-Request-ID)``.
* Apache / Nginx ``combined`` and ``common`` formats, or a ``custom`` format given in ``options.log_format``
  using Apache ``%`` directives (``%h %l %u %t "%r" %>s %b %I %O %D %T %v %{Header}i %{VAR}e``) or Nginx
  ``$variables`` (``$remote_addr $remote_user [$time_local] $time_iso8601 "$request" $status $body_bytes_sent
  $bytes_sent $request_length $request_id $http_x_request_id $host ...``). Times carry their own offset.

URL paths are reduced by :func:`safe_url_path` (no query string, identifier-like segments templated). User
agents and referrers are never stored.
"""

from __future__ import annotations

import re

from ..timenorm import parse_clf, parse_iso
from .base import ParseContext, blank, clean_ip, iter_lines, safe_url_path, to_int

VERSION = "1.0"

COMBINED = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"'
COMMON = '%h %l %u %t "%r" %>s %b'
_REQ_HEADERS = {"x-request-id", "request-id", "x-correlation-id"}


def _apache_regex(fmt: str) -> re.Pattern:
    out, i = [], 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%":
            out.append(re.escape(c))
            i += 1
            continue
        m = re.match(r"%[<>]?(?:\{([^}]*)\})?([a-zA-Z%])", fmt[i:])
        if not m:
            out.append(re.escape(c))
            i += 1
            continue
        arg, d = m.group(1), m.group(2)
        i += m.end()
        pat = {
            "h": r"(?P<remote>\S+)", "a": r"(?P<remote2>\S+)", "l": r"\S+", "u": r"(?P<user>\S+)",
            "t": r"\[(?P<clf>[^\]]+)\]", "r": r"(?P<request>.*?)", "s": r"(?P<status>\d{3}|-)",
            "b": r"(?P<bytes>\d+|-)", "B": r"(?P<bytes>\d+)", "O": r"(?P<bytes>\d+|-)", "I": r"(?P<bytes_in>\d+|-)",
            "D": r"\S+", "T": r"\S+", "v": r"(?P<vhost>\S+)", "V": r"(?P<vhost>\S+)", "%": "%",
        }.get(d, r"\S*")
        if d in ("i", "e", "n") and arg:
            key = arg.lower()
            pat = r"(?P<reqid>[^\s\"]*)" if key in _REQ_HEADERS or key == "unique_id" else r".*?"
        out.append(pat)
    return _dedupe(out)


def _nginx_regex(fmt: str) -> re.Pattern:
    out, i = [], 0
    while i < len(fmt):
        m = re.match(r"\$\{?([a-z0-9_]+)\}?", fmt[i:])
        if fmt[i] == "$" and m:
            v = m.group(1)
            i += m.end()
            pat = {
                "remote_addr": r"(?P<remote>\S+)", "remote_user": r"(?P<user>\S+)",
                "time_local": r"(?P<clf>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})",
                "time_iso8601": r"(?P<iso>\S+)", "request": r"(?P<request>.*?)", "status": r"(?P<status>\d{3}|-)",
                "body_bytes_sent": r"(?P<bytes>\d+|-)", "bytes_sent": r"(?P<bytes>\d+|-)",
                "request_length": r"(?P<bytes_in>\d+|-)", "request_id": r"(?P<reqid>[^\s\"]*)",
                "http_x_request_id": r"(?P<reqid>[^\s\"]*)", "host": r"(?P<vhost>\S+)",
                "server_name": r"(?P<vhost>\S+)", "request_method": r"(?P<method>[A-Z]+|-)",
                "request_uri": r"(?P<uri>\S+)", "uri": r"(?P<uri>\S+)",
            }.get(v, r".*?" if v.startswith("http_") else r"\S*")
            out.append(pat)
            continue
        out.append(re.escape(fmt[i]))
        i += 1
    return _dedupe(out)


def _dedupe(parts: list[str]) -> re.Pattern:
    seen, fixed = set(), []
    for p in parts:
        names = re.findall(r"\?P<(\w+)>", p)
        for nm in names:
            if nm in seen:
                p = p.replace(f"?P<{nm}>", "?:")
            seen.add(nm)
        fixed.append(p)
    return re.compile("^" + "".join(fixed) + r"\s*$")


def compile_format(family: str, fmt: str, options: dict) -> re.Pattern:
    if fmt == "combined":
        return _apache_regex(COMBINED)
    if fmt == "common":
        return _apache_regex(COMMON)
    lf = options["log_format"]
    return _nginx_regex(lf) if "$" in lf else _apache_regex(lf)


def _split_request(req: str | None) -> tuple[str | None, str | None, bool]:
    if not req or req == "-":
        return None, None, False
    parts = req.split(" ")
    if len(parts) >= 2 and re.fullmatch(r"[A-Z]{3,10}", parts[0]):
        path, q = safe_url_path(parts[1])
        return parts[0], path, q
    return None, None, False


def _parse_clf_family(ctx: ParseContext, stream, relname: str):
    rx = compile_format(ctx.family, ctx.fmt, ctx.options)
    for n, line in iter_lines(stream):
        if not line.strip():
            continue
        loc = f"{relname}:{n}"
        m = rx.match(line)
        if not m:
            ctx.fail(loc, "line does not match the declared log format")
            continue
        g = m.groupdict()
        if g.get("clf"):
            ts, prec = parse_clf(g["clf"])
            abbr = None
        elif g.get("iso"):
            ts, prec, abbr = parse_iso(g["iso"])
        else:
            ts, prec, abbr = None, "unknown", None
        if ts is None:
            ctx.fail(loc, "unparseable timestamp")
            continue
        method, path, had_q = _split_request(g.get("request"))
        if g.get("uri") and path is None:
            path, had_q = safe_url_path(g["uri"])
        method = method or blank(g.get("method"))
        flags = ["query_stripped"] if had_q else []
        yield {
            "_raw": line, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host,
            "account": blank(g.get("user")), "remote_ip": clean_ip(g.get("remote") or g.get("remote2")),
            "request_id": blank(g.get("reqid")), "method": method, "url_path": path,
            "http_status": to_int(g.get("status")), "bytes": to_int(g.get("bytes")),
            "bytes_received": to_int(g.get("bytes_in")), "domain": blank(g.get("vhost")),
            "operation": (method or "request").lower(), "observation_type": "web_request",
            "outcome": _outcome(to_int(g.get("status"))), "flags": flags,
        }


def _outcome(status: int | None) -> str:
    if status is None:
        return "unknown"
    return "success" if status < 400 else "failure"


def _parse_w3c(ctx: ParseContext, stream, relname: str):
    fields: list[str] | None = None
    req_field = (ctx.options.get("request_id_field") or "").lower() or None
    ip_field = (ctx.options.get("client_ip_field") or "c-ip").lower()
    for n, line in iter_lines(stream):
        loc = f"{relname}:{n}"
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.lower().startswith("#fields:"):
                fields = [f.lower() for f in line.split(":", 1)[1].split()]
            continue
        if fields is None:
            ctx.fail(loc, "data line before #Fields directive")
            continue
        vals = line.split(" ")
        if len(vals) != len(fields):
            ctx.fail(loc, "field count differs from #Fields")
            continue
        d = dict(zip(fields, vals, strict=True))
        ts, prec, abbr = parse_iso(f"{d.get('date', '')} {d.get('time', '')}")
        if ts is None:
            ctx.fail(loc, "unparseable date/time")
            continue
        path, _ = safe_url_path(d.get("cs-uri-stem"))
        q = blank(d.get("cs-uri-query"))
        rid = None
        if req_field:
            rid = blank(d.get(req_field))
        else:
            for k in d:
                if any(h in k for h in _REQ_HEADERS):
                    rid = blank(d[k])
                    break
        status = to_int(d.get("sc-status"))
        user = blank(d.get("cs-username"))
        yield {
            "_raw": line, "_loc": loc, "_ts": (ts, prec, abbr),
            "host": blank(d.get("s-computername")) or ctx.host, "account": user.replace("+", " ") if user else None,
            "remote_ip": clean_ip(d.get(ip_field)), "request_id": rid, "method": blank(d.get("cs-method")),
            "url_path": path, "http_status": status, "bytes": to_int(d.get("sc-bytes")),
            "bytes_received": to_int(d.get("cs-bytes")), "domain": blank(d.get("cs-host")),
            "dest_ip": clean_ip(d.get("s-ip")), "dest_port": to_int(d.get("s-port")),
            "operation": (blank(d.get("cs-method")) or "request").lower(), "observation_type": "web_request",
            "outcome": _outcome(status), "flags": ["query_stripped"] if q else [],
        }


def parse(ctx: ParseContext, stream, relname: str):
    if ctx.family == "iis":
        yield from _parse_w3c(ctx, stream, relname)
    else:
        yield from _parse_clf_family(ctx, stream, relname)
