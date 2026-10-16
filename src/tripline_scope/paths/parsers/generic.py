"""Documented field mappings for VPN, firewall, proxy and other tabular logs (CSV, JSON, JSON Lines, key=value).

``mapping`` in ``logs.yaml``::

    mapping:
      timestamp_format: "%Y-%m-%d %H:%M:%S"   # or iso8601 | epoch_s | epoch_ms | clf
      csv: {delimiter: ",", header: true}      # or columns: [...] when there is no header row
      fields:                                  # event column <- source field (only these are read)
        ts: time
        account: user
        session_id: session
        remote_ip: public_ip
        assigned_ip: tunnel_ip
        request_id: auth_ref                   # e.g. the identity provider request id that authorised the VPN
        bytes: bytes_out                       # bytes leaving the hospital side
        bytes_received: bytes_in
        operation: event
      operation_map: {"session-start": vpn_connect, "session-end": vpn_disconnect}
      observation_map: {vpn_connect: vpn_connect, vpn_disconnect: vpn_disconnect}
      outcome_map: {ok: success, fail: failure}
      constants: {operation: outbound_flow}

Only mapped fields are read, so password/token columns in an export are never touched. ``url`` is reduced to
domain + path without query string. Unmapped observation types default by family: ``vpn`` connect/disconnect
words -> ``vpn_connect``/``vpn_disconnect``; ``firewall`` -> ``network_flow``; ``proxy`` -> ``proxy_request``.
"""

from __future__ import annotations

import csv
import json
import re
from urllib.parse import urlsplit

from tripline_scope.core.errors import ConfigError

from ..schema import FIELD_NAMES
from ..timenorm import parse_with_format
from .base import ParseContext, blank, clean_ip, safe_url_path, text_stream, to_int

VERSION = "1.0"
_TARGETS = (set(FIELD_NAMES) - {"event_id", "source_id", "source_family", "ordinal", "ts_original_text",
                                 "tz_original", "ts_utc", "clock_offset_s", "ts_uncertainty_s", "time_precision",
                                 "parser", "raw_sha256", "consequence_class", "record_locator", "tz_basis",
                                 "ts_utc_min", "ts_utc_max", "objects", "flags", "statement_fp"}) | {"ts", "url"}
_INT_TARGETS = {"rows", "bytes", "bytes_received", "http_status", "dest_port"}
_IP_TARGETS = {"remote_ip", "dest_ip", "assigned_ip"}
_KV = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S*)')


def validate_mapping(mapping: dict) -> None:
    bad = set(mapping.get("fields", {})) - _TARGETS
    if bad:
        raise ConfigError(f"mapping targets not in the event schema: {sorted(bad)}")


def _records(ctx: ParseContext, stream, relname: str):
    m = ctx.mapping or {}
    if ctx.fmt == "csv":
        opts = m.get("csv") or {}
        reader = csv.reader(text_stream(stream), delimiter=opts.get("delimiter", ","))
        header = list(opts["columns"]) if opts.get("columns") else None
        skip_first = bool(opts.get("header", header is None))
        first = True
        for row in reader:
            if not row:
                continue
            if first:
                first = False
                if skip_first:
                    header = header or [h.strip().lstrip("\ufeff") for h in row]
                    continue
            yield f"{relname}:{reader.line_num}", dict(zip(header, row, strict=False)), "\x1f".join(row)
        return
    if ctx.fmt == "kv":
        for n, line in enumerate(text_stream(stream), 1):
            line = line.rstrip("\r\n")
            if line.strip():
                yield f"{relname}:{n}", {k: v.strip('"') for k, v in _KV.findall(line)}, line
        return
    text = text_stream(stream).read()
    s = text.lstrip()
    if ctx.fmt == "json" and s.startswith(("[", "{")):
        doc = json.loads(s)
        items = doc.get(m.get("records_key", "value"), []) if isinstance(doc, dict) else doc
        for i, it in enumerate(items, 1):
            yield f"{relname}#{i}", it if isinstance(it, dict) else None, it
        return
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                it = json.loads(line)
            except json.JSONDecodeError:
                it = None
            yield f"{relname}:{n}", it if isinstance(it, dict) else None, line


def _get(d: dict, path: str):
    cur = d
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _default_observation(family: str, op: str | None) -> str:
    o = (op or "").lower()
    if family == "vpn":
        if any(w in o for w in ("disconnect", "logout", "logoff", "end", "stop", "close")):
            return "vpn_disconnect"
        if any(w in o for w in ("connect", "login", "logon", "start", "establish", "open", "auth")):
            return "vpn_connect"
        return "vpn_activity"
    if family == "firewall":
        return "network_flow"
    if family == "proxy":
        return "proxy_request"
    return "other"


def parse(ctx: ParseContext, stream, relname: str):
    m = ctx.mapping or {}
    validate_mapping(m)
    fields = m["fields"]
    tsfmt = m.get("timestamp_format", "iso8601")
    op_map = {str(k).lower(): v for k, v in (m.get("operation_map") or {}).items()}
    obs_map = {str(k).lower(): v for k, v in (m.get("observation_map") or {}).items()}
    out_map = {str(k).lower(): v for k, v in (m.get("outcome_map") or {}).items()}
    consts = m.get("constants") or {}
    for loc, d, raw in _records(ctx, stream, relname):
        if d is None:
            ctx.fail(loc, "record could not be read with the declared format")
            continue
        ts_text = _get(d, fields["ts"])
        if ts_text is None or str(ts_text).strip() == "":
            ctx.fail(loc, "no timestamp in mapped field")
            continue
        ts, prec, abbr = parse_with_format(str(ts_text), tsfmt)
        if ts is None:
            ctx.fail(loc, "timestamp does not match timestamp_format")
            continue
        rec: dict = {"_raw": raw, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host, "flags": []}
        for target, src in fields.items():
            if target == "ts":
                continue
            v = _get(d, src)
            if target == "url":
                v = blank(v)
                if v:
                    parts = urlsplit(v if "://" in v else "//" + v)
                    rec["domain"] = (parts.hostname or "").lower() or None
                    rec["url_path"], had_q = safe_url_path(parts.path or "/")
                    if parts.query or had_q:
                        rec["flags"].append("query_stripped")
                continue
            if target in _INT_TARGETS:
                rec[target] = to_int(v)
            elif target in _IP_TARGETS:
                rec[target] = clean_ip(blank(v))
            elif target == "domain":
                rec[target] = (blank(v) or "").lower().rstrip(".") or None
            else:
                rec[target] = blank(v)
        for k, v in consts.items():
            if k in _TARGETS and rec.get(k) is None:
                rec[k] = v
        op = rec.get("operation")
        if op is not None:
            mapped = op_map.get(str(op).lower())
            rec["operation"] = str(mapped if mapped is not None else op).lower()[:60]
        if rec.get("outcome") is not None:
            o = out_map.get(str(rec["outcome"]).lower(), rec["outcome"])
            rec["outcome"] = o if o in ("success", "failure", "unknown") else "unknown"
        else:
            rec["outcome"] = "unknown"
        if rec.get("observation_type") is None:
            rec["observation_type"] = obs_map.get(str(rec.get("operation") or "").lower()) or \
                _default_observation(ctx.family, rec.get("operation"))
        if rec.get("mfa") not in (None, "true", "false", "unknown"):
            rec["mfa"] = {"yes": "true", "1": "true", "no": "false", "0": "false"}.get(str(rec["mfa"]).lower(), "unknown")
        yield rec
