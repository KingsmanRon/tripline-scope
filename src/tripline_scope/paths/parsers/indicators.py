"""Partner-supplied indicators (IP addresses, CIDR ranges, domains, file hashes) as CSV or JSON.

Columns/keys: ``type`` (ip | cidr | domain | sha256 | sha1 | md5), ``value``, ``provenance`` (required: who
supplied it and from what work, e.g. "Partner IR firm, report PIR-2026-117"), ``valid_from``, ``valid_to``
(ISO-8601 with zone; missing bounds are recorded as open and flagged), optional ``reference``,
``confidence`` and ``description``. Indicators without provenance, with invalid values or with an inverted
validity range are rejected and counted. Matching an indicator is never attribution.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re

from tripline_scope.core.redact import scrub_text

from ..timenorm import parse_iso, to_iso
from .base import ParseContext, blank, raw_hash, text_stream

VERSION = "1.0"
_HASH_LEN = {"sha256": 64, "sha1": 40, "md5": 32}
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _items(ctx: ParseContext, stream, relname: str):
    if ctx.fmt == "csv":
        reader = csv.DictReader(text_stream(stream))
        for row in reader:
            yield f"{relname}:{reader.line_num}", {str(k).strip().lower(): v for k, v in row.items() if k}
        return
    text = text_stream(stream).read()
    s = text.lstrip()
    if ctx.fmt == "json" and s.startswith(("[", "{")):
        doc = json.loads(s)
        items = doc.get("indicators", doc.get("value", [])) if isinstance(doc, dict) else doc
        for i, it in enumerate(items, 1):
            yield f"{relname}#{i}", {str(k).lower(): v for k, v in it.items()} if isinstance(it, dict) else None
        return
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                it = json.loads(line)
            except json.JSONDecodeError:
                it = None
            yield f"{relname}:{n}", {str(k).lower(): v for k, v in it.items()} if isinstance(it, dict) else None


def _time(v):
    v = blank(v)
    if not v:
        return None, False
    t, _p, abbr = parse_iso(str(v))
    if t is None or t.tzinfo is None or abbr:
        return None, True
    return t, False


def parse(ctx: ParseContext, stream, relname: str) -> list[dict]:
    out = []
    for loc, d in _items(ctx, stream, relname):
        if d is None:
            ctx.rejected.append({"locator": loc, "reason": "unreadable record"})
            continue
        typ = (blank(d.get("type")) or "").lower()
        value = blank(d.get("value"))
        prov = blank(d.get("provenance"))
        if not prov:
            ctx.rejected.append({"locator": loc, "reason": "no provenance"})
            continue
        if not value:
            ctx.rejected.append({"locator": loc, "reason": "no value"})
            continue
        try:
            if typ == "ip":
                value = str(ipaddress.ip_address(value))
            elif typ == "cidr":
                value = str(ipaddress.ip_network(value, strict=False))
            elif typ == "domain":
                value = value.lower().rstrip(".")
                if not _DOMAIN.match(value):
                    raise ValueError
            elif typ in _HASH_LEN:
                value = value.lower()
                if not re.fullmatch(rf"[0-9a-f]{{{_HASH_LEN[typ]}}}", value):
                    raise ValueError
            else:
                ctx.rejected.append({"locator": loc, "reason": "unsupported indicator type"})
                continue
        except ValueError:
            ctx.rejected.append({"locator": loc, "reason": f"invalid {typ} value"})
            continue
        vf, bad_f = _time(d.get("valid_from"))
        vt, bad_t = _time(d.get("valid_to"))
        if bad_f or bad_t:
            ctx.rejected.append({"locator": loc, "reason": "validity bounds must be ISO-8601 with a zone"})
            continue
        if vf and vt and vt < vf:
            ctx.rejected.append({"locator": loc, "reason": "valid_to before valid_from"})
            continue
        flags = []
        if vf is None or vt is None:
            flags.append("open_validity")
        conf = d.get("confidence")
        try:
            conf = max(0.0, min(1.0, float(conf))) if conf not in (None, "") else None
        except (TypeError, ValueError):
            conf = None
        out.append({
            "indicator_id": f"IND-{ctx.source_id}-{len(out) + 1:04d}", "type": typ, "value": value,
            "provenance": scrub_text(prov)[:200], "reference": scrub_text(blank(d.get("reference")) or "")[:120] or None,
            "description": scrub_text(blank(d.get("description")) or "")[:200] or None,
            "valid_from": to_iso(vf), "valid_to": to_iso(vt), "partner_confidence": conf, "flags": flags,
            "locator": loc, "raw_sha256": raw_hash(d),
        })
    return out
