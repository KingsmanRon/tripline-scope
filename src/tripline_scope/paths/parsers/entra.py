"""Entra ID (Azure AD) sign-in exports: Microsoft Graph ``auditLogs/signIns`` JSON (``{"value": [...]}``, a list,
or JSON Lines) and the portal's CSV download.

Fields: ``createdDateTime``/``Date (UTC)``, ``id``/``Request ID``, ``correlationId``/``Correlation ID``,
``sessionId``/``Session ID`` (when exported), ``userPrincipalName``/``Username``, ``appDisplayName``/
``Application``, ``ipAddress``/``IP address``, ``location``/``Location``, ``status.errorCode``/``Sign-in error
code``, ``authenticationRequirement``/``Authentication requirement``, ``mfaDetail``/``Multifactor
authentication result``. Display names (``userDisplayName``/``User``) are never read. MFA is ``true`` only when
the export shows multi-factor authentication satisfied, ``false`` only when it shows single-factor, else
``unknown``.
"""

from __future__ import annotations

import csv
import json

from ..timenorm import parse_iso
from .base import ParseContext, blank, clean_ip, text_stream

VERSION = "1.0"

_CSV = {
    "date (utc)": "ts", "date": "ts", "createddatetime": "ts", "request id": "request_id", "id": "request_id",
    "correlation id": "correlation_id", "session id": "session_id", "username": "account",
    "user principal name": "account", "userprincipalname": "account", "application": "application",
    "ip address": "remote_ip", "location": "location", "status": "status", "sign-in error code": "error_code",
    "authentication requirement": "auth_req", "multifactor authentication result": "mfa_result",
    "mfa result": "mfa_result", "client app": "client_app",
}


def _mfa(auth_req, mfa_result, mfa_detail, auth_details) -> str:
    req = (auth_req or "").lower()
    if auth_details:
        for step in auth_details:
            if isinstance(step, dict) and step.get("succeeded") and str(step.get("authenticationStepRequirement", "")).lower().startswith("secondary"):
                return "true"
    if mfa_detail and isinstance(mfa_detail, dict) and (mfa_detail.get("authMethod") or mfa_detail.get("authDetail")):
        return "true"
    if mfa_result:
        r = str(mfa_result).lower()
        if "succe" in r or "satisfied" in r or "mfa requirement satisfied" in r:
            return "true"
    if req == "multifactorauthentication" or req == "multifactor authentication" or req == "multi-factor authentication":
        return "true" if not mfa_result or "fail" not in str(mfa_result).lower() else "false"
    if req in ("singlefactorauthentication", "single-factor authentication", "single factor authentication"):
        return "false"
    return "unknown"


def _loc_text(loc) -> str | None:
    if isinstance(loc, dict):
        parts = [blank(loc.get("countryOrRegion")), blank(loc.get("city"))]
        return "/".join(p for p in parts if p) or None
    return blank(loc)


def _json_items(text: str):
    s = text.lstrip()
    if s.startswith("[") or (s.startswith("{") and '"value"' in s[:2000]):
        doc = json.loads(s)
        items = doc.get("value", []) if isinstance(doc, dict) else doc
        for i, it in enumerate(items, 1):
            yield i, it
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                yield i, json.loads(line)
            except json.JSONDecodeError:
                yield i, None


def parse(ctx: ParseContext, stream, relname: str):
    if ctx.fmt in ("json", "jsonl"):
        for i, it in _json_items(text_stream(stream).read()):
            loc = f"{relname}#{i}"
            if not isinstance(it, dict) or not it.get("createdDateTime"):
                ctx.fail(loc, "sign-in record without createdDateTime")
                continue
            ts, prec, abbr = parse_iso(str(it["createdDateTime"]))
            if ts is None:
                ctx.fail(loc, "unparseable createdDateTime")
                continue
            status = it.get("status") or {}
            code = status.get("errorCode") if isinstance(status, dict) else None
            raw = {k: v for k, v in it.items() if k not in ("userDisplayName",)}
            yield {
                "_raw": raw, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host or "entra",
                "account": blank(it.get("userPrincipalName")), "application": blank(it.get("appDisplayName")),
                "request_id": blank(it.get("id")), "correlation_id": blank(it.get("correlationId")),
                "session_id": blank(it.get("sessionId")), "remote_ip": clean_ip(it.get("ipAddress")),
                "location": _loc_text(it.get("location")),
                "outcome": "unknown" if code is None else ("success" if int(code) == 0 else "failure"),
                "event_code": None if code is None else str(code),
                "mfa": _mfa(it.get("authenticationRequirement"), None, it.get("mfaDetail"), it.get("authenticationDetails")),
                "operation": "sign_in", "observation_type": "sign_in", "flags": [],
            }
        return
    reader = csv.reader(text_stream(stream))
    header = None
    utc_header = False
    for row in reader:
        if not row:
            continue
        if header is None:
            header = [_CSV.get(h.strip().lstrip("﻿").lower()) for h in row]
            utc_header = any(h.strip().lower() == "date (utc)" for h in row)
            if "ts" not in header:
                ctx.fail(f"{relname}:1", "no date column in sign-in CSV header")
                return
            continue
        d = {k: v for k, v in zip(header, row, strict=False) if k}
        loc = f"{relname}:{reader.line_num}"
        ts, prec, abbr = parse_iso(d.get("ts", ""))
        if ts is None:
            ctx.fail(loc, "unparseable sign-in date")
            continue
        flags = []
        if ts.tzinfo is None and utc_header:
            import datetime as _dt

            ts = ts.replace(tzinfo=_dt.UTC)
            flags.append("utc_from_header")
        st = (d.get("status") or "").lower()
        outcome = "success" if st.startswith("success") else ("failure" if st.startswith(("fail", "interrupt")) else "unknown")
        yield {
            "_raw": "\x1f".join(row), "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host or "entra",
            "account": blank(d.get("account")), "application": blank(d.get("application")),
            "request_id": blank(d.get("request_id")), "correlation_id": blank(d.get("correlation_id")),
            "session_id": blank(d.get("session_id")), "remote_ip": clean_ip(d.get("remote_ip")),
            "location": blank(d.get("location")), "outcome": outcome, "event_code": blank(d.get("error_code")),
            "mfa": _mfa(d.get("auth_req"), d.get("mfa_result"), None, None),
            "operation": "sign_in", "observation_type": "sign_in", "flags": flags,
        }
