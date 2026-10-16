"""Small shared helpers for the analysis: canonical names, intervals, stable ids."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress

UTC = dt.UTC
SYSTEM_LOGON_IDS = {"0x0", "0x3e7", "0x3e4", "0x3e5"}


def canon_host(name: str | None) -> str | None:
    """``LABSQL01\\INST`` / ``labsql01.lab.example`` -> ``labsql01`` (IP addresses kept as they are)."""
    if not name:
        return None
    h = str(name).strip().lower()
    if "\\" in h:
        h = h.split("\\", 1)[0]
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    return h.split(".", 1)[0] or None


def acct_key(account: str | None, directory_domains: list[str]) -> str | None:
    """Key used to compare account names across sources: lower case, NetBIOS prefix removed, and the UPN
    suffix removed only for the hospital's own directory domains (other e-mail-shaped names stay whole)."""
    if not account:
        return None
    a = str(account).strip().lower()
    if "\\" in a:
        a = a.split("\\", 1)[1]
    if "@" in a:
        local, _, domain = a.partition("@")
        if domain in {d.lower() for d in directory_domains}:
            a = local
    return a or None


def stable_id(prefix: str, *parts) -> str:
    h = hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:12]
    return f"{prefix}-{h}"


def as_utc(t):
    if t is None:
        return None
    if isinstance(t, str):
        return dt.datetime.fromisoformat(t.replace("Z", "+00:00")).astimezone(UTC)
    if t.tzinfo is None:
        return t.replace(tzinfo=UTC)
    return t.astimezone(UTC)


def iso(t) -> str | None:
    t = as_utc(t)
    if t is None:
        return None
    if t.microsecond:
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_intervals(ivs: list[tuple]) -> list[tuple]:
    out: list[list] = []
    for a, b in sorted((i for i in ivs if i[0] is not None and i[1] is not None and i[1] >= i[0]), key=lambda x: x[0]):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [tuple(x) for x in out]


def subtract_intervals(base: list[tuple], minus: list[tuple]) -> list[tuple]:
    res = merge_intervals(base)
    for ma, mb in merge_intervals(minus):
        nxt = []
        for a, b in res:
            if mb <= a or ma >= b:
                nxt.append((a, b))
                continue
            if ma > a:
                nxt.append((a, ma))
            if mb < b:
                nxt.append((mb, b))
        res = nxt
    return res


def clip(ivs: list[tuple], lo, hi) -> list[tuple]:
    return [(max(a, lo), min(b, hi)) for a, b in ivs if b > lo and a < hi]


def is_internal(ip: str | None, nets) -> bool | None:
    return nets.contains(ip)
