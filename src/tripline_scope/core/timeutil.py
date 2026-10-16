from __future__ import annotations

import datetime as dt
import os

UTC = dt.UTC


def utcnow() -> dt.datetime:
    """Current UTC time at second precision. ``TSCOPE_FIXED_NOW`` (ISO-8601) pins it for reproducible tests."""
    fixed = os.environ.get("TSCOPE_FIXED_NOW")
    if fixed:
        return parse_utc(fixed)
    return dt.datetime.now(UTC).replace(microsecond=0)


def iso(ts: dt.datetime | None) -> str | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        raise ValueError("naive datetime")
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(utcnow())


def parse_utc(text: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("timestamp must carry a time zone")
    return t.astimezone(UTC)
