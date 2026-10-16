"""Time normalisation for log records.

Rules (documented in ``docs/ACCESS_PATHS.md``):

* the original text is always kept, with the zone it declared (``tz_original``) and where the zone came from
  (``tz_basis``): ``record`` (the record carries an offset/``Z``/known abbreviation) > ``manifest`` (the
  operator declared the source's zone) > ``format`` (the format documents UTC, e.g. SQL Server Audit
  ``event_time``, IIS W3C, Entra) > ``unknown``;
* a record without a resolvable zone gets ``ts_utc = null`` and ``tz_original = "unknown"``; it is never
  silently assigned a zone. Its bounds cover every real-world offset (UTC-12 to UTC+14) so it can still be
  shown as *possibly* inside a window, and it is reported as a gap;
* a documented clock offset (host clock minus true time, seconds; positive = host clock fast) is subtracted,
  and the clock uncertainty widens ``ts_utc_min``/``ts_utc_max``; unknown uncertainty stays ``null`` and the
  analysis applies the configured assumption, stated as such;
* ambiguous or non-existent local times around DST transitions keep both candidate instants in the bounds.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from tripline_scope.core.errors import ConfigError

UTC = dt.UTC
_PRECISION_WIDTH = {"millisecond": 0.001, "second": 1.0, "minute": 60.0, "day": 86400.0, "unknown": 0.0}
_UNKNOWN_BEFORE = dt.timedelta(hours=14)    # local = utc + offset, offset in [-12h, +14h]
_UNKNOWN_AFTER = dt.timedelta(hours=12)
BUILTIN_ABBREVIATIONS = {"UTC": 0, "GMT": 0, "Z": 0, "SAST": 7200}
_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{2}):?(\d{2})?$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}


def parse_offset(text: str) -> int | None:
    """Seconds east of UTC for ``Z``, ``UTC``, ``+02:00``, ``+0200``, ``-05``; ``None`` otherwise."""
    t = text.strip()
    if t.upper() in ("Z", "UTC", "GMT", "+00:00", "-00:00"):
        return 0
    m = _OFFSET_RE.match(t)
    if not m:
        return None
    secs = int(m.group(2)) * 3600 + int(m.group(3) or 0) * 60
    if secs > 14 * 3600:
        return None
    return -secs if m.group(1) == "-" else secs


def offset_text(seconds: int) -> str:
    if seconds == 0:
        return "Z"
    sign = "+" if seconds > 0 else "-"
    s = abs(seconds)
    return f"{sign}{s // 3600:02d}:{(s % 3600) // 60:02d}"


@dataclass
class ZoneSpec:
    zone: str = "unknown"                 # "Z" | "+02:00" | IANA name | "unknown"
    basis: str = "unknown"                # manifest | format | unknown
    clock_offset_s: float = 0.0
    clock_uncertainty_s: float | None = None
    abbreviations: dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        self._fixed: int | None = None
        self._zi: ZoneInfo | None = None
        z = (self.zone or "unknown").strip()
        if z.lower() == "unknown":
            self.zone, self.basis = "unknown", "unknown"
            return
        off = parse_offset(z)
        if off is not None:
            self._fixed = off
            return
        try:
            self._zi = ZoneInfo(z)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ConfigError(f"time zone {z!r} is not a known IANA zone or fixed offset") from exc

    @property
    def known(self) -> bool:
        return self._fixed is not None or self._zi is not None

    def abbreviation(self, abbr: str) -> int | None:
        a = abbr.strip().upper()
        if a in self.abbreviations:
            return self.abbreviations[a]
        if a in BUILTIN_ABBREVIATIONS:
            return BUILTIN_ABBREVIATIONS[a]
        return parse_offset(a)

    def localise(self, naive: dt.datetime) -> tuple[dt.datetime, dt.datetime, list[str]]:
        """(earliest, latest) aware instants for a naive local time under this zone."""
        if self._fixed is not None:
            t = naive.replace(tzinfo=dt.timezone(dt.timedelta(seconds=self._fixed)))
            return t, t, []
        assert self._zi is not None
        a = naive.replace(tzinfo=self._zi, fold=0)
        b = naive.replace(tzinfo=self._zi, fold=1)
        ua, ub = a.astimezone(UTC), b.astimezone(UTC)
        if ua == ub:
            return a, a, []
        return (a, b, ["dst_ambiguous"]) if ua < ub else (b, a, ["dst_ambiguous"])


@dataclass
class TimeResult:
    ts_utc: dt.datetime | None
    ts_min: dt.datetime | None
    ts_max: dt.datetime | None
    tz_original: str
    tz_basis: str
    precision: str
    uncertainty_s: float | None
    flags: list[str]


def normalise(value: dt.datetime | None, precision: str, spec: ZoneSpec, *, record_offset: int | None = None,
              record_abbrev: str | None = None) -> TimeResult:
    """Normalise one parsed timestamp. ``value`` is aware when the record declared its zone."""
    if value is None:
        return TimeResult(None, None, None, "unknown", "unknown", "unknown", spec.clock_uncertainty_s, ["no_timestamp"])
    flags: list[str] = []
    width = dt.timedelta(seconds=_PRECISION_WIDTH.get(precision, 0.0))
    unc = spec.clock_uncertainty_s
    unc_td = dt.timedelta(seconds=unc or 0.0)
    skew = dt.timedelta(seconds=spec.clock_offset_s or 0.0)
    if value.tzinfo is None and record_abbrev is not None:
        off = spec.abbreviation(record_abbrev)
        if off is not None:
            value = value.replace(tzinfo=dt.timezone(dt.timedelta(seconds=off)))
            record_offset = off
        else:
            flags.append("tz_abbreviation_unrecognised")
    if value.tzinfo is not None:
        off = int(value.utcoffset().total_seconds()) if record_offset is None else record_offset
        utc = value.astimezone(UTC) - skew
        return TimeResult(utc, utc - unc_td, utc + width + unc_td, offset_text(off), "record", precision, unc, flags)
    if spec.known:
        early, late, f2 = spec.localise(value)
        flags += f2
        ue, ul = early.astimezone(UTC) - skew, late.astimezone(UTC) - skew
        off = int(early.utcoffset().total_seconds())
        return TimeResult(ue, ue - unc_td, ul + width + unc_td, offset_text(off), spec.basis, precision, unc, flags)
    local = value.replace(tzinfo=UTC) - skew
    flags.append("time_zone_unknown")
    return TimeResult(None, local - _UNKNOWN_BEFORE - unc_td, local + _UNKNOWN_AFTER + width + unc_td, "unknown",
                      "unknown", precision, unc, flags)


# ---------------------------------------------------------------------------------------------- parsing
def _precision_of(time_part: str) -> str:
    if "." in time_part or "," in time_part:
        return "millisecond"
    colons = time_part.count(":")
    if colons >= 2:
        return "second"
    if colons == 1:
        return "minute"
    return "day"


_ISO_SPLIT = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?))?\s*(.*)$")


def parse_iso(text: str) -> tuple[dt.datetime | None, str, str | None]:
    """Parse ISO-8601-like text. Returns (datetime aware-or-naive, precision, unrecognised zone abbreviation)."""
    t = (text or "").strip().strip('"')
    m = _ISO_SPLIT.match(t)
    if not m:
        return None, "unknown", None
    date_part, time_part, rest = m.group(1), m.group(2) or "", m.group(3).strip()
    precision = _precision_of(time_part) if time_part else "day"
    tp = time_part.replace(",", ".")
    if "." in tp:
        main, frac = tp.split(".", 1)
        tp = f"{main}.{(frac + '000000')[:6]}"
    if tp and tp.count(":") == 1:
        tp += ":00"
    if tp and len(tp.split(":")[0]) == 1:
        tp = "0" + tp
    base = f"{date_part}T{tp}" if tp else date_part
    try:
        naive = dt.datetime.fromisoformat(base)
    except ValueError:
        return None, "unknown", None
    if not rest:
        return naive, precision, None
    off = parse_offset(rest)
    if off is not None:
        return naive.replace(tzinfo=dt.timezone(dt.timedelta(seconds=off))), precision, None
    if re.fullmatch(r"[A-Za-z]{2,6}", rest):
        return naive, precision, rest
    return None, "unknown", None


def parse_clf(text: str) -> tuple[dt.datetime | None, str]:
    """Common/combined log format time ``10/Oct/2026:13:55:36 +0200`` (brackets optional)."""
    t = text.strip().strip("[]")
    try:
        datepart, _, zone = t.partition(" ")
        d, mon, rest = datepart.split("/", 2)
        y, hh, mm, ss = rest.split(":")
        frac = ""
        if "." in ss:
            ss, frac = ss.split(".", 1)
        naive = dt.datetime(int(y), _MONTHS[mon.lower()[:3]], int(d), int(hh), int(mm), int(ss),
                            int((frac + "000000")[:6]) if frac else 0)
    except (ValueError, KeyError):
        return None, "unknown"
    precision = "millisecond" if frac else "second"
    if zone:
        off = parse_offset(zone)
        if off is None:
            return None, "unknown"
        return naive.replace(tzinfo=dt.timezone(dt.timedelta(seconds=off))), precision
    return naive, precision


def parse_epoch(text: str, unit: str = "s") -> tuple[dt.datetime | None, str]:
    try:
        v = float(text)
    except (TypeError, ValueError):
        return None, "unknown"
    if unit == "ms":
        return dt.datetime.fromtimestamp(v / 1000.0, UTC), "millisecond"
    precision = "second" if float(v).is_integer() else "millisecond"
    return dt.datetime.fromtimestamp(v, UTC), precision


def parse_with_format(text: str, fmt: str) -> tuple[dt.datetime | None, str, str | None]:
    """Parse with an operator-declared format: ``iso8601``, ``clf``, ``epoch_s``, ``epoch_ms`` or strptime."""
    if fmt in ("iso8601", "iso", None, ""):
        return parse_iso(text)
    if fmt == "clf":
        v, p = parse_clf(text)
        return v, p, None
    if fmt in ("epoch_s", "epoch"):
        v, p = parse_epoch(text, "s")
        return v, p, None
    if fmt == "epoch_ms":
        v, p = parse_epoch(text, "ms")
        return v, p, None
    try:
        v = dt.datetime.strptime(text.strip(), fmt)
    except ValueError:
        return None, "unknown", None
    if "%f" in fmt:
        p = "millisecond"
    elif "%S" in fmt:
        p = "second"
    elif "%M" in fmt:
        p = "minute"
    else:
        p = "day"
    return v, p, None


def to_iso(t: dt.datetime | None) -> str | None:
    """Second-precision UTC ISO text used in reports (milliseconds kept when present)."""
    if t is None:
        return None
    t = t.astimezone(UTC)
    if t.microsecond:
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_window(text: str) -> tuple[dt.datetime, dt.datetime]:
    """``START/END`` (ISO-8601 with zone) -> aware UTC datetimes."""
    if not text or "/" not in text:
        raise ConfigError("window must be START/END in ISO-8601 with a time zone")
    a, b = text.split("/", 1)
    out = []
    for part in (a, b):
        v, _p, abbr = parse_iso(part)
        if v is None or v.tzinfo is None or abbr:
            raise ConfigError("window bounds must be ISO-8601 timestamps with an explicit zone (e.g. Z)")
        out.append(v.astimezone(UTC))
    if out[1] < out[0]:
        raise ConfigError("window ends before it starts")
    return out[0], out[1]
