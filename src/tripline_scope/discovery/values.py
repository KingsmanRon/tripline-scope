"""Value evidence for column classification.

Two implementations of every check, kept side by side so they agree:

* Python profilers run on the in-memory **sample** (default 10 000 rows) and give per-check match rates;
* SQL expressions (DuckDB, using the core ``tscope_*`` macros) run on every batch of the **full scan** to
  confirm the chosen category's match rate and the null rate.

Nothing here stores or returns values: only counts and rates leave these functions.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from tripline_scope.core.identifiers import (
    card_number_like,
    icd10_like,
    medical_aid_like,
    normalise_email,
    normalise_phone,
    parse_sa_id,
    passport_like,
)

MIN_YEAR, MAX_YEAR = 1880, 2100

# ------------------------------------------------------------------------------------------ dates
# name -> (regex, group names in order, strptime format applied to "<g1>-<g2>-<g3>" in canonical order)
DATE_PARSERS: dict[str, tuple[str, tuple[str, str, str]]] = {
    "ymd": (r"^\s*(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T].*)?$", ("y", "m", "d")),
    "dmy": (r"^\s*(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?:[ T].*)?$", ("d", "m", "y")),
    "mdy": (r"^\s*(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?:[ T].*)?$", ("m", "d", "y")),
    "compact": (r"^\s*(\d{4})(\d{2})(\d{2})\s*$", ("y", "m", "d")),
    "dmony": (r"^\s*(\d{1,2})[ \-/]([A-Za-z]{3})[A-Za-z]*\.?[ \-/](\d{4})(?:[ T].*)?$", ("d", "b", "y")),
}
_DATE_RX = {k: re.compile(v[0]) for k, v in DATE_PARSERS.items()}
_MONTHS = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                            "nov", "dec"])}
# Preference when two parsers are equally good (SA convention is day-first).
_DATE_ORDER = ("ymd", "dmy", "dmony", "mdy", "compact")


def parse_date(value: object, parser: str) -> dt.date | None:
    if value is None:
        return None
    m = _DATE_RX[parser].match(str(value))
    if not m:
        return None
    parts = dict(zip(DATE_PARSERS[parser][1], m.groups(), strict=True))
    try:
        month = _MONTHS[parts["b"].lower()] if "b" in parts else int(parts["m"])
        d = dt.date(int(parts["y"]), month, int(parts["d"]))
    except (KeyError, ValueError):
        return None
    return d if MIN_YEAR <= d.year <= MAX_YEAR else None


def date_sql(v: str, parser: str) -> str:
    """DuckDB expression parsing VARCHAR ``v`` to DATE with ``parser`` (NULL when it does not parse)."""
    rx, names = DATE_PARSERS[parser]
    rx_sql = rx.replace("'", "''")
    names_sql = "[" + ", ".join(f"'{n}'" for n in names) + "]"
    s = f"regexp_extract(CAST({v} AS VARCHAR), '{rx_sql}', {names_sql})"
    if "b" in names:
        expr = f"try_strptime({s}.d || '-' || {s}.b || '-' || {s}.y, '%d-%b-%Y')"
    else:
        expr = f"try_strptime({s}.y || '-' || {s}.m || '-' || {s}.d, '%Y-%m-%d')"
    return (f"(CASE WHEN year(CAST({expr} AS DATE)) BETWEEN {MIN_YEAR} AND {MAX_YEAR} "
            f"THEN CAST({expr} AS DATE) END)")


def best_date_parser(values: list[str]) -> tuple[str | None, float]:
    if not values:
        return None, 0.0
    best, best_rate = None, 0.0
    for name in _DATE_ORDER:
        ok = sum(1 for v in values if parse_date(v, name) is not None)
        rate = ok / len(values)
        if rate > best_rate + 1e-9:
            best, best_rate = name, rate
    return best, best_rate


# ------------------------------------------------------------------------------------------ simple checks
_SEP = re.compile(r"[\s\-]")
_NAME_RX = re.compile(r"^[^\W\d_][^\W\d_ '’.\-]*(?:[ '’.\-]+[^\W\d_][^\W\d_ '’.\-]*){0,5}\.?$")
SEX_VALUES = {"M", "F", "U", "MALE", "FEMALE", "UNKNOWN", "MAN", "WOMAN", "MANLIK", "VROULIK", "V", "O", "OTHER",
              "I", "INDETERMINATE"}
SEX_MAP = {"M": "M", "MALE": "M", "MAN": "M", "MANLIK": "M", "F": "F", "FEMALE": "F", "WOMAN": "F", "VROULIK": "F",
           "V": "F", "U": "U", "UNKNOWN": "U", "O": "U", "OTHER": "U", "I": "U", "INDETERMINATE": "U"}


def digits_of(value: str) -> str:
    return _SEP.sub("", value)


def padded_id(value: str, pad: bool) -> str:
    d = digits_of(value)
    if pad and len(d) == 12 and d.isdigit():
        return "0" + d
    return d


def name_like(value: str) -> bool:
    s = value.strip()
    return 1 <= len(s) <= 80 and bool(_NAME_RX.match(s))


def free_text_like(value: str) -> bool:
    s = value.strip()
    return len(s.split()) >= 5 or (len(s) >= 40 and " " in s)


def phone_formatted(value: str) -> bool:
    s = re.sub(r"[\s\-()]", "", value)
    return bool(re.match(r"^(\+|00|0[1-8]|27[1-8])", s)) and normalise_phone(s) is not None


def bank_like(value: str) -> bool:
    d = digits_of(value)
    return d.isdigit() and 6 <= len(d) <= 16


CHECKS = ("sa_id", "passport", "phone", "phone_formatted", "email", "date", "icd10", "card", "digits", "name",
          "sex", "postal", "med_aid", "free_text", "bank", "digits13")


@dataclass
class Profile:
    sampled: int
    nonnull: int
    distinct: int
    distinct_capped: bool
    avg_len: float
    rates: dict[str, float] = field(default_factory=dict)
    date_parser: str | None = None

    @property
    def null_rate(self) -> float:
        return 1.0 - (self.nonnull / self.sampled) if self.sampled else 1.0

    @property
    def distinct_ratio(self) -> float:
        return self.distinct / self.nonnull if self.nonnull else 0.0

    def rate(self, check: str) -> float:
        return self.rates.get(check, 0.0)


def profile_values(values: list[str | None], *, id_pad: bool = False, distinct_cap: int = 50_000) -> Profile:
    """Profile a sample column. ``values`` are strings or ``None`` (in memory only; never stored)."""
    vals = [v for v in values if v is not None and str(v).strip() != ""]
    n = len(vals)
    distinct: set[str] = set()
    capped = False
    for v in vals:
        if len(distinct) >= distinct_cap:
            capped = True
            break
        distinct.add(v)
    prof = Profile(sampled=len(values), nonnull=n, distinct=len(distinct), distinct_capped=capped,
                   avg_len=(sum(len(v) for v in vals) / n) if n else 0.0)
    if not n:
        return prof
    counts = dict.fromkeys(CHECKS, 0)
    for v in vals:
        s = str(v)
        d = digits_of(s)
        is_digits = d.isdigit()
        if is_digits:
            counts["digits"] += 1
            if len(d) == 13:
                counts["digits13"] += 1
        if is_digits and len(padded_id(s, id_pad)) == 13 and parse_sa_id(padded_id(s, id_pad)).valid:
            counts["sa_id"] += 1
        if not is_digits and passport_like(s):
            counts["passport"] += 1
        if normalise_phone(s) is not None:
            counts["phone"] += 1
            if phone_formatted(s):
                counts["phone_formatted"] += 1
        if "@" in s and normalise_email(s) is not None:
            counts["email"] += 1
        if icd10_like(s):
            counts["icd10"] += 1
        if is_digits and card_number_like(d):
            counts["card"] += 1
        if name_like(s):
            counts["name"] += 1
        if s.strip().upper() in SEX_VALUES:
            counts["sex"] += 1
        if re.fullmatch(r"\s*\d{4}\s*", s):
            counts["postal"] += 1
        if medical_aid_like(s):
            counts["med_aid"] += 1
        if free_text_like(s):
            counts["free_text"] += 1
        if bank_like(s):
            counts["bank"] += 1
    parser, date_rate = best_date_parser(vals)
    prof.rates = {k: round(c / n, 6) for k, c in counts.items()}
    prof.rates["date"] = round(date_rate, 6)
    prof.date_parser = parser
    return prof


_CHECK_FOR = {
    "sa_id": "sa_id", "guardian_sa_id": "sa_id", "passport": "passport", "phone": "phone", "guardian_phone": "phone",
    "email": "email", "guardian_email": "email", "dob": "date", "record_date": "date", "first_name": "name",
    "last_name": "name", "full_name": "name", "maiden_name": "name", "guardian_name": "name", "sex": "sex",
    "postal_code": "postal", "medical_aid_no": "med_aid", "icd10": "icd10", "card_number": "card",
    "bank_account": "bank",
}


def sample_rate(category: str, prof: Profile) -> float:
    """Sample match rate of the chosen category (non-empty rate for categories without a value check)."""
    check = _CHECK_FOR.get(category)
    return prof.rate(check) if check else 1.0


# ------------------------------------------------------------------------------------------ SQL validators
def null_sql(v: str) -> str:
    return f"({v} IS NULL OR trim({v}) = '')"


def id_digits_sql(v: str, pad: bool) -> str:
    if pad:
        return (f"(CASE WHEN regexp_full_match(tscope_digits({v}), '[0-9]{{12}}') THEN '0' || tscope_digits({v}) "
                f"ELSE tscope_digits({v}) END)")
    return f"tscope_digits({v})"


def sa_id_norm_sql(v: str, pad: bool) -> str:
    d = id_digits_sql(v, pad)
    # Only 13-digit values reach the (expensive) Luhn macro.
    return f"(CASE WHEN regexp_full_match({d}, '[0-9]{{13}}') THEN tscope_sa_id_norm({d}) END)"


def match_sql(category: str, v: str, *, date_parser: str | None = None, id_pad: bool = False) -> str:
    """Boolean DuckDB expression: does VARCHAR ``v`` look like a valid value of ``category``?"""
    nn = f"NOT {null_sql(v)}"
    if category in ("sa_id", "guardian_sa_id"):
        return f"({sa_id_norm_sql(v, id_pad)} IS NOT NULL)"
    if category == "passport":
        return f"(tscope_passport_like({v}) AND NOT regexp_full_match(tscope_digits({v}), '[0-9]+'))"
    if category in ("phone", "guardian_phone"):
        return f"(tscope_phone_e164({v}) IS NOT NULL)"
    if category in ("email", "guardian_email"):
        return f"(tscope_email_norm({v}) IS NOT NULL)"
    if category in ("first_name", "last_name", "full_name", "maiden_name", "guardian_name"):
        return f"(coalesce(regexp_full_match(trim({v}), '[\\p{{L}}][\\p{{L}} ''’.\\-]{{0,79}}'), false))"
    if category in ("dob", "record_date"):
        if not date_parser:
            return "false"
        return f"({date_sql(v, date_parser)} IS NOT NULL)"
    if category == "sex":
        vals = ", ".join(f"'{s}'" for s in sorted(SEX_VALUES))
        return f"(upper(trim({v})) IN ({vals}))"
    if category == "postal_code":
        return f"(coalesce(regexp_full_match(trim({v}), '[0-9]{{4}}'), false))"
    if category == "medical_aid_no":
        return (f"(coalesce(regexp_full_match(upper(regexp_replace({v}, '\\s', '', 'g')), "
                f"'[A-Z]{{0,4}}[0-9]{{6,12}}[A-Z0-9]{{0,2}}'), false))")
    if category == "icd10":
        return f"tscope_icd10_like({v})"
    if category == "card_number":
        return f"(CASE WHEN regexp_full_match(tscope_digits({v}), '[0-9]{{13,19}}') THEN tscope_card_like({v}) ELSE false END)"
    if category == "bank_account":
        return f"(coalesce(regexp_full_match(tscope_digits({v}), '[0-9]{{6,16}}'), false))"
    return f"({nn})"


def present_sql(category: str, v: str) -> str:
    """Row-level presence for ``_has_<exposure>`` flags: a non-empty value, except that masked or truncated
    card numbers (fewer than 12 digits, or containing mask characters) do not count as a card number."""
    if category == "card_number":
        return f"(coalesce(regexp_full_match(tscope_digits({v}), '[0-9]{{12,19}}'), false))"
    return f"(NOT {null_sql(v)})"
