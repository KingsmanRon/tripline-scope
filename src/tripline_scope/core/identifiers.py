"""Identifier validation and normalisation (Python reference implementations and DuckDB SQL macros).

The SQL macros are registered on every hardened DuckDB connection (see :mod:`tripline_scope.core.duck`) so
full-table scans run vectorised; tests assert the SQL and Python versions agree.
"""

from __future__ import annotations

import datetime as dt
import re
import unicodedata
from dataclasses import dataclass

_NON_DIGIT = re.compile(r"[\s\-]")


# ------------------------------------------------------------------------------------------ Luhn
def luhn_ok(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(partial: str) -> str:
    for c in "0123456789":
        if luhn_ok(partial + c):
            return c
    raise ValueError("no check digit")


# ------------------------------------------------------------------------------------------ SA ID
@dataclass(frozen=True)
class SAID:
    valid: bool
    dob_candidates: tuple[dt.date, ...] = ()
    sex: str | None = None
    citizenship: str | None = None

    def dob(self, reference: dt.date | None = None) -> dt.date | None:
        """Best single date of birth: the latest candidate not after ``reference`` (default today)."""
        ref = reference or dt.date.today()
        ok = [d for d in self.dob_candidates if d <= ref]
        return max(ok) if ok else None


def _date_or_none(y: int, m: int, d: int) -> dt.date | None:
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def parse_sa_id(value: object) -> SAID:
    """Validate a South African ID number: 13 digits, real YYMMDD date (either century), citizenship digit
    0/1/2, Luhn check digit. Returns the possible dates of birth (century is ambiguous from the ID alone)."""
    if value is None:
        return SAID(False)
    s = _NON_DIGIT.sub("", str(value))
    if len(s) != 13 or not s.isdigit():
        return SAID(False)
    yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    cands = tuple(d for d in (_date_or_none(1900 + yy, mm, dd), _date_or_none(2000 + yy, mm, dd)) if d)
    if not cands or s[10] not in "012" or not luhn_ok(s):
        return SAID(False)
    sex = "F" if int(s[6:10]) < 5000 else "M"
    cit = {"0": "citizen", "1": "permanent_resident", "2": "refugee"}[s[10]]
    return SAID(True, cands, sex, cit)


def sa_id_ok(value: object) -> bool:
    return parse_sa_id(value).valid


def normalise_sa_id(value: object) -> str | None:
    if value is None:
        return None
    s = _NON_DIGIT.sub("", str(value))
    return s if parse_sa_id(s).valid else None


def sa_id_dob_consistent(sa_id: str, dob: dt.date | None) -> bool:
    """True when ``dob`` matches one of the ID's possible dates of birth, or when no DOB is recorded."""
    p = parse_sa_id(sa_id)
    if not p.valid:
        return False
    return dob is None or dob in p.dob_candidates


def make_sa_id(dob: dt.date, sequence: int, citizenship: int = 0, race_digit: int = 8) -> str:
    """Build a structurally valid SA ID (used only by the synthetic data generator and tests)."""
    base = f"{dob:%y%m%d}{sequence:04d}{citizenship}{race_digit}"
    return base + luhn_check_digit(base)


# ------------------------------------------------------------------------------------------ phones / email
def normalise_phone(value: object, default_country: str = "27") -> str | None:
    """Normalise to E.164. South African local formats (0XX..., 27XX..., 9-digit mobile without 0) map to +27."""
    if value is None:
        return None
    s = re.sub(r"[^0-9+]", "", str(value))
    if not s:
        return None
    if s.startswith("00"):
        s = "+" + s[2:]
    if s.startswith("+"):
        digits = s[1:]
        if not digits.isdigit():
            return None
        if digits.startswith("27"):
            return s if re.fullmatch(r"27[1-8]\d{8}", digits) else None
        return s if re.fullmatch(r"[1-9]\d{7,14}", digits) else None
    if re.fullmatch(r"0[1-8]\d{8}", s):
        return "+" + default_country + s[1:]
    if re.fullmatch(r"27[1-8]\d{8}", s):
        return "+" + s
    if re.fullmatch(r"[6-8]\d{8}", s):
        return "+" + default_country + s
    return None


_EMAIL = re.compile(r"^[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def normalise_email(value: object) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    return s if _EMAIL.match(s) else None


# ------------------------------------------------------------------------------------------ names
def normalise_name(value: object) -> str | None:
    if value is None:
        return None
    s = unicodedata.normalize("NFKD", str(value))
    s = "".join(c for c in s if not unicodedata.combining(c)).upper()
    s = re.sub(r"[^A-Z \-']", " ", s)
    s = re.sub(r"['\-]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or None


_SOUNDEX = {**dict.fromkeys("BFPV", "1"), **dict.fromkeys("CGJKQSXZ", "2"), **dict.fromkeys("DT", "3"),
            "L": "4", **dict.fromkeys("MN", "5"), "R": "6"}


def soundex(value: object) -> str | None:
    name = normalise_name(value)
    if not name:
        return None
    name = name.replace(" ", "")
    first = name[0]
    out = [first]
    last = _SOUNDEX.get(first, "")
    for ch in name[1:]:
        code = _SOUNDEX.get(ch, "")
        if code and code != last:
            out.append(code)
        if ch not in "HW":
            last = code
    return ("".join(out) + "000")[:4]


# ------------------------------------------------------------------------------------------ other formats
_PASSPORT = re.compile(r"^[A-Z]{1,2}\d{6,9}$")
_ICD10 = re.compile(r"^[A-TV-Z]\d[0-9AB](\.?[0-9A-KXZ]{1,4})?$")
_CARD_PREFIX = re.compile(r"^(4|5[1-5]|2[2-7]|3[47]|6(011|5)|30[0-5]|36|38|35)")


def passport_like(value: object) -> bool:
    return bool(value) and bool(_PASSPORT.match(re.sub(r"\s", "", str(value)).upper()))


def icd10_like(value: object) -> bool:
    return bool(value) and bool(_ICD10.match(str(value).strip().upper()))


def card_number_like(value: object) -> bool:
    if value is None:
        return False
    s = re.sub(r"[\s\-]", "", str(value))
    return 13 <= len(s) <= 19 and s.isdigit() and bool(_CARD_PREFIX.match(s)) and luhn_ok(s)


def medical_aid_like(value: object) -> bool:
    if value is None:
        return False
    s = re.sub(r"\s", "", str(value)).upper()
    return bool(re.fullmatch(r"[A-Z]{0,4}\d{6,12}[A-Z0-9]{0,2}", s))


# ------------------------------------------------------------------------------------------ DuckDB macros
def _sa_id_macros() -> str:
    """SA ID check as pure arithmetic over a 13-character digit string (unrolled Luhn, calendar check without
    strptime): about 5x faster than a lambda/strptime version on full scans. Feb 29 is valid when YY % 4 == 0
    because either 19YY or 20YY is then a leap year (YY = 00 → 2000)."""

    def dig(i: int) -> str:
        return f"(ascii(substr(d, {i}, 1)) - 48)"

    terms = []
    for i in range(13):
        d = dig(i + 1)
        terms.append(f"(CASE WHEN {d} * 2 > 9 THEN {d} * 2 - 9 ELSE {d} * 2 END)" if (12 - i) % 2 == 1 else d)
    yy, mm, dd = (f"({dig(1)} * 10 + {dig(2)})", f"({dig(3)} * 10 + {dig(4)})", f"({dig(5)} * 10 + {dig(6)})")
    return (
        "CREATE OR REPLACE MACRO tscope_sa_id_ok_digits(d) AS coalesce(regexp_full_match(d, '[0-9]{13}')\n"
        f"  AND {mm} BETWEEN 1 AND 12 AND {dd} >= 1\n"
        f"  AND {dd} <= CASE WHEN {mm} IN (1, 3, 5, 7, 8, 10, 12) THEN 31 WHEN {mm} IN (4, 6, 9, 11) THEN 30\n"
        f"                   WHEN {yy} % 4 = 0 THEN 29 ELSE 28 END\n"
        "  AND substr(d, 11, 1) IN ('0', '1', '2')\n"
        f"  AND (({' + '.join(terms)}) % 10 = 0), false);\n"
        "CREATE OR REPLACE MACRO tscope_sa_id_ok(s) AS tscope_sa_id_ok_digits(\n"
        "  CASE WHEN length(CAST(s AS VARCHAR)) = 13 THEN CAST(s AS VARCHAR) ELSE tscope_digits(s) END);\n"
    )


# DuckDB does not short-circuit AND, so every step uses TRY_CAST and COALESCE.
DUCKDB_MACROS = r"""
CREATE OR REPLACE MACRO tscope_digits(s) AS regexp_replace(CAST(s AS VARCHAR), '[\s\-]', '', 'g');
CREATE OR REPLACE MACRO tscope_luhn_ok(d) AS (
  coalesce(regexp_full_match(d, '[0-9]+'), false) AND coalesce(list_sum(list_transform(range(length(d)), lambda i:
    CASE WHEN (length(d) - 1 - i) % 2 = 1 THEN
      CASE WHEN coalesce(try_cast(substr(d, i + 1, 1) AS INTEGER), 0) * 2 > 9
           THEN coalesce(try_cast(substr(d, i + 1, 1) AS INTEGER), 0) * 2 - 9
           ELSE coalesce(try_cast(substr(d, i + 1, 1) AS INTEGER), 0) * 2 END
    ELSE coalesce(try_cast(substr(d, i + 1, 1) AS INTEGER), 0) END)) % 10 = 0, false));
__SA_ID_MACROS__
CREATE OR REPLACE MACRO tscope_sa_id_norm(s) AS CASE WHEN tscope_sa_id_ok(s) THEN tscope_digits(s) ELSE NULL END;
CREATE OR REPLACE MACRO tscope_phone_raw(s) AS regexp_replace(CAST(s AS VARCHAR), '[^0-9+]', '', 'g');
CREATE OR REPLACE MACRO tscope_phone_pre(s) AS CASE WHEN starts_with(tscope_phone_raw(s), '00')
  THEN '+' || substr(tscope_phone_raw(s), 3) ELSE tscope_phone_raw(s) END;
CREATE OR REPLACE MACRO tscope_phone_e164(s) AS CASE
  WHEN regexp_full_match(tscope_phone_pre(s), '\+27[1-8][0-9]{8}') THEN tscope_phone_pre(s)
  WHEN regexp_full_match(tscope_phone_pre(s), '\+27.*') THEN NULL
  WHEN regexp_full_match(tscope_phone_pre(s), '\+[1-9][0-9]{7,14}') THEN tscope_phone_pre(s)
  WHEN regexp_full_match(tscope_phone_pre(s), '0[1-8][0-9]{8}') THEN '+27' || substr(tscope_phone_pre(s), 2)
  WHEN regexp_full_match(tscope_phone_pre(s), '27[1-8][0-9]{8}') THEN '+' || tscope_phone_pre(s)
  WHEN regexp_full_match(tscope_phone_pre(s), '[6-8][0-9]{8}') THEN '+27' || tscope_phone_pre(s)
  ELSE NULL END;
CREATE OR REPLACE MACRO tscope_email_norm(s) AS CASE
  WHEN regexp_full_match(lower(trim(CAST(s AS VARCHAR))), '[a-z0-9._%+''\-]+@[a-z0-9.\-]+\.[a-z]{2,}')
  THEN lower(trim(CAST(s AS VARCHAR))) ELSE NULL END;
CREATE OR REPLACE MACRO tscope_name_norm(s) AS nullif(trim(regexp_replace(regexp_replace(regexp_replace(
  upper(strip_accents(CAST(s AS VARCHAR))), '[^A-Z \-'']', ' ', 'g'), '[''\-]', '', 'g'), '\s+', ' ', 'g')), '');
CREATE OR REPLACE MACRO tscope_card_like(s) AS coalesce(
  regexp_full_match(tscope_digits(s), '(4|5[1-5]|2[2-7]|3[47]|6011|65|30[0-5]|36|38|35)[0-9]{11,17}')
  AND length(tscope_digits(s)) BETWEEN 13 AND 19 AND tscope_luhn_ok(tscope_digits(s)), false);
CREATE OR REPLACE MACRO tscope_icd10_like(s) AS coalesce(
  regexp_full_match(upper(trim(CAST(s AS VARCHAR))), '[A-TV-Z][0-9][0-9AB](\.?[0-9A-KXZ]{1,4})?'), false);
CREATE OR REPLACE MACRO tscope_passport_like(s) AS coalesce(
  regexp_full_match(upper(regexp_replace(CAST(s AS VARCHAR), '\s', '', 'g')), '[A-Z]{1,2}[0-9]{6,9}'), false);
""".replace("__SA_ID_MACROS__\n", _sa_id_macros())
