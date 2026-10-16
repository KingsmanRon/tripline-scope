"""Masking for operator displays and scrubbing of identifier-like text from logs and messages.

Defence in depth: code paths are written not to emit values at all; these helpers catch mistakes.
"""

from __future__ import annotations

import logging
import re

from .identifiers import card_number_like, luhn_ok, sa_id_ok

_DIGIT_RUN = re.compile(r"(?<![0-9])(?:\d[\s\-]?){12,18}\d(?![0-9])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![0-9A-Za-z])(?:\+27|0027|\b0)[\s\-]?[1-8](?:[\s\-]?\d){8}(?![0-9])")
_SECRETISH = re.compile(r"(?i)(password|pwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s;,'\"]+")
# A maximal hex token of digest length (MD5/SHA-1/SHA-256/SHA-512) containing at least one a-f letter is a hash:
# decimal runs inside it only resemble IDs, cards or phone numbers by coincidence (about 0.15% of SHA-256 values).
_HASH_TOKEN = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9a-fA-F]*[a-fA-F])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
    r"(?![0-9A-Za-z])")

REDACTED = "[redacted]"


def _digit_sub(m: re.Match) -> str:
    digits = re.sub(r"[\s\-]", "", m.group(0))
    if (len(digits) == 13 and sa_id_ok(digits)) or card_number_like(digits) or luhn_ok(digits):
        return REDACTED
    return m.group(0)


def _scrub_segment(text: str) -> str:
    text = _EMAIL.sub(REDACTED, text)
    text = _DIGIT_RUN.sub(_digit_sub, text)
    text = _PHONE.sub(REDACTED, text)
    return text


def scrub_text(text: str | None) -> str:
    """Remove SA-ID-like, card-like, email, SA phone and ``password=...`` patterns from free text.

    Digest-shaped hex tokens (hashes) are left intact."""
    if not text:
        return text or ""
    text = _SECRETISH.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    out, pos = [], 0
    for m in _HASH_TOKEN.finditer(text):
        out.append(_scrub_segment(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_scrub_segment(text[pos:]))
    return "".join(out)


def find_identifier_like(text: str) -> list[str]:
    """Kinds of identifier-like content present in ``text`` (used by leak tests and output guards)."""
    kinds = []
    text = _HASH_TOKEN.sub(" ", text)
    if _EMAIL.search(text):
        kinds.append("email")
    for m in _DIGIT_RUN.finditer(text):
        d = re.sub(r"[\s\-]", "", m.group(0))
        if len(d) == 13 and sa_id_ok(d):
            kinds.append("sa_id")
        elif card_number_like(d):
            kinds.append("card")
    if _PHONE.search(text):
        kinds.append("phone")
    return kinds


def mask(value: object, keep_last: int = 2) -> str:
    """Operator-safe mask: length-preserving bullets with only the last ``keep_last`` characters shown."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= keep_last + 2:
        return "•" * len(s)
    return "•" * (len(s) - keep_last) + s[-keep_last:]


def mask_name(value: object) -> str:
    """Initial plus length, e.g. ``N••••``. Reviewers see full compared fields on the review page only."""
    if not value:
        return ""
    s = str(value)
    return s[0] + "•" * (len(s) - 1)


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            msg = str(record.msg)
        record.msg = scrub_text(msg)
        record.args = ()
        return True


def install_log_scrubbing() -> None:
    root = logging.getLogger()
    if not any(isinstance(f, ScrubFilter) for f in root.filters):
        root.addFilter(ScrubFilter())
    for h in root.handlers:
        if not any(isinstance(f, ScrubFilter) for f in h.filters):
            h.addFilter(ScrubFilter())
