"""Financial-application audit and independent settlement records (families ``fin_app_audit``, ``bank_settlement``).

A narrowly scoped, configurable adapter for normalised exports of a financial application's audit trail and of a
bank's settlement statement. Input is CSV, JSON or JSON Lines; each record is read through a documented field set
(``docs/ENTERPRISE_FINANCIAL_INCIDENT.md`` §3). ``mapping.fields`` renames source columns onto that field set, and
``mapping.action_map`` / ``outcome_map`` translate the system's own words; only mapped fields are read.

``fin_app_audit`` fields (``*`` required): ``event_id*, timestamp*, source_system*, actor_reference*, action*,
outcome*, evidence_source_id*, session_reference, target_reference, transaction_reference, approval_reference,
amount, currency, payee_reference, idp_correlation_id, client_host, target_account``.

``bank_settlement`` fields: ``event_id*, timestamp*, transaction_reference*, amount*, currency*, outcome*,
evidence_source_id*, source_system, bank_reference, payee_reference``.

Rules (a failing record is not stored: it is counted with its locator and reason, never silently repaired):

* timestamps go through the shared normaliser (``iso8601`` by default; zone from the record or the manifest);
* ``action`` must map onto :data:`ACTIONS` (else it is kept as ``other`` and flagged ``unmapped_action``);
* ``amount`` is a non-negative decimal with no more fraction digits than the currency allows; it is stored as an
  integer in minor units (``amount_minor``) with its ISO 4217 code -- an amount without a known currency is a
  failure, never guessed;
* ``payee_reference`` (often an account number) is stored only as a keyed fingerprint (``counterparty_ref``);
* a source ``event_id`` seen twice in one source is kept and flagged ``duplicate_source_event_id`` (the
  transaction analysis decides whether it is an exact duplicate or a conflicting one).

Column mapping into the Module B event schema: ``actor_reference``→``account``, ``session_reference``→
``session_id``, ``action``→``operation``, ``source_system``→``application``, ``target_reference``→``object_name``,
source ``event_id``→``event_code``, ``idp_correlation_id``→``correlation_id``, plus the additive financial columns
``txn_ref, approval_ref, evidence_ref, amount_minor, currency, counterparty_ref``.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from tripline_scope.core.redact import scrub_text

from ..timenorm import parse_with_format
from .base import ParseContext, blank
from .generic import _get, _records

VERSION = "1.0"

ACTIONS = (
    "payment_created", "payee_modified", "approval_submitted", "approval_rejected", "approval_completed",
    "payment_released", "payment_stopped", "ledger_posted", "settlement_confirmed", "transaction_reversed",
    "role_assigned", "role_removed", "other",
)
SETTLEMENT_OUTCOMES = ("settled", "returned", "pending", "rejected")
APP_FIELDS = ("event_id", "timestamp", "source_system", "actor_reference", "action", "outcome", "evidence_source_id",
              "session_reference", "target_reference", "transaction_reference", "approval_reference", "amount",
              "currency", "payee_reference", "idp_correlation_id", "client_host", "target_account")
APP_REQUIRED = ("event_id", "timestamp", "source_system", "actor_reference", "action", "outcome", "evidence_source_id")
BANK_FIELDS = ("event_id", "timestamp", "transaction_reference", "amount", "currency", "outcome", "evidence_source_id",
               "source_system", "bank_reference", "payee_reference")
BANK_REQUIRED = ("event_id", "timestamp", "transaction_reference", "amount", "currency", "outcome",
                 "evidence_source_id")
# ISO 4217 minor-unit exponents for the currencies this release accepts. An unlisted code is refused, not guessed.
CURRENCY_EXPONENT = {"ZAR": 2, "USD": 2, "EUR": 2, "GBP": 2, "CHF": 2, "AUD": 2, "CAD": 2, "CNY": 2, "BWP": 2,
                     "NAD": 2, "MZN": 2, "ZMW": 2, "KES": 2, "NGN": 2, "JPY": 0, "KRW": 0, "BHD": 3, "KWD": 3}
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,79}$")


def validate_mapping(mapping: dict | None, family: str) -> None:
    from tripline_scope.core.errors import ConfigError

    m = mapping or {}
    allowed = APP_FIELDS if family == "fin_app_audit" else BANK_FIELDS
    bad = set(m.get("fields") or {}) - set(allowed)
    if bad:
        raise ConfigError(f"{family} mapping names unknown fields: {sorted(bad)}")
    if family == "fin_app_audit":
        badact = {v for v in (m.get("action_map") or {}).values()} - set(ACTIONS)
        if badact:
            raise ConfigError(f"{family} action_map targets are not known actions: {sorted(badact)}")


def amount_minor(text, currency: str | None) -> tuple[int | None, str | None]:
    """(minor units, error). ``currency`` must already be validated."""
    if text is None or str(text).strip() == "":
        return None, None
    if currency is None:
        return None, "amount without a currency"
    exp = CURRENCY_EXPONENT[currency]
    s = str(text).strip().replace(" ", "")
    if not re.fullmatch(r"\d+(\.\d+)?", s):
        return None, "amount is not a non-negative decimal number"
    try:
        d = Decimal(s)
    except InvalidOperation:
        return None, "amount is not a decimal number"
    if -d.as_tuple().exponent > exp:
        return None, f"amount has more fraction digits than {currency} allows"
    return int(d.scaleb(exp)), None


def _currency(v) -> tuple[str | None, str | None]:
    c = blank(v)
    if c is None:
        return None, None
    c = c.strip().upper()
    if c not in CURRENCY_EXPONENT:
        return None, "currency is not a supported ISO 4217 code"
    return c, None


def _ref(v) -> str | None:
    v = blank(v)
    if v is None:
        return None
    v = v.strip()
    return v if _REF.match(v) else None


def parse(ctx: ParseContext, stream, relname: str):
    family = ctx.family
    m = ctx.mapping or {}
    validate_mapping(m, family)
    names = APP_FIELDS if family == "fin_app_audit" else BANK_FIELDS
    required = APP_REQUIRED if family == "fin_app_audit" else BANK_REQUIRED
    fmap = {f: (m.get("fields") or {}).get(f, f) for f in names}
    tsfmt = m.get("timestamp_format", "iso8601")
    act_map = {str(k).lower(): v for k, v in (m.get("action_map") or {}).items()}
    out_map = {str(k).lower(): v for k, v in (m.get("outcome_map") or {}).items()}
    seen: set[str] = set()
    for loc, d, raw in _records(ctx, stream, relname):
        if d is None:
            ctx.fail(loc, "record could not be read with the declared format")
            continue
        v = {f: _get(d, fmap[f]) for f in names}
        missing = [f for f in required if v.get(f) is None or str(v[f]).strip() == ""]
        if missing:
            ctx.fail(loc, "missing required field(s): " + ", ".join(missing))
            continue
        ts, prec, abbr = parse_with_format(str(v["timestamp"]), tsfmt)
        if ts is None:
            ctx.fail(loc, "timestamp does not match timestamp_format")
            continue
        src_event = _ref(v["event_id"])
        if src_event is None:
            ctx.fail(loc, "event_id is not a plain identifier")
            continue
        currency, cerr = _currency(v.get("currency"))
        if cerr:
            ctx.fail(loc, cerr)
            continue
        amt, aerr = amount_minor(v.get("amount"), currency)
        if aerr:
            ctx.fail(loc, aerr)
            continue
        txn = _ref(v.get("transaction_reference"))
        if v.get("transaction_reference") not in (None, "") and txn is None:
            ctx.fail(loc, "transaction_reference is not a plain identifier")
            continue
        flags = []
        if src_event in seen:
            flags.append("duplicate_source_event_id")
        seen.add(src_event)
        outcome_raw = str(v["outcome"]).strip().lower()
        outcome_raw = str(out_map.get(outcome_raw, outcome_raw)).lower()
        payee = blank(v.get("payee_reference"))
        rec: dict = {
            "_raw": raw, "_loc": loc, "_ts": (ts, prec, abbr), "host": ctx.host, "flags": flags,
            "event_code": src_event, "application": scrub_text(str(v.get("source_system") or family))[:80],
            "txn_ref": txn, "evidence_ref": _ref(v.get("evidence_source_id")), "amount_minor": amt, "currency": currency,
            "counterparty_ref": ("CPTY-" + ctx.file_fp("payee:" + payee.strip().lower())[:12]) if payee else None,
        }
        if family == "bank_settlement":
            if outcome_raw not in SETTLEMENT_OUTCOMES:
                ctx.fail(loc, "settlement outcome must be one of " + "/".join(SETTLEMENT_OUTCOMES))
                continue
            rec.update(operation="settlement_" + outcome_raw, observation_type="settlement_record",
                       outcome="success" if outcome_raw == "settled" else "failure",
                       object_name=_ref(v.get("bank_reference")))
            rec["flags"].append("settlement_outcome:" + outcome_raw)
        else:
            action = act_map.get(str(v["action"]).strip().lower(), str(v["action"]).strip().lower())
            if action not in ACTIONS:
                flags.append("unmapped_action")
                action = "other"
            if outcome_raw in ("denied", "blocked", "rejected_by_control"):
                outcome = "failure"
                flags.append("outcome_denied")
            elif outcome_raw in ("success", "failure", "unknown"):
                outcome = outcome_raw
            else:
                outcome = "unknown"
            obs = {"role_assigned": "privilege_change", "role_removed": "privilege_revoke"}.get(action, "financial_action")
            target = blank(v.get("target_reference"))
            rec.update(account=blank(v["actor_reference"]), session_id=_ref(v.get("session_reference")),
                       operation=action, observation_type=obs, outcome=outcome,
                       object_name=scrub_text(target)[:120] if target else None,
                       approval_ref=_ref(v.get("approval_reference")),
                       correlation_id=_ref(v.get("idp_correlation_id")),
                       client_host=_ref(v.get("client_host")), target_account=blank(v.get("target_account")))
        yield rec
