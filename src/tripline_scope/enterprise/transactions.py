"""Transaction evidence: normalised financial-application events → per-transaction evidence state.

This is not Module C's patient matching. It answers, for each financial transaction seen in the evidence, how far
the *evidence* shows it got, and what is missing or contradictory. Every number it produces is a count or sum of
records in the input; it never estimates loss.

Actions (``ACTIONS``) are what a source system recorded. A recorded action becomes a **verified transition** only
when (a) the record's outcome is ``success`` and (b) the transaction already holds the state the action requires
and (c) its timestamp does not precede that state. Anything else is kept as an *attempt* or an *unverified action*
with the reason, never silently applied.

Evidence categories (``CATEGORIES``), strongest first, are mutually exclusive per transaction:

* ``settled_corroborated`` — released, and an **independent** settlement record (a different source from the
  financial application, ``bank_settlement`` family) names the same transaction reference with the identical
  amount (minor units) and currency and a ``settled`` outcome. The application saying "settled" never suffices.
  This category does not imply a ledger posting: ``ledger_posting_verified`` says whether one was recorded.
* ``reversed`` — a verified reversal after posting.
* ``posted`` — verified ledger posting; settlement not corroborated.
* ``released_not_posted`` — verified payment release; no verified posting.
* ``approved_not_released``, ``pending_approval``, ``initiated`` — earlier verified states.
* ``rejected_or_stopped`` — a verified rejection or stop, and nothing verified after it.
* ``undetermined`` — contradictory records, or actions without the record that would establish their predecessor
  (e.g. a release with no creation record), so the state cannot be established.

Monetary totals are kept per (category, currency); currencies are never added together. A transaction is linked
to privilege evidence only through its own sessions (``sessions_with_privilege_evidence``), never because the same
actor held privileges at some other time.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import defaultdict

ACTIONS = (
    "payment_created", "payee_modified", "approval_submitted", "approval_rejected", "approval_completed",
    "payment_released", "payment_stopped", "ledger_posted", "settlement_confirmed", "transaction_reversed",
    "role_assigned", "role_removed", "other",
)
# state names in order of progress (stopped/rejected and reversed are terminal side states)
STATES = ("none", "initiated", "pending_approval", "approved", "released", "posted", "settled", "reversed",
          "rejected_or_stopped")
CATEGORIES = ("settled_corroborated", "reversed", "posted", "released_not_posted", "approved_not_released",
              "pending_approval", "initiated", "rejected_or_stopped", "undetermined")
# action -> (states it may follow, state it produces)
TRANSITIONS = {
    "payment_created": ({"none"}, "initiated"),
    "approval_submitted": ({"initiated"}, "pending_approval"),
    "approval_rejected": ({"pending_approval"}, "rejected_or_stopped"),
    "approval_completed": ({"pending_approval"}, "approved"),
    "payment_released": ({"approved"}, "released"),
    "payment_stopped": ({"initiated", "pending_approval", "approved", "released"}, "rejected_or_stopped"),
    "ledger_posted": ({"released"}, "posted"),
    "transaction_reversed": ({"posted", "settled"}, "reversed"),
}
OUTCOMES = ("success", "failure", "denied", "unknown")


def _ts(v) -> dt.datetime | None:
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.UTC)
    return None


def content_hash(ev: dict) -> str:
    keep = {k: ev.get(k) for k in ("source_system", "event_id", "action", "transaction_ref", "actor", "session_ref",
                                   "target_ref", "outcome", "approval_ref", "amount_minor", "currency", "payee_ref")}
    keep["ts"] = ev["ts_utc"].isoformat() if _ts(ev.get("ts_utc")) else None
    return hashlib.sha256(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()


def dedupe(events: list[dict]) -> tuple[list[dict], dict]:
    """Drop exact duplicates of (source_system, event_id); keep *conflicting* duplicates, each flagged.

    Returns (events, stats). A conflicting duplicate is two records with the same source event id but different
    content: neither is trusted to establish a transition on its own (both carry the ``conflicting_duplicate``
    flag and the transaction is marked contradictory)."""
    seen: dict[tuple, str] = {}
    conflicted: set[tuple] = set()
    out, exact = [], 0
    for ev in events:
        key = (ev.get("source_system"), ev.get("event_id"))
        h = content_hash(ev)
        if key in seen:
            if seen[key] == h:
                exact += 1
                continue
            conflicted.add(key)
        else:
            seen[key] = h
        out.append(ev)
    for ev in out:
        if (ev.get("source_system"), ev.get("event_id")) in conflicted:
            ev.setdefault("flags", []).append("conflicting_duplicate")
    return out, {"exact_duplicates_dropped": exact, "conflicting_duplicate_ids": len(conflicted)}


def _order_key(ev: dict):
    t = _ts(ev.get("ts_utc"))
    return (t is None, t or dt.datetime.min.replace(tzinfo=dt.UTC), ev.get("ordinal") or 0)


def analyse_transaction(tx_ref: str, events: list[dict], settlements: list[dict], *, app_source_ids: set[str]) -> dict:
    """Evidence state of one transaction from its events (any order) and candidate settlement records."""
    evs = sorted(events, key=_order_key)
    state, state_ts = "none", None
    steps, attempts, contradictions, missing, flags = [], [], [], [], set()
    initiators, approvers, releasers, actors, sessions = set(), set(), set(), set(), set()
    amounts, currencies = set(), set()
    approved_ok = rejected = released_unapproved = payee_changed_after_approval = erp_settlement_claim = False
    premature: list[tuple[int, set, str]] = []     # (position, prerequisite states, event) of unverified actions
    reached: list[tuple[int, str]] = []            # (position, state) as states are established
    for pos, ev in enumerate(evs):
        a = ev.get("action") or "other"
        t = _ts(ev.get("ts_utc"))
        actors.add(ev.get("actor"))
        if ev.get("session_ref"):
            sessions.add(ev["session_ref"])
        if ev.get("amount_minor") is not None:
            amounts.add(ev["amount_minor"])
        if ev.get("currency"):
            currencies.add(ev["currency"])
        if t is None:
            flags.add("timestamp_unresolved")
        rec = {"event": ev["ref"], "action": a, "ts_utc": t.isoformat().replace("+00:00", "Z") if t else None,
               "outcome": ev.get("outcome"), "actor": ev.get("actor"), "session": ev.get("session_ref")}
        if "conflicting_duplicate" in (ev.get("flags") or []):
            contradictions.append({"event": ev["ref"], "reason": "two records share this source event id with "
                                                                  "different content"})
            attempts.append(dict(rec, reason="conflicting duplicate record"))
            continue
        if a == "payee_modified":
            if ev.get("outcome") == "success":
                steps.append(dict(rec, transition=None, verified=True, note="payee changed"))
                if state in ("approved", "released", "posted"):
                    payee_changed_after_approval = True
            else:
                attempts.append(dict(rec, reason=f"outcome {ev.get('outcome')}"))
            continue
        if a == "settlement_confirmed":
            # the application's own claim of settlement: kept, but never a settlement on its own
            erp_settlement_claim = ev.get("outcome") == "success"
            steps.append(dict(rec, transition=None, verified=False,
                              note="settlement claimed by the financial application; not independent evidence"))
            continue
        if a not in TRANSITIONS:
            steps.append(dict(rec, transition=None, verified=False, note="action recorded; no state change defined"))
            continue
        if ev.get("outcome") != "success":
            attempts.append(dict(rec, reason=f"outcome {ev.get('outcome') or 'unknown'}: not a state change"))
            if a == "payment_released" and ev.get("outcome") in ("denied", "failure"):
                flags.add("release_attempt_blocked")
            continue
        allowed, new_state = TRANSITIONS[a]
        if a == "payment_created":
            initiators.add(ev.get("actor"))
        if state not in allowed:
            reason = f"requires state {sorted(allowed)}, evidence shows '{state}'"
            if a == "payment_released" and state in ("initiated", "pending_approval") and not rejected:
                released_unapproved = True
                reason += " (no completed approval recorded)"
            premature.append((pos, set(allowed), ev["ref"]))
            if state == "rejected_or_stopped":
                contradictions.append({"event": ev["ref"], "reason": f"{a} recorded after the transaction was "
                                                                      "rejected or stopped"})
            elif state == "none":
                missing.append({"event": ev["ref"], "missing": "payment_created record",
                                "reason": f"{a} recorded with no creation record in the evidence"})
            else:
                missing.append({"event": ev["ref"], "missing": "prior state", "reason": reason})
            steps.append(dict(rec, transition=f"{state}->{new_state}", verified=False, note=reason))
            continue
        if state_ts and t and t < state_ts:
            contradictions.append({"event": ev["ref"], "reason": "timestamp precedes the record that established "
                                                                  "the prior state"})
            steps.append(dict(rec, transition=f"{state}->{new_state}", verified=False,
                              note="timestamp inconsistency: earlier than the prior state"))
            continue
        steps.append(dict(rec, transition=f"{state}->{new_state}", verified=True))
        if a == "approval_completed":
            approved_ok = True
            approvers.add(ev.get("actor"))
        if a == "approval_rejected":
            rejected = True
        if a == "payment_released":
            releasers.add(ev.get("actor"))
        state, state_ts = new_state, t or state_ts
        reached.append((pos, state))
    # an action recorded *before* the record that establishes its prerequisite: the records are out of sequence
    # (timestamp inconsistency) or one is wrong; neither order can be trusted
    for pos, need, ref in premature:
        if any(p > pos and s in need for p, s in reached):
            contradictions.append({"event": ref, "reason": "timestamp inconsistency: recorded before the record that "
                                                           "establishes the state it requires"})
    if len(amounts) > 1:
        contradictions.append({"event": None, "reason": f"{len(amounts)} different amounts recorded"})
    if len(currencies) > 1:
        contradictions.append({"event": None, "reason": f"{len(currencies)} different currencies recorded"})
    amount = next(iter(amounts)) if len(amounts) == 1 else None
    currency = next(iter(currencies)) if len(currencies) == 1 else None

    # independent settlement: different source, exact reference, amount and currency, settled outcome
    settle_match, settle_mismatch = None, []
    for s in settlements:
        if s.get("source_id") in app_source_ids:
            settle_mismatch.append({"settlement": s["ref"], "reason": "settlement record comes from the financial "
                                                                       "application's own source"})
            continue
        ok_amount = amount is not None and s.get("amount_minor") == amount
        ok_cur = currency is not None and s.get("currency") == currency
        if s.get("outcome") == "settled" and ok_amount and ok_cur:
            settle_match = s
        else:
            settle_mismatch.append({"settlement": s["ref"], "reason": "outcome, amount or currency does not match "
                                                                       "the transaction evidence"})
    if settle_match and state not in ("released", "posted", "reversed"):
        contradictions.append({"event": None, "reason": "independent settlement record for a transaction whose "
                                                        "release is not established by the evidence"})
    for m in settle_mismatch:
        contradictions.append({"event": None, "reason": m["reason"], "settlement": m["settlement"]})

    if contradictions:
        category = "undetermined"
    elif settle_match and state in ("released", "posted"):
        category = "settled_corroborated"
    elif state == "reversed":
        category = "reversed"
    elif state == "posted":
        category = "posted"
    elif state == "released":
        category = "released_not_posted"
    elif state == "approved":
        category = "approved_not_released"
    elif state == "pending_approval":
        category = "pending_approval"
    elif state == "initiated":
        category = "initiated"
    elif state == "rejected_or_stopped":
        category = "rejected_or_stopped"
    else:
        category = "undetermined"
    if missing and category not in ("undetermined",):
        # a later verified state with an unverified earlier action still stands; record the gap
        flags.add("missing_transition_records")
    if missing and state == "none":
        category = "undetermined"

    sod = bool(initiators & approvers - {None}) or bool(initiators & releasers - {None} and not approvers)
    indicators = []
    if released_unapproved:
        indicators.append("release_without_completed_approval")
    if sod:
        indicators.append("same_actor_initiated_and_approved")
    if payee_changed_after_approval:
        indicators.append("payee_changed_after_approval")
    if erp_settlement_claim and category != "settled_corroborated":
        indicators.append("settlement_claimed_without_independent_evidence")
    ledger_posting_verified = any(st["verified"] and st["action"] == "ledger_posted" for st in steps)
    return {
        "transaction": tx_ref, "category": category, "evidence_state": state,
        "ledger_posting_verified": ledger_posting_verified,
        "amount_minor": amount, "currency": currency,
        "actors": sorted(a for a in actors if a), "sessions": sorted(sessions),
        "approvers": sorted(a for a in approvers if a), "approval_completed": approved_ok,
        "steps": steps, "attempts": attempts, "contradictions": contradictions, "missing": missing,
        "approval_indicators": indicators, "flags": sorted(flags),
        "settlement": ({"record": settle_match["ref"], "source": settle_match["source_id"],
                        "amount_minor": settle_match["amount_minor"], "currency": settle_match["currency"],
                        "value_date": settle_match.get("value_date")} if settle_match and category == "settled_corroborated"
                       else None),
    }


def analyse(events: list[dict], settlements: list[dict], *, app_source_ids: set[str],
            suspicious_sessions: dict[str, list[str]], sessions_with_privilege_evidence: set[str]) -> dict:
    """All transactions. ``suspicious_sessions`` maps a session ref to the reasons it is flagged;
    ``sessions_with_privilege_evidence`` are the session refs whose own privilege link found privilege events for
    that session's account inside the configured window (a *correlated* link: account and time)."""
    events, dup = dedupe(events)
    by_tx = defaultdict(list)
    no_ref = 0
    for ev in events:
        if ev.get("transaction_ref"):
            by_tx[ev["transaction_ref"]].append(ev)
        elif ev.get("action") not in ("role_assigned", "role_removed", "other"):
            no_ref += 1
    settle_by_tx = defaultdict(list)
    for s in settlements:
        settle_by_tx[s.get("transaction_ref")].append(s)
    txs = []
    for ref in sorted(by_tx):
        t = analyse_transaction(ref, by_tx[ref], settle_by_tx.get(ref, []), app_source_ids=app_source_ids)
        reasons = sorted({r for s in t["sessions"] for r in suspicious_sessions.get(s, [])})
        t["suspicious_session_reasons"] = reasons
        t["sessions_with_privilege_evidence"] = sorted(set(t["sessions"]) & sessions_with_privilege_evidence)
        t["privilege_link"] = "correlated" if t["sessions_with_privilege_evidence"] else "none_observed"
        t["suspicious"] = bool(reasons) or bool(t["approval_indicators"])
        txs.append(t)
    orphan_settlements = [s["ref"] for ref, ss in settle_by_tx.items() if ref not in by_tx for s in ss]
    return {"transactions": txs, "duplicates": dup, "events_without_transaction_ref": no_ref,
            "settlements_without_transaction": orphan_settlements, "counts": counts(txs)}


def counts(txs: list[dict]) -> dict:
    """Only quantities the evidence supports. Totals per (category, currency); unknown amounts counted, not summed."""
    by_cat = {c: 0 for c in CATEGORIES}
    amount_unknown: dict[str, int] = defaultdict(int)
    for t in txs:
        by_cat[t["category"]] += 1
        if t["amount_minor"] is None or not t["currency"]:
            amount_unknown[t["category"]] += 1
    sus = [t for t in txs if t["suspicious"]]
    return {
        "transactions": len(txs),
        "by_category": by_cat,
        "suspicious_transactions": len(sus),
        "linked_to_sessions_with_privilege_evidence": sum(1 for t in txs if t["sessions_with_privilege_evidence"]),
        "rejected_or_stopped": by_cat["rejected_or_stopped"],
        "ledger_posting_verified": sum(1 for t in txs if t["ledger_posting_verified"]),
        "settled_corroborated": by_cat["settled_corroborated"],
        "settled_corroborated_without_ledger_posting": sum(1 for t in txs if t["category"] == "settled_corroborated"
                                                           and not t["ledger_posting_verified"]),
        "unresolved": by_cat["undetermined"],
        "release_attempts_blocked": sum(1 for t in txs if "release_attempt_blocked" in t["flags"]),
        "amount_totals_minor_by_category": _totals(txs),
        "amount_unknown_by_category": dict(sorted(amount_unknown.items())),
        "suspicious_by_category": {c: sum(1 for t in sus if t["category"] == c) for c in CATEGORIES
                                   if any(t["category"] == c for t in sus)},
        "suspicious_amount_totals_minor_by_category": _totals(sus),
    }


def _totals(txs: list[dict]) -> dict:
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for t in txs:
        if t["amount_minor"] is not None and t["currency"]:
            out[t["category"]][t["currency"]] += t["amount_minor"]
    return {c: dict(sorted(v.items())) for c, v in sorted(out.items())}
