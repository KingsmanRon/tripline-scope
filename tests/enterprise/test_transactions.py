"""Transaction evidence: verified transitions, attempts, contradictions, duplicates, timestamps, independent
settlement and per-currency totals. Pure unit tests over normalised events."""

import datetime as dt

from tripline_scope.enterprise import transactions as T

T0 = dt.datetime(2026, 9, 5, 22, 0, tzinfo=dt.UTC)
APP, BANK = "SRC-APP", "SRC-BANK"


def ev(n, action, *, txn="PAY-1", outcome="success", minutes=0, actor="ACCT-a", session="FSN-1", amount=100000,
       currency="ZAR", ts=True, event_id=None, **extra):
    return {"ref": f"{APP}:{n}", "event_id": event_id or f"FA-{n}", "source_system": "ERP",
            "ts_utc": T0 + dt.timedelta(minutes=minutes) if ts else None, "ordinal": n, "action": action,
            "outcome": outcome, "actor": actor, "session_ref": session, "transaction_ref": txn, "amount_minor": amount,
            "currency": currency, **extra}


def settle(n, *, txn="PAY-1", amount=100000, currency="ZAR", outcome="settled", source=BANK):
    return {"ref": f"{source}:{n}", "source_id": source, "transaction_ref": txn, "amount_minor": amount,
            "currency": currency, "outcome": outcome, "value_date": "2026-09-07T09:00:00Z"}


def full_chain(**kw):
    return [ev(1, "payment_created", minutes=0, **kw), ev(2, "approval_submitted", minutes=1, **kw),
            ev(3, "approval_completed", minutes=2, actor="ACCT-b", **kw), ev(4, "payment_released", minutes=3, **kw),
            ev(5, "ledger_posted", minutes=4, **kw)]


def one(events, settlements=(), **kw):
    r = T.analyse(events, list(settlements), app_source_ids={APP}, suspicious_sessions=kw.get("sus", {}),
                  privileged_actors=kw.get("priv", set()))
    return r, {t["transaction"]: t for t in r["transactions"]}


def test_full_chain_with_independent_settlement_is_corroborated():
    r, tx = one(full_chain(), [settle(1)])
    t = tx["PAY-1"]
    assert t["category"] == "settled_corroborated" and t["settlement"]["record"] == "SRC-BANK:1"
    assert all(s["verified"] for s in t["steps"]) and not t["contradictions"]
    assert r["counts"]["settled_corroborated"] == 1 and r["counts"]["posted"] == 1


def test_application_settlement_claim_is_not_settlement():
    evs = full_chain() + [ev(6, "settlement_confirmed", minutes=600)]
    _, tx = one(evs)
    assert tx["PAY-1"]["category"] == "posted"
    assert "settlement_claimed_without_independent_evidence" in tx["PAY-1"]["approval_indicators"]
    # a settlement record from the application's own source is not independent either
    _, tx = one(full_chain(), [settle(1, source=APP)])
    assert tx["PAY-1"]["category"] == "undetermined"


def test_settlement_must_match_amount_and_currency_exactly():
    for bad in (settle(1, amount=100001), settle(1, currency="USD"), settle(1, outcome="returned")):
        _, tx = one(full_chain(), [bad])
        assert tx["PAY-1"]["category"] == "undetermined", bad
        assert tx["PAY-1"]["settlement"] is None


def test_settlement_without_release_is_a_contradiction():
    _, tx = one(full_chain()[:3], [settle(1)])
    assert tx["PAY-1"]["category"] == "undetermined"
    assert any("release is not established" in c["reason"] for c in tx["PAY-1"]["contradictions"])


def test_payment_initiation_is_not_money_movement():
    _, tx = one([ev(1, "payment_created")])
    assert tx["PAY-1"]["category"] == "initiated"
    _, tx = one(full_chain()[:3])
    assert tx["PAY-1"]["category"] == "approved_not_released"


def test_rejected_and_denied_release_are_stopped_attempts():
    evs = [ev(1, "payment_created"), ev(2, "approval_submitted", minutes=1),
           ev(3, "payment_released", outcome="failure", minutes=2), ev(4, "approval_rejected", actor="ACCT-b", minutes=9)]
    r, tx = one(evs)
    t = tx["PAY-1"]
    assert t["category"] == "rejected_or_stopped" and "release_attempt_blocked" in t["flags"]
    assert [a["action"] for a in t["attempts"]] == ["payment_released"]
    assert r["counts"]["rejected_or_stopped"] == 1 and r["counts"]["release_attempts_blocked"] == 1


def test_action_after_rejection_is_a_contradiction():
    evs = [ev(1, "payment_created"), ev(2, "approval_submitted", minutes=1),
           ev(3, "approval_rejected", minutes=2), ev(4, "payment_released", minutes=3)]
    _, tx = one(evs)
    assert tx["PAY-1"]["category"] == "undetermined"
    assert any("rejected or stopped" in c["reason"] for c in tx["PAY-1"]["contradictions"])


def test_release_without_approval_is_flagged_not_applied():
    evs = [ev(1, "payment_created"), ev(2, "approval_submitted", minutes=1), ev(3, "payment_released", minutes=2)]
    _, tx = one(evs)
    t = tx["PAY-1"]
    assert t["category"] == "pending_approval"            # the release record did not establish a release
    assert "release_without_completed_approval" in t["approval_indicators"]
    assert any(not s["verified"] and s["action"] == "payment_released" for s in t["steps"])


def test_missing_creation_record_is_undetermined():
    _, tx = one([ev(1, "ledger_posted")])
    t = tx["PAY-1"]
    assert t["category"] == "undetermined" and t["missing"][0]["missing"] == "payment_created record"


def test_timestamp_before_prior_state_is_not_a_verified_transition():
    evs = [ev(1, "payment_created", minutes=10), ev(2, "approval_submitted", minutes=11),
           ev(3, "approval_completed", minutes=12), ev(4, "payment_released", minutes=13, ts=True)]
    evs[3]["ts_utc"] = T0 + dt.timedelta(minutes=12)   # released at the same minute as approval: allowed
    _, tx = one(evs)
    assert tx["PAY-1"]["category"] == "released_not_posted"
    evs2 = [ev(1, "payment_created", minutes=10), ev(2, "approval_submitted", minutes=11)]
    evs2.append(ev(3, "approval_completed", minutes=12))
    evs2[2]["ordinal"] = 1                                # ordinal says first ...
    evs2[0]["ts_utc"] = None                              # ... and the creation record has no usable time
    _, tx = one(evs2)
    assert "timestamp_unresolved" in tx["PAY-1"]["flags"]


def test_out_of_order_timestamps_flag_a_contradiction():
    evs = [ev(1, "payment_created", minutes=10), ev(2, "approval_submitted", minutes=11),
           ev(3, "approval_completed", minutes=12), ev(4, "payment_released", minutes=13)]
    # a second release-like posting recorded with a time before the release that it depends on
    evs.append(ev(5, "ledger_posted", minutes=13))
    evs[4]["ts_utc"] = T0 + dt.timedelta(minutes=13)
    _, tx = one(evs)
    assert tx["PAY-1"]["category"] == "posted"
    late = [ev(1, "payment_created", minutes=10), ev(2, "approval_submitted", minutes=11),
            ev(3, "approval_completed", minutes=12)]
    late[2]["ts_utc"] = T0 + dt.timedelta(minutes=11, seconds=30)
    late.append(ev(4, "payment_released", minutes=12))
    late[3]["ts_utc"] = T0 + dt.timedelta(minutes=11)       # earlier than the approval it requires
    _, tx = one(late)
    t = tx["PAY-1"]
    assert t["category"] == "undetermined"
    assert any("timestamp" in c["reason"] for c in t["contradictions"])


def test_exact_duplicates_dropped_conflicting_duplicates_flagged():
    evs = full_chain()
    evs.append(dict(evs[0], ref=f"{APP}:99", ordinal=99))       # same source event id and content: exact duplicate
    r, tx = one(evs)
    assert r["duplicates"] == {"exact_duplicates_dropped": 1, "conflicting_duplicate_ids": 0}
    assert tx["PAY-1"]["category"] == "posted"
    evs = full_chain()
    evs.append(dict(evs[3], ref=f"{APP}:98", ordinal=98, amount_minor=999999))   # same id, different content
    r, tx = one(evs)
    assert r["duplicates"]["conflicting_duplicate_ids"] == 1
    assert tx["PAY-1"]["category"] == "undetermined"


def test_multiple_amounts_or_currencies_are_contradictory():
    evs = full_chain()
    evs[4] = dict(evs[4], amount_minor=200000)
    _, tx = one(evs)
    assert tx["PAY-1"]["category"] == "undetermined" and tx["PAY-1"]["amount_minor"] is None


def test_currency_totals_are_never_mixed():
    evs = full_chain(txn="PAY-Z", currency="ZAR", amount=1_000_00) + \
        [dict(e, ref=e["ref"] + "u", event_id=e["event_id"] + "u") for e in full_chain(txn="PAY-U", currency="USD", amount=500_00)] + \
        [dict(e, ref=e["ref"] + "z", event_id=e["event_id"] + "z") for e in full_chain(txn="PAY-Z2", currency="ZAR", amount=250_00)]
    r, _ = one(evs, sus={"FSN-1": ["supplier_outside_window"]})
    tot = r["counts"]["amount_totals_minor_by_category"]
    assert tot == {"posted": {"USD": 50000, "ZAR": 125000}}
    assert r["counts"]["suspicious_amount_totals_minor_by_category"] == tot


def test_unknown_amount_counted_not_summed():
    _, _ = one([ev(1, "payment_created", amount=None, currency=None)])
    r, _ = one([ev(1, "payment_created", amount=None, currency=None)])
    assert r["counts"]["amount_unknown_by_category"] == {"initiated": 1}
    assert r["counts"]["amount_totals_minor_by_category"] == {}


def test_suspicion_and_privilege_links_and_segregation_of_duties():
    evs = [ev(1, "payment_created", actor="ACCT-x", session="FSN-s"), ev(2, "approval_submitted", minutes=1, actor="ACCT-x", session="FSN-s"),
           ev(3, "approval_completed", minutes=2, actor="ACCT-x", session="FSN-s")]
    r, tx = one(evs, sus={"FSN-s": ["privilege_granted_before_session"]}, priv={"ACCT-x"})
    t = tx["PAY-1"]
    assert t["suspicious"] and t["linked_to_privileged_session"]
    assert "same_actor_initiated_and_approved" in t["approval_indicators"]
    assert r["counts"]["suspicious_transactions"] == 1 and r["counts"]["linked_to_privileged_sessions"] == 1


def test_payee_change_after_approval_and_reversal():
    evs = full_chain()[:3] + [ev(9, "payee_modified", minutes=2, txn="PAY-1")] + full_chain()[3:] + \
        [ev(6, "transaction_reversed", minutes=50)]
    _, tx = one(evs)
    t = tx["PAY-1"]
    assert t["category"] == "reversed" and "payee_changed_after_approval" in t["approval_indicators"]


def test_settlements_without_a_transaction_are_reported():
    r, _ = one(full_chain(), [settle(1), settle(2, txn="PAY-ORPHAN")])
    assert r["settlements_without_transaction"] == ["SRC-BANK:2"]
