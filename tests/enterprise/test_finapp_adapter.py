"""Financial-application audit and settlement adapter (Module B families fin_app_audit, bank_settlement):
documented schema, malformed input, duplicates, amounts/currencies, mapping and safe handling of payee details."""

import io
import json

import pytest

from tripline_scope.core.errors import ConfigError
from tripline_scope.paths.parsers import REGISTRY, finapp
from tripline_scope.paths.parsers.base import ParseContext


def ctx(family="fin_app_audit", fmt="jsonl", mapping=None):
    fp = lambda s: "f" * 64  # noqa: E731 - fixed keyed fingerprint stand-in
    return ParseContext(source_id="SRC-001", family=family, fmt=fmt, host="FIN-APP-01", options={}, mapping=mapping,
                        sql_fp=fp, file_fp=fp)


GOOD = {"event_id": "FA-1", "timestamp": "2026-09-05T22:25:00Z", "source_system": "ERP", "actor_reference": "UTIL\\user1",
        "action": "payment_created", "outcome": "success", "evidence_source_id": "EXPORT-1",
        "session_reference": "S-1", "transaction_reference": "PAY-1", "amount": "1275400.00", "currency": "zar",
        "payee_reference": "62012345678", "idp_correlation_id": "corr-1", "approval_reference": "APR-1"}


def parse(records, **kw):
    c = ctx(**kw)
    data = "".join(json.dumps(r) + "\n" for r in records).encode()
    out = list(finapp.parse(c, io.BytesIO(data), "erp.jsonl"))
    return c, out


def test_registered_for_both_families():
    assert REGISTRY["fin_app_audit"] is finapp and REGISTRY["bank_settlement"] is finapp


def test_documented_fields_map_onto_the_event_schema():
    c, out = parse([GOOD])
    r = out[0]
    assert c.failures == 0
    assert (r["account"], r["session_id"], r["operation"], r["event_code"], r["correlation_id"]) == \
        ("UTIL\\user1", "S-1", "payment_created", "FA-1", "corr-1")
    assert (r["txn_ref"], r["approval_ref"], r["evidence_ref"]) == ("PAY-1", "APR-1", "EXPORT-1")
    assert (r["amount_minor"], r["currency"]) == (127540000, "ZAR")
    assert r["observation_type"] == "financial_action" and r["outcome"] == "success"


def test_payee_reference_is_only_kept_as_a_keyed_fingerprint():
    _, out = parse([GOOD])
    r = out[0]
    assert r["counterparty_ref"].startswith("CPTY-") and "62012345678" not in json.dumps(
        {k: v for k, v in r.items() if k not in ("_raw", "_ts")})


@pytest.mark.parametrize("change,reason", [
    ({"timestamp": "yesterday"}, "timestamp"),
    ({"event_id": None}, "missing required"),
    ({"actor_reference": ""}, "missing required"),
    ({"amount": "12.345"}, "fraction digits"),
    ({"amount": "-5.00"}, "non-negative"),
    ({"amount": "1e6"}, "non-negative"),
    ({"currency": "XYZ"}, "ISO 4217"),
    ({"currency": None}, "amount without a currency"),
    ({"transaction_reference": "PAY 1; DROP"}, "transaction_reference"),
    ({"event_id": "FA 1 <script>"}, "event_id"),
])
def test_malformed_records_are_failed_not_repaired(change, reason):
    rec = dict(GOOD, **change)
    rec = {k: v for k, v in rec.items() if v is not None}
    c, out = parse([rec])
    assert out == [] and c.failures == 1 and reason in c.failure_samples[0]["reason"]


def test_unreadable_lines_are_failures_and_good_lines_survive():
    c = ctx()
    data = (json.dumps(GOOD) + "\nnot json at all\n" + json.dumps(dict(GOOD, event_id="FA-2")) + "\n").encode()
    out = list(finapp.parse(c, io.BytesIO(data), "erp.jsonl"))
    assert [r["event_code"] for r in out] == ["FA-1", "FA-2"] and c.failures == 1


def test_duplicate_source_event_ids_are_kept_and_flagged():
    _, out = parse([GOOD, GOOD])
    assert out[0]["flags"] == [] and out[1]["flags"] == ["duplicate_source_event_id"]


def test_action_and_outcome_mapping_and_unknown_actions():
    m = {"action_map": {"APPROVE": "approval_completed"}, "outcome_map": {"ok": "success"}}
    _, out = parse([dict(GOOD, action="APPROVE", outcome="ok"), dict(GOOD, event_id="FA-2", action="wobble"),
                    dict(GOOD, event_id="FA-3", outcome="denied")], mapping=m)
    assert out[0]["operation"] == "approval_completed" and out[0]["outcome"] == "success"
    assert out[1]["operation"] == "other" and "unmapped_action" in out[1]["flags"]
    assert out[2]["outcome"] == "failure" and "outcome_denied" in out[2]["flags"]


def test_role_assignment_is_a_privilege_change():
    _, out = parse([dict(GOOD, action="role_assigned", target_account="UTIL\\user2", transaction_reference=None)])
    assert out[0]["observation_type"] == "privilege_change" and out[0]["target_account"] == "UTIL\\user2"


def test_settlement_records_need_a_documented_outcome_and_exact_amount():
    rec = {"event_id": "B-1", "timestamp": "2026-09-07T09:00:00Z", "transaction_reference": "PAY-1",
           "amount": "1275400.00", "currency": "ZAR", "outcome": "settled", "evidence_source_id": "STMT-1"}
    c, out = parse([rec, dict(rec, event_id="B-2", outcome="maybe")], family="bank_settlement")
    assert len(out) == 1 and c.failures == 1
    assert out[0]["observation_type"] == "settlement_record" and "settlement_outcome:settled" in out[0]["flags"]
    assert out[0]["amount_minor"] == 127540000


def test_mapping_validation_rejects_unknown_fields_and_actions():
    with pytest.raises(ConfigError):
        finapp.validate_mapping({"fields": {"password": "pw"}}, "fin_app_audit")
    with pytest.raises(ConfigError):
        finapp.validate_mapping({"action_map": {"x": "wire_money"}}, "fin_app_audit")
    finapp.validate_mapping({"fields": {"amount": "amt"}}, "bank_settlement")


def test_csv_with_renamed_columns():
    m = {"fields": {"event_id": "line", "timestamp": "booked", "transaction_reference": "ref", "amount": "amt",
                    "currency": "ccy", "outcome": "status", "evidence_source_id": "doc"},
         "outcome_map": {"SETTLED": "settled"}}
    c = ctx(family="bank_settlement", fmt="csv", mapping=m)
    data = b"line,booked,ref,amt,ccy,status,doc,secret_column\nL1,2026-09-07T09:00:00Z,PAY-1,10.50,USD,SETTLED,D1,hunter2\n"
    out = list(finapp.parse(c, io.BytesIO(data), "stmt.csv"))
    assert out[0]["amount_minor"] == 1050 and out[0]["currency"] == "USD"
    assert "hunter2" not in json.dumps({k: v for k, v in out[0].items() if k not in ("_raw", "_ts")})
