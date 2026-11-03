"""Investigator on enterprise cases: the bundle carries the released financial report, the deterministic fixture
passes validation, and unsupported fraud, blame, money-movement, loss and absence claims are rejected."""

import copy
import json

import pytest

from conftest import cli, clone, report
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.investigator import bundle as B
from tripline_scope.investigator import fixture as F
from tripline_scope.investigator import validate as V


@pytest.fixture(scope="module")
def bundles(scenarios):
    out = {}
    for sc, ns in scenarios.items():
        ns.env.apply()
        out[sc] = B.build(Case(ns.case_dir), Home())
    return out


def run(bundle, cand):
    return V.validate(json.dumps(cand).encode(), bundle, case_id=bundle["case_id"])


def main_hyp(bundle, **over):
    c = F.candidate(bundle)
    h = copy.deepcopy(c["hypotheses"][0])
    h.update(over)
    c["hypotheses"] = [h]
    return c


def txns(bundle, category=None, suspicious_only=True):
    return [i for i in bundle["evidence"].values() if i["type"] == "transaction"
            and (category is None or i["financial_category"] == category)
            and (not suspicious_only or "suspicious: True" in (i["statement"] or ""))]


def test_bundle_reads_released_enterprise_reports(bundles):
    b = bundles["c"]
    assert [r["kind"] for r in b["reports"]] == ["exposure", "paths", "financial"]
    assert b["not_assessed"] == []                      # Module C scope is not part of the enterprise profile
    assert "financial application audit" not in b["missing_source_families"]
    assert b["facts"]["FACT-F-impact-status"]["value"] == "settlement_corroborated"
    assert {i["type"] for i in b["evidence"].values()} >= {"fin_session", "transaction", "privilege_event", "recommendation"}


@pytest.mark.parametrize("sc", ["a", "b", "c"])
def test_fixture_output_is_fully_accepted(bundles, sc):
    v = run(bundles[sc], F.candidate(bundles[sc]))
    assert v["envelope"]["verdict"] == "accepted"
    assert all(x["verdict"] == "accepted" for x in v["verdicts"].values()), v["verdicts"]


@pytest.mark.parametrize("stmt", [
    "Fraud was proven: the supplier account emptied the payment run.",
    "This is confirmed fraud by the supplier.",
    "The finance clerk behind the account committed fraud.",
    "The employee using the account defrauded the company.",
    "The account holder is guilty of theft.",
    "The perpetrator used the supplier account.",
])
def test_fraud_and_blame_claims_rejected(bundles, stmt):
    v = run(bundles["c"], main_hyp(bundles["c"], statement=stmt))["verdicts"]["H1"]
    assert v["verdict"] == "rejected" and "financial_unsupported" in v["codes"]


def test_hedged_language_is_not_a_claim(bundles):
    c = main_hyp(bundles["c"], statement="Whether fraud was committed cannot be determined from this evidence; that "
                                         "is for the responsible officers.")
    assert run(bundles["c"], c)["verdicts"]["H1"]["verdict"] == "accepted"


def test_money_movement_needs_independent_settlement(bundles):
    b = bundles["c"]
    settled = txns(b, "settled_corroborated")[0]["id"]
    posted = txns(b, "posted")[0]["id"]
    c = F.candidate(b)
    h = c["hypotheses"][0]
    assert settled in h["supporting_evidence"] and posted in h["supporting_evidence"]
    for stmt in (f"Funds were transferred for {posted}.", f"{posted} was paid out to the new payee.",
                 f"{settled} and {posted} were settled.", "Money left the organisation through the payment run."):
        bad = main_hyp(b, statement=stmt)
        v = run(b, bad)["verdicts"]["H1"]
        assert v["verdict"] == "rejected" and "financial_unsupported" in v["codes"], stmt
    ok = main_hyp(b, statement=f"{settled} was settled according to an independent settlement record.")
    assert run(b, ok)["verdicts"]["H1"]["verdict"] == "accepted"
    # the same sentence without citing the settled transaction is rejected
    no_cite = main_hyp(b, statement=f"{settled} was settled.", supporting_evidence=[
        x for x in h["supporting_evidence"] if x != settled])
    assert "financial_unsupported" in run(b, no_cite)["verdicts"]["H1"]["codes"]


def test_loss_claims_rejected_for_attempted_transactions(bundles):
    b = bundles["b"]
    for stmt in ("A financial loss of the attempted amount occurred.", "The company suffered a loss through the supplier.",
                 "The payment was paid to the attacker's account."):
        v = run(b, main_hyp(b, statement=stmt))["verdicts"]["H1"]
        assert v["verdict"] == "rejected" and "financial_unsupported" in v["codes"], stmt


def test_missing_logs_never_prove_no_suspicious_activity(bundles):
    b = bundles["a"]
    for stmt in ("No suspicious transactions occurred during the audit outage.",
                 "There were no unauthorised payments in the window."):
        v = run(b, main_hyp(b, statement=stmt))["verdicts"]["H1"]
        assert v["verdict"] == "rejected" and "missing_logs_as_absence" in v["codes"], stmt


def test_listed_items_are_checked_too(bundles):
    b = bundles["b"]
    c = F.candidate(b)
    c["investigation_steps"][0]["step"] = "Recover the funds that were transferred to the attacker."
    c["remediation"][0]["action"] = "Discipline the clerk who committed fraud."
    v = run(b, c)["verdicts"]
    assert "financial_unsupported" in v["S1"]["codes"] and "financial_unsupported" in v["R1"]["codes"]


def test_released_investigation_report_on_an_enterprise_case(scenarios, tmp_path):
    ns = clone(scenarios["c"], tmp_path)
    ns.env.apply()
    rc, out, _ = cli(["investigator", "analyse", *ns.c, "--provider", "fixture"], "olivia")
    assert out["analysis_status"] == "completed" and out["is_model_inference"] is False
    for h in out["hypotheses"]:
        cli(["investigator", "review", *ns.c, "--run", out["run_id"], "--item", h, "--decision", "accept",
             "--note", "checked against the cited evidence"], "rami")
    cli(["investigator", "report", *ns.c], "olivia")
    cli(["release", *ns.c, "--kind", "investigation", "--approver", "ines"])
    rc, v, _ = cli(["investigator", "verify", *ns.c], "rami")
    assert v["chain_ok"] is True and v["reproducible"] is True
    body = report(ns.case_dir, "investigation")
    fin = body["deterministic_findings"]["financial"]
    assert fin["impact_status"] == "settlement_corroborated" and "scope" not in body["deterministic_findings"]
