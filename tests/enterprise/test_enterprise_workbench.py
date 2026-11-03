"""Workbench on enterprise cases: Financial activity section behind the integrity gate, profile-aware navigation,
no account labels or raw references, roles and read-only behaviour."""

import json

from dashkit_ent import signed_in

from conftest import report
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store


def client(ns, user="rami"):
    ns.env.apply()
    case = Case(ns.case_dir)
    return signed_in(case, open_store(case, Home()), Home(), user=user), case


def test_financial_section_matches_the_released_report(scenarios):
    for sc, ns in scenarios.items():
        c, _ = client(ns)
        v = c.get("/api/financial").json()
        r = report(ns.case_dir, "financial")
        assert v["status"] == "released" and v["financial_impact"]["status"] == r["financial_impact"]["status"]
        for k in ("transactions", "suspicious_transactions", "settled_corroborated", "rejected_or_stopped"):
            assert v["counts"][k] == r["counts"][k], (sc, k)
        assert v["integrity_alerts"] == []


def test_amounts_shown_per_currency_and_labels_withheld(scenarios):
    ns = scenarios["c"]
    c, _ = client(ns)
    v = c.get("/api/financial").json()
    shown = {(a["category"], a["display"]) for a in v["suspicious_amounts"]}
    assert shown == {("posted", "USD 18,500.00"), ("settled_corroborated", "ZAR 1,275,400.00")}
    blob = json.dumps(v)
    assert "account_label" not in blob and "vendor01" not in blob          # pseudonymous refs only
    for n in ns.truth["secrets_never_in_outputs"]:
        assert n not in blob


def test_enterprise_navigation_and_people_not_applicable(scenarios):
    c, _ = client(scenarios["b"])
    page = c.get("/").text
    assert 'data-section="financial"' in page and 'data-section="people"' not in page
    assert c.get("/api/people").json()["status"] == "not_applicable"
    ov = c.get("/api/overview").json()
    assert ov["profile"] == "enterprise" and set(ov["reports"]) == {"exposure", "paths", "financial", "investigation",
                                                                      "readiness"}


def test_financial_views_are_audited_and_need_a_role(scenarios):
    ns = scenarios["a"]
    c, case = client(ns)
    before = len([e for e in case.audit.entries() if e["command"] == "dashboard view"])
    c.get("/api/financial")
    c.get("/api/financial")
    after = [e for e in case.audit.entries() if e["command"] == "dashboard view"]
    assert len(after) - before == 2 and after[-1]["params"]["section"] == "financial"
    anon = signed_in.__globals__["TestClient"](c.app, base_url="http://127.0.0.1")
    assert anon.get("/api/financial").status_code == 401


def test_workbench_is_read_only_for_financial_data(scenarios):
    ns = scenarios["c"]
    c, _ = client(ns)
    before = {p: p.read_bytes() for p in (ns.case_dir / "reports").rglob("*") if p.is_file()}
    for path in ("/api/financial", "/api/overview", "/api/reports", "/reports/financial/v1/report.json"):
        assert c.get(path).status_code == 200
    assert c.post("/api/financial").status_code in (403, 405)
    after = {p: p.read_bytes() for p in (ns.case_dir / "reports").rglob("*") if p.is_file()}
    assert before == after
