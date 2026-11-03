"""Enterprise profile end to end on the synthetic utility: three scenarios distinguished, correlation labels,
exposure controls E1–E5, evidence-backed counts and currency totals, roles, signatures, tampering, leakage and
offline execution."""

import json
import socket
import subprocess
import sys

import pytest

from conftest import build, cli, clone, report
from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store

EXPECTED = {"a": "not_determinable", "b": "attempted_and_stopped", "c": "settlement_corroborated"}


def _refs(ns) -> dict:
    """TXN- id -> raw transaction reference, from the encrypted work store (authorised investigator view)."""
    ns.env.apply()
    case = Case(ns.case_dir)
    store = open_store(case, Home())
    return store.read_json("work/financial/refs.json")["transactions"]


# ------------------------------------------------------------------------------------------------ scenarios
@pytest.mark.parametrize("sc", ["a", "b", "c"])
def test_scenarios_are_distinguished_and_match_ground_truth(scenarios, sc):
    ns = scenarios[sc]
    r = report(ns.case_dir, "financial")
    assert r["financial_impact"]["status"] == EXPECTED[sc]
    refs = _refs(ns)
    by_raw = {refs[t["transaction_id"]]: t for t in r["transactions"]}
    for raw, exp in ns.truth["transactions"].items():
        t = by_raw[raw]
        assert t["category"] == exp["expected_category"], (raw, t["category"])
        assert t["suspicious"] == exp["suspicious"], raw
        if "amount_minor" in exp:
            assert (t["amount_minor"], t["currency"]) == (exp["amount_minor"], exp["currency"])
    assert r["counts"]["suspicious_transactions"] == len(ns.truth["suspicious"])
    assert r["counts"]["settled_corroborated"] == sum(1 for e in ns.truth["transactions"].values()
                                                      if e["expected_category"] == "settled_corroborated")
    assert r["inputs"]["duplicates"]["exact_duplicates_dropped"] == ns.truth["exact_duplicates"]


def test_scenario_a_gap_prevents_a_determination(scenarios):
    r = report(scenarios["a"].case_dir, "financial")
    kinds = {g["kind"]: g for g in r["gaps"]}
    assert "settlement_evidence_not_supplied" in kinds
    sus = [s["session_id"] for s in r["sessions"] if s["suspicious_reasons"]]
    assert kinds["declared_missing_period"]["overlaps_sessions"] == sus
    assert r["counts"]["suspicious_transactions"] == 0          # nothing is invented to fill the gap
    assert "not determinable" in r["financial_impact"]["statement"] or "prevent" in r["financial_impact"]["statement"]


def test_scenario_b_attempt_is_not_money_movement(scenarios):
    r = report(scenarios["b"].case_dir, "financial")
    sus = [t for t in r["transactions"] if t["suspicious"]]
    assert [t["category"] for t in sus] == ["rejected_or_stopped"]
    assert "release_attempt_blocked" in sus[0]["flags"] and sus[0]["settlement"] is None
    assert r["counts"]["release_attempts_blocked"] == 1
    assert r["counts"]["suspicious_amount_totals_minor_by_category"] == {"rejected_or_stopped": {"ZAR": 485000000}}


def test_scenario_c_settlement_amount_reference_and_currencies(scenarios):
    r = report(scenarios["c"].case_dir, "financial")
    tot = r["counts"]["suspicious_amount_totals_minor_by_category"]
    assert tot == {"posted": {"USD": 1850000}, "settled_corroborated": {"ZAR": 127540000}}   # never mixed
    settled = [t for t in r["transactions"] if t["suspicious"] and t["category"] == "settled_corroborated"]
    assert len(settled) == 1 and settled[0]["settlement"]["amount_minor"] == 127540000
    assert settled[0]["settlement"]["currency"] == "ZAR"
    assert "same_actor_initiated_and_approved" in settled[0]["approval_indicators"]
    posted = [t for t in r["transactions"] if t["suspicious"] and t["category"] == "posted"]
    assert "settlement_claimed_without_independent_evidence" in posted[0]["approval_indicators"]


def test_cross_system_correlation_labels(scenarios):
    r = report(scenarios["c"].case_dir, "financial")
    s = next(s for s in r["sessions"] if s["suspicious_reasons"])
    labels = {k: v["label"] for k, v in s["links"].items()}
    assert labels == {"identity": "direct", "remote_access": "direct", "host_logon": "correlated", "privilege": "correlated"}
    assert set(s["suspicious_reasons"]) >= {"supplier_outside_window", "privilege_granted_before_session",
                                            "signin_without_mfa", "external_signin"}
    assert all(p["resolved"] for p in r["privilege_events"])      # the directory group grant maps to the account
    # routine approver sessions: identity only correlated (no shared id), never upgraded to direct
    routine = [x for x in r["sessions"] if not x["suspicious_reasons"] and x["links"]["identity"]["label"] != "unresolved"]
    assert routine and {x["links"]["identity"]["label"] for x in routine} <= {"direct", "correlated"}


# ------------------------------------------------------------------------------------------------ Module A
def test_enterprise_exposure_controls(scenarios):
    r = report(scenarios["c"].case_dir, "exposure")
    rules = {f["rule_id"] for f in r["findings"] if f["control_id"].startswith("E")}
    assert set(scenarios["c"].truth["exposure_rules"]) <= rules
    assert set(r["summary"]["by_control"]) == {"A1", "A2", "A3", "A4", "A5", "E1", "E2", "E3", "E4", "E5"}
    for f in r["findings"]:
        if f["control_id"].startswith("E"):
            assert f["finding_id"].startswith("AF-") and f["asset"]["asset_id"] and f["severity"]
            assert f["basis"] in ("observation", "inference") and f["suggested_fix"]["action"]
            assert f["details"]["source_sha256"] and f["source_ids"] and f["evidence_ids"]
    e3 = [f for f in r["findings"] if f["rule_id"] == "E3.copy-outside-inventory"]
    assert not any("Approved/" in (f["details"].get("path") or "") for f in e3)         # inventoried copy not flagged
    e1 = [f["location"].get("principal", "") for f in r["findings"] if f["rule_id"] == "E1.privileged-unmapped"]
    assert not any("approver01" in p for p in e1)                                     # mapped privilege not flagged
    e4 = r["coverage"]["E4"]
    assert e4["status"] == "partially assessed"
    assert all("insufficient evidence" in x["reason"] for x in e4["not_assessed"])    # unknown is not a failure


def test_enterprise_controls_are_not_assessed_without_their_inputs(tmp_path):
    import yaml

    ns = build(tmp_path, "a", financial=False)
    man = ns.gen / "estate" / "manifest.yaml"
    doc = yaml.safe_load(man.read_text())
    doc["enterprise"] = {"financial_assets": ["AST-FIN-APP01"], "entitlements": "enterprise/entitlements.csv"}
    (ns.gen / "estate" / "manifest_partial.yaml").write_text(yaml.safe_dump(doc))
    ns.env.apply()
    cli(["exposure", "scan", *ns.c, "--inputs", str(ns.gen / "estate" / "manifest_partial.yaml")], "olivia")
    cli(["exposure", "report", *ns.c, "--no-pdf"])
    cli(["release", *ns.c, "--kind", "exposure", "--approver", "ines"])
    r = report(ns.case_dir, "exposure")
    for ctl in ("E1", "E2", "E3", "E4", "E5"):
        assert r["coverage"][ctl]["status"] == "not assessed", ctl
        assert all("insufficient evidence" in x["reason"] for x in r["coverage"][ctl]["not_assessed"]), ctl
        # earlier findings are carried as not-assessed (never as failed) when their evidence is not supplied
        assert not [f for f in r["findings"] if f["control_id"] == ctl and f["state"] in ("new", "open")], ctl
        assert {f["state"] for f in r["findings"] if f["control_id"] == ctl} <= {"not-assessed"}, ctl


# ------------------------------------------------------------------------------------------------ roles, profile
def test_roles_profile_and_release_gates(scenarios, tmp_path):
    ns = clone(scenarios["b"], tmp_path)
    ns.env.apply()
    rc, _, _ = cli(["financial", "analyse", *ns.c, "--config", str(ns.gen / "financial.yaml")], "rami", ok=False)
    assert rc == 3                                                 # reviewer cannot run the analysis
    cli(["financial", "analyse", *ns.c, "--config", str(ns.gen / "financial.yaml")], "olivia")
    cli(["financial", "report", *ns.c])
    rc, _, _ = cli(["release", *ns.c, "--kind", "financial", "--approver", "olivia"], ok=False)
    assert rc != 0                                                 # operator cannot approve
    cli(["release", *ns.c, "--kind", "financial", "--approver", "ines"])
    hc = testing.open_case(tmp_path / "inst", "HC-TEST-001")      # healthcare profile (default)
    rc, _, err = cli(["financial", "analyse", "--case", str(hc), "--config", str(ns.gen / "financial.yaml")], "olivia",
                     ok=False)
    assert rc == 2 and "enterprise" in err
    import yaml

    assert "profile" not in yaml.safe_load((hc / "case.yaml").read_text())   # healthcare case.yaml unchanged


def test_stale_financial_analysis_is_refused(scenarios, tmp_path):
    ns = clone(scenarios["a"], tmp_path)
    ns.env.apply()
    cli(["paths", "report", *ns.c, "--exposure-report", str(ns.case_dir / "reports" / "exposure" / "v0001")], "olivia")
    cli(["release", *ns.c, "--kind", "paths", "--approver", "ines"])
    rc, _, err = cli(["financial", "report", *ns.c], "olivia", ok=False)
    assert rc != 0 and "stale" in err


# ------------------------------------------------------------------------------------------------ signatures
def _verify_chain(ns, kind):
    pub = ns.env.home_dir / "keys" / "hospital_signing.pub"
    return subprocess.run([sys.executable, "-m", "tscope_verify", "chain", str(ns.case_dir / "reports" / kind),
                           "--hospital-key", str(pub)], capture_output=True, text=True,
                          env={"PYTHONPATH": ":".join(sys.path)})


def test_signed_report_verifies_and_tampering_is_detected(scenarios, tmp_path):
    ns = clone(scenarios["c"], tmp_path)
    ns.env.apply()
    ok = _verify_chain(ns, "financial")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    rj = ns.case_dir / "reports" / "financial" / "v0001" / "report.json"
    rj.chmod(0o644)
    doc = json.loads(rj.read_bytes())
    doc["financial_impact"]["status"] = "no_suspicious_session_identified"
    rj.write_bytes(canonical_bytes(doc))
    assert _verify_chain(ns, "financial").returncode != 0
    rc, _, _ = cli(["verify", "--case", str(ns.case_dir)], "rami", ok=False)
    assert rc != 0
    # the workbench refuses the tampered kind with an explicit warning
    from dashkit_ent import signed_in

    case = Case(ns.case_dir)
    c = signed_in(case, open_store(case, Home()), Home())
    v = c.get("/api/financial").json()
    assert v["status"] == "integrity_failure" and v["warning"].startswith("INTEGRITY FAILURE")
    assert "transactions" not in v


# ------------------------------------------------------------------------------------------------ leakage, offline
def test_no_secret_or_raw_reference_in_released_outputs(scenarios):
    from tripline_scope.core.pdf import pdf_text

    for sc, ns in scenarios.items():
        needles = [n for n in ns.truth["secrets_never_in_outputs"] if len(n) >= 6]
        assert needles
        files = [p for p in (ns.case_dir / "reports").rglob("*") if p.is_file()] + [ns.case_dir / "audit.log"]
        for f in files:
            data = f.read_bytes()
            text = pdf_text(data) if data[:4] == b"%PDF" else data.decode("utf-8", "replace")
            hit = [n for n in needles if n in text]
            assert not hit, (sc, f.name)
        # positive control: the generated inputs do contain them
        assert any(n in (ns.gen / "logs" / "finapp" / "erp_audit.jsonl").read_text() for n in needles)


def test_financial_analysis_runs_offline(scenarios, tmp_path, monkeypatch):
    ns = clone(scenarios["c"], tmp_path)
    ns.env.apply()
    attempts = []

    def deny(*a, **k):
        attempts.append(a[:1])
        raise OSError("network disabled for this test")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    cli(["financial", "analyse", *ns.c, "--config", str(ns.gen / "financial.yaml")], "olivia")
    cli(["financial", "report", *ns.c])
    assert attempts == []
