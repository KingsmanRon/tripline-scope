"""Acceptance: access-versus-theft classification across JSON/PDF/regulator outputs, containment advice,
scope-candidates for Module C, and the demo scenario."""

import json

from paths_helpers import activate, build_case

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.pdf import pdf_text
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.reports import ReportStore

FORBIDDEN = ["SELECT * FROM", "bcp ", "?session", "session=", "api_key", "token=", "hunter2", "Synthetic Person",
             "synthetic.portal.user@example.com", "another.portal.user@example.com", "Synthetic-CmdLine-Secret-7731",
             "D:\\temp\\p3.dat", "billing_0905.csv"]


def _report(ns, monkeypatch, *extra):
    activate(ns, monkeypatch)
    rc, out, err = testing.run_cli(["--json", "paths", "report", "--case", str(ns.case_dir), *extra])
    assert rc == 0, err
    return json.loads(out)


def _draft(ns, kind="paths"):
    rs = ReportStore(Case(ns.case_dir))
    d = rs.get_draft(kind, None)
    body = json.loads((d.path / "report.json").read_bytes())
    pdf = (d.path / "report.pdf").read_bytes()
    att = {p.name: p.read_bytes() for p in (d.path / "attachments").iterdir()}
    return body, pdf, att


def test_report_json_pdf_and_regulator_agree(acc, monkeypatch, tmp_path):
    measures = tmp_path / "measures.txt"
    measures.write_text("- VPN account of the implicated user suspended by the hospital on 2026-09-04\n"
                        "- Database audit specification re-enabled\n")
    _report(acc, monkeypatch, "--measures", str(measures))
    body, pdf, _att = _draft(acc)
    text = pdf_text(pdf)
    tables = {t["table"]: t for t in body["tables"]}
    for name, cls in acc.truth["expected_table_classes"].items():
        assert tables[name]["consequence_class"] == cls
        assert name in text and cls in text
    # the same classification everywhere
    reg = {t["table"]: t["consequence_class"] for t in body["regulator"]["observed_access"]}
    for name, t in tables.items():
        if t["consequence_class"] not in (None, "undetermined"):
            assert reg[name] == t["consequence_class"]
    assert body["regulator"]["counts"] == body["counts"]
    c = body["counts"]
    assert c["confirmed_exfiltration"]["tables"] == 1                    # only the corroborated table
    assert c["confirmed_exfiltration"]["records"] == "not determinable"
    assert "not determinable" in c["observed_access"]["people"] and "not determinable" in c["possible_exposure"]["people"]
    assert c["possible_exposure"]["tables"] == len(body["tables"]) >= c["observed_access"]["tables"]
    for label in ("Observed access", "Possible exposure", "Confirmed exfiltration", "not determinable"):
        assert label in text
    assert any("suspended" in m for m in body["regulator"]["measures_taken"])
    assert body["regulator"]["missing_evidence"] and body["regulator"]["unknown_actors"]
    assert "notification" in body["regulator"]["notification_note"].lower()


def test_no_identifiers_statements_or_query_strings_in_outputs(acc, monkeypatch):
    _report(acc, monkeypatch)
    body, pdf, att = _draft(acc)
    blobs = {"report.json": json.dumps(body), "report.pdf": pdf_text(pdf),
             **{k: v.decode("utf-8") for k, v in att.items()}}
    for name, blob in blobs.items():
        assert find_identifier_like(blob) == [], name
        for needle in FORBIDDEN:
            assert needle not in blob, (name, needle)


def test_containment_is_advisory_ranked_and_evidence_backed(acc, monkeypatch):
    _report(acc, monkeypatch)
    body, pdf, _ = _draft(acc)
    cont = body["containment"]
    assert "Advisory only" in cont["notice"] and "executes no containment" in cont["notice"]
    recs = cont["recommendations"]
    assert recs
    order = ["critical", "high", "medium", "low"]
    assert [order.index(r["urgency"]) for r in recs] == sorted(order.index(r["urgency"]) for r in recs)
    for r in recs:
        assert r["requires_hospital_authorisation"] is True and r["executed"] is False
        assert r["evidence_ids"] or r["anomaly_ids"]
    cats = {r["category"] for r in recs}
    assert {"accounts_to_review", "credentials_to_rotate", "addresses_to_investigate", "access_paths_to_close"} <= cats
    dest = next(r for r in recs if r["target"].get("value") == "185.220.101.47")
    assert dest["urgency"] == "critical" and any("not attribution" in c for c in dest["caveats"])
    assert cont["module_a"]["status"] == "not supplied"
    # recommendations never claim exfiltration or attribution
    for r in recs:
        assert "exfiltrat" not in r["action"].lower() and "attacker" not in r["action"].lower()
    assert "Advisory only" in pdf_text(pdf)


def test_module_a_cross_reference(acc, monkeypatch, tmp_path):
    exp = tmp_path / "exposure" / "v0001"
    exp.mkdir(parents=True)
    (exp / "report.json").write_text(json.dumps({
        "schema": "tripline.report/v1", "kind": "exposure", "version": 1,
        "findings": [{"finding_id": "FND-a1b2c3", "control_id": "A1", "asset_id": "AST-LABSQL01",
                      "location": {"principal": "LAB\\t.naidoo"}, "title": "Credential in a configuration file",
                      "severity": "high", "state": "open"},
                     {"finding_id": "FND-unrelated", "control_id": "A3", "asset_id": "AST-OTHER",
                      "location": {"principal": "nobody"}, "title": "Unrelated", "severity": "low", "state": "open"}]}))
    _report(acc, monkeypatch, "--exposure-report", str(exp))
    body, _, _ = _draft(acc)
    assert body["containment"]["module_a"]["status"] == "cross-referenced"
    refs = {x["finding_id"] for r in body["containment"]["recommendations"] for x in r["module_a_refs"]}
    assert "FND-a1b2c3" in refs and "FND-unrelated" not in refs


def test_report_is_deterministic_and_releases(acc, monkeypatch):
    a = _report(acc, monkeypatch)
    b = _report(acc, monkeypatch)
    assert a["report_sha256"] == b["report_sha256"]
    rc, out, err = testing.run_cli(["--json", "release", "--case", str(acc.case_dir), "--kind", "paths",
                                    "--approver", "ines"])
    assert rc == 0, err
    res = ReportStore(Case(acc.case_dir)).verify("paths", Home())
    assert res.ok, res.render()


def test_timeline_is_bounded(acc, monkeypatch):
    out = _report(acc, monkeypatch, "--timeline-rows", "500")
    assert out["timeline_truncated"] is True and out["timeline_rows"] == 500
    body, _, att = _draft(acc)
    lines = att["timeline.csv"].decode().splitlines()
    assert len(lines) == 501 and lines[0].startswith("event_id,source_id")
    assert body["timeline"]["rows_in_window"] > 500
    # the incident's key events survive truncation (prioritised)
    assert any("185.220.101.47" in ln for ln in lines)


def test_scope_candidates_shape_and_conservatism(acc, monkeypatch, tmp_path):
    activate(acc, monkeypatch)
    out = tmp_path / "cand.json"
    rc, so, err = testing.run_cli(["--json", "paths", "scope-candidates", "--case", str(acc.case_dir), "--out", str(out)])
    assert rc == 0, err
    doc = json.loads(out.read_text())
    assert doc["schema"] == "tripline.scope-candidates/v1" and doc["coverage_status"] == "partial"
    assert set(doc) >= {"tables", "coverage_gaps", "scenarios", "exclusion_policy", "operator_may_widen", "generated_from"}
    t = {x["table"]: x for x in doc["tables"]}
    p3 = t["LabDB03.dbo.patients"]
    assert p3["window_class"] == "confirmed" and p3["consequence_class"] == "egress_suspected"
    conf = [w for w in p3["windows"] if w["class"] == "confirmed"]
    assert conf and all(w["accounts"] and w["evidence_ids"] for w in conf)
    assert any(a["label"] == "LAB\\t.naidoo" and a["account_ref"].startswith("ACCT-") for a in p3["accounts"])
    for name in (f"LabDB09.dbo.{x}" for x in ("patients", "admissions", "billing", "results")):
        assert t[name]["window_class"] == "not_assessable" and t[name]["consequence_class"] == "undetermined"
    upper = {x["table"] for x in doc["scenarios"]["upper"]["tables"]}
    lower = {x["table"] for x in doc["scenarios"]["lower"]["tables"]}
    assert upper == set(t) and lower < upper
    assert not lower & {f"LabDB09.dbo.{x}" for x in ("patients", "admissions", "billing", "results")}
    assert "LabDB10.dbo.patients" in upper                 # never dropped for lack of observed access
    assert any(g["kind"] == "auditing_disabled" for g in doc["coverage_gaps"])
    assert find_identifier_like(out.read_text()) == []


def test_scope_candidates_without_module_b_inputs(case_dir, tmp_path):
    testing.login("olivia")
    cfg = tmp_path / "paths.yaml"
    cfg.write_text("sensitive_tables: [LabDB01.dbo.patients, 'LabDB*.dbo.results']\n")
    rc, out, err = testing.run_cli(["paths", "config", "--case", str(case_dir), "--file", str(cfg)])
    assert rc == 0, err
    o = tmp_path / "c.json"
    rc, out, err = testing.run_cli(["--json", "paths", "scope-candidates", "--case", str(case_dir), "--out", str(o)])
    assert rc == 0, err
    doc = json.loads(o.read_text())
    assert doc["coverage_status"] == "not_assessable" and "not_assessable" in doc["statement"]
    assert [x["table"] for x in doc["tables"]] == ["LabDB01.dbo.patients"]
    assert doc["tables"][0]["window_class"] == "not_assessable"
    assert doc["scenarios"]["upper"]["all_tables"] is True and doc["scenarios"]["lower"]["tables"] == []
    # analysis and report also work with no inputs and say so
    rc, out, err = testing.run_cli(["--json", "paths", "analyse", "--case", str(case_dir)])
    assert rc == 0, err
    rc, out, err = testing.run_cli(["--json", "paths", "report", "--case", str(case_dir)])
    assert rc == 0, err
    body = json.loads(next((case_dir / "reports" / "paths" / "drafts").iterdir()).joinpath("report.json").read_text())
    assert any(g["kind"] == "no_log_sources" for g in body["gaps"])
    assert body["counts"]["confirmed_exfiltration"]["tables"] == "not determinable"


def test_demo_scenario_claims_no_exfiltration(demo, monkeypatch):
    a = demo.analysis
    classes = {t["table"]: t["consequence_class"] for t in a["tables"]}
    assert "exfiltration_evidenced" not in classes.values()
    for name in ("LabDB03.dbo.patients", "LabDB03.dbo.admissions", "LabDB07.dbo.patients", "LabDB07.dbo.admissions"):
        assert classes[name] == "egress_suspected"
    assert {t["window_class"] for t in a["tables"] if t["table"].startswith("LabDB09.")} == {"not_assessable"}
    _report(demo, monkeypatch)
    body, pdf, _ = _draft(demo)
    assert body["counts"]["confirmed_exfiltration"]["tables"] == "not determinable"
    assert "does not show that no data left" in body["counts"]["confirmed_exfiltration"]["note"]
    assert "exfiltration_evidenced" not in json.dumps(body["classification"])


def test_reingest_reuses_registrations_and_tamper_aborts(demo_dir, tmp_path, monkeypatch):
    import shutil

    syn = tmp_path / "syn"
    shutil.copytree(demo_dir, syn)
    ns = build_case(tmp_path / "inst", syn, analyse=False)
    n_sources = len(Case(ns.case_dir).sources())
    activate(ns, monkeypatch)
    rc, out, err = testing.run_cli(["--json", "paths", "ingest", "--case", str(ns.case_dir), "--manifest", str(syn / "logs.yaml")])
    assert rc == 0, err
    assert len(Case(ns.case_dir).sources()) == n_sources
    assert not any(s["newly_registered"] for s in json.loads(out)["sources"])
    # same size and mtime, different content, changed by another process (this one refuses to write sources)
    import subprocess

    f = syn / "network" / "firewall.csv"
    script = ("import os,sys;f=sys.argv[1];st=os.stat(f);d=bytearray(open(f,'rb').read());"
              "d[-3]=55 if d[-3]!=55 else 56;os.chmod(f,0o644);open(f,'r+b').write(bytes(d));"
              "os.utime(f,ns=(st.st_atime_ns,st.st_mtime_ns))")
    subprocess.run(["python3", "-c", script, str(f)], check=True)
    rc, out, err = testing.run_cli(["paths", "ingest", "--case", str(ns.case_dir), "--manifest", str(syn / "logs.yaml")])
    assert rc == 4 and "hash mismatch" in err


def test_module_a_findings_are_matched_by_nested_asset_id():
    """Released exposure findings carry ``asset.asset_id``; containment must cross-reference them by it."""
    from tripline_scope.paths import containment

    f = {"finding_id": "AF-x", "control_id": "A4", "asset": {"asset_id": "AST-LABSQL01"}, "severity": "critical",
         "state": "new", "title": "xp_cmdshell enabled"}
    assert containment._finding_asset(f) == "AST-LABSQL01"
    assert containment._finding_ref(f)["asset_id"] == "AST-LABSQL01"
    assert containment._finding_asset({"asset_id": "AST-1"}) == "AST-1"
    assert containment._finding_asset({"asset": None}) is None
