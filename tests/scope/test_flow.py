"""End to end through the CLI: estimate → match → review → report → pack → release (hook) → export → diff."""

import csv
import json

import pyarrow.parquet as pq

from conftest import c, cli
from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.scope import config as C
from tripline_scope.scope import data as D
from tripline_scope.scope import run as R
from tripline_scope.scope.simulate import row_truth


def _report(case_dir, version=None):
    d = case_dir / "reports" / "scope"
    if version is None:
        drafts = sorted((d / "drafts").iterdir(), key=lambda p: p.stat().st_mtime)
        return json.loads((drafts[-1] / "report.json").read_bytes()), drafts[-1]
    return json.loads((d / f"v{version:04d}" / "report.json").read_bytes()), d / f"v{version:04d}"


def test_full_flow(scoped, synth_dir, tmp_path):
    case_dir, smap = scoped
    rc, out, err = cli(["estimate"] + c(case_dir), "olivia")
    assert out["report_status"] == "preliminary" and out["lower"] <= out["people_estimate"] <= out["upper"]
    body, ddir = _report(case_dir)
    assert body["report_status"] == "preliminary" and "PRELIMINARY" in (ddir / "report.pdf").read_bytes().decode("latin-1")
    rc, est, err = cli(["scope", "match"] + c(case_dir))
    assert est["people"] > 0
    rc, out, err = cli(["scope", "decide"] + c(case_dir) + ["--simulate-reviewer", str(synth_dir / "ground_truth.parquet")],
                       "rami")
    assert out["simulated"] is True
    simulated = out["recorded"] > 0
    rc, m, err = cli(["scope", "match"] + c(case_dir), "olivia")
    assert m["review_items"] == 0
    rc, rep, err = cli(["scope", "report"] + c(case_dir))
    assert rep["simulated_review"] is simulated
    body, ddir = _report(case_dir)
    assert body["report_status"] == "refined" and body["review_decisions_simulated"] is simulated
    assert any("simulated" in x for x in body["limitations"]) is simulated
    # estimate lands within 5 % of the refined count
    prelim = body["preliminary_estimate"]["point"]
    assert abs(prelim - body["counts"]["unique_people"]) / body["counts"]["unique_people"] < 0.05
    tiers = body["scope_tiers"]
    assert set(tiers) == {"observed_access", "possible_exposure", "confirmed_exfiltration", "notification_scope"}
    assert tiers["observed_access"]["count"] == "not determinable"  # no Module B input
    assert body["degraded_evidence"]["degraded_confidence"] is True
    assert tiers["notification_scope"]["proposed_count"] == tiers["possible_exposure"]["count"] == body["counts"]["unique_people"]
    # confirmed exfiltration = people in the leak sample, only for the leak's categories
    leak_people = pq.read_table(synth_dir / "ground_truth.parquet").to_pylist()
    true_leak = {r["person_id"] for r in leak_people if r["table"] == "leak_sample"}
    assert abs(tiers["confirmed_exfiltration"]["count"] - len(true_leak)) <= 1
    leak_cats = {k for k, v in tiers["confirmed_exfiltration"]["people_per_category"].items() if v}
    assert leak_cats <= {"identity_number", "name", "date_of_birth", "contact_details"}
    assert tiers["confirmed_exfiltration"]["exfiltration_evidence_kind"] == "independently_confirmed_external_copy"
    # pack is locked before release
    rc, pack, err = cli(["scope", "notify", "build"] + c(case_dir))
    assert pack["locked"] is True
    out_dir = tmp_path / "export"
    rc, o, err = cli(["scope", "notify", "export"] + c(case_dir) + ["--out", str(out_dir), "--approver", "ines"],
                     ok=False)
    assert rc == 3 and not out_dir.exists(), "export must be refused before release"
    for who in ("rami", "olivia"):
        rc, o, err = cli(["scope", "notify", "export"] + c(case_dir) + ["--out", str(out_dir), "--approver", who],
                         ok=False)
        assert rc == 3, f"{who} must not export"
    rc, o, err = cli(["release", "--kind", "scope", "--approver", "ines"] + c(case_dir))
    rc, o, err = cli(["scope", "notify", "export"] + c(case_dir) + ["--out", str(out_dir), "--approver", "ines"])
    assert o["exported_people"] == pack["people"]
    rows = list(csv.DictReader(open(out_dir / "people.csv")))
    assert len(rows) == pack["people"]
    segs = {}
    for r in rows:
        segs[r["segment"]] = segs.get(r["segment"], 0) + 1
        if r["segment"] == "minor_guardian_routed":
            assert r["guardian_phone"] or r["guardian_email"]
            assert not r["phone"] and not r["email"]
        if r["segment"] == "no_usable_contact":
            assert not (r["phone"] or r["email"] or r["postal_address"] or r["first_name"])
        if r["notice_file"]:
            assert (out_dir / r["notice_file"]).exists()
    assert segs == pack["segments"]
    notice = (out_dir / rows[0]["notice_file"]).read_text() if rows[0]["notice_file"] else ""
    if notice:
        assert "What happened and when" in notice and "What you can do" in notice
    summ = json.loads((out_dir / "regulator_summary.json").read_bytes())
    assert [s["field"] for s in summ["sections"]] == ["dates", "description", "number_of_data_subjects",
                                                      "categories_of_personal_information", "likely_consequences",
                                                      "measures_taken"]
    assert (out_dir / "regulator_summary.pdf").read_bytes().startswith(b"%PDF")
    # segments agree with the synthetic ground truth person by person
    case = Case(case_dir)
    store = open_store(case, Home())
    data = D.load(case, store, C.load(case), include_dependent=False)
    con = data.con
    row_truth(con, synth_dir / "ground_truth.parquet")
    con.register("_gt", pq.read_table(synth_dir / "ground_truth.parquet"))
    con.register("_pr", store.read_table(R.PERSON_ROWS))
    con.register("_pp", store.read_table(R.PEOPLE))
    agree = con.execute("""
        WITH f AS (SELECT DISTINCT person_id, is_minor, has_guardian, has_contact FROM _gt WHERE is_minor IS NOT NULL),
        exp AS (SELECT person_id, CASE WHEN bool_or(is_minor) THEN CASE WHEN bool_or(has_guardian)
                    THEN 'minor_guardian_routed' ELSE 'minor_flagged_no_guardian' END
                  WHEN bool_or(has_contact) THEN 'adult_with_contact' ELSE 'no_usable_contact' END AS seg
                FROM f GROUP BY person_id),
        p AS (SELECT DISTINCT pr.person_key, t.person_id FROM _pr pr JOIN truth t USING (row_key))
        SELECT avg(CASE WHEN pp.segment = e.seg THEN 1.0 ELSE 0.0 END), count(*)
        FROM p JOIN exp e USING (person_id) JOIN _pp pp USING (person_key)""").fetchone()
    con.close()
    assert agree[1] > 500 and agree[0] > 0.98, agree
    rc, v, err = cli(["verify"] + c(case_dir), "olivia")
    assert v["ok"] is True


def test_rerun_diff_and_constrain(scoped, synth_dir, tmp_path):
    case_dir, smap = scoped
    cli(["scope", "match"] + c(case_dir), "olivia")
    cli(["scope", "report"] + c(case_dir))
    cli(["release", "--kind", "scope", "--approver", "ines"] + c(case_dir))
    # Module B candidates refer to (database, table) as named in the backup, case-insensitively
    cand = {"schema": "tripline.scope-candidates/v1", "tables": [
        {"database": "DB01", "table": "PATIENTS", "window_class": "confirmed",
         "windows": [{"start": "2026-09-01T00:00:00Z", "end": "2026-09-10T00:00:00Z"}],
         "consequence_class": "access_observed", "basis": "observation", "accounts": ["svc_lab"],
         "evidence_ids": ["EV-1"], "confidence": 0.9, "limitations": []},
        {"database": "db02", "table": "patients", "window_class": "possible", "windows": [], "consequence_class":
         "undetermined", "basis": "inference", "accounts": [], "evidence_ids": [], "confidence": 0.5, "limitations": []},
        {"database": "db99", "table": "nothing", "window_class": "confirmed", "windows": []}],
        "coverage_gaps": [{"description": "firewall logs missing for 3 days"}],
        "scenarios": {"lower": {}, "upper": {}}}
    f = tmp_path / "cand.json"
    f.write_text(json.dumps(cand))
    rc, o, err = cli(["scope", "constrain"] + c(case_dir) + ["--candidates", str(f), "--reason", "Module B v1 windows"])
    assert o["kind"] == "constrain_to_candidates"
    cli(["scope", "report"] + c(case_dir))
    body, _ = _report(case_dir)
    sc = body["scenarios"]
    assert 0 < sc["lower"] <= sc["candidate"] <= sc["upper"] == sc["full_scope"] == body["counts"]["unique_people"]
    assert body["scope_tiers"]["observed_access"]["count"] == sc["lower"]
    assert body["scope_tiers"]["notification_scope"]["proposed_count"] == sc["full_scope"], "never narrowed"
    assert body["degraded_evidence"] is None
    assert body["scenarios"]["unmatched_candidate_tables"] == [{"database": "db99", "table": "nothing",
                                                                "window_class": "confirmed"}]
    assert [d["kind"] for d in body["scoping_decisions"]] == ["constrain_to_candidates"]
    assert body["diff_from_previous"]["available"] is True
    assert body["diff_from_previous"]["people"]["added"] == 0 and body["diff_from_previous"]["people"]["removed"] == 0
    # widening is recorded with its reason and moves the lower scenario up
    rc, o, err = cli(["scope", "constrain"] + c(case_dir) + ["--widen", "db02.patients", "--reason", "IO instruction"])
    cli(["scope", "report"] + c(case_dir))
    body2, _ = _report(case_dir)
    assert body2["scenarios"]["lower"] >= sc["lower"] and len(body2["scoping_decisions"]) == 2
    # a re-run with simulated decisions is a new version linked to the previous one, with a per-category diff
    cli(["scope", "decide"] + c(case_dir) + ["--simulate-reviewer", str(synth_dir / "ground_truth.parquet")], "rami")
    cli(["scope", "match"] + c(case_dir), "olivia")
    cli(["scope", "report"] + c(case_dir))
    cli(["release", "--kind", "scope", "--approver", "ines"] + c(case_dir))
    v2, vdir = _report(case_dir, 2)
    v1, v1dir = _report(case_dir, 1)
    import hashlib

    assert v2["previous_report_sha256"] == hashlib.sha256((v1dir / "report.json").read_bytes()).hexdigest()
    att = json.loads((vdir / "attachments" / "diff.json").read_bytes())
    assert att["available"] and set(att["per_category"]) >= {"name", "clinical_diagnosis"}
    rc, d, err = cli(["scope", "diff"] + c(case_dir) + ["--from", "1", "--to", "2"])
    assert d == att
    p = v2["counts"]["unique_people"] - v1["counts"]["unique_people"]
    assert d["people"]["current"] - d["people"]["previous"] == p
    testing.login("olivia")
