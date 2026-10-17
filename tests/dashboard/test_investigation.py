"""AI Investigator section: not performed without a run; a stored fixture result is shown as advisory, labelled as
deterministic fixture output, with its evidence ids resolved against the released reports."""

import pytest
from dashkit import audit, report, signed_in

from tripline_scope.dashboard import data as D
from tripline_scope.investigator import storage

RUN = "RUN-0123456789ab"


@pytest.fixture
def fixture_run(dash, built):
    """A validated ``tripline.investigation/v1`` result citing real ids from the released reports (removed after)."""
    case, store, home = dash
    paths, expo = report(built.case_dir, "paths", 1), report(built.case_dir, "exposure", 1)
    ids = {"path": paths["paths"][0]["path_id"], "gap": paths["gaps"][1]["gap_id"],
           "anom": paths["anomalies"][0]["anomaly_id"], "clm": paths["tables"][0]["claim"]["claim_id"],
           "cor": paths["inputs"]["corroborations"][0]["corroboration_id"],
           "rec": paths["containment"]["recommendations"][0]["rec_id"], "af": expo["findings"][0]["finding_id"],
           "fact": "FACT-paths-0001", "ghost": "PATH-000000000000"}
    v = {"verdict": "accepted", "codes": []}
    result = {
        "schema": "tripline.investigation/v1", "case_id": case.case_id, "run_id": RUN,
        "created_at": "2026-10-17T08:00:00Z", "analysis_status": "completed", "status_reason": None,
        "references": [{"kind": "paths", "version": 1, "report_sha256": "a" * 64}],
        "not_assessed_modules": [], "bundle_sha256": "b" * 64, "method_version": "investigator/1.0.0",
        "validator_version": "validator/1.0.0",
        "provenance": {"provider": "fixture", "provider_kind": "fixture", "model_id": "tripline-fixture",
                       "model_version": "1", "is_model_inference": False, "endpoint_class": "none"},
        "model_output_sha256": "c" * 64,
        "summary": "Export and outbound flows on one database host are consistent with suspected egress.",
        "hypotheses": [{
            "hypothesis_id": "H1", "rank": "main", "basis": "hypothesis", "consequence_class": "egress_suspected",
            "statement": "Tables on the database host were exported and may have left through outbound flows.",
            "supporting_evidence": [ids["path"], ids["anom"], ids["clm"]],
            "contradicting_evidence": [ids["gap"]], "assets": ["AST-LABSQL01"], "sources": ["SRC-012"],
            "time_window": {"start": "2026-09-03T23:00:00Z", "end": "2026-09-04T01:00:00Z"},
            "confidence": "moderate", "confidence_rationale": "export and flow are correlated, content unknown",
            "alternative_explanations": ["an authorised backup job"],
            "tests": [{"evidence_needed": "proxy content logs", "would_resolve": "whether data left"}],
            "cannot_conclude": ["that records were received by a third party"],
            "quantities": [{"fact_id": ids["fact"], "value": 2}], "validation": v}],
        "missing_evidence": [{"description": "endpoint telemetry for the client host", "source_family": "edr",
                              "related_evidence": [ids["gap"]], "validation": v}],
        "investigation_steps": [{"step": "Request proxy content logs for the window", "priority": "immediate",
                                 "evidence_ids": [ids["path"], ids["cor"]], "validation": v}],
        "remediation": [{"action": "Rotate the account credentials after review", "priority": "next",
                         "evidence_ids": [ids["rec"], ids["af"], ids["ghost"]], "asset_ids": ["AST-LABSQL01"],
                         "validation": v}],
        "unproven_assertions": ["who operated the account"],
        "validation": {"verdict": "completed", "counts": {"accepted": 1, "rejected": 1, "unverified": 0},
                       "rejections": [{"item": "H2", "codes": ["promotion"]}]},
        "human_review": {"required": True, "decisions": {}},
    }
    store.write_json(f"{storage.run_dir(RUN)}/result.json", result)
    storage.add_run(store, {"run_id": RUN, "created_at": result["created_at"], "provider": "fixture",
                            "provider_kind": "fixture", "model_id": "tripline-fixture", "status": "completed"})
    storage.append_review(store, RUN, {"item_id": "H1", "decision": "accept", "reviewer": "rami",
                                       "at": "2026-10-17T09:00:00Z", "note": "consistent with the path"})
    try:
        yield ids, result
    finally:
        for rel in (f"{storage.run_dir(RUN)}/result.json", f"{storage.run_dir(RUN)}/reviews.jsonl", storage.INDEX):
            store.delete(rel)


def test_not_performed_without_a_run(dash):
    case, store, home = dash
    assert storage.latest_result(store) is None
    c = signed_in(case, store, home)
    r = c.get("/api/investigation").json()
    assert r == {"status": "not_performed", "reason": "no authorised AI analysis has been run for this case",
                 "advisory": True}


def test_fixture_result_is_advisory_and_resolves_evidence(dash, fixture_run):
    case, store, home = dash
    ids, result = fixture_run
    n_views = len(audit(case, "dashboard view"))
    c = signed_in(case, store, home, user="ines")
    r = c.get("/api/investigation").json()
    assert r["status"] == "available" and r["advisory"] is True
    assert r["banner"] == "Advisory — AI-generated hypotheses, not findings"
    assert r["is_model_inference"] is False and r["fixture"] is True
    assert r["provenance_note"] == "Deterministic fixture output — not AI inference"
    assert r["released_report"]["status"] == "awaiting_analysis"
    run = r["latest_run"]
    assert run["run_id"] == RUN and run["hypotheses"][0]["statement"] == result["hypotheses"][0]["statement"]
    assert run["provenance"]["is_model_inference"] is False
    assert run["human_review"]["decisions"]["H1"]["decision"] == "accept"
    links = r["evidence_links"]
    expect = {ids["path"]: ("paths", "path"), ids["anom"]: ("paths", "anomaly"), ids["clm"]: ("paths", "table_claim"),
              ids["gap"]: ("paths", "gap"), ids["cor"]: ("paths", "corroboration"),
              ids["rec"]: ("paths", "recommendation"), ids["af"]: ("exposure", "finding")}
    for eid, (module, typ) in expect.items():
        assert links[eid]["module"] == module and links[eid]["type"] == typ and links[eid]["found"] is True, eid
    assert links[ids["fact"]] == {"id": ids["fact"], "module": "paths", "type": "quantity", "found": None,
                                  "note": "a quantity declared in the evidence bundle"}
    assert links[ids["ghost"]]["found"] is False  # an id not in the released report is flagged, not hidden
    assert set(links) == set(expect) | {ids["fact"], ids["ghost"]}
    c.get("/api/investigation")
    views = [e for e in audit(case, "dashboard view")[n_views:] if e["params"]["section"] == "investigation"]
    assert len(views) == 2 and views[0]["actor"] == "ines" and views[0]["role"] == "approver"
    page = c.get("/").text
    assert "Advisory \\u2014 AI-generated hypotheses, not findings" in page
    assert "Deterministic fixture output \\u2014 not AI inference" in page


def test_resolve_evidence_prefixes():
    idx = {"finding": {"AF-x"}, "path": set(), "table_claim": set(), "anomaly": set(), "gap": set(),
           "corroboration": set(), "recommendation": set()}
    assert D.resolve_evidence("AF-x", idx)["found"] is True
    assert D.resolve_evidence("AF-y", idx) == {"id": "AF-y", "module": "exposure", "type": "finding", "found": False,
                                               "section": "exposure"}
    assert D.resolve_evidence("FACT-scope-1", idx)["module"] == "scope"
    assert D.resolve_evidence("FACT-1", idx)["module"] is None
    assert D.resolve_evidence("XYZ-1", idx)["type"] == "unknown"
    assert D.referenced_ids({"hypotheses": [{"supporting_evidence": ["PATH-1", "<script>"], "quantities": [
        {"fact_id": "FACT-2"}]}], "remediation": [{"evidence_ids": ["PATH-1", "REC-3"]}]}) == ["PATH-1", "FACT-2", "REC-3"]


def test_output_guard_keeps_ids_and_redacts_identifier_like_text():
    assert D.scrub({"run": "RUN-0123456789ab", "f": ["FACT-0821234567"]}) == {
        "run": "RUN-0123456789ab", "f": ["FACT-0821234567"]}
    out = D.scrub({"note": "call 0821234567 or mail a.person@example.org", "n": 5, "x": None})
    assert "0821234567" not in out["note"] and "@" not in out["note"] and out["n"] == 5 and out["x"] is None
