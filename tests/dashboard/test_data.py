"""Workbench read models: values agree with the released report files; paging, filters and validation; missing data
is a status and never 0."""

import json
from collections import Counter

import pytest
from dashkit import API, report, signed_in

from tripline_scope.core.canonical import sha256_file
from tripline_scope.core.reports import ReportStore
from tripline_scope.core.timeutil import parse_utc
from tripline_scope.dashboard import data as D


def _timeline_lines(case_dir):
    p = case_dir / "reports" / "paths" / "v0001" / "attachments" / "timeline.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


# ------------------------------------------------------------------------------------------------ overview
def test_overview_agrees_with_reports(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    ov = c.get("/api/overview").json()
    assert ov["case_id"] == "DASH-001" and ov["mode"] == "incident" and ov["case_status"] == "open"
    assert ov["incident_window"] == {"start": "2026-09-01T00:00:00Z", "end": "2026-09-14T23:59:59Z"}
    assert ov["legal_hold"]["active"] is False
    rs = ReportStore(case)
    for kind in ("exposure", "paths", "scope"):
        vs = rs.versions(kind)
        r = ov["reports"][kind]
        assert r["status"] == "released" and r["released_versions"] == [n for n, _ in vs]
        rel = json.loads((vs[-1][1] / "release.json").read_bytes())
        assert r["report_sha256"] == rel["report_sha256"] == sha256_file(vs[-1][1] / "report.json")
        assert r["approved_by"] == "ines" == rel["approval"]["approver"]
        assert r["approved_at"] == rel["approval"]["approved_at"]
        assert r["draft_present"] is False
    assert ov["reports"]["scope"]["report_status"] == "refined"
    for kind in ("investigation", "readiness"):
        assert ov["reports"][kind]["status"] == "awaiting_analysis" and ov["reports"][kind]["released_versions"] == []
    ev = ov["evidence_state"]
    assert ev["sources_registered"] == len(case.sources())
    assert ev["latest_source_received_at"] == max(s["received_at"] for s in case.sources())
    approvals = [json.loads((p / "release.json").read_bytes())["approval"]["approved_at"]
                 for k in ("exposure", "paths", "scope") for _, p in rs.versions(k)]
    assert ev["latest_release_approved_at"] == max(approvals)
    pb = report(built.case_dir, "paths", 1)
    mb = ov["module_b"]
    assert mb["gaps"]["total"] == len(pb["gaps"])
    assert mb["gaps"]["by_kind"] == dict(Counter(g["kind"] for g in pb["gaps"]))
    assert mb["sources"] == len(pb["inputs"]["sources"])
    assert mb["families_present"] == sorted({s["family"] for s in pb["inputs"]["sources"]})
    assert mb["missing_source_families"] == []  # the acceptance logs cover every family group
    assert mb["forensic_not_covered"] == pb["forensic_handoff"]["not_covered"]
    assert mb["paths_by_class"] == pb["classification"]["paths_by_class"]
    assert ov["score"] is None  # no invented overall score


def test_missing_source_families_are_listed():
    body = {"inputs": {"sources": [{"source_id": "SRC-1", "family": "mssql_audit"}]}, "gaps": []}

    class FakeCase:  # only what _module_b_coverage touches through released()
        pass

    import tripline_scope.dashboard.data as mod

    orig = mod.released
    try:
        mod.released = lambda case, kind, version=None: (1, None, body)
        mb = mod._module_b_coverage(FakeCase())
    finally:
        mod.released = orig
    groups = [m["group"] for m in mb["missing_source_families"]]
    assert "database audit" not in groups
    assert set(groups) == {"identity provider sign-ins", "VPN", "host security (Windows)", "web server",
                           "network flow (firewall / proxy)"}


# ------------------------------------------------------------------------------------------------ people
def test_people_counts_agree_and_never_person_level(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    p = c.get("/api/people").json()
    v1, v2 = report(built.case_dir, "scope", 1), report(built.case_dir, "scope", 2)
    assert v1["report_status"] == "preliminary" and v2["report_status"] == "refined"
    pe = p["preliminary_estimate"]
    assert pe["report_version"] == 1
    assert pe["people"] == {k: v1["counts"]["unique_people"][k] for k in ("point", "lower", "upper")}
    # "not determinable" in the preliminary report is a status, never 0
    assert v1["scope_tiers"]["observed_access"]["count"] == "not determinable"
    assert pe["scope_tiers"]["observed_access"]["count"]["status"] == "not_determinable"
    rf = p["refined"]
    assert rf["report_version"] == 2
    tiers = v2["scope_tiers"]
    assert rf["scope_tiers"]["possible_exposure"]["count"] == tiers["possible_exposure"]["count"]
    assert rf["scope_tiers"]["observed_access"]["count"] == tiers["observed_access"]["count"]
    assert rf["scope_tiers"]["confirmed_exfiltration"]["count"] == tiers["confirmed_exfiltration"]["count"]
    assert rf["scope_tiers"]["notification_scope"]["proposed_count"] == tiers["notification_scope"]["proposed_count"]
    assert rf["scope_tiers"]["notification_scope"]["decided_by"] is None
    assert rf["counts"]["unique_people"] == v2["counts"]["unique_people"]
    assert rf["counts"]["bounds"]["lower"] == v2["counts"]["bounds"]["lower"]
    assert rf["counts"]["bounds"]["upper"] == v2["counts"]["bounds"]["upper"]
    assert rf["counts"]["people_per_category"] == v2["counts"]["people_per_category"]
    assert rf["counts"]["notification_routes"] == v2["counts"]["notification_routes"]
    assert rf["unresolvable_rows"]["totals"] == v2["counts"]["unresolvable_rows"]
    per_src = {sid: sum(t.get("unresolvable_identity_rows", 0) for t in s["tables"])
               for sid, s in v2["rows_per_source"].items()}
    assert {k: v["identity_rows"] for k, v in rf["unresolvable_rows"]["per_source"].items()} == per_src
    assert rf["matching"]["bands"] == v2["matching"]["bands"]
    assert rf["matching"]["blocking_rules"] == len(v2["matching"]["blocking_rules"])
    assert rf["measured_error_rates"] == v2["measured_error_rates"]
    person_keys = {"row_key", "person_key", "person_id", "first", "first_name", "last", "surname", "maiden", "dob",
                   "sa_id", "passport", "phone", "email", "postal", "contact", "guardian"}

    def walk(o):  # no person-level field and no row-sized list anywhere
        if isinstance(o, dict):
            assert not person_keys & set(o), set(o) & person_keys
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            assert len(o) <= 50
            for v in o:
                walk(v)

    walk(p)


def test_people_view_unit_statuses():
    body = {"report_status": "refined", "counts": {"unique_people": None, "bounds": {},
                                                   "unresolvable_rows": "not determinable (no extract)"},
            "scope_tiers": {"possible_exposure": {"basis": "inference", "count": None},
                            "observed_access": {"basis": "unknown", "count": "not determinable"}}}
    v = D.people_view(None, (3, body))
    assert v["preliminary_estimate"]["status"] == "awaiting_analysis"
    r = v["refined"]
    assert r["counts"]["unique_people"]["status"] == "not_determinable"
    assert r["counts"]["bounds"]["lower"]["status"] == "not_determinable"
    assert r["scope_tiers"]["possible_exposure"]["count"]["status"] == "not_determinable"
    assert r["scope_tiers"]["observed_access"]["count"] == {"status": "not_determinable", "reason": "not determinable"}
    assert r["scope_tiers"]["confirmed_exfiltration"]["status"] == "not_determinable"
    assert r["unresolvable_rows"]["totals"]["total"]["status"] == "not_determinable"
    assert r["measured_error_rates"]["status"] == "not_assessed"
    assert D.quantity(0) == 0 and D.quantity(None)["status"] == "not_determinable"


# ------------------------------------------------------------------------------------------------ exposure
def test_exposure_counts_agree(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    x = c.get("/api/exposure").json()
    body = report(built.case_dir, "exposure", 1)
    assert x["summary"] == body["summary"]
    assert len(x["findings"]) == body["summary"]["findings"] == len(body["findings"])
    by_sev = Counter(f["severity"] for f in x["findings"])
    assert {k: v for k, v in body["summary"]["by_severity"].items() if v} == dict(by_sev)
    assert dict(Counter(f["control_id"] for f in x["findings"])) == body["summary"]["by_control"]
    f0, b0 = x["findings"][0], body["findings"][0]
    assert (f0["finding_id"], f0["rule_id"], f0["asset_id"], f0["suggested_fix"], f0["confidence"], f0["basis"]) == (
        b0["finding_id"], b0["rule_id"], b0["asset"]["asset_id"], b0["suggested_fix"]["text"], b0["confidence"],
        b0["basis"])
    assert set(x["coverage"]) == set(body["coverage"])
    for cid, cov in x["coverage"].items():
        assert cov["status"] == body["coverage"][cid]["status"]
        assert cov["assessed_units"] == len(body["coverage"][cid]["assessed"])
        assert len(cov["not_assessed"]) == len(body["coverage"][cid]["not_assessed"])
    xr = x["module_b_cross_references"]
    assert xr["label"] == "cross-referenced by Module B containment advice; not evidence of causation"
    pb = report(built.case_dir, "paths", 1)
    expected = {}
    for rec in pb["containment"]["recommendations"]:
        for ref in rec["module_a_refs"]:
            expected.setdefault(ref["finding_id"], []).append(rec["rec_id"])
    assert xr["by_finding"] == expected


def test_exposure_cross_references_unit():
    body = {"findings": [{"finding_id": "AF-1", "severity": "high", "asset": {"asset_id": "AST-X"}}], "summary": {}}
    paths_body = {"containment": {"recommendations": [
        {"rec_id": "REC-a", "module_a_refs": [{"finding_id": "AF-1"}]},
        {"rec_id": "REC-b", "module_a_refs": ["AF-1", "AF-2"]},
        {"rec_id": "REC-c", "module_a_refs": []}]}}
    v = D.exposure_view(body, paths_body)
    assert v["module_b_cross_references"]["by_finding"] == {"AF-1": ["REC-a", "REC-b"], "AF-2": ["REC-b"]}
    assert "not evidence of causation" in v["module_b_cross_references"]["label"]
    assert D.exposure_view(body, None)["module_b_cross_references"]["status"] == "not_assessed"


# ------------------------------------------------------------------------------------------------ paths
def test_paths_agree_and_labels_never_upgraded(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    p = c.get("/api/paths").json()
    body = report(built.case_dir, "paths", 1)
    assert p["paths_by_class"] == body["classification"]["paths_by_class"]
    assert p["sensitive_tables_by_class"] == body["classification"]["sensitive_tables_by_class"]
    assert len(p["paths"]) == len(body["paths"])
    assert dict(Counter(x["consequence_class"] for x in p["paths"])) == body["classification"]["paths_by_class"]
    seen_labels = set()
    for view, src in zip(p["paths"], body["paths"], strict=True):
        assert view["path_id"] == src["path_id"] and view["consequence_class"] == src["consequence_class"]
        stage_labels = {s["stage"]: s["label"] for s in src["stages"]}
        assert {e["stage"]: e["label"] for e in view["edges"]} == stage_labels
        for e in view["edges"]:
            seen_labels.add(e["label"])
            assert e["path_id"] == src["path_id"] and e["evidence_ids"] == src["claim"]["evidence_ids"]
            if stage_labels[e["stage"]] in ("correlated", "unresolved"):
                assert e["label"] != "direct"
        node_ids = {n["id"] for n in view["nodes"]}
        assert all(e["from"] in node_ids and e["to"] in node_ids for e in view["edges"])
        for n in view["nodes"]:
            assert n["path_id"] == src["path_id"] and n["evidence_ids"] == src["claim"]["evidence_ids"]
        kinds = [n["kind"] for n in view["nodes"]]
        assert kinds[:5] == ["identity", "network", "host_application", "database_host", "tables"]
        assert kinds[-1] == "egress" and ("staging" in kinds) == ("staging" in stage_labels)
        tables = next(n for n in view["nodes"] if n["kind"] == "tables")["values"]["tables"]
        assert [(t["table"], t["consequence_class"]) for t in tables] == [
            (t["table"], t["consequence_class"]) for t in src["tables"]]
    assert seen_labels == {"direct", "correlated", "unresolved", "observed"}
    # a label outside the vocabulary is shown as unresolved, never upgraded
    weird = dict(body["paths"][0], stages=[dict(s, label="strong") for s in body["paths"][0]["stages"]])
    assert {e["label"] for e in D.path_view(weird, {})["edges"]} == {"unresolved"}


# ------------------------------------------------------------------------------------------------ timeline
def test_timeline_paging(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    lines = _timeline_lines(built.case_dir)
    t = c.get("/api/timeline").json()
    assert t["total"] == len(lines) and t["offset"] == 0 and t["limit"] == 100 and len(t["events"]) == 100
    assert [e["event_id"] for e in t["events"]] == [x["event_id"] for x in lines[:100]]
    t = c.get("/api/timeline?limit=1000").json()
    assert t["limit"] == 500 and len(t["events"]) == 500
    ids = []
    offset = 0
    while True:
        page = c.get(f"/api/timeline?limit=500&offset={offset}").json()
        assert page["total"] == len(lines) and page["offset"] == offset
        ids += [e["event_id"] for e in page["events"]]
        if offset + 500 >= page["total"]:
            assert len(page["events"]) == page["total"] - offset
            break
        offset += 500
    assert ids == [x["event_id"] for x in lines] and len(set(ids)) == len(lines)
    beyond = c.get(f"/api/timeline?offset={len(lines) + 10}").json()
    assert beyond["total"] == len(lines) and beyond["events"] == []
    e0 = t["events"][0]
    assert set(e0) >= {"event_id", "source_id", "family", "ts_utc", "ts_utc_earliest", "ts_utc_latest", "tz_original",
                       "time_precision", "host", "asset_id", "account_ref", "account_label", "operation",
                       "observation_type", "objects", "consequence_class", "path_ids", "anomaly_ids",
                       "indicator_match"}
    assert "raw_sha256" not in e0 and "url_path" not in e0 and "remote_ip" not in e0


def test_timeline_filters(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    lines = _timeline_lines(built.case_dir)

    def total(qs):
        r = c.get("/api/timeline?" + qs + "&limit=500")
        assert r.status_code == 200, r.text
        return r.json()

    t = total("class=access_observed")
    assert t["total"] == sum(1 for x in lines if x["consequence_class"] == "access_observed") > 0
    assert all(e["consequence_class"] == "access_observed" for e in t["events"])
    acct = next(x["account_ref"] for x in lines if x["consequence_class"] == "access_observed")
    t = total(f"account={acct}")
    assert t["total"] == sum(1 for x in lines if x["account_ref"] == acct) > 0
    assert all(e["account_ref"] == acct for e in t["events"])
    t = total("family=vpn")
    assert t["total"] == sum(1 for x in lines if x["family"] == "vpn") > 0
    t = total("source=SRC-012&class=access_observed")
    assert t["total"] == sum(1 for x in lines if x["source_id"] == "SRC-012"
                             and x["consequence_class"] == "access_observed") > 0
    start, end = "2026-09-03T23:00:00Z", "2026-09-04T01:00:00Z"
    s, e = parse_utc(start), parse_utc(end)
    want = [x["event_id"] for x in lines
            if parse_utc(x["ts_utc_latest"]) >= s and parse_utc(x["ts_utc_earliest"]) <= e]
    t = total(f"start={start}&end={end}")
    assert t["total"] == len(want) > 0 and [x["event_id"] for x in t["events"]] == want[:500]
    body = report(built.case_dir, "paths", 1)
    for g in t["gaps"]:  # gaps overlapping the window (open-ended gaps included)
        assert (g["start"] is None or parse_utc(g["start"]) <= e) and (g["end"] is None or parse_utc(g["end"]) >= s)
    assert len(t["gaps"]) < len(body["gaps"])
    assert any(g["kind"] == "log_cleared" for g in t["gaps"])
    t = total("asset=AST-LABSQL01")
    assert t["total"] > 0 and {x["asset_id"] for x in t["events"]} == {"AST-LABSQL01"}
    assert {x["host"].split(".")[0].lower() for x in t["events"]} == {"labsql01"}
    assert total("asset=labsql01")["total"] == t["total"]


@pytest.mark.parametrize("qs", [
    "start=yesterday", "start=2026-09-01T00:00:00", "end=2026-13-01T00:00:00Z", "start=2026-09-05T00:00:00Z&end=2026-09-01T00:00:00Z",
    "class=stolen", "class=", "family=syslog", "source=SRC-1;DROP", "source=12", "account=bob",
    "account=ACCT-ZZZZ", "asset=../etc", "asset=%3Cscript%3E", "limit=0", "limit=-5", "limit=abc", "limit=1e3",
    "offset=-1", "offset=1.5", "offset=99999999999", "limit=10&limit=20", "foo=bar", "start=" + "9" * 100,
])
def test_timeline_rejects_bad_parameters(dash, qs):
    case, store, home = dash
    c = signed_in(case, store, home)
    if qs == "class=":
        assert c.get("/api/timeline?" + qs).status_code == 200  # empty means "any"
        return
    r = c.get("/api/timeline?" + qs)
    assert r.status_code == 400, (qs, r.status_code, r.text)
    assert "error" in r.json()


# ------------------------------------------------------------------------------------------------ nothing released
def test_nothing_released_is_never_zero(empty_case):
    case, store, home = empty_case
    c = signed_in(case, store, home, user="rami")
    ov = c.get("/api/overview").json()
    assert all(r["status"] == "awaiting_analysis" for r in ov["reports"].values())
    assert ov["module_b"]["status"] == "awaiting_analysis"
    assert ov["evidence_state"]["latest_source_received_at"]["status"] == "not_assessed"
    assert ov["evidence_state"]["latest_release_approved_at"]["status"] == "awaiting_analysis"
    t = c.get("/api/timeline").json()
    assert t["status"] == "awaiting_analysis" and t["total"] is None and t["events"] == []
    assert c.get("/api/paths").json()["status"] == "awaiting_analysis"
    assert c.get("/api/exposure").json()["status"] == "awaiting_analysis"
    p = c.get("/api/people").json()
    assert p["status"] == "awaiting_analysis"
    assert p["preliminary_estimate"]["status"] == "awaiting_analysis" and p["refined"]["status"] == "awaiting_analysis"
    i = c.get("/api/investigation").json()
    assert i == {"status": "not_performed", "reason": "no authorised AI analysis has been run for this case",
                 "advisory": True}
    rep = c.get("/api/reports").json()
    assert all(k["status"] == "awaiting_analysis" and k["versions"] == [] for k in rep["kinds"].values())
    for path in API:  # no count anywhere is a bare 0 standing in for "missing"
        body = c.get(path).json()

        def walk(o, key=None):
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, k)
            elif isinstance(o, list):
                for v in o:
                    walk(v, key)
            elif o == 0 and not isinstance(o, bool):
                assert key in ("offset", "sources_registered", "declared_gaps", "operators", "reviewers",
                               "approvers"), (path, key)

        walk(body)


def test_reports_listing_and_verification(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    r = c.get("/api/reports").json()
    rs = ReportStore(case)
    for kind in ("exposure", "paths", "scope"):
        k = r["kinds"][kind]
        assert k["verification"]["ok"] is True and k["verification"]["failed"] == []
        assert [v["version"] for v in k["versions"]] == [n for n, _ in rs.versions(kind)]
        for v in k["versions"]:
            rel = json.loads((rs.kind_dir(kind) / f"v{v['version']:04d}" / "release.json").read_bytes())
            assert v["report_sha256"] == rel["report_sha256"] and v["artefacts"] == rel["artefacts"]
            assert v["approval"]["approver"] == rel["approval"]["approver"]
            assert v["provider_cosigned"] is rel["provider_cosigned"]
            assert set(v["files"]) <= {"report.json", "report.pdf", "release.json", "signatures.json"}
            for name, url in v["files"].items():
                assert c.get(url).content == (rs.kind_dir(kind) / f"v{v['version']:04d}" / name).read_bytes()
    assert c.get("/api/reports?refresh=1").json()["kinds"]["paths"]["verification"]["ok"] is True
    assert c.get("/api/reports?refresh=yes").status_code == 400


def test_verification_failure_is_rendered(dash, built, monkeypatch):
    """Verification results are cached per process; ?refresh=1 recomputes and a failure carries the rendering."""
    case, store, home = dash
    c = signed_in(case, store, home)
    assert c.get("/api/reports").json()["kinds"]["exposure"]["verification"]["ok"] is True

    class Bad:
        ok = False
        checks = []

        def render(self):
            return f"FAIL  {ReportStore(case).kind_dir('exposure')}\n  [FAIL] v0001: hospital signature"

    monkeypatch.setattr(ReportStore, "verify", lambda self, kind, home, version=None: Bad())
    assert c.get("/api/reports").json()["kinds"]["exposure"]["verification"]["ok"] is True  # cached
    v = c.get("/api/reports?refresh=1").json()["kinds"]["exposure"]["verification"]
    assert v["ok"] is False and "hospital signature" in v["render"]
    assert str(case.root) not in v["render"]  # local paths are not shown
