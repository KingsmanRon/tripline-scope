"""Acceptance: path reconstruction on a synthetic multi-source incident with known ground truth."""

import pyarrow.compute as pc
from paths_helpers import activate, edges_between, find_units

from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.paths.analyse import CORRELATED_CAP, DIRECT_CONFIDENCE


def test_every_family_parses_without_failures(acc):
    by_family = {s["family"] for s in acc.ingest["sources"]}
    assert {"mssql_audit", "pgaudit", "iis", "nginx", "win_security", "entra_signin", "vpn", "firewall", "proxy",
            "generic", "indicators"} <= by_family
    assert acc.ingest["parse_failures"] == 0
    assert acc.ingest["events"] > 20_000
    assert acc.ingest["indicators_rejected"] == acc.truth["indicator"]["rejected_without_provenance"]


def test_direct_edges_recovered_where_identifiers_exist(acc):
    for exp in acc.truth["expected_direct_edges"]:
        es = edges_between(acc.analysis, exp["from"], exp["to"])
        assert es, f"missing direct edge {exp}"
        assert all(e["label"] == "direct" and e["basis"] == "observation" for e in es)
        assert all(e["confidence"] >= DIRECT_CONFIDENCE for e in es)


def test_temporal_links_remain_inferences(acc):
    for exp in acc.truth["expected_correlated_edges"]:
        es = edges_between(acc.analysis, exp["from"], exp["to"])
        assert es, f"missing correlated edge {exp}"
        for e in es:
            assert e["label"] == "correlated" and e["basis"] == "inference"
            assert e["confidence"] <= CORRELATED_CAP < DIRECT_CONFIDENCE
            assert e["window"] and e["window"].get("configured_s") is not None
            assert e["confidence_reason"]


def test_missing_links_are_not_invented(acc):
    for exp in acc.truth["expected_absent_edges"]:
        assert not edges_between(acc.analysis, exp["from"], exp["to"]), exp
    # rows without session ids never get direct edges
    for sel in acc.truth["expected_no_direct_edges_for"]:
        units = find_units(acc.analysis, sel)
        assert units and all("no_session_id" in u["flags"] for u in units)
        ids = {u["unit_id"] for u in units}
        assert not [e for e in acc.analysis["edges"] if e["label"] == "direct" and ({e["from"], e["to"]} & ids)]
    # a session with no upstream evidence stops at the database stage
    for sel in acc.truth["expected_unresolved_upstream"]:
        ids = {u["unit_id"] for u in find_units(acc.analysis, sel)}
        assert ids and not [e for e in acc.analysis["edges"] if e["to"] in ids]
        path = next(p for p in acc.analysis["paths"] if set(p["sessions"]) & ids)
        upstream = [s for s in path["stages"] if s["stage"] in ("web_identity", "network", "host_application")]
        assert upstream and all(s["label"] == "unresolved" and s["reason"] for s in upstream)


def test_nat_address_is_shared_and_users_are_not_merged(acc):
    a = acc.analysis
    for ip in acc.truth["shared_ips"]:
        assert ip in a["shared_ips"]
    zp = next(p for p in a["paths"] if p["route"]["account"] == "LAB\\z.patel")
    assert "k.smith@lab.example" not in [x.lower() for x in zp["upstream_accounts"]]
    ident = next(s for s in zp["stages"] if s["stage"] == "web_identity")
    assert ident["label"] == "correlated" and ident["confidence"] < 0.5
    e = edges_between(a, {"family": "entra_signin", "account": "z.patel@lab.example"}, {"family": "vpn", "session_id": "VPN-7790"})
    assert e and "shared_ip" in e[0]["flags"]


def test_attacker_chain_stops_where_evidence_stops(acc):
    a = acc.analysis
    p1 = next(p for p in a["paths"] if p["route"]["account"] == "LAB\\t.naidoo" and p["route"]["host"] == "labsql01")
    st = {s["stage"]: s for s in p1["stages"]}
    assert st["web_identity"]["label"] == "direct"           # sign-in request id carried by the VPN
    assert st["network"]["label"] == "correlated"            # VPN lease -> SQL client address
    assert st["host_application"]["label"] == "correlated"   # Windows network logon from the address
    assert st["egress"]["label"] == "correlated" and "185.220.101.47" in p1["egress_destinations"]
    assert p1["consequence_class"] == "egress_suspected"
    assert p1["chain_confidence"] < DIRECT_CONFIDENCE
    p2 = next(p for p in a["paths"] if p["route"]["account"] == "LAB\\t.naidoo" and p["route"]["host"] == "labsql02")
    assert {s["stage"]: s for s in p2["stages"]}["host_application"]["label"] == "unresolved"
    assert p1["rank"] <= 2 and p2["rank"] <= 3
    assert any("initial intrusion vector" in x for x in p1["limitations"])


def test_gaps_are_reported_not_filled(acc):
    gaps = acc.analysis["gaps"]
    off = [g for g in gaps if g["kind"] == "auditing_disabled"]
    assert off and off[0]["database"] == acc.truth["audit_off"]["database"]
    assert off[0]["start"] == acc.truth["audit_off"]["start"] and off[0]["end"] == acc.truth["audit_off"]["end"]
    assert any(g["kind"] == "log_cleared" and g["host"] == "labsql01" for g in gaps)
    assert any(g["kind"] == "declared_missing" for g in gaps)
    tz = [g for g in gaps if g["kind"] == "time_zone_unknown"]
    assert tz and all(g["consequence_class"] == "undetermined" for g in gaps)


def test_table_and_window_classes_match_ground_truth(acc):
    tables = {t["table"]: t for t in acc.analysis["tables"]}
    for name, cls in acc.truth["expected_table_classes"].items():
        assert tables[name]["consequence_class"] == cls, name
    for name, wc in acc.truth["expected_window_classes"].items():
        assert tables[name]["window_class"] == wc, name
    for name in acc.truth["no_access_observed_tables"]:
        assert tables[name]["status"] == "no_access_observed" and tables[name]["consequence_class"] is None


def test_access_never_becomes_theft(acc):
    a = acc.analysis
    for p in a["paths"]:
        assert p["consequence_class"] != "exfiltration_evidenced"      # logs alone never evidence exfiltration
    ex = [t for t in a["tables"] if t["consequence_class"] == "exfiltration_evidenced"]
    assert [t["table"] for t in ex] == ["LabDB07.dbo.patients"]
    claim = ex[0]["claim"]
    assert claim["exfiltration_evidence_kind"] == "independently_confirmed_external_copy" and claim["evidence_ids"]
    assert "does not establish" in claim["statement"].lower()
    sel = next(t for t in a["tables"] if t["table"] == "LabDB07.dbo.results")
    assert sel["consequence_class"] == "access_observed"            # read in the same session, never exported


def test_harmless_bulk_import_is_not_export(acc):
    a = acc.analysis
    for acct in acc.truth["harmless"]["accounts"]:
        assert not [x for x in a["anomalies"] if acct in x["accounts"] and x["detector"] in ("dump_export", "bulk_read")]
        for p in a["paths"]:
            if p["route"]["account"] == acct:
                assert p["consequence_class"] == "access_observed"


def test_detectors_expose_assumptions_and_find_the_incident(acc):
    a = acc.analysis
    for name, info in a["detectors"].items():
        assert info["assumptions"] and info["false_positive_caveats"] and "status" in info, name
    att = [x for x in a["anomalies"] if "LAB\\t.naidoo" in x["accounts"]]
    found = {x["detector"] for x in att}
    assert {"bulk_read", "dump_export", "privilege_grant", "auditing_disabled", "first_seen_sensitive_access",
            "off_hours"} <= found
    assert any(x["detector"] == "web_admin_before_db" and x["details"]["linked_db_units"] for x in a["anomalies"])
    assert any(x["detector"] == "new_source_location" and x["details"]["attribute"] == "sign-in country" for x in a["anomalies"])
    # volume unknown where rows are not logged (LABSQL02 export has no row counts)
    assert "LabDB07.dbo.patients" in a["detectors"]["bulk_read"]["sessions_with_volume_unknown"]


def test_indicator_matches_carry_provenance_not_attribution(acc):
    ms = acc.analysis["indicator_matches"]
    assert ms and all(m["provenance"] and "not attribution" in m["statement"] for m in ms)
    assert any(m["indicator_value"] == acc.truth["indicator"]["value"] for m in ms)


def test_time_normalisation(acc, monkeypatch):
    activate(acc, monkeypatch)
    store = open_store(Case(acc.case_dir), Home())
    ids = {s["label"]: s["source_id"] for s in store.read_json("work/paths/sources.json").values()}
    vpn = store.read_table(f"work/paths/events/{ids['vpn']}.parquet").to_pylist()
    att = next(r for r in vpn if r["session_id"] == "VPN-7781" and r["observation_type"] == "vpn_connect")
    assert att["tz_original"] == "+02:00" and att["tz_basis"] == "manifest"
    assert att["ts_utc"].isoformat().startswith("2026-09-03T23:06:00")
    assert att["ts_uncertainty_s"] is None                       # undocumented -> unknown, not zero
    fw = store.read_table(f"work/paths/events/{ids['firewall']}.parquet").to_pylist()
    flow = next(r for r in fw if r["dest_ip"] == "185.220.101.47")
    assert flow["clock_offset_s"] == 95 and flow["ts_utc"].isoformat().startswith("2026-09-04T00:35:00")
    pg = store.read_table(f"work/paths/events/{ids['lispg01']}.parquet").to_pylist()
    assert all(r["tz_original"] == "+02:00" and r["tz_basis"] == "record" for r in pg)
    iis = store.read_table(f"work/paths/events/{ids['web01-iis']}.parquet", columns=["tz_basis", "tz_original"]).to_pylist()
    assert {(r["tz_basis"], r["tz_original"]) for r in iis} == {("format", "Z")}
    mw = store.read_table(f"work/paths/events/{ids['middleware']}.parquet").to_pylist()
    assert all(r["ts_utc"] is None and r["tz_original"] == "unknown" and r["ts_utc_min"] and r["ts_utc_max"] for r in mw)
    signin = store.read_table(f"work/paths/events/{ids['entra-portal-csv']}.parquet").to_pylist()
    assert signin[0]["mfa"] == "unknown"


def test_no_statements_queries_or_secrets_in_normalised_events(acc, monkeypatch):
    activate(acc, monkeypatch)
    store = open_store(Case(acc.case_dir), Home())
    text = []
    for rel in store.list("work/paths/events"):
        t = store.read_table(rel)
        for name in t.column_names:
            col = t.column(name)
            if str(col.type) in ("string", "large_string"):
                text += [v for v in pc.unique(col).to_pylist() if v]
            elif str(col.type).startswith("list"):
                text += [v for v in pc.unique(pc.list_flatten(col)).to_pylist() if v]
    blob = "\n".join(text)
    for needle in acc.truth["secrets_never_in_outputs"] + ["hunter2", "?session", "token="]:
        if needle in ("synthetic.portal.user@example.com",):
            continue          # portal usernames are kept (encrypted) as the account of web events
        assert needle not in blob, needle
