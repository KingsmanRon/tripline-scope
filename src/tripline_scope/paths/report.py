"""``tscope paths report``: draft ``paths`` report (JSON + PDF + bounded timeline CSV/JSON Lines).

The body is deterministic (no wall-clock values) and carries ``method_version``, ``config_sha256``, the input
hashes, coverage and gaps, the ranked paths, anomalies, indicator matches, advisory containment, regulator-facing
fields and the three separate counts. The PDF is rendered from the same body, so both always state the same
classification. Release is the shared ``tscope release --kind paths`` (approver sign-in, hospital signature).
"""

from __future__ import annotations

import csv
import io
import json

import pyarrow as pa

from tripline_scope.core import duck, pdf
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import IntegrityError, NotReady
from tripline_scope.core.evidence import NOT_DETERMINABLE
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.reports import ReportStore

from . import containment
from .config import load_config
from .display import Display, safe_text
from .schema import METHOD_VERSION
from .util import as_utc, iso

CLASS_ORDER = ["exfiltration_evidenced", "egress_suspected", "export_or_staging_observed", "access_observed",
               "undetermined"]
EVIDENCE_RULE = {
    "access_observed": "Authenticated or otherwise attributable reading/querying of a table; proves access only within "
                       "log reliability and identity limits.",
    "export_or_staging_observed": "A dump/export command, generated export file or staged dataset; indicates a copy, "
                                  "not transmission beyond the hospital.",
    "egress_suspected": "Outbound flow or transfer indicator compatible with exfiltration, without payload/destination "
                        "evidence establishing which records left.",
    "exfiltration_evidenced": "Independently verifiable evidence of data leaving an authorised boundary, with a statement "
                              "of exactly what it establishes.",
    "undetermined": "Logging gaps or ambiguity prevent a supported determination.",
}
TIMELINE_COLUMNS = ["event_id", "source_id", "family", "record_locator", "ts_utc", "ts_utc_earliest", "ts_utc_latest",
                    "tz_original", "time_precision", "host", "account_ref", "account_label", "application", "operation",
                    "observation_type", "objects", "rows", "bytes", "outcome", "mfa", "remote_ip", "dest_ip", "url_path",
                    "http_status", "consequence_class", "path_ids", "anomaly_ids", "indicator_match", "raw_sha256"]


def _ordered_classes(counter: dict) -> dict:
    return {k: counter.get(k, 0) for k in CLASS_ORDER + ["no_access_observed"] if counter.get(k)}


def build(ctx, *, exposure_report: str | None = None, measures: list[str] | None = None,
          timeline_rows: int | None = None) -> dict:
    case, store = ctx.case, ctx.store
    if not store.exists("work/paths/analysis.json"):
        raise NotReady("no access-path analysis: run 'tscope paths analyse' first")
    a = store.read_json("work/paths/analysis.json")
    analysis_sha = sha256_hex(canonical_bytes(a))
    ctx.input("analysis", analysis_sha)
    cfg = load_config(case)
    if cfg != a["config"]:
        raise NotReady("case.yaml paths settings changed since the analysis: re-run 'tscope paths analyse'")
    disp = Display(store, cfg["directory_domains"])
    exposure = containment.load_exposure_report(exposure_report)
    if exposure:
        ctx.input("exposure_report", exposure["sha256"])
    cont = containment.build(a, disp, cfg, exposure)
    measures = [safe_text(m, 300) for m in (measures if measures is not None else cfg["measures_taken"]) if m]
    cap = int(timeline_rows or cfg["timeline_max_rows"])
    timeline, tl_meta = _timeline(store, a, disp, cap)
    body_content = _content(case, a, analysis_sha, cfg, disp, cont, measures, tl_meta)
    rs = ReportStore(case)
    body = rs.new_body("paths", **body_content)
    pdf_bytes = render_pdf(body)
    attachments = {"timeline.csv": timeline["csv"], "timeline.jsonl": timeline["jsonl"]}
    for name, data in attachments.items():
        kinds = find_identifier_like(data.decode("utf-8"))
        if kinds:
            raise IntegrityError(f"refusing to attach {name}: identifier-like values ({sorted(set(kinds))})")
    draft = rs.save_draft("paths", body, pdf=pdf_bytes, attachments=attachments)
    ctx.output("draft_report", draft.report_sha256)
    return {"draft_id": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256,
            "paths": len(body["paths"]), "recommendations": len(cont["recommendations"]),
            "timeline_rows": tl_meta["rows_exported"], "timeline_truncated": tl_meta["truncated"],
            "body": body, "pdf": pdf_bytes}


# ---------------------------------------------------------------------------------------------- content
def _content(case, a, analysis_sha, cfg, disp, cont, measures, tl_meta) -> dict:
    tables = a["tables"]
    by_cls: dict[str, int] = {}
    for t in tables:
        k = t["consequence_class"] or "no_access_observed"
        by_cls[k] = by_cls.get(k, 0) + 1
    path_cls: dict[str, int] = {}
    for p in a["paths"]:
        path_cls[p["consequence_class"]] = path_cls.get(p["consequence_class"], 0) + 1
    observed = [t for t in tables if t["consequence_class"] in ("access_observed", "export_or_staging_observed",
                                                                "egress_suspected", "exfiltration_evidenced")]
    exfil = [t for t in tables if t["consequence_class"] == "exfiltration_evidenced"]
    rows_logged = sum(w.get("rows_logged") or 0 for t in observed for w in t["windows"] if w["window_class"] == "confirmed")
    vol_unknown = any(w.get("volume_unknown") for t in observed for w in t["windows"] if w["window_class"] == "confirmed")
    counts = {
        "observed_access": {"tables": len(observed), "records": NOT_DETERMINABLE, "people": f"{NOT_DETERMINABLE} here "
                            "(person counts come from Module C)",
                            "rows_returned_as_logged": rows_logged if rows_logged else None,
                            "rows_note": ("rows returned by logged statements (sum; not distinct records" +
                                          ("; volume unknown for some access)" if vol_unknown else ")"))},
        "possible_exposure": {"tables": len(tables), "records": NOT_DETERMINABLE,
                              "people": f"{NOT_DETERMINABLE} here (person counts come from Module C)",
                              "note": "every sensitive table is kept in the upper scenario, including not-assessable "
                                      "and no-access-observed tables"},
        "confirmed_exfiltration": {"tables": len(exfil) if exfil else NOT_DETERMINABLE, "records": NOT_DETERMINABLE,
                                   "people": f"{NOT_DETERMINABLE} here (Module C matches corroborated copies to people)",
                                   "note": "only from independently verifiable evidence" if exfil else
                                   "no independently verifiable evidence of exfiltration was supplied; this does not "
                                   "show that no data left"},
        "notification_scope": "decided by the Information Officer with counsel; not proposed by this report",
    }
    paths_out = [_path_out(p, disp, a) for p in a["paths"][: cfg["max_paths_detailed"]]]
    rest = a["paths"][cfg["max_paths_detailed"]:]
    anomalies = [_anomaly_out(x, disp) for x in a["anomalies"]]
    regulator = _regulator(a, disp, measures, counts, tables)
    sources = []
    for c in a["coverage"]:
        inp = a["inputs"].get(c["source_id"], {})
        sources.append({"source_id": c["source_id"], "label": c["label"], "family": c["family"], "format": c["format"],
                        "parser": c["parser"], "files": [{"name": f["name"], "sha256": f["sha256"], "size": f["size"]}
                                                         for f in c["files"]][:200],
                        "file_count": len(c["files"]), "custody_manifest_sha256": inp.get("manifest_sha256"),
                        "evidence_role": inp.get("evidence_role"), "events": c.get("events"),
                        "indicators": c.get("indicators"), "parse_failures": c.get("parse_failures"),
                        "first_event_utc": c.get("first_event_utc"), "last_event_utc": c.get("last_event_utc"),
                        "events_without_resolvable_time": c.get("events_without_resolvable_time"),
                        "declared_coverage": c.get("declared_coverage"), "time_zone": c.get("zone"),
                        "completeness": c.get("completeness"), "completeness_problems": c.get("completeness_problems")})
    return {
        "report_status": "preliminary",
        "title": "Access-path analysis (Module B)",
        "method_version": METHOD_VERSION, "config_sha256": a["config_sha256"], "analysis_sha256": analysis_sha,
        "window": a["window"], "baseline": a["baseline"],
        "inputs": {"sources": sources,
                   "corroborations": [{k: c.get(k) for k in ("corroboration_id", "kind", "tables", "evidence_ids",
                                                            "evidence_sha256", "establishes", "does_not_establish",
                                                            "qualifies_as_exfiltration_evidence")}
                                      for c in a["corroborations"]],
                   "indicator_sources": sorted({i["indicator_id"].split("-")[1] + "-" + i["indicator_id"].split("-")[2]
                                                for i in a["indicators"]}),
                   "indicators_accepted": len(a["indicators"]), "indicators_rejected": len(a["indicators_rejected"]),
                   "exposure_report": cont["module_a"]},
        "evidence_rule": EVIDENCE_RULE,
        "classification": {"sensitive_tables_by_class": _ordered_classes(by_cls),
                           "paths_by_class": _ordered_classes(path_cls)},
        "counts": counts,
        "tables": [_table_out(t, disp) for t in tables],
        "paths": paths_out,
        "paths_not_detailed": {"count": len(rest), "by_class": _ordered_classes(
            {c: sum(1 for p in rest if p["consequence_class"] == c) for c in CLASS_ORDER})},
        "edges_summary": {"direct": sum(1 for e in a["edges"] if e["label"] == "direct"),
                          "correlated": sum(1 for e in a["edges"] if e["label"] == "correlated"),
                          "by_join": dict(sorted({e["join"]: sum(1 for x in a["edges"] if x["join"] == e["join"])
                                                  for e in a["edges"]}.items()))},
        "anomalies": anomalies, "detectors": a["detectors"],
        "indicator_matches": [{k: m[k] for k in ("match_id", "indicator_id", "indicator_type", "indicator_value",
                                                  "provenance", "reference", "event_id", "family", "field", "ts_utc",
                                                  "validity", "statement")} for m in a["indicator_matches"][:200]],
        "indicator_match_total": a["indicator_match_total"],
        "shared_addresses": a["shared_ips"],
        "gaps": a["gaps"],
        "containment": cont,
        "regulator": regulator,
        "timeline": tl_meta,
        "forensic_handoff": {
            "statement": "Each event id is <source id>:<ordinal>; record_locator gives the original file and line or "
                         "record number, and raw_sha256 the hash of the original record, so investigators can find "
                         "the exact record in the hospital's own copy of the log.",
            "not_covered": ["endpoint, memory, malware and full disk forensics",
                            "content of network transfers (no packet capture)",
                            "initial intrusion vector (not established without endpoint evidence)"],
        },
        "limitations": [
            "Module B works only from exported logs; it does not run live and does not replace endpoint, memory, malware "
            "or full digital forensics.",
            "Correlated links are inferences within configured time windows; temporal proximity is not causation.",
            "Absent or disabled logging is reported as a gap and never treated as absence of activity.",
            "Accounts are logged identifiers, not proof of which person acted.",
            "Rows returned are per statement and are not distinct patient records; where no row counts are logged the "
            "volume is unknown.",
        ],
    }


def _account_list(disp, accounts):
    return disp.accounts(accounts)


def _path_out(p, disp, a) -> dict:
    r = p["route"]
    return {
        "rank": p["rank"], "path_id": p["path_id"], "consequence_class": p["consequence_class"],
        "observation_type": p["observation_type"],
        "route": {"account": disp.account(r["account"]), "client_ip": r["client_ip"],
                  "client_host": safe_text(r.get("client_host"), 60), "database_host": r["host"],
                  "application": safe_text(r.get("application"), 80), "source_id": r["source_id"]},
        "sessions": p["session_count"], "first_activity": p["first_activity"], "last_activity": p["last_activity"],
        "earliest_supported": p["earliest_supported"], "latest_supported": p["latest_supported"],
        "stages": [{k: s.get(k) for k in ("stage", "label", "confidence", "unit_count", "unit_types", "alternatives",
                                          "reason")} for s in p["stages"]],
        "tables": [{k: t[k] for k in ("table", "sensitive", "operations", "observation_types", "consequence_class",
                                      "rows_logged", "volume", "first", "last", "evidence_ids", "corroborations",
                                      "egress_linked")} for t in p["tables"]],
        "upstream_accounts": disp.accounts(p["upstream_accounts"]),
        "egress_destinations": p["egress_destinations"], "egress_bytes_logged": p["egress_bytes_logged"],
        "anomalies": p["anomalies"], "indicator_matches": p["indicator_matches"],
        "confidence": p["confidence"], "chain_confidence": p["chain_confidence"],
        "chain_confidence_reason": p["chain_confidence_reason"], "limitations": p["limitations"],
        "claim": _claim_out(p["claim"]),
    }


def _claim_out(c: dict) -> dict:
    return {k: c.get(k) for k in ("claim_id", "statement", "basis", "consequence_class", "observation_type",
                                  "confidence", "confidence_reason", "evidence_ids", "source_ids", "parser",
                                  "time_precision", "source_time_window", "limitations", "exfiltration_evidence_kind")}


def _anomaly_out(x, disp) -> dict:
    d = {k: x[k] for k in ("anomaly_id", "detector", "detector_version", "title", "severity", "evidence_ids", "first",
                           "last", "assumptions", "false_positive_caveats")}
    d["accounts"] = disp.accounts(x["accounts"])
    d["path_ids"] = sorted(set(x.get("path_ids", [])))
    d["claim"] = _claim_out(x["claim"])
    det = dict(x.get("details") or {})
    if "new_scripts" in det:
        det["new_scripts"] = [safe_text(s, 120) for s in det["new_scripts"]]
    d["details"] = json.loads(json.dumps(det, default=str))
    return d


def _table_out(t, disp) -> dict:
    ws = []
    for w in t["windows"]:
        d = {k: w.get(k) for k in ("window_class", "start", "end", "basis", "consequence_class", "rows_logged",
                                   "volume_unknown", "reason", "paths", "session_count")}
        if w.get("accounts"):
            d["accounts"] = disp.accounts(w["accounts"])
        d["evidence_ids"] = (w.get("evidence_ids") or [])[:10]
        ws.append({k: v for k, v in d.items() if v is not None})
    return {"table": t["table"], "consequence_class": t["consequence_class"], "status": t["status"],
            "window_class": t["window_class"], "window_classes": t["window_classes"], "windows": ws,
            "covering_sources": t["covering_sources"], "paths": t["paths"], "corroborations": t["corroborations"],
            "claim": _claim_out(t["claim"])}


def _regulator(a, disp, measures, counts, tables) -> dict:
    observed = [t for t in tables if t["consequence_class"] not in (None, "undetermined")]
    known, unknown = {}, []
    for p in a["paths"]:
        if p["consequence_class"] == "access_observed" and not p["anomalies"]:
            continue
        acc = disp.account(p["route"]["account"])
        if acc:
            k = known.setdefault(acc["account_ref"], {**acc, "paths": [], "basis": "logged account (not proof of the "
                                                                                      "person)"})
            k["paths"].append(p["path_id"])
        ups = {s["stage"]: s for s in p["stages"]}
        if all(ups.get(s, {}).get("label") == "unresolved" for s in ("web_identity", "network", "host_application")):
            unknown.append({"path_id": p["path_id"], "description": "who used this account is not established beyond "
                                                                    "the logged account (no upstream evidence)"})
    web_unknown = [x for x in a["anomalies"] if x["detector"] == "web_admin_before_db" and not x["accounts"]]
    for x in web_unknown:
        unknown.append({"anomaly_id": x["anomaly_id"], "description": "unauthenticated external web requests to admin/"
                                                                      "upload paths: actor unknown"})
    systems = {}
    asset_by_host = {str(s.get("host") or "").lower().split(".")[0]: s.get("asset_id") for s in a["inputs"].values()}
    for p in a["paths"]:
        if p["consequence_class"] == "access_observed" and not p["anomalies"]:
            continue
        h = p["route"]["host"]
        sysd = systems.setdefault(h, {"host": h, "asset_id": asset_by_host.get(h or ""), "databases": set(),
                                      "applications": set()})
        for t in p["tables"]:
            if t["sensitive"]:
                sysd["databases"].add(t["table"].split(".")[0])
        if p["route"].get("application"):
            sysd["applications"].add(safe_text(p["route"]["application"], 80))
    missing = [{"kind": g["kind"], "scope": g["scope"], "source_id": g["source_id"], "host": g["host"],
                "database": g["database"], "start": g["start"], "end": g["end"], "description": g["description"]}
               for g in a["gaps"]]
    missing.append({"kind": "out_of_scope", "description": "No endpoint, memory or malware forensics and no packet "
                                                           "capture were available to Module B."})
    return {
        "observed_access": [{"table": t["table"], "consequence_class": t["consequence_class"],
                             "windows": [{"start": w["start"], "end": w["end"]} for w in t["windows"]
                                         if w["window_class"] == "confirmed"][:20]} for t in observed],
        "classification_statement": "Outcomes are classified separately from the suspected consequence: access, "
                                    "export/staging, suspected egress and evidenced exfiltration are distinct; none is "
                                    "promoted to a stronger class without the evidence that class requires.",
        "counts": counts,
        "known_actors": [dict(v, paths=sorted(set(v["paths"]))) for _k, v in sorted(known.items())],
        "unknown_actors": unknown,
        "affected_systems": [{"host": s["host"], "asset_id": s["asset_id"], "databases": sorted(s["databases"]),
                              "applications": sorted(x for x in s["applications"] if x)}
                             for _h, s in sorted(systems.items(), key=lambda x: x[0] or "")],
        "measures_taken": measures or ["not supplied by the hospital"],
        "missing_evidence": missing,
        "notification_note": "The Information Officer and counsel decide notification and legal characterisation. "
                             "Absence of proven exfiltration does not by itself remove possible notification "
                             "obligations.",
    }


# ---------------------------------------------------------------------------------------------- timeline
def _timeline(store, a, disp, cap: int) -> tuple[dict, dict]:
    rels = store.list("work/paths/events")
    path_by_event, anom_by_event = {}, {}
    units = {u["unit_id"]: u for u in a["units"]}
    notable = set()
    edges = {e["edge_id"]: e for e in a["edges"]}
    for p in a["paths"]:
        ev = set()
        uids = set(p["sessions"] + p["egress_units"] + p["staged_files"])
        if p["consequence_class"] != "access_observed" or p["anomalies"]:
            uids |= {x for eid in p["edges"] for x in (edges[eid]["from"], edges[eid]["to"]) if eid in edges}
        for uid in uids:
            ev |= set(units.get(uid, {}).get("evidence_ids", []))
        for t in p["tables"]:
            ev |= set(t["evidence_ids"])
        for e in ev:
            path_by_event.setdefault(e, set()).add(p["path_id"])
        if p["consequence_class"] != "access_observed" or p["anomalies"]:
            notable |= ev
    for x in a["anomalies"]:
        for e in x["evidence_ids"]:
            anom_by_event.setdefault(e, set()).add(x["anomaly_id"])
    ind_events = {m["event_id"] for m in a["indicator_matches"]}
    gap_events = {e for g in a["gaps"] for e in g.get("evidence_ids", [])}
    tier0 = sorted(notable | set(anom_by_event) | ind_events | gap_events)
    tier1 = sorted(set(path_by_event) - set(tier0))
    rows: list[dict] = []
    total = 0
    if rels:
        cols = ["event_id", "source_id", "source_family", "record_locator", "ts_utc", "ts_utc_min", "ts_utc_max",
                "tz_original", "time_precision", "host", "account", "application", "operation", "observation_type",
                "objects", "rows", "bytes", "outcome", "mfa", "remote_ip", "dest_ip", "url_path", "http_status",
                "consequence_class", "raw_sha256", "ordinal"]
        tbl = store.read_tables(rels, columns=cols)
        for name in ("ts_utc", "ts_utc_min", "ts_utc_max"):
            i = tbl.schema.get_field_index(name)
            tbl = tbl.set_column(i, name, tbl.column(name).cast(pa.timestamp("us")))
        con = duck.connect()
        con.register("ev", tbl)
        w0, w1 = as_utc(a["window"]["start"]).replace(tzinfo=None), as_utc(a["window"]["end"]).replace(tzinfo=None)
        total = con.execute("SELECT count(*) FROM ev WHERE ts_utc_max >= ? AND ts_utc_min <= ?", [w0, w1]).fetchone()[0]
        cur = con.execute(
            "SELECT * FROM ev WHERE ts_utc_max >= ? AND ts_utc_min <= ? ORDER BY "
            "CASE WHEN list_contains(?, event_id) THEN 0 WHEN list_contains(?, event_id) THEN 1 ELSE 2 END, "
            "ts_utc NULLS LAST, source_id, ordinal LIMIT ?",
            [w0, w1, tier0, tier1, cap])
        names = [d[0] for d in cur.description]
        for r in cur.fetchall():
            rows.append(dict(zip(names, r, strict=True)))
        con.close()
    rows.sort(key=lambda r: (r["ts_utc"] is None, r["ts_utc"] or as_utc(a["window"]["start"]).replace(tzinfo=None),
                             r["source_id"], r["ordinal"]))
    out_rows = []
    for r in rows:
        out_rows.append({
            "event_id": r["event_id"], "source_id": r["source_id"], "family": r["source_family"],
            "record_locator": safe_text(r["record_locator"], 120), "ts_utc": iso(r["ts_utc"]),
            "ts_utc_earliest": iso(r["ts_utc_min"]), "ts_utc_latest": iso(r["ts_utc_max"]),
            "tz_original": r["tz_original"], "time_precision": r["time_precision"], "host": safe_text(r["host"], 80),
            "account_ref": disp.ref(r["account"]), "account_label": disp.label(r["account"]),
            "application": safe_text(r["application"], 80), "operation": r["operation"],
            "observation_type": r["observation_type"], "objects": ";".join(safe_text(o, 120) for o in (r["objects"] or [])),
            "rows": r["rows"], "bytes": r["bytes"], "outcome": r["outcome"], "mfa": r["mfa"], "remote_ip": r["remote_ip"],
            "dest_ip": r["dest_ip"], "url_path": safe_text(r["url_path"], 200), "http_status": r["http_status"],
            "consequence_class": r["consequence_class"], "path_ids": ";".join(sorted(path_by_event.get(r["event_id"], []))),
            "anomaly_ids": ";".join(sorted(anom_by_event.get(r["event_id"], []))),
            "indicator_match": r["event_id"] in ind_events, "raw_sha256": r["raw_sha256"],
        })
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=TIMELINE_COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in out_rows:
        w.writerow({k: ("" if v is None else v) for k, v in r.items()})
    jsonl = b"".join(canonical_bytes(r) + b"\n" for r in out_rows)
    csv_bytes = buf.getvalue().encode("utf-8")
    key = [r for r in out_rows if r["path_ids"] or r["anomaly_ids"] or r["indicator_match"]]
    key = [r for r in key if r["consequence_class"] != "not_applicable" or r["anomaly_ids"] or r["indicator_match"]][:300]
    meta = {"rows_in_window": int(total), "rows_exported": len(out_rows), "row_cap": cap,
            "truncated": int(total) > len(out_rows),
            "ordering": "kept first: evidence of anomalies, indicator matches, gaps and non-routine paths; then other "
                        "path events; then the rest chronologically. The attachment itself is sorted by UTC time "
                        "(unplaceable events last)",
            "attachments": {"timeline.csv": sha256_hex(csv_bytes), "timeline.jsonl": sha256_hex(jsonl)},
            "columns": TIMELINE_COLUMNS, "content_note": "no SQL text, query strings, command lines or message text",
            "key_events": [{k: r[k] for k in ("event_id", "ts_utc", "family", "host", "account_ref", "account_label",
                                              "operation", "observation_type", "objects", "consequence_class",
                                              "path_ids", "anomaly_ids")} for r in key]}
    return {"csv": csv_bytes, "jsonl": jsonl}, meta


# ---------------------------------------------------------------------------------------------- PDF
def _t(v) -> str:
    """Report time as 'YYYY-MM-DD HH:MM' (never digit runs joined by hyphens across fields)."""
    return v[:16].replace("T", " ") if v else "?"


def _acct(d) -> str:
    return f"{d['label']} [{d['account_ref']}]" if d else "-"


def render_pdf(body: dict) -> bytes:
    S = pdf.Section
    c = body["counts"]
    secs = [
        S("1. Classification of outcomes (evidence-of-access versus evidence-of-theft)",
          [f"{k}: {v}" for k, v in body["evidence_rule"].items()] +
          ["Outcomes are reported per sensitive table and per access path. A stronger class is never inferred from a "
           "weaker one: access is not export, export is not egress, and egress is not evidenced exfiltration."],
          table=[["Count", "Tables", "Records", "People"],
                 ["Observed access", str(c["observed_access"]["tables"]), c["observed_access"]["records"],
                  c["observed_access"]["people"]],
                 ["Possible exposure", str(c["possible_exposure"]["tables"]), c["possible_exposure"]["records"],
                  c["possible_exposure"]["people"]],
                 ["Confirmed exfiltration", str(c["confirmed_exfiltration"]["tables"]),
                  c["confirmed_exfiltration"]["records"], c["confirmed_exfiltration"]["people"]]]),
        S("2. Sensitive tables by outcome", [
            "Sensitive tables by class: " + ", ".join(f"{k}={v}" for k, v in
                                                       body["classification"]["sensitive_tables_by_class"].items()),
            c["confirmed_exfiltration"]["note"]],
          table=[["Table", "Outcome", "Window class", "Confirmed windows / gaps"]] + [
              [t["table"], t["consequence_class"] or "no access observed", t["window_class"],
               "; ".join(f"{w['window_class']} {_t(w.get('start'))} to {_t(w.get('end'))}" for w in t["windows"][:4])]
              for t in body["tables"]]),
        S("3. Ranked access paths", ["Stages: web/identity -> network -> host/application -> database -> data -> "
                                     "egress. 'direct' = exact shared identifier; 'correlated' = configured time-window "
                                     "inference; 'unresolved' = evidence stops."],
          table=[["#", "Outcome", "Account / client", "DB host", "Stages", "Egress"]] + [
              [str(p["rank"]), p["consequence_class"], f"{_acct(p['route']['account'])} {p['route']['client_ip'] or ''}",
               p["route"]["database_host"] or "-",
               ", ".join(f"{s['stage']}:{s['label']}" for s in p["stages"]),
               ", ".join(p["egress_destinations"]) or "-"] for p in body["paths"][:40]], page_break_before=True),
        S("4. Anomalies (leads, with assumptions and false-positive caveats in the JSON report)", [],
          table=[["Severity", "Detector", "Title", "Accounts", "First"]] + [
              [x["severity"], x["detector"], x["title"], ", ".join(_acct(a) for a in x["accounts"][:3]),
               x["first"] or "-"] for x in body["anomalies"][:60]]),
        S("5. Indicator matches (not attribution)", [f"{body['indicator_match_total']} match(es)."],
          table=[["Indicator", "Provenance", "Event", "Time"]] + [
              [m["indicator_value"], m["provenance"], m["event_id"], m["ts_utc"] or "-"]
              for m in body["indicator_matches"][:30]] if body["indicator_matches"] else None),
        S("6. Urgent containment recommendations (advisory)", [body["containment"]["notice"],
                                                                "Module A: " + body["containment"]["module_a"]["status"]],
          table=[["#", "Urgency", "Category", "Target", "Action"]] + [
              [str(r["rank"]), r["urgency"], r["category"],
               (r["target"].get("label") or r["target"].get("value") or r["target"].get("description") or "-"),
               r["action"]] for r in body["containment"]["recommendations"][:60]], page_break_before=True),
        S("7. Regulator-facing summary", [
            body["regulator"]["classification_statement"],
            "Observed access: " + (", ".join(f"{t['table']} ({t['consequence_class']})"
                                              for t in body["regulator"]["observed_access"]) or "none"),
            "Known actors (logged accounts, not proof of the person): " +
            (", ".join(_acct(k) for k in body["regulator"]["known_actors"]) or "none"),
            "Unknown actors: " + (str(len(body["regulator"]["unknown_actors"])) + " item(s)"),
            "Affected systems: " + (", ".join(f"{s['host']} ({s['asset_id'] or 'no asset id'})"
                                              for s in body["regulator"]["affected_systems"]) or "none"),
            "Measures taken: " + "; ".join(body["regulator"]["measures_taken"]),
            body["regulator"]["notification_note"]]),
        S("8. Missing evidence and gaps", [],
          table=[["Kind", "Scope", "Start", "End", "Description"]] + [
              [g["kind"], g.get("database") or g.get("host") or g.get("source_id") or g.get("scope") or "-",
               g.get("start") or "-", g.get("end") or "-", g.get("description") or "-"]
              for g in body["regulator"]["missing_evidence"]]),
        S("9. Sources, coverage and method", [
            f"Method {body['method_version']}; configuration sha256 {body['config_sha256']}; analysis sha256 "
            f"{body['analysis_sha256']}.",
            f"Window {body['window']['start']} to {body['window']['end']}; baseline {body['baseline']['start']} to "
            f"{body['baseline']['end']}.",
            f"Timeline attachment: {body['timeline']['rows_exported']} of {body['timeline']['rows_in_window']} events "
            f"(cap {body['timeline']['row_cap']}).", body["forensic_handoff"]["statement"]] + body["limitations"],
          table=[["Source", "Family", "Events", "Failures", "Time zone", "Completeness"]] + [
              [s["source_id"], s["family"], str(s["events"] if s["events"] is not None else s.get("indicators")),
               str(s["parse_failures"]), f"{(s['time_zone'] or {}).get('timezone', '-')} "
                                         f"({(s['time_zone'] or {}).get('basis', '-')})", s.get("completeness") or "-"]
              for s in body["inputs"]["sources"]], page_break_before=True),
    ]
    title = f"Tripline Scope - access-path analysis - case {body['case_id']} (v{body['version']}, {body['report_status']})"
    sub = [f"Window {body['window']['start']} to {body['window']['end']}",
           "Classification: " + ", ".join(f"{k}={v}" for k, v in body["classification"]["sensitive_tables_by_class"].items()),
           "Offline analysis of hospital-exported logs. Recommendations are advisory; nothing was executed."]
    data = pdf.render(title, sub, secs, footer=f"case {body['case_id']} - paths report v{body['version']} - "
                                               f"{body['report_status']}")
    kinds = find_identifier_like(pdf.pdf_text(data))
    if kinds:
        raise IntegrityError(f"refusing to render a PDF containing identifier-like values ({sorted(set(kinds))})")
    return data
