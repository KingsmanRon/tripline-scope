"""``tscope paths scope-candidates``: the machine-readable bridge to Module C (``tripline.scope-candidates/v1``).

Per sensitive table: ``window_class`` (``confirmed`` | ``possible`` | ``not_assessable``, or ``none_observed``
when the database was covered and no access was logged), the windows themselves, the consequence class,
basis, account/session provenance, evidence ids, confidence and limitations; the coverage gaps; and two
scenarios: ``lower`` (confirmed windows only) and ``upper`` (every sensitive table over the whole window,
including not-assessable and no-access-observed tables). Uncertain or absent logs never remove a table: Module C
may constrain matching to the lower scenario, the operator may widen it, and every scoping decision is logged
and signed by Module C. When no access-path logs were analysed the whole document is ``not_assessable``.
"""

from __future__ import annotations

from tripline_scope.core.canonical import canonical_bytes, sha256_hex

from .config import config_sha256, load_config
from .display import Display
from .schema import CANDIDATES_SCHEMA, METHOD_VERSION

EXCLUSION_POLICY = ("Uncertain or absent logs never exclude potentially exposed people: not_assessable and "
                    "none_observed tables stay in the upper scenario. Module C may limit matching to candidate "
                    "tables/windows only as an explicit, logged and signed scoping decision, and the operator may "
                    "always widen it.")


def build_candidates(case, store) -> dict:
    cfg = load_config(case)
    disp = Display(store, cfg["directory_domains"])
    if not store.exists("work/paths/analysis.json"):
        return _not_assessable(case, cfg)
    a = store.read_json("work/paths/analysis.json")
    analysis_sha = sha256_hex(canonical_bytes(a))
    W = a["window"]
    tables = []
    for t in a["tables"]:
        windows = []
        for w in t["windows"]:
            d = {"class": w["window_class"], "start": w["start"], "end": w["end"], "basis": w["basis"],
                 "consequence_class": w["consequence_class"]}
            if w["window_class"] != "not_assessable":
                d.update(accounts=disp.accounts(w.get("accounts")), sessions=w.get("sessions", [])[:20],
                         session_count=w.get("session_count", len(w.get("sessions", []))),
                         evidence_ids=w.get("evidence_ids", [])[:20], paths=w.get("paths", []),
                         rows_logged=w.get("rows_logged"), volume_unknown=bool(w.get("volume_unknown", True)),
                         time_uncertainty_s=w.get("time_uncertainty_s"))
            if w.get("reason"):
                d["reason"] = w["reason"]
            windows.append(d)
        claim = t["claim"]
        accts = sorted({x for w in t["windows"] for x in w.get("accounts", [])})
        tables.append({
            "table": t["table"], "database": t["database"], "sensitive": True, "declared": t["declared"],
            "window_class": t["window_class"], "window_classes": t["window_classes"], "status": t["status"],
            "consequence_class": t["consequence_class"], "basis": claim["basis"], "windows": windows,
            "accounts": disp.accounts(accts), "paths": t["paths"], "corroborations": t["corroborations"],
            "covering_sources": t["covering_sources"], "evidence_ids": claim["evidence_ids"][:30],
            "confidence": claim["confidence"], "confidence_reason": claim["confidence_reason"],
            "limitations": claim["limitations"],
        })
    lower = [{"table": t["table"], "windows": [{"start": w["start"], "end": w["end"]} for w in t["windows"]
                                              if w["class"] == "confirmed"]}
             for t in tables if any(w["class"] == "confirmed" for w in t["windows"])]
    upper = [{"table": t["table"], "windows": [{"start": W["start"], "end": W["end"]}], "window_class": t["window_class"]}
             for t in tables]
    counts = {k: sum(1 for t in tables if t["window_class"] == k)
              for k in ("confirmed", "possible", "not_assessable", "none_observed")}
    status = "assessed"
    if any(t["window_class"] == "not_assessable" or "not_assessable" in t["window_classes"] for t in tables) or \
            any(g["kind"] in ("no_source_family", "no_log_sources") for g in a["gaps"]):
        status = "partial"
    if not a["coverage"]:
        status = "not_assessable"
    return {
        "schema": CANDIDATES_SCHEMA, "case_id": case.case_id, "method_version": METHOD_VERSION,
        "generated_from": {"analysis_sha256": analysis_sha, "config_sha256": a["config_sha256"], "window": W,
                           "sources": sorted(a["inputs"])},
        "coverage_status": status,
        "coverage_statement": {"assessed": "Database audit coverage is complete as declared for the window.",
                               "partial": "Some tables or periods are not assessable (see coverage_gaps); they are "
                                          "kept in the upper scenario.",
                               "not_assessable": "No access-path logs were analysed."}[status],
        "exclusion_policy": EXCLUSION_POLICY, "operator_may_widen": True,
        "tables": tables,
        "coverage_gaps": [{k: g[k] for k in ("gap_id", "kind", "scope", "source_id", "host", "database", "start", "end",
                                             "basis", "description")} for g in a["gaps"]],
        "scenarios": {
            "lower": {"description": "Tables and windows with directly observed access only (confirmed). A lower "
                                     "bound for scoping, never a reason to exclude anyone.", "tables": lower},
            "upper": {"description": "Every sensitive table over the whole analysis window, including possible, "
                                     "not-assessable and no-access-observed tables (conservative).", "tables": upper},
        },
        "counts": {"tables_" + k: v for k, v in counts.items()},
        "statement": "Candidate source-and-time constraints for Module C. People counts come from tscope scope.",
    }


def _not_assessable(case, cfg) -> dict:
    iw = case.config.get("incident_window") or {}
    W = {"start": iw.get("start"), "end": iw.get("end")}
    declared = [t for t in cfg["sensitive_tables"] if not any(c in t for c in "*?[")]
    patterns = [t for t in cfg["sensitive_tables"] if any(c in t for c in "*?[")]
    tables = [{"table": t, "database": t.split(".")[0], "sensitive": True, "declared": True,
               "window_class": "not_assessable", "window_classes": ["not_assessable"], "status": "not_assessable",
               "consequence_class": "undetermined", "basis": "unknown",
               "windows": [{"class": "not_assessable", "start": W["start"], "end": W["end"], "basis": "unknown",
                            "consequence_class": "undetermined", "reason": "no access-path logs analysed"}],
               "accounts": [], "paths": [], "corroborations": [], "covering_sources": [], "evidence_ids": [],
               "confidence": 0.0, "confidence_reason": "no logs", "limitations": ["no access-path logs analysed"]}
              for t in declared]
    return {
        "schema": CANDIDATES_SCHEMA, "case_id": case.case_id, "method_version": METHOD_VERSION,
        "generated_from": {"analysis_sha256": None, "config_sha256": config_sha256(cfg), "window": W, "sources": []},
        "coverage_status": "not_assessable",
        "coverage_statement": "No access-path logs were analysed: Module B cannot constrain scope. Module C must use "
                              "every source in scope (the upper scenario is everything).",
        "exclusion_policy": EXCLUSION_POLICY, "operator_may_widen": True, "tables": tables,
        "sensitive_table_patterns": patterns,
        "coverage_gaps": [{"gap_id": "GAP-NO-LOGS", "kind": "no_log_sources", "scope": "case", "source_id": None,
                           "host": None, "database": None, "start": W["start"], "end": W["end"], "basis": "observation",
                           "description": "No access-path logs were ingested and analysed."}],
        "scenarios": {"lower": {"description": "No confirmed windows.", "tables": []},
                      "upper": {"description": "All sources and tables in scope (nothing can be excluded).",
                                "tables": [{"table": t["table"], "windows": [W], "window_class": "not_assessable"}
                                           for t in tables], "all_tables": True}},
        "counts": {"tables_confirmed": 0, "tables_possible": 0, "tables_not_assessable": len(tables),
                   "tables_none_observed": 0},
        "statement": "not_assessable: Module B inputs are absent.",
    }
