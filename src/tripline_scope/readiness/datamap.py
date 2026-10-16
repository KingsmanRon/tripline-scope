"""Readiness data map: where ID numbers, contact details, medical-aid, payment and clinical columns live.

Built only from discovery output (names, categories, rates and row counts); it never contains values. The
draft ``datamap`` report (JSON + PDF + ``datamap.csv``) is released by an approver with ``tscope release
--kind datamap``; the hospital keeps it, and it doubles as an exposure map.
"""

from __future__ import annotations

import csv
import io

from tripline_scope import METHOD_VERSION
from tripline_scope.core import pdf
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.discovery.categories import DISCOVERY_METHOD, SPECS
from tripline_scope.ingest.files import safe_name

DATAMAP_METHOD = "datamap/0.1.0"
GROUPS = (
    ("identity_numbers", "ID and passport numbers"),
    ("names", "Names"),
    ("date_of_birth", "Dates of birth"),
    ("contact", "Contact details and addresses"),
    ("medical_aid", "Medical aid"),
    ("payment", "Payment card and bank details"),
    ("clinical", "Clinical (diagnoses, tests, results, notes)"),
)
_GROUP_LABEL = dict(GROUPS)
MIN_CONFIDENCE = 0.5


def _r(x):
    return None if x is None else round(float(x), 4)


def _source_entry(source: dict, disc: dict) -> dict:
    tables = []
    for t in disc["tables"]:
        cols = []
        groups: dict[str, list[str]] = {}
        for c in t["columns"]:
            name = safe_name(c["name"], c["position"])
            group = SPECS[c["category"]].map_group if c["category"] in SPECS else "other"
            if t["scanned"] and c["confidence"] >= MIN_CONFIDENCE and group in _GROUP_LABEL \
                    and (c["null_rate"] is None or c["null_rate"] < 1.0):
                groups.setdefault(group, []).append(name)
            cols.append({
                "name": name,
                "category": c["category"],
                "group": group,
                "exposure_category": c["exposure_category"],
                "confidence": _r(c["confidence"]),
                "match_rate": _r(c["match_rate"]),
                "null_rate": _r(c["null_rate"]),
                "extracted": bool(c["extracted"]),
            })
        tables.append({
            "database": t["database"],
            "table": t["table"],
            "row_count": t["row_count"],
            "assessed": bool(t["scanned"]),
            "role": t["role"],
            "groups": {g: sorted(v) for g, v in sorted(groups.items())},
            "columns": cols,
        })
    tables.sort(key=lambda x: (x["database"] or "", x["table"]))
    return {
        "source_id": source["source_id"],
        "kind": source["kind"],
        "label": source.get("label"),
        "evidence_role": source.get("evidence_role"),
        "custody_sha256": sorted(f.get("sha256") or f.get("tree_sha256") or "" for f in source.get("files", [])),
        "discovery_sha256": sha256_hex(canonical_bytes(disc)),
        "tables": tables,
    }


def build_body(rs, case, sources: list[tuple[dict, dict]]) -> dict:
    entries = [_source_entry(s, d) for s, d in sorted(sources, key=lambda x: x[0]["source_id"])]
    summary = {}
    for g, label in GROUPS:
        tabs = [(e["source_id"], t) for e in entries for t in e["tables"] if g in t["groups"]]
        summary[g] = {
            "label": label,
            "sources": len({sid for sid, _ in tabs}),
            "tables": len(tabs),
            "columns": sum(len(t["groups"][g]) for _, t in tabs),
            "rows_in_tables": sum(t["row_count"] or 0 for _, t in tabs),
        }
    not_assessed = sum(1 for e in entries for t in e["tables"] if not t["assessed"])
    return rs.new_body(
        "datamap",
        report_status="draft for approver release",
        method_version=f"{METHOD_VERSION}; {DISCOVERY_METHOD}; {DATAMAP_METHOD}",
        config_sha256=case.config_sha256(),
        mode=case.mode,
        inputs={e["source_id"]: {"custody_sha256": e["custody_sha256"], "discovery_sha256": e["discovery_sha256"]}
                for e in entries},
        totals={
            "sources": len(entries),
            "tables": sum(len(e["tables"]) for e in entries),
            "tables_not_assessed": not_assessed,
            "rows": sum(t["row_count"] or 0 for e in entries for t in e["tables"]),
        },
        summary=summary,
        sources=entries,
        limitations=[
            "Columns are classified by name hints and value checks on a sample, then confirmed on every row; "
            "confidence below 0.5 is listed but not counted in the summary.",
            "Values are never shown: only table and column names, categories, match and null rates and row counts.",
            "Free-text columns are reported as possibly clinical; their content is not inspected beyond format checks.",
            "Card and bank columns are detected and flagged; their values are never copied anywhere.",
            "Tables marked not assessed were outside the selected scope; only their row counts are listed.",
        ],
    )


def render_csv(body: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source_id", "database", "table", "table_rows", "assessed", "role", "column", "category", "group",
                "exposure_category", "confidence", "match_rate", "null_rate", "extracted"])
    for e in body["sources"]:
        for t in e["tables"]:
            for c in t["columns"]:
                w.writerow([e["source_id"], t["database"] or "", t["table"], t["row_count"], t["assessed"], t["role"],
                            c["name"], c["category"], c["group"], c["exposure_category"] or "", c["confidence"],
                            "" if c["match_rate"] is None else c["match_rate"],
                            "" if c["null_rate"] is None else c["null_rate"], c["extracted"]])
    return buf.getvalue().encode("utf-8")


def render_pdf(body: dict, hospital: str) -> bytes:
    t = body["totals"]
    sections = [pdf.Section("Summary", [
        f"{t['sources']} source(s), {t['tables']} table(s), {t['rows']} row(s) in total; "
        f"{t['tables_not_assessed']} table(s) not assessed.",
        "This map shows where sensitive categories of personal information are stored. It contains no values.",
    ], table=[["Category", "Sources", "Tables", "Columns", "Rows in those tables"]] + [
        [s["label"], str(s["sources"]), str(s["tables"]), str(s["columns"]), str(s["rows_in_tables"])]
        for s in body["summary"].values()])]
    rows = [["Category", "Source", "Table", "Rows", "Columns"]]
    for g, label in GROUPS:
        for e in body["sources"]:
            for tb in e["tables"]:
                if g in tb["groups"]:
                    where = ".".join(x for x in (tb["database"], tb["table"]) if x)
                    rows.append([label, e["source_id"], where, str(tb["row_count"]), ", ".join(tb["groups"][g])])
    sections.append(pdf.Section("Where sensitive data lives", table=rows if len(rows) > 1 else None,
                                paragraphs=[] if len(rows) > 1 else ["No sensitive categories were found."]))
    inv = [["Source", "Table", "Rows", "Role", "Assessed"]]
    for e in body["sources"]:
        for tb in e["tables"]:
            inv.append([e["source_id"], ".".join(x for x in (tb["database"], tb["table"]) if x),
                        str(tb["row_count"]), tb["role"], "yes" if tb["assessed"] else "no"])
    sections.append(pdf.Section("Table inventory", table=inv, page_break_before=True))
    sections.append(pdf.Section("Method and limitations", list(body["limitations"]) + [
        f"Method: {body['method_version']}. Configuration hash: {body['config_sha256'][:16]}."]))
    sub = [f"{hospital} - case {body['case_id']} ({body['mode']} mode)", f"Data map version {body['version']}"]
    return pdf.render("Readiness data map", sub, sections,
                      footer=f"Tripline Scope data map - case {body['case_id']} - no patient values")
