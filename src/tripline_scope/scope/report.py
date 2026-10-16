"""Scope report: deterministic JSON body (RFC 8785 via the core report store), PDF and ``diff.json``.

The body carries counts, hashes and case facts only — never identifiers, never wall-clock times — so identical
inputs give a byte-identical ``report.json``. Every number is traceable: source custody hashes, extract manifest
hashes, the configuration hash, the review-decision hash, the model parameters, the scoping decisions and the
previous version's hash.
"""

from __future__ import annotations

import json
import re
from importlib import resources

import pyarrow as pa

from tripline_scope import METHOD_VERSION
from tripline_scope.core import duck
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.evidence import EXFILTRATION_EVIDENCE_KINDS, NOT_DETERMINABLE
from tripline_scope.core.pdf import Section, render
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.reports import ReportStore

from . import constrain as K
from . import decisions as DEC
from . import run as R
from .config import EXPOSURE_CATEGORIES
from .data import CAT_BIT
from .people import CONFIDENCE, SEGMENTS

SNAPSHOTS = "work/scope/snapshots"
VERSIONS = "work/scope/versions"
CATEGORY_LABELS = {
    "identity_number": "ID or passport number", "name": "Name", "date_of_birth": "Date of birth",
    "contact_details": "Phone number or e-mail", "address": "Postal or street address", "medical_aid": "Medical aid number",
    "clinical_diagnosis": "Diagnosis codes", "clinical_tests": "Laboratory tests ordered", "clinical_results": "Test results",
    "clinical_notes": "Clinical notes", "payment_card": "Payment card number", "bank_account": "Bank account number",
}
_HEX = re.compile(r"^[0-9a-f]{16,128}$")


# ---------------------------------------------------------------------------------------------------- helpers
def error_rates() -> dict:
    try:
        text = resources.files("tripline_scope").joinpath("templates/measured/error_rates.json").read_text()
        return json.loads(text)
    except (FileNotFoundError, OSError, ValueError):
        return {"status": "not yet measured on this build"}


def source_hashes(case) -> list[dict]:
    out = []
    for s in case.sources():
        files = [{"sha256": f.get("sha256") or f.get("tree_sha256"), "size": f.get("size"),
                  "kind": f.get("kind", "file")} for f in s.get("files", [])]
        out.append({"source_id": s["source_id"], "kind": s["kind"], "evidence_role": s["evidence_role"],
                    "label": s.get("label"), "manifest_sha256": s.get("manifest_sha256"), "files": files})
    return out


def check_body(body: dict) -> bool:
    """True when the body is clean apart from hexadecimal hashes (which can contain digit runs that look like
    numbers); raises if anything else looks like an identifier."""
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items()}
        if isinstance(o, list):
            return [strip(v) for v in o]
        if isinstance(o, str) and _HEX.match(o):
            return "#"
        return o

    from tripline_scope.core.errors import IntegrityError

    if find_identifier_like(canonical_bytes(strip(body)).decode("utf-8")):
        raise IntegrityError("refusing to build a scope report containing identifier-like values")
    return bool(find_identifier_like(canonical_bytes(body).decode("utf-8")))


def fmt_hash(h: str | None) -> str:
    if not h:
        return "-"
    return "·".join(h[i:i + 8] for i in range(0, len(h), 8))


def _con_with(tables: dict[str, pa.Table]):
    con = duck.connect(lock=False)
    for name, t in tables.items():
        con.register(f"_{name}", t)
        con.execute(f"CREATE TABLE {name} AS SELECT * FROM _{name}")
        con.unregister(f"_{name}")
    return con


# ---------------------------------------------------------------------------------------------------- counts
def compute_counts(store, case) -> dict:
    people = store.read_table(R.PEOPLE)
    ptab = store.read_table(R.PERSON_TABLES)
    tables = store.read_json(R.TABLES)["tables"]
    con = _con_with({"people": people, "ptab": ptab})
    try:
        cands = K.load_candidates(store)
        sdecs = K.load_decisions(store)
        rules = K.table_rules(cands, tables, sdecs)
        n = con.execute("SELECT count(*) FROM people").fetchone()[0]

        def by_cat(where="TRUE", mask="cat_mask"):
            out = {}
            for c in EXPOSURE_CATEGORIES:
                out[c] = int(con.execute(f"SELECT count(*) FROM people WHERE ({where}) AND {mask} & {CAT_BIT[c]} <> 0").fetchone()[0])
            return out

        conf = {c: 0 for c in CONFIDENCE}
        conf.update({k: int(v) for k, v in con.execute("SELECT confidence, count(*) FROM people GROUP BY 1").fetchall()})
        seg = {s: 0 for s in SEGMENTS}
        seg.update({k: int(v) for k, v in con.execute("SELECT segment, count(*) FROM people GROUP BY 1").fetchall()})
        flagged_no_contact = int(con.execute("SELECT count(*) FROM people WHERE segment = 'minor_flagged_no_guardian' "
                                             "AND NOT own_contact").fetchone()[0])
        per_source = []
        for sid, n_p in con.execute("SELECT source_id, count(DISTINCT person_key) FROM ptab GROUP BY 1 ORDER BY 1").fetchall():
            cats = {}
            for c in EXPOSURE_CATEGORIES:
                cats[c] = int(con.execute(f"SELECT count(DISTINCT person_key) FROM ptab WHERE source_id = ? "
                                          f"AND cat_mask & {CAT_BIT[c]} <> 0", [sid]).fetchone()[0])
            per_source.append({"source_id": sid, "people": int(n_p), "people_per_category": cats})
        scen = {}
        for name in ("lower", "candidate", "upper"):
            pred = K.scenario_sql(rules["rules"], name)
            scen[name] = int(con.execute(f"SELECT count(DISTINCT person_key) FROM ptab WHERE {pred}").fetchone()[0])
        upper_keys = [r[0] for r in con.execute(
            f"SELECT DISTINCT person_key FROM ptab WHERE {K.scenario_sql(rules['rules'], 'upper')} ORDER BY 1").fetchall()]
        from .notify import people_set_digest

        notification_digest = people_set_digest(upper_keys)
        leak = int(con.execute("SELECT count(*) FROM people WHERE in_leak").fetchone()[0])
        leak_cats = by_cat("in_leak", "leak_mask")
        rows_per_source: dict[str, dict] = {}
        unres = {"identity_rows_without_identifiers": 0, "dependent_rows_unlinked": 0}
        for t in tables:
            rs = rows_per_source.setdefault(t["source_id"], {"rows": 0, "tables": []})
            rs["rows"] += int(t["rows"])
            rs["tables"].append({"database": t["database"], "table": t["table"], "role": t["role"], "rows": int(t["rows"]),
                                 "unresolvable_identity_rows": int(t["identity_rows_without_identifiers"]),
                                 "unresolvable_dependent_rows": int(t["dependent_rows_unlinked"])})
            unres["identity_rows_without_identifiers"] += int(t["identity_rows_without_identifiers"])
            unres["dependent_rows_unlinked"] += int(t["dependent_rows_unlinked"])
        unres["total"] = unres["identity_rows_without_identifiers"] + unres["dependent_rows_unlinked"]
        return {
            "unique_people": int(n),
            "people_per_category": by_cat(),
            "people_per_confidence": conf,
            "people_per_category_per_source": per_source,
            "segments": seg,
            "minors": {"total": seg["minor_guardian_routed"] + seg["minor_flagged_no_guardian"],
                       "routed_to_guardian": seg["minor_guardian_routed"],
                       "flagged_no_guardian_contact": seg["minor_flagged_no_guardian"]},
            "without_contact_details": {
                "adults_public_notice_route": seg["no_usable_contact"],
                "minors_without_guardian_or_own_contact": flagged_no_contact,
                "total": seg["no_usable_contact"] + flagged_no_contact},
            "age_unknown": int(con.execute("SELECT count(*) FROM people WHERE NOT age_known").fetchone()[0]),
            "rows_per_source": rows_per_source,
            "unresolvable_rows": unres,
            "scenarios": scen,
            "leak": {"people": leak, "people_per_category": leak_cats},
            "rules": rules,
            "notification_people_set_sha256": notification_digest,
            "candidates": cands,
            "scoping_decisions": sdecs,
        }
    finally:
        con.close()


def _tiers(c: dict, case) -> tuple[dict, dict | None]:
    cands = c["candidates"]
    has_leak = any(s.get("evidence_role") == "leak_sample" for s in case.sources())
    if cands:
        observed = {"count": c["scenarios"]["lower"], "basis": "observation",
                    "explanation": "People with records in tables where Module B confirmed access (or the operator widened "
                                   "scope), created no later than the end of a confirmed access window."}
        degraded = None
    else:
        observed = {"count": NOT_DETERMINABLE, "basis": "unknown",
                    "explanation": "No access-path analysis (Module B) has been supplied, so observed access cannot be "
                                   "determined from logs."}
        degraded = {"degraded_confidence": True,
                    "statement": "No scope candidates from access-path analysis are available. The whole of every "
                                 "extracted source is treated as possibly exposed; uncertainty is broadened, never "
                                 "narrowed. Observed access is not determinable."}
    if has_leak:
        exfil = {"count": c["leak"]["people"], "basis": "observation",
                 "exfiltration_evidence_kind": "independently_confirmed_external_copy",
                 "people_per_category": c["leak"]["people_per_category"],
                 "explanation": "People whose records match a leak sample received from outside the hospital; counted "
                                "only for the categories present in that sample."}
        assert exfil["exfiltration_evidence_kind"] in EXFILTRATION_EVIDENCE_KINDS
    else:
        exfil = {"count": NOT_DETERMINABLE, "basis": "unknown",
                 "explanation": "No independently verifiable evidence of exfiltration (such as a leak sample) has been "
                                "registered. Exfiltration is neither confirmed nor excluded; mere database access is not "
                                "treated as proof that data was taken."}
    tiers = {
        "observed_access": observed,
        "possible_exposure": {"count": c["scenarios"]["upper"], "basis": "inference",
                              "explanation": "Everyone with a record in any extracted source that may have been exposed. "
                                             "Absent or uncertain logs never reduce this number."},
        "confirmed_exfiltration": exfil,
        "notification_scope": {"proposed_count": c["scenarios"]["upper"], "basis": "proposal",
                               "decided_by": None, "people_set_sha256": c["notification_people_set_sha256"],
                               "explanation": "Proposal only: the possible-exposure upper bound. The Information Officer "
                                              "decides the legal notification scope with counsel; releasing this report "
                                              "records that decision. The software does not make legal determinations."},
    }
    return tiers, degraded


def _diff(store, current_people: pa.Table, current_rows: pa.Table, prev_version: int | None) -> dict:
    if prev_version is None:
        return {"available": False, "reason": "first version"}
    base = f"{VERSIONS}/v{prev_version:04d}"
    if not store.exists(f"{base}/people.parquet"):
        return {"available": False, "reason": "the previous version was a preliminary estimate (no person-level result)"}
    con = _con_with({"cp": current_people.select(["person_key", "cat_mask"]), "cr": current_rows,
                     "pp": store.read_table(f"{base}/people.parquet", columns=["person_key", "cat_mask"]),
                     "pr": store.read_table(f"{base}/person_rows.parquet")})
    try:
        con.execute("CREATE TABLE link AS SELECT DISTINCT c.person_key AS cur, p.person_key AS prev "
                    "FROM cr c JOIN pr p USING (row_key)")
        con.execute("CREATE TABLE cur_prev AS SELECT l.cur, bit_or(pp.cat_mask) AS m FROM link l "
                    "JOIN pp ON pp.person_key = l.prev GROUP BY l.cur")
        con.execute("CREATE TABLE prev_cur AS SELECT l.prev, bit_or(cp.cat_mask) AS m FROM link l "
                    "JOIN cp ON cp.person_key = l.cur GROUP BY l.prev")
        added = con.execute("SELECT count(*) FROM cp WHERE person_key NOT IN (SELECT cur FROM link)").fetchone()[0]
        removed = con.execute("SELECT count(*) FROM pp WHERE person_key NOT IN (SELECT prev FROM link)").fetchone()[0]
        per = {}
        for c in EXPOSURE_CATEGORIES:
            b = CAT_BIT[c]
            a = con.execute(f"SELECT count(*) FROM cp LEFT JOIN cur_prev x ON x.cur = cp.person_key "
                            f"WHERE cp.cat_mask & {b} <> 0 AND coalesce(x.m, 0) & {b} = 0").fetchone()[0]
            r = con.execute(f"SELECT count(*) FROM pp LEFT JOIN prev_cur x ON x.prev = pp.person_key "
                            f"WHERE pp.cat_mask & {b} <> 0 AND coalesce(x.m, 0) & {b} = 0").fetchone()[0]
            per[c] = {"added": int(a), "removed": int(r)}
        return {"available": True, "from_version": prev_version,
                "people": {"previous": int(con.execute("SELECT count(*) FROM pp").fetchone()[0]),
                           "current": int(con.execute("SELECT count(*) FROM cp").fetchone()[0]),
                           "added": int(added), "removed": int(removed)},
                "per_category": per,
                "method": "people are matched across versions by shared record keys; a person whose records were not "
                          "in any person of the other version is added or removed"}
    finally:
        con.close()


# ---------------------------------------------------------------------------------------------------- bodies
def build_match_report(case, store, *, home=None) -> tuple[dict, bytes, dict[str, bytes]]:
    rs = ReportStore(case)
    m = store.read_json(R.MATCH)
    c = compute_counts(store, case)
    tiers, degraded = _tiers(c, case)
    est = store.read_json(R.ESTIMATE) if store.exists(R.ESTIMATE) else None
    version, prev_sha = rs.next_chain("scope")
    people = store.read_table(R.PEOPLE)
    rows = store.read_table(R.PERSON_ROWS)
    diff = _diff(store, people, rows, version - 1 if version > 1 else None)
    decs = m["review_decisions"]
    rules = {f"{sid}/{slug}": {"class": r["class"], "widened": r["widened"],
                               "cutoff": r["cutoff"].isoformat() if r["cutoff"] else None,
                               "consequence_class": r["consequence_class"]}
             for (sid, slug), r in sorted(c["rules"]["rules"].items())}
    body = rs.new_body(
        "scope",
        report_status="refined",
        method_version=METHOD_VERSION,
        incident_window=case.config.get("incident_window"),
        reference_date_for_age=m["reference_date"],
        source_hashes=source_hashes(case),
        extract_manifests_sha256=m["extract_manifests_sha256"],
        config_sha256=m["config_sha256"],
        review_decisions_sha256=m["review_decisions_sha256"],
        review_decisions=decs,
        review_decisions_simulated=bool(decs.get("any_simulated")),
        rows_per_source=c["rows_per_source"],
        counts={
            "unique_people": c["unique_people"],
            "bounds": {"lower": m["people_lower_bound"], "upper": c["unique_people"],
                       "explanation": "Upper: pending review pairs kept apart and over-merged clusters split (the count "
                                      "reported). Lower: every pending review pair accepted as the same person."},
            "people_per_category": c["people_per_category"],
            "people_per_confidence": c["people_per_confidence"],
            "people_per_category_per_source": c["people_per_category_per_source"],
            "unresolvable_rows": c["unresolvable_rows"],
            "minors": c["minors"],
            "without_contact_details": c["without_contact_details"],
            "notification_routes": c["segments"],
            "age_unknown": c["age_unknown"],
        },
        scope_tiers=tiers,
        scenarios={"lower": c["scenarios"]["lower"] if c["candidates"] else NOT_DETERMINABLE,
                   "candidate": c["scenarios"]["candidate"] if c["candidates"] else NOT_DETERMINABLE,
                   "upper": c["scenarios"]["upper"], "full_scope": c["unique_people"],
                   "table_rules": rules if c["candidates"] else {},
                   "unmatched_candidate_tables": c["rules"]["unmatched"] if c["candidates"] else [],
                   "coverage_gaps": (c["candidates"] or {}).get("coverage_gaps", [])},
        degraded_evidence=degraded,
        scoping_decisions=[{k: v for k, v in d.items()} for d in c["scoping_decisions"]],
        declared_gaps=[{"gap_id": g.get("gap_id"), "description": g.get("description"), "affects": g.get("affects")}
                       for g in case.config.get("declared_gaps") or []],
        matching={"statistics": m["stats"], "review_queue": m["review_queue"], "model": m["model"],
                  "bands": m["config"]["bands"], "blocking_rules": m["config"]["blocking"]["rules"],
                  "max_block_size": m["config"]["blocking"]["max_block_size"], "guards": m["config"]["guards"],
                  "over_merge_guard": m["config"]["over_merge"]},
        preliminary_estimate=({"point": est["estimate"]["point"], "lower": est["estimate"]["lower"],
                               "upper": est["estimate"]["upper"]} if est else None),
        measured_error_rates=error_rates(),
        diff_from_previous=diff,
        limitations=LIMITATIONS + ([SIMULATED_NOTE] if decs.get("any_simulated") else []),
    )
    pdf = render_pdf(case, body)
    attachments = {"diff.json": canonical_bytes(diff)}
    return body, pdf, attachments


def build_estimate_report(case, store) -> tuple[dict, bytes, dict[str, bytes]]:
    rs = ReportStore(case)
    e = store.read_json(R.ESTIMATE)
    est = e["estimate"]
    rows_per_source: dict[str, dict] = {}
    for t in e["tables"]:
        r = rows_per_source.setdefault(t["source_id"], {"rows": 0, "tables": []})
        r["rows"] += int(t["rows"])
        r["tables"].append({"database": t["database"], "table": t["table"], "role": t["role"], "rows": int(t["rows"])})
    has_leak = any(s.get("evidence_role") == "leak_sample" for s in case.sources())
    body = rs.new_body(
        "scope",
        report_status="preliminary",
        method_version=METHOD_VERSION,
        incident_window=case.config.get("incident_window"),
        reference_date_for_age=e["reference_date"],
        source_hashes=source_hashes(case),
        extract_manifests_sha256=e["extract_manifests_sha256"],
        config_sha256=e["config_sha256"],
        review_decisions_sha256=DEC.digest({}),
        rows_per_source=rows_per_source,
        counts={"unique_people": {"point": est["point"], "lower": est["lower"], "upper": est["upper"]},
                "people_with_valid_sa_id": est["people_with_valid_sa_id"],
                "people_per_category": est["per_category"],
                "unresolvable_rows": e["unresolvable"] | {"total": sum(e["unresolvable"].values())}},
        uncertainty={"statement": "Preliminary estimate from exact ID matching and distinct counts of phonetic name and "
                                  "date-of-birth keys. It will be replaced by a refined, person-level count. The lower and "
                                  "upper values bound how far the method can be off in either direction.",
                     "method": est["method"]},
        scope_tiers={
            "observed_access": {"count": NOT_DETERMINABLE, "basis": "unknown",
                                "explanation": "Not assessed in the preliminary estimate."},
            "possible_exposure": {"count": est["point"], "lower": est["lower"], "upper": est["upper"],
                                  "basis": "inference", "explanation": "Everyone with a record in an extracted source."},
            "confirmed_exfiltration": {"count": NOT_DETERMINABLE, "basis": "unknown",
                                       "explanation": "Determined in the refined report" +
                                                      (" (a leak sample is registered)." if has_leak else ".")},
            "notification_scope": {"proposed_count": est["upper"], "basis": "proposal", "decided_by": None,
                                   "explanation": "Proposal only (the upper bound); the Information Officer decides."},
        },
        declared_gaps=[{"gap_id": g.get("gap_id"), "description": g.get("description"), "affects": g.get("affects")}
                       for g in case.config.get("declared_gaps") or []],
        measured_error_rates=error_rates(),
        limitations=LIMITATIONS,
    )
    pdf = render_pdf(case, body)
    return body, pdf, {"diff.json": canonical_bytes({"available": False, "reason": "preliminary estimate"})}


LIMITATIONS = [
    "Counts are of people found in the extracted sources; records outside them are not counted.",
    "Rows without enough identifiers are counted separately and are never assigned to people.",
    "Matching error rates are measured on synthetic data shaped like hospital data; real data may differ.",
    "Mere access to a database is not treated as proof that data was copied.",
]
SIMULATED_NOTE = ("Reviewer decisions in this version were simulated from synthetic ground truth for a drill or "
                  "demonstration; they are not decisions by a person.")


# ---------------------------------------------------------------------------------------------------- PDF
def _num(v) -> str:
    if isinstance(v, int):
        return f"{v:,}".replace(",", " ")
    return str(v)


def render_pdf(case, body: dict) -> bytes:
    prelim = body["report_status"] == "preliminary"
    c = body["counts"]
    win = body.get("incident_window") or {}
    tiers = body["scope_tiers"]
    if prelim:
        u = c["unique_people"]
        people_line = (f"Our first estimate is that records of about {_num(u['point'])} people were held in the affected "
                       f"systems (between {_num(u['lower'])} and {_num(u['upper'])}).")
    else:
        b = c["bounds"]
        people_line = (f"We found records of {_num(c['unique_people'])} distinct people in the affected systems "
                       f"(at least {_num(b['lower'])} if every uncertain match is confirmed).")
    summary = [
        f"This is version {body['version']} of the breach scope report for case {body['case_id']}"
        f" ({'a preliminary estimate' if prelim else 'a refined, person-level count'}).",
        f"Incident window under investigation: {win.get('start') or 'unknown'} to {win.get('end') or 'unknown'}.",
        people_line,
        "Four measures are kept separate: observed access (logs show the data was accessed), possible exposure (the data "
        "could have been accessed), confirmed exfiltration (independent evidence that a copy left the hospital) and the "
        "notification scope, which the Information Officer decides with counsel. The software proposes and explains; it "
        "does not make legal determinations.",
    ]
    if not prelim:
        mn, wc = c["minors"], c["without_contact_details"]
        summary.append(f"{_num(mn['total'])} of the people are children under 18; notices for {_num(mn['routed_to_guardian'])} "
                       f"can go to a parent or guardian recorded in the source, {_num(mn['flagged_no_guardian_contact'])} "
                       "are flagged because no guardian contact is held.")
        summary.append(f"{_num(wc['total'])} people have no usable contact details and are counted for the public-notice "
                       "route that section 22(4) allows (website or news media).")
        if body.get("review_decisions_simulated"):
            summary.append(SIMULATED_NOTE)
        if body.get("degraded_evidence"):
            summary.append(body["degraded_evidence"]["statement"])
    er = body.get("measured_error_rates") or {}
    if er.get("dataset_rows"):
        summary.append(f"On a synthetic benchmark of {_num(er['dataset_rows'])} rows the method's automatic links were "
                       f"{er.get('auto_link_precision_pct')}% correct and the people count was within "
                       f"{er.get('person_count_error_pct')}% of the truth.")
    tier_rows = [["Measure", "People", "Basis"]]
    for k, label in (("observed_access", "Observed access"), ("possible_exposure", "Possible exposure"),
                     ("confirmed_exfiltration", "Confirmed exfiltration"), ("notification_scope", "Notification scope (proposed)")):
        t = tiers[k]
        tier_rows.append([label, _num(t.get("count", t.get("proposed_count"))), t["basis"]])
    cat_rows = [["Category", "People"]]
    for cat, n in c["people_per_category"].items():
        val = n["point"] if isinstance(n, dict) else n
        cat_rows.append([CATEGORY_LABELS.get(cat, cat), _num(val)])
    sections = [Section("Summary for the board and the Information Regulator", summary),
                Section("Scope measures", [t["explanation"] for t in tiers.values()], table=tier_rows),
                Section("People per category of information", [], table=cat_rows)]
    if not prelim:
        conf_rows = [["Confidence", "People"]] + [[k, _num(v)] for k, v in c["people_per_confidence"].items()]
        sections.append(Section("How each person was identified", [
            "deterministic: joined only by a valid SA ID with a consistent date of birth (or a single record); "
            "auto-linked: joined by a high-scoring probabilistic match; reviewed: a reviewer decided; "
            "probabilistic-unreviewed: an uncertain match awaits review and the person is counted conservatively."],
            table=conf_rows))
        route_rows = [["Notification route", "People"],
                      ["Adults with contact details", _num(c["notification_routes"]["adult_with_contact"])],
                      ["Children: via parent or guardian", _num(c["minors"]["routed_to_guardian"])],
                      ["Children: flagged, no guardian contact", _num(c["minors"]["flagged_no_guardian_contact"])],
                      ["No usable contact details (public notice)", _num(c["without_contact_details"]["total"])]]
        sections.append(Section("Notification routes", [], table=route_rows))
    src_rows = [["Source", "Rows", "Unresolvable"]]
    for sid, r in sorted(body["rows_per_source"].items()):
        unres = sum(t.get("unresolvable_identity_rows", 0) + t.get("unresolvable_dependent_rows", 0) for t in r["tables"])
        src_rows.append([sid, _num(r["rows"]), _num(unres) if not prelim else "-"])
    unr = c["unresolvable_rows"]
    sections.append(Section("Rows per source", [f"Rows that cannot be tied to a person are counted separately and never "
                                                f"forced into people: {_num(unr['total'])} in total."], table=src_rows))
    gaps = body.get("declared_gaps") or []
    sections.append(Section("Declared evidence gaps and scoping decisions",
                            [f"{g['gap_id']}: {g['description']}" for g in gaps] or ["No gaps declared."]
                            + [f"{d['decision_id']} ({d['kind']}): {d['reason']}" for d in body.get("scoping_decisions") or []]))
    # technical appendix
    tech = [f"Method version: {body['method_version']}",
            f"Configuration hash: {fmt_hash(body['config_sha256'])}",
            f"Review-decision hash: {fmt_hash(body['review_decisions_sha256'])}",
            f"Previous report hash: {fmt_hash(body.get('previous_report_sha256'))}"]
    if not prelim:
        mt = body["matching"]
        tech.append("Bands on match probability: auto-link at or above "
                    f"{mt['bands']['auto_link']}, review from {mt['bands']['review']}, non-link below.")
        tech.append("Blocking rules: " + ", ".join(mt["blocking_rules"]) + f" (blocks larger than {mt['max_block_size']} "
                    "records on phone or e-mail are not used).")
        tech.append("Guards: " + ", ".join(f"{k} → {v}" for k, v in mt["guards"].items()))
        tech.append("Statistics: " + ", ".join(f"{k} {v}" for k, v in mt["statistics"].items()))
    model_rows = None
    if not prelim and body["matching"].get("model"):
        model_rows = [["Comparison", "Level", "m", "u", "Weight"]]
        for comp in body["matching"]["model"]["comparisons"]:
            for lv in comp["levels"]:
                if lv.get("null_level"):
                    continue
                model_rows.append([comp["comparison"], lv["label"][:60], str(lv["m"]), str(lv["u"]),
                                   str(lv["match_weight"])])
    sections.append(Section("Technical appendix", tech, table=model_rows, page_break_before=True))
    hash_rows = [["Source", "Role", "Manifest hash"]] + [[s["source_id"], s["evidence_role"], fmt_hash(s["manifest_sha256"])]
                                                        for s in body["source_hashes"]]
    sections.append(Section("Source custody hashes", ["Hashes identify the exact evidence used; contents are never "
                                                      "included."], table=hash_rows))
    if not prelim and body.get("diff_from_previous", {}).get("available"):
        d = body["diff_from_previous"]
        rows = [["Category", "Added", "Removed"]] + [[CATEGORY_LABELS.get(k, k), _num(v["added"]), _num(v["removed"])]
                                                   for k, v in d["per_category"].items()]
        sections.append(Section(f"Changes since version {d['from_version']}",
                                [f"People added: {_num(d['people']['added'])}; removed: {_num(d['people']['removed'])}."],
                                table=rows))
    sections.append(Section("Limitations", body.get("limitations") or []))
    title = f"Breach scope report — {body['case_id']} — version {body['version']}"
    sub = [f"Status: {'PRELIMINARY ESTIMATE' if prelim else 'refined count'} (draft until released by the Information Officer)",
           "Contains counts only; no personal information."]
    return render(title, sub, sections, footer=f"{body['case_id']} scope v{body['version']} · {body['method_version']}")


# ---------------------------------------------------------------------------------------------------- saving
def save(case, store, body: dict, pdf: bytes, attachments: dict[str, bytes], *, provider=None):
    allow = check_body(body)
    rs = ReportStore(case)
    draft = rs.save_draft("scope", body, pdf=pdf, attachments=attachments, provider=provider,
                          allow_identifier_like=allow)
    snap = f"{SNAPSHOTS}/{draft.draft_id}"
    if body["report_status"] != "preliminary":
        store.write_table(f"{snap}/people.parquet", store.read_table(R.PEOPLE))
        store.write_table(f"{snap}/person_rows.parquet", store.read_table(R.PERSON_ROWS))
    store.write_json(f"{snap}/meta.json", {"report_sha256": draft.report_sha256, "version": draft.version,
                                           "status": body["report_status"]})
    return draft


def promote_snapshot(store, draft_id: str, version: int) -> None:
    """Release hook helper: keep the released version's person-level snapshot for later diffs."""
    snap = f"{SNAPSHOTS}/{draft_id}"
    dst = f"{VERSIONS}/v{version:04d}"
    for name in ("people.parquet", "person_rows.parquet"):
        if store.exists(f"{snap}/{name}"):
            store.write_table(f"{dst}/{name}", store.read_table(f"{snap}/{name}"))
    if store.exists(f"{snap}/meta.json"):
        store.write_json(f"{dst}/meta.json", store.read_json(f"{snap}/meta.json"))
