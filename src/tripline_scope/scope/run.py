"""Orchestration of ``tscope estimate`` and ``tscope scope match`` and persistence of their results.

Everything persisted goes through ``CaseStore`` (authenticated encryption under the case key):

``work/scope/estimate.json``        preliminary estimate (counts only)
``work/scope/match.json``           match summary: config, hashes, model parameters, statistics, bounds, timings
``work/scope/tables.json``          extracted tables with rows and unresolvable counts
``work/scope/people.parquet``       one row per person (no identifiers: positional person key, flags, masks)
``work/scope/person_tables.parquet``  person × table exposure
``work/scope/person_rows.parquet``  identity record key → person key
``review/queue.json``               pending review items (record keys and HMAC pair keys only)
"""

from __future__ import annotations

import datetime as dt
import time

import pyarrow as pa

from tripline_scope import METHOD_VERSION

from . import config as C
from . import data as D
from . import decisions as DEC
from . import estimate as E
from . import people as P
from .match import PAIR_PURPOSE, Matcher, make_pair_key

ESTIMATE = "work/scope/estimate.json"
MATCH = "work/scope/match.json"
TABLES = "work/scope/tables.json"
PEOPLE = "work/scope/people.parquet"
PERSON_TABLES = "work/scope/person_tables.parquet"
PERSON_ROWS = "work/scope/person_rows.parquet"


def extract_hashes(store, data: D.ScopeData) -> dict[str, str]:
    return {sid: store.file_sha256(f"work/extract/{sid}/manifest.json") for sid in sorted(data.sources)}


def _tables_json(con) -> list[dict]:
    rows = con.execute("""
    SELECT t.t_idx, t.source_id, t.slug, t.database, t."table", t.role, t.evidence_role, t.row_count,
           coalesce(u.identity_rows_without_identifiers, 0), coalesce(u.dependent_rows_unlinked, 0)
    FROM src_tables t LEFT JOIN unresolvable u USING (t_idx) ORDER BY t.t_idx""").fetchall()
    keys = ["t_idx", "source_id", "slug", "database", "table", "role", "evidence_role", "rows",
            "identity_rows_without_identifiers", "dependent_rows_unlinked"]
    return [dict(zip(keys, r, strict=True)) for r in rows]


def run_estimate(case, store, cfg: dict, *, threads=None, reference_date: dt.date | None = None) -> dict:
    t0 = time.time()
    data = D.load(case, store, cfg, threads=threads, reference_date=reference_date)
    t1 = time.time()
    est = E.estimate(data)
    con = data.con
    unres_id = con.execute("SELECT count(*) FROM ident WHERE NOT usable").fetchone()[0]
    unres_dep = con.execute("""SELECT coalesce(sum(d.n_rows), 0) FROM dep d WHERE NOT EXISTS (
        SELECT 1 FROM dep_link l WHERE l.t_idx = d.t_idx AND l.patient_ref IS NOT DISTINCT FROM d.patient_ref)""").fetchone()[0]
    tables = []
    for t in data.tables:
        tables.append({k: t[k] for k in ("t_idx", "source_id", "slug", "database", "table", "role", "evidence_role")}
                      | {"rows": t["row_count"]})
    out = {
        "schema": "tripline.scope-estimate/v1",
        "method_version": METHOD_VERSION,
        "config_sha256": C.config_sha256(cfg),
        "extract_manifests_sha256": extract_hashes(store, data),
        "reference_date": data.reference_date.isoformat(),
        "estimate": est,
        "unresolvable": {"identity_rows_without_identifiers": int(unres_id), "dependent_rows_unlinked": int(unres_dep)},
        "tables": tables,
        "timings_s": {"load": round(t1 - t0, 3), "estimate": round(time.time() - t1, 3)},
    }
    store.write_json(ESTIMATE, out)
    con.close()
    return out


def run_match(case, store, cfg: dict, *, threads=None, reference_date: dt.date | None = None,
              keep_session: bool = False):
    """Run the full matcher and persist people, exposure and the review queue. Returns (summary, data|None)."""
    t0 = time.time()
    data = D.load(case, store, cfg, threads=threads, reference_date=reference_date)
    t_load = time.time() - t0
    decs = DEC.latest(store)
    m = Matcher(data, cfg, pair_key=make_pair_key(store.fingerprinter(PAIR_PURPOSE)), decisions=decs, threads=threads)
    m.run()
    t1 = time.time()
    P.build(data.con, cfg, data.reference_date)
    con = data.con
    # lower bound: every pending review link accepted
    m._components("""SELECT a, b FROM edges_final
                     UNION ALL SELECT rid_l, rid_r FROM pairs_final WHERE band = 'review' AND decision IS NULL
                     UNION ALL SELECT rid_l, rid_r FROM cluster_review""", "comp_lower")
    lower = con.execute("SELECT count(DISTINCT comp) FROM comp_lower").fetchone()[0]
    people_n = con.execute("SELECT count(*) FROM people").fetchone()[0]
    queue = m.review_queue()
    t_people = time.time() - t1
    # persist
    store.write_table(PEOPLE, con.execute("""
        SELECT p.person_key, p.confidence, p.n_rows, p.n_sources, p.age_known, p.is_minor, p.own_contact,
               p.guardian_contact, p.segment, p.language, p.in_leak, p.leak_mask, coalesce(k.cat_mask, 0) AS cat_mask
        FROM people p LEFT JOIN people_mask k USING (person_key) ORDER BY p.person_key""").fetch_arrow_table())
    store.write_table(PERSON_TABLES, con.execute("""
        SELECT pt.person_key, t.source_id, t.slug, pt.n_rows, pt.min_date, pt.n_null_date, pt.cat_mask
        FROM person_tables pt JOIN src_tables t USING (t_idx) ORDER BY pt.person_key, t.source_id, t.slug""").fetch_arrow_table())
    store.write_table(PERSON_ROWS, con.execute("""
        SELECT i.row_key, pr.person_key FROM person_rows pr JOIN ident i USING (row_id) ORDER BY i.row_key""").fetch_arrow_table())
    tables = _tables_json(con)
    store.write_json(TABLES, {"tables": tables})
    store.write_json(DEC.QUEUE, {"items": queue})
    summary = {
        "schema": "tripline.scope-match/v1",
        "method_version": METHOD_VERSION,
        "config": cfg,
        "config_sha256": C.config_sha256(cfg),
        "review_decisions_sha256": DEC.digest(decs),
        "review_decisions": DEC.summary(decs),
        "extract_manifests_sha256": extract_hashes(store, data),
        "reference_date": data.reference_date.isoformat(),
        "stats": {k: int(v) for k, v in m.stats.items()},
        "people": int(people_n),
        "people_lower_bound": int(lower),
        "review_queue": {"items": len(queue), "review_band": sum(1 for q in queue if q["reason"] == "review_band"),
                         "over_merge_guard": sum(1 for q in queue if q["reason"] == "over_merge_guard")},
        "model": model_summary(m.model),
        "timings_s": {"load": round(t_load, 3), **m.timings, "people": round(t_people, 3)},
    }
    store.write_json(MATCH, summary)
    if keep_session:
        return summary, data
    con.close()
    return summary, None


def _sig(x, digits=6):
    if isinstance(x, float):
        return float(f"{x:.{digits}g}")
    return x


def model_summary(model: dict) -> dict:
    """Comparison levels with m, u and match weight (log2 Bayes factor), rounded; no data values."""
    import math

    if not model:
        return {}
    comps = []
    for c in model.get("comparisons", []):
        levels = []
        for lv in c.get("comparison_levels", []):
            if lv.get("is_null_level"):
                levels.append({"label": lv.get("label_for_charts") or "null", "null_level": True})
                continue
            m, u = lv.get("m_probability"), lv.get("u_probability")
            w = None
            if isinstance(m, float) and isinstance(u, float) and m > 0 and u > 0:
                w = _sig(math.log2(m / u), 4)
            levels.append({"label": lv.get("label_for_charts") or lv.get("sql_condition", "")[:80],
                           "m": _sig(m), "u": _sig(u), "match_weight": w,
                           "term_frequency_adjusted": bool(lv.get("tf_adjustment_column"))})
        comps.append({"comparison": c.get("output_column_name"), "levels": levels})
    return {"probability_two_random_records_match": _sig(model.get("probability_two_random_records_match")),
            "comparisons": comps}


def load_people(store) -> pa.Table:
    return store.read_table(PEOPLE)
