"""Accuracy against synthetic ground truth (benchmark and drill only; never used on real cases).

Metrics:

* **auto-link precision (edges)**: share of auto-link pairs whose two records belong to the same true person;
* **pairwise precision / recall (clusters)**: over all pairs of usable identity rows, the share of predicted
  same-person pairs that are truly the same person, and the share of true same-person pairs predicted;
* **unique-person count error**: |predicted people − true people| / true people, where true people are the
  distinct ground-truth persons among usable identity rows;
* **review-band share**: people touched by a pending review item / predicted people;
* **estimate error**: |preliminary point estimate − final count| / final count (and against the truth).
"""

from __future__ import annotations

from pathlib import Path

import pyarrow.parquet as pq


def load_ground_truth(con, gt_path: Path | str, source_map: dict[str, str]) -> None:
    """Map ground truth onto identity rows: ``gt_rows(row_id, person_id, is_minor, has_guardian, has_contact)``."""
    gt = pq.read_table(gt_path)
    con.register("_gt", gt)
    con.execute("CREATE OR REPLACE TABLE _srcmap(db VARCHAR, source_id VARCHAR)")
    con.executemany("INSERT INTO _srcmap VALUES (?, ?)", [[k, v] for k, v in source_map.items()])
    con.execute("""
    CREATE OR REPLACE TABLE gt_rows AS
    WITH base AS (SELECT i.row_id, i.usable, i.local_key, (i.ordinal + 1)::VARCHAR AS ord1, m.db
                  FROM ident i JOIN src_tables t ON t.t_idx = i.t_idx JOIN _srcmap m ON m.source_id = t.source_id)
    SELECT b.row_id, g.person_id, g.is_minor, g.has_guardian, g.has_contact, g.usable AS gt_usable, b.usable
    FROM base b JOIN _gt g ON g.source_db = b.db AND g."table" = 'patients' AND g.local_patient_key = b.local_key
    UNION ALL
    SELECT b.row_id, g.person_id, g.is_minor, g.has_guardian, g.has_contact, g.usable AS gt_usable, b.usable
    FROM base b JOIN _gt g ON g.source_db = b.db AND g."table" = 'leak_sample' AND g.local_patient_key = b.ord1""")
    con.unregister("_gt")


def evaluate(con, *, estimate_point: int | None = None) -> dict:
    """Requires tables gt_rows, rec_rows, pairs_final, person_rows(row_id, person_key) and people."""
    out: dict = {}
    n_ident = con.execute("SELECT count(*) FROM ident").fetchone()[0]
    n_gt = con.execute("SELECT count(*) FROM gt_rows").fetchone()[0]
    out["identity_rows"] = n_ident
    out["identity_rows_with_truth"] = n_gt
    out["usable_rule_agrees_with_truth"] = con.execute(
        "SELECT count(*) FROM gt_rows WHERE usable = gt_usable").fetchone()[0] / max(1, n_gt)
    # edges
    e = con.execute("""
    SELECT count(*), sum(CASE WHEN gl.person_id = gr.person_id THEN 1 ELSE 0 END)
    FROM pairs_final p JOIN gt_rows gl ON gl.row_id = p.rid_l JOIN gt_rows gr ON gr.row_id = p.rid_r
    WHERE p.band = 'auto'""").fetchone()
    out["auto_link_pairs"] = int(e[0])
    out["auto_link_precision"] = (e[1] or 0) / e[0] if e[0] else 1.0
    r = con.execute("""
    SELECT count(*), sum(CASE WHEN gl.person_id = gr.person_id THEN 1 ELSE 0 END)
    FROM pairs_final p JOIN gt_rows gl ON gl.row_id = p.rid_l JOIN gt_rows gr ON gr.row_id = p.rid_r
    WHERE p.band = 'review'""").fetchone()
    out["review_pairs"] = int(r[0])
    out["review_pairs_true_match_share"] = (r[1] or 0) / r[0] if r[0] else None
    # cluster pairwise precision/recall over usable rows
    con.execute("""
    CREATE OR REPLACE TEMP TABLE _ev AS
    SELECT g.row_id, g.person_id, pr.person_key FROM gt_rows g JOIN person_rows pr USING (row_id) WHERE g.usable""")
    tp = con.execute("""
    SELECT coalesce(sum(n * (n - 1) / 2), 0) FROM (SELECT count(*) AS n FROM _ev GROUP BY person_id, person_key)""").fetchone()[0]
    pred = con.execute("""
    SELECT coalesce(sum(n * (n - 1) / 2), 0) FROM (SELECT count(*) AS n FROM _ev GROUP BY person_key)""").fetchone()[0]
    true = con.execute("""
    SELECT coalesce(sum(n * (n - 1) / 2), 0) FROM (SELECT count(*) AS n FROM _ev GROUP BY person_id)""").fetchone()[0]
    out["pairwise_precision"] = float(tp) / float(pred) if pred else 1.0
    out["pairwise_recall"] = float(tp) / float(true) if true else 1.0
    true_people = con.execute("SELECT count(DISTINCT person_id) FROM _ev").fetchone()[0]
    pred_people = con.execute("SELECT count(*) FROM people").fetchone()[0]
    out["true_people"] = int(true_people)
    out["predicted_people"] = int(pred_people)
    out["person_count_error"] = abs(pred_people - true_people) / true_people if true_people else 0.0
    out["person_count_signed_error"] = (pred_people - true_people) / true_people if true_people else 0.0
    out["over_merged_predicted_people"] = con.execute("""
        SELECT count(*) FROM (SELECT person_key FROM _ev GROUP BY person_key HAVING count(DISTINCT person_id) > 1)""").fetchone()[0]
    out["split_true_people"] = con.execute("""
        SELECT count(*) FROM (SELECT person_id FROM _ev GROUP BY person_id HAVING count(DISTINCT person_key) > 1)""").fetchone()[0]
    rv = con.execute("SELECT count(*) FROM people WHERE confidence = 'probabilistic-unreviewed'").fetchone()[0]
    out["review_band_people"] = int(rv)
    out["review_band_share"] = rv / pred_people if pred_people else 0.0
    if estimate_point is not None:
        out["estimate_point"] = int(estimate_point)
        out["estimate_error_vs_final"] = abs(estimate_point - pred_people) / pred_people if pred_people else 0.0
        out["estimate_error_vs_truth"] = abs(estimate_point - true_people) / true_people if true_people else 0.0
    # notices against truth (person-level flags of the majority true person per predicted person)
    seg = con.execute("""
    WITH t AS (SELECT DISTINCT person_id, is_minor, has_guardian, has_contact FROM gt_rows
               WHERE usable AND is_minor IS NOT NULL),
         tp AS (SELECT person_id, bool_or(is_minor) AS is_minor, bool_or(has_guardian) AS has_guardian,
                       bool_or(has_contact) AS has_contact FROM t GROUP BY person_id)
    SELECT sum(CASE WHEN is_minor THEN 1 ELSE 0 END),
           sum(CASE WHEN is_minor AND has_guardian THEN 1 ELSE 0 END),
           sum(CASE WHEN is_minor AND NOT has_guardian THEN 1 ELSE 0 END),
           sum(CASE WHEN NOT is_minor AND NOT has_contact THEN 1 ELSE 0 END)
    FROM tp""").fetchone()
    out["truth_minors"] = int(seg[0] or 0)
    out["truth_minors_routed_to_guardian"] = int(seg[1] or 0)
    out["truth_minors_flagged_no_guardian"] = int(seg[2] or 0)
    out["truth_adults_without_contact"] = int(seg[3] or 0)
    ps = dict(con.execute("SELECT segment, count(*) FROM people GROUP BY segment").fetchall())
    out["predicted_segments"] = {k: int(v) for k, v in sorted(ps.items())}
    return out
