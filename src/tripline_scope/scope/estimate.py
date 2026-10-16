"""Preliminary estimate: exact ID matching plus distinct counts over phonetic name keys, with bounds.

Method (all counts over *usable* identity rows; unresolvable rows are counted separately):

* people with a valid SA ID: the number of distinct ID numbers (exact);
* rows without an ID are keyed by passport number, else by (sorted soundex of first name and surname, date of
  birth); a key already carried by an ID row is the same person and is not counted again;
* point estimate = distinct IDs + distinct new keys;
* lower bound = point estimate reduced by the configured margin (default 5 %, the accuracy target for the
  estimate). This end is *calibrated*, not guaranteed: on synthetic estates from 50k to 10M rows the point estimate
  was 2.2-2.7 % above the true number of people. Purely structural lower bounds were tested and rejected: distinct
  ID counts overshoot (one person can carry two valid IDs after a keying error), and transitive merging on name and
  date keys chains unrelated people together at scale (21-38 % too low at 10M);
* upper bound = distinct IDs + distinct exact (first name, surname, date of birth / passport) keys among rows
  without an ID, with no overlap removal (splits more than the final matcher).

People per exposure category use the same point method restricted to rows (identity row plus its linked
dependent rows) that carry the category. The result is labelled preliminary in every output.

Scale: each usable identity row is reduced to five 64-bit values (hashes of the SA ID and the three keys, plus the
category mask) in ``est_rows``; all counts run over that table. :func:`estimate_sliced` fills it one slice of the
extracts at a time (:func:`data.slices`), so the estimate needs memory for the largest slice plus about 40 bytes
per identity row, not for the whole estate. Two different keys share a 64-bit hash with probability about
n^2 / 2^65 (1e-5 at 20 million keys), far inside the estimate's 5 % margin.
"""

from __future__ import annotations

import time

from .config import EXPOSURE_CATEGORIES
from .data import CAT_BIT, ScopeData, slices

EST_ROWS_SQL = """CREATE TABLE IF NOT EXISTS est_rows(sa_id UBIGINT, k_point UBIGINT, k_name UBIGINT,
                                                    k_fine UBIGINT, cat_mask INTEGER)"""

_NAME_KEY = """'N:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
       || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '')"""

KEYS_SQL = f"""
INSERT INTO est_rows
SELECT CASE WHEN i.sa_id IS NULL THEN NULL ELSE hash(i.sa_id) END,
  CASE WHEN i.sa_id IS NOT NULL THEN NULL
       WHEN i.passport IS NOT NULL THEN hash('P:' || i.passport)
       ELSE hash({_NAME_KEY}) END,
  hash({_NAME_KEY}),
  hash(coalesce('P:' || i.passport, 'F:' || coalesce(i.first, '') || '|' || coalesce(i.last, '') || '|'
       || coalesce(strftime(i.dob_eff, '%Y%m%d'), ''))),
  i.cat_own | coalesce(d.dep_mask, 0)
FROM ident i
LEFT JOIN (SELECT l.row_id, bit_or(d.cat_mask) AS dep_mask FROM dep_link l
           JOIN dep d USING (t_idx, patient_ref) GROUP BY l.row_id) d USING (row_id)
WHERE i.usable
"""

UNRESOLVABLE_SQL = """
SELECT (SELECT count(*) FROM ident WHERE NOT usable),
       (SELECT coalesce(sum(d.n_rows), 0) FROM dep d WHERE NOT EXISTS (
          SELECT 1 FROM dep_link l WHERE l.t_idx = d.t_idx AND l.patient_ref IS NOT DISTINCT FROM d.patient_ref))
"""


def _margin(cfg: dict | None) -> float:
    return float(((cfg or {}).get("estimate") or {}).get("lower_margin", 0.05))


def _counts(con, where: str, margin: float) -> dict:
    n_id, point, upper = con.execute(f"""
        SELECT count(DISTINCT sa_id),
               count(DISTINCT k_point) FILTER (WHERE sa_id IS NULL AND NOT id_name),
               count(DISTINCT k_fine) FILTER (WHERE sa_id IS NULL)
        FROM est_x WHERE {where}""").fetchone()
    point = int(n_id + point)
    return {"point": point, "lower": int(point * (1.0 - margin)), "upper": int(n_id + upper),
            "people_with_valid_sa_id": int(n_id)}


def _summarise(con, margin: float) -> dict:
    # a row's point key "already carried by an ID row" is decided once, over the whole estate
    con.execute("""CREATE OR REPLACE TEMP TABLE est_x AS
        SELECT r.sa_id, r.k_point, r.k_fine, r.cat_mask, (n.k IS NOT NULL) AS id_name
        FROM est_rows r LEFT JOIN (SELECT DISTINCT k_name AS k FROM est_rows WHERE sa_id IS NOT NULL) n
             ON n.k = r.k_point""")
    total = _counts(con, "TRUE", margin)
    per_cat = {}
    for c in EXPOSURE_CATEGORIES:
        bit = CAT_BIT[c]
        if con.execute(f"SELECT count(*) FROM est_x WHERE cat_mask & {bit} <> 0").fetchone()[0] == 0:
            per_cat[c] = {"point": 0, "lower": 0, "upper": 0}
            continue
        r = _counts(con, f"cat_mask & {bit} <> 0", margin)
        per_cat[c] = {k: r[k] for k in ("point", "lower", "upper")}
    con.execute("DROP TABLE est_x")
    total["per_category"] = per_cat
    total["lower_bound_basis"] = (f"point estimate minus {margin:.0%}: calibrated on synthetic data, where the "
                                  "estimate was 2.2-2.7 % above the true count; not a guarantee")
    total["method"] = ("exact distinct SA ID numbers + distinct phonetic (soundex) name and date-of-birth keys for "
                       "rows without an ID, excluding keys already carried by an ID row")
    return total


def estimate(data: ScopeData, cfg: dict | None = None) -> dict:
    """Estimate from data already loaded in full (:func:`data.load`)."""
    con = data.con
    con.execute("DROP TABLE IF EXISTS est_rows")
    con.execute(EST_ROWS_SQL)
    con.execute(KEYS_SQL)
    return _summarise(con, _margin(cfg))


def estimate_sliced(case, store, cfg: dict, *, threads: int | None = None, memory_limit: str | None = None,
                    reference_date=None) -> dict:
    """Estimate one slice of the extracts at a time (see the module docstring); same result as :func:`estimate`.

    Returns ``estimate``, ``unresolvable``, ``tables``, ``sources``, ``reference_date``, ``slices`` and timings."""
    rows_per_pass = int(((cfg.get("estimate") or {}).get("rows_per_pass")) or 3_000_000)
    t0 = time.time()
    unres_id = unres_dep = n_slices = 0
    tables, sources, con, ref = [], {}, None, None
    for d in slices(case, store, cfg, threads=threads, memory_limit=memory_limit, reference_date=reference_date,
                    rows_per_pass=rows_per_pass):
        con, ref = d.con, d.reference_date
        con.execute(EST_ROWS_SQL)
        con.execute(KEYS_SQL)
        a, b = con.execute(UNRESOLVABLE_SQL).fetchone()
        unres_id, unres_dep, n_slices = unres_id + int(a), unres_dep + int(b), n_slices + 1
        if d.counts["slice"] == 0:
            tables += d.tables
            sources |= d.sources
    t1 = time.time()
    est = _summarise(con, _margin(cfg))
    con.close()
    return {"estimate": est, "reference_date": ref, "tables": tables, "sources": sources, "slices": n_slices,
            "rows_per_pass": rows_per_pass,
            "unresolvable": {"identity_rows_without_identifiers": unres_id, "dependent_rows_unlinked": unres_dep},
            "timings_s": {"load": round(t1 - t0, 3), "estimate": round(time.time() - t1, 3)}}
