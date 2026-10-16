"""Preliminary estimate: exact ID matching plus distinct counts over phonetic name keys, with bounds.

Method (all counts over *usable* identity rows; unresolvable rows are counted separately):

* people with a valid SA ID: the number of distinct ID numbers (exact);
* rows without an ID are keyed by passport number, else by (sorted soundex of first name and surname, date of
  birth); a key already carried by an ID row is the same person and is not counted again;
* point estimate = distinct IDs + distinct new keys;
* lower bound = connected components over *all* usable rows, ID rows included, where rows are joined when they
  share any of: SA ID, (surname soundex, date of birth), or (sorted name-soundex pair, birth year). This merges far
  more aggressively than the final matcher (it also joins different people who happen to share these keys), so
  it under-counts; one person carrying two different valid ID numbers after a keying error is still merged;
* upper bound = distinct IDs + distinct exact (first name, surname, date of birth / passport) keys among rows
  without an ID, with no overlap removal (splits more than the final matcher).

People per exposure category use the same point method restricted to rows (identity row plus its linked
dependent rows) that carry the category. The result is labelled preliminary in every output.
"""

from __future__ import annotations

from .config import EXPOSURE_CATEGORIES
from .data import CAT_BIT, ScopeData

KEYS_SQL = """
CREATE OR REPLACE TEMP TABLE est_rows AS
SELECT i.row_id, i.sa_id,
  CASE WHEN i.sa_id IS NOT NULL THEN NULL
       WHEN i.passport IS NOT NULL THEN 'P:' || i.passport
       ELSE 'N:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
            || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '') END AS k_point,
  'N:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
       || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '') AS k_name,
  'C:' || coalesce(i.sx_last, '') || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '') AS k_coarse,
  'Y:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
       || '|' || coalesce(strftime(i.dob_eff, '%Y'), '') AS k_coarse_year,
  coalesce('P:' || i.passport, 'F:' || coalesce(i.first, '') || '|' || coalesce(i.last, '') || '|'
       || coalesce(strftime(i.dob_eff, '%Y%m%d'), '')) AS k_fine,
  i.cat_own | coalesce(d.dep_mask, 0) AS cat_mask
FROM ident i
LEFT JOIN (SELECT l.row_id, bit_or(d.cat_mask) AS dep_mask FROM dep_link l
           JOIN dep d USING (t_idx, patient_ref) GROUP BY l.row_id) d USING (row_id)
WHERE i.usable
"""


def _aggressive_components(con, max_iter: int = 12) -> int:
    """Count connected components of est_sub rows linked by any shared aggressive key (label propagation).
    Stopping early can only leave components split, i.e. a larger count; iterations continue until stable."""
    con.execute("""CREATE OR REPLACE TEMP TABLE est_lab AS
        SELECT row_id, coalesce('I:' || sa_id, 'R:' || row_id::VARCHAR) AS k1, k_coarse AS k2, k_coarse_year AS k3,
               row_id AS lab FROM est_sub""")
    prev = None
    for _ in range(max_iter):
        con.execute("""CREATE OR REPLACE TEMP TABLE est_lab AS
            WITH a AS (SELECT k1, min(lab) m FROM est_lab GROUP BY k1),
                 b AS (SELECT k2, min(lab) m FROM est_lab GROUP BY k2),
                 c AS (SELECT k3, min(lab) m FROM est_lab GROUP BY k3)
            SELECT e.row_id, e.k1, e.k2, e.k3, least(e.lab, a.m, b.m, c.m) AS lab
            FROM est_lab e JOIN a USING (k1) JOIN b USING (k2) JOIN c USING (k3)""")
        n = con.execute("SELECT count(DISTINCT lab) FROM est_lab").fetchone()[0]
        if n == prev:
            break
        prev = n
    return int(prev)


def _counts(data: ScopeData, where: str) -> dict:
    con = data.con
    con.execute(f"CREATE OR REPLACE TEMP TABLE est_sub AS SELECT * FROM est_rows WHERE {where}")
    n_id = con.execute("SELECT count(DISTINCT sa_id) FROM est_sub").fetchone()[0]
    point = con.execute("""
        SELECT count(DISTINCT s.k_point) FROM est_sub s
        WHERE s.sa_id IS NULL AND NOT EXISTS (SELECT 1 FROM est_id_names n WHERE n.k = s.k_point)""").fetchone()[0]
    lower = _aggressive_components(con)
    upper = con.execute("SELECT count(DISTINCT k_fine) FROM est_sub WHERE sa_id IS NULL").fetchone()[0]
    point = int(n_id + point)
    return {"point": point, "lower": int(min(lower, point)), "upper": int(n_id + upper),
            "people_with_valid_sa_id": int(n_id)}


def estimate(data: ScopeData) -> dict:
    con = data.con
    con.execute(KEYS_SQL)
    con.execute("CREATE OR REPLACE TEMP TABLE est_id_names AS SELECT DISTINCT k_name AS k FROM est_rows WHERE sa_id IS NOT NULL")
    total = _counts(data, "TRUE")
    per_cat = {}
    for c in EXPOSURE_CATEGORIES:
        bit = CAT_BIT[c]
        if con.execute(f"SELECT count(*) FROM est_rows WHERE cat_mask & {bit} <> 0").fetchone()[0] == 0:
            per_cat[c] = {"point": 0, "lower": 0, "upper": 0}
            continue
        r = _counts(data, f"cat_mask & {bit} <> 0")
        per_cat[c] = {k: r[k] for k in ("point", "lower", "upper")}
    total["per_category"] = per_cat
    total["method"] = ("exact distinct SA ID numbers + distinct phonetic (soundex) name and date-of-birth keys for "
                       "rows without an ID, excluding keys already carried by an ID row")
    return total
