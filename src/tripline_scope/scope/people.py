"""People: clusters → person records with exposure per source, confidence, age group and contact route.

Tables built (in the DuckDB session):

``person_rows``    usable identity row → person_key (the smallest record key in the person's cluster; record keys are
                   positional "<SRC>|<table>|<ordinal>" strings, never patient identifiers)
``people``         person_key, confidence, n_rows, n_sources, dob (most frequent, ties → youngest), is_minor,
                   age_known, own_contact, guardian_contact, segment, language, in_leak, leak_mask, cat_mask
``person_tables``  person_key × extracted table: rows, earliest record date, rows without a date, category mask
                   (identity rows of the person plus the dependent rows that reference them)
``unresolvable``   per table: identity rows without enough identifiers and dependent rows that reference no usable
                   identity row — counted separately, never forced into people

Confidence: ``probabilistic-unreviewed`` when a pending review item touches the person; else ``reviewed`` when a
reviewer decision shaped the person; else ``auto-linked`` when an auto-link joined records; else
``deterministic`` (ID links only, or a single record).
"""

from __future__ import annotations

import datetime as dt

SEGMENTS = ("adult_with_contact", "minor_guardian_routed", "minor_flagged_no_guardian", "no_usable_contact")
CONFIDENCE = ("deterministic", "auto-linked", "reviewed", "probabilistic-unreviewed")


def build(con, cfg: dict, reference_date: dt.date) -> None:
    years = int(cfg["minor_age_years"])
    ref = reference_date.isoformat()
    con.execute("""
    CREATE OR REPLACE TABLE person_rows AS
    WITH r AS (SELECT rr.row_id, c.comp FROM rec_rows rr JOIN comp c ON c.rid = rr.rid),
    k AS (SELECT r.row_id, r.comp, i.row_key FROM r JOIN ident i USING (row_id))
    SELECT row_id, min(row_key) OVER (PARTITION BY comp) AS person_key FROM k ORDER BY row_id""")
    con.execute("""
    CREATE OR REPLACE TABLE pending_recs AS
    SELECT rid_l AS rid FROM pairs_final WHERE band = 'review' AND decision IS NULL
    UNION SELECT rid_r FROM pairs_final WHERE band = 'review' AND decision IS NULL
    UNION SELECT rid_l FROM cluster_review UNION SELECT rid_r FROM cluster_review""")
    con.execute("""
    CREATE OR REPLACE TABLE decided_recs AS
    SELECT rid_l AS rid FROM pairs_final WHERE decision IN ('same', 'different')
    UNION SELECT rid_r FROM pairs_final WHERE decision IN ('same', 'different')""")
    con.execute("""
    CREATE OR REPLACE TABLE person_conf AS
    WITH pk AS (SELECT DISTINCT c.comp, pr.person_key FROM person_rows pr JOIN rec_rows rr USING (row_id)
                JOIN comp c ON c.rid = rr.rid),
    ek AS (SELECT c.comp, bool_or(e.kind = 'auto') AS has_auto, bool_or(e.kind = 'reviewed') AS has_rev
           FROM edges_final e JOIN comp c ON c.rid = e.a GROUP BY c.comp),
    pend AS (SELECT DISTINCT c.comp FROM pending_recs p JOIN comp c USING (rid)),
    dec AS (SELECT DISTINCT c.comp FROM decided_recs p JOIN comp c USING (rid))
    SELECT pk.person_key,
      CASE WHEN pk.comp IN (SELECT comp FROM pend) THEN 'probabilistic-unreviewed'
           WHEN coalesce(ek.has_rev, false) OR pk.comp IN (SELECT comp FROM dec) THEN 'reviewed'
           WHEN coalesce(ek.has_auto, false) THEN 'auto-linked'
           ELSE 'deterministic' END AS confidence
    FROM pk LEFT JOIN ek USING (comp)""")
    con.execute(f"""
    CREATE OR REPLACE TABLE people AS
    WITH rows AS (
      SELECT pr.person_key, i.*, t.evidence_role, t.source_id
      FROM person_rows pr JOIN ident i USING (row_id) JOIN src_tables t ON t.t_idx = i.t_idx),
    dobc AS (SELECT person_key, dob_eff, count(*) AS n FROM rows WHERE dob_eff IS NOT NULL GROUP BY ALL),
    dob AS (SELECT person_key, arg_max(dob_eff, n * 100000 + (dob_eff - DATE '1800-01-01')) AS dob FROM dobc
            GROUP BY person_key),
    langc AS (SELECT person_key, lang, count(*) AS n FROM rows WHERE lang IS NOT NULL GROUP BY ALL),
    lang AS (SELECT person_key, arg_max(lang, n * 1000 - hash(lang) % 997) AS lang FROM langc GROUP BY person_key),
    agg AS (
      SELECT person_key, count(*) AS n_rows, count(DISTINCT source_id) AS n_sources,
        bool_or(own_contact AND coalesce(evidence_role, '') <> 'leak_sample') AS own_contact,
        bool_or(guardian_contact AND coalesce(evidence_role, '') <> 'leak_sample') AS guardian_contact,
        bool_or(evidence_role = 'leak_sample') AS in_leak,
        bit_or(CASE WHEN evidence_role = 'leak_sample' THEN cat_own ELSE 0 END) AS leak_mask
      FROM rows GROUP BY person_key)
    SELECT a.person_key, c.confidence, a.n_rows, a.n_sources, d.dob, d.dob IS NOT NULL AS age_known,
      coalesce(d.dob + INTERVAL {years} YEAR > DATE '{ref}', false) AS is_minor,
      a.own_contact, a.guardian_contact,
      CASE WHEN coalesce(d.dob + INTERVAL {years} YEAR > DATE '{ref}', false) THEN
             CASE WHEN a.guardian_contact THEN 'minor_guardian_routed' ELSE 'minor_flagged_no_guardian' END
           WHEN a.own_contact THEN 'adult_with_contact' ELSE 'no_usable_contact' END AS segment,
      l.lang AS language, a.in_leak, a.leak_mask
    FROM agg a JOIN person_conf c USING (person_key) LEFT JOIN dob d USING (person_key)
    LEFT JOIN lang l USING (person_key)
    ORDER BY a.person_key""")
    con.execute("""
    CREATE OR REPLACE TABLE person_tables AS
    WITH idr AS (
      SELECT pr.person_key, i.t_idx, count(*) AS n_rows, min(i.record_date) AS min_date,
             count(*) FILTER (WHERE i.record_date IS NULL) AS n_null_date, bit_or(i.cat_own) AS cat_mask
      FROM person_rows pr JOIN ident i USING (row_id) GROUP BY ALL),
    dpr AS (
      SELECT DISTINCT pr.person_key, d.t_idx, d.patient_ref, d.n_rows, d.min_date, d.n_null_date, d.cat_mask
      FROM dep_link l JOIN dep d USING (t_idx, patient_ref) JOIN person_rows pr USING (row_id)),
    dp AS (SELECT person_key, t_idx, sum(n_rows)::BIGINT AS n_rows, min(min_date) AS min_date,
                  sum(n_null_date)::BIGINT AS n_null_date, bit_or(cat_mask) AS cat_mask FROM dpr GROUP BY ALL)
    SELECT * FROM idr UNION ALL SELECT * FROM dp ORDER BY person_key, t_idx""")
    con.execute("""
    CREATE OR REPLACE TABLE people_mask AS
    SELECT person_key, bit_or(cat_mask) AS cat_mask FROM person_tables GROUP BY person_key""")
    con.execute("""
    CREATE OR REPLACE TABLE unresolvable AS
    WITH a AS (SELECT t_idx, count(*) AS n FROM ident WHERE NOT usable GROUP BY t_idx),
    b AS (SELECT d.t_idx, sum(d.n_rows)::BIGINT AS n FROM dep d
          WHERE NOT EXISTS (SELECT 1 FROM dep_link l WHERE l.t_idx = d.t_idx AND l.patient_ref IS NOT DISTINCT FROM d.patient_ref)
          GROUP BY d.t_idx)
    SELECT t.t_idx, t.source_id, t.slug, coalesce(a.n, 0) AS identity_rows_without_identifiers,
           coalesce(b.n, 0) AS dependent_rows_unlinked
    FROM src_tables t LEFT JOIN a USING (t_idx) LEFT JOIN b USING (t_idx) ORDER BY t.t_idx""")
