"""Streaming, vectorised generator of lab-like synthetic data with ground truth.

All randomness is a keyed hash of (entity id, tag, seed) evaluated inside DuckDB, so generation is fully
vectorised, needs no global state beyond one compact SA-ID sequence table, gives identical output for the same
seed on any thread count, and runs in chunks of households so 80M admission rows fit in bounded memory.

Population model (per block of four person slots = one household):

* slot 0 is the household head (adult); slot 1 is a spouse (opposite sex, shared surname, the woman usually
  with a maiden surname) or an unrelated single adult; slots 2 and 3 are children (shared surname and
  household phone, guardian = mother or head) or unrelated single adults; slot 3 is sometimes a twin of slot 2
  (same date of birth and phone, different first name).
* 6 % foreign nationals carry passports instead of SA IDs; children usually have no ID number recorded.
* Each person has 1-7 registrations (patient rows) spread over the databases (so the same person appears in
  several databases and sometimes twice in one), each a noisy copy: typos, swapped name order, maiden vs
  married surname, missing or mistyped ID numbers (a single mistyped digit always fails the Luhn check),
  DOB typos, old phone numbers, missing fields, varied formatting.
* 0.4 % of registrations are placeholder rows ("UNKNOWN", no date of birth or ID) that cannot be resolved.
* Admissions (many per registration, ICD-10 code and a short generic note), billing (synthetic Luhn-valid test
  card numbers and bank account numbers, to test flag-never-copy) and result metadata (test code and status
  only, no results) hang off each registration; 0.3 % of admissions reference a patient key that does not exist.

Outputs: ``sources/dbNN/{patients,admissions,billing,results}.parquet``, ``leak_sample.csv`` (identity fields of
a few hundred people from one database), ``ground_truth.parquet`` and ``synth_meta.json``.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import math
import os
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from tripline_scope.core import duck

from . import names as N
from .schema import STYLES, TABLES, db_name, style_of

GENERATOR_VERSION = "tripline-synth/1.0"
DEFAULT_SEED = 20260914
DEFAULT_REFERENCE_DATE = dt.date(2026, 9, 14)
DB_WEIGHTS = [0.16, 0.13, 0.12, 0.11, 0.10, 0.09, 0.08, 0.08, 0.07, 0.06]
MEAN_REGS = 1.75
MEAN_ADMISSIONS = 4.0
LEAK_DB = 3


def _sql_list(values) -> str:
    return "[" + ", ".join("'" + str(v).replace("'", "''") + "'" for v in values) + "]"


def _flat(groups: dict[str, list[str]]) -> tuple[list[str], dict[str, tuple[int, int]]]:
    flat, spans = [], {}
    for g, lst in groups.items():
        spans[g] = (len(flat), len(lst))
        flat.extend(lst)
    return flat, spans


def _case(expr: str, mapping: dict[str, object], default="NULL") -> str:
    parts = " ".join(f"WHEN '{k}' THEN {v}" for k, v in mapping.items())
    return f"CASE {expr} {parts} ELSE {default} END"


def _macros(con, seed: int, n_dbs: int) -> None:
    sn_flat, sn_span = _flat(N.SURNAMES)
    fn_m, fm_span = _flat(N.MALE)
    fn_f, ff_span = _flat(N.FEMALE)
    groups = list(N.GROUPS)
    cum, acc = [], 0.0
    for g in groups:
        acc += N.GROUPS[g][0]
        cum.append((g, acc))
    grp_case = "CASE " + " ".join(f"WHEN x < {c:.6f} THEN '{g}'" for g, c in cum[:-1]) + f" ELSE '{cum[-1][0]}' END"
    w = DB_WEIGHTS[:n_dbs] if n_dbs <= len(DB_WEIGHTS) else [1.0] * n_dbs
    tot = sum(w)
    acc, db_case = 0.0, []
    for i, wi in enumerate(w[:-1], 1):
        acc += wi / tot
        db_case.append(f"WHEN x < {acc:.6f} THEN {i}")
    db_case_sql = "CASE " + " ".join(db_case) + f" ELSE {len(w)} END" if db_case else "1"
    tail = {"zu": 0.40, "xh": 0.40, "st": 0.40, "ts": 0.40, "fo": 0.35, "en": 0.30, "af": 0.30, "in": 0.0}
    langs = {g: f"'{v[1]}'" for g, v in N.GROUPS.items()}
    stmts = [
        f"CREATE OR REPLACE MACRO rnd(k, tag) AS (hash(k, tag, {int(seed)}) % 1000000007)::DOUBLE / 1000000007.0",
        f"CREATE OR REPLACE MACRO rint(k, tag, n) AS (hash(k, tag, {int(seed)}) % (n)::UBIGINT)::BIGINT",
        f"CREATE OR REPLACE MACRO grp_pick(x) AS {grp_case}",
        f"CREATE OR REPLACE MACRO db_pick(x) AS {db_case_sql}",
        f"CREATE OR REPLACE MACRO lang_of(g) AS {_case('g', langs)}",
        f"CREATE OR REPLACE MACRO sn_all() AS {_sql_list(sn_flat)}",
        f"CREATE OR REPLACE MACRO fm_all() AS {_sql_list(fn_m)}",
        f"CREATE OR REPLACE MACRO ff_all() AS {_sql_list(fn_f)}",
        f"CREATE OR REPLACE MACRO sn_start(g) AS {_case('g', {k: v[0] for k, v in sn_span.items()}, 0)}",
        f"CREATE OR REPLACE MACRO sn_count(g) AS {_case('g', {k: v[1] for k, v in sn_span.items()}, 1)}",
        f"CREATE OR REPLACE MACRO fm_start(g) AS {_case('g', {k: v[0] for k, v in fm_span.items()}, 0)}",
        f"CREATE OR REPLACE MACRO fm_count(g) AS {_case('g', {k: v[1] for k, v in fm_span.items()}, 1)}",
        f"CREATE OR REPLACE MACRO ff_start(g) AS {_case('g', {k: v[0] for k, v in ff_span.items()}, 0)}",
        f"CREATE OR REPLACE MACRO ff_count(g) AS {_case('g', {k: v[1] for k, v in ff_span.items()}, 1)}",
        f"CREATE OR REPLACE MACRO tail_share(g) AS {_case('g', tail, 0.0)}",
        f"CREATE OR REPLACE MACRO syl_p() AS {_sql_list(N.SYLL_PREFIX)}",
        f"CREATE OR REPLACE MACRO syl_m() AS {_sql_list(N.SYLL_MID)}",
        f"CREATE OR REPLACE MACRO syl_s() AS {_sql_list(N.SYLL_SUFFIX)}",
        f"CREATE OR REPLACE MACRO en_p() AS {_sql_list(N.EN_PREFIX)}",
        f"CREATE OR REPLACE MACRO en_s() AS {_sql_list(N.EN_SUFFIX)}",
        f"CREATE OR REPLACE MACRO af_p() AS {_sql_list(N.AF_PREFIX)}",
        f"CREATE OR REPLACE MACRO af_r() AS {_sql_list(N.AF_ROOT)}",
        f"CREATE OR REPLACE MACRO streets() AS {_sql_list(N.STREETS)}",
        f"CREATE OR REPLACE MACRO suburbs() AS {_sql_list(N.SUBURBS)}",
        f"CREATE OR REPLACE MACRO domains() AS {_sql_list(N.EMAIL_DOMAINS)}",
        f"CREATE OR REPLACE MACRO icd_codes() AS {_sql_list(N.ICD10)}",
        f"CREATE OR REPLACE MACRO notes() AS {_sql_list(N.NOTES)}",
        f"CREATE OR REPLACE MACRO test_codes() AS {_sql_list(N.TEST_CODES)}",
        f"CREATE OR REPLACE MACRO res_status() AS {_sql_list(N.RESULT_STATUS)}",
        f"CREATE OR REPLACE MACRO wards() AS {_sql_list(N.WARDS)}",
        # pick from a list by a hash
        "CREATE OR REPLACE MACRO pick(lst, k, tag) AS lst[1 + rint(k, tag, len(lst))]",
        # common surname (Zipf-like) or generated long-tail surname
        """CREATE OR REPLACE MACRO surname_of(g, k, tag) AS CASE
             WHEN rnd(k, tag || 't') < tail_share(g) THEN
               CASE WHEN g = 'en' THEN pick(en_p(), k, tag || 'a') || lower(pick(en_s(), k, tag || 'b'))
                    WHEN g = 'af' THEN pick(af_p(), k, tag || 'a') || ' ' || pick(af_r(), k, tag || 'b')
                    ELSE pick(syl_p(), k, tag || 'a')
                         || CASE WHEN rnd(k, tag || 'm') < 0.5 THEN pick(syl_m(), k, tag || 'c') ELSE '' END
                         || pick(syl_s(), k, tag || 'b') END
             ELSE sn_all()[1 + sn_start(g) + floor(pow(rnd(k, tag), 2.0) * sn_count(g))::INT] END""",
        """CREATE OR REPLACE MACRO first_of(g, female, k, tag) AS CASE
             WHEN rnd(k, tag || 'x') < 0.12 THEN
               CASE WHEN female THEN ff_all()[1 + ff_start('en') + floor(pow(rnd(k, tag), 1.6) * ff_count('en'))::INT]
                    ELSE fm_all()[1 + fm_start('en') + floor(pow(rnd(k, tag), 1.6) * fm_count('en'))::INT] END
             WHEN female THEN ff_all()[1 + ff_start(g) + floor(pow(rnd(k, tag), 1.6) * ff_count(g))::INT]
             ELSE fm_all()[1 + fm_start(g) + floor(pow(rnd(k, tag), 1.6) * fm_count(g))::INT] END""",
        """CREATE OR REPLACE MACRO luhn_digit(b) AS ((10 - (list_sum(list_transform(range(length(b)), i ->
             CASE WHEN (length(b) - 1 - i) % 2 = 0 THEN
               (CASE WHEN substr(b, i + 1, 1)::INT * 2 > 9 THEN substr(b, i + 1, 1)::INT * 2 - 9
                     ELSE substr(b, i + 1, 1)::INT * 2 END)
             ELSE substr(b, i + 1, 1)::INT END)) % 10)) % 10)::VARCHAR""",
        # one keyboard-style typo: substitution, deletion, insertion or transposition (first letter kept 90%)
        """CREATE OR REPLACE MACRO typo(s, k, tag) AS CASE WHEN s IS NULL OR length(s) < 3 THEN s ELSE (
             WITH_POS(s, CASE WHEN rnd(k, tag || 'f') < 0.1 THEN 1
                              ELSE 2 + rint(k, tag || 'p', length(s) - 1)::INT END,
                      chr(65 + rint(k, tag || 'l', 26)::INT), rint(k, tag || 'k', 4)::INT)) END""",
        """CREATE OR REPLACE MACRO WITH_POS(s, p, c, kind) AS CASE kind
             WHEN 0 THEN left(s, p - 1) || c || substr(s, p + 1)
             WHEN 1 THEN left(s, p - 1) || substr(s, p + 1)
             WHEN 2 THEN left(s, p - 1) || c || substr(s, p)
             ELSE CASE WHEN p < length(s) THEN left(s, p - 1) || substr(s, p + 1, 1) || substr(s, p, 1) || substr(s, p + 2)
                       ELSE left(s, p - 2) || substr(s, p, 1) || substr(s, p - 1, 1) END END""",
        """CREATE OR REPLACE MACRO mobile(k, tag) AS '0' || (6 + rint(k, tag || 'n', 3))::VARCHAR
             || (1 + rint(k, tag || 'o', 9))::VARCHAR || lpad(rint(k, tag || 'd', 10000000)::VARCHAR, 7, '0')""",
        """CREATE OR REPLACE MACRO fmt_phone(d, v) AS CASE WHEN d IS NULL THEN NULL ELSE CASE v
             WHEN 0 THEN d
             WHEN 1 THEN substr(d, 1, 3) || ' ' || substr(d, 4, 3) || ' ' || substr(d, 7, 4)
             WHEN 2 THEN '+27' || substr(d, 2)
             WHEN 3 THEN '+27 ' || substr(d, 2, 2) || ' ' || substr(d, 4, 3) || ' ' || substr(d, 7, 4)
             WHEN 4 THEN '27' || substr(d, 2)
             ELSE '(' || substr(d, 1, 3) || ') ' || substr(d, 4, 3) || '-' || substr(d, 7, 4) END END""",
        """CREATE OR REPLACE MACRO title_case(s) AS CASE WHEN s IS NULL THEN NULL ELSE array_to_string(list_transform(
             string_split(s, ' '), w -> CASE WHEN w IN ('van', 'der', 'du', 'de', 'le', 'den', 'janse') THEN w
                                         ELSE upper(left(w, 1)) || lower(substr(w, 2)) END), ' ') END""",
        """CREATE OR REPLACE MACRO fmt_case(s, mode, k) AS CASE
             WHEN s IS NULL THEN NULL
             WHEN mode = 'upper' THEN upper(s)
             WHEN mode = 'title' THEN title_case(s)
             WHEN rnd(k, 'case') < 0.5 THEN upper(s) ELSE title_case(s) END""",
    ]
    for s in stmts:
        con.execute(s)


def _persons_sql(lo: int, hi: int, ref: dt.date) -> str:
    """Person attributes for pids in [lo, hi) as pure functions of (pid, household)."""
    r = f"DATE '{ref.isoformat()}'"
    return f"""
    WITH b AS (SELECT pid, pid // 4 AS hh, (pid % 4)::INT AS slot FROM range({lo}, {hi}) t(pid)),
    h AS (
      SELECT *, grp_pick(rnd(hh, 'grp')) AS hgrp,
        rnd(hh, 'couple') < 0.55 AS couple, rnd(hh, 'c2') < 0.62 AS has_c2, rnd(hh, 'c3') < 0.45 AS has_c3,
        rnd(hh, 'tw') < 0.09 AS twin3, 22 + floor(pow(rnd(hh, 'hage'), 1.15) * 63)::INT AS head_age,
        rnd(hh, 'hsex') < 0.5 AS head_female
      FROM b),
    ro AS (
      SELECT *, CASE WHEN slot = 0 THEN 'head'
                     WHEN slot = 1 AND couple THEN 'spouse'
                     WHEN slot = 2 AND has_c2 THEN 'child'
                     WHEN slot = 3 AND has_c3 AND twin3 AND has_c2 THEN 'twin'
                     WHEN slot = 3 AND has_c3 THEN 'child'
                     ELSE 'single' END AS role
      FROM h),
    p AS (
      SELECT *,
        CASE WHEN role = 'single' THEN grp_pick(rnd(pid, 'grp')) ELSE hgrp END AS grp,
        CASE role WHEN 'head' THEN head_female WHEN 'spouse' THEN NOT head_female ELSE rnd(pid, 'sex') < 0.5 END
          AS female,
        CASE role
          WHEN 'head' THEN head_age * 365 + rint(hh, 'hday', 365)::INT
          WHEN 'spouse' THEN greatest(18, head_age + rint(hh, 'sage', 13)::INT - 6) * 365 + rint(pid, 'day', 365)::INT
          WHEN 'child' THEN floor(rnd(pid, 'cage') * least(25, head_age - 17) * 365.25)::INT
          WHEN 'twin' THEN floor(rnd(hh * 4 + 2, 'cage') * least(25, head_age - 17) * 365.25)::INT
          ELSE (18 + floor(pow(rnd(pid, 'age1'), 1.2) * 72)::INT) * 365 + rint(pid, 'day', 365)::INT END AS age_days
      FROM ro),
    q AS (
      SELECT *, ({r} - age_days)::DATE AS dob,
        CASE WHEN role = 'single' THEN pid ELSE hh * 4 END AS fam_key,
        grp = 'fo' AS foreign_national,
        CASE WHEN grp = 'fo' THEN NULL WHEN rnd(pid, 'pr') < 0.02 THEN 1 ELSE 0 END AS cit
      FROM p)
    SELECT * FROM q
    """


def _id_sql(dob: str, seq: str, cit: str) -> str:
    base = f"strftime({dob}, '%y%m%d') || lpad(({seq})::VARCHAR, 4, '0') || ({cit})::VARCHAR || '8'"
    return f"({base} || luhn_digit({base}))"


# Every synthetic identifier string that must never appear outside the notification pack (one column per
# kind, strings only, so a leak scan can read every string column). Values are listed both as stored and in
# normalised form (E.164 phones, plain 13-digit IDs).
IDENTIFIERS_SQL = """
SELECT id_out AS sa_id,
       CASE WHEN id_out IS NULL THEN NULL ELSE substr(id_out, 1, 6) || ' ' || substr(id_out, 7, 4) || ' '
            || substr(id_out, 11, 3) END AS sa_id_grouped,
       passport_out AS passport_no,
       phone_digits AS phone,
       CASE WHEN phone_digits IS NULL THEN NULL ELSE '+27' || substr(phone_digits, 2) END AS phone_e164,
       email_out AS email,
       med_out AS medical_aid_no,
       CASE WHEN first_out IS NULL OR last_out IS NULL OR unres THEN NULL
            ELSE upper(first_out || ' ' || last_out) END AS full_name,
       CASE WHEN with_guardian THEN upper(g_first || ' ' || g_surname) END AS guardian_name,
       CASE WHEN with_guardian THEN g_phone END AS guardian_phone,
       CASE WHEN with_guardian AND g_phone IS NOT NULL THEN '+27' || substr(g_phone, 2) END AS guardian_phone_e164,
       CASE WHEN with_guardian THEN g_sa_id END AS guardian_sa_id,
       CAST(NULL AS VARCHAR) AS card_number,
       CAST(NULL AS VARCHAR) AS bank_account
FROM regs_cut
UNION ALL
SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       CASE WHEN card0 IS NULL THEN NULL ELSE card0 || luhn_digit(card0) END, bank_account
FROM bil WHERE card0 IS NOT NULL OR bank_account IS NOT NULL
"""


class Generator:
    def __init__(self, out_dir: Path | str, rows: int, *, seed: int = DEFAULT_SEED, databases: int = 10,
                 reference_date: dt.date = DEFAULT_REFERENCE_DATE, leak_rows: int = 300,
                 chunk_persons: int = 400_000, threads: int | None = None, progress=None,
                 styles: list[dict] | None = None):
        if rows < 100:
            raise ValueError("rows must be at least 100")
        if not 1 <= databases <= 99:
            raise ValueError("databases must be 1..99")
        self.out = Path(out_dir)
        self.rows = int(rows)
        self.seed = int(seed)
        self.n_dbs = int(databases)
        self.ref = reference_date
        self.leak_rows = int(leak_rows)
        self.chunk = max(4, (int(chunk_persons) // 4) * 4)
        self.progress = progress or (lambda msg: None)
        self.threads = threads
        self.leak_db = LEAK_DB if self.n_dbs >= LEAK_DB else 1
        self.custom_styles = list(styles or [])

    def _style(self, d: int) -> tuple[str, dict]:
        """(key-format letter, column layout) for database ``d``; custom layouts (drills) cycle over databases."""
        if self.custom_styles:
            st = self.custom_styles[(d - 1) % len(self.custom_styles)]
            return st.get("key_style", "A"), st
        return style_of(d), STYLES[style_of(d)]

    # ---------------------------------------------------------------------------------------------- run
    def run(self) -> dict:
        t0 = time.time()
        if self.out.exists() and any(self.out.iterdir()):
            raise FileExistsError("output directory exists and is not empty")
        (self.out / "sources").mkdir(parents=True, exist_ok=True)
        con = duck.connect(threads=self.threads, lock=False)
        _macros(con, self.seed, self.n_dbs)
        p_max = max(400, int(math.ceil(self.rows / (MEAN_REGS * MEAN_ADMISSIONS) * 1.3)))
        p_max = ((p_max + 3) // 4) * 4
        self._sequences(con, p_max)
        writers: dict[tuple[int, str], pq.ParquetWriter] = {}
        gt_writer = None
        id_writer = None
        counters = {(d, t): 0 for d in range(1, self.n_dbs + 1) for t in TABLES}
        seqs = {(d, t): 0 for d in range(1, self.n_dbs + 1) for t in ("admissions", "billing", "results")}
        stats = {"persons": 0, "registrations": 0, "unresolvable_registrations": 0, "orphan_admissions": 0,
                 "minors": 0, "minors_with_guardian": 0, "adults_without_contact": 0, "twins": 0}
        orphans_by_db: dict[int, int] = {}
        leak_rows: list[dict] = []
        produced = 0
        lo = 0
        try:
            while produced < self.rows:
                if lo >= p_max:
                    raise RuntimeError("synthetic population exhausted before reaching the row target")
                hi = min(lo + self.chunk, p_max)
                produced = self._chunk(con, lo, hi, produced, writers, counters, seqs, stats, orphans_by_db, leak_rows)
                gt = con.execute("SELECT * FROM gt ORDER BY source_db, local_patient_key").fetch_arrow_table()
                if gt_writer is None:
                    gt_writer = pq.ParquetWriter(self.out / "ground_truth.parquet", gt.schema, compression="zstd")
                gt_writer.write_table(gt)
                ids = con.execute(IDENTIFIERS_SQL).fetch_arrow_table()
                if id_writer is None:
                    id_writer = pq.ParquetWriter(self.out / "ground_truth_identifiers.parquet", ids.schema,
                                                 compression="zstd")
                id_writer.write_table(ids)
                self.progress(f"synth: persons {hi:,}/{p_max:,} admissions {produced:,}/{self.rows:,}")
                lo = hi
        finally:
            for w in writers.values():
                w.close()
            if id_writer is not None:
                id_writer.close()
        leak = self._write_leak(leak_rows)
        if gt_writer is None:
            raise RuntimeError("no data generated")
        gt_writer.write_table(leak)
        gt_writer.close()
        con.close()
        meta = self._meta(counters, stats, orphans_by_db, len(leak), time.time() - t0)
        (self.out / "synth_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        return meta

    # ---------------------------------------------------------------------------------------------- steps
    def _sequences(self, con, p_max: int) -> None:
        """SA ID sequence numbers, unique per (date of birth, sex) over the whole population."""
        con.execute(f"""
        CREATE OR REPLACE TABLE seqs AS
        SELECT pid, (row_number() OVER (PARTITION BY dob, female ORDER BY pid) - 1
                     + CASE WHEN female THEN 0 ELSE 5000 END)::INT AS seq
        FROM ({_persons_sql(0, p_max, self.ref)}) WHERE NOT foreign_national""")
        worst = con.execute("SELECT max(seq % 5000) FROM seqs").fetchone()[0] or 0
        if worst >= 4999:
            raise RuntimeError("SA ID sequence space exhausted for one date of birth")

    def _chunk(self, con, lo, hi, produced, writers, counters, seqs, stats, orphans_by_db, leak_rows) -> int:
        ref = f"DATE '{self.ref.isoformat()}'"
        end = f"({ref} + 20)"
        # ---------------------------------------------------------------- persons with full attributes
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE per AS
        SELECT q.*, s.seq,
          CASE WHEN s.seq IS NULL THEN NULL ELSE {_id_sql('q.dob', 's.seq', 'q.cit')} END AS sa_id,
          CASE WHEN q.foreign_national THEN chr(65 + rint(q.pid, 'pp1', 26)::INT) || chr(65 + rint(q.pid, 'pp2', 26)::INT)
               || lpad(rint(q.pid, 'ppn', 10000000)::VARCHAR, 7, '0') END AS passport,
          first_of(q.grp, q.female, q.pid, 'fn') AS first0,
          surname_of(q.grp, q.fam_key, 'sn') AS surname,
          CASE WHEN q.couple AND q.role IN ('head', 'spouse') AND q.female AND rnd(q.pid, 'hasmaiden') < 0.85
               THEN surname_of(q.grp, q.pid, 'maiden') END AS maiden,
          CASE WHEN rnd(q.pid, 'hasmid') < 0.45 THEN first_of(q.grp, q.female, q.pid, 'mid') END AS middle0,
          q.age_days < 6574 AS minor_now,
          CASE WHEN q.role IN ('head', 'single') THEN CASE WHEN rnd(q.pid, 'hasph') < 0.92 THEN mobile(q.pid, 'ph') END
               WHEN q.role = 'spouse' THEN CASE WHEN rnd(q.pid, 'ownph') < 0.7 THEN mobile(q.pid, 'ph') ELSE 'HH' END
               WHEN q.age_days >= 14 * 365 AND rnd(q.pid, 'teenph') < 0.5 THEN mobile(q.pid, 'ph')
               ELSE 'HH' END AS phone0,
          (q.age_days >= 18 * 365 AND rnd(q.pid, 'hasem') < 0.38) AS has_email,
          CASE WHEN rnd(q.fam_key, 'hasaddr') < 0.88 THEN
               (1 + rint(q.fam_key, 'stno', 400))::VARCHAR || ' ' || pick(streets(), q.fam_key, 'st') || ', '
               || pick(suburbs(), q.fam_key, 'sub') END AS address,
          lpad((1 + rint(q.fam_key, 'pc', 9998))::VARCHAR, 4, '0') AS postal,
          CASE WHEN rnd(q.fam_key, 'hasma') < 0.28 THEN lpad(rint(q.fam_key, 'ma', 1000000000)::VARCHAR, 9, '0')
               || CASE q.slot WHEN 0 THEN '00' WHEN 1 THEN '01' WHEN 2 THEN '02' ELSE '03' END END AS med_aid,
          lang_of(q.grp) AS lang
        FROM ({_persons_sql(lo, hi, self.ref)}) q LEFT JOIN seqs s USING (pid)""")
        # twins get a first name different from their sibling's; households resolve shared phones and guardians
        con.execute("""
        CREATE OR REPLACE TEMP TABLE per2 AS
        SELECT p.*,
          CASE WHEN p.role = 'twin' AND p.first0 = sib.first0 THEN first_of(p.grp, p.female, p.pid, 'fn2')
               ELSE p.first0 END AS first_name,
          CASE WHEN p.phone0 = 'HH' THEN head.phone0 ELSE p.phone0 END AS phone,
          CASE WHEN p.role IN ('child', 'twin') AND p.minor_now THEN
               CASE WHEN p.couple AND spouse.female THEN spouse.pid ELSE head.pid END END AS guardian_pid
        FROM per p
        LEFT JOIN per head ON head.pid = p.hh * 4
        LEFT JOIN per spouse ON spouse.pid = p.hh * 4 + 1 AND p.couple
        LEFT JOIN per sib ON sib.pid = p.hh * 4 + 2""")
        con.execute("""
        CREATE OR REPLACE TEMP TABLE people AS
        SELECT p.*, CASE WHEN p.middle0 = p.first_name THEN NULL ELSE p.middle0 END AS middle,
          g.first_name AS g_first, g.surname AS g_surname, g.phone AS g_phone, g.sa_id AS g_sa_id,
          CASE WHEN p.has_email THEN lower(replace(p.first_name, ' ', '')) ||
               CASE WHEN rnd(p.pid, 'emf') < 0.5 THEN '.' || lower(replace(p.surname, ' ', ''))
                    ELSE lower(replace(p.surname, ' ', '')) || rint(p.pid, 'emn', 100)::VARCHAR END
               || '@' || pick(domains(), p.pid, 'dom') END AS email
        FROM per2 p LEFT JOIN per2 g ON g.pid = p.guardian_pid""")
        stats["twins"] += con.execute("SELECT count(*) FROM people WHERE role = 'twin'").fetchone()[0]
        # ---------------------------------------------------------------- registrations
        styles_case = _case("db", {str(d): f"'{self._style(d)[1]['case']}'" for d in range(1, self.n_dbs + 1)},
                            "'upper'").replace("CASE db WHEN '", "CASE db::VARCHAR WHEN '")
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE regs0 AS
        WITH k AS (
          SELECT p.*, CASE WHEN x < 0.56 THEN 1 WHEN x < 0.81 THEN 2 WHEN x < 0.92 THEN 3 WHEN x < 0.97 THEN 4
                           WHEN x < 0.99 THEN 5 ELSE 6 + rint(pid, 'k2', 2)::INT END AS k
          FROM (SELECT *, rnd(pid, 'k') AS x FROM people) p),
        e AS (SELECT k.*, unnest(range(k.k)) AS j FROM k)
        SELECT e.*, pid * 8 + j AS rk,
          CASE WHEN j > 0 AND rnd(pid * 8 + j, 'dupdb') < 0.08 THEN db_pick(rnd(pid * 8, 'db'))
               ELSE db_pick(rnd(pid * 8 + j, 'db')) END AS db,
          ((pid * 8 + j)::HUGEINT * 2654435761 % 4294967311)::BIGINT AS key_num,
          (greatest(dob, DATE '2006-01-01') + rint(pid * 8 + j, 'regd',
              greatest(1, ({end} - greatest(dob, DATE '2006-01-01'))::INT))::INT)::DATE AS reg_date,
          rnd(pid * 8 + j, 'unres') < 0.004 AS unres
        FROM e""")
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE regs1 AS
        SELECT r.*, {styles_case} AS case_mode,
          -- identifiers
          CASE WHEN unres OR sa_id IS NULL THEN NULL
               WHEN rnd(rk, 'idmiss') < CASE WHEN minor_now THEN 0.55 ELSE 0.10 END THEN NULL
               WHEN rnd(rk, 'idtypo') < 0.01 THEN
                    left(sa_id, (rint(rk, 'idp', 13))::INT) ||
                    ((substr(sa_id, (rint(rk, 'idp', 13) + 1)::INT, 1)::INT + 1 + rint(rk, 'idd', 9)::INT) % 10)::VARCHAR
                    || substr(sa_id, (rint(rk, 'idp', 13) + 2)::INT)
               ELSE sa_id END AS id_out,
          CASE WHEN unres OR passport IS NULL OR rnd(rk, 'ppmiss') < 0.15 THEN NULL ELSE passport END AS passport_out,
          -- names
          CASE WHEN unres THEN CASE WHEN rnd(rk, 'unf') < 0.5 THEN NULL ELSE 'Unknown' END
               WHEN rnd(rk, 'fntypo') < 0.035 THEN typo(upper(first_name), rk, 'fnt') ELSE first_name END AS f1,
          CASE WHEN unres THEN NULL WHEN middle IS NULL OR rnd(rk, 'middrop') < 0.5 THEN NULL ELSE middle END AS m1,
          CASE WHEN unres THEN 'UNKNOWN'
               WHEN maiden IS NOT NULL AND rnd(rk, 'usemaiden') < 0.25 THEN maiden
               WHEN rnd(rk, 'sntypo') < 0.035 THEN typo(upper(surname), rk, 'snt') ELSE surname END AS l1,
          CASE WHEN unres OR maiden IS NULL OR rnd(rk, 'mdn') < 0.5 THEN NULL
               ELSE CASE WHEN rnd(rk, 'usemaiden') < 0.25 THEN surname ELSE maiden END END AS maiden_out,
          NOT unres AND rnd(rk, 'swap') < 0.02 AS swapped,
          -- dates
          CASE WHEN unres OR rnd(rk, 'dobmiss') < 0.025 THEN NULL
               WHEN rnd(rk, 'dobtypo') < 0.02 THEN CASE rint(rk, 'dtk', 4)
                    WHEN 0 THEN CASE WHEN day(dob) <= 12 AND day(dob) <> month(dob)
                                     THEN make_date(year(dob), day(dob), month(dob)) ELSE (dob + 1)::DATE END
                    WHEN 1 THEN (dob + 1)::DATE
                    WHEN 2 THEN coalesce(try_cast(strftime(dob, '%Y-%m-%d').replace(left(strftime(dob, '%Y-%m-%d'), 4),
                                         (year(dob) + 1)::VARCHAR) AS DATE), (dob - 1)::DATE)
                    ELSE (dob - 1)::DATE END
               ELSE dob END AS dob_out,
          CASE WHEN rnd(rk, 'sexmiss') < 0.02 THEN NULL WHEN female THEN 'F' ELSE 'M' END AS sex_out,
          -- contact
          CASE WHEN phone IS NULL OR (unres AND rnd(rk, 'unph') < 0.6) OR rnd(rk, 'phmiss') < 0.12 THEN NULL
               WHEN rnd(rk, 'phold') < 0.07 THEN mobile(rk, 'oldph') ELSE phone END AS phone_digits,
          rint(rk, 'phfmt', 6)::INT AS phone_fmt,
          CASE WHEN unres OR email IS NULL OR rnd(rk, 'emmiss') < 0.35 THEN NULL ELSE email END AS email_out,
          CASE WHEN unres OR address IS NULL OR rnd(rk, 'admiss') < 0.15 THEN NULL ELSE address END AS address_out,
          CASE WHEN unres OR address IS NULL OR rnd(rk, 'pcmiss') < 0.15 THEN NULL ELSE postal END AS postal_out,
          CASE WHEN unres OR med_aid IS NULL OR rnd(rk, 'mamiss') < 0.2 THEN NULL ELSE med_aid END AS med_out,
          CASE WHEN rnd(rk, 'langmiss') < 0.3 THEN NULL ELSE lang END AS lang_out,
          guardian_pid IS NOT NULL AND NOT unres AND rnd(rk, 'gmiss') < 0.8 AS with_guardian
        FROM regs0 r""")
        con.execute("""
        CREATE OR REPLACE TEMP TABLE regs AS
        SELECT r.*,
          CASE WHEN swapped THEN l1 ELSE f1 END AS first_out,
          CASE WHEN swapped THEN f1 ELSE l1 END AS last_out,
          (CASE WHEN l1 IS NOT NULL AND NOT unres THEN 1 ELSE 0 END + CASE WHEN dob_out IS NOT NULL THEN 1 ELSE 0 END
           + CASE WHEN id_out = sa_id THEN 1 ELSE 0 END + CASE WHEN passport_out IS NOT NULL THEN 1 ELSE 0 END) >= 2
            AS usable,
          (phone_digits IS NOT NULL OR email_out IS NOT NULL OR (address_out IS NOT NULL AND postal_out IS NOT NULL))
            AS own_contact,
          (with_guardian AND g_phone IS NOT NULL) AS guardian_contact,
          rint(rk, 'adm', 1000000)::DOUBLE AS _u
        FROM regs1 r""")
        # admissions per registration (geometric-like, mean about 4) and the exact row target
        con.execute("""
        CREATE OR REPLACE TEMP TABLE regs_a AS
        SELECT *, (sum(n_adm) OVER (ORDER BY pid, j ROWS UNBOUNDED PRECEDING))::BIGINT AS cum
        FROM (SELECT *, least(60, 1 + floor(-ln(1 - rnd(rk, 'nadm') * 0.999999) * 3.5))::INT AS n_adm FROM regs)""")
        remaining = self.rows - produced
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE regs_cut AS
        SELECT * REPLACE ((CASE WHEN cum > {remaining} THEN n_adm - (cum - {remaining}) ELSE n_adm END)::INT AS n_adm)
        FROM regs_a WHERE cum - n_adm < {remaining}""")
        added = con.execute("SELECT coalesce(sum(n_adm), 0) FROM regs_cut").fetchone()[0]
        # person-level ground-truth flags (over the registrations actually emitted)
        con.execute("""
        CREATE OR REPLACE TEMP TABLE pflags AS
        SELECT pid, bool_or(guardian_contact) AS has_guardian, bool_or(own_contact) AS has_contact,
               bool_or(usable) AS any_usable, any_value(minor_now) AS is_minor
        FROM regs_cut GROUP BY pid""")
        s = con.execute("""SELECT count(*), sum(CASE WHEN is_minor THEN 1 ELSE 0 END),
                                  sum(CASE WHEN is_minor AND has_guardian THEN 1 ELSE 0 END),
                                  sum(CASE WHEN NOT is_minor AND NOT has_contact THEN 1 ELSE 0 END) FROM pflags""").fetchone()
        stats["persons"] += s[0]
        stats["minors"] += s[1] or 0
        stats["minors_with_guardian"] += s[2] or 0
        stats["adults_without_contact"] += s[3] or 0
        r = con.execute("SELECT count(*), sum(CASE WHEN NOT usable THEN 1 ELSE 0 END) FROM regs_cut").fetchone()
        stats["registrations"] += r[0]
        stats["unresolvable_registrations"] += r[1] or 0
        # ---------------------------------------------------------------- dependent rows
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE adm AS
        WITH e AS (SELECT r.db, r.pid, r.j, r.rk, r.key_num, r.reg_date, r.med_out, unnest(range(r.n_adm)) AS i
                   FROM regs_cut r)
        SELECT e.*, e.rk * 64 + e.i AS ak,
          CASE WHEN rnd(e.rk * 64 + e.i, 'orphan') < 0.003
               THEN ((e.pid * 8 + 7)::HUGEINT * 2654435761 % 4294967311)::BIGINT ELSE e.key_num END AS ref_num,
          (e.reg_date + rint(e.rk * 64 + e.i, 'ad', greatest(1, ({end} - e.reg_date)::INT))::INT)::DATE AS admit_date
        FROM e""")
        con.execute("""
        CREATE OR REPLACE TEMP TABLE adm2 AS
        SELECT a.*, (a.admit_date + rint(ak, 'los', 12)::INT)::DATE AS discharge_date,
          pick(wards(), ak, 'ward') AS ward, pick(icd_codes(), ak, 'icd') AS icd10,
          CASE WHEN rnd(ak, 'nonote') < 0.15 THEN NULL ELSE pick(notes(), ak, 'note') END AS note,
          ref_num <> key_num AS orphan,
          row_number() OVER (PARTITION BY db ORDER BY pid, j, i) AS dbseq
        FROM adm a""")
        for d, n in con.execute("SELECT db, count(*) FROM adm2 WHERE orphan GROUP BY db").fetchall():
            orphans_by_db[int(d)] = orphans_by_db.get(int(d), 0) + int(n)
            stats["orphan_admissions"] += int(n)
        con.execute("""
        CREATE OR REPLACE TEMP TABLE bil AS
        SELECT a.db, a.pid, a.j, a.i, a.ak, a.ref_num, a.admit_date, a.dbseq AS adm_seq, a.med_out,
          (a.admit_date + rint(a.ak, 'invd', 30)::INT)::DATE AS invoice_date,
          round(100 + rnd(a.ak, 'amt') * 25000, 2) AS amount,
          CASE WHEN rnd(a.ak, 'card') < 0.3 THEN '4000' || lpad(rint(a.ak, 'cn', 100000000000)::VARCHAR, 11, '0') END AS card0,
          CASE WHEN rnd(a.ak, 'bank') < 0.12 THEN (1 + rint(a.ak, 'b1', 9))::VARCHAR
               || lpad(rint(a.ak, 'bn', 1000000000)::VARCHAR, 9, '0') END AS bank_account,
          row_number() OVER (PARTITION BY a.db ORDER BY a.pid, a.j, a.i) AS dbseq
        FROM adm2 a WHERE rnd(a.ak, 'bill') < 0.5""")
        con.execute("""
        CREATE OR REPLACE TEMP TABLE res AS
        WITH e AS (SELECT a.db, a.pid, a.j, a.i, a.ak, a.ref_num, a.admit_date, a.dbseq AS adm_seq,
                          unnest(range(CASE WHEN rnd(a.ak, 'nres') < 0.25 THEN 0 WHEN rnd(a.ak, 'nres') < 0.65 THEN 1
                                            WHEN rnd(a.ak, 'nres') < 0.88 THEN 2 ELSE 3 END)) AS t
                   FROM adm2 a)
        SELECT e.*, (e.admit_date + rint(e.ak * 4 + e.t, 'cd', 3)::INT)::DATE AS collected,
          pick(test_codes(), e.ak * 4 + e.t, 'tc') AS test_code, pick(res_status(), e.ak * 4 + e.t, 'rs') AS status,
          row_number() OVER (PARTITION BY e.db ORDER BY e.pid, e.j, e.i, e.t) AS dbseq
        FROM e""")
        # ---------------------------------------------------------------- write per database
        for d in range(1, self.n_dbs + 1):
            st = self._style(d)[1]
            for table in TABLES:
                sql = self._select_sql(d, table, st, seqs)
                reader = con.execute(sql).fetch_record_batch(200_000)
                w = writers.get((d, table))
                for batch in reader:
                    if batch.num_rows == 0:
                        continue
                    if w is None:
                        (self.out / "sources" / db_name(d)).mkdir(parents=True, exist_ok=True)
                        w = pq.ParquetWriter(self.out / "sources" / db_name(d) / f"{table}.parquet", batch.schema,
                                             compression="zstd")
                        writers[(d, table)] = w
                    w.write_batch(batch)
                    counters[(d, table)] += batch.num_rows
            for t, tbl in (("admissions", "adm2"), ("billing", "bil"), ("results", "res")):
                seqs[(d, t)] += con.execute(f"SELECT count(*) FROM {tbl} WHERE db = {d}").fetchone()[0]
        # ---------------------------------------------------------------- ground truth and leak candidates
        key_expr = self._key_case("r.db", "r.key_num")
        con.execute(f"""
        CREATE OR REPLACE TEMP TABLE gt AS
        SELECT 'db' || lpad(r.db::VARCHAR, 2, '0') AS source_db, 'patients' AS "table",
               {key_expr} AS local_patient_key, r.pid AS person_id, f.is_minor, f.has_guardian, f.has_contact,
               r.usable
        FROM regs_cut r JOIN pflags f USING (pid)""")
        want = self.leak_rows - len(leak_rows)
        if want > 0:
            cands = con.execute(f"""
            SELECT r.pid, r.first_out, r.m1, r.last_out, r.id_out, r.dob_out, r.phone_digits, r.rk
            FROM regs_cut r WHERE r.db = {self.leak_db} AND r.usable AND r.id_out IS NOT NULL
              AND rnd(r.rk, 'leak') < 0.25
            ORDER BY hash(r.rk, 'leakorder') LIMIT {want}""").fetchall()
            for c in cands:
                leak_rows.append({"pid": c[0], "first": c[1], "middle": c[2], "last": c[3], "id": c[4], "dob": c[5],
                                  "phone": c[6]})
        return produced + int(added)

    def _key_case(self, db_col: str, num_col: str) -> str:
        parts = []
        for d in range(1, self.n_dbs + 1):
            parts.append(f"WHEN {d} THEN {self._key_fmt(self._style(d)[0], num_col)}")
        return f"CASE {db_col} {' '.join(parts)} END"

    @staticmethod
    def _key_fmt(style: str, num: str) -> str:
        return {
            "A": f"'MRN' || lpad(({num})::VARCHAR, 10, '0')",
            "B": f"({num})::VARCHAR",
            "C": f"'C' || ({num})::VARCHAR",
            "D": f"'PK-' || ({num})::VARCHAR",
            "E": f"lpad(({num})::VARCHAR, 11, '0')",
        }[style]

    @staticmethod
    def _key_value(style: str, num: str) -> str:
        if style == "B":
            return f"({num})::BIGINT"
        return Generator._key_fmt(style, num)

    def _select_sql(self, d: int, table: str, st: dict, seqs) -> str:
        cols = st[table]
        style = self._style(d)[0]
        if table == "patients":
            return self._patients_sql(d, st, style)
        off = seqs[(d, table)]
        key = lambda n: self._key_value(style, n)  # noqa: E731
        out = []
        if table == "admissions":
            exprs = {"key": f"(dbseq + {off})::BIGINT", "patient_ref": key("ref_num"),
                     "record_date": "admit_date", "discharge": "discharge_date", "ward": "ward",
                     "icd10": "icd10", "note": "note"}
            src = "adm2"
        elif table == "billing":
            aoff = seqs[(d, "admissions")]
            exprs = {"key": f"(dbseq + {off})::BIGINT", "patient_ref": key("ref_num"),
                     "admission_ref": f"(adm_seq + {aoff})::BIGINT", "record_date": "invoice_date",
                     "amount": "amount", "medical_aid_no": "med_out",
                     "card_number": "CASE WHEN card0 IS NULL THEN NULL ELSE card0 || luhn_digit(card0) END",
                     "bank_account": "bank_account"}
            src = "bil"
        else:
            aoff = seqs[(d, "admissions")]
            exprs = {"key": f"(dbseq + {off})::BIGINT", "admission_ref": f"(adm_seq + {aoff})::BIGINT",
                     "patient_ref": key("ref_num"), "record_date": "collected", "test_code": "test_code",
                     "status": "status"}
            src = "res"
        for field, col in cols.items():
            out.append(f'{exprs[field]} AS "{col}"')
        return f"SELECT {', '.join(out)} FROM {src} WHERE db = {d} ORDER BY dbseq"

    def _patients_sql(self, d: int, st: dict, style: str) -> str:
        cols = st["patients"]
        cm = "case_mode"
        first = f"fmt_case(first_out, {cm}, rk)"
        middle = f"fmt_case(m1, {cm}, rk)"
        last = f"fmt_case(last_out, {cm}, rk)"
        if st["dob_format"] == "date":
            dob = "dob_out"
        else:
            dob = f"strftime(dob_out, '{st['dob_format']}')"
        sex = {"MF": "sex_out", "MaleFemale": "CASE sex_out WHEN 'M' THEN 'Male' WHEN 'F' THEN 'Female' END",
               "12": "CASE sex_out WHEN 'M' THEN '1' WHEN 'F' THEN '2' END"}[st["sex_format"]]
        sa = ("CASE WHEN id_out IS NULL THEN NULL ELSE substr(id_out, 1, 6) || ' ' || substr(id_out, 7, 4) || ' ' "
              "|| substr(id_out, 11, 3) END") if st["id_format"] == "grouped" else "id_out"
        g_name = (f"CASE WHEN with_guardian THEN fmt_case(g_first || ' ' || g_surname, {cm}, rk) END")
        exprs = {
            "local_patient_key": self._key_value(style, "key_num"),
            "sa_id": sa,
            "first_name": (f"CASE WHEN m1 IS NULL THEN {first} ELSE {first} || ' ' || {middle} END"
                           if st["name_format"] == "given_names" else first),
            "middle_names": middle,
            "last_name": last,
            "full_name": f"CASE WHEN last_out IS NULL THEN {first} WHEN first_out IS NULL THEN {last} "
                         f"ELSE {last} || ', ' || {first} || coalesce(' ' || {middle}, '') END",
            "maiden_name": f"fmt_case(maiden_out, {cm}, rk)",
            "dob": dob,
            "sex": sex,
            "phone": "fmt_phone(phone_digits, phone_fmt)",
            "phone_alt": "CASE WHEN rnd(rk, 'alt') < 0.1 THEN fmt_phone(mobile(rk, 'altph'), 0) END",
            "email": "email_out",
            "address": "address_out",
            "postal_code": "postal_out",
            "medical_aid_no": "med_out",
            "language": "lang_out",
            "guardian_name": g_name,
            "guardian_phone": "CASE WHEN with_guardian THEN fmt_phone(g_phone, (phone_fmt + 1) % 6) END",
            "guardian_sa_id": "CASE WHEN with_guardian THEN g_sa_id END",
            "passport_no": "passport_out",
            "record_date": "reg_date",
        }
        out = [f'{exprs[field]} AS "{col}"' for field, col in cols.items()]
        return f"SELECT {', '.join(out)} FROM regs_cut WHERE db = {d} ORDER BY key_num"

    def _write_leak(self, rows: list[dict]) -> pa.Table:
        path = self.out / "leak_sample.csv"
        gt = {"source_db": [], "table": [], "local_patient_key": [], "person_id": [], "is_minor": [],
              "has_guardian": [], "has_contact": [], "usable": []}
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Name", "Surname", "ID Number", "Date of Birth", "Cell"])
            for i, r in enumerate(rows, 1):
                name = r["first"] if not r["middle"] else f"{r['first']} {r['middle']}"
                phone = r["phone"]
                phone = f"{phone[:3]} {phone[3:6]} {phone[6:]}" if phone else ""
                w.writerow([(name or "").upper(), (r["last"] or "").upper(), r["id"] or "",
                            r["dob"].isoformat() if r["dob"] else "", phone])
                gt["source_db"].append("leak_sample")
                gt["table"].append("leak_sample")
                gt["local_patient_key"].append(str(i))
                gt["person_id"].append(int(r["pid"]))
                for k in ("is_minor", "has_guardian", "has_contact"):
                    gt[k].append(None)
                gt["usable"].append(True)
        schema = pa.schema([("source_db", pa.string()), ("table", pa.string()), ("local_patient_key", pa.string()),
                            ("person_id", pa.int64()), ("is_minor", pa.bool_()), ("has_guardian", pa.bool_()),
                            ("has_contact", pa.bool_()), ("usable", pa.bool_())])
        return pa.table(gt, schema=schema)

    def _meta(self, counters, stats, orphans_by_db, leak_n, seconds) -> dict:
        import duckdb

        dbs = []
        for d in range(1, self.n_dbs + 1):
            style, st = self._style(d)
            dbs.append({
                "database": db_name(d), "style": style, "path": f"sources/{db_name(d)}",
                "tables": {t: {"rows": counters[(d, t)], "columns": st[t]} for t in TABLES},
                "formats": {k: st[k] for k in ("name_format", "dob_format", "sex_format", "case", "id_format")},
                "orphan_admissions": orphans_by_db.get(d, 0),
            })
        return {
            "schema": "tripline.synth-meta/v1",
            "generator": GENERATOR_VERSION,
            "duckdb": duckdb.__version__,
            "seed": self.seed,
            "rows_requested": self.rows,
            "reference_date": self.ref.isoformat(),
            "databases": dbs,
            "totals": {t: sum(counters[(d, t)] for d in range(1, self.n_dbs + 1)) for t in TABLES},
            "population": stats,
            "leak_sample": {"path": "leak_sample.csv", "rows": leak_n, "drawn_from": db_name(self.leak_db),
                            "columns": {"Name": "full_name", "Surname": "last_name", "ID Number": "sa_id",
                                        "Date of Birth": "dob", "Cell": "phone"},
                            "categories": ["name", "identity_number", "date_of_birth", "contact_details"]},
            "ground_truth": "ground_truth.parquet",
            "ground_truth_identifiers": "ground_truth_identifiers.parquet",
            "generation_seconds": round(seconds, 1),
            "notes": "Synthetic data only. Card numbers are Luhn-valid test numbers with the 4000 test prefix; "
                     "bank account numbers are random; notes are generic phrases with no identifiers.",
        }


def generate(out_dir, rows: int, **kw) -> dict:
    return Generator(out_dir, rows, **kw).run()


def default_threads() -> int:
    return max(1, min(4, os.cpu_count() or 1))
