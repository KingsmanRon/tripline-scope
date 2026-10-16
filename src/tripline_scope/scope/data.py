"""Load extracts into an in-memory DuckDB session and prepare identity records.

Tables built here (all in memory, nothing spills):

``src_tables``  one row per extracted table: t_idx, source_id, slug, database, table, role, evidence_role, rows
``ident``       one row per identity row, normalised: names (placeholders removed, first token, variants),
                surname without spaces, soundex keys, DOB (recorded, else from the SA ID), sex, phone, email, postal
                code, medical-aid number, passport, contact and guardian-contact flags, language, category mask,
                ``usable`` (≥ ``min_identifiers`` of surname / date of birth / valid SA ID / passport)
``dep``         dependent rows aggregated per (t_idx, patient_ref): row count, min/max record date, rows without a
                date, category mask (bit-or of presence flags and fields), resolved to identity rows by
                ``patient_ref = local_patient_key`` within the same source (``links_to`` tables)
``dep_link``    dependent group → identity row_id (only usable identity rows)

Patient identifiers stay inside this process; nothing is printed or logged.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field

import pyarrow as pa

from tripline_scope.core import duck
from tripline_scope.core.errors import NotReady

from .config import EXPOSURE_CATEGORIES, FIELD_CATEGORIES, FLAG_CATEGORIES

log = logging.getLogger(__name__)

IDENTITY_FIELDS = ["sa_id", "passport_no", "first_name", "middle_names", "last_name", "full_name", "maiden_name",
                   "dob", "sex", "medical_aid_no", "local_patient_key", "phone", "phone_alt", "email", "address",
                   "postal_code", "language", "guardian_name", "guardian_phone", "guardian_email", "guardian_sa_id",
                   "record_date"]
CAT_BIT = {c: 1 << i for i, c in enumerate(EXPOSURE_CATEGORIES)}

# Soundex (same algorithm as core.identifiers.soundex): letters → digit classes, H/W dropped before collapsing
# runs (so letters separated by H/W collapse), vowels (0) separate runs and are removed at the end.
SOUNDEX_MACROS = r"""
CREATE OR REPLACE MACRO tsx_collapse(t) AS
  regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(
    t, '0+', '0', 'g'), '1+', '1', 'g'), '2+', '2', 'g'), '3+', '3', 'g'), '4+', '4', 'g'), '5+', '5', 'g'),
    '6+', '6', 'g');
CREATE OR REPLACE MACRO tsx_code(n) AS tsx_collapse(translate(n, 'BFPVCGJKQSXZDTLMNRAEIOUYHW', '111122222222334556000000'));
CREATE OR REPLACE MACRO tscope_soundex(s) AS CASE WHEN s IS NULL OR replace(s, ' ', '') = '' THEN NULL ELSE
  left(rpad(left(replace(s, ' ', ''), 1) || replace(
    CASE WHEN left(replace(s, ' ', ''), 1) IN ('H', 'W') THEN tsx_code(replace(s, ' ', ''))
         ELSE substr(tsx_code(replace(s, ' ', '')), 2) END, '0', ''), 4, '0'), 4) END;
"""


@dataclass
class ScopeData:
    con: object
    tables: list[dict]
    sources: dict[str, dict]
    reference_date: dt.date
    counts: dict = field(default_factory=dict)

    def q(self, sql: str, params=None):
        return self.con.execute(sql, params or [])

    def scalar(self, sql: str, params=None):
        return self.con.execute(sql, params or []).fetchone()[0]


def connect(threads: int | None = None, memory_limit: str | None = None):
    con = duck.connect(lock=False, threads=threads, memory_limit=memory_limit)
    for stmt in SOUNDEX_MACROS.strip().split(";\n"):
        if stmt.strip():
            con.execute(stmt)
    return con


def manifests(case, store) -> dict[str, dict]:
    out = {}
    for s in case.sources():
        sid = s["source_id"]
        rel = f"work/extract/{sid}/manifest.json"
        if store.exists(rel):
            out[sid] = store.read_json(rel)
    return out


def _part_paths(sid: str, entry: dict) -> list[str]:
    parts = entry.get("parts") or []
    if isinstance(parts, int):
        parts = [f"part-{i:05d}.parquet" for i in range(parts)]
    out = []
    for p in parts:
        p = str(p)
        if p.startswith("work/"):
            out.append(p)
        else:
            out.append(f"work/extract/{sid}/{entry['slug']}/{p}")
    return out


def _mask_sql(cols: set[str], flag_cols: set[str]) -> str:
    terms = []
    for f in sorted(cols):
        cat = FIELD_CATEGORIES.get(f)
        if cat:
            terms.append(f"CASE WHEN \"{f}\" IS NOT NULL THEN {CAT_BIT[cat]} ELSE 0 END")
    for fc in sorted(flag_cols):
        cat = FLAG_CATEGORIES.get(fc[len("_has_"):])
        if cat:
            terms.append(f"CASE WHEN coalesce(\"{fc}\", false) THEN {CAT_BIT[cat]} ELSE 0 END")
    if not terms:
        return "0"
    return "(" + " | ".join(terms) + ")::INTEGER"


def load(case, store, cfg: dict, *, threads: int | None = None, memory_limit: str | None = None,
         reference_date: dt.date | None = None, include_dependent: bool = True) -> ScopeData:
    mans = manifests(case, store)
    if not mans:
        raise NotReady("no extracted sources (run ingest first)")
    con = connect(threads=threads, memory_limit=memory_limit)
    ref = reference_date or _incident_end(case)
    src_roles = {s["source_id"]: s.get("evidence_role") for s in case.sources()}
    tables = []
    for sid in sorted(mans):
        for e in mans[sid]["tables"]:
            tables.append({"t_idx": len(tables), "source_id": sid, "slug": e["slug"], "database": e.get("database"),
                           "table": e.get("table"), "role": e.get("role", "other"),
                           "evidence_role": src_roles.get(sid), "row_count": int(e.get("row_count") or 0),
                           "links_to": list(e.get("links_to") or []), "parts": _part_paths(sid, e)})
    con.execute("""CREATE TABLE src_tables(t_idx INTEGER, source_id VARCHAR, slug VARCHAR, database VARCHAR,
                   "table" VARCHAR, role VARCHAR, evidence_role VARCHAR, row_count BIGINT)""")
    con.executemany("INSERT INTO src_tables VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [[t["t_idx"], t["source_id"], t["slug"], t["database"], t["table"], t["role"], t["evidence_role"],
                      t["row_count"]] for t in tables])
    _load_identity(con, store, tables)
    _prepare_identity(con, cfg, ref)
    if include_dependent:
        _load_dependent(con, store, tables)
    else:
        con.execute("CREATE TABLE dep(t_idx INTEGER, patient_ref VARCHAR, n_rows BIGINT, min_date DATE, "
                     "max_date DATE, n_null_date BIGINT, cat_mask INTEGER)")
    _link_dependent(con, tables)
    data = ScopeData(con, tables, {sid: {"manifest": m, "evidence_role": src_roles.get(sid)} for sid, m in mans.items()},
                     ref)
    return data


def _incident_end(case) -> dt.date:
    end = (case.config.get("incident_window") or {}).get("end")
    if end:
        return dt.date.fromisoformat(str(end)[:10])
    raise NotReady("case has no incident window end (needed to determine minors)")


def _load_identity(con, store, tables) -> None:
    cols_sql = ", ".join(f'"{f}" {"DATE" if f in ("dob", "record_date") else "VARCHAR"}' for f in IDENTITY_FIELDS)
    con.execute(f"CREATE TABLE ident_raw(row_key VARCHAR, t_idx INTEGER, ordinal BIGINT, {cols_sql}, cat_own INTEGER)")
    for t in tables:
        if t["role"] != "identity":
            continue
        for rel in t["parts"]:
            if not store.exists(rel):
                raise NotReady(f"extract part missing for {t['source_id']}/{t['slug']}")
            for batch in store.iter_batches(rel, batch_size=262_144):
                tb = pa.Table.from_batches([batch])
                names = set(tb.column_names)
                flags = {c for c in names if c.startswith("_has_")}
                present = {f for f in IDENTITY_FIELDS if f in names}
                sel = []
                for f in IDENTITY_FIELDS:
                    if f in present:
                        sel.append(f'"{f}"::{"DATE" if f in ("dob", "record_date") else "VARCHAR"}')
                    else:
                        sel.append("NULL")
                con.register("_b", tb)
                con.execute(f"""INSERT INTO ident_raw SELECT "_row_key", {t['t_idx']},
                    TRY_CAST(split_part("_row_key", '|', 3) AS BIGINT), {', '.join(sel)},
                    {_mask_sql(present, flags)} FROM _b""")
                con.unregister("_b")


def _prepare_identity(con, cfg: dict, ref: dt.date) -> None:
    ident_cfg = cfg["identity"]
    ph = [p.upper() for p in ident_cfg["name_placeholders"]]
    particles = [p.upper() for p in ident_cfg["surname_particles"]]
    con.execute("CREATE TABLE name_variants(name VARCHAR, canon VARCHAR)")
    rows = []
    for grp in cfg.get("name_variants") or []:
        canon = str(grp[0]).upper()
        for n in grp:
            rows.append([str(n).upper(), canon])
    if rows:
        con.executemany("INSERT INTO name_variants VALUES (?, ?)", rows)
    ph_list = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in ph) + "]"
    part_list = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in particles) + "]"
    min_ids = int(ident_cfg["min_identifiers"])
    ref_s = ref.isoformat()
    con.execute(f"""
    CREATE TEMP TABLE ident1 AS
    WITH a AS (
      SELECT *,
        -- full name "SURNAME, FIRST MIDDLE" or "FIRST MIDDLE SURNAME" when no split names are present
        CASE WHEN first_name IS NULL AND last_name IS NULL AND full_name IS NOT NULL THEN
             CASE WHEN contains(full_name, ',') THEN tscope_name_norm(split_part(full_name, ',', 2))
                  ELSE tscope_name_norm(array_to_string(string_split(trim(full_name), ' ')[1:-2], ' ')) END
             ELSE tscope_name_norm(first_name) END AS fn0,
        CASE WHEN first_name IS NULL AND last_name IS NULL AND full_name IS NOT NULL THEN
             CASE WHEN contains(full_name, ',') THEN tscope_name_norm(split_part(full_name, ',', 1))
                  ELSE tscope_name_norm(string_split(trim(full_name), ' ')[-1]) END
             ELSE tscope_name_norm(last_name) END AS ln0,
        tscope_name_norm(middle_names) AS mn0,
        tscope_name_norm(maiden_name) AS md0
      FROM ident_raw),
    b AS (
      SELECT *,
        CASE WHEN fn0 IS NULL OR list_contains({ph_list}, fn0) THEN NULL ELSE fn0 END AS fn1,
        CASE WHEN ln0 IS NULL OR list_contains({ph_list}, ln0) THEN NULL ELSE ln0 END AS ln1,
        CASE WHEN md0 IS NULL OR list_contains({ph_list}, md0) THEN NULL ELSE md0 END AS md1
      FROM a),
    c AS (
      SELECT *,
        CASE WHEN fn1 IS NULL THEN NULL
             WHEN list_contains({part_list}, string_split(fn1, ' ')[1]) THEN replace(fn1, ' ', '')
             ELSE string_split(fn1, ' ')[1] END AS first_tok,
        CASE WHEN fn1 IS NULL OR list_contains({part_list}, string_split(fn1, ' ')[1]) THEN mn0
             ELSE nullif(trim(array_to_string(string_split(fn1, ' ')[2:], ' ') || ' ' || coalesce(mn0, '')), '') END
          AS middle,
        replace(ln1, ' ', '') AS last,
        replace(md1, ' ', '') AS maiden,
        tscope_sa_id_norm(sa_id) AS sa_id_n,
        nullif(upper(regexp_replace(passport_no, '[^A-Za-z0-9]', '', 'g')), '') AS passport,
        CASE upper(trim(sex)) WHEN 'M' THEN 'M' WHEN 'MALE' THEN 'M' WHEN '1' THEN 'M'
                              WHEN 'F' THEN 'F' WHEN 'FEMALE' THEN 'F' WHEN '2' THEN 'F' END AS sex0,
        tscope_phone_e164(phone) AS phone_n, tscope_phone_e164(phone_alt) AS phone_alt_n,
        tscope_email_norm(email) AS email_n,
        nullif(regexp_replace(postal_code, '[^0-9]', '', 'g'), '') AS postal,
        nullif(upper(regexp_replace(medical_aid_no, '[^A-Za-z0-9]', '', 'g')), '') AS med,
        tscope_phone_e164(guardian_phone) AS g_phone_n, tscope_email_norm(guardian_email) AS g_email_n,
        tscope_sa_id_norm(guardian_sa_id) AS g_sa_id_n,
        nullif(lower(trim(language)), '') AS lang
      FROM b)
    SELECT c.* EXCLUDE (fn0, ln0, mn0, md0, fn1, ln1, md1), coalesce(v.canon, c.first_tok) AS first
    FROM c LEFT JOIN name_variants v ON v.name = c.first_tok""")
    con.execute(f"""
    CREATE TABLE ident AS
    WITH d AS (
      SELECT *,
        CASE WHEN sa_id_n IS NULL THEN NULL ELSE
          CASE WHEN try_strptime('20' || left(sa_id_n, 6), '%Y%m%d')::DATE <= DATE '{ref_s}'
               THEN try_strptime('20' || left(sa_id_n, 6), '%Y%m%d')::DATE
               ELSE try_strptime('19' || left(sa_id_n, 6), '%Y%m%d')::DATE END END AS dob_from_id
      FROM ident1)
    SELECT row_number() OVER (ORDER BY t_idx, ordinal, row_key) AS row_id, row_key, t_idx, ordinal,
      local_patient_key AS local_key, record_date,
      first, middle, last, maiden, sa_id_n AS sa_id, passport, dob,
      coalesce(dob, dob_from_id) AS dob_eff,
      (dob IS NULL OR sa_id_n IS NULL OR strftime(dob, '%y%m%d') = left(sa_id_n, 6)) AS dob_consistent,
      coalesce(sex0, CASE WHEN sa_id_n IS NULL THEN NULL WHEN substr(sa_id_n, 7, 4)::INT < 5000 THEN 'F' ELSE 'M' END)
        AS sex,
      phone_n AS phone, phone_alt_n AS phone_alt, email_n AS email, postal, med, lang,
      tscope_soundex(first) AS sx_first, tscope_soundex(last) AS sx_last, tscope_soundex(maiden) AS sx_maiden,
      (phone_n IS NOT NULL OR phone_alt_n IS NOT NULL OR email_n IS NOT NULL
        OR (address IS NOT NULL AND {"postal_code IS NOT NULL" if cfg["contact"]["address_requires_postal_code"] else "TRUE"}))
        AS own_contact,
      (g_phone_n IS NOT NULL OR g_email_n IS NOT NULL) AS guardian_contact,
      g_sa_id_n AS guardian_sa_id,
      ((CASE WHEN last IS NOT NULL THEN 1 ELSE 0 END) + (CASE WHEN dob IS NOT NULL THEN 1 ELSE 0 END)
       + (CASE WHEN sa_id_n IS NOT NULL THEN 1 ELSE 0 END) + (CASE WHEN passport IS NOT NULL THEN 1 ELSE 0 END))
        >= {min_ids} AS usable,
      cat_own
    FROM d
    ORDER BY row_id""")
    con.execute("DROP TABLE ident1")
    con.execute("DROP TABLE ident_raw")


def _load_dependent(con, store, tables) -> None:
    con.execute("""CREATE TABLE dep_stage(t_idx INTEGER, patient_ref VARCHAR, record_date DATE, cat_mask INTEGER)""")
    con.execute("""CREATE TABLE dep_part(t_idx INTEGER, patient_ref VARCHAR, n_rows BIGINT, min_date DATE,
                   max_date DATE, n_null_date BIGINT, cat_mask INTEGER)""")
    staged = 0

    def compact():
        con.execute("""INSERT INTO dep_part SELECT t_idx, patient_ref, count(*), min(record_date), max(record_date),
                       count(*) FILTER (WHERE record_date IS NULL), bit_or(cat_mask)
                       FROM dep_stage GROUP BY t_idx, patient_ref""")
        con.execute("DELETE FROM dep_stage")

    for t in tables:
        if t["role"] == "identity":
            continue
        for rel in t["parts"]:
            if not store.exists(rel):
                raise NotReady(f"extract part missing for {t['source_id']}/{t['slug']}")
            for batch in store.iter_batches(rel, batch_size=262_144):
                tb = pa.Table.from_batches([batch])
                names = set(tb.column_names)
                flags = {c for c in names if c.startswith("_has_")}
                present = {f for f in FIELD_CATEGORIES if f in names}
                ref = '"patient_ref"::VARCHAR' if "patient_ref" in names else "NULL"
                rd = '"record_date"::DATE' if "record_date" in names else "NULL"
                con.register("_b", tb)
                con.execute(f"INSERT INTO dep_stage SELECT {t['t_idx']}, {ref}, {rd}, {_mask_sql(present, flags)} FROM _b")
                con.unregister("_b")
                staged += tb.num_rows
                if staged >= 8_000_000:
                    compact()
                    staged = 0
    compact()
    con.execute("""CREATE TABLE dep AS SELECT t_idx, patient_ref, sum(n_rows)::BIGINT AS n_rows, min(min_date) AS min_date,
                   max(max_date) AS max_date, sum(n_null_date)::BIGINT AS n_null_date, bit_or(cat_mask) AS cat_mask
                   FROM dep_part GROUP BY t_idx, patient_ref ORDER BY t_idx, patient_ref""")
    con.execute("DROP TABLE dep_stage")
    con.execute("DROP TABLE dep_part")


def _link_dependent(con, tables) -> None:
    """dep group → identity rows of the same source whose local key equals the group's patient_ref."""
    by_slug = {(t["source_id"], t["slug"]): t["t_idx"] for t in tables}
    pairs = []
    for t in tables:
        if t["role"] == "identity":
            continue
        targets = [by_slug[(t["source_id"], s)] for s in t["links_to"] if (t["source_id"], s) in by_slug]
        if not targets:
            targets = [x["t_idx"] for x in tables if x["source_id"] == t["source_id"] and x["role"] == "identity"]
        pairs += [[t["t_idx"], x] for x in targets]
    con.execute("CREATE TABLE dep_targets(dep_t INTEGER, ident_t INTEGER)")
    if pairs:
        con.executemany("INSERT INTO dep_targets VALUES (?, ?)", pairs)
    con.execute("""
    CREATE TABLE dep_link AS
    SELECT d.t_idx, d.patient_ref, i.row_id
    FROM dep d JOIN dep_targets x ON x.dep_t = d.t_idx
    JOIN ident i ON i.t_idx = x.ident_t AND i.local_key = d.patient_ref AND i.usable
    ORDER BY d.t_idx, d.patient_ref, i.row_id""")


def category_names(mask: int) -> list[str]:
    return [c for c in EXPOSURE_CATEGORIES if mask & CAT_BIT[c]]
