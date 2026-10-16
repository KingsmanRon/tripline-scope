"""Test/drill fixture: register synthetic databases as sources and write them in the PLAN §5 extract layout.

This stands in for ``tscope ingest`` (owned by the ingest track) so Module C, its tests, the benchmark and the
drill can run without SQL Server or PostgreSQL. It writes exactly what ingest is specified to write:

``work/extract/<SRC>/<slug>/part-NNNNN.parquet`` (encrypted envelopes, through ``CaseStore``), one row per source
row, standard schema::

    _row_key = "<SRC>|<slug>|<ordinal>"  (ordinal 0-based, in source order)
    _source_id, _table (= slug)
    sa_id        normalised, only when the value is a valid SA ID (tscope_sa_id_norm), else null
    passport_no, first_name, middle_names, last_name, full_name, maiden_name    raw text as stored
    dob          DATE (parsed with the format discovery found: DATE column, '%d/%m/%Y' or '%Y%m%d')
    sex          raw text as stored (M/F, Male/Female or 1/2: Module C normalises)
    medical_aid_no, local_patient_key, patient_ref (keys cast to text)
    phone, phone_alt, guardian_phone   E.164 (tscope_phone_e164), null when not a phone number
    email, guardian_email               raw text
    address, postal_code, language, guardian_name, guardian_sa_id (normalised like sa_id)
    record_date  DATE
    _has_<column category>  BOOLEAN presence flags for exposure-only columns, never their values:
                 _has_icd10, _has_clinical_free_text, _has_test_code, _has_card_number, _has_bank_account

Column mapping used (synthetic column → standard field) is the one recorded in ``synth_meta.json``; e.g. db01
``id_number→sa_id, first_name→first_name, surname→last_name, date_of_birth→dob, cell_phone→phone,
registered_on→record_date``; db02 ``given_names→first_name`` (first and middle names in one column); db03
``patient_name→full_name`` ("SURNAME, FIRST MIDDLE") and ``birth_date`` text '%d/%m/%Y'; db04 ``DOB`` text
'%Y%m%d'. Dependent tables map their patient foreign key to ``patient_ref``, dates to ``record_date``,
``medical_aid_no`` (billing) to ``medical_aid_no``, and ICD-10 / note / test code / card / bank columns to flags only.

``manifest.json`` (encrypted) per source::

    {"schema": "tripline.extract-manifest/v1", "source_id": "SRC-001",
     "tables": [{"database": "db01", "table": "patients", "slug": "patients", "row_count": 771,
                 "parts": ["part-00000.parquet"], "role": "identity", "key": "local_patient_key",
                 "fields": [...standard fields present...], "flags": ["_has_..."], "links_to": []}, ...]}

Dependent tables carry ``"role": "dependent"`` and ``"links_to": ["patients"]`` (slugs of the identity tables their
``patient_ref`` points at).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pyarrow as pa

from tripline_scope.core import custody, duck
from tripline_scope.core.case import Case
from tripline_scope.core.timeutil import now_iso
from tripline_scope.synth.schema import FIELD_CATEGORY

MANIFEST_SCHEMA = "tripline.extract-manifest/v1"

STANDARD_FIELDS = [
    "sa_id", "passport_no", "first_name", "middle_names", "last_name", "full_name", "maiden_name", "dob", "sex",
    "medical_aid_no", "local_patient_key", "patient_ref", "phone", "phone_alt", "email", "address", "postal_code",
    "language", "guardian_name", "guardian_phone", "guardian_email", "guardian_sa_id", "record_date",
]
DATE_FIELDS = {"dob", "record_date"}
FLAG_FIELDS = ["icd10", "clinical_free_text", "test_code", "test_result", "card_number", "bank_account"]
PART_ROWS = 2_000_000


def standard_schema() -> pa.Schema:
    fields = [pa.field("_row_key", pa.string()), pa.field("_source_id", pa.string()), pa.field("_table", pa.string())]
    for f in STANDARD_FIELDS:
        fields.append(pa.field(f, pa.date32() if f in DATE_FIELDS else pa.string()))
    for f in FLAG_FIELDS:
        fields.append(pa.field(f"_has_{f}", pa.bool_()))
    return pa.schema(fields)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return s or "table"


def _q(col: str) -> str:
    return '"' + col.replace('"', '""') + '"'


def _std_exprs(cols: dict[str, str], fmt: dict, role: str) -> dict[str, str]:
    """SQL expression per standard field for one synthetic table (what ingest + discovery would produce)."""
    e: dict[str, str] = {}
    dob_fmt = fmt.get("dob_format", "date")
    for field, col in cols.items():
        c = _q(col)
        if field in ("sa_id", "guardian_sa_id"):
            e[field] = f"tscope_sa_id_norm({c})"
        elif field in ("phone", "phone_alt", "guardian_phone"):
            e[field] = f"tscope_phone_e164({c})"
        elif field == "dob":
            e[field] = c + "::DATE" if dob_fmt == "date" else f"try_strptime({c}, '{dob_fmt}')::DATE"
        elif field == "record_date":
            e[field] = f"TRY_CAST({c} AS DATE)"
        elif field in STANDARD_FIELDS:
            e[field] = f"NULLIF(trim(CAST({c} AS VARCHAR)), '')"
        elif field == "key":
            continue
        elif field in ("icd10", "note", "test_code", "card_number", "bank_account"):
            flag = {"note": "clinical_free_text"}.get(field, field)
            e[f"_has_{flag}"] = f"(NULLIF(trim(CAST({c} AS VARCHAR)), '') IS NOT NULL)"
    if role == "identity" and "local_patient_key" in cols:
        e["local_patient_key"] = f"CAST({_q(cols['local_patient_key'])} AS VARCHAR)"
    if "patient_ref" in cols:
        e["patient_ref"] = f"CAST({_q(cols['patient_ref'])} AS VARCHAR)"
    return e


def register_synth_sources(case: Case, store, synth_dir: Path | str, *, actor: str, include_leak: bool = True,
                           received_at: str | None = None) -> dict[str, str]:
    """Register each synthetic database (directory, system_copy) and the leak sample (csv, leak_sample).

    Returns {database name or 'leak_sample': source_id}."""
    synth_dir = Path(synth_dir).resolve()
    meta = json.loads((synth_dir / "synth_meta.json").read_text())
    at = received_at or now_iso()
    out = {}
    for db in meta["databases"]:
        rec = custody.add_source(case, store, kind="directory", paths=[synth_dir / db["path"]],
                                 label=f"Synthetic lab database {db['database']}", evidence_role="system_copy",
                                 legal_basis="synthetic drill data (no personal information)",
                                 supplied_by="synthetic generator", received_at=at, registered_by=actor)
        out[db["database"]] = rec["source_id"]
    if include_leak and (synth_dir / meta["leak_sample"]["path"]).exists():
        rec = custody.add_source(case, store, kind="csv", paths=[synth_dir / meta["leak_sample"]["path"]],
                                 label="Synthetic published leak sample", evidence_role="leak_sample",
                                 legal_basis="synthetic drill data (no personal information)",
                                 supplied_by="synthetic generator", received_at=at, registered_by=actor)
        out["leak_sample"] = rec["source_id"]
    return out


def load_synth_as_extract(case: Case, store, synth_dir: Path | str, *, source_map: dict[str, str] | None = None,
                          actor: str | None = None, database_names: dict[str, str] | None = None,
                          table_prefix: str = "", tables: tuple[str, ...] = ("patients", "admissions", "billing",
                                                                             "results")) -> dict[str, dict]:
    """Write the synthetic databases as extracts. ``source_map`` maps database name → source id (registers the
    sources when omitted). ``database_names`` renames databases as they would appear inside a restored backup
    (e.g. {"db01": "LabDB01"}) and ``table_prefix`` qualifies tables (e.g. "dbo.")."""
    synth_dir = Path(synth_dir).resolve()
    meta = json.loads((synth_dir / "synth_meta.json").read_text())
    if source_map is None:
        source_map = register_synth_sources(case, store, synth_dir, actor=actor or "fixture")
    manifests = {}
    files = [synth_dir / db["path"] / f"{t}.parquet" for db in meta["databases"] for t in tables]
    files.append(synth_dir / meta["leak_sample"]["path"])
    con = duck.connect(read_paths=[f for f in files if f.exists()])
    try:
        for db in meta["databases"]:
            sid = source_map.get(db["database"])
            if not sid:
                continue
            dbname = (database_names or {}).get(db["database"], db["database"])
            entries = []
            for t in tables:
                path = synth_dir / db["path"] / f"{t}.parquet"
                if not path.exists():
                    continue
                role = "identity" if t == "patients" else "dependent"
                cols = db["tables"][t]["columns"]
                exprs = _std_exprs(cols, db["formats"], role)
                table_name = table_prefix + t
                slug = slugify(table_name)
                entry = _write_table(con, store, sid, slug, f"read_parquet('{path}', file_row_number = true)", exprs,
                                     dbname, table_name, role, ordinal="file_row_number")
                entry["links_to"] = [slugify(table_prefix + "patients")] if role == "dependent" else []
                entry["key"] = "local_patient_key" if role == "identity" else None
                entries.append(entry)
            manifests[sid] = _write_manifest(store, sid, entries)
        lsid = source_map.get("leak_sample")
        lpath = synth_dir / meta["leak_sample"]["path"]
        if lsid and lpath.exists():
            exprs = {"first_name": "NULLIF(trim(\"Name\"), '')", "last_name": "NULLIF(trim(\"Surname\"), '')",
                     "sa_id": "tscope_sa_id_norm(\"ID Number\")",
                     "dob": "try_strptime(CAST(\"Date of Birth\" AS VARCHAR), '%Y-%m-%d')::DATE",
                     "phone": "tscope_phone_e164(\"Cell\")"}
            src = f"read_csv('{lpath}', header = true, all_varchar = true)"
            entry = _write_table(con, store, lsid, "leak_sample", src, exprs, "leak_sample.csv", "leak_sample",
                                 "identity")
            entry["links_to"] = []
            entry["key"] = None
            manifests[lsid] = _write_manifest(store, lsid, [entry])
    finally:
        con.close()
    return manifests


def _write_table(con, store, sid, slug, src_sql, exprs, dbname, table_name, role,
                 ordinal: str = "(row_number() OVER () - 1)") -> dict:
    schema = standard_schema()
    sel = [f"'{sid}|{slug}|' || ({ordinal})::VARCHAR AS _row_key", f"'{sid}' AS _source_id",
           f"'{slug}' AS _table"]
    present, flags = [], []
    for f in schema.names[3:]:
        if f in exprs:
            sel.append(f"{exprs[f]} AS {_q(f)}")
            if f.startswith("_has_"):
                flags.append(f)
            else:
                present.append(f)
        elif f.startswith("_has_"):
            sel.append(f"CAST(NULL AS BOOLEAN) AS {_q(f)}")
        else:
            sel.append(f"CAST(NULL AS {'DATE' if f in DATE_FIELDS else 'VARCHAR'}) AS {_q(f)}")
    order = " ORDER BY file_row_number" if ordinal == "file_row_number" else ""
    reader = con.execute(f"SELECT {', '.join(sel)} FROM {src_sql}{order}").fetch_record_batch(250_000)
    parts, rows, part_rows, writer_ctx, writer = [], 0, 0, None, None
    try:
        for batch in reader:
            if batch.num_rows == 0:
                continue
            batch = pa.RecordBatch.from_arrays([batch.column(i).cast(schema.field(i).type) for i in range(len(schema))],
                                               schema=schema)
            if writer is None or part_rows >= PART_ROWS:
                if writer_ctx is not None:
                    writer_ctx.__exit__(None, None, None)
                name = f"part-{len(parts):05d}.parquet"
                parts.append(name)
                writer_ctx = store.table_writer(f"work/extract/{sid}/{slug}/{name}", schema)
                writer = writer_ctx.__enter__()
                part_rows = 0
            writer.write_batch(batch)
            rows += batch.num_rows
            part_rows += batch.num_rows
    finally:
        if writer_ctx is not None:
            writer_ctx.__exit__(None, None, None)
    if not parts:
        name = "part-00000.parquet"
        store.write_table(f"work/extract/{sid}/{slug}/{name}", schema.empty_table())
        parts.append(name)
    return {"database": dbname, "table": table_name, "slug": slug, "row_count": rows, "parts": parts, "role": role,
            "fields": sorted(present), "flags": sorted(flags)}


def write_rows_as_extract(store, sid: str, tables: list[dict]) -> dict:
    """Write hand-made rows (lists of standard-field dicts) as an extract; for tests and drills.

    ``tables``: ``[{"database", "table", "role", "rows": [...], "links_to": [slug...]}]``."""
    schema = standard_schema()
    entries = []
    for t in tables:
        slug = slugify(t["table"])
        cols = {f: [] for f in schema.names}
        present, flags = set(), set()
        for i, r in enumerate(t["rows"]):
            for f in schema.names:
                if f == "_row_key":
                    v = f"{sid}|{slug}|{i}"
                elif f == "_source_id":
                    v = sid
                elif f == "_table":
                    v = slug
                else:
                    v = r.get(f)
                    if v is not None:
                        (flags if f.startswith("_has_") else present).add(f)
                cols[f].append(v)
        tb = pa.table({f: pa.array(cols[f], type=schema.field(f).type) for f in schema.names}, schema=schema)
        store.write_table(f"work/extract/{sid}/{slug}/part-00000.parquet", tb)
        entries.append({"database": t["database"], "table": t["table"], "slug": slug, "row_count": tb.num_rows,
                        "parts": ["part-00000.parquet"], "role": t["role"], "fields": sorted(present),
                        "flags": sorted(flags), "links_to": t.get("links_to") or [],
                        "key": "local_patient_key" if t["role"] == "identity" else None})
    return _write_manifest(store, sid, entries)


def _write_manifest(store, sid: str, entries: list[dict]) -> dict:
    doc = {"schema": MANIFEST_SCHEMA, "source_id": sid, "tables": entries,
           "column_categories": {e["slug"]: {f: FIELD_CATEGORY.get(f, f) for f in e["fields"]} for e in entries}}
    store.write_json(f"work/extract/{sid}/manifest.json", doc)
    return doc


def synth_reference_date(synth_dir: Path | str) -> dt.date:
    return dt.date.fromisoformat(json.loads((Path(synth_dir) / "synth_meta.json").read_text())["reference_date"])
