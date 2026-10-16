"""Extraction: only the columns needed for matching and contact, normalised into the standard schema (PLAN §5).

Per extracted table, rows are read again in the same deterministic order as discovery, normalised in an
in-memory DuckDB and streamed into encrypted Parquet parts ``work/extract/<SRC>/<slug>/part-NNNNN.parquet``:

* ``sa_id`` normalised and valid only (13 digits, real date, citizenship digit, Luhn); invalid values dropped;
* passports upper-case alphanumerics; phones E.164; e-mails lower-case and well-formed; names upper-case ASCII
  (accents stripped); dates as DATE; sex as ``M``/``F``/``U``; local keys trimmed;
* ``_has_<exposure>`` flags for every exposure category. Clinical, card and bank columns contribute **only**
  their flags: their values are never selected, so they never reach a file.

``work/extract/<SRC>/manifest.json`` lists every table of the source (extracted or not) with row counts.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable

import pyarrow as pa

from tripline_scope.core import duck
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.discovery.categories import (
    EXPOSURE_CATEGORIES,
    NEVER_EXTRACTED,
    SPECS,
    STANDARD_FIELDS,
)
from tripline_scope.discovery.values import SEX_MAP, date_sql, present_sql, sa_id_norm_sql

from .model import assign_slugs

MANIFEST_SCHEMA = "tripline.extract-manifest/v1"
EXTRACT_METHOD = "extract/0.1.0"
_ARROW = {"s": pa.string(), "d": pa.date32(), "b": pa.bool_()}
SCHEMA = pa.schema([pa.field(name, _ARROW[t]) for name, t in STANDARD_FIELDS])


def _lit(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _name(v: str) -> str:
    return f"tscope_name_norm({v})"


def _coalesce(exprs: list[str]) -> str:
    if not exprs:
        return "NULL"
    return exprs[0] if len(exprs) == 1 else "coalesce(" + ", ".join(exprs) + ")"


def build_sql(source_id: str, tdoc: dict) -> str:
    """SELECT producing the standard schema from a registered ``batch`` (columns ``c<i>`` plus ``_ord``)."""
    cols = {c["name"]: c for c in tdoc["columns"]}
    fields: dict[str, list[str]] = tdoc["fields"]
    for names in fields.values():
        for n in names:
            if cols[n]["category"] in NEVER_EXTRACTED:
                raise IntegrityError("refusing to extract a column whose category is never extracted")

    def v(name: str) -> str:
        return f"c{cols[name]['position']}"

    prep: list[str] = ["_ord"]
    out: dict[str, str] = {}

    def ids(field: str) -> str:
        return _coalesce([sa_id_norm_sql(v(n), cols[n]["id_pad"]) for n in fields.get(field, [])])

    out["sa_id"] = ids("sa_id")
    out["guardian_sa_id"] = ids("guardian_sa_id")
    pp = []
    for n in fields.get("passport_no", []):
        x = f"upper(regexp_replace({v(n)}, '[\\s\\-]', '', 'g'))"
        pp.append(f"(CASE WHEN regexp_full_match({x}, '[A-Z0-9]{{6,15}}') THEN {x} END)")
    for n in ([] if pp else fields.get("sa_id", [])):     # only when there is no passport column
        x = f"upper(regexp_replace({v(n)}, '\\s', '', 'g'))"
        pp.append(f"(CASE WHEN {sa_id_norm_sql(v(n), cols[n]['id_pad'])} IS NULL AND tscope_passport_like({v(n)}) "
                  f"AND NOT regexp_full_match(tscope_digits({v(n)}), '[0-9]+') THEN {x} END)")
    out["passport_no"] = _coalesce(pp)

    # names
    first_cols = [n for n in fields.get("first_name", []) if cols[n]["standard_field"] == "first_name"]
    middle_cols = [n for n in fields.get("middle_names", [])]
    full_cols = fields.get("full_name", [])
    last_cols = fields.get("last_name", [])
    if first_cols:
        fn = _coalesce([_name(v(n)) for n in first_cols])
        prep.append(f"{fn} AS _fn")
        out["first_name"] = "nullif(split_part(_fn, ' ', 1), '')"
        rest = "nullif(trim(regexp_replace(_fn, '^\\S+\\s*', '')), '')"
        mids = [rest] + [_name(v(n)) for n in middle_cols]
        out["middle_names"] = "nullif(concat_ws(' ', " + ", ".join(mids) + "), '')"
    elif middle_cols:
        out["middle_names"] = _coalesce([_name(v(n)) for n in middle_cols])
    if full_cols:
        raw = full_cols[0]
        prep.append(f"{_name(v(raw))} AS _full")
        prep.append(f"(strpos(coalesce({v(raw)}, ''), ',') > 0) AS _comma")
        prep.append(f"{_name(f'split_part({v(raw)}, {_lit(',')}, 1)')} AS _full_last")
        prep.append(f"{_name(f'split_part({v(raw)}, {_lit(',')}, 2)')} AS _full_given")
        out["full_name"] = _coalesce([_name(v(n)) for n in full_cols]) if len(full_cols) > 1 else "_full"
        if not first_cols and not last_cols:
            out["first_name"] = ("CASE WHEN _comma THEN nullif(split_part(_full_given, ' ', 1), '') "
                                 "WHEN strpos(_full, ' ') > 0 THEN split_part(_full, ' ', 1) END")
            out["last_name"] = ("CASE WHEN _comma THEN _full_last "
                                "ELSE nullif(regexp_extract(_full, '(\\S+)$', 1), '') END")
            out["middle_names"] = ("CASE WHEN _comma THEN nullif(trim(regexp_replace(_full_given, '^\\S+\\s*', '')), '') "
                                   "ELSE nullif(trim(regexp_replace(regexp_replace(_full, '^\\S+\\s*', ''), "
                                   "'\\s*\\S+$', '')), '') END")
    if last_cols:
        out["last_name"] = _coalesce([_name(v(n)) for n in last_cols])
    out["maiden_name"] = _coalesce([_name(v(n)) for n in fields.get("maiden_name", [])])
    out["guardian_name"] = _coalesce([_name(v(n)) for n in fields.get("guardian_name", [])])

    # dates, demographics, keys
    def dates(field: str) -> str:
        return _coalesce([date_sql(v(n), cols[n]["date_parser"]) for n in fields.get(field, [])
                          if cols[n]["date_parser"]])

    out["dob"] = dates("dob")
    out["record_date"] = dates("record_date")
    case_sex = " ".join(f"WHEN {_lit(k)} THEN {_lit(m)}" for k, m in sorted(SEX_MAP.items()))
    out["sex"] = _coalesce([f"(CASE upper(trim({v(n)})) {case_sex} END)" for n in fields.get("sex", [])])
    out["medical_aid_no"] = _coalesce([f"nullif(upper(regexp_replace({v(n)}, '[\\s\\-/]', '', 'g')), '')"
                                       for n in fields.get("medical_aid_no", [])])
    out["local_patient_key"] = _coalesce([f"nullif(trim({v(n)}), '')" for n in fields.get("local_patient_key", [])])
    out["patient_ref"] = _coalesce([f"nullif(trim({v(n)}), '')" for n in fields.get("patient_ref", [])])
    out["language"] = _coalesce([f"nullif(trim({v(n)}), '')" for n in fields.get("language", [])])
    out["postal_code"] = _coalesce([f"nullif(upper(trim({v(n)})), '')" for n in fields.get("postal_code", [])])

    # contact
    out["phone"] = _coalesce([f"tscope_phone_e164({v(n)})" for n in fields.get("phone", [])])
    out["phone_alt"] = _coalesce([f"tscope_phone_e164({v(n)})" for n in fields.get("phone_alt", [])])
    out["email"] = _coalesce([f"tscope_email_norm({v(n)})" for n in fields.get("email", [])])
    out["guardian_email"] = _coalesce([f"tscope_email_norm({v(n)})" for n in fields.get("guardian_email", [])])
    out["guardian_phone"] = _coalesce([f"tscope_phone_e164({v(n)})" for n in fields.get("guardian_phone", [])])
    addr = fields.get("address", [])
    if addr:
        parts = ", ".join(f"nullif(trim(regexp_replace({v(n)}, '\\s+', ' ', 'g')), '')" for n in addr)
        out["address"] = f"nullif(concat_ws(', ', {parts}), '')"

    # presence flags: any column of that exposure category (values never selected)
    flags = {}
    for e in EXPOSURE_CATEGORIES:
        conds = [present_sql(c["category"], f"c{c['position']}") for c in tdoc["columns"]
                 if c["exposure_category"] == e and c["confidence"] >= 0.5 and c["readable"]]
        flags[f"_has_{e}"] = " OR ".join(conds) if conds else "false"
        if conds:
            prep.append(f"({flags[f'_has_{e}']}) AS _f_{e}")

    select = []
    for name, typ in STANDARD_FIELDS:
        if name == "_row_key":
            expr = f"{_lit(f'{source_id}|{tdoc['slug']}|')} || CAST(_ord AS VARCHAR)"
        elif name == "_source_id":
            expr = _lit(source_id)
        elif name == "_table":
            expr = _lit(tdoc["slug"])
        elif name.startswith("_has_"):
            e = name[len("_has_"):]
            expr = f"coalesce(_f_{e}, false)" if flags[name] != "false" else "false"
        else:
            expr = out.get(name) or "NULL"
        cast = {"s": "VARCHAR", "d": "DATE", "b": "BOOLEAN"}[typ]
        select.append(f"CAST({expr} AS {cast}) AS {name}")
    return f"WITH s AS (SELECT *, {', '.join(prep[1:]) or '1 AS _x'} FROM batch) SELECT {', '.join(select)} FROM s ORDER BY _ord"


def _table_flags(tdoc: dict) -> list[str]:
    return sorted({f"_has_{c['exposure_category']}" for c in tdoc["columns"]
                   if c["exposure_category"] and c["confidence"] >= 0.5 and c["readable"]},
                  key=lambda f: EXPOSURE_CATEGORIES.index(f[len("_has_"):]))


def clear_extract(store, source_id: str) -> None:
    for rel in store.list(f"work/extract/{source_id}"):
        store.delete(rel)


def extract_source(reader, store, discovery: dict, *, source_id: str, batch_rows: int = 50_000,
                   part_rows: int = 500_000, progress: Callable[[str, int], None] | None = None) -> dict:
    if discovery.get("source_id") != source_id:
        raise IntegrityError("discovery output belongs to a different source")
    clear_extract(store, source_id)
    tables = reader.tables()
    assign_slugs(tables)
    by_slug = {t.slug: t for t in tables}
    con = duck.connect()
    entries = []
    try:
        for tdoc in discovery["tables"]:
            entry = {
                "database": tdoc["database"], "table": tdoc["table"], "slug": tdoc["slug"],
                "row_count": tdoc["row_count"], "role": tdoc["role"], "scanned": tdoc["scanned"],
                "extracted": False, "parts": [], "part_sha256": [], "extracted_rows": 0,
                "fields": sorted(tdoc["fields"]), "source_columns": tdoc["fields"], "flags": _table_flags(tdoc),
                "patient_key": tdoc["patient_key"], "patient_refs": tdoc["patient_refs"],
                "relations": tdoc["relations"], "exposure_categories": tdoc["exposure_categories"],
                "columns_not_extracted": sorted(c["name"] for c in tdoc["columns"] if not c["extracted"]),
            }
            if not tdoc["extract"]:
                entries.append(entry)
                continue
            table = by_slug.get(tdoc["slug"])
            if table is None:
                raise IntegrityError("source tables changed since discovery; run discovery again")
            sql = build_sql(source_id, tdoc)
            ordinal = 0
            part_no = 0
            part_rows_now = 0
            stack = contextlib.ExitStack()
            writer = None
            try:
                for batch in reader.iter_batches(table, batch_rows):
                    if batch.num_rows == 0:
                        continue
                    ords = pa.array(range(ordinal, ordinal + batch.num_rows), type=pa.int64())  # 0-based (PLAN §5)
                    ordinal += batch.num_rows
                    t = pa.Table.from_batches([batch]).append_column("_ord", ords)
                    con.register("batch", t)
                    try:
                        res = con.execute(sql).to_arrow_table()
                    finally:
                        con.unregister("batch")
                    res = res.cast(SCHEMA)
                    if writer is None or part_rows_now >= part_rows:
                        stack.close()
                        stack = contextlib.ExitStack()
                        part_no += 1
                        rel = f"work/extract/{source_id}/{tdoc['slug']}/part-{part_no:05d}.parquet"
                        writer = stack.enter_context(store.table_writer(rel, SCHEMA))
                        entry["parts"].append(rel)
                        part_rows_now = 0
                    writer.write_table(res)
                    part_rows_now += res.num_rows
                    entry["extracted_rows"] += res.num_rows
                    if progress:
                        progress(tdoc["slug"], ordinal)
                stack.close()
            except BaseException:
                stack.close()
                raise
            if not entry["parts"]:     # empty table: still write one empty part so consumers see the schema
                rel = f"work/extract/{source_id}/{tdoc['slug']}/part-00001.parquet"
                store.write_table(rel, SCHEMA.empty_table())
                entry["parts"].append(rel)
            if tdoc["row_count"] is not None and ordinal != tdoc["row_count"]:
                raise IntegrityError(f"table {tdoc['slug']} changed between discovery and extraction "
                                     f"({tdoc['row_count']} vs {ordinal} rows)")
            entry["part_sha256"] = [store.file_sha256(p) for p in entry["parts"]]
            entry["extracted"] = True
            entries.append(entry)
    finally:
        con.close()
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "method_version": EXTRACT_METHOD,
        "source_id": source_id,
        "engine": discovery.get("engine"),
        "discovery_sha256": sha256_hex(canonical_bytes(discovery)),
        "standard_schema": [[n, t] for n, t in STANDARD_FIELDS],
        "tables": entries,
        "totals": {
            "tables": len(entries),
            "extracted_tables": sum(1 for e in entries if e["extracted"]),
            "rows": sum(e["row_count"] or 0 for e in entries),
            "extracted_rows": sum(e["extracted_rows"] for e in entries),
        },
    }
    store.write_json(f"work/extract/{source_id}/manifest.json", manifest)
    return manifest


def read_extract(store, source_id: str, slug: str | None = None) -> pa.Table:
    """Load extracted rows (all tables, or one) for downstream modules and tests."""
    m = store.read_json(f"work/extract/{source_id}/manifest.json")
    parts = [p for e in m["tables"] if e["extracted"] and (slug is None or e["slug"] == slug) for p in e["parts"]]
    if not parts:
        return SCHEMA.empty_table()
    return store.read_tables(parts)


__all__ = ["SCHEMA", "build_sql", "extract_source", "read_extract", "SPECS", "ConfigError"]
