"""Discovery: classify every column of every selected table, by sampling and then a confirming full scan.

1. **Sample** the first ``sample_rows`` rows of each table (deterministic order) and classify each column from
   its name hint and value evidence (:mod:`classify`); ``case.yaml`` overrides and relations win.
2. Resolve each table: generic name columns, identity table (>= 2 of name / DOB / SA ID / passport), the
   identity table's local patient key, and patient references in other tables.
3. **Full scan** every row, batch by batch, in an in-memory sandboxed DuckDB: null and match counts for the
   chosen category of every column (``tscope_*`` macros), exact row counts, and the set of patient-key values
   of identity tables (held in memory only, bounded) to test reference containment.
4. Confirm or demote sample decisions, infer relations, decide which columns are extracted.

The output (``work/discovery/<SRC>.json``, encrypted) holds names, categories, rates and counts only. It is
deterministic for identical input (no timestamps), so reports built on it are byte-identical.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

import pyarrow as pa

from tripline_scope.core import duck
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError

from .categories import DISCOVERY_METHOD, DISCOVERY_SCHEMA, EXPOSURE_CATEGORIES, SPECS, validate_category
from .classify import (
    ColumnState,
    Decision,
    apply_override,
    classify_column,
    confirm,
    is_identity_table,
    resolve_keys,
    resolve_names,
)
from .hints import tokenise
from .values import Profile, match_sql, null_sql, profile_values, sample_rate

# A table is extracted when it has at least one of these (rows that can be linked to, or describe, a person).
_LINKABLE_FIELDS = {"sa_id", "passport_no", "first_name", "last_name", "full_name", "maiden_name", "dob",
                    "medical_aid_no", "local_patient_key", "patient_ref", "phone", "email", "address",
                    "guardian_name", "guardian_phone", "guardian_email", "guardian_sa_id"}
MIN_EXTRACT_CONFIDENCE = 0.5


@dataclass
class TableState:
    table: object                    # ingest.model.TableRef
    cols: list[ColumnState]
    identity: bool = False
    key_col: ColumnState | None = None
    sampled_rows: int = 0
    row_count: int = 0
    key_values: set[str] | None = None
    key_values_capped: bool = False
    ref_samples: dict[int, set[str]] = field(default_factory=dict)
    relations: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


def _overrides_for(case_config: dict, source_id: str) -> dict:
    ov = (case_config.get("column_overrides") or {}).get(source_id) or {}
    if not isinstance(ov, dict):
        raise ConfigError("column_overrides must map source id -> table -> column -> category")
    for table, cols in ov.items():
        if not isinstance(cols, dict):
            raise ConfigError(f"column_overrides for {source_id} table {table!r} must map column -> category")
        for cat in cols.values():
            validate_category(str(cat))
    return ov


def _relations_for(case_config: dict, source_id: str) -> list[dict]:
    out = []
    for r in case_config.get("relations") or []:
        if not isinstance(r, dict) or r.get("source") != source_id:
            continue
        ref = r.get("references") or {}
        if not (r.get("table") and r.get("column") and ref.get("table") and ref.get("column")):
            raise ConfigError("each relation needs source, table, column and references{table, column}")
        out.append(r)
    return out


def _find_col(cols: list[ColumnState], name: str) -> ColumnState | None:
    for c in cols:
        if c.name == name:
            return c
    for c in cols:
        if c.name.lower() == str(name).lower():
            return c
    return None


def _table_overrides(ov: dict, table) -> dict:
    for tname, cols in ov.items():
        if table.matches(str(tname)):
            return cols
    return {}


def _empty_profile() -> Profile:
    return Profile(sampled=0, nonnull=0, distinct=0, distinct_capped=False, avg_len=0.0)


# ------------------------------------------------------------------------------------------ sample
def _read_sample(reader, table, sample_rows: int, batch_rows: int) -> tuple[list[list[str | None]], int]:
    cols: list[list[str | None]] = [[] for _ in table.columns]
    n = 0
    gen = reader.iter_batches(table, min(batch_rows, sample_rows), limit=sample_rows)
    try:
        for batch in gen:
            for i in range(len(table.columns)):
                cols[i].extend(batch.column(i).to_pylist())
            n += batch.num_rows
            if n >= sample_rows:
                break
    finally:
        gen.close()
    return cols, n


def _classify_table(table, sample: list[list[str | None]], nrows: int, overrides: dict,
                    rel_cols: dict[str, str]) -> TableState:
    cols: list[ColumnState] = []
    for i, c in enumerate(table.columns):
        if c.readable:
            from .classify import hint_for, needs_id_pad

            prof = profile_values(sample[i], id_pad=needs_id_pad(hint_for(c.name, table.name), c.numeric))
        else:
            prof = _empty_profile()
        d = classify_column(c.name, table.name, prof, numeric=c.numeric, readable=c.readable)
        cols.append(ColumnState(i, c.name, c.data_type, c.numeric, c.readable, d, prof))
    tov = _table_overrides(overrides, table)
    for cname, cat in tov.items():
        cs = _find_col(cols, str(cname))
        if cs is None:
            raise ConfigError(f"column override names a column that does not exist in table {table.label}")
        apply_override(cs, str(cat))
    for cname, cat in rel_cols.items():
        cs = _find_col(cols, cname)
        if cs is None:
            raise ConfigError(f"relation names a column that does not exist in table {table.label}")
        if not cs.override:
            apply_override(cs, cat)
            cs.decision.reasons[-1] = "case_yaml_relation"
    resolve_names(cols)
    st = TableState(table, cols, sampled_rows=nrows)
    st.identity = is_identity_table(cols)
    st.key_col = resolve_keys(cols, st.identity, table.key)
    return st


# ------------------------------------------------------------------------------------------ full scan
def _scan_sql(st: TableState) -> tuple[str, list[tuple[int, bool]]]:
    exprs = ["count(*) AS n"]
    plan = []
    for c in st.cols:
        if not c.readable:
            continue
        v = f"c{c.index}"
        exprs.append(f"count_if(NOT {null_sql(v)}) AS nn{c.index}")
        has_match = c.decision.category not in ("other", "other_identifier")
        if has_match:
            m = match_sql(c.decision.category, v, date_parser=c.decision.date_parser, id_pad=c.decision.id_pad)
            exprs.append(f"count_if({m}) AS m{c.index}")
        plan.append((c.index, has_match))
    return "SELECT " + ", ".join(exprs) + " FROM batch", plan


def _full_scan(con, reader, st: TableState, batch_rows: int, key_cap: int, max_rows: int,
               progress: Callable[[str, int], None] | None) -> None:
    sql, plan = _scan_sql(st)
    for c in st.cols:
        c.full_rows = c.full_nonnull = c.full_match = 0
    st.row_count = 0
    if st.key_col is not None:
        st.key_values = set()
    ref_idx = [c.index for c in st.cols if c.decision.category == "patient_ref"]
    st.ref_samples = {i: set() for i in ref_idx}
    by_index = {c.index: c for c in st.cols}
    for batch in reader.iter_batches(st.table, batch_rows):
        if batch.num_rows == 0:
            continue
        con.register("batch", pa.Table.from_batches([batch]))
        try:
            row = con.execute(sql).fetchone()
            if st.key_values is not None and not st.key_values_capped:
                k = st.key_col.index
                for (val,) in con.execute(f"SELECT DISTINCT trim(c{k}) FROM batch WHERE NOT {null_sql(f'c{k}')}").fetchall():
                    if len(st.key_values) >= key_cap:
                        st.key_values_capped = True
                        break
                    st.key_values.add(val)
            for i in ref_idx:
                s = st.ref_samples[i]
                if len(s) < 10_000:
                    for (val,) in con.execute(f"SELECT DISTINCT trim(c{i}) FROM batch WHERE NOT {null_sql(f'c{i}')} "
                                              f"LIMIT {10_000 - len(s)}").fetchall():
                        s.add(val)
        finally:
            con.unregister("batch")
        n = int(row[0])
        st.row_count += n
        pos = 1
        for idx, has_match in plan:
            c = by_index[idx]
            c.full_rows += n
            c.full_nonnull += int(row[pos])
            pos += 1
            if has_match:
                c.full_match += int(row[pos])
                pos += 1
            else:
                c.full_match += int(row[pos - 1])
        if st.row_count > max_rows:
            raise ConfigError(f"table {st.table.slug} exceeds the configured row limit ({max_rows}); "
                              "raise ingest.max_rows_per_table to process it")
        if progress:
            progress(st.table.slug, st.row_count)
    for c in st.cols:
        if not c.readable:
            c.full_rows = st.row_count


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 6) if den else None


def _confirm_table(st: TableState) -> None:
    changed = False
    for c in st.cols:
        if not c.readable or c.override:
            continue
        before = c.decision.category
        numeric_like = bool(c.profile and c.profile.rate("digits") >= 0.9)
        confirm(c.decision, _rate(c.full_match, c.full_nonnull), numeric_like)
        changed |= before != c.decision.category
    if changed:
        identity = is_identity_table(st.cols)
        if identity != st.identity:
            st.identity = identity
            st.key_col = resolve_keys(st.cols, identity, st.table.key)


# ------------------------------------------------------------------------------------------ relations
def _infer_relations(states: list[TableState], case_rel: list[dict]) -> None:
    identities = [s for s in states if s.identity and s.key_col is not None]
    by_slug = {s.table.slug: s for s in states}
    for st in states:
        for c in st.cols:
            if c.decision.category != "patient_ref":
                continue
            declared = next((r for r in case_rel if st.table.matches(str(r["table"]))
                             and str(r["column"]).lower() == c.name.lower()), None)
            if declared:
                target = next((s for s in states if s.table.matches(str(declared["references"]["table"]))), None)
                if target is None:
                    raise ConfigError("relation references a table that is not in this source (or not selected)")
                kc = _find_col(target.cols, str(declared["references"]["column"]))
                if kc is None:
                    raise ConfigError("relation references a column that does not exist")
                st.relations.append({"patient_ref": c.name, "identity_table": target.table.slug,
                                     "patient_key": kc.name, "containment": _containment(st, c, target),
                                     "basis": "case.yaml"})
                continue
            best, best_score = None, -1.0
            for ident in identities:
                if ident is st:
                    continue
                cont = _containment(st, c, ident)
                score = (cont or 0.0) + (0.5 if c.name.lower() == ident.key_col.name.lower() else 0.0)
                if score > best_score:
                    best, best_score = ident, score
            cont = _containment(st, c, best) if best is not None else None
            if best is None or ((cont or 0.0) < 0.5 and c.name.lower() != best.key_col.name.lower()):
                # A key-like name whose values match no patient key of this source is not a patient reference.
                if any(i is not st for i in identities) and not c.override:
                    c.decision.set("other_identifier", 0.5, "table", "values_match_no_patient_key_in_source")
                continue
            st.relations.append({"patient_ref": c.name, "identity_table": best.table.slug,
                                 "patient_key": best.key_col.name, "containment": cont, "basis": "inferred"})
    del by_slug


def _containment(st: TableState, c: ColumnState, ident: TableState) -> float | None:
    refs = st.ref_samples.get(c.index) or set()
    if not refs or ident.key_values is None:
        return None
    return round(len(refs & ident.key_values) / len(refs), 6)


# ------------------------------------------------------------------------------------------ field plan
_SLOTS = {"phone": ("phone", "phone_alt")}      # a second phone column goes to phone_alt
_COMPOSED = {"address": 6}                      # address parts (line, suburb, city ...) form one address
_ALT_TOKENS = re.compile(r"(?:^|_)(?:alt|alternative|other|second|secondary|work|office|home|landline|fax|2)(?:_|$)")


def plan_fields(cols: list[dict]) -> dict[str, list[str]]:
    """Assign source columns to standard fields: one column per field, never filling one column's gaps with
    another's values. The best column (confidence, then a primary-looking name, then column order) takes the
    field; a second phone takes ``phone_alt``; columns left without a slot get ``standard_field: null`` and a
    reason (they are still classified and flagged). Address parts are joined in column order."""
    usable = [c for c in cols if c["standard_field"] and c["category"] in SPECS
              and SPECS[c["category"]].standard_field is not None and c["confidence"] >= MIN_EXTRACT_CONFIDENCE]
    usable.sort(key=lambda c: (-c["confidence"], bool(_ALT_TOKENS.search(tokenise(c["name"]))), c["position"]))
    out: dict[str, list[str]] = {}
    for c in usable:
        f = c["standard_field"]
        if f in _COMPOSED:
            parts = out.setdefault(f, [])
            if len(parts) < _COMPOSED[f]:
                parts.append(c["name"])
                continue
            free = None
        else:
            free = next((slot for slot in _SLOTS.get(f, (f,)) if slot not in out), None)
        if free is None:
            c["standard_field"] = None
            c["reasons"] = list(c["reasons"]) + [f"no_free_standard_field_slot_for_{f}"]
            continue
        out[free] = [c["name"]]
        c["standard_field"] = free
    for f in _COMPOSED:
        if f in out:
            out[f].sort(key=lambda n: next(c["position"] for c in cols if c["name"] == n))
    return out


def _table_doc(st: TableState, scanned: bool) -> dict:
    t = st.table
    cols = []
    for c in st.cols:
        d: Decision = c.decision
        spec = SPECS[d.category]
        p = c.profile
        cols.append({
            "name": c.name,
            "position": c.index,
            "data_type": c.data_type,
            "category": d.category,
            "confidence": round(d.confidence, 3),
            "basis": d.basis,
            "reasons": list(d.reasons),
            "hint": d.hint,
            "match_rate": _rate(c.full_match, c.full_nonnull) if scanned else None,
            "null_rate": _rate(c.full_rows - c.full_nonnull, c.full_rows) if scanned and c.readable else None,
            "sample_match_rate": sample_rate(d.category, p) if p and p.nonnull else None,
            "sample_null_rate": round(p.null_rate, 6) if p and p.sampled else None,
            "purpose": spec.purpose,
            "exposure_category": spec.exposure,
            "standard_field": d.standard_field if spec.standard_field else None,
            "override": c.override,
            "extracted": False,
            "date_parser": d.date_parser if d.category in ("dob", "record_date") else None,
            "id_pad": bool(d.id_pad) if d.category in ("sa_id", "guardian_sa_id") else False,
            "readable": c.readable,
        })
    fields = plan_fields(cols)
    extracted_names = {n for names in fields.values() for n in names}
    linkable = any(f in _LINKABLE_FIELDS for f in fields)
    for col in cols:
        col["extracted"] = linkable and col["name"] in extracted_names
    exposures = sorted({c["exposure_category"] for c in cols
                        if c["exposure_category"] and c["confidence"] >= MIN_EXTRACT_CONFIDENCE
                        and (not scanned or (c["null_rate"] is not None and c["null_rate"] < 1.0))},
                       key=EXPOSURE_CATEGORIES.index)
    refs = [c.name for c in st.cols if c.decision.category == "patient_ref"]
    role = "identity" if st.identity else ("dependent" if refs else "other")
    return {
        "slug": t.slug,
        "database": t.database,
        "schema": t.schema,
        "name": t.name,
        "table": f"{t.schema}.{t.name}" if t.schema else t.name,
        "label": t.label,
        "scanned": scanned,
        "row_count": st.row_count if scanned else st.extra.get("row_count"),
        "sampled_rows": st.sampled_rows,
        "role": role,
        "patient_key": st.key_col.name if (st.key_col is not None and st.identity) else None,
        "patient_refs": refs,
        "relations": st.relations,
        "key_values_capped": st.key_values_capped,
        "exposure_categories": exposures,
        "extract": linkable and scanned,
        "fields": fields if linkable else {},
        "columns": cols,
        "reader": st.extra.get("reader") or {},
    }


def discover(reader, *, source_id: str, case_config: dict, sample_rows: int = 10_000, batch_rows: int = 50_000,
             tables_filter: list[str] | None = None, key_cap: int = 2_000_000, max_rows: int = 50_000_000,
             progress: Callable[[str, int], None] | None = None) -> dict:
    from tripline_scope.ingest.model import assign_slugs

    if sample_rows < 1 or batch_rows < 1:
        raise ConfigError("sample and batch sizes must be positive")
    overrides = _overrides_for(case_config, source_id)
    case_rel = _relations_for(case_config, source_id)
    tables = reader.tables()
    assign_slugs(tables)
    selected = tables
    if tables_filter:
        unknown = [w for w in tables_filter if not any(t.matches(w) for t in tables)]
        if unknown:
            raise ConfigError(f"{len(unknown)} table name(s) given with --tables are not in source {source_id}")
        selected = [t for t in tables if any(t.matches(w) for w in tables_filter)]
    rel_cols: dict[str, dict[str, str]] = {}
    for r in case_rel:
        for t in selected:
            if t.matches(str(r["table"])):
                rel_cols.setdefault(t.slug, {})[str(r["column"])] = "patient_ref"
            if t.matches(str(r["references"]["table"])):
                rel_cols.setdefault(t.slug, {})[str(r["references"]["column"])] = "patient_key"
    states: list[TableState] = []
    for t in selected:
        sample, n = _read_sample(reader, t, sample_rows, batch_rows)
        st = _classify_table(t, sample, n, overrides, rel_cols.get(t.slug, {}))
        del sample
        states.append(st)
    con = duck.connect()
    try:
        for st in states:
            _full_scan(con, reader, st, batch_rows, key_cap, max_rows, progress)
            st.extra["reader"] = reader_stats(reader, st.table)
            _confirm_table(st)
    finally:
        con.close()
    _infer_relations(states, case_rel)
    docs = [_table_doc(st, True) for st in states]
    for st in states:      # values used for containment never outlive discovery
        st.key_values = None
        st.ref_samples = {}
    for t in tables:
        if t in selected:
            continue
        cols = [ColumnState(i, c.name, c.data_type, c.numeric, c.readable,
                            Decision("other", 0.0, "not_assessed", ["table_not_selected"]), None)
                for i, c in enumerate(t.columns)]
        st = TableState(t, cols)
        st.extra["row_count"] = reader.count_rows(t)
        docs.append(_table_doc(st, False))
    docs.sort(key=lambda d: d["slug"])
    return {
        "schema": DISCOVERY_SCHEMA,
        "method_version": DISCOVERY_METHOD,
        "source_id": source_id,
        "engine": reader.engine,
        "sample_rows": sample_rows,
        "overrides_sha256": sha256_hex(canonical_bytes({"column_overrides": overrides, "relations": case_rel})),
        "tables": docs,
        "totals": {
            "tables": len(docs),
            "tables_scanned": sum(1 for d in docs if d["scanned"]),
            "rows": sum(d["row_count"] or 0 for d in docs),
            "columns": sum(len(d["columns"]) for d in docs),
            "extract_tables": sum(1 for d in docs if d["extract"]),
        },
    }


def reader_stats(reader, table) -> dict:
    fn = getattr(reader, "table_stats", None)
    return dict(fn(table)) if fn else {}
