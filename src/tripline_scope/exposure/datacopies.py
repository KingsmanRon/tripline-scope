"""A3: uncontrolled patient-data copies (exports, extracts, reports, dumps and backups) in snapshot roots.

Tabular files (CSV/TSV, XLSX, JSON/JSONL, SQL text dumps) are profiled column by column: header names are mapped
to personal-information categories, and values are checked for valid South African ID numbers (13 digits, real
date, citizenship digit, Luhn check; ``core.identifiers``). A column counts as *confirmed* SA IDs only when most
values pass every check **and** the header or neighbouring columns give person context; a high pass rate without
context is reported as *probable*; 13-digit values that mostly fail the checks are never treated as IDs.

Only categories, rates, count bands, bounded estimates, age and location leave this module; no value does.
Binary backups and data files are recognised by format headers only and reported as opaque.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import re
import warnings
import zipfile
from dataclasses import dataclass, field

from tripline_scope.core.identifiers import normalise_email, parse_sa_id
from tripline_scope.core.redact import find_identifier_like

from .filetypes import basename
from .model import Finding, bump, count_band, size_band
from .secrets import location_likelihood
from .state import ScanState
from .walker import Item

DETECTOR = "exposure.datacopies/0.1.0"
_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_NONDIGIT = re.compile(r"[\s\-]")

ID_HEADERS = {"id", "idno", "idnumber", "idnum", "idnr", "said", "saidno", "saidnumber", "rsaid", "rsaidnumber",
              "identity", "identityno", "identitynumber", "identitynr", "nationalid", "nationalidnumber",
              "identification", "identificationnumber", "idpassport", "idorpassport", "patientidnumber",
              "patientidno", "memberidnumber", "idnumbers", "southafricanid"}
_NAME_SUB = ("surname", "firstname", "lastname", "fullname", "forename", "givenname", "patientname", "membername",
             "maidenname", "middlename", "firstnames", "christianname")
_DOB_SUB = ("dob", "dateofbirth", "birthdate", "birthday", "datebirth")
_CONTACT_SUB = ("phone", "cellphone", "mobile", "telephone", "email", "contactno", "contactnumber", "cellno", "cell")
_ADDRESS_SUB = ("address", "street", "suburb", "postalcode", "postcode")
_AID_SUB = ("medicalaid", "medaid", "scheme", "memberno", "membernumber", "dependant", "dependent", "policyno")
_CLIN_TOKENS = {"diagnosis", "icd", "icd10", "result", "results", "test", "tests", "testcode", "testname", "specimen",
                "pathology", "hiv", "viral", "cd4", "clinical", "notes", "procedure", "medication", "condition",
                "allergy", "allergies", "ward", "admission", "discharge", "histology", "cytology", "culture",
                "prescription", "dx"}
_KEY_SUB = ("mrn", "folderno", "foldernumber", "patientno", "patientnumber", "hospitalno", "hospitalnumber",
            "patientid", "patientref", "patientkey")
PERSON_CATEGORIES = {"name", "dob", "contact", "address", "medical_aid", "patient_key", "sa_id_header"}


def header_categories(h: str) -> set[str]:
    toks = [t.lower() for t in _SPLIT.split(h or "") if t]
    joined = "".join(toks)
    cats = set()
    if joined in ID_HEADERS or "idnumber" in joined or "identitynumber" in joined or joined.endswith("saidnumber"):
        cats.add("sa_id_header")
    if any(s in joined for s in _NAME_SUB) or joined in {"name", "names", "initials", "patient"}:
        cats.add("name")
    if any(s in joined for s in _DOB_SUB) or joined == "born":
        cats.add("dob")
    if any(s in joined for s in _CONTACT_SUB) or joined in {"tel", "telno", "cellno"}:
        cats.add("contact")
    if any(s in joined for s in _ADDRESS_SUB):
        cats.add("address")
    if any(s in joined for s in _AID_SUB):
        cats.add("medical_aid")
    if any(t in _CLIN_TOKENS for t in toks) or any(s in joined for s in ("diagnosis", "icd10", "testresult")):
        cats.add("clinical")
    if any(s in joined for s in _KEY_SUB):
        cats.add("patient_key")
    if joined in {"sex", "gender"}:
        cats.add("sex")
    return cats


def display_header(h, idx: int) -> str:
    s = str(h or "").strip()
    if not s or len(s) > 40 or find_identifier_like(s) or re.search(r"\d{6,}", s):
        return f"column {idx + 1}"
    return s


@dataclass
class ColumnProfile:
    name: str
    categories: set[str]
    nonempty: int = 0
    thirteen: int = 0
    valid_ids: int = 0
    emails: int = 0


@dataclass
class TableProfile:
    columns: list[ColumnProfile]
    rows: int = 0
    rows_inspected: int = 0
    count_complete: bool = True
    estimated_rows: int | None = None
    rows_with_valid_id: int = 0
    id_assessment: str = "none"
    id_columns: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)

    def finish(self) -> TableProfile:
        cats = set()
        for c in self.columns:
            cats |= c.categories
            if c.emails and c.emails >= 0.8 * max(c.nonempty, 1):
                cats.add("contact")
        person_context = bool(cats & PERSON_CATEGORIES)
        confirmed, probable, unconfirmed = [], [], []
        for c in self.columns:
            if c.nonempty == 0:
                continue
            rate = c.valid_ids / c.nonempty
            if c.valid_ids and rate >= 0.8:
                (confirmed if ("sa_id_header" in c.categories or person_context) else probable).append(c.name)
            elif c.thirteen / c.nonempty >= 0.5 or "sa_id_header" in c.categories:
                unconfirmed.append(c.name)
        if confirmed:
            self.id_assessment = "confirmed"
            self.id_columns = confirmed
        elif probable:
            self.id_assessment = "probable"
            self.id_columns = probable
        elif unconfirmed:
            self.id_assessment = "unconfirmed"
            self.id_columns = unconfirmed
        cats.discard("sa_id_header")
        if self.id_assessment in ("confirmed", "probable"):
            cats.add("identity_number")
        self.categories = cats
        return self


def _looks_header(row: list) -> bool:
    cells = [str(c).strip() for c in row if c is not None and str(c).strip()]
    if not cells:
        return False
    texty = sum(1 for c in cells if re.search(r"[A-Za-z]", c) and not re.fullmatch(r"[\d\s\-/.:]+", c))
    if any(parse_sa_id(c).valid or normalise_email(c) for c in cells):
        return False
    return texty >= max(1, 0.6 * len(cells))


def profile_rows(rows, *, max_inspect: int, max_rows: int, total_bytes: int | None = None, consumed=None) -> TableProfile:
    """Profile an iterator of rows (lists). The first row is used as header when it looks like one."""
    it = iter(rows)
    first = next(it, None)
    if first is None:
        return TableProfile([]).finish()
    has_header = _looks_header(list(first))
    width = len(first)
    if has_header:
        cols = [ColumnProfile(display_header(h, i), header_categories(str(h or ""))) for i, h in enumerate(first)]
        pending = []
    else:
        cols = [ColumnProfile(f"column {i + 1}", set()) for i in range(width)]
        pending = [first]
    prof = TableProfile(cols)

    def _row(r):
        nonlocal width
        prof.rows += 1
        if prof.rows_inspected >= max_inspect:
            return
        prof.rows_inspected += 1
        has_id = False
        for i, v in enumerate(r):
            if i >= len(prof.columns):
                prof.columns.append(ColumnProfile(f"column {i + 1}", set()))
            if v is None:
                continue
            s = str(v).strip()
            if not s:
                continue
            c = prof.columns[i]
            c.nonempty += 1
            d = _NONDIGIT.sub("", s)
            if len(d) == 13 and d.isdigit():
                c.thirteen += 1
                if parse_sa_id(d).valid:
                    c.valid_ids += 1
                    has_id = True
            elif "@" in s and normalise_email(s):
                c.emails += 1
        if has_id:
            prof.rows_with_valid_id += 1

    for r in pending:
        _row(r)
    for r in it:
        if prof.rows >= max_rows:
            prof.count_complete = False
            break
        _row(list(r))
    if not prof.count_complete and total_bytes and consumed:
        used = consumed()
        if used:
            prof.estimated_rows = int(prof.rows * total_bytes / used)
    return prof.finish()


def _sniff_delimiter(text: str, ext: str) -> str:
    if ext in (".tsv", ".tab"):
        return "\t"
    if ext == ".psv":
        return "|"
    line = text[:4096].split("\n", 1)[0]
    counts = {d: line.count(d) for d in (",", ";", "\t", "|")}
    best = max(counts, key=lambda d: counts[d])
    return best if counts[best] else ","


def profile_delimited(text: str, ext: str, budget: dict) -> TableProfile:
    buf = io.StringIO(text)
    reader = csv.reader(buf, delimiter=_sniff_delimiter(text, ext))
    return profile_rows(reader, max_inspect=budget["max_rows_inspected"], max_rows=budget["max_rows_per_file"],
                        total_bytes=len(text), consumed=buf.tell)


def _records(doc) -> list[dict]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        lists = [v for v in doc.values() if isinstance(v, list) and v and isinstance(v[0], dict)]
        if lists:
            return [r for r in max(lists, key=len) if isinstance(r, dict)]
        return [doc]
    return []


def _dict_rows(records: list[dict]):
    keys: list[str] = []
    for r in records[:500]:
        for k in r:
            if k not in keys:
                keys.append(k)
    yield keys
    for r in records:
        yield [None if isinstance(r.get(k), dict | list) else r.get(k) for k in keys]


def profile_json(text: str, budget: dict, *, lines: bool) -> TableProfile:
    if lines:
        recs = []
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    recs.append(obj)
    else:
        recs = _records(json.loads(text))
    if not recs:
        return TableProfile([]).finish()
    return profile_rows(_dict_rows(recs), max_inspect=budget["max_rows_inspected"],
                        max_rows=budget["max_rows_per_file"])


class ArchiveBomb(Exception):
    pass


def profile_xlsx(data: bytes, budget: dict) -> list[tuple[str, TableProfile]]:
    zf = zipfile.ZipFile(io.BytesIO(data))
    total = 0
    for info in zf.infolist():
        total += info.file_size
        if info.file_size / max(info.compress_size, 1) > budget["archive_max_ratio"] and info.file_size > (1 << 20):
            raise ArchiveBomb("compression ratio")
    if total > budget["archive_max_total_bytes"]:
        raise ArchiveBomb("decompressed size")
    import openpyxl

    out = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        try:
            for ws in wb.worksheets:
                prof = profile_rows(ws.iter_rows(values_only=True), max_inspect=budget["max_rows_inspected"],
                                    max_rows=budget["max_rows_per_file"])
                out.append((display_header(ws.title, len(out)) if ws.title else f"sheet {len(out) + 1}", prof))
        finally:
            wb.close()
    return out


_CREATE = re.compile(r"(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\[\]\"`]+)\s*\((.{0,20000}?)\)\s*;")
_THIRTEEN = re.compile(r"(?<!\d)\d{13}(?!\d)")


def profile_sql_dump(text: str, budget: dict) -> TableProfile:
    cols: list[ColumnProfile] = []
    for m in _CREATE.finditer(text[: 20 << 20]):
        for line in m.group(2).split(","):
            tok = line.strip().split(None, 1)
            if tok:
                name = tok[0].strip("[]\"`")
                if name.upper() in ("PRIMARY", "CONSTRAINT", "FOREIGN", "UNIQUE", "KEY", "INDEX", "CHECK"):
                    continue
                cols.append(ColumnProfile(display_header(name, len(cols)), header_categories(name)))
    prof = TableProfile(cols)
    id_col = ColumnProfile("values", set())
    in_copy = False
    for line in text.splitlines():
        if in_copy:
            if line.startswith("\\."):
                in_copy = False
                continue
            rows = 1
        elif line.lstrip().upper().startswith("INSERT INTO"):
            rows = max(1, line.count("),(") + line.count("), (") + 1)
        elif line.startswith("COPY ") and line.rstrip().endswith("FROM stdin;"):
            in_copy = True
            continue
        else:
            continue
        prof.rows += rows
        if prof.rows_inspected < budget["max_rows_inspected"]:
            prof.rows_inspected += rows
            hit = False
            for t in _THIRTEEN.findall(line):
                id_col.nonempty += 1
                id_col.thirteen += 1
                if parse_sa_id(t).valid:
                    id_col.valid_ids += 1
                    hit = True
            if hit:
                prof.rows_with_valid_id += 1
    if id_col.thirteen:
        id_col.categories = set()
        prof.columns.append(id_col)
    return prof.finish()


# ------------------------------------------------------------------------------------------ findings
BACKUP_FORMATS = {
    "mssql_backup": "SQL Server native backup (Microsoft Tape Format header)",
    "pg_custom_dump": "PostgreSQL custom-format dump (PGDMP header)",
    "mssql_data_file": "SQL Server data/log file (page header)",
    "oracle_export": "Oracle export dump (EXPORT header)",
}
_HINT = re.compile(r"(?i)(backup|bak|dump|export|extract|patient|lab|claims|results|db|sql|his|lis|ris|pacs)")


def _age(state: ScanState, item: Item) -> tuple[int | None, bool, str | None]:
    if item.mtime is None:
        return None, False, None
    mt = dt.datetime.fromtimestamp(item.mtime, dt.UTC)
    days = (state.m.as_of - mt).days
    return max(days, 0), days >= state.m.stale_after_days, mt.date().isoformat()


def _base_location(item: Item, sheet: str | None = None) -> dict:
    root_rel, _, member = item.rel.partition("!")
    from .walker import scrub_rel

    loc = {"type": "file", "root": item.root.id, "path": scrub_rel(root_rel), "member": scrub_rel(member) or None,
           "display": item.display}
    if sheet:
        loc["sheet"] = sheet
        loc["display"] = f"{item.display} [sheet {sheet}]"
    return loc


def copy_finding(state: ScanState, item: Item, fmt: str, prof: TableProfile, sheet: str | None = None) -> Finding | None:
    cats = prof.categories
    person = cats & {"identity_number", "name", "dob", "contact", "address", "medical_aid", "patient_key"}
    if not person:
        if prof.id_assessment == "unconfirmed":
            state.rec.count("A3", "files_with_13_digit_non_ids")
        return None
    clinical = "clinical" in cats
    ids = prof.id_assessment in ("confirmed", "probable")
    names = "name" in cats
    if clinical and (ids or names):
        sensitivity, impact = "special personal information (health) with identifiers", "high"
    elif ids:
        sensitivity, impact = "personal information with SA ID numbers", "high"
    elif names and cats & {"dob", "contact", "address", "medical_aid"}:
        sensitivity, impact = "personal information (names with dates of birth or contact details)", "medium"
    else:
        sensitivity, impact = "limited personal information", "low"
    rows = prof.rows if prof.count_complete else (prof.estimated_rows or prof.rows)
    if rows < 10 and impact == "high":
        impact = "medium"
    elif rows < 10:
        impact = "low"
    age_days, stale, mdate = _age(state, item)
    likelihood, lreason = location_likelihood(item.root.kind, item.rel)
    if item.root.kind == "web_root" and likelihood == "medium":
        likelihood = "high" if fmt in ("delimited", "json", "jsonl", "xlsx", "sql_dump") else likelihood
    if stale and likelihood == "low":
        likelihood = bump(likelihood)
    asset = state.root_asset(item.root)
    basis = "observation" if prof.id_assessment == "confirmed" or not ids else "inference"
    conf = 0.9 if prof.id_assessment == "confirmed" else 0.65 if prof.id_assessment == "probable" else 0.7
    fmt_label = {"delimited": "delimited text export", "json": "JSON export", "jsonl": "JSON Lines export",
                 "xlsx": "spreadsheet", "sql_dump": "SQL text dump"}.get(fmt, fmt)
    if ids:
        title = f"Patient-data copy with {'valid' if prof.id_assessment == 'confirmed' else 'probable'} SA ID numbers ({fmt_label})"
    else:
        title = f"Personal-information copy ({fmt_label})"
    caveats = ["Record counts are bands or bounded estimates; values were read transiently and are not reported.",
               "Presence of a copy does not mean it was accessed or exfiltrated."]
    if prof.id_assessment == "probable":
        caveats.append("ID-like values pass structure, date and Luhn checks but no column name or neighbouring "
                       "person data confirms they are SA ID numbers (labelled probable).")
    if not prof.count_complete:
        caveats.append("Row count stopped at the budget; the total is a bounded estimate.")
    details = {
        "format": fmt,
        "sensitivity": sensitivity,
        "categories": sorted(cats),
        "id_assessment": prof.id_assessment,
        "id_columns": prof.id_columns,
        "record_count_band": count_band(rows),
        "count_basis": "exact" if prof.count_complete else "bounded estimate",
        "rows_with_valid_sa_id_band": count_band(prof.rows_with_valid_id) + (
            " (in inspected rows)" if prof.rows_inspected < prof.rows else ""),
        "size_band": size_band(item.size),
        "modified_date": mdate,
        "age_days": age_days,
        "stale": stale,
        "stale_after_days": state.m.stale_after_days,
    }
    unit = item.unit
    f = Finding(
        control_id="A3", rule_id="A3.data-copy", title=title, impact=impact, likelihood=likelihood,
        rationale={"impact": f"{sensitivity}; {details['record_count_band']} records",
                   "likelihood": lreason + ("; stale copy (not modified for "
                                            f"{age_days} days) is likely outside current controls" if stale else "")},
        asset=asset, location=_base_location(item, sheet), coverage_unit=unit,
        id_parts=[item.root.id, item.rel, sheet], basis=basis, confidence=conf,
        confidence_reason={"confirmed": "valid SA ID numbers with person context",
                           "probable": "valid SA ID structure without column context"}.get(
            prof.id_assessment, "column names indicate personal information"),
        fix_action="remove-or-protect-copy", source_ids=[state.source_for.get(unit)] if state.source_for.get(unit) else [],
        evidence_ids=[state.evidence(unit, item.rel, sheet)], caveats=caveats, details=details,
        ownership=state.owner_for(item.root.owner, asset.get("asset_id")), detector=DETECTOR,
    )
    return state.add(f)


def backup_finding(state: ScanState, item: Item, kind: str) -> Finding:
    name = basename(item.rel)
    target = None
    stem = re.split(r"[_\-. ]", name)[0] if name else ""
    for cand in (stem, name.rsplit(".", 1)[0]):
        target = state.resolve_target(None, cand) if cand else None
        if target:
            break
    patient = state.is_patient_asset(target)
    impact = "high" if patient or target is None else "medium"
    likelihood, lreason = location_likelihood(item.root.kind, item.rel)
    age_days, stale, mdate = _age(state, item)
    asset = state.root_asset(item.root)
    unit = item.unit
    f = Finding(
        control_id="A3", rule_id="A3.database-backup", title=f"Database backup or data file outside controlled storage "
                                                             f"({BACKUP_FORMATS[kind].split(' (')[0]})",
        impact=impact, likelihood=likelihood,
        rationale={"impact": ("backup appears to belong to a patient-data store" if patient else
                              "opaque backup: contents not inspected; a hospital database backup normally holds "
                              "patient data" if target is None else "backup of a non-patient system"),
                   "likelihood": lreason},
        asset=asset, target_asset=target, location=_base_location(item), coverage_unit=unit,
        id_parts=[item.root.id, item.rel], basis="observation", confidence=0.9,
        confidence_reason="format recognised from the file header", fix_action="remove-or-protect-copy",
        source_ids=[state.source_for.get(unit)] if state.source_for.get(unit) else [],
        evidence_ids=[state.evidence(unit, item.rel)],
        caveats=["Detected by format header only; the contents were not opened or restored.",
                 "Sensitivity is inferred from the format and name, not observed."],
        details={"format": BACKUP_FORMATS[kind], "sensitivity": "unknown (opaque format)", "size_band": size_band(item.size),
                 "modified_date": mdate, "age_days": age_days, "stale": stale,
                 "target_inferred_from": "file name" if target else None},
        ownership=state.owner_for(item.root.owner, asset.get("asset_id")), detector=DETECTOR,
    )
    return state.add(f)


def opaque_archive_finding(state: ScanState, item: Item, kind: str) -> Finding | None:
    name = basename(item.rel)
    if not _HINT.search(name):
        return None
    likelihood, lreason = location_likelihood(item.root.kind, item.rel)
    age_days, stale, mdate = _age(state, item)
    asset = state.root_asset(item.root)
    unit = item.unit
    f = Finding(
        control_id="A3", rule_id="A3.opaque-archive", title=f"Opaque archive that may hold an extract ({kind})",
        impact="medium", likelihood=likelihood,
        rationale={"impact": "archive name suggests a data extract or backup; contents could not be inspected",
                   "likelihood": lreason},
        asset=asset, location=_base_location(item), coverage_unit=unit, id_parts=[item.root.id, item.rel],
        basis="unknown", confidence=0.4, confidence_reason="name hint only; format not supported for inspection",
        fix_action="remove-or-protect-copy",
        source_ids=[state.source_for.get(unit)] if state.source_for.get(unit) else [],
        evidence_ids=[state.evidence(unit, item.rel)],
        caveats=["Contents not inspected (unsupported or encrypted archive format); sensitivity unknown."],
        details={"format": kind, "sensitivity": "unknown", "size_band": size_band(item.size), "modified_date": mdate,
                 "age_days": age_days, "stale": stale},
        ownership=state.owner_for(item.root.owner, asset.get("asset_id")), detector=DETECTOR,
    )
    return state.add(f)
