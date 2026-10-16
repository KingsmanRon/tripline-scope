"""Discovery precision on mixed columns, including negative cases, overrides, relations and full-scan demotion."""

import datetime as dt
import random

import ingest_helpers as H
import pytest

from tripline_scope.core.errors import ConfigError
from tripline_scope.core.identifiers import make_sa_id
from tripline_scope.discovery.engine import discover
from tripline_scope.discovery.hints import name_hint
from tripline_scope.ingest.model import ColumnInfo, TableRef, batch_from_columns


class ListReader:
    """In-memory reader over {table: {column: [values]}} for discovery unit tests."""

    engine = "memory"

    def __init__(self, tables: dict[str, dict[str, list]], numeric: set[str] = frozenset()):
        self._data = tables
        self._numeric = numeric

    def tables(self):
        return [TableRef(name, [ColumnInfo(c, numeric=f"{name}.{c}" in self._numeric) for c in cols], kind="file")
                for name, cols in self._data.items()]

    def iter_batches(self, table, batch_rows, limit=None):
        cols = list(self._data[table.name].values())
        n = len(cols[0]) if cols else 0
        if limit is not None:
            n = min(n, limit)
        for s in range(0, n, batch_rows):
            yield batch_from_columns([[None if v is None else str(v) for v in c[s:s + batch_rows]] for c in cols],
                                     len(cols))

    def count_rows(self, table):
        return len(next(iter(self._data[table.name].values())))

    def close(self):
        pass


def _cats(doc, table):
    t = next(t for t in doc["tables"] if t["name"] == table)
    return {c["name"]: c for c in t["columns"]}


def _run(tables, config=None, **kw):
    return discover(ListReader(tables, kw.pop("numeric", set())), source_id="SRC-009",
                    case_config=config or {}, **kw)


def _ids(rng, n):
    return [make_sa_id(dt.date(1950, 1, 1) + dt.timedelta(days=rng.randrange(0, 25000)), rng.randrange(10000))
            for _ in range(n)]


def test_negative_cases_and_context():
    rng = random.Random(1)
    n = 400
    tables = {"mixed": {
        "col_a": _ids(rng, n),                                              # valid IDs, no name hint
        "Ref13": [str(rng.randrange(10**12, 10**13)) for _ in range(n)],   # arbitrary 13-digit numbers
        "Code13": [H.luhn_random(rng, 13) for _ in range(n)],              # Luhn-valid 13-digit, no context
        "Num16": [H.luhn_random(rng, 16) for _ in range(n)],               # Luhn-valid 16-digit, random prefix
        "ref_x": [H.card_number(rng) for _ in range(n)],                   # card numbers without a hint
        "Remarks2": [" ".join(rng.choice(H.NOTE_WORDS) for _ in range(9)) for _ in range(n)],
        "blob_text": [" ".join(rng.choice(H.NOTE_WORDS) for _ in range(9)) for _ in range(n)],
        "ward": [rng.choice(["A1", "B2", "ICU"]) for _ in range(n)],
        "id_number": [v if i % 3 else "UNKNOWN" for i, v in enumerate(_ids(rng, n))],   # hinted, dirty
        "IDNo": [str(rng.randrange(10**12, 10**13)) for _ in range(n)],    # hinted but not SA IDs
    }}
    c = _cats(_run(tables), "mixed")
    assert c["col_a"]["category"] == "sa_id" and c["col_a"]["basis"] == "values"
    assert c["col_a"]["confidence"] == 0.85 and c["id_number"]["confidence"] == 0.9   # hint + values > values
    assert c["Ref13"]["category"] == "other_identifier"
    assert c["Code13"]["category"] == "other_identifier"
    assert c["Num16"]["category"] == "other_identifier"
    assert c["ref_x"]["category"] == "card_number" and c["ref_x"]["extracted"] is False
    assert c["Remarks2"]["category"] == "clinical_free_text"
    assert c["blob_text"]["category"] == "clinical_free_text" and c["blob_text"]["confidence"] == 0.5
    assert c["ward"]["category"] == "other"
    assert c["id_number"]["category"] == "sa_id" and 0.6 < c["id_number"]["match_rate"] < 0.7
    assert c["IDNo"]["category"] == "other_identifier"
    for col in c.values():
        assert 0 <= col["confidence"] <= 1 and col["null_rate"] is not None


def test_full_scan_demotes_biased_sample():
    rng = random.Random(2)
    # first 100 rows look like SA IDs, the remaining 900 are other 13-digit numbers
    vals = _ids(rng, 100) + [str(rng.randrange(10**12, 10**13)) for _ in range(900)]
    doc = _run({"t": {"x": vals, "y": list(range(1000))}}, sample_rows=100, batch_rows=128)
    c = _cats(doc, "t")["x"]
    assert c["category"] == "other_identifier" and any("demoted" in r for r in c["reasons"])
    assert c["sample_match_rate"] is None or c["sample_match_rate"] <= 1.0


def test_overrides_and_relations_win():
    rng = random.Random(3)
    n = 60
    ids = _ids(rng, n)
    tables = {
        "people": {"k": [f"K{i}" for i in range(n)], "nm": [rng.choice(H.LAST) for _ in range(n)],
                   "geb": [f"{1950 + i % 50}-01-0{1 + i % 9}" for i in range(n)], "ident": ids,
                   "secret_col": [H.card_number(rng) for _ in range(n)]},
        "visits": {"who": [f"K{i % n}" for i in range(2 * n)], "when": ["2026-02-01"] * (2 * n)},
    }
    config = {
        "column_overrides": {"SRC-009": {"people": {"nm": "last_name", "geb": "dob", "secret_col": "other"},
                                         "visits": {"when": "record_date"}}},
        "relations": [{"source": "SRC-009", "table": "visits", "column": "who",
                       "references": {"table": "people", "column": "k"}}],
    }
    doc = _run(tables, config)
    p = _cats(doc, "people")
    assert p["nm"]["category"] == "last_name" and p["nm"]["override"] is True and p["nm"]["confidence"] == 1.0
    assert p["secret_col"]["category"] == "other"         # override wins even over card detection
    assert p["k"]["category"] == "patient_key"
    v = next(t for t in doc["tables"] if t["name"] == "visits")
    assert v["role"] == "dependent" and v["relations"][0]["basis"] == "case.yaml"
    assert v["relations"][0]["containment"] == 1.0
    people = next(t for t in doc["tables"] if t["name"] == "people")
    assert people["role"] == "identity" and people["patient_key"] == "k"
    with pytest.raises(ConfigError):
        _run(tables, {"column_overrides": {"SRC-009": {"people": {"nm": "not_a_category"}}}})
    with pytest.raises(ConfigError):
        _run(tables, {"column_overrides": {"SRC-009": {"people": {"missing": "sa_id"}}}})


def test_names_surname_layout_and_full_name_split():
    rng = random.Random(4)
    n = 50
    tables = {"a": {"Names": [rng.choice(H.FIRST) for _ in range(n)], "Surname": [rng.choice(H.LAST) for _ in range(n)],
                    "DOB": ["1980-02-03"] * n},
              "b": {"patient_name": [f"{rng.choice(H.LAST)}, {rng.choice(H.FIRST)}" for _ in range(n)],
                    "birth_date": ["03/02/1980"] * n}}
    doc = _run(tables)
    assert _cats(doc, "a")["Names"]["category"] == "first_name"
    b = _cats(doc, "b")
    assert b["patient_name"]["category"] == "full_name" and b["birth_date"]["date_parser"] == "dmy"


def test_numeric_ids_with_dropped_leading_zeros():
    ids = [make_sa_id(dt.date(2000, 1, 1 + i % 28), i) for i in range(40)] + \
          [make_sa_id(dt.date(2004, 5, 1 + i % 28), i) for i in range(40)]
    nums = [str(int(x)) for x in ids]
    doc = _run({"p": {"national": nums}}, numeric={"p.national"})
    c = _cats(doc, "p")["national"]
    assert c["category"] == "sa_id" and c["id_pad"] is True and c["match_rate"] == 1.0


@pytest.mark.parametrize("name,table,expected", [
    ("id_number", "", "sa_id"), ("idno", "", "sa_id"), ("rsa_id", "", "sa_id"), ("surname", "", "last_name"),
    ("cell", "", "phone"), ("med_aid_no", "", "medical_aid_no"), ("scheme", "", "medical_aid_scheme"),
    ("folder_no", "", "patient_key"), ("mrn", "", "patient_key"), ("NextOfKinTel", "", "guardian_phone"),
    ("ResultID", "results", "other_identifier"), ("value", "lab_results", "test_result"),
    ("value", "billing", None), ("invoice_no", "", "other_identifier"), ("ip_address", "", "not_address"),
    ("account_no", "", "other_identifier"), ("bank_acc_no", "", "bank_account"), ("CardNo", "", "card_number"),
    ("date_of_birth", "", "dob"), ("admission_date", "", "record_date"), ("ICD10Code", "", "icd10"),
])
def test_name_hints(name, table, expected):
    assert name_hint(name, table) == expected
