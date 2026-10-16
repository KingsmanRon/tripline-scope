"""File exports (CSV / TSV / XLSX / JSONL / JSON) through discovery and extraction."""

import json

import ingest_helpers as H
import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.ingest.extract import read_extract


@pytest.fixture
def op_case(case_dir):
    testing.login("olivia")
    return case_dir


def _store(case_dir):
    case = Case(case_dir)
    return case, open_store(case, Home())


def _cols(doc, slug):
    t = next(t for t in doc["tables"] if t["slug"] == slug)
    return t, {c["name"]: c for c in t["columns"]}


def test_csv_ingest_end_to_end(op_case, tmp_path):
    data = H.make_dataset(200)
    paths = [H.write_csv(tmp_path / "exp" / f"{name}.csv", rows) for name, rows in data.items()]
    sid = H.add_source(op_case, paths, "csv")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(op_case)])
    assert rc == 0, err
    res = json.loads(out)
    assert res["source_checksums_unchanged"] is True
    st = res["sources"][0]
    assert st["source_id"] == sid and st["tables"] == 4
    case, store = _store(op_case)
    doc = store.read_json(f"work/discovery/{sid}.json")
    t, cols = _cols(doc, "patients")
    assert t["role"] == "identity" and t["patient_key"] == "PatientID"
    expect = {"FirstNames": "first_name", "Surname": "last_name", "IDNumber": "sa_id", "DateOfBirth": "dob",
              "Gender": "sex", "CellNo": "phone", "Email": "email", "Address1": "address", "Suburb": "address",
              "PostalCode": "postal_code", "MedAidNo": "medical_aid_no", "Scheme": "medical_aid_scheme",
              "PatientID": "patient_key"}
    for name, cat in expect.items():
        assert cols[name]["category"] == cat, (name, cols[name])
    assert cols["IDNumber"]["match_rate"] == 1.0 and 0.03 < cols["IDNumber"]["null_rate"] < 0.06
    t, cols = _cols(doc, "results")
    assert t["role"] == "dependent"
    assert t["relations"][0]["identity_table"] == "patients" and t["relations"][0]["containment"] == 1.0
    assert cols["ICD10"]["category"] == "icd10" and cols["Notes"]["category"] == "clinical_free_text"
    assert cols["TestCode"]["category"] == "test_code" and cols["Result"]["category"] == "test_result"
    assert cols["CollectedDate"]["category"] == "record_date"
    t, cols = _cols(doc, "billing")
    assert cols["CardNumber"]["category"] == "card_number" and cols["BankAccountNo"]["category"] == "bank_account"
    t, cols = _cols(doc, "misc")
    assert cols["Ref13"]["category"] != "sa_id" and cols["BatchCode"]["category"] not in ("sa_id", "card_number")
    assert cols["Token16"]["category"] != "card_number"
    assert t["role"] == "other" and not t["extract"]

    ext = read_extract(store, sid, "patients").to_pylist()
    assert len(ext) == 200
    first = ext[0]
    assert first["_row_key"] == f"{sid}|patients|0" and first["sa_id"] and first["phone"].startswith("+27")
    assert first["_has_identity_number"] and first["_has_contact_details"] and first["_has_medical_aid"]
    assert first["dob"] is not None and first["email"] == first["email"].lower()
    res_rows = read_extract(store, sid, "results").to_pylist()
    assert len(res_rows) == len(data["results"])
    assert all(r["patient_ref"] for r in res_rows) and all(r["_has_clinical_results"] for r in res_rows)
    assert all(r["_has_clinical_notes"] and r["_has_clinical_diagnosis"] for r in res_rows)
    bill = read_extract(store, sid, "billing").to_pylist()
    assert all(r["_has_payment_card"] and r["_has_bank_account"] for r in bill)
    m = store.read_json(f"work/extract/{sid}/manifest.json")
    misc = next(e for e in m["tables"] if e["slug"] == "misc")
    assert misc["row_count"] == 200 and not misc["extracted"]
