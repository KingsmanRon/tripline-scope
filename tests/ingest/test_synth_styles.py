"""Regression: discovery and extraction on the five column-naming styles (A-E) of the synthetic lab estate.

Column names mirror ``tripline_scope.synth.schema.STYLES`` (Module C); value formats mirror its generator
(grouped IDs, day-first / compact dates, M/F, Male/Female or ISO 5218 1/2 sex codes, six phone formats, sparse
guardian and passport columns). Every column must land in the expected category and standard-field slot, and
extraction must never fill one column's gaps with another column's values.
"""

import datetime as dt
import random

import ingest_helpers as H
import pyarrow as pa
import pytest
from ingest_helpers import ListReader

from tripline_scope.core import duck
from tripline_scope.core.identifiers import make_sa_id
from tripline_scope.discovery.engine import discover
from tripline_scope.ingest.extract import SCHEMA, build_sql

STYLES = {
    "A": {"name_format": "split", "dob_format": "date", "sex_format": "MF", "id_format": "plain",
          "patients": {"local_patient_key": "patient_id", "sa_id": "id_number", "first_name": "first_name",
                       "middle_names": "middle_name", "last_name": "surname", "maiden_name": "maiden_name",
                       "dob": "date_of_birth", "sex": "sex", "phone": "cell_phone", "email": "email",
                       "address": "address_line", "postal_code": "postal_code", "medical_aid_no": "medical_aid_no",
                       "language": "home_language", "guardian_name": "guardian_name",
                       "guardian_phone": "guardian_phone", "guardian_sa_id": "guardian_id_number",
                       "passport_no": "passport_no", "record_date": "registered_on"},
          "admissions": {"key": "admission_id", "patient_ref": "patient_id", "record_date": "admit_date",
                         "discharge": "discharge_date", "ward": "ward", "icd10": "icd10_code", "note": "clinical_note"},
          "billing": {"key": "invoice_id", "patient_ref": "patient_id", "admission_ref": "admission_id",
                      "record_date": "invoice_date", "amount": "amount", "medical_aid_no": "medical_aid_no",
                      "card_number": "card_number", "bank_account": "bank_account"},
          "results": {"key": "result_id", "admission_ref": "admission_id", "patient_ref": "patient_id",
                      "record_date": "collected_on", "test_code": "test_code", "status": "status"}},
    "B": {"name_format": "given_names", "dob_format": "date", "sex_format": "MaleFemale", "id_format": "plain",
          "patients": {"local_patient_key": "pat_no", "sa_id": "sa_id_no", "first_name": "given_names",
                       "last_name": "last_name", "maiden_name": "maiden_surname", "dob": "dob", "sex": "gender",
                       "phone": "mobile", "email": "email_address", "address": "street_address",
                       "postal_code": "post_code", "medical_aid_no": "scheme_member_no",
                       "guardian_name": "next_of_kin", "guardian_phone": "nok_contact", "passport_no": "passport",
                       "record_date": "created_date"},
          "admissions": {"key": "adm_no", "patient_ref": "pat_no", "record_date": "admitted",
                         "discharge": "discharged", "ward": "ward_code", "icd10": "diagnosis_code", "note": "notes"},
          "billing": {"key": "bill_no", "patient_ref": "pat_no", "admission_ref": "adm_no", "record_date": "billed_on",
                      "amount": "total", "medical_aid_no": "scheme_member_no", "card_number": "payment_card",
                      "bank_account": "account_no"},
          "results": {"key": "res_id", "admission_ref": "adm_no", "patient_ref": "pat_no",
                      "record_date": "specimen_date", "test_code": "test", "status": "result_status"}},
    "C": {"name_format": "full_name_comma", "dob_format": "%d/%m/%Y", "sex_format": "12", "id_format": "grouped",
          "patients": {"local_patient_key": "mrn", "sa_id": "identity_no", "full_name": "patient_name",
                       "dob": "birth_date", "sex": "sex_code", "phone": "contact_no", "email": "email",
                       "address": "physical_address", "postal_code": "postal", "medical_aid_no": "med_aid_number",
                       "language": "lang", "guardian_name": "parent_guardian", "guardian_phone": "parent_contact",
                       "passport_no": "foreign_id", "record_date": "reg_date"},
          "admissions": {"key": "visit_id", "patient_ref": "mrn", "record_date": "visit_date",
                         "discharge": "end_date", "ward": "unit", "icd10": "icd10", "note": "comment"},
          "billing": {"key": "txn_id", "patient_ref": "mrn", "admission_ref": "visit_id", "record_date": "txn_date",
                      "amount": "amount_zar", "medical_aid_no": "med_aid_number", "card_number": "cc_number",
                      "bank_account": "bank_acc"},
          "results": {"key": "lab_no", "admission_ref": "visit_id", "patient_ref": "mrn", "record_date": "collected",
                      "test_code": "test_cd", "status": "state"}},
    "D": {"name_format": "split", "dob_format": "%Y%m%d", "sex_format": "MF", "id_format": "plain",
          "patients": {"local_patient_key": "PatientKey", "sa_id": "IDNo", "first_name": "FirstName",
                       "middle_names": "MiddleNames", "last_name": "LastName", "maiden_name": "MaidenName",
                       "dob": "DOB", "sex": "Gender", "phone": "Phone", "phone_alt": "AltPhone", "email": "Email",
                       "address": "Address", "postal_code": "PostalCode", "medical_aid_no": "MedicalAidNo",
                       "language": "PreferredLanguage", "guardian_name": "GuardianName",
                       "guardian_phone": "GuardianPhone", "passport_no": "PassportNo", "record_date": "CreatedOn"},
          "admissions": {"key": "AdmissionKey", "patient_ref": "PatientKey", "record_date": "AdmitDate",
                         "discharge": "DischargeDate", "ward": "Ward", "icd10": "PrimaryICD10", "note": "Note"},
          "billing": {"key": "InvoiceKey", "patient_ref": "PatientKey", "admission_ref": "AdmissionKey",
                      "record_date": "InvoiceDate", "amount": "Amount", "medical_aid_no": "MedicalAidNo",
                      "card_number": "CardNo", "bank_account": "BankAccountNo"},
          "results": {"key": "ResultKey", "admission_ref": "AdmissionKey", "patient_ref": "PatientKey",
                      "record_date": "CollectedOn", "test_code": "TestCode", "status": "Status"}},
    "E": {"name_format": "split", "dob_format": "date", "sex_format": "MF", "id_format": "plain",
          "patients": {"local_patient_key": "client_ref", "sa_id": "rsa_id", "first_name": "forename",
                       "middle_names": "other_names", "last_name": "family_name", "maiden_name": "birth_surname",
                       "dob": "birthdate", "sex": "sex", "phone": "tel", "email": "e_mail", "address": "addr",
                       "postal_code": "zip", "medical_aid_no": "member_no", "language": "language",
                       "guardian_name": "guardian", "guardian_phone": "guardian_tel",
                       "guardian_sa_id": "guardian_rsa_id", "passport_no": "passport_number", "record_date": "opened"},
          "admissions": {"key": "episode_id", "patient_ref": "client_ref", "record_date": "episode_start",
                         "discharge": "episode_end", "ward": "location", "icd10": "dx_code", "note": "free_text"},
          "billing": {"key": "claim_id", "patient_ref": "client_ref", "admission_ref": "episode_id",
                      "record_date": "claim_date", "amount": "claim_amount", "medical_aid_no": "member_no",
                      "card_number": "card_pan", "bank_account": "debit_account"},
          "results": {"key": "order_id", "admission_ref": "episode_id", "patient_ref": "client_ref",
                      "record_date": "order_date", "test_code": "order_code", "status": "order_status"}},
}
try:  # use Module C's definitions when they are present, so the two never drift apart
    from tripline_scope.synth.schema import STYLES as _SYNTH

    STYLES = {k: {kk: vv for kk, vv in v.items() if kk in STYLES[k]} for k, v in _SYNTH.items()}
except ImportError:
    pass

# standard field -> (category, standard_field slot); dependent-table fields -> acceptable categories
PATIENT_EXPECT = {
    "local_patient_key": ("patient_key", "local_patient_key"), "sa_id": ("sa_id", "sa_id"),
    "first_name": ("first_name", "first_name"), "middle_names": ("first_name", "middle_names"),
    "last_name": ("last_name", "last_name"), "maiden_name": ("maiden_name", "maiden_name"),
    "full_name": ("full_name", "full_name"), "dob": ("dob", "dob"), "sex": ("sex", "sex"),
    "phone": ("phone", "phone"), "phone_alt": ("phone", "phone_alt"), "email": ("email", "email"),
    "address": ("address", "address"), "postal_code": ("postal_code", "postal_code"),
    "medical_aid_no": ("medical_aid_no", "medical_aid_no"), "language": ("language", "language"),
    "guardian_name": ("guardian_name", "guardian_name"), "guardian_phone": ("guardian_phone", "guardian_phone"),
    "guardian_sa_id": ("guardian_sa_id", "guardian_sa_id"), "passport_no": ("passport", "passport_no"),
    "record_date": ("record_date", "record_date"),
}
DEP_EXPECT = {
    "icd10": {"icd10"}, "note": {"clinical_free_text"}, "test_code": {"test_code"}, "card_number": {"card_number"},
    "bank_account": {"bank_account"}, "medical_aid_no": {"medical_aid_no"}, "status": {"other"},
    "ward": {"other", "other_identifier"}, "amount": {"other"}, "discharge": {"record_date"},
    "record_date": {"record_date"}, "key": {"other", "other_identifier"},
    "admission_ref": {"other", "other_identifier"}, "patient_ref": {"patient_ref"},
}


def _phone(rng, digits=None):
    d = digits or f"0{rng.choice('678')}{rng.randrange(1, 10)}{rng.randrange(10**7):07d}"
    v = rng.randrange(6)
    return [d, f"{d[:3]} {d[3:6]} {d[6:]}", "+27" + d[1:], f"+27 {d[1:3]} {d[3:6]} {d[6:]}", "27" + d[1:],
            f"({d[:3]}) {d[3:6]}-{d[6:]}"][v], d


def _case(s, mode, rng):
    if s is None:
        return None
    if mode == "upper" or (mode == "mixed" and rng.random() < 0.5):
        return s.upper()
    return " ".join(w if w in ("van", "der", "du", "de", "le") else w[:1].upper() + w[1:].lower() for w in s.split())


def make_style_tables(style: str, n: int = 300, seed: int = 5) -> dict:
    st = STYLES[style]
    rng = random.Random(seed + ord(style))
    case_mode = {"A": "upper", "B": "title", "C": "upper", "D": "title", "E": "mixed"}[style]
    pats = []
    for i in range(1, n + 1):
        minor = rng.random() < 0.15
        dob = (dt.date(2012, 1, 1) if minor else dt.date(1945, 1, 1)) + dt.timedelta(days=rng.randrange(0, 365 * 12))
        female = rng.random() < 0.5
        foreign = rng.random() < 0.06
        sid = None if (minor or foreign) else make_sa_id(dob, rng.randrange(10000))
        first, middle, last = rng.choice(H.FIRST), rng.choice([None, None, "Grace", "Thabo", "Marie"]), rng.choice(H.LAST)
        phone, _ = _phone(rng)
        gphone, _ = _phone(rng)
        rec = {
            "local_patient_key": f"P{i:06d}" if style in "ACE" else i,
            "sa_id": (f"{sid[:6]} {sid[6:10]} {sid[10:]}" if st["id_format"] == "grouped" else sid) if sid else None,
            "first_name": _case(f"{first} {middle}" if st["name_format"] == "given_names" and middle else first,
                                case_mode, rng),
            "middle_names": _case(middle, case_mode, rng),
            "last_name": _case(last, case_mode, rng),
            "maiden_name": _case(rng.choice(H.LAST), case_mode, rng) if female and rng.random() < 0.3 else None,
            "full_name": _case(f"{last}, {first}" + (f" {middle}" if middle else ""), case_mode, rng),
            "dob": dob.isoformat() if st["dob_format"] == "date" else dob.strftime(st["dob_format"]),
            "sex": {"MF": "F" if female else "M", "MaleFemale": "Female" if female else "Male",
                    "12": "2" if female else "1"}[st["sex_format"]],
            "phone": None if rng.random() < 0.12 else phone,
            "phone_alt": _phone(rng)[0] if rng.random() < 0.1 else None,
            "email": f"{first.lower()}{i}@example.org" if rng.random() < 0.7 else None,
            "address": f"{rng.randrange(1, 400)} {rng.choice(['Church', 'Main', 'Long'])} Street",
            "postal_code": f"{rng.randrange(1, 9999):04d}",
            "medical_aid_no": f"{rng.randrange(10**8, 10**9)}" if rng.random() < 0.6 else None,
            "language": rng.choice(["English", "isiZulu", "Afrikaans", "Sesotho"]),
            "guardian_name": _case(f"{rng.choice(H.FIRST)} {last}", case_mode, rng) if minor else None,
            "guardian_phone": gphone if minor else None,
            "guardian_sa_id": make_sa_id(dt.date(1980, 5, 5), rng.randrange(10000)) if minor else None,
            "passport_no": f"{chr(65 + rng.randrange(26))}{chr(65 + rng.randrange(26))}{rng.randrange(10**7):07d}"
                           if foreign else None,
            "record_date": (dt.date(2020, 1, 1) + dt.timedelta(days=rng.randrange(0, 2000))).isoformat(),
        }
        pats.append(rec)
    keys = [p["local_patient_key"] for p in pats]
    adm, bill, res = [], [], []
    for j in range(2 * n):
        pk = keys[j % n]
        d0 = dt.date(2026, 1, 1) + dt.timedelta(days=j % 200)
        adm.append({"key": 1000 + j, "patient_ref": pk, "record_date": d0.isoformat(),
                    "discharge": (d0 + dt.timedelta(days=3)).isoformat() if j % 5 else None,
                    "ward": rng.choice(["MED", "SURG", "ICU", "MAT"]), "icd10": rng.choice(H.ICD),
                    "note": " ".join(rng.choice(H.NOTE_WORDS) for _ in range(8))})
        bill.append({"key": 5000 + j, "patient_ref": pk, "admission_ref": 1000 + j, "record_date": d0.isoformat(),
                     "amount": f"{rng.uniform(100, 25000):.2f}", "medical_aid_no": f"{rng.randrange(10**8, 10**9)}",
                     "card_number": H.card_number(rng), "bank_account": f"{rng.randrange(10**9, 10**10)}"})
        res.append({"key": 9000 + j, "admission_ref": 1000 + j, "patient_ref": pk, "record_date": d0.isoformat(),
                    "test_code": rng.choice(["HB", "FBC", "CRP", "TSH"]),
                    "status": rng.choice(["final", "pending", "amended"])})

    def table(spec, rows):
        return {col: [r.get(field) for r in rows] for field, col in spec.items()}

    return {"patients": table(st["patients"], pats), "admissions": table(st["admissions"], adm),
            "billing": table(st["billing"], bill), "results": table(st["results"], res)}, pats


@pytest.mark.parametrize("style", ["A", "B", "C", "D", "E"])
def test_style_columns_map_to_expected_fields(style):
    tables, _ = make_style_tables(style)
    doc = discover(ListReader(tables), source_id="SRC-001", case_config={})
    st = STYLES[style]
    by_table = {t["name"]: {c["name"]: c for c in t["columns"]} for t in doc["tables"]}
    wrong = []
    for field, col in st["patients"].items():
        c = by_table["patients"][col]
        if (c["category"], c["standard_field"]) != PATIENT_EXPECT[field]:
            wrong.append(f"patients.{col}: {c['category']}/{c['standard_field']} (want {PATIENT_EXPECT[field]})")
    for tname in ("admissions", "billing", "results"):
        for field, col in st[tname].items():
            c = by_table[tname][col]
            if c["category"] not in DEP_EXPECT[field]:
                wrong.append(f"{tname}.{col}: {c['category']} (want {sorted(DEP_EXPECT[field])})")
    assert not wrong, wrong
    roles = {t["name"]: t["role"] for t in doc["tables"]}
    assert roles == {"patients": "identity", "admissions": "dependent", "billing": "dependent",
                     "results": "dependent"}
    pt = next(t for t in doc["tables"] if t["name"] == "patients")
    assert pt["patient_key"] == st["patients"]["local_patient_key"]
    # one column per standard field: no field is fed by two columns
    assert all(len(v) == 1 for k, v in pt["fields"].items() if k != "address"), pt["fields"]


@pytest.mark.parametrize("style", ["A", "B", "C", "D", "E"])
def test_style_extraction_never_fills_between_columns(style):
    tables, pats = make_style_tables(style)
    doc = discover(ListReader(tables), source_id="SRC-001", case_config={})
    pt = next(t for t in doc["tables"] if t["name"] == "patients")
    cols = list(tables["patients"])
    arrays = [pa.array([None if v is None else str(v) for v in tables["patients"][c]], pa.string()) for c in cols]
    batch = pa.table(arrays + [pa.array(range(1, len(pats) + 1), pa.int64())],
                     names=[f"c{i}" for i in range(len(cols))] + ["_ord"])
    con = duck.connect()
    con.register("batch", batch)
    rows = con.execute(build_sql("SRC-001", pt)).to_arrow_table().cast(SCHEMA).to_pylist()
    from tripline_scope.core.identifiers import normalise_phone

    for src, out in zip(pats, rows, strict=True):
        # the patient's phone comes only from the patient's phone column (never the guardian's or the alt column)
        assert out["phone"] == (normalise_phone(src["phone"]) if src["phone"] else None)
        if "guardian_phone" in STYLES[style]["patients"]:
            assert out["guardian_phone"] == (normalise_phone(src["guardian_phone"]) if src["guardian_phone"] else None)
        if "phone_alt" in STYLES[style]["patients"]:
            assert out["phone_alt"] == (normalise_phone(src["phone_alt"]) if src["phone_alt"] else None)
        else:
            assert out["phone_alt"] is None
        assert out["sex"] == ("F" if src["sex"] in ("F", "Female", "2") else "M")
        if "passport_no" in STYLES[style]["patients"]:
            assert out["passport_no"] == src["passport_no"]
        if style == "E":
            assert out["first_name"] == src["first_name"].upper()
            assert out["middle_names"] == (src["middle_names"].upper() if src["middle_names"] else None)
            assert out["full_name"] is None
        if style == "C":
            assert out["full_name"] and out["last_name"] == src["last_name"].upper().replace(" ", " ")
        assert (out["sa_id"] is not None) == (src["sa_id"] is not None)
