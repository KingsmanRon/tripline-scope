"""A3 profiling: SA ID validation with context, 13-digit non-IDs, count bands, formats, malformed input."""

import datetime as dt
import io
import json
import random

import pytest

from tripline_scope.core.identifiers import make_sa_id, parse_sa_id
from tripline_scope.exposure.datacopies import (
    header_categories,
    profile_delimited,
    profile_json,
    profile_sql_dump,
    profile_xlsx,
)
from tripline_scope.exposure.manifest import DEFAULT_BUDGET
from tripline_scope.exposure.model import count_band

R = random.Random(5)
B = dict(DEFAULT_BUDGET)


def sid():
    return make_sa_id(dt.date(1950, 1, 1) + dt.timedelta(days=R.randrange(25000)), R.randrange(10000))


def non_id():
    while True:
        v = "".join(R.choice("0123456789") for _ in range(13))
        if not parse_sa_id(v).valid:
            return v


def csv_text(rows):
    return "\n".join(",".join(map(str, r)) for r in rows) + "\n"


def test_confirmed_ids_with_header():
    p = profile_delimited(csv_text([["ID Number", "Surname"]] + [[sid(), "Nkosi"] for _ in range(50)]), ".csv", B)
    assert p.id_assessment == "confirmed" and "identity_number" in p.categories and p.rows == 50


def test_ids_with_person_context_but_odd_header():
    p = profile_delimited(csv_text([["ref", "Surname", "DOB"]] + [[sid(), "Botha", "1980-01-01"] for _ in range(20)]),
                          ".csv", B)
    assert p.id_assessment == "confirmed"


def test_ids_without_context_are_probable():
    p = profile_delimited(csv_text([[sid(), "X1"] for _ in range(30)]), ".csv", B)
    assert p.id_assessment == "probable" and p.columns[0].name == "column 1"


def test_thirteen_digit_non_ids_never_confirmed():
    p = profile_delimited(csv_text([["accession_no", "specimen"]] + [[non_id(), "blood"] for _ in range(500)]),
                          ".csv", B)
    assert p.id_assessment == "unconfirmed" and "identity_number" not in p.categories
    # even under an ID-looking header, values failing the checks are not IDs
    p = profile_delimited(csv_text([["ID Number", "Surname"]] + [[non_id(), "Smit"] for _ in range(100)]), ".csv", B)
    assert p.id_assessment == "unconfirmed" and "identity_number" not in p.categories


def test_random_thirteen_digit_pass_rate_is_tiny():
    # structural + date + citizenship + Luhn checks reject almost all random 13-digit strings
    n = sum(parse_sa_id("".join(R.choice("0123456789") for _ in range(13))).valid for _ in range(20000))
    assert n / 20000 < 0.01


def test_mixed_column_below_threshold_not_confirmed():
    rows = [["ID Number"]] + [[sid()] for _ in range(10)] + [[non_id()] for _ in range(90)]
    assert profile_delimited(csv_text(rows), ".csv", B).id_assessment == "unconfirmed"


def test_row_budget_gives_bounded_estimate():
    b = dict(B, max_rows_per_file=100, max_rows_inspected=50)
    p = profile_delimited(csv_text([["ID Number"]] + [[sid()] for _ in range(1000)]), ".csv", b)
    assert not p.count_complete and p.rows == 100 and p.estimated_rows and 500 < p.estimated_rows < 2000
    assert p.rows_inspected == 50


def test_count_bands():
    assert [count_band(n) for n in (0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000)] == [
        "0", "1-9", "1-9", "10-99", "10-99", "100-999", "100-999", "1k-10k", "1k-10k", "10k+"]


def test_json_jsonl_sql_dump_and_xlsx():
    recs = [{"id_number": sid(), "surname": "Pillay", "icd10": "E11.9"} for _ in range(15)]
    p = profile_json(json.dumps({"results": recs}), B, lines=False)
    assert p.id_assessment == "confirmed" and "clinical" in p.categories
    p = profile_json("\n".join(json.dumps(r) for r in recs), B, lines=True)
    assert p.rows == 15
    dump = ("-- PostgreSQL database dump\nCREATE TABLE public.patients (\n id_number text,\n surname text\n);\n"
            "COPY public.patients (id_number, surname) FROM stdin;\n"
            + "".join(f"{sid()}\tDlamini\n" for _ in range(12)) + "\\.\n")
    p = profile_sql_dump(dump, B)
    assert p.rows == 12 and p.id_assessment == "confirmed"
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Sheet A"
    ws.append(["Member No", "ID Number", "Name"])
    for _ in range(11):
        ws.append(["123", sid(), "Thandi Nkosi"])
    buf = io.BytesIO()
    wb.save(buf)
    sheets = profile_xlsx(buf.getvalue(), B)
    assert sheets[0][0] == "Sheet A" and sheets[0][1].id_assessment == "confirmed"


def test_malformed_inputs_raise():
    with pytest.raises(ValueError):
        profile_json('{"a": [1, 2', B, lines=False)
    with pytest.raises(Exception):
        profile_xlsx(b"PK\x03\x04garbage", B)


def test_header_categories():
    assert "sa_id_header" in header_categories("ID Number")
    assert "name" in header_categories("Surname") and "dob" in header_categories("DateOfBirth")
    assert "clinical" in header_categories("TestCode") and "clinical" not in header_categories("latest_update")
    assert "patient_key" in header_categories("PatientID")
