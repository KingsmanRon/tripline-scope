"""SQL Server .bak restore -> discovery -> extraction -> closure (shared Developer Edition test container)."""

import json

import ingest_helpers as H
import pytest

from conftest import MSSQL_PW_ENV, configure_mssql, drop_test_databases, mssql_query
from tripline_scope import testing
from tripline_scope.core.canonical import sha256_file
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.ingest import restores
from tripline_scope.ingest.extract import read_extract

pytestmark = pytest.mark.docker


@pytest.fixture
def mssql_case(install, case_dir, mssql, monkeypatch):
    configure_mssql(install.home_dir)
    monkeypatch.setenv(MSSQL_PW_ENV, mssql["password"])
    testing.login("olivia")
    yield case_dir
    drop_test_databases()


def test_bak_restore_extract_and_closure_drop(mssql_case, demo_baks):
    bak = demo_baks / "ingest_LabDB01.bak"
    sha_before = sha256_file(bak)
    sid = H.add_source(mssql_case, bak, "mssql_bak")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(mssql_case)])
    assert rc == 0, err
    res = json.loads(out)
    st = res["sources"][0]
    assert st["tables"] == 4 and st["tables_extracted"] == 3 and res["source_checksums_unchanged"]
    case = Case(mssql_case)
    store = open_store(case, Home())
    entry = restores.active(store, sid)
    assert entry["database"] == "ingest_tscope_case_test_001_src_001"
    assert entry["original_database"] == "ingest_LabDB01" and entry["transfer_copy_removed"]
    ro = mssql_query("SELECT is_read_only FROM sys.databases WHERE name = %(n)s", {"n": entry["database"]})
    assert ro == [(True,)]
    m = store.read_json(f"work/extract/{sid}/manifest.json")
    tabs = {e["table"]: e for e in m["tables"]}
    assert set(tabs) == {"dbo.patients", "dbo.results", "dbo.billing", "dbo.misc"}
    assert all(e["database"] == "ingest_LabDB01" for e in m["tables"])
    assert tabs["dbo.patients"]["role"] == "identity" and tabs["dbo.patients"]["row_count"] == 300
    assert tabs["dbo.results"]["role"] == "dependent" and tabs["dbo.misc"]["extracted"] is False
    pats = read_extract(store, sid, "dbo_patients").to_pylist()
    assert len(pats) == 300 and sum(1 for p in pats if p["sa_id"]) == 288
    assert [p["_row_key"] for p in pats[:2]] == [f"{sid}|dbo_patients|1", f"{sid}|dbo_patients|2"]
    assert all(p["dob"] is not None for p in pats)
    doc = store.read_json(f"work/discovery/{sid}.json")
    t = next(t for t in doc["tables"] if t["slug"] == "dbo_patients")
    cols = {c["name"]: c for c in t["columns"]}
    assert cols["IDNumber"]["category"] == "sa_id" and cols["DateOfBirth"]["category"] == "dob"
    assert cols["DateOfBirth"]["data_type"] == "date"

    # a second run reuses the restore (no second database, same row keys)
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(mssql_case)])
    assert rc == 0, err
    assert len(restores.load(store)["restores"]) == 1
    assert read_extract(store, sid, "dbo_patients").column("_row_key").to_pylist() == [p["_row_key"] for p in pats]
    rc, out, err = testing.run_cli(["--json", "ingest", "restores", "--case", str(mssql_case)])
    assert rc == 0 and json.loads(out)["restores"][0]["status"] == "restored"

    # closure drops the restored database and the certificate says so
    testing.login("ines")
    rc, out, err = testing.run_cli(["--json", "case", "close", "--case", str(mssql_case), "--approver", "ines"])
    assert rc == 0, err
    cert = json.loads((mssql_case / "reports" / "closure" / "certificate.json").read_text())
    dropped = cert["destroyed"]["restored_databases"]
    assert dropped and dropped[0]["database"] == entry["database"] and dropped[0]["verified_absent"] is True
    assert dropped[0]["instance_ref"].startswith("mssql:") and "14330" not in json.dumps(dropped)
    assert mssql_query("SELECT DB_ID(%(n)s)", {"n": entry["database"]}) == [(None,)]
    assert sha256_file(bak) == sha_before


def test_bak_variant_schema_numeric_ids_and_no_pk(mssql_case, demo_baks):
    sid = H.add_source(mssql_case, demo_baks / "ingest_LabDB02.bak", "mssql_bak")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(mssql_case), "--batch-rows", "97"])
    assert rc == 0, err
    store = open_store(Case(mssql_case), Home())
    doc = store.read_json(f"work/discovery/{sid}.json")
    pt = next(t for t in doc["tables"] if t["slug"] == "dbo_patients")
    cols = {c["name"]: c for c in pt["columns"]}
    assert cols["id_no"]["category"] == "sa_id" and cols["id_no"]["id_pad"] is True
    assert cols["id_no"]["data_type"] == "bigint" and cols["id_no"]["match_rate"] == 1.0
    assert pt["patient_key"] == "pat_no" and cols["cell"]["category"] == "phone"
    adm = next(t for t in doc["tables"] if t["slug"] == "dbo_admissions")
    assert adm["role"] == "dependent" and adm["relations"][0]["containment"] == 1.0
    assert {c["name"]: c["category"] for c in adm["columns"]}["diagnosis"] == "icd10"
    rows = read_extract(store, sid, "dbo_admissions").to_pylist()
    assert len(rows) == 600 and all(r["patient_ref"] for r in rows) and all(r["_has_clinical_diagnosis"] for r in rows)
    # keys are unique and ordered although the admissions table has no primary key (ORDER BY all columns)
    keys = [r["_row_key"] for r in rows]
    assert len(set(keys)) == 600
    pats = read_extract(store, sid, "dbo_patients").to_pylist()
    assert all(p["sa_id"] is None or len(p["sa_id"]) == 13 for p in pats)
    assert sum(1 for p in pats if p["sa_id"] and p["sa_id"].startswith("0")) >= 1


def test_bak_encrypted_copy_refused(mssql_case, demo_baks):
    H.add_source(mssql_case, demo_baks / "ingest_LabDB01.bak", "mssql_bak", copy=True)
    rc, out, err = testing.run_cli(["ingest", "--case", str(mssql_case)])
    assert rc == 2 and "reference" in err
