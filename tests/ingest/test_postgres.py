"""PostgreSQL custom and plain dumps: restore into a throw-away cluster, discover, extract, drop at closure."""

import json
import os
import subprocess
from pathlib import Path

import ingest_helpers as H
import pytest

from conftest import PG_BIN, PG_PORT, PG_PW_ENV, PG_SUPER_PW, configure_pg, pg_super
from tripline_scope import testing
from tripline_scope.core.canonical import sha256_file
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.ingest import restores
from tripline_scope.ingest.extract import read_extract
from tripline_scope.ingest.pgplain import PlainDump

pytestmark = pytest.mark.postgres


def _build_source_db(name: str, n: int = 250) -> dict:
    data = H.make_dataset(n, seed=23)
    con = pg_super()
    con.run(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
    con.run(f"CREATE DATABASE {name}")
    con.close()
    con = pg_super(name)
    con.run("CREATE TABLE patients (patient_id text PRIMARY KEY, first_name text, surname text, id_number text, "
            "date_of_birth date, cell text, email text, med_aid_no text, notes text)")
    con.run("CREATE TABLE lab_results (patient_id text, test_code text, result text, icd10 text, "
            "collected_at timestamp, comment text)")
    rows = []
    for p in data["patients"]:
        d, m, y = p["DateOfBirth"].split("/")
        rows.append("\t".join([p["PatientID"], p["FirstNames"], p["Surname"], p["IDNumber"] or "\\N",
                               f"{y}-{m}-{d}", p["CellNo"], p["Email"], p["MedAidNo"], "it's a \\\\ test; ok"]))
    con.run("COPY patients FROM STDIN", stream=["\n".join(rows) + "\n"])
    res = []
    for r in data["results"]:
        res.append("\t".join([r["PatientID"], r["TestCode"], r["Result"], r["ICD10"], r["CollectedDate"] + " 08:30:00",
                              r["Notes"]]))
    con.run("COPY lab_results FROM STDIN", stream=["\n".join(res) + "\n"])
    con.run("CREATE FUNCTION f_semicolon() RETURNS text LANGUAGE sql AS $fn$ SELECT 'a;b' $fn$")
    con.close()
    return data


def _dump(name: str, out: Path, fmt: str) -> Path:
    env = dict(os.environ, PGPASSWORD=PG_SUPER_PW)
    subprocess.run([f"{PG_BIN}/pg_dump", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "pgsuper", f"-F{fmt}",
                    "-f", str(out), name], check=True, env=env, capture_output=True)
    os.chmod(out, 0o444)
    return out


@pytest.fixture(scope="module")
def dumps(pg_cluster, tmp_path_factory):
    d = tmp_path_factory.mktemp("dumps")
    data = _build_source_db("ingest_labpg")
    custom = _dump("ingest_labpg", d / "labpg.dump", "c")
    plain = _dump("ingest_labpg", d / "labpg.sql", "p")
    con = pg_super()
    con.run("DROP DATABASE ingest_labpg WITH (FORCE)")
    con.close()
    return {"custom": custom, "plain": plain, "data": data}


@pytest.fixture
def pg_case(install, case_dir, pg_cluster, monkeypatch):
    configure_pg(install.home_dir)
    monkeypatch.setenv(PG_PW_ENV, pg_cluster["restore_pw"])
    testing.login("olivia")
    yield case_dir
    con = pg_super()
    for (name,) in con.run("SELECT datname FROM pg_database WHERE datname LIKE 'ingest_tscope_%'"):
        con.run(f'DROP DATABASE "{name}" WITH (FORCE)')
    con.close()


def _db_exists(name: str) -> bool:
    con = pg_super()
    try:
        return bool(con.run("SELECT 1 FROM pg_database WHERE datname = :n", n=name))
    finally:
        con.close()


def _check(case_dir, sid, n):
    store = open_store(Case(case_dir), Home())
    doc = store.read_json(f"work/discovery/{sid}.json")
    t = next(t for t in doc["tables"] if t["slug"] == "public_patients")
    cols = {c["name"]: c["category"] for c in t["columns"]}
    assert t["role"] == "identity" and t["patient_key"] == "patient_id"
    assert cols["id_number"] == "sa_id" and cols["date_of_birth"] == "dob" and cols["cell"] == "phone"
    assert cols["notes"] == "clinical_free_text"
    lr = next(t for t in doc["tables"] if t["slug"] == "public_lab_results")
    lcols = {c["name"]: c["category"] for c in lr["columns"]}
    assert lr["role"] == "dependent" and lcols["icd10"] == "icd10" and lcols["collected_at"] == "record_date"
    pats = read_extract(store, sid, "public_patients").to_pylist()
    assert len(pats) == n and sum(1 for p in pats if p["sa_id"]) == n - n // 25
    m = store.read_json(f"work/extract/{sid}/manifest.json")
    tabs = {e["table"]: e for e in m["tables"]}
    assert set(tabs) == {"public.patients", "public.lab_results"}
    return store


def test_custom_dump_restore_extract_close(pg_case, dumps):
    sha = sha256_file(dumps["custom"])
    sid = H.add_source(pg_case, dumps["custom"], "pg_dump")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(pg_case)])
    assert rc == 0, err
    store = _check(pg_case, sid, 250)
    entry = restores.active(store, sid)
    assert entry["dump_format"] == "custom" and entry["original_database"] == "ingest_labpg"
    m = store.read_json(f"work/extract/{sid}/manifest.json")
    assert all(e["database"] == "ingest_labpg" for e in m["tables"])
    con = pg_super(entry["database"])
    assert con.run("SHOW default_transaction_read_only")[0][0] == "on"
    con.close()
    testing.login("ines")
    rc, out, err = testing.run_cli(["case", "close", "--case", str(pg_case), "--approver", "ines"])
    assert rc == 0, err
    cert = json.loads((pg_case / "reports" / "closure" / "certificate.json").read_text())
    assert cert["destroyed"]["restored_databases"][0]["verified_absent"] is True
    assert not _db_exists(entry["database"])
    assert sha256_file(dumps["custom"]) == sha


def test_plain_dump_encrypted_copy(pg_case, dumps):
    sid = H.add_source(pg_case, dumps["plain"], "pg_dump", copy=True)
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(pg_case)])
    assert rc == 0, err
    store = _check(pg_case, sid, 250)
    entry = restores.active(store, sid)
    assert entry["dump_format"] == "plain" and entry["restore_stats"]["statements_failed"] == 0
    assert entry["restore_stats"]["rows_copied"] == 250 + len(dumps["data"]["results"])
    rc, out, err = testing.run_cli(["--json", "ingest", "drop", "--case", str(pg_case), "--source", sid])
    assert rc == 0, err
    assert json.loads(out)["verified_absent"] is True and not _db_exists(entry["database"])


def test_plain_dump_meta_command_refused(pg_case, tmp_path):
    marker = tmp_path / "pwned"
    evil = tmp_path / "evil.sql"
    evil.write_text("SET statement_timeout = 0;\nCREATE TABLE t (a text);\n"
                    f"\\! touch {marker}\nSELECT 1;\n")
    H.add_source(pg_case, evil, "pg_dump")
    rc, out, err = testing.run_cli(["ingest", "--case", str(pg_case)])
    assert rc == 2 and "meta-command" in err
    assert not marker.exists()
    assert not _db_exists("ingest_tscope_case_test_001_src_001")  # failed restore cleaned up
    store = open_store(Case(pg_case), Home())
    assert [e["status"] for e in restores.load(store)["restores"]] == ["dropped"]


def test_plain_dump_copy_program_refused(pg_case, tmp_path):
    evil = tmp_path / "evil2.sql"
    evil.write_text("CREATE TABLE t (a text);\nCOPY t FROM PROGRAM 'id';\n")
    H.add_source(pg_case, evil, "pg_dump")
    rc, out, err = testing.run_cli(["ingest", "--case", str(pg_case)])
    assert rc == 2 and "COPY" in err


def test_superuser_login_refused_for_plain(install, case_dir, pg_cluster, monkeypatch, dumps):
    configure_pg(install.home_dir, login="pgsuper")
    monkeypatch.setenv(PG_PW_ENV, PG_SUPER_PW)
    testing.login("olivia")
    H.add_source(case_dir, dumps["plain"], "pg_dump")
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir)])
    assert rc == 2 and "superuser" in err


def test_plain_lexer_quotes_dollar_and_copy():
    text = ("-- header\n\\restrict abc\nSET standard_conforming_strings = on;\n"
            "CREATE FUNCTION f() RETURNS text AS $x$ SELECT ';' $x$ LANGUAGE sql;\n"
            "INSERT INTO t VALUES ('a;''b', E'c\\';d', \"x;y\");\n/* c; */ SELECT 1; SELECT 2;\n"
            "COPY t (a) FROM stdin;\nrow;1\n\\.\nSELECT 3;\n\\unrestrict abc\n")
    dump = PlainDump(iter(text.splitlines(keepends=True)))
    items = []
    for kind, sql in dump.statements():
        if kind == "copy":
            data = dump.copy_data()
            items.append(("copy", "".join(data)))
        else:
            items.append((kind, sql.strip()))
    kinds = [k for k, _ in items]
    assert kinds == ["sql", "sql", "sql", "sql", "sql", "copy", "sql"]
    assert items[5][1] == "row;1\n" and items[1][1].endswith("LANGUAGE sql;")
    assert dump.meta_skipped == 2
