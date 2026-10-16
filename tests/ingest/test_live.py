"""Optional read-only live connections: approval, permission checks (pass / refuse), forced read-only sessions."""

import json

import ingest_helpers as H
import pytest
import yaml

from conftest import MSSQL, PG_PORT, mssql_query, pg_super
from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.ingest.extract import read_extract

LIVE_PW = "Synthetic-Live-Pw-9"
LIVE_ENV = "INGEST_TEST_LIVE_PASSWORD"


def _add_live(case_dir, kind):
    rc, out, err = testing.run_cli(["--json", "source", "add", "--case", str(case_dir), "--kind", kind, "--label",
                                    "lab system (live)", "--evidence-role", "system_copy", "--legal-basis",
                                    "POPIA s22 incident response", "--supplied-by", "Hospital IT",
                                    "--received-at", "2026-09-15T08:00:00Z"])
    assert rc == 0, err
    return json.loads(out)["source_id"]


def _connections(home_dir, conns: dict):
    p = home_dir / "config.yaml"
    cfg = yaml.safe_load(p.read_text())
    cfg["live_connections"] = conns
    p.write_text(yaml.safe_dump(cfg, sort_keys=False))


def _enable(case_dir, sid, conn, db, *extra):
    testing.login("ines")
    rc, out, err = testing.run_cli(["ingest", "live-enable", "--case", str(case_dir), "--source", sid,
                                    "--connection", conn, "--database", db, *extra])
    assert rc == 0, err
    testing.login("olivia")


# ------------------------------------------------------------------------------------------ PostgreSQL
@pytest.fixture(scope="module")
def pg_live(pg_cluster):
    con = pg_super()
    con.run("DROP DATABASE IF EXISTS ingest_live WITH (FORCE)")
    con.run("CREATE DATABASE ingest_live")
    for role in ("ingest_live_ro", "ingest_live_rw"):
        con.run(f"DROP ROLE IF EXISTS {role}")
        con.run(f"CREATE ROLE {role} LOGIN PASSWORD '{LIVE_PW}'")
    con.close()
    con = pg_super("ingest_live")
    con.run("CREATE TABLE patients (patient_id text PRIMARY KEY, surname text, first_name text, id_number text, "
            "cell text)")
    rows = H.make_dataset(60, seed=3)["patients"]
    con.run("COPY patients FROM STDIN", stream=["".join(
        "\t".join([r["PatientID"], r["Surname"], r["FirstNames"], r["IDNumber"] or "\\N", r["CellNo"]]) + "\n"
        for r in rows)])
    for role in ("ingest_live_ro", "ingest_live_rw"):
        con.run(f"GRANT USAGE ON SCHEMA public TO {role}")
        con.run(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}")
    con.run("GRANT INSERT ON patients TO ingest_live_rw")
    con.close()
    yield
    con = pg_super()
    con.run("DROP DATABASE IF EXISTS ingest_live WITH (FORCE)")
    con.run("DROP ROLE IF EXISTS ingest_live_ro")
    con.run("DROP ROLE IF EXISTS ingest_live_rw")
    con.close()


@pytest.mark.postgres
def test_pg_live_read_only_passes_writer_refused(install, case_dir, pg_live, monkeypatch):
    monkeypatch.setenv(LIVE_ENV, LIVE_PW)
    base = {"engine": "postgres", "host": "127.0.0.1", "port": PG_PORT, "password_env": LIVE_ENV}
    _connections(install.home_dir, {"pg_ro": dict(base, login="ingest_live_ro"),
                                    "pg_rw": dict(base, login="ingest_live_rw")})
    testing.login("olivia")
    sid = _add_live(case_dir, "live_pg")
    # off by default
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid])
    assert rc == 3 and "live access is off" in err
    _enable(case_dir, sid, "pg_ro", "ingest_live", "--max-rows", "1000")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(case_dir), "--source", sid])
    assert rc == 0, err
    assert "WARNING: LIVE read-only connection" in err
    store = open_store(Case(case_dir), Home())
    pats = read_extract(store, sid, "public_patients").to_pylist()
    assert len(pats) == 60 and sum(1 for p in pats if p["sa_id"]) >= 57
    entry = [e for e in Case(case_dir).audit.entries() if e["command"] == "ingest"][-1]
    assert entry["outcome"] == "ok" and "LIVE read-only" in entry["note"]
    # row cap: a cap below the table size refuses rather than truncating
    _enable(case_dir, sid, "pg_ro", "ingest_live", "--max-rows", "10")
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid])
    assert rc == 2 and "row cap" in err
    # a login with INSERT on a table is refused before any data is read
    sid2 = _add_live(case_dir, "live_pg")
    _enable(case_dir, sid2, "pg_rw", "ingest_live")
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid2])
    assert rc == 3 and "refusing live access" in err and "INSERT" in err
    con = pg_super("ingest_live")
    assert con.run("SELECT count(*) FROM patients")[0][0] == 60
    con.close()


@pytest.mark.postgres
def test_live_hand_edited_approval_refused(install, case_dir, pg_live, monkeypatch):
    monkeypatch.setenv(LIVE_ENV, LIVE_PW)
    _connections(install.home_dir, {"pg_ro": {"engine": "postgres", "host": "127.0.0.1", "port": PG_PORT,
                                              "login": "ingest_live_ro", "password_env": LIVE_ENV}})
    testing.login("olivia")
    sid = _add_live(case_dir, "live_pg")
    case = Case(case_dir)
    case.config["live_access"] = {sid: {"live": True, "connection": "pg_ro", "databases": ["ingest_live"],
                                        "approved_by": "ines"}}
    case.save()
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid])
    assert rc == 3 and "audit" in err


def test_live_enable_requires_approver(case_dir):
    testing.login("olivia")
    sid = _add_live(case_dir, "live_pg")
    rc, out, err = testing.run_cli(["ingest", "live-enable", "--case", str(case_dir), "--source", sid,
                                    "--connection", "x", "--database", "y"])
    assert rc == 3


# ------------------------------------------------------------------------------------------ SQL Server
@pytest.fixture
def mssql_live(mssql):
    db = "ingest_live_ms"
    mssql_query(f"IF DB_ID('{db}') IS NOT NULL BEGIN ALTER DATABASE [{db}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
                f"DROP DATABASE [{db}] END")
    for login in ("ingest_live_ro", "ingest_live_rw"):
        mssql_query(f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN [{login}]")
        mssql_query(f"CREATE LOGIN [{login}] WITH PASSWORD = '{LIVE_PW}', CHECK_POLICY = OFF")
    mssql_query(f"CREATE DATABASE [{db}]")
    mssql_query("CREATE TABLE dbo.patients (patient_id INT PRIMARY KEY, surname NVARCHAR(50), "
                "first_name NVARCHAR(50), id_number NVARCHAR(13), cell NVARCHAR(20))", database=db)
    rows = H.make_dataset(40, seed=5)["patients"]
    for i, r in enumerate(rows, 1):
        mssql_query("INSERT INTO dbo.patients VALUES (%(i)s, %(s)s, %(f)s, %(n)s, %(c)s)",
                    {"i": i, "s": r["Surname"], "f": r["FirstNames"], "n": r["IDNumber"] or None, "c": r["CellNo"]},
                    database=db)
    for login, roles in (("ingest_live_ro", ["db_datareader"]), ("ingest_live_rw", ["db_datareader", "db_datawriter"])):
        mssql_query(f"CREATE USER [{login}] FOR LOGIN [{login}]", database=db)
        for role in roles:
            mssql_query(f"ALTER ROLE {role} ADD MEMBER [{login}]", database=db)
    yield db
    mssql_query(f"ALTER DATABASE [{db}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{db}]")
    for login in ("ingest_live_ro", "ingest_live_rw"):
        mssql_query(f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN [{login}]")


@pytest.mark.docker
def test_mssql_live_read_only_passes_writer_refused(install, case_dir, mssql_live, monkeypatch):
    monkeypatch.setenv(LIVE_ENV, LIVE_PW)
    base = {"engine": "mssql", "host": MSSQL["host"], "port": MSSQL["port"], "password_env": LIVE_ENV}
    _connections(install.home_dir, {"ms_ro": dict(base, login="ingest_live_ro"),
                                    "ms_rw": dict(base, login="ingest_live_rw"),
                                    "ms_sa": dict(base, login="sa")})
    testing.login("olivia")
    sid = _add_live(case_dir, "live_mssql")
    _enable(case_dir, sid, "ms_ro", mssql_live, "--table", "dbo.patients")
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(case_dir), "--source", sid])
    assert rc == 0, err
    assert "WARNING: LIVE read-only connection" in err
    store = open_store(Case(case_dir), Home())
    pats = read_extract(store, sid, "dbo_patients").to_pylist()
    assert len(pats) == 40 and all(p["phone"] for p in pats)
    sid2 = _add_live(case_dir, "live_mssql")
    _enable(case_dir, sid2, "ms_rw", mssql_live)
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid2])
    assert rc == 3 and "db_datawriter" in err
    sid3 = _add_live(case_dir, "live_mssql")
    monkeypatch.setenv(LIVE_ENV, MSSQL["password"])
    _enable(case_dir, sid3, "ms_sa", mssql_live)
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir), "--source", sid3])
    assert rc == 3 and "sysadmin" in err
    assert mssql_query("SELECT COUNT(*) FROM dbo.patients", database=mssql_live) == [(40,)]
