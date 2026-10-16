"""The shipped catalogue SQL and the metadata-only collector against real engines.

* PostgreSQL 16: a throw-away cluster (initdb) on 127.0.0.1:15442, removed afterwards.
* SQL Server 2022 Developer: the shared ``mssql-test`` container; every object created is prefixed ``expo_`` and
  dropped afterwards. Server-wide settings are never changed.
"""

import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.errors import PermissionDenied
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.exposure.collect import collect

PG_BIN = Path("/usr/lib/postgresql/16/bin")
PG_PORT = 15442
MSSQL = {"dsn": "127.0.0.1", "port": 14330, "user": "sa", "password": "Synth3tic!Demo"}


def _port_open(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _as_postgres(cmd):
    if os.geteuid() == 0:
        cmd = ["runuser", "-u", "postgres", "--", *cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


@pytest.fixture(scope="module")
def pg_cluster():
    if not (PG_BIN / "initdb").exists():
        pytest.skip("PostgreSQL 16 binaries not installed")
    if _port_open(PG_PORT):
        pytest.skip("port 15442 already in use")
    d = Path(tempfile.mkdtemp(prefix="expo_pg_"))
    if os.geteuid() == 0:
        import pwd

        pw = pwd.getpwnam("postgres")
        os.chown(d, pw.pw_uid, pw.pw_gid)
    os.chmod(d, 0o700)
    data = d / "data"
    try:
        r = _as_postgres([str(PG_BIN / "initdb"), "-D", str(data), "-U", "postgres", "--auth-local=trust",
                          "--auth-host=scram-sha-256", "-E", "UTF8", "--no-instructions"])
        assert r.returncode == 0, r.stderr
        r = _as_postgres([str(PG_BIN / "pg_ctl"), "-D", str(data), "-l", str(d / "log"), "-w", "-o",
                          f"-p {PG_PORT} -k {d} -c listen_addresses=127.0.0.1", "start"])
        assert r.returncode == 0, r.stderr
        import pg8000.dbapi

        su = pg8000.dbapi.connect(user="postgres", unix_sock=f"{d}/.s.PGSQL.{PG_PORT}", database="postgres")
        su.autocommit = True
        su.cursor().execute("CREATE DATABASE expo_pathdb")
        su.close()
        pw = {k: "Expo-" + secrets.token_hex(8) for k in ("app", "report", "etl", "meta", "writer")}
        db = pg8000.dbapi.connect(user="postgres", unix_sock=f"{d}/.s.PGSQL.{PG_PORT}", database="expo_pathdb")
        db.autocommit = True
        cur = db.cursor()
        for sql in [
            "CREATE TABLE patients (id_number text, surname text, dob date)",
            "CREATE TABLE results (patient_id int, icd10 text, result text)",
            "CREATE TABLE lab_codes (code text, description text)",
            f"CREATE ROLE expo_app LOGIN SUPERUSER PASSWORD '{pw['app']}'",
            f"CREATE ROLE expo_report LOGIN PASSWORD '{pw['report']}'",
            "GRANT SELECT ON patients TO expo_report",
            f"CREATE ROLE expo_etl LOGIN PASSWORD '{pw['etl']}'",
            "GRANT pg_execute_server_program TO expo_etl",
            "GRANT SELECT ON results TO PUBLIC",
            "CREATE EXTENSION dblink",
            f"CREATE ROLE expo_meta LOGIN PASSWORD '{pw['meta']}'",
            "GRANT pg_read_all_settings TO expo_meta",
            f"CREATE ROLE expo_writer LOGIN PASSWORD '{pw['writer']}'",
            "GRANT INSERT ON patients TO expo_writer",
        ]:
            cur.execute(sql)
        db.close()
        yield {"dir": d, "pw": pw}
    finally:
        if data.exists():
            _as_postgres([str(PG_BIN / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"])
        shutil.rmtree(d, ignore_errors=True)


def _pg(user, pw, **kw):
    return collect("postgres", host="127.0.0.1", port=PG_PORT, user=user, password=pw, database="expo_pathdb",
                   timeout_s=10, max_rows=10000, **kw)


def _scan_with(tmp_path, case_dir, dbdecl):
    doc = {"schema": "tripline.exposure-manifest/v1", "owner": "IT", "legal_basis": "integration test",
           "received_at": "2026-10-01T00:00:00Z", "budget": {"max_files": 10}, "databases": [dbdecl]}
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(doc))
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(tmp_path / "m.yaml")])
    assert rc == 0, err
    store = open_store(Case(case_dir), Home())
    return store.read_json("work/exposure/findings.json"), store.read_json("work/exposure/scan.json")


@pytest.mark.postgres
def test_pg_catalogue_sql_collector_and_scan(pg_cluster, install, tmp_path, monkeypatch):
    with pytest.raises(PermissionDenied):
        _pg("expo_writer", pg_cluster["pw"]["writer"])   # a login that can write is refused
    with pytest.raises(PermissionDenied):
        _pg("expo_app", pg_cluster["pw"]["app"])         # superuser refused
    doc = _pg("expo_meta", pg_cluster["pw"]["meta"])
    assert "hba_rules" in doc["errors"] and "permission denied" in doc["errors"]["hba_rules"]
    assert not set(doc["errors"]) - {"hba_rules"}, doc["errors"]
    roles = {r["rolname"]: r for r in doc["queries"]["roles"]}
    assert roles["expo_app"]["rolsuper"] is True and "rolpassword" not in roles["expo_app"]
    assert {("pg_execute_server_program", "expo_etl")} <= {(r["role_name"], r["member_name"])
                                                          for r in doc["queries"]["auth_members"]}
    assert any(r["grantee"] == "PUBLIC" and r["table_name"] == "results" for r in doc["queries"]["table_privileges"])
    export = tmp_path / "pathdb.json"
    export.write_text(json.dumps(doc))
    case_dir = testing.open_case(tmp_path, "READY-PG", mode="readiness")
    testing.login("olivia")
    findings, scan = _scan_with(tmp_path, case_dir, {"id": "pathdb", "engine": "postgres", "name": "expo_pathdb",
                                                     "patient_data": True, "export": "pathdb.json"})
    got = {(f["rule_id"], f["location"].get("principal")) for f in findings}
    for exp in [("A2.app-admin-rights", "expo_app"), ("A4.pg-copy-program", "expo_app"),
                ("A4.pg-copy-program", "expo_etl"), ("A4.pg-public-table-grant", None), ("A4.pg-dblink", None),
                ("A4.pg-audit-disabled", None)]:
        assert exp in got, exp
    assert not any(f["location"].get("principal") == "expo_report" for f in findings)       # least privilege
    assert not any(f["rule_id"] == "A4.pg-public-schema-create" for f in findings)           # PG16 default
    assert any(u["unit"] == "db:pathdb:hba_auth" for u in scan["coverage"]["unavailable"])
    # the same through a declared metadata-only login (live_metadata), with only that endpoint allowed
    monkeypatch.setenv("EXPO_PG_PW", pg_cluster["pw"]["meta"])
    live, scan2 = _scan_with(tmp_path, case_dir, {
        "id": "pathdb", "engine": "postgres", "name": "expo_pathdb", "patient_data": True, "mode": "live_metadata",
        "live": {"host": "127.0.0.1", "port": PG_PORT, "user": "expo_meta", "password_env": "EXPO_PG_PW"}})
    assert {(f["rule_id"], f["location"].get("principal")) for f in live} == got
    assert scan2["metrics"]["network_attempts_blocked"] == 0


@pytest.fixture(scope="module")
def mssql_db():
    try:
        import pytds

        conn = pytds.connect(database="master", autocommit=True, login_timeout=5, timeout=60, **MSSQL)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"SQL Server test container unavailable ({type(exc).__name__})")
    sfx = secrets.token_hex(3)
    names = {"db": f"expo_labdb_{sfx}", "meta": f"expo_meta_{sfx}", "app": f"expo_app_{sfx}", "wr": f"expo_wr_{sfx}"}
    pw = {k: f"Expo-{secrets.token_hex(6)}-Aa1!" for k in ("meta", "app", "wr")}
    cur = conn.cursor()
    try:
        cur.execute(f"CREATE DATABASE [{names['db']}]")
        for k in ("meta", "app", "wr"):
            cur.execute(f"CREATE LOGIN [{names[k]}] WITH PASSWORD = '{pw[k]}'")
        cur.execute(f"GRANT VIEW ANY DEFINITION TO [{names['meta']}]")
        cur.execute(f"GRANT VIEW SERVER STATE TO [{names['meta']}]")
        cur.execute(f"USE [{names['db']}]")
        cur.execute("CREATE TABLE dbo.Patients (IDNumber nvarchar(13), Surname nvarchar(60), DOB date)")
        for k in ("meta", "app", "wr"):
            cur.execute(f"CREATE USER [{names[k]}] FOR LOGIN [{names[k]}]")
        cur.execute(f"ALTER ROLE db_owner ADD MEMBER [{names['app']}]")
        cur.execute(f"ALTER ROLE db_datawriter ADD MEMBER [{names['wr']}]")
        cur.execute("USE master")
        yield {"names": names, "pw": pw}
    finally:
        try:
            cur.execute("USE master")
            cur.execute(f"IF DB_ID('{names['db']}') IS NOT NULL ALTER DATABASE [{names['db']}] SET SINGLE_USER "
                        "WITH ROLLBACK IMMEDIATE")
            cur.execute(f"IF DB_ID('{names['db']}') IS NOT NULL DROP DATABASE [{names['db']}]")
            for k in ("meta", "app", "wr"):
                cur.execute(f"IF SUSER_ID('{names[k]}') IS NOT NULL DROP LOGIN [{names[k]}]")
        finally:
            conn.close()


def _ms(n, pw, db):
    return collect("mssql", host=MSSQL["dsn"], port=MSSQL["port"], user=n, password=pw, database=db, timeout_s=30,
                   max_rows=50000)


@pytest.mark.docker
def test_mssql_catalogue_sql_collector_and_scan(mssql_db, install, tmp_path):
    n, pw = mssql_db["names"], mssql_db["pw"]
    with pytest.raises(PermissionDenied):
        _ms(n["wr"], pw["wr"], n["db"])
    with pytest.raises(PermissionDenied):
        _ms(n["app"], pw["app"], n["db"])
    doc = _ms(n["meta"], pw["meta"], n["db"])
    q = doc["queries"]
    assert not doc["errors"], doc["errors"]
    assert n["app"] in {r["name"] for r in q["server_principals"]}
    assert ("db_owner", n["app"]) in {(r["role_name"], r["member_name"]) for r in q["database_role_members"]}
    assert "xp_cmdshell" in {r["name"] for r in q["configurations"]}
    assert {"name", "is_policy_checked"} <= set(q["sql_logins"][0])
    export = tmp_path / "labdb.json"
    export.write_text(json.dumps(doc))
    case_dir = testing.open_case(tmp_path, "READY-MS", mode="readiness")
    testing.login("olivia")
    findings, scan = _scan_with(tmp_path, case_dir, {"id": "labdb", "engine": "mssql", "name": n["db"],
                                                     "patient_data": True, "export": "labdb.json"})
    assert ("A2.app-admin-rights", n["app"]) in {(f["rule_id"], f["location"].get("principal")) for f in findings}
    assert not any(f["location"].get("principal") == n["meta"] for f in findings)
    a4 = {x["unit"] for x in scan["coverage"]["assessed"].get("A4", [])}
    assert {"db:labdb:xp_cmdshell", "db:labdb:audit", "db:labdb:guest_access", "db:labdb:linked_servers"} <= a4
