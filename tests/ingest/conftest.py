"""Fixtures for ingest tests: shared SQL Server container, throw-away PostgreSQL cluster, demo backups."""

from __future__ import annotations

import datetime as dt
import importlib.util
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import ingest_helpers as H
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
MSSQL = {"host": "127.0.0.1", "port": 14330, "login": "sa", "password": "Synth3tic!Demo", "container": "mssql-test"}
MSSQL_PW_ENV = "INGEST_TEST_MSSQL_PASSWORD"
PG_PORT = 15441
PG_BIN = "/usr/lib/postgresql/16/bin"
PG_SUPER_PW = "Synthetic-Super-Pw-1"
PG_RESTORE_PW = "Synthetic-Restore-Pw-1"
PG_PW_ENV = "INGEST_TEST_PG_PASSWORD"


# ------------------------------------------------------------------------------------------ SQL Server
def _mssql_up() -> bool:
    try:
        import pytds

        con = pytds.connect(dsn=MSSQL["host"], port=MSSQL["port"], user=MSSQL["login"],
                            password=MSSQL["password"], database="master", login_timeout=3, autocommit=True)
        con.close()
        res = subprocess.run(["docker", "exec", MSSQL["container"], "true"], capture_output=True, timeout=20)
        return res.returncode == 0
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(scope="session")
def mssql():
    if not _mssql_up():
        pytest.skip("SQL Server test container not reachable")
    os.environ[MSSQL_PW_ENV] = MSSQL["password"]
    return MSSQL


def mssql_query(sql: str, params=None, database: str = "master"):
    import pytds

    con = pytds.connect(dsn=MSSQL["host"], port=MSSQL["port"], user=MSSQL["login"], password=MSSQL["password"],
                        database=database, autocommit=True, login_timeout=5)
    try:
        cur = con.cursor()
        cur.execute(sql, params)
        try:
            return cur.fetchall()
        except Exception:  # noqa: BLE001
            return None
    finally:
        con.close()


def load_build_baks():
    spec = importlib.util.spec_from_file_location("build_baks", REPO / "demo" / "lab-breach" / "build_baks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write_synth_parquet(root: Path, n_patients: int = 300, seed: int = 11) -> Path:
    """Two databases with slightly different schemas, in the ``tscope synth`` layout."""
    data = H.make_dataset(n_patients, seed=seed)
    db1 = root / "sources" / "db01"
    db1.mkdir(parents=True)
    pats = [dict(r, DateOfBirth=dt.datetime.strptime(r["DateOfBirth"], "%d/%m/%Y").date()) for r in data["patients"]]
    pq.write_table(pa.Table.from_pylist(pats), db1 / "patients.parquet")
    res = [dict(r, CollectedDate=dt.date.fromisoformat(r["CollectedDate"])) for r in data["results"]]
    pq.write_table(pa.Table.from_pylist(res), db1 / "results.parquet")
    bill = [dict(r, Amount=float(r["Amount"])) for r in data["billing"]]
    pq.write_table(pa.Table.from_pylist(bill), db1 / "billing.parquet")
    pq.write_table(pa.Table.from_pylist(data["misc"]), db1 / "misc.parquet")
    db2 = root / "sources" / "db02"
    db2.mkdir(parents=True)
    pats2 = [{"pat_no": i + 1, "first_name": r["FirstNames"], "surname": r["Surname"],
              "id_no": int(r["IDNumber"]) if r["IDNumber"] else None,
              "dob": dt.datetime.strptime(r["DateOfBirth"], "%d/%m/%Y"), "cell": r["CellNo"].replace(" ", ""),
              "med_aid_no": r["MedAidNo"]} for i, r in enumerate(data["patients"])]
    pq.write_table(pa.Table.from_pylist(pats2), db2 / "patients.parquet")
    adm = [{"pat_no": (i % len(pats2)) + 1, "admission_date": dt.date(2026, 3, 1) + dt.timedelta(days=i % 60),
            "ward": ["A1", "B2", "ICU"][i % 3], "diagnosis": H.ICD[i % len(H.ICD)]} for i in range(len(pats2) * 2)]
    pq.write_table(pa.Table.from_pylist(adm), db2 / "admissions.parquet")
    return root


@pytest.fixture(scope="session")
def demo_baks(mssql, tmp_path_factory):
    synth = write_synth_parquet(tmp_path_factory.mktemp("synth"))
    out = tmp_path_factory.mktemp("baks")
    mod = load_build_baks()
    rc = mod.main(["--synth", str(synth), "--out", str(out), "--host", MSSQL["host"], "--port", str(MSSQL["port"]),
                   "--container", MSSQL["container"], "--password-env", MSSQL_PW_ENV, "--db-prefix", "ingest_",
                   "--server-backup-dir", "/var/opt/mssql/backup/ingest_build"])
    assert rc == 0
    for p in out.glob("*.bak"):
        os.chmod(p, 0o444)
    return out


def configure_mssql(home_dir: Path, **extra) -> None:
    cfg_path = home_dir / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg.setdefault("restore_targets", {})["mssql"] = {
        "host": MSSQL["host"], "port": MSSQL["port"], "login": MSSQL["login"], "password_env": MSSQL_PW_ENV,
        "backup_transfer": "docker_cp", "container": MSSQL["container"],
        "server_backup_dir": "/var/opt/mssql/backup/ingest_tscope", "data_dir": "/var/opt/mssql/data",
        "encryption": False, "trust_server_certificate": True, "database_prefix": "ingest_tscope_", **extra}
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))


def drop_test_databases(prefix: str = "ingest_tscope_") -> None:
    rows = mssql_query("SELECT name FROM sys.databases WHERE name LIKE %(p)s", {"p": prefix + "%"}) or []
    for (name,) in rows:
        mssql_query(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")


# ------------------------------------------------------------------------------------------ PostgreSQL
def _pg_run(args: list[str], *, user: str | None = None, env=None, check=True, timeout=120):
    cmd = args
    if os.geteuid() == 0 and user:
        cmd = ["runuser", "-u", user, "--", *args]
    return subprocess.run(cmd, capture_output=True, timeout=timeout, check=check, env=env)


@pytest.fixture(scope="session")
def pg_cluster():
    """Throw-away PostgreSQL 16 cluster on port 15441 with a non-superuser restore role."""
    if not Path(PG_BIN, "initdb").exists():
        pytest.skip("PostgreSQL 16 binaries not installed")
    run_as = "postgres" if os.geteuid() == 0 else None
    for stale in Path(tempfile.gettempdir()).glob("tscope-ingest-pg-*"):   # left by an interrupted run
        if (stale / "data" / "postmaster.pid").exists():
            _pg_run([f"{PG_BIN}/pg_ctl", "-D", str(stale / "data"), "-m", "immediate", "stop"], user=run_as,
                    check=False)
        shutil.rmtree(stale, ignore_errors=True)
    base = Path(tempfile.mkdtemp(prefix="tscope-ingest-pg-"))
    data = base / "data"
    pwfile = base / "pw"
    pwfile.write_text(PG_SUPER_PW + "\n")
    if run_as:
        shutil.chown(base, user=run_as)
        shutil.chown(pwfile, user=run_as)
    os.chmod(base, 0o700)
    _pg_run([f"{PG_BIN}/initdb", "-D", str(data), "-U", "pgsuper", "--auth=scram-sha-256", f"--pwfile={pwfile}",
             "-E", "UTF8", "--locale=C.UTF-8"], user=run_as)
    _pg_run([f"{PG_BIN}/pg_ctl", "-D", str(data), "-l", str(base / "log"), "-w", "-o",
             f"-p {PG_PORT} -k {base} -c listen_addresses=127.0.0.1", "start"], user=run_as)
    import pg8000.native as pgn

    deadline = time.time() + 30
    while True:
        try:
            con = pgn.Connection("pgsuper", host="127.0.0.1", port=PG_PORT, password=PG_SUPER_PW, database="postgres")
            break
        except Exception:  # noqa: BLE001
            if time.time() > deadline:
                raise
            time.sleep(0.5)
    con.run(f"CREATE ROLE tscope_restore LOGIN CREATEDB PASSWORD '{PG_RESTORE_PW}'")
    con.close()
    os.environ[PG_PW_ENV] = PG_RESTORE_PW
    info = {"port": PG_PORT, "super": "pgsuper", "super_pw": PG_SUPER_PW, "restore": "tscope_restore",
            "restore_pw": PG_RESTORE_PW, "base": base}
    try:
        yield info
    finally:
        _pg_run([f"{PG_BIN}/pg_ctl", "-D", str(data), "-m", "immediate", "stop"], user=run_as, check=False)
        shutil.rmtree(base, ignore_errors=True)


def pg_super(database: str = "postgres"):
    import pg8000.native as pgn

    return pgn.Connection("pgsuper", host="127.0.0.1", port=PG_PORT, password=PG_SUPER_PW, database=database)


def configure_pg(home_dir: Path, **extra) -> None:
    cfg_path = home_dir / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg.setdefault("restore_targets", {})["postgres"] = {
        "host": "127.0.0.1", "port": PG_PORT, "login": "tscope_restore", "password_env": PG_PW_ENV,
        "bin_dir": PG_BIN, "database_prefix": "ingest_tscope_", **extra}
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))
