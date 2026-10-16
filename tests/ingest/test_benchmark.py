"""Throughput measurements (``-m slow``): ~200k rows per engine through restore, discovery and extraction.

Run: ``pytest -q -m slow tests/ingest/test_benchmark.py -s`` (needs Docker SQL Server and PostgreSQL binaries).
Results are printed and written to ``$BENCH_OUT`` (JSON) when set.
"""

import json
import os
import subprocess
import time

import ingest_helpers as H
import pytest

from conftest import (
    MSSQL,
    MSSQL_PW_ENV,
    PG_BIN,
    PG_PORT,
    PG_PW_ENV,
    PG_SUPER_PW,
    configure_mssql,
    configure_pg,
    drop_test_databases,
    load_build_baks,
    pg_super,
    write_synth_parquet,
)
from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store

pytestmark = pytest.mark.slow
N_PATIENTS = int(os.environ.get("BENCH_PATIENTS", "40000"))
RESULTS: dict = {}


def _record(name, case_dir, sid, wall):
    store = open_store(Case(case_dir), Home())
    st = store.read_json(f"work/ingest/{sid}.json")
    RESULTS[name] = {"rows": st["rows"], "extracted_rows": st["extracted_rows"], "tables": st["tables"],
                     "timings_s": st["timings_s"], "rows_per_s": st["rows_per_s"], "command_wall_s": round(wall, 2)}
    print(f"\n{name}: {json.dumps(RESULTS[name])}")
    _save()


def _save():
    out = os.environ.get("BENCH_OUT")
    if out:
        with open(out, "w") as fh:
            json.dump(RESULTS, fh, indent=2)


@pytest.fixture(autouse=True)
def _only_when_selected(request):
    if "slow" not in (request.config.getoption("-m") or ""):
        pytest.skip("benchmark: run with -m slow")


def _ingest(case_dir):
    t = time.monotonic()
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(case_dir)])
    assert rc == 0, err
    return time.monotonic() - t


def test_bench_csv(case_dir, tmp_path):
    testing.login("olivia")
    data = H.make_dataset(N_PATIENTS, seed=99)
    paths = [H.write_csv(tmp_path / "csv" / f"{n}.csv", rows) for n, rows in data.items()]
    sid = H.add_source(case_dir, paths, "csv")
    _record("csv", case_dir, sid, _ingest(case_dir))


@pytest.mark.docker
def test_bench_mssql(install, case_dir, mssql, tmp_path, monkeypatch):
    synth = write_synth_parquet(tmp_path / "synth", n_patients=N_PATIENTS, seed=99)
    (synth / "sources" / "db02").rename(tmp_path / "unused_db02")
    out = tmp_path / "baks"
    t = time.monotonic()
    assert load_build_baks().main(["--synth", str(synth), "--out", str(out), "--host", MSSQL["host"], "--port",
                                   str(MSSQL["port"]), "--container", MSSQL["container"], "--password-env",
                                   MSSQL_PW_ENV, "--db-prefix", "ingest_bench_",
                                   "--server-backup-dir", "/var/opt/mssql/backup/ingest_build"]) == 0
    build_s = time.monotonic() - t
    configure_mssql(install.home_dir)
    monkeypatch.setenv(MSSQL_PW_ENV, mssql["password"])
    testing.login("olivia")
    sid = H.add_source(case_dir, out / "ingest_bench_LabDB01.bak", "mssql_bak")
    try:
        _record("mssql_bak", case_dir, sid, _ingest(case_dir))
        RESULTS["mssql_bak"]["bak_build_s"] = round(build_s, 2)
        RESULTS["mssql_bak"]["bak_bytes"] = (out / "ingest_bench_LabDB01.bak").stat().st_size
        _save()
    finally:
        drop_test_databases()


@pytest.mark.postgres
def test_bench_pg_custom(install, case_dir, pg_cluster, tmp_path, monkeypatch):
    data = H.make_dataset(N_PATIENTS, seed=99)
    con = pg_super()
    con.run("DROP DATABASE IF EXISTS ingest_bench WITH (FORCE)")
    con.run("CREATE DATABASE ingest_bench")
    con.close()
    con = pg_super("ingest_bench")
    for name, rows in data.items():
        cols = list(rows[0])
        con.run(f"CREATE TABLE {name} ({', '.join(f'{c} text' for c in cols)})")
        con.run(f"COPY {name} FROM STDIN", stream=["".join(
            "\t".join(str(r[c]) if r[c] not in (None, "") else "\\N" for c in cols) + "\n" for r in rows)])
    con.run("ALTER TABLE patients ADD PRIMARY KEY (patientid)")
    con.close()
    dump = tmp_path / "bench.dump"
    subprocess.run([f"{PG_BIN}/pg_dump", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "pgsuper", "-Fc", "-f",
                    str(dump), "ingest_bench"], check=True, env=dict(os.environ, PGPASSWORD=PG_SUPER_PW))
    con = pg_super()
    con.run("DROP DATABASE ingest_bench WITH (FORCE)")
    con.close()
    configure_pg(install.home_dir)
    monkeypatch.setenv(PG_PW_ENV, pg_cluster["restore_pw"])
    testing.login("olivia")
    sid = H.add_source(case_dir, dump, "pg_dump")
    try:
        _record("pg_custom", case_dir, sid, _ingest(case_dir))
    finally:
        con = pg_super()
        for (name,) in con.run("SELECT datname FROM pg_database WHERE datname LIKE 'ingest_tscope_%'"):
            con.run(f'DROP DATABASE "{name}" WITH (FORCE)')
        con.close()
