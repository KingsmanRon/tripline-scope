"""Cross-module: synthetic estate → .bak backups → restore + discovery + extract (ingest) → Module C matching
must give the same results as Module C's direct extract of the same data. Guards the PLAN §5 contract."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store

REPO = Path(__file__).resolve().parents[2]
PW = "Synth3tic!Demo"  # noqa: S105 - synthetic SQL Server Developer test container


def _mssql_up() -> bool:
    try:
        r = subprocess.run(["docker", "exec", "mssql-test", "/opt/mssql-tools18/bin/sqlcmd", "-S", "localhost", "-U", "sa",
                            "-P", PW, "-C", "-Q", "select 1"], capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _drop(prefix: str) -> None:
    q = ("DECLARE @n sysname; DECLARE c CURSOR FOR SELECT name FROM sys.databases WHERE name LIKE '" + prefix + "%'; "
         "OPEN c; FETCH NEXT FROM c INTO @n; WHILE @@FETCH_STATUS = 0 BEGIN "
         "EXEC('ALTER DATABASE [' + @n + '] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [' + @n + ']'); "
         "FETCH NEXT FROM c INTO @n; END; CLOSE c; DEALLOCATE c;")
    subprocess.run(["docker", "exec", "mssql-test", "/opt/mssql-tools18/bin/sqlcmd", "-S", "localhost", "-U", "sa", "-P", PW,
                    "-C", "-Q", q], capture_output=True, timeout=120)


def _evaluate(case_dir: Path, synth: Path, source_map: dict) -> dict:
    from tripline_scope.scope import config as scfg
    from tripline_scope.scope import data as sdata
    from tripline_scope.scope import evaluate, people
    from tripline_scope.scope.match import Matcher, make_pair_key

    case = Case(case_dir)
    store = open_store(case, Home())
    cfg = scfg.load(case)
    d = sdata.load(case, store, cfg)
    Matcher(d, cfg, pair_key=make_pair_key(store.fingerprinter("review-pairs"))).run()
    people.build(d.con, cfg, d.reference_date if hasattr(d, "reference_date") else d.ref)
    evaluate.load_ground_truth(d.con, synth / "ground_truth.parquet", source_map)
    return evaluate.evaluate(d.con)


@pytest.mark.docker
def test_real_ingest_matches_direct_extract(install, tmp_path, monkeypatch):
    if not _mssql_up():
        pytest.skip("SQL Server test container not available")
    from tripline_scope.scope import fixtures
    from tripline_scope.synth.generate import generate

    _drop("tscope_CONSIST")
    synth = tmp_path / "synth"
    generate(synth, 6000, seed=5)
    monkeypatch.setenv("TSCOPE_CONSIST_PW", PW)
    subprocess.run([sys.executable, str(REPO / "demo/lab-breach/build_baks.py"), "--synth", str(synth),
                    "--out", str(tmp_path / "baks"), "--password-env", "TSCOPE_CONSIST_PW", "--container", "mssql-test",
                    "--db-prefix", "consist_"], check=True, capture_output=True, env={**os.environ})
    cfgp = Path(os.environ["TSCOPE_HOME"]) / "config.yaml"
    c = yaml.safe_load(cfgp.read_text())
    c["restore_targets"] = {"mssql": {"host": "127.0.0.1", "port": 14330, "login": "sa", "password_env": "TSCOPE_CONSIST_PW",
                                      "backup_transfer": "docker_cp", "container": "mssql-test",
                                      "server_backup_dir": "/var/opt/mssql/backup/tscope-consist",
                                      "data_dir": "/var/opt/mssql/data", "encryption": False,
                                      "trust_server_certificate": True}}
    cfgp.write_text(yaml.safe_dump(c))
    try:
        real = testing.open_case(tmp_path / "a", "CONSIST-REAL")
        testing.login("olivia")
        common = ["--legal-basis", "synthetic", "--received-at", "2026-09-15T08:00:00Z", "--case", str(real),
                  "--supplied-by", "IT"]
        smap = {}
        for b in sorted((tmp_path / "baks").glob("*.bak")):
            rc, out, err = testing.run_cli(["--json", "source", "add", "--kind", "mssql_bak", "--path", str(b),
                                            "--label", b.stem, "--evidence-role", "system_copy", *common])
            assert rc == 0, err
            smap[f"db{int(b.stem[-2:]):02d}"] = json.loads(out)["source_id"]
        rc, out, err = testing.run_cli(["--json", "source", "add", "--kind", "csv", "--path", str(synth / "leak_sample.csv"),
                                        "--label", "leak", "--evidence-role", "leak_sample", "--copy", *common])
        assert rc == 0, err
        smap["leak_sample"] = json.loads(out)["source_id"]
        rc, out, err = testing.run_cli(["ingest", "--case", str(real)])
        assert rc == 0, err
        a = _evaluate(real, synth, smap)

        direct = testing.open_case(tmp_path / "b", "CONSIST-DIRECT")
        cb = Case(direct)
        sb = open_store(cb, Home())
        smap_b = fixtures.register_synth_sources(cb, sb, synth, actor="olivia")
        fixtures.load_synth_as_extract(cb, sb, synth, source_map=smap_b, actor="olivia")
        b = _evaluate(direct, synth, smap_b)
    finally:
        _drop("tscope_CONSIST")
    # Outcomes must be identical; redundant intra-cluster edges may differ by a few without changing any person.
    for k in ("identity_rows", "identity_rows_with_truth", "predicted_people", "predicted_segments", "review_band_people",
              "pairwise_precision", "pairwise_recall", "person_count_error"):
        assert a[k] == b[k], k
    assert a["auto_link_precision"] >= 0.995 and a["over_merged_predicted_people"] == b["over_merged_predicted_people"]
