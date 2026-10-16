"""Sources are never written: the write guard blocks writes during commands, and full SHA-256 checksums are
identical before and after every ingest / discover / map command (recorded in the audit log)."""

import os

import ingest_helpers as H
import pytest

from tripline_scope import testing
from tripline_scope.core.canonical import sha256_file
from tripline_scope.core.case import Case
from tripline_scope.ingest import files as files_mod


@pytest.fixture
def src(case_dir, tmp_path):
    testing.login("olivia")
    data = H.make_dataset(60)
    paths = [H.write_csv(tmp_path / "src" / f"{n}.csv", rows) for n, rows in data.items()]
    sid = H.add_source(case_dir, paths, "csv")
    return case_dir, paths, sid


def test_checksums_identical_and_recorded_for_every_command(src):
    case_dir, paths, sid = src
    before = {p: sha256_file(p) for p in paths}
    for argv in (["discover"], ["ingest"], ["map"], ["ingest", "status"], ["map", "--rediscover"]):
        rc, out, err = testing.run_cli(argv + ["--case", str(case_dir)])
        assert rc == 0, (argv, err)
        assert {p: sha256_file(p) for p in paths} == before
    entries = {e["command"]: e for e in Case(case_dir).audit.entries() if e["outcome"] == "ok"}
    for cmd in ("discover", "ingest", "map"):
        e = entries[cmd]
        recorded = {k: v for k, v in e["inputs"].items() if k.startswith("source:")}
        assert sorted(recorded.values()) == sorted(before.values())
        assert "identical before and after" in e["note"]


def test_write_guard_blocks_a_write_during_ingest(src, monkeypatch):
    case_dir, paths, sid = src
    before = sha256_file(paths[0])
    attempts = []
    real = files_mod.FileReader._csv_batches

    def evil(self, table, batch_rows, limit):
        for p in paths:
            for action in (lambda: open(p, "a"), lambda: os.remove(p), lambda: os.rename(p, str(p) + ".x"),
                           lambda: os.truncate(p, 0), lambda: os.chmod(p, 0o666)):
                try:
                    action()
                    attempts.append("allowed")
                except PermissionError:
                    attempts.append("blocked")
        yield from real(self, table, batch_rows, limit)

    monkeypatch.setattr(files_mod.FileReader, "_csv_batches", evil)
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir)])
    assert rc == 0, err
    assert attempts and set(attempts) == {"blocked"}
    assert sha256_file(paths[0]) == before and all(p.exists() for p in paths)


def test_source_changed_during_command_is_detected(src, monkeypatch):
    case_dir, paths, sid = src
    real = files_mod.FileReader._csv_batches

    def tamper(self, table, batch_rows, limit):
        # an outside process (not this one: the guard would stop us) appends to the original mid-command
        import subprocess

        subprocess.run(["sh", "-c", f"echo extra >> '{paths[0]}'"], check=True)
        yield from real(self, table, batch_rows, limit)

    monkeypatch.setattr(files_mod.FileReader, "_csv_batches", tamper)
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir)])
    assert rc == 4 and "changed" in err   # row-count consistency or the source checks
    last = list(Case(case_dir).audit.entries())[-1]
    assert last["command"] == "ingest" and last["outcome"] == "error"


def test_closure_without_restores_and_status_counts_only(src):
    case_dir, paths, sid = src
    assert testing.run_cli(["ingest", "--case", str(case_dir)])[0] == 0
    rc, out, err = testing.run_cli(["--json", "ingest", "restores", "--case", str(case_dir)])
    assert rc == 0 and '"restores": []' in out
    testing.login("ines")
    rc, out, err = testing.run_cli(["case", "close", "--case", str(case_dir), "--approver", "ines"])
    assert rc == 0, err
    import json

    cert = json.loads((case_dir / "reports" / "closure" / "certificate.json").read_text())
    assert cert["destroyed"]["restored_databases"] == []
    assert not any(p.is_file() for p in (case_dir / "work").rglob("*"))
