import os

import pytest

from tripline_scope import testing
from tripline_scope.core import custody
from tripline_scope.core.case import Case
from tripline_scope.core.errors import PermissionDenied


def _add(case_dir, path, *extra, kind="csv", role="leak_sample"):
    return testing.run_cli(["--json", "source", "add", "--case", str(case_dir), "--kind", kind, "--path", str(path),
                            "--label", "test source", "--evidence-role", role, "--legal-basis", "POPIA s22 incident",
                            "--supplied-by", "Hospital legal counsel", "--received-at", "2026-09-15T08:00:00Z", *extra])


def test_separation_of_duties_at_case_init(install, tmp_path):
    testing.login("admin")
    rc, out, err = testing.run_cli(["case", "init", str(tmp_path / "c"), "--case-id", "C-SOD", "--operator", "olivia",
                                    "--approver", "olivia", "--incident-start", "2026-01-01T00:00:00Z",
                                    "--incident-end", "2026-01-02T00:00:00Z"])
    assert rc != 0 and "separation of duties" in err


def test_roles_enforced(case_dir, tmp_path):
    f = tmp_path / "leak.csv"
    f.write_text("a,b\n1,2\n")
    testing.login("rami")  # reviewer cannot register sources
    rc, out, err = _add(case_dir, f)
    assert rc == 3
    testing.login("olivia")
    rc, out, err = _add(case_dir, f)
    assert rc == 0, err
    case = Case(case_dir)
    log = list(case.audit.entries())
    assert [e["outcome"] for e in log if e["command"] == "source add"] == ["denied", "ok"]
    with pytest.raises(PermissionDenied):
        case.assign("olivia", "approver")


def test_reference_source_custody_and_write_guard(case_dir, tmp_path):
    f = tmp_path / "leak.csv"
    f.write_text("a,b\n1,2\n")
    before = f.read_bytes()
    testing.login("olivia")
    rc, out, err = _add(case_dir, f)
    assert rc == 0, err
    case = Case(case_dir)
    s = case.sources()[0]
    assert s["files"][0]["sha256"] and s["supplied_by"] == "Hospital legal counsel"
    assert (case_dir / "sources" / s["source_id"] / "leak.csv").is_symlink()
    custody.protect_case_sources(case)
    with pytest.raises(PermissionError):
        open(f, "a")
    with pytest.raises(PermissionError):
        open(case_dir / "sources" / s["source_id"] / "leak.csv", "w")
    with pytest.raises(PermissionError):
        os.remove(f)
    with pytest.raises(PermissionError):
        os.chmod(f, 0o777)
    assert f.read_bytes() == before
    assert custody.full_check(case)
    # unlinking the case's own symlink is allowed (does not touch the original)
    (case_dir / "sources" / s["source_id"] / "leak.csv").unlink()
    assert f.exists()


def test_modified_source_detected(case_dir, tmp_path):
    f = tmp_path / "data" / "x.csv"
    f.parent.mkdir()
    f.write_text("a\n1\n")
    testing.login("olivia")
    assert _add(case_dir, f)[0] == 0
    # simulate someone else modifying the original outside the product
    import subprocess

    subprocess.run(["sh", "-c", f"echo 2 >> '{f}'"], check=True)
    rc, out, err = testing.run_cli(["source", "list", "--case", str(case_dir)])
    assert rc == 0  # read-only listing still works
    rc, out, err = testing.run_cli(["case", "gap", "--case", str(case_dir), "--description", "x"])
    assert rc == 4 and "source changed" in err


def test_encrypted_copy(case_dir, tmp_path):
    f = tmp_path / "sample.csv"
    f.write_text("name\nMARKER_SECRET_ROW\n")
    testing.login("olivia")
    rc, out, err = _add(case_dir, f, "--copy")
    assert rc == 0, err
    enc = list((case_dir / "sources").rglob("*.tse"))
    assert enc and b"MARKER_SECRET_ROW" not in enc[0].read_bytes()
    from tripline_scope.core.home import Home
    from tripline_scope.core.store import open_store

    case = Case(case_dir)
    with custody.open_source_file(case, open_store(case, Home()), "SRC-001", "sample.csv") as fh:
        assert b"MARKER_SECRET_ROW" in fh.read()
