"""Walker guardrails: confinement, symlinks, special files, exclusions, budgets, archive bombs, inaccessible files."""

import gzip
import io
import os
import zipfile
from pathlib import Path

import pytest
import yaml

from tripline_scope.exposure.coverage import Recorder
from tripline_scope.exposure.filetypes import sniff
from tripline_scope.exposure.manifest import load_manifest
from tripline_scope.exposure.walker import Budget, BudgetExhausted, Walker


def _manifest(tmp_path, budget=None, exclusions=None):
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    doc = {"schema": "tripline.exposure-manifest/v1", "owner": "IT", "legal_basis": "test",
           "received_at": "2026-10-01T00:00:00Z", "budget": budget or {"max_file_bytes": 4096},
           "exclusions": exclusions or [], "roots": [{"id": "r1", "path": "root", "kind": "share"}]}
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(doc))
    return root


def _walk(tmp_path, expand=False):
    m = load_manifest(tmp_path / "m.yaml")
    rec = Recorder()
    w = Walker(m, Budget(m.budget), rec)
    items = []

    def visit(it):
        items.append(it)
        k = sniff(it.rel, it.header)
        if expand and it.complete and k in ("zip", "tar", "gzip"):
            for mem in w.expand(it, k):
                visit(mem)

    for it in w.walk(m.roots[0]):
        visit(it)
    return items, rec


def test_symlinks_never_followed_and_escapes_rejected(tmp_path):
    root = _manifest(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("decoy")
    (root / "a.txt").write_text("x")
    (root / "esc_dir").symlink_to(outside, target_is_directory=True)
    (root / "esc_file").symlink_to(outside / "secret.txt")
    (root / "rel_esc").symlink_to(Path("..") / "outside" / "secret.txt")
    (root / "loop").symlink_to(".", target_is_directory=True)
    items, rec = _walk(tmp_path)
    assert [i.rel for i in items] == ["a.txt"]
    kinds = {(e["kind"], e["location"]) for e in rec.exclusions}
    assert ("symlink-escape-rejected", "r1:esc_dir") in kinds and ("symlink-escape-rejected", "r1:rel_esc") in kinds
    assert ("symlink-not-followed", "r1:loop") in kinds


def test_fifo_never_opened_and_exclusions(tmp_path):
    root = _manifest(tmp_path, exclusions=["**/node_modules/**", "*.log"])
    os.mkfifo(root / "pipe")
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "c.js").write_text("y")
    (root / "app.log").write_text("z")
    (root / "keep.txt").write_text("k")
    items, rec = _walk(tmp_path)  # a FIFO opened for reading would block: completing proves it was not opened
    assert [i.rel for i in items] == ["keep.txt"]
    assert {e["kind"] for e in rec.exclusions} == {"special-file", "declared-exclusion"}


def test_large_file_header_only_and_unavailable(tmp_path):
    root = _manifest(tmp_path)
    with open(root / "big.bak", "wb") as fh:
        fh.write(b"TAPE")
        fh.truncate(1 << 20)
    items, rec = _walk(tmp_path)
    assert items[0].data is None and items[0].header.startswith(b"TAPE") and len(items[0].header) <= 4096
    assert any("per-file size budget" in u["reason"] for u in rec.unavailable)


def test_file_count_budget(tmp_path):
    root = _manifest(tmp_path, budget={"max_files": 3})
    for i in range(10):
        (root / f"f{i}.txt").write_text("x")
    with pytest.raises(BudgetExhausted):
        _walk(tmp_path)


def test_inaccessible_file_reported_unavailable(tmp_path, monkeypatch):
    root = _manifest(tmp_path)
    (root / "locked.txt").write_text("x")
    (root / "ok.txt").write_text("y")
    real = os.open

    def fake_open(path, flags, *a, **k):
        if str(path).endswith("locked.txt"):
            raise PermissionError(13, "denied")
        return real(path, flags, *a, **k)

    monkeypatch.setattr("tripline_scope.exposure.walker.os.open", fake_open)
    items, rec = _walk(tmp_path)
    assert [i.rel for i in items] == ["ok.txt"]
    assert rec.unavailable[0]["reason"] == "file not readable (PermissionError)"


def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
    return buf.getvalue()


def test_archive_bombs_depth_and_member_limits(tmp_path):
    root = _manifest(tmp_path, budget={"max_file_bytes": 1 << 20, "archive_max_depth": 2, "archive_max_members": 5,
                                       "archive_max_ratio": 50, "archive_max_total_bytes": 1 << 20})
    (root / "bomb.zip").write_bytes(_zip({"z.csv": b"0" * (900 << 10)}))
    (root / "gz.csv.gz").write_bytes(gzip.compress(b"0" * (900 << 10)))
    (root / "many.zip").write_bytes(_zip({f"m{i}.txt": b"x" for i in range(9)}))
    inner = _zip({"deep.txt": b"deep"})
    (root / "nest.zip").write_bytes(_zip({"l1.zip": _zip({"l2.zip": inner})}))
    (root / "ok.zip").write_bytes(_zip({"../../evil/../a.txt": b"fine"}))
    items, rec = _walk(tmp_path, expand=True)
    rels = {i.rel for i in items}
    assert "ok.zip!a.txt" in rels  # member names are normalised; nothing is ever extracted to disk
    assert "nest.zip!l1.zip!l2.zip" in rels and not any(r.endswith("deep.txt") for r in rels)
    assert len([r for r in rels if r.startswith("many.zip!")]) == 5
    reasons = " | ".join(u["reason"] for u in rec.unavailable)
    assert "possible archive bomb" in reasons and "depth budget" in reasons and "more members" in reasons
    assert rec.counts["A3"]["archive_bombs_refused"] == 2


def test_sniffing():
    assert sniff("x.bak", b"TAPE\x00") == "mssql_backup"
    assert sniff("x.dump", b"PGDMP\x01") == "pg_custom_dump"
    assert sniff("x.xlsx", b"PK\x03\x04") == "xlsx" and sniff("x.zip", b"PK\x03\x04") == "zip"
    assert sniff("x.7z", b"7z\xbc\xaf\x27\x1c") == "7z"
    assert sniff("x.mdf", bytes([1, 15]) + bytes(200)) == "mssql_data_file"
    assert sniff("x.txt", b"hello") == "text" and sniff("x.bin", b"\x00\x01") == "binary"
