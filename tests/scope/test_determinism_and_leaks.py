"""Identical inputs give a byte-identical report; no synthetic identifier leaks outside the notification pack."""

import json
import re
import shutil

import pyarrow.parquet as pq

from conftest import c, cli, ingest
from tripline_scope import testing
from tripline_scope.core.home import Home
from tripline_scope.core.pdf import pdf_text
from tripline_scope.core.redact import find_identifier_like

HEX = re.compile(r"[0-9a-f]{16,}")


def _draft_bytes(case_dir):
    drafts = sorted((case_dir / "reports" / "scope" / "drafts").iterdir(), key=lambda p: p.stat().st_mtime)
    return (drafts[-1] / "report.json").read_bytes(), (drafts[-1] / "report.pdf").read_bytes()


def test_identical_inputs_byte_identical_report(install, tmp_path, synth_dir, monkeypatch):
    monkeypatch.setenv("TSCOPE_FIXED_NOW", "2026-09-20T08:00:00Z")
    out = []
    for name in ("a", "b"):
        case_dir = testing.open_case(tmp_path / name, "CASE-SAME")
        ingest(case_dir, synth_dir)
        cli(["estimate"] + c(case_dir), "olivia")
        cli(["scope", "match"] + c(case_dir))
        cli(["scope", "report"] + c(case_dir))
        out.append(_draft_bytes(case_dir))
        shutil.rmtree(case_dir)
        Home().wrapped_dek_path("CASE-SAME").unlink()
    assert out[0][0] == out[1][0]
    assert out[0][1] == out[1][1]
    body = json.loads(out[0][0])
    assert body["method_version"] and body["config_sha256"] and body["review_decisions_sha256"]
    assert body["measured_error_rates"]


def _identifiers(synth_dir) -> set[str]:
    t = pq.read_table(synth_dir / "ground_truth_identifiers.parquet")
    vals = set()
    for col in t.column_names:
        for v in t.column(col).to_pylist():
            if v and len(v) >= 6:
                vals.add(v)
                vals.add(v.lower())
                vals.add(v.title())
    return vals


def _scan(text: str, ids: set[str], where: str):
    hits = [v for v in ids if v in text]
    assert not hits, f"{where}: {len(hits)} synthetic identifiers found"
    assert not find_identifier_like(HEX.sub("#", text)), f"{where}: identifier-like content"


def test_no_identifiers_outside_notification_pack(scoped, synth_dir, tmp_path):
    case_dir, _ = scoped
    console = []
    for argv, user in ((["estimate"], "olivia"), (["scope", "match"], None), (["scope", "queue"], None),
                       (["scope", "decide", "--simulate-reviewer", str(synth_dir / "ground_truth.parquet")], "rami"),
                       (["scope", "match"], "olivia"), (["scope", "report"], None), (["scope", "notify", "build"], None)):
        rc, out, err = cli(argv + c(case_dir), user)
        console.append(json.dumps(out) + err)
    rc, out, err = cli(["release", "--kind", "scope", "--approver", "ines"] + c(case_dir))
    console.append(json.dumps(out) + err)
    export = tmp_path / "export"
    rc, out, err = cli(["scope", "notify", "export"] + c(case_dir) + ["--out", str(export), "--approver", "ines"])
    console.append(json.dumps(out) + err)
    ids = _identifiers(synth_dir)
    assert len(ids) > 1000
    _scan("\n".join(console), ids, "console")
    _scan((case_dir / "audit.log").read_text(), ids, "audit log")
    for p in (case_dir / "reports").rglob("*"):
        if p.is_file():
            data = p.read_bytes()
            text = pdf_text(data) if p.suffix == ".pdf" else data.decode("utf-8")
            _scan(text, ids, str(p.relative_to(case_dir)))
    # working files are encrypted envelopes: no plaintext identifiers on disk
    sample = sorted(ids)[:300]
    for sub in ("work", "review", "notify"):
        for p in (case_dir / sub).rglob("*.tse"):
            raw = p.read_bytes()
            assert not any(v.encode() in raw for v in sample), p
    # the exported notification pack is the exempt place where contact details belong
    people = (export / "people.csv").read_text()
    assert any(v in people for v in ids)
