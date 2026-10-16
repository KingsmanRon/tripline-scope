"""Tests for the acceptance harness (leak scan, source safety, offline runner) using only the shared core.

The last test runs the core CLI flow (init -> users -> login -> case init -> sources -> verify -> audit) as
separate processes with networking disabled, proves every source is byte-identical and never opened for
writing around every command, and leak-scans every console capture, the installation home, the case
directory and the SIEM export for the synthetic identifiers.
"""

import datetime as dt
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from leakscan import GroundTruth, LeakScanner
from source_safety import RUN_OFFLINE, WriteWatcher, assert_source_safe, diff, run_commands, snapshot

from tripline_scope import testing
from tripline_scope.core.identifiers import make_sa_id
from tripline_scope.core.pdf import Section, render

ROOT = Path(__file__).resolve().parents[2]

PERSON = {
    "first_name": "Thandeka", "last_name": "Mokoena", "maiden_name": "Dlamini",
    "sa_id": make_sa_id(dt.date(1987, 3, 14), 4021),
    "phone": "082 555 0143", "email": "thandeka.mokoena@example.org",
    "medical_aid_no": "MA88412093", "local_patient_key": "LAB-7730215",
}
OTHER = {"full_name": "Pieter van der Merwe", "sa_id": make_sa_id(dt.date(1970, 11, 2), 5133, citizenship=1),
         "phone": "+27 21 555 0199", "email": "pvdm@example.net"}


@pytest.fixture
def gt():
    return GroundTruth.from_records([PERSON, OTHER])


# ------------------------------------------------------------------------------------------- leak scan
def test_ground_truth_loaders(tmp_path):
    (tmp_path / "gt.json").write_text(json.dumps({"meta": {"seed": 1}, "people": [PERSON, OTHER]}))
    (tmp_path / "gt.jsonl").write_text("\n".join(json.dumps(r) for r in (PERSON, OTHER)))
    (tmp_path / "gt.csv").write_text(f"first_name,last_name,sa_id,phone\nThandeka,Mokoena,{PERSON['sa_id']},0825550143\n")
    (tmp_path / "gt.txt").write_text(f"# identifiers\n{PERSON['sa_id']}\nthandeka.mokoena@example.org\n"
                                     "Thandeka Mokoena\n0825550143\nMA88412093\n")
    (tmp_path / "gt2.json").write_text(json.dumps({"sa_id": [PERSON["sa_id"]], "email": [PERSON["email"]]}))
    for name in ("gt.json", "gt.jsonl", "gt.csv", "gt.txt", "gt2.json"):
        g = GroundTruth.load(tmp_path / name)
        assert PERSON["sa_id"] in g.digits, name
    full = GroundTruth.load(tmp_path / "gt.json")
    assert ("thandeka", "mokoena") in full.names and ("mokoena", "thandeka") in full.names
    assert ("thandeka", "dlamini") in full.names            # maiden name
    assert "27825550143" in full.phones and "MA88412093" in full.tokens and "LAB7730215" in full.tokens
    (tmp_path / "empty.json").write_text("[]")
    with pytest.raises(ValueError):
        GroundTruth.load(tmp_path / "empty.json")


def test_scan_finds_identifiers_in_every_format(tmp_path, gt):
    out = tmp_path / "case"
    (out / "logs").mkdir(parents=True)
    sid = PERSON["sa_id"]
    (out / "logs" / "run.log").write_text(f"INFO matched record id {sid[:6]} {sid[6:10]} {sid[10:]}\n")
    (out / "result.json").write_text(json.dumps({"contact": "THANDEKA.MOKOENA@example.org"}))
    (out / "table.csv").write_text("ref,phone\n1,(082) 555-0143\n")
    (out / "intl.txt").write_text("call +27 21 555 0199 after hours\n")
    (out / "report.pdf").write_bytes(render("Scope report", ["synthetic"], [
        Section("People", ["Notified person: Mokoena, Thandeka (maiden name Dlamini)."])]))
    (out / "keys.txt").write_text("folder lab-7730215 and scheme member MA 8841 2093? no: MA88412093\n")
    (out / "archive.log.gz").write_bytes(gzip.compress(b"user Pieter van der Merwe exported rows\n"))
    import pyarrow as pa
    import pyarrow.parquet as pq

    pq.write_table(pa.table({"x": ["nothing", "ref " + PERSON["medical_aid_no"]]}), out / "plain.parquet")
    import openpyxl

    wb = openpyxl.Workbook()
    wb.active["A1"] = "pvdm@example.net"
    wb.save(out / "sheet.xlsx")
    rep = LeakScanner(gt).scan_tree(out)
    by_file = {}
    for f in rep.findings:
        by_file.setdefault(Path(f.where.split("!")[0]).name, set()).add(f.kind)
    assert "identifier:sa_id" in by_file["run.log"]
    assert "identifier:email" in by_file["result.json"]
    assert "identifier:phone" in by_file["table.csv"] and "identifier:phone" in by_file["intl.txt"]
    assert "identifier:name" in by_file["report.pdf"]
    assert "identifier:record_number" in by_file["keys.txt"]
    assert "identifier:name" in by_file["archive.log"]
    assert "identifier:record_number" in by_file["plain.parquet"]
    assert "identifier:email" in by_file["sheet.xlsx"]
    # findings never echo the identifier itself
    rendered = rep.summary()
    for value in (sid, "thandeka.mokoena@example.org", "Mokoena", "MA88412093"):
        assert value.lower() not in rendered.lower()


def test_exemptions_and_symlinks(tmp_path, gt):
    case = tmp_path / "case"
    (case / "notify").mkdir(parents=True)
    (case / "case.yaml").write_text("case_id: CASE-X\n")
    (case / "work" / "notify").mkdir(parents=True)            # not the notification pack: never exempt
    (case / "work" / "notify" / "x.txt").write_text("pvdm@example.net\n")
    (case / "notify" / "letters.csv").write_text(f"Thandeka Mokoena,{PERSON['sa_id']}\n")
    export = tmp_path / "approver-export"
    export.mkdir()
    (export / "pack.csv").write_text("thandeka.mokoena@example.org\n")
    original = tmp_path / "original.csv"
    original.write_text(f"{PERSON['sa_id']}\n")
    (case / "sources").mkdir()
    (case / "sources" / "leak.csv").symlink_to(original)
    (case / "work" / "notify-not-exempt.txt").write_text("Thandeka Mokoena\n")
    rep = LeakScanner(gt, exempt=["notify", str(export)]).scan_tree(case)
    assert {Path(f.where).name for f in rep.findings} == {"notify-not-exempt.txt", "x.txt"}
    assert any("(symlink)" in s for s in rep.skipped) and any("(exempt)" in s for s in rep.skipped)
    # an explicitly passed approver export directory is exempt wherever the scan starts
    assert LeakScanner(gt, exempt=[str(export)]).scan_tree(export).clean
    rep2 = LeakScanner(gt, exempt=["notify", str(export)]).scan_tree(tmp_path)
    assert {Path(f.where).name for f in rep2.findings} == {"notify-not-exempt.txt", "x.txt", "original.csv"}


def test_identifier_like_patterns_and_hash_masking(tmp_path):
    unknown_id = make_sa_id(dt.date(1992, 6, 30), 7788)
    scanner = LeakScanner(None)
    assert {f.kind for f in scanner.scan_text(f"id {unknown_id}", "t")} == {"pattern:sa_id"}
    assert {f.kind for f in scanner.scan_text("card 4111 1111 1111 1111", "t")} == {"pattern:card"}
    assert {f.kind for f in scanner.scan_text("mail someone@example.com", "t")} == {"pattern:email"}
    assert {f.kind for f in scanner.scan_text("cell 072 123 4567", "t")} == {"pattern:phone"}
    # hex digests and base64 signatures are masked before the pattern scan, even when they embed a valid id
    digest = ("ab" + unknown_id + "cd").ljust(64, "e")
    sig = "A" * 10 + unknown_id + "Zm9vYmFy" * 4
    text = f'{{"report_sha256": "{digest}", "signature": "{sig}=="}}'
    assert scanner.scan_text(text, "audit.log") == []
    assert scanner.scan_text("contact it-support@hospital.example", "t") != []
    assert LeakScanner(None, allow_values=["it-support@hospital.example"]).scan_text(
        "contact it-support@hospital.example", "t") == []


def test_console_capture_scan(gt):
    out, err = "source_id: SRC-001\nfiles: 1\n", "WARNING could not parse row for Pieter van der Merwe\n"
    s = LeakScanner(gt)
    assert s.scan_text(out, "console:stdout") == []
    found = s.scan_text(err, "console:stderr")
    assert [f.kind for f in found] == ["identifier:name"] and found[0].line == 1


def test_cli_entry(tmp_path):
    (tmp_path / "gt.json").write_text(json.dumps([PERSON]))
    d = tmp_path / "out"
    d.mkdir()
    (d / "ok.txt").write_text("nothing here\n")
    run = [sys.executable, str(ROOT / "tests" / "acceptance" / "leakscan.py"), "--ground-truth",
           str(tmp_path / "gt.json"), "--json", str(d)]
    env = dict(os.environ, PYTHONPATH=f"{ROOT / 'src'}:{ROOT / 'verify' / 'src'}")
    assert subprocess.run(run, env=env, capture_output=True).returncode == 0
    (d / "bad.txt").write_text(PERSON["email"])
    r = subprocess.run(run, env=env, capture_output=True, text=True)
    assert r.returncode == 1 and json.loads(r.stdout)["findings"][0]["kind"] == "identifier:email"


# ------------------------------------------------------------------------------------------- source safety
def test_snapshot_diff_detects_every_change(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    f = src / "a.csv"
    f.write_text("a\n")
    (src / "sub" / "b.csv").write_text("b\n")
    (src / "link").symlink_to(f)
    before = snapshot([src])
    assert diff(before, snapshot([src])) == []
    f.write_text("A\n")
    os.utime(f, ns=(before[str(f)].mtime_ns, before[str(f)].mtime_ns))   # content change with mtime restored
    os.chmod(src / "sub" / "b.csv", 0o600)
    (src / "sub" / "c.csv").write_text("c\n")
    (src / "link").unlink()
    (src / "link").symlink_to(src / "sub")
    changes = "\n".join(diff(before, snapshot([src])))
    assert "a.csv: sha256" in changes
    assert "b.csv: mode" in changes
    assert "added" in changes and "c.csv" in changes
    assert any(ln.endswith("/link: mtime_ns, target") or ln.endswith("/link: target") for ln in changes.splitlines())


def test_write_watcher_sees_writes_not_reads(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    f = src / "data.csv"
    f.write_text("x\n")
    os.utime(f, (1_600_000_000, 1_600_000_000))
    with WriteWatcher([src]) as w:
        f.read_bytes()
        with open(f, "rb"):
            pass
        assert w.poll() == []
        with open(f, "ab"):
            pass                                  # opened for writing, nothing written: still reported
        assert any("CLOSE_WRITE" in k for _, k in w.poll())
        os.chmod(f, 0o444)
        assert any("ATTRIB" in k for _, k in w.poll())


def test_run_commands_reports_violations(tmp_path):
    f = tmp_path / "source.csv"
    f.write_text("x\n")

    def reader():
        return 0, f.read_text(), ""

    def writer():
        with open(f, "a") as fh:
            fh.write("y\n")
        return 0, "", ""

    results = run_commands([("read", reader), ("write", writer)], [f])
    assert results[0].source_safe and not results[1].source_safe
    assert results[1].changes and results[1].write_events
    with pytest.raises(AssertionError, match="write"):
        assert_source_safe(results)


# ------------------------------------------------------------------------------------------- offline runner
PROBE = r"""
import errno, socket, sys
ifaces = [l.split(":")[0].strip() for l in open("/proc/self/net/dev").read().splitlines()[2:]]
results = {}
for host, port in (("1.1.1.1", 443), ("10.0.0.1", 80), ("127.0.0.1", 39233), ("pypi.org", 443)):
    try:
        socket.create_connection((host, port), timeout=3).close()
        results[host] = "connected"
    except OSError as exc:
        results[host] = type(exc).__name__
print(ifaces, results)
sys.exit(0 if ifaces == ["lo"] and "connected" not in results.values() else 1)
"""


def test_run_offline_has_no_network(offline):
    r = subprocess.run([str(offline), sys.executable, "-c", PROBE], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "['lo']" in r.stdout


def test_run_offline_refuses_when_it_cannot_isolate(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("sh", "id", "cat", "dirname", "basename"):
        for d in ("/usr/bin", "/bin"):
            if os.path.exists(f"{d}/{tool}"):
                (bindir / tool).symlink_to(f"{d}/{tool}")
                break
    env = {"PATH": str(bindir)}  # no unshare available
    r = subprocess.run([str(bindir / "sh"), str(RUN_OFFLINE), "true"], env=env, capture_output=True, text=True)
    assert r.returncode == 96 and "cannot disable networking" in r.stderr


# ------------------------------------------------------------------------------------------- core flow
def test_core_cli_flow_offline_is_source_safe_and_leak_free(offline, tmp_path, gt):
    src = tmp_path / "originals"
    (src / "logs").mkdir(parents=True)
    patients = src / "patients.csv"
    patients.write_text("first_name,last_name,sa_id,phone,email,medical_aid_no\n"
                        f"{PERSON['first_name']},{PERSON['last_name']},{PERSON['sa_id']},{PERSON['phone']},"
                        f"{PERSON['email']},{PERSON['medical_aid_no']}\n")
    leak = src / "leak_sample.csv"
    leak.write_text(f"name,id\n{OTHER['full_name']},{OTHER['sa_id']}\n")
    (src / "logs" / "app.log").write_text(f"2026-09-03T10:00:00Z login ok user={PERSON['email']}\n")
    for p in (patients, leak, src / "logs" / "app.log"):
        os.chmod(p, 0o444)
    sources = [src]
    home, case, exports = tmp_path / "install", tmp_path / "case", tmp_path / "exports"
    exports.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TSCOPE_", "OTEL_"))}
    env.update(testing.Env(home, tmp_path / "session.token").vars())
    env["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT / 'verify' / 'src'}"
    tscope = [sys.executable, "-m", "tripline_scope"]
    add = ["source", "add", "--case", str(case), "--legal-basis", "POPIA s22 incident response",
           "--supplied-by", "Hospital IT", "--received-at", "2026-09-15T08:00:00Z"]
    commands = [
        ("version", tscope + ["--version"]),
        ("init", tscope + ["init", "--hospital-name", "Synthetic Hospital", "--admin", "admin",
                           "--kek", str(tmp_path / "kek-media" / "kek.json")]),
        ("login admin", tscope + ["login", "--user", "admin"]),
        *[(f"user add {u}", tscope + ["user", "add", u]) for u in ("olivia", "rami", "ines")],
        ("case init", tscope + ["case", "init", str(case), "--case-id", "CASE-ACC-001", "--operator", "olivia",
                                "--reviewer", "rami", "--approver", "ines", "--incident-start",
                                "2026-09-01T00:00:00Z", "--incident-end", "2026-09-14T23:59:59Z"]),
        ("login olivia", tscope + ["login", "--user", "olivia"]),
        ("source add system copy", tscope + add + ["--kind", "csv", "--path", str(patients), "--label",
                                                   "LIS patient extract", "--evidence-role", "system_copy"]),
        ("source add leak (copy)", tscope + add + ["--kind", "csv", "--path", str(leak), "--label", "leak sample",
                                                   "--evidence-role", "leak_sample", "--copy"]),
        ("source add logs", tscope + add + ["--kind", "log", "--path", str(src / "logs"), "--label", "app logs",
                                            "--evidence-role", "log"]),
        ("source list", tscope + ["source", "list", "--case", str(case)]),
        ("source verify", tscope + ["source", "verify", "--case", str(case), "--full"]),
        ("case show", tscope + ["--json", "case", "show", "--case", str(case)]),
        ("case gap", tscope + ["case", "gap", "--case", str(case), "--description", "firewall logs rotated"]),
        ("audit verify", tscope + ["audit", "verify", "--case", str(case)]),
        ("audit export", tscope + ["audit", "export", "--case", str(case), "--out", str(exports / "siem.jsonl")]),
        ("verify", tscope + ["verify", "--case", str(case)]),
        ("doctor", tscope + ["doctor"]),
    ]
    digests = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in src.rglob("*") if p.is_file()}
    results = run_commands(commands, sources, env=env, cwd=tmp_path, offline=True)
    failed = [(r.label, r.returncode, r.stderr[-400:]) for r in results if r.returncode != 0]
    assert not failed, failed
    assert_source_safe(results)                     # identical before/after every command, no write opens
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in src.rglob("*") if p.is_file()} == digests
    scanner = LeakScanner(gt)
    report = scanner.scan_tree(home)
    report.extend(scanner.scan_tree(case))
    report.extend(scanner.scan_tree(exports))
    for r in results:
        report.extend(scanner.scan_text(r.stdout, f"console:{r.label}:stdout"))
        report.extend(scanner.scan_text(r.stderr, f"console:{r.label}:stderr"))
    report.assert_clean()
    assert report.files_scanned >= 8 and any("(symlink)" in s for s in report.skipped)
    # the scan is meaningful: the originals (inputs) do contain the identifiers
    assert not scanner.scan_tree(src).clean
