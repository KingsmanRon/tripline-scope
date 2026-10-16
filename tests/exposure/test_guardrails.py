"""Guardrails: confinement to declared inputs, no network, network-namespace run, accepted risks, purge, manifest."""

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.exposure.synthetic import build

_REC = {"on": False, "paths": [], "who": []}
_HOOKED = False


def _hook(event, args):
    if not _REC["on"]:
        return
    if event in ("open", "os.scandir", "os.listdir") and args:
        p = args[0]
        if isinstance(p, bytes):
            p = os.fsdecode(p)
        if isinstance(p, str | os.PathLike):
            f, who = sys._getframe(1), "other"
            while f is not None:
                fn = f.f_code.co_filename
                if fn.endswith(os.path.join("core", "custody.py")) or f.f_code.co_name == "_content_hash":
                    who = "custody-hash"
                    break
                if fn.endswith(os.path.join("exposure", "walker.py")):
                    who = "scanner"
                    break
                f = f.f_back
            _REC["paths"].append(os.path.abspath(os.fspath(p)))
            _REC["who"].append(who)


def _record():
    global _HOOKED
    if not _HOOKED:
        sys.addaudithook(_hook)
        _HOOKED = True
    _REC["paths"] = []
    _REC["who"] = []
    _REC["on"] = True


@pytest.fixture
def synth_case(install, tmp_path):
    case_dir = testing.open_case(tmp_path, "READY-002", mode="readiness")
    gt = build(tmp_path / "synth")
    testing.login("olivia")
    return case_dir, tmp_path / "synth", gt


def _findings(case_dir):
    return open_store(Case(case_dir), Home()).read_json("work/exposure/findings.json")


def test_no_path_outside_declared_inputs_is_visited(synth_case):
    case_dir, synth, gt = synth_case
    _record()
    try:
        rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "manifest.yaml")])
    finally:
        _REC["on"] = False
    assert rc == 0, err
    paths = _REC["paths"]
    assert paths
    decoy, excluded = gt["decoy_dir"], gt["excluded_dir"]
    assert not [p for p in paths if p.startswith(decoy) or os.path.realpath(p).startswith(decoy)]
    # excluded paths are hashed for custody of the declared snapshot, but never opened for inspection
    by_scanner = [p for p, w in zip(paths, _REC["who"], strict=True) if w == "scanner"]
    assert by_scanner and not [p for p in by_scanner if p.startswith(excluded)]
    assert {w for p, w in zip(paths, _REC["who"], strict=True) if p.startswith(excluded)} <= {"custody-hash"}
    declared = [str((synth / x).resolve()) for x in ("snapshot", "catalog", "identity", "assets.yaml",
                                                     "accepted_risks.yaml", "manifest.yaml")]
    stray = [p for p in paths if p.startswith(str(synth.resolve())) and not any(p.startswith(d) for d in declared)]
    assert not stray, stray[:5]
    assert not [p for p in paths if p.endswith("ground_truth.json")]


def test_network_attempt_during_scan_is_refused(synth_case, monkeypatch):
    case_dir, synth, gt = synth_case
    import tripline_scope.exposure.scan as scanmod

    real = scanmod.profile_json
    seen = []

    def chatty(*a, **k):
        try:
            socket.create_connection(("127.0.0.1", 9), timeout=1)
        except PermissionError as exc:
            seen.append(type(exc).__name__)
            raise
        return real(*a, **k)

    monkeypatch.setattr(scanmod, "profile_json", chatty)
    rc, out, err = testing.run_cli(["--json", "exposure", "scan", "--case", str(case_dir), "--inputs",
                                    str(synth / "manifest.yaml")])
    assert rc == 0, err
    assert seen and set(seen) == {"PermissionError"}
    assert json.loads(out)["metrics"]["network_attempts_blocked"] >= 1
    # outside a scan the guard is inactive: an ordinary connection attempt fails with ECONNREFUSED, not the guard
    s = socket.socket()
    try:
        assert s.connect_ex(("127.0.0.1", 9)) != 0
    finally:
        s.close()


def test_scan_inside_network_namespace(synth_case, install):
    case_dir, synth, gt = synth_case
    if not shutil.which("unshare") or subprocess.run(["unshare", "-n", "true"], capture_output=True).returncode:
        pytest.skip("cannot create a network namespace here")
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "manifest.yaml")])
    assert rc == 0, err
    before = _findings(case_dir)
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ, **install.vars(), PYTHONPATH=f"{root / 'src'}:{root / 'verify' / 'src'}")
    env.pop("TSCOPE_SESSION", None)
    p = subprocess.run(["unshare", "-n", sys.executable, "-m", "tripline_scope", "--json", "exposure", "scan", "--case",
                        str(case_dir), "--inputs", str(synth / "manifest.yaml")], env=env, cwd=str(root),
                       capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr
    probe = subprocess.run(["unshare", "-n", sys.executable, "-c",
                            "import socket,sys\ns=socket.socket()\ns.settimeout(2)\n"
                            "sys.exit(0 if s.connect_ex(('1.1.1.1', 443)) != 0 else 1)"], capture_output=True)
    assert probe.returncode == 0  # the namespace really has no route out
    after = _findings(case_dir)
    assert [f["finding_id"] for f in after] == [f["finding_id"] for f in before]
    assert json.loads(p.stdout)["findings"] == len(before)


def test_accepted_risk_register_and_purge(synth_case):
    case_dir, synth, gt = synth_case
    c = str(case_dir)
    assert testing.run_cli(["exposure", "scan", "--case", c, "--inputs", str(synth / "manifest.yaml")])[0] == 0
    target = next(f for f in _findings(case_dir) if f["rule_id"] == "A4.pg-dblink")
    expired = next(f for f in _findings(case_dir) if f["rule_id"] == "A4.mssql-sa-enabled")
    (synth / "accepted_risks.yaml").write_text(yaml.safe_dump({"accepted_risks": [
        {"finding_id": target["finding_id"], "accepted_by": "Information Officer", "reason": "decommission Q1",
         "expires": "2027-03-31", "reference": "RISK-12"},
        {"finding_id": expired["finding_id"], "accepted_by": "Information Officer", "reason": "old",
         "expires": "2026-01-31"}]}))
    assert testing.run_cli(["exposure", "scan", "--case", c, "--inputs", str(synth / "manifest.yaml")])[0] == 0
    rc, out, err = testing.run_cli(["--json", "exposure", "report", "--case", c])
    assert rc == 0, err
    draft = json.loads(out)
    body = json.loads((case_dir / "reports" / "exposure" / "drafts" / draft["draft_id"] / "report.json").read_bytes())
    states = {f["finding_id"]: f for f in body["findings"]}
    assert states[target["finding_id"]]["state"] == "accepted-risk"
    assert states[target["finding_id"]]["accepted_risk"]["reference"] == "RISK-12"
    assert states[expired["finding_id"]]["state"] == "new"   # expired acceptance does not apply
    assert body["scan"]["accepted_risks_sha256"]
    rc, out, err = testing.run_cli(["exposure", "purge", "--case", c])
    assert rc == 0, err
    assert not list((case_dir / "work" / "exposure").rglob("*.tse"))
    rc, out, err = testing.run_cli(["exposure", "report", "--case", c])
    assert rc == 7 and "no exposure scan" in err


def test_reviewer_cannot_scan_and_manifest_validation(synth_case, tmp_path):
    case_dir, synth, gt = synth_case
    testing.login("rami")
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "manifest.yaml")])
    assert rc == 3
    testing.login("olivia")
    doc = yaml.safe_load((synth / "manifest.yaml").read_text())
    bad = dict(doc)
    bad.pop("budget")
    (synth / "nobudget.yaml").write_text(yaml.safe_dump(bad))
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "nobudget.yaml")])
    assert rc == 2 and "budget" in err
    bad = dict(doc, roots=[{"id": "x", "path": "does/not/exist", "kind": "share"}])
    (synth / "missing.yaml").write_text(yaml.safe_dump(bad))
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "missing.yaml")])
    assert rc == 2 and "does not exist" in err
    (synth / "garbage.yaml").write_text("schema: [unclosed")
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "garbage.yaml")])
    assert rc == 2


def test_malformed_catalogue_is_unavailable_not_fatal(synth_case):
    case_dir, synth, gt = synth_case
    (synth / "catalog" / "labdb_mssql.json").write_text('{"engine": "mssql", "queries": {"server_principals": 5}')
    rc, out, err = testing.run_cli(["exposure", "scan", "--case", str(case_dir), "--inputs", str(synth / "manifest.yaml")])
    assert rc == 0, err
    scan = open_store(Case(case_dir), Home()).read_json("work/exposure/scan.json")
    assert any(u["unit"] == "db:labdb" for u in scan["coverage"]["unavailable"])
    assert any(p["format"] == "catalogue" for p in scan["coverage"]["parser_failures"])
    assert not any(f["location"].get("database") == "labdb" and f["control_id"] == "A4" for f in _findings(case_dir))
