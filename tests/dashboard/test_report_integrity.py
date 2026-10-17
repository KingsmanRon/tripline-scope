"""Integrity gate: released data is shown only after its signed report chain verifies, every read is bound to the
verified hashes, a failure is refused with an explicit warning, and the verification cache follows file changes.

Each test works on a private copy of the installation (tampering never touches the shared case)."""

import json
import os
import subprocess

import pytest
from dashkit import API, signed_in

from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store


@pytest.fixture
def private(built, tmp_path, monkeypatch):
    src, dst = built.case_dir.parent, tmp_path / "inst"
    subprocess.run(["cp", "-a", str(src), str(dst)], check=True)   # child process: no source write guard
    for p in dst.rglob("*.yaml"):
        p.write_text(p.read_text().replace(str(src), str(dst)))
    env = testing.Env(dst / "home", dst / "session.token")
    for k, v in env.vars().items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("TSCOPE_SESSION", raising=False)
    case = Case(dst / built.case_dir.name)
    home = Home()
    return case, open_store(case, home), home


def _vdir(case, kind, n=1):
    return case.root / "reports" / kind / f"v{n:04d}"


def _rewrite(path, fn):
    path.chmod(0o644)
    path.write_bytes(fn(path.read_bytes()))


def _tamper_report(case, kind, mutate, n=1):
    def fn(raw):
        doc = json.loads(raw)
        mutate(doc)
        return canonical_bytes(doc)
    _rewrite(_vdir(case, kind, n) / "report.json", fn)


def _is_failure(body, kind):
    return body["status"] == "integrity_failure" and body["kind"] == kind and body["warning"].startswith(
        f"INTEGRITY FAILURE: the released {kind} report chain failed verification")


def test_tampered_report_is_refused_with_an_explicit_warning(private):
    case, store, home = private
    c = signed_in(case, store, home)
    assert c.get("/api/paths").json()["status"] == "released"
    _tamper_report(case, "paths", lambda d: d.update(limitations=["zzTamperedSentinelzz"]))
    r = c.get("/api/paths").json()
    assert _is_failure(r, "paths") and "paths" not in r and "zzTamperedSentinelzz" not in json.dumps(r)
    t = c.get("/api/timeline").json()
    assert _is_failure(t, "paths") and t["events"] == [] and t["total"] is None
    ov = c.get("/api/overview").json()
    assert _is_failure(ov["reports"]["paths"], "paths") and "report_status" not in ov["reports"]["paths"]
    assert _is_failure(ov["module_b"], "paths")
    assert ov["reports"]["exposure"]["status"] == "released"          # other kinds stay available
    # Module A is shown, but its Module B cross-references (from the tampered report) are withheld
    ex = c.get("/api/exposure").json()
    assert ex["status"] == "released" and ex["findings"]
    assert ex["module_b_cross_references"]["status"] == "integrity_failure"
    assert ex["module_b_cross_references"]["by_finding"] == {}
    rep = c.get("/api/reports").json()["kinds"]["paths"]
    assert _is_failure(rep, "paths") and rep["versions"] == [] and rep["verification"]["ok"] is False
    # every view announces the failure; downloads of the affected kind are refused, others still served
    for path in API:
        alerts = c.get(path).json()["integrity_alerts"]
        assert [a["kind"] for a in alerts] == ["paths"], path
    d = c.get("/reports/paths/v1/report.json")
    assert d.status_code == 409 and d.json()["error"].startswith("INTEGRITY FAILURE") and b"zzTampered" not in d.content
    assert c.get("/reports/paths/v1/release.json").status_code == 409
    assert c.get("/reports/exposure/v1/report.json").status_code == 200


def test_tampered_attachment_and_signature_are_refused(private):
    case, store, home = private
    c = signed_in(case, store, home)
    assert c.get("/api/timeline").json()["status"] == "released"
    tl = _vdir(case, "paths") / "attachments" / "timeline.jsonl"
    _rewrite(tl, lambda raw: raw + b'{"ts_utc": "2026-09-03T23:30:00Z", "family": "proxy"}\n')
    assert _is_failure(c.get("/api/timeline").json(), "paths")
    # a forged scope release (re-hashed but not re-signed) is refused too
    def forge(raw):
        rel = json.loads(raw)
        rel["approval"]["approver"] = "mallory"
        return canonical_bytes(rel)
    _rewrite(_vdir(case, "scope", 2) / "release.json", forge)
    p = c.get("/api/people").json()
    assert _is_failure(p, "scope") and "refined" not in p and "preliminary_estimate" not in p
    assert sorted(a["kind"] for a in p["integrity_alerts"]) == ["paths", "scope"]


def test_cache_follows_file_changes_even_when_mtime_is_restored(private):
    case, store, home = private
    c = signed_in(case, store, home)
    gate = c.app.state.dashboard.gate
    assert c.get("/api/paths").json()["status"] == "released"
    n = gate.verifications
    c.get("/api/paths")
    c.get("/api/timeline")
    assert gate.verifications == n                        # unchanged files: the verified result is reused
    rj = _vdir(case, "paths") / "report.json"
    st = rj.stat()
    original = rj.read_bytes()
    assert b"egress_suspected" in original
    _rewrite(rj, lambda raw: raw.replace(b"egress_suspected", b"egress_suspectee", 1))   # same size
    os.utime(rj, ns=(st.st_atime_ns, st.st_mtime_ns))                                      # same mtime
    assert rj.stat().st_size == st.st_size and rj.stat().st_mtime_ns == st.st_mtime_ns
    assert _is_failure(c.get("/api/paths").json(), "paths")
    assert gate.verifications == n + 1                    # the ctime change invalidated the cache
    rj.write_bytes(original)
    os.utime(rj, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert c.get("/api/paths").json()["status"] == "released"   # restored: verified again and shown again
    assert gate.verifications == n + 2
    assert c.get("/api/reports?refresh=1").json()["kinds"]["paths"]["verification"]["ok"] is True
    assert gate.verifications > n + 2                     # an explicit refresh re-verifies


def test_reads_are_bound_to_the_verified_hashes(private, monkeypatch):
    """Even if a change slipped past the cache fingerprint (here: forced constant), the bytes read must be the
    bytes that were verified."""
    case, store, home = private
    c = signed_in(case, store, home)
    gate = c.app.state.dashboard.gate
    assert c.get("/api/paths").json()["status"] == "released"
    assert c.get("/reports/scope/v2/report.json").status_code == 200
    monkeypatch.setattr(gate, "fingerprint", lambda kind: ("frozen",))
    gate.check("paths", refresh=True)
    gate.check("scope", refresh=True)
    _tamper_report(case, "paths", lambda d: d.update(limitations=["zzAfterVerificationzz"]))
    _tamper_report(case, "scope", lambda d: d.update(report_status="zzAfterVerificationzz"), n=2)
    r = c.get("/api/paths").json()
    assert _is_failure(r, "paths") and "zzAfterVerificationzz" not in json.dumps(r)
    assert c.get("/reports/scope/v2/report.json").status_code == 409
    assert _is_failure(c.get("/api/people").json(), "scope")


def test_investigation_run_on_a_tampered_chain_is_withheld(private):
    case, store, home = private
    testing.login("olivia")
    rc, out, err = testing.run_cli(["--json", "investigator", "analyse", "--case", str(case.root), "--provider", "fixture"])
    assert rc == 0, err
    c = signed_in(case, store, home)
    inv = c.get("/api/investigation").json()
    assert inv["latest_run"]["run_id"] == json.loads(out)["run_id"] and inv["evidence_links"]
    _tamper_report(case, "scope", lambda d: d["scope_tiers"]["possible_exposure"].update(count=1), n=2)
    inv = c.get("/api/investigation").json()
    run = inv["latest_run"]
    assert run["status"] == "integrity_failure" and run["kind"] == "scope" and "hypotheses" not in run
    assert inv["evidence_links"] == {} and '"hypotheses":' not in json.dumps(inv)
