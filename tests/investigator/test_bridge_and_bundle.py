"""The synthetic-only manual bridge (origin proven by the attested registry) and the evidence bundle's boundaries."""

import json
import os
import stat

import pyarrow.parquet as pq
import pytest

from conftest import _build, cli, store_of
from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.core.home import Home
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.store import CaseStore
from tripline_scope.investigator import bundle as B
from tripline_scope.investigator import fixture as F
from tripline_scope.investigator import storage as S
from tripline_scope.investigator import synthetic as SY


def _attest_hook(home_getter):
    def hook(logs_dir):
        SY.attest_outputs(home_getter(), "paths-logs", {"scenario": "demo"}, [logs_dir])
    return hook


@pytest.fixture(scope="module")
def attested(tmp_path_factory):
    """A case whose every source comes from attested generators (Module A estate + Module B logs)."""
    from tripline_scope.exposure import synthetic as ES

    base = tmp_path_factory.mktemp("inv-bridge")
    real_build = ES.build

    def build_and_attest(out, *a, **k):
        gt = real_build(out, *a, **k)
        SY.attest_outputs(Home(), "exposure-estate", {"variant": "baseline"}, [out])
        return gt

    ES.build = build_and_attest
    try:
        ns = _build(base, scenario="demo", with_scope=False, logs_hook=_attest_hook(Home))
    finally:
        ES.build = real_build
    return ns


def test_bridge_refused_for_unattested_case(shared, tmp_path):
    out = tmp_path / "prompt.json"
    rc, _, err = cli(["investigator", "bridge-export", *shared.c, "--out", str(out)], "olivia", ok=False)
    assert rc == 3 and "manual bridge refused" in err and not out.exists()


def test_bridge_round_trip_on_attested_synthetic_case(attested, tmp_path):
    attested.env.apply()
    out = tmp_path / "prompt.json"
    rc, exp, _ = cli(["investigator", "bridge-export", *attested.c, "--out", str(out)], "olivia")
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    doc = json.loads(out.read_bytes())
    assert doc["notice"].startswith("SYNTHETIC DATA ONLY") and [m["role"] for m in doc["messages"]] == ["system", "user"]
    assert not find_identifier_like(json.dumps(doc["messages"]).replace("\\\\", "\\"))
    bundle = json.loads(doc["messages"][1]["content"])["evidence_bundle_untrusted_data"]
    reply = tmp_path / "reply.json"
    reply.write_bytes(F.output(bundle))
    rc, res, _ = cli(["investigator", "bridge-import", *attested.c, "--run", exp["run_id"], "--response", str(reply),
                      "--model-label", "Example Model (synthetic test)"], "olivia")
    assert res["analysis_status"] == "completed" and res["provider_kind"] == "manual_bridge"
    assert res["model_id"] == "user-declared: Example Model (synthetic test)"
    rc, _, err = cli(["investigator", "bridge-import", *attested.c, "--run", exp["run_id"], "--response", str(reply),
                      "--model-label", "x"], "olivia", ok=False)
    assert rc == 2 and "not awaiting" in err
    # a reply produced for a different bundle is rejected
    out2 = tmp_path / "prompt2.json"
    rc, exp2, _ = cli(["investigator", "bridge-export", *attested.c, "--out", str(out2)], "olivia")
    other = dict(json.loads(reply.read_bytes()), bundle_sha256="0" * 64)
    reply.write_text(json.dumps(other))
    rc, res2, _ = cli(["investigator", "bridge-import", *attested.c, "--run", exp2["run_id"], "--response", str(reply),
                       "--model-label", "x"], "olivia", ok=False)
    assert rc == 8 and res2["analysis_status"] == "failed" and "bundle_mismatch" in res2["status_reason"]


def test_bridge_refused_after_an_unattested_source_is_added(attested, tmp_path):
    attested.env.apply()
    real = tmp_path / "hospital_export.csv"
    real.write_text("col\nvalue\n")
    cli(["source", "add", *attested.c, "--kind", "csv", "--path", str(real), "--label", "an unverified export",
         "--evidence-role", "system_copy", "--supplied-by", "IT", "--legal-basis", "test",
         "--received-at", "2026-09-15T08:00:00Z"], "olivia")
    rc, _, err = cli(["investigator", "bridge-export", *attested.c, "--out", str(tmp_path / "p.json")], "olivia", ok=False)
    assert rc == 3 and "not produced by an attested synthetic generator" in err


def test_registry_is_tamper_evident(attested):
    attested.env.apply()
    home = Home()
    entries = SY.registered(home)
    assert entries
    p = home.root / "synthetic_registry.json"
    doc = json.loads(p.read_bytes())
    doc["entries"]["f" * 64] = {"generator": "synth", "params_sha256": "0", "attested_at": "x"}
    original = p.read_bytes()
    p.write_bytes(canonical_bytes(doc))
    try:
        with pytest.raises(IntegrityError):
            SY.registered(home)
    finally:
        p.write_bytes(original)
    with pytest.raises(ConfigError):
        SY.attest_outputs(home, "made-up-generator", {}, [])


# ---------------------------------------------------------------------------------------------- bundle
def test_bundle_uses_released_reports_only_and_reads_no_case_data(shared, monkeypatch):
    reads = []
    real = CaseStore.open_read

    def spy(self, rel):
        reads.append(rel)
        return real(self, rel)

    monkeypatch.setattr(CaseStore, "open_read", spy)
    case, _ = store_of(shared.case_dir)
    b = B.build(case, Home())
    assert reads == []          # no extracts, restores, notify pack or working data are read
    assert [r["kind"] for r in b["reports"]] == ["exposure", "paths", "scope"]
    assert all(r["released"] and r["verified"] for r in b["reports"]) and b["not_assessed"] == []
    assert len(canonical_bytes(b)) <= B.MAX_BYTES and len(b["evidence"]) <= B.MAX_ITEMS
    assert b["bundle_sha256"] == B.bundle_hash(b)


def test_bundle_contains_no_patient_identifiers(shared):
    case, _ = store_of(shared.case_dir)
    blob = canonical_bytes(B.build(case, Home())).decode()
    gt = pq.read_table(shared.base / "synth" / "ground_truth_identifiers.parquet")
    needles = {v for c in gt.column_names for v in gt.column(c).to_pylist() if isinstance(v, str) and len(v) >= 6}
    assert needles and not [n for n in needles if n in blob]
    assert not find_identifier_like(blob.replace("\\\\", "\\"))


def test_tampered_released_report_is_refused(cloned):
    rj = cloned.case_dir / "reports" / "scope" / "v0001" / "report.json"
    rj.chmod(0o644)
    doc = json.loads(rj.read_bytes())
    doc["scope_tiers"]["possible_exposure"]["count"] = 1
    rj.write_bytes(canonical_bytes(doc))
    rc, _, err = cli(["investigator", "analyse", *cloned.c, "--provider", "fixture"], "olivia", ok=False)
    assert rc == 4 and "failed verification" in err


def test_missing_modules_are_not_assessed_and_analysis_still_works(tmp_path):
    ns = _build(tmp_path, scenario="demo", with_scope=False)
    rc, out, _ = cli(["investigator", "analyse", *ns.c, "--provider", "fixture"], "olivia")
    assert out["analysis_status"] == "completed"
    _, store = store_of(ns.case_dir)
    res = S.load_result(store, out["run_id"])
    assert res["not_assessed_modules"] == ["scope"]
    assert all(q == [] for q in (h["quantities"] for h in res["hypotheses"]))   # no Module C numbers invented
    testing.login("olivia")
