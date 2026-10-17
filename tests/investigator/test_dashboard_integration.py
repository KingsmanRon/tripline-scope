"""The workbench shows a real investigator run: every cited evidence id resolves to a released module artefact,
the fixture is labelled as not AI inference, and the released investigation report appears once approved."""

from conftest import cli, store_of
from tripline_scope.core.home import Home
from tripline_scope.dashboard import data as D
from tripline_scope.dashboard.integrity import TrustGate


def test_workbench_resolves_every_evidence_link_of_a_real_run(cloned):
    case, store = store_of(cloned.case_dir)
    assert D.investigation(case, store, TrustGate(case, Home()))["status"] == "not_performed"
    rc, out, _ = cli(["investigator", "analyse", *cloned.c, "--provider", "fixture"], "olivia")
    view = D.investigation(case, store, TrustGate(case, Home()))
    assert view["advisory"] is True and view["fixture"] is True and view["is_model_inference"] is False
    assert view["provenance_note"].startswith("Deterministic fixture output")
    links = view["evidence_links"]
    assert links and all(v["type"] != "unknown" for v in links.values())
    missing = [k for k, v in links.items() if v["type"] != "quantity" and v["found"] is not True]
    assert missing == []
    assert {v["module"] for v in links.values()} >= {"paths", "exposure"}
    for h in out["hypotheses"]:
        cli(["investigator", "review", *cloned.c, "--run", out["run_id"], "--item", h, "--decision", "accept"], "rami")
    cli(["investigator", "report", *cloned.c], "olivia")
    cli(["release", *cloned.c, "--kind", "investigation", "--approver", "ines"])
    view = D.investigation(case, store, TrustGate(case, Home()))
    assert view["released_report"]["report_version"] == 1
    assert view["released_report"]["body"]["ai_analysis"]["advisory"] is True
