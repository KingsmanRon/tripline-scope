"""Shared fixtures for the Investigation Workbench tests.

One realistic case is built per test session without SQL Server: Module A (synthetic estate scan), Module B
(synthetic incident logs) and Module C (synthetic databases loaded as extracts) are run and released through the
real CLI, giving released ``exposure`` v1, ``paths`` v1 and ``scope`` v1 (preliminary) + v2 (refined). A second
case in the same installation has nothing released. A user ``mallory`` exists with no role on either case.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.exposure import synthetic as ES
from tripline_scope.paths import synthetic as PS
from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources
from tripline_scope.synth.generate import generate


@dataclass
class Built:
    env: testing.Env
    work: Path
    case_dir: Path
    empty_dir: Path

    @property
    def synth(self) -> Path:
        return self.work / "synth"


def _cli(argv, user=None):
    if user:
        testing.login(user)
    rc, out, err = testing.run_cli(["--json"] + argv)
    assert rc == 0, (argv, err, out)
    return json.loads(out) if out.strip() else None


@pytest.fixture(scope="session")
def built(tmp_path_factory) -> Built:
    w = tmp_path_factory.mktemp("dashboard")
    env = testing.setup_installation(w / "inst")
    cd = testing.open_case(w / "inst", "DASH-001")
    c = ["--case", str(cd)]
    ES.build(w / "expo")
    _cli(["exposure", "scan", *c, "--inputs", str(w / "expo" / "manifest.yaml")], "olivia")
    _cli(["exposure", "report", *c, "--no-pdf"])
    _cli(["release", *c, "--kind", "exposure", "--approver", "ines"])
    PS.generate(w / "logs", "acceptance", 3000)
    _cli(["paths", "ingest", *c, "--manifest", str(w / "logs" / "logs.yaml")], "olivia")
    _cli(["paths", "analyse", *c, "--window", "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"])
    _cli(["paths", "report", *c, "--exposure-report", str(cd / "reports" / "exposure" / "v0001")])
    _cli(["paths", "scope-candidates", *c, "--out", str(w / "cand.json")])
    _cli(["release", *c, "--kind", "paths", "--approver", "ines"])
    generate(w / "synth", 5000, seed=4242, leak_rows=100)
    testing.login("olivia")
    case = Case(cd)
    with command("test ingest", home=Home(), case=case, role="operator") as ctx:
        smap = register_synth_sources(case, ctx.store, w / "synth", actor=ctx.actor)
        load_synth_as_extract(case, ctx.store, w / "synth", source_map=smap)
    _cli(["scope", "constrain", *c, "--candidates", str(w / "cand.json"), "--reason", "test"], "olivia")
    _cli(["estimate", *c])
    _cli(["release", *c, "--kind", "scope", "--approver", "ines"])  # preliminary
    _cli(["scope", "match", *c])
    _cli(["scope", "report", *c])
    _cli(["release", *c, "--kind", "scope", "--approver", "ines"])  # refined
    empty = testing.open_case(w / "inst", "DASH-EMPTY")
    testing.login("admin")
    rc, out, err = testing.run_cli(["user", "add", "mallory"])
    assert rc == 0, err
    return Built(env=env, work=w, case_dir=cd, empty_dir=empty)


@pytest.fixture
def dash(built, monkeypatch):
    """Re-apply the installation environment for this test (the autouse fixture clears TSCOPE_* per test)."""
    for k, v in built.env.vars().items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("TSCOPE_SESSION", raising=False)
    case = Case(built.case_dir)
    home = Home()
    return case, open_store(case, home), home


@pytest.fixture
def empty_case(built, dash):
    case = Case(built.empty_dir)
    home = Home()
    return case, open_store(case, home), home
