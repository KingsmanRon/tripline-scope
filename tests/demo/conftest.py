"""Unified laboratory demo without SQL Server: one installation and case per scenario, built once per session.

Every input is generated with ``--attest``: ``tscope synth`` (Module C data), the Module A laboratory estate and
the Module B incident logs. Module A runs ``tscope exposure scan/report`` and ``release``; Module B runs ``paths
ingest/analyse/report --exposure-report/scope-candidates`` and ``release``; Module C registers the synthetic
databases as directory sources (the leak sample only in the corroborated scenario) and writes their extracts the
way a restore would name them (``LabDBnn`` / ``dbo.<table>``, ``scope.fixtures``), then constrain → estimate →
release → match → simulated review → report → release. The Docker demo (``run_demo.py``) does the same with real
``.bak`` restores.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.home import Home
from tripline_scope.exposure import synthetic as estate_gen
from tripline_scope.paths import synthetic as logs_gen
from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources

CORROBORATED = "LabDB03.dbo.patients"
WINDOW = "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"
SYNTH_ROWS = 3000


def cli(argv, user=None):
    if user:
        testing.login(user)
    rc, out, err = testing.run_cli(["--json"] + argv)
    assert rc == 0, (argv, err, out)
    return json.loads(out) if out.strip() else None


def released(case_dir: Path, kind: str, version: int | None = None) -> tuple[Path, dict]:
    d = case_dir / "reports" / kind
    versions = sorted(p for p in d.glob("v[0-9][0-9][0-9][0-9]") if (p / "release.json").is_file())
    v = versions[-1] if version is None else d / f"v{version:04d}"
    return v, json.loads((v / "report.json").read_bytes())


def run_flow(base: Path, scenario: str) -> SimpleNamespace:
    corroborated = scenario == "corroborated"
    env = testing.setup_installation(base / "inst", hospital="Synthetic Lab Group")
    case_dir = testing.open_case(base / "inst", "DEMO-T-001")
    c = str(case_dir)
    synth, estate, logs = base / "synth", base / "estate", base / "logs"
    # generators, each attesting its outputs under this installation
    cli(["synth", "--rows", str(SYNTH_ROWS), "--databases", "10", "--seed", "2026", "--leak-rows", "80",
         "--out", str(synth), "--attest"])
    assert estate_gen.main(["--out", str(estate), "--estate", "lab", "--attest"]) == 0
    gen = ["--scenario", "acceptance", "--corroborate", CORROBORATED] if corroborated else ["--scenario", "demo"]
    assert logs_gen.main(["--out", str(logs), *gen, "--scale", "8000", "--attest"]) == 0
    # Stage 1: Module A
    scan = cli(["exposure", "scan", "--case", c, "--inputs", str(estate / "manifest.yaml")], "olivia")
    cli(["exposure", "report", "--case", c])
    cli(["release", "--case", c, "--kind", "exposure", "--approver", "ines"])
    exp_dir, exposure = released(case_dir, "exposure")
    # Stages 2-3: Module B
    cli(["paths", "ingest", "--case", c, "--manifest", str(logs / "logs.yaml")], "olivia")
    cli(["paths", "analyse", "--case", c, "--window", WINDOW])
    cli(["paths", "report", "--case", c, "--exposure-report", str(exp_dir)])
    cand = base / "candidates.json"
    cli(["paths", "scope-candidates", "--case", c, "--out", str(cand)])
    cli(["release", "--case", c, "--kind", "paths", "--approver", "ines"])
    _, paths = released(case_dir, "paths")
    # Stage 4: Module C
    testing.login("olivia")
    case = Case(case_dir)
    with command("demo test ingest (synthetic)", home=Home(), case=case, role="operator") as ctx:
        smap = register_synth_sources(case, ctx.store, synth, actor=ctx.actor, include_leak=corroborated)
        load_synth_as_extract(case, ctx.store, synth, source_map=smap, table_prefix="dbo.",
                              database_names={f"db{i:02d}": f"LabDB{i:02d}" for i in range(1, 11)})
    cli(["scope", "constrain", "--case", c, "--candidates", str(cand), "--reason", "Module B candidates"], "olivia")
    cli(["estimate", "--case", c])
    cli(["release", "--case", c, "--kind", "scope", "--approver", "ines"])
    cli(["scope", "match", "--case", c], "olivia")
    cli(["scope", "decide", "--case", c, "--simulate-reviewer", str(synth / "ground_truth.parquet")], "rami")
    cli(["scope", "match", "--case", c], "olivia")
    cli(["scope", "report", "--case", c])
    cli(["release", "--case", c, "--kind", "scope", "--approver", "ines"])
    _, scope = released(case_dir, "scope")
    return SimpleNamespace(base=base, env=env, case_dir=case_dir, synth=synth, estate=estate, logs=logs,
                           scan=scan, exposure=exposure, exposure_dir=exp_dir, paths=paths, scope=scope,
                           estate_truth=json.loads((estate / "ground_truth.json").read_bytes()),
                           logs_truth=json.loads((logs / "ground_truth.json").read_bytes()), scenario=scenario)


@pytest.fixture(scope="session")
def suspected(tmp_path_factory):
    return run_flow(tmp_path_factory.mktemp("demo-suspected"), "suspected")


@pytest.fixture(scope="session")
def corroborated(tmp_path_factory):
    return run_flow(tmp_path_factory.mktemp("demo-corroborated"), "corroborated")


@pytest.fixture
def as_env(monkeypatch):
    """Apply one run's installation environment for the duration of a test."""

    def apply(run):
        for k, v in run.env.vars().items():
            monkeypatch.setenv(k, v)

    return apply
