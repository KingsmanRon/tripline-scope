"""Enterprise-profile cases for scenarios A, B and C, built once per session through the real CLI (synthetic
utility enterprise; Module A → Module B → financial analysis → releases), and cloned for tests that mutate them."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tripline_scope import testing
from tripline_scope.enterprise import synthetic as ES

WINDOW = "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"


def cli(argv, user=None, ok=True):
    if user:
        testing.login(user)
    rc, out, err = testing.run_cli(["--json"] + argv)
    if ok:
        assert rc == 0, (argv, rc, err, out[:400])
    try:
        return rc, (json.loads(out) if out.strip() else None), err
    except ValueError:
        return rc, out, err


def build(base: Path, scenario: str, *, financial: bool = True) -> SimpleNamespace:
    env = testing.setup_installation(base / "inst", hospital="Synthetic Utility Ltd (fictional)")
    case_dir = testing.open_case(base / "inst", f"ENT-TEST-{scenario.upper()}", profile="enterprise")
    c = ["--case", str(case_dir)]
    gen = base / "gen"
    truth = ES.generate(gen, scenario)
    cli(["exposure", "scan", *c, "--inputs", str(gen / "estate" / "manifest.yaml")], "olivia")
    cli(["exposure", "report", *c, "--no-pdf"])
    cli(["release", *c, "--kind", "exposure", "--approver", "ines"])
    cli(["paths", "ingest", *c, "--manifest", str(gen / "logs" / "logs.yaml")], "olivia")
    cli(["paths", "analyse", *c, "--window", WINDOW])
    cli(["paths", "report", *c, "--exposure-report", str(case_dir / "reports" / "exposure" / "v0001")])
    cli(["release", *c, "--kind", "paths", "--approver", "ines"])
    if financial:
        cli(["financial", "analyse", *c, "--config", str(gen / "financial.yaml")], "olivia")
        cli(["financial", "report", *c])
        cli(["release", *c, "--kind", "financial", "--approver", "ines"])
    return SimpleNamespace(base=base, env=env, case_dir=case_dir, c=c, gen=gen, truth=truth, scenario=scenario)


@pytest.fixture(scope="session")
def scenarios(tmp_path_factory):
    return {s: build(tmp_path_factory.mktemp(f"ent-{s}"), s) for s in ("a", "b", "c")}


def clone(t: SimpleNamespace, dest: Path) -> SimpleNamespace:
    src_inst, dst_inst = t.base / "inst", dest / "inst"
    subprocess.run(["cp", "-a", str(src_inst), str(dst_inst)], check=True)   # child process: no source write guard
    for p in list(dst_inst.rglob("*.yaml")):
        p.write_text(p.read_text().replace(str(src_inst), str(dst_inst)))
    env = testing.Env(dst_inst / "home", dst_inst / "session.token")
    case_dir = dst_inst / t.case_dir.name
    return SimpleNamespace(base=t.base, env=env, case_dir=case_dir, c=["--case", str(case_dir)], gen=t.gen,
                           truth=t.truth, scenario=t.scenario)


def report(case_dir: Path, kind: str, version: int | None = None) -> dict:
    d = case_dir / "reports" / kind
    v = max(d.glob("v*")) if version is None else d / f"v{version:04d}"
    return json.loads((v / "report.json").read_bytes())
