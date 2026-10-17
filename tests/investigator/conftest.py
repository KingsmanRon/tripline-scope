"""A realistic case with released Module A, B and C reports, built once per session and cloned for tests that
mutate it (releases, tampering, closure)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store

CASE_ID = "INV-TEST-001"


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


def _build(base: Path, *, scenario: str = "acceptance", with_scope: bool = True, logs_hook=None) -> SimpleNamespace:
    from tripline_scope.exposure import synthetic as ES
    from tripline_scope.paths import synthetic as PS

    env = testing.setup_installation(base / "inst")
    case_dir = testing.open_case(base / "inst", CASE_ID)
    c = ["--case", str(case_dir)]
    ES.build(base / "expo")
    cli(["exposure", "scan", *c, "--inputs", str(base / "expo" / "manifest.yaml")], "olivia")
    cli(["exposure", "report", *c, "--no-pdf"])
    cli(["release", *c, "--kind", "exposure", "--approver", "ines"])
    PS.generate(base / "logs", scenario, 2500)
    if logs_hook:
        logs_hook(base / "logs")
    cli(["paths", "ingest", *c, "--manifest", str(base / "logs" / "logs.yaml")], "olivia")
    cli(["paths", "analyse", *c, "--window", "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"])
    cli(["paths", "report", *c, "--exposure-report", str(case_dir / "reports" / "exposure" / "v0001")])
    cli(["paths", "scope-candidates", *c, "--out", str(base / "cand.json")])
    cli(["release", *c, "--kind", "paths", "--approver", "ines"])
    if with_scope:
        from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources
        from tripline_scope.synth.generate import generate

        generate(base / "synth", 4000, seed=4242, leak_rows=80)
        testing.login("olivia")
        case = Case(case_dir)
        with command("test ingest", home=Home(), case=case, role="operator") as ctx:
            smap = register_synth_sources(case, ctx.store, base / "synth", actor=ctx.actor)
            load_synth_as_extract(case, ctx.store, base / "synth", source_map=smap)
        cli(["scope", "constrain", *c, "--candidates", str(base / "cand.json"), "--reason", "test"], "olivia")
        cli(["estimate", *c])
        cli(["scope", "match", *c])
        cli(["scope", "report", *c])
        cli(["release", *c, "--kind", "scope", "--approver", "ines"])
    return SimpleNamespace(base=base, env=env, case_dir=case_dir, c=c)


@pytest.fixture(scope="session")
def template(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("inv-template"))


def clone(t: SimpleNamespace, dest: Path) -> SimpleNamespace:
    """Copy the installation + case and point every absolute path in their YAML config at the copy."""
    src_inst, dst_inst = t.base / "inst", dest / "inst"
    # a child process: this test process carries the source write guard, which (rightly) refuses to create links
    # to registered sources
    subprocess.run(["cp", "-a", str(src_inst), str(dst_inst)], check=True)
    for p in list(dst_inst.rglob("*.yaml")):
        p.write_text(p.read_text().replace(str(src_inst), str(dst_inst)))
    env = testing.Env(dst_inst / "home", dst_inst / "session.token")
    case_dir = dst_inst / t.case_dir.name
    return SimpleNamespace(base=t.base, env=env, case_dir=case_dir, c=["--case", str(case_dir)])


@pytest.fixture
def shared(template):
    """The template itself (tests must not release, tamper or close)."""
    template.env.apply()
    return template


@pytest.fixture
def cloned(template, tmp_path):
    ns = clone(template, tmp_path)
    ns.env.apply()
    return ns


def store_of(case_dir):
    case = Case(case_dir)
    return case, open_store(case, Home())


def tree_hashes(root: Path) -> dict[str, str]:
    from tripline_scope.core.canonical import sha256_file

    return {str(p.relative_to(root)): sha256_file(p) for p in sorted(root.rglob("*")) if p.is_file()}
