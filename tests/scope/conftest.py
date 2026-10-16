import json
from pathlib import Path

import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.home import Home
from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources
from tripline_scope.synth.generate import generate

ROWS = 6000


@pytest.fixture(scope="session")
def synth_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth") / "data"
    generate(out, ROWS, seed=4242, leak_rows=120)
    return out


def ingest(case_dir, synth, **kw):
    """Register the synthetic databases and write their extracts, as the operator would through ingest."""
    testing.login("olivia")
    case = Case(case_dir)
    with command("test ingest", home=Home(), case=case, role="operator") as ctx:
        smap = register_synth_sources(case, ctx.store, synth, actor=ctx.actor)
        load_synth_as_extract(case, ctx.store, synth, source_map=smap, **kw)
    return smap


def cli(argv, user=None, ok=True):
    if user:
        testing.login(user)
    rc, out, err = testing.run_cli(["--json"] + argv)
    if ok:
        assert rc == 0, err + out
    try:
        return rc, json.loads(out) if out.strip() else None, err
    except ValueError:
        return rc, out, err


@pytest.fixture
def scoped(case_dir, synth_dir):
    smap = ingest(case_dir, synth_dir)
    return case_dir, smap


def c(case_dir: Path) -> list[str]:
    return ["--case", str(case_dir)]
