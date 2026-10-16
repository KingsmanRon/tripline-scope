"""Shared fixtures for Module B: synthetic incidents generated once per session, ingested and analysed once
per module (an installation, a case, ``paths ingest`` and ``paths analyse`` through the CLI)."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from paths_helpers import build_case

from tripline_scope.paths import synthetic


@pytest.fixture(scope="session")
def acceptance_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synth-acceptance")
    synthetic.generate(out, "acceptance", scale=20_000)
    return out


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synth-demo")
    synthetic.generate(out, "demo", scale=8_000)
    return out


@pytest.fixture(scope="module")
def acc(tmp_path_factory, acceptance_dir) -> SimpleNamespace:
    return build_case(tmp_path_factory.mktemp("acc-case"), acceptance_dir)


@pytest.fixture(scope="module")
def demo(tmp_path_factory, demo_dir) -> SimpleNamespace:
    return build_case(tmp_path_factory.mktemp("demo-case"), demo_dir)
