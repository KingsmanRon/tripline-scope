import os

import pytest

from tripline_scope import testing


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Every test gets its own environment variables; nothing leaks between tests."""
    for k in list(os.environ):
        if k.startswith("TSCOPE_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TSCOPE_SESSION_FILE", str(tmp_path / "no-session"))
    yield


@pytest.fixture
def install(tmp_path, monkeypatch):
    env = testing.setup_installation(tmp_path)
    for k, v in env.vars().items():
        monkeypatch.setenv(k, v)
    return env


@pytest.fixture
def case_dir(install, tmp_path):
    return testing.open_case(tmp_path)
