"""Fixtures for packaging tests: script imports, the built bundle and a local wheelhouse."""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def pytest_configure(config):
    config.addinivalue_line("markers", "bundle: needs a bundle built by `make bundle` (skipped otherwise)")


def _bundles() -> list[Path]:
    out = ROOT / "bundle" / "out"
    return sorted(out.glob("tripline-scope-*/SHA256SUMS.sig"), key=lambda p: p.stat().st_mtime) if out.exists() else []


@pytest.fixture(scope="session")
def bundle_dir() -> Path:
    """The most recent complete bundle (TSCOPE_BUNDLE overrides); skips when none has been built."""
    env = os.environ.get("TSCOPE_BUNDLE")
    if env:
        return Path(env)
    found = _bundles()
    if not found:
        pytest.skip("no bundle built (run `make bundle`)")
    return found[-1].parent


@pytest.fixture(scope="session")
def bundle_info(bundle_dir) -> dict:
    return json.loads((bundle_dir / "BUILDINFO.json").read_text())


@pytest.fixture(scope="session")
def wheelhouse() -> Path:
    """Runtime wheels: TSCOPE_WHEELHOUSE, the newest bundle's wheels/, or build/wheelhouse (make wheelhouse)."""
    candidates = [os.environ.get("TSCOPE_WHEELHOUSE")]
    candidates += [str(p.parent / "wheels") for p in reversed(_bundles())]
    candidates.append(str(ROOT / "build" / "wheelhouse"))
    for c in candidates:
        if c and Path(c).is_dir() and any(Path(c).glob("cryptography-*.whl")):
            return Path(c)
    pytest.skip("no wheelhouse (run `make wheelhouse` or `make bundle`)")


@pytest.fixture(scope="session")
def uv() -> str:
    exe = os.environ.get("UV") or shutil.which("uv") or (str(Path.home() / ".local/bin/uv")
                                                        if (Path.home() / ".local/bin/uv").exists() else None)
    if not exe:
        pytest.skip("uv not available to create clean virtualenvs")
    return exe
