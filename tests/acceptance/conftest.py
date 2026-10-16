"""Acceptance harness: make leakscan / source_safety importable from any test (also with --import-mode=importlib)."""

import os
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

ROOT = HERE.parents[1]
RUN_OFFLINE = ROOT / "scripts" / "run_offline.sh"


def offline_available() -> bool:
    return (os.geteuid() == 0 and shutil.which("unshare") is not None) or os.environ.get(
        "TSCOPE_OFFLINE_ALLOW_USERNS") == "1"


@pytest.fixture
def offline():
    """Skip unless commands can be run in an empty network namespace (scripts/run_offline.sh)."""
    if not offline_available():
        pytest.skip("run_offline.sh needs root + unshare (or TSCOPE_OFFLINE_ALLOW_USERNS=1)")
    return RUN_OFFLINE
