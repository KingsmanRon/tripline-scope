"""Offline install proof (scripts/install_test.sh). Needs Docker and a bundle built with images.

venv mode: a clean python:3.12-slim container started with --network none installs the bundle (checksums,
release signature, pip --no-index --require-hashes) and passes the bundled smoke test with --require-offline.
container mode: docker load + compose on an internal-only network; the app reaches PostgreSQL 16 and nothing
off the host. This is a clean *container* without network, not a clean VM.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.docker, pytest.mark.bundle]


def _docker_ok() -> bool:
    return shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.fixture
def bundle_with_images(bundle_dir, bundle_info):
    if not _docker_ok():
        pytest.skip("Docker daemon not available")
    if not bundle_info.get("images"):
        pytest.skip("bundle built without images (WITH_IMAGES=0)")
    return bundle_dir


@pytest.mark.parametrize("mode, marker", [("venv", "VENV-MODE OFFLINE INSTALL: PASS"),
                                          ("container", "CONTAINER-MODE INSTALL ON INTERNAL NETWORK: PASS")])
def test_offline_install(bundle_with_images, mode, marker):
    r = subprocess.run([str(ROOT / "scripts" / "install_test.sh"), mode, str(bundle_with_images)],
                       capture_output=True, text=True, timeout=1200)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    assert marker in r.stdout and "SMOKE TEST PASSED" in r.stdout
    if mode == "venv":
        assert "release signature valid" in r.stdout and "network interfaces visible: lo \n" in r.stdout
