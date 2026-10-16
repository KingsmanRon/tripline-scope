"""The offline bundle built by `make bundle`: contents, hashes, signature, installer refusal paths."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import check_locks
import pytest
from check_licences import normalize_name, parse_lock

from tscope_verify.checksums import verify_checksums
from tscope_verify.keys import key_id, load_public_key

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ["wheels", "requirements.txt", "sbom.cdx.json", "licences.json", "install.sh", "smoke-test.sh",
            "prune.list", "prune.sh", "docker-compose.yml", "compose.env.example", "Dockerfile", "docs/README.md",
            "docs/SUPPLY_CHAIN.md", "docs/VERIFY.md", "BUILDINFO.json", "release.pub", "SHA256SUMS",
            "SHA256SUMS.sig"]


def test_bundle_contents(bundle_dir, bundle_info):
    missing = [r for r in REQUIRED if not (bundle_dir / r).exists()]
    assert not missing, missing
    if bundle_info["images"]:
        images = {p.name for p in (bundle_dir / "images").glob("*.tar")}
        assert f"tripline-scope-{bundle_info['version']}.tar" in images and "postgres-16.tar" in images
        assert any("mssql" in i for i in images) == bundle_info["with_mssql_demo"]
        if bundle_info["with_mssql_demo"]:
            assert (bundle_dir / "images" / "MSSQL-DEVELOPER-EDITION.txt").is_file()


def test_signed_checksums_verify(bundle_dir, bundle_info):
    pub = load_public_key(bundle_dir / "release.pub")
    assert key_id(pub) == bundle_info["release_key_id"]
    res = verify_checksums(bundle_dir / "SHA256SUMS", sig=bundle_dir / "SHA256SUMS.sig", release_keys=[pub])
    assert res.ok, res.render()
    # the documented command, via the stand-alone verifier's CLI
    r = subprocess.run([sys.executable, "-m", "tscope_verify", "checksums", "SHA256SUMS", "--sig", "SHA256SUMS.sig",
                        "--key", "release.pub"], cwd=bundle_dir, capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=str(ROOT / "verify" / "src")))
    assert r.returncode == 0, r.stdout + r.stderr


def test_every_file_is_listed_exactly_once(bundle_dir):
    listed = [ln.split("  ", 1)[1] for ln in (bundle_dir / "SHA256SUMS").read_text().splitlines() if ln]
    present = sorted(p.relative_to(bundle_dir).as_posix() for p in bundle_dir.rglob("*")
                     if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig"))
    assert sorted(listed) == present and len(set(listed)) == len(listed)


def test_tampering_and_foreign_keys_fail(bundle_dir, tmp_path):
    for name in ("SHA256SUMS", "SHA256SUMS.sig", "release.pub"):
        shutil.copy(bundle_dir / name, tmp_path / name)
    pub = load_public_key(tmp_path / "release.pub")
    sums = tmp_path / "SHA256SUMS"
    assert verify_checksums(sums, sig=tmp_path / "SHA256SUMS.sig", release_keys=[pub], check_files=False).ok
    lines = sums.read_text().splitlines(keepends=True)
    lines[0] = ("0" if lines[0][0] != "0" else "1") + lines[0][1:]
    sums.write_text("".join(lines))
    assert not verify_checksums(sums, sig=tmp_path / "SHA256SUMS.sig", release_keys=[pub], check_files=False).ok
    shutil.copy(bundle_dir / "SHA256SUMS", sums)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    foreign = Ed25519PrivateKey.generate().public_key()
    assert not verify_checksums(sums, sig=tmp_path / "SHA256SUMS.sig", release_keys=[foreign], check_files=False).ok


def test_requirements_and_wheels_match_the_lock(bundle_dir):
    req = bundle_dir / "requirements.txt"
    assert check_locks.check_lock_file(req, required=[], first_party_allowed=True) == []
    bundle_lock = parse_lock(req)
    runtime = parse_lock(ROOT / "requirements" / "runtime.txt")
    assert set(bundle_lock) == set(runtime) | {"tripline-scope", "tripline-scope-verify"}
    for key, e in runtime.items():
        assert bundle_lock[key]["version"] == e["version"]
    wheels = {normalize_name(w.name.split("-")[0]): w for w in (bundle_dir / "wheels").glob("*.whl")}
    assert set(wheels) == set(bundle_lock), "one wheel per pinned requirement, nothing else"
    import hashlib

    for key, w in wheels.items():
        assert f"sha256:{hashlib.sha256(w.read_bytes()).hexdigest()}" in bundle_lock[key]["hashes"], w.name


def test_licence_report_in_bundle(bundle_dir):
    report = json.loads((bundle_dir / "licences.json").read_text())
    assert report["ok"] and report["schema"] == "tripline.licence-check/v1"
    assert len(report["packages"]) == len(parse_lock(ROOT / "requirements" / "runtime.txt"))


def test_no_private_key_material_in_bundle(bundle_dir):
    for p in bundle_dir.rglob("*"):
        if p.is_file() and p.parent.name != "images":
            data = p.read_bytes()
            assert b"PRIVATE KEY" not in data and b"ENCRYPTED PRIVATE" not in data, p
    assert b"PUBLIC KEY" in (bundle_dir / "release.pub").read_bytes()


@pytest.fixture
def mini_bundle(bundle_dir, tmp_path):
    """A signed copy of the bundle without images (re-signed with a throw-away key outside the repo)."""
    mini = tmp_path / "mini"
    shutil.copytree(bundle_dir, mini, ignore=shutil.ignore_patterns("images"))
    key = tmp_path / "keys"
    from tripline_scope.core.keys import generate_keypair

    generate_keypair(key / "release.pem", key / "release.pub", "pw-for-test")
    env = dict(os.environ, RELEASE_KEY=str(key / "release.pem"), RELEASE_KEY_PASSPHRASE="pw-for-test")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "sign_release.py"), str(mini)], env=env, check=True,
                   capture_output=True)
    kid = key_id(load_public_key(mini / "release.pub"))
    return mini, kid


def _install(mini, *args):
    return subprocess.run(["bash", str(mini / "install.sh"), "--prefix", str(mini.parent / "prefix"), *args],
                          capture_output=True, text=True, timeout=300)


def test_installer_requires_and_checks_the_release_key_id(mini_bundle):
    mini, kid = mini_bundle
    r = _install(mini)
    assert r.returncode == 1 and f"--release-key-id {kid}" in r.stderr
    r = _install(mini, "--release-key-id", "0" * 32)
    assert r.returncode == 1 and "does not match the expected" in r.stderr
    assert not (mini.parent / "prefix").exists()


def test_installer_rejects_modified_files_and_forged_checksums(mini_bundle):
    mini, kid = mini_bundle
    req = mini / "requirements.txt"
    original = req.read_text()
    req.write_text(original + "\n# injected\n")
    r = _install(mini, "--release-key-id", kid)
    assert r.returncode == 1 and "do not match SHA256SUMS" in r.stderr
    # attacker also updates SHA256SUMS: the signature no longer matches
    import hashlib

    sums = mini / "SHA256SUMS"
    original_sums = sums.read_text()
    digest = hashlib.sha256(req.read_bytes()).hexdigest()
    sums.write_text("".join(f"{digest}  requirements.txt\n" if ln.endswith("  requirements.txt\n") else ln
                            for ln in sums.read_text().splitlines(keepends=True)))
    r = _install(mini, "--release-key-id", kid)
    assert r.returncode == 1 and "signature over SHA256SUMS is INVALID" in r.stderr
    # an unlisted extra file is refused too (everything else restored and valid)
    req.write_text(original)
    sums.write_text(original_sums)
    (mini / "wheels" / "extra-1.0-py3-none-any.whl").write_bytes(b"not listed")
    r = _install(mini, "--release-key-id", kid)
    assert r.returncode == 1 and "not listed in SHA256SUMS" in r.stderr
    assert not (mini.parent / "prefix").exists()
