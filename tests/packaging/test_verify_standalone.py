"""The stand-alone verifier: installed alone (cryptography + rfc8785 only, offline, hash-checked) it verifies
a report chain, an audit log, a destruction certificate and a signed checksum file produced by the full
product, and never imports tripline_scope."""

import ast
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from check_licences import normalize_name, parse_lock

from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.keys import generate_keypair, load_signer
from tripline_scope.core.reports import ReportStore

ROOT = Path(__file__).resolve().parents[2]
RUN_OFFLINE = ROOT / "scripts" / "run_offline.sh"
ALLOWED_DISTS = {"cffi", "cryptography", "pycparser", "rfc8785", "tripline-scope-verify"}


def test_verifier_source_never_imports_the_product():
    for py in (ROOT / "verify" / "src" / "tscope_verify").rglob("*.py"):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            assert not any(n.startswith("tripline_scope") for n in names), py


@pytest.fixture(scope="module")
def verifier_venv(tmp_path_factory, wheelhouse, uv):
    tmp = tmp_path_factory.mktemp("verifier")
    vw = sorted(wheelhouse.glob("tripline_scope_verify-*.whl"))
    if not vw:
        dist = tmp / "dist"
        subprocess.run([str(ROOT / "scripts" / "build_wheels.sh"), str(dist)], check=True, capture_output=True)
        vw = sorted(dist.glob("tripline_scope_verify-*.whl"))
    wheel = vw[-1]
    lock = parse_lock(ROOT / "requirements" / "runtime.txt")
    import hashlib

    lines = [f"{lock[n]['name']}=={lock[n]['version']} " + " ".join(f"--hash={h}" for h in lock[n]["hashes"])
             for n in ("cryptography", "cffi", "pycparser", "rfc8785")]
    lines.append(f"tripline-scope-verify @ {wheel.as_uri()} --hash=sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}")
    req = tmp / "verifier-requirements.txt"
    req.write_text("\n".join(lines) + "\n")
    venv = tmp / "venv"
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
    subprocess.run([uv, "venv", "--quiet", "--python", "3.12", str(venv)], check=True, env=env)
    subprocess.run([uv, "pip", "install", "--quiet", "--python", str(venv / "bin" / "python"), "--offline",
                    "--no-index", "--find-links", str(wheelhouse), "--require-hashes", "-r", str(req)],
                   check=True, env=env)
    return venv


def _run(venv, args, cwd, offline=True):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV") and not k.startswith("TSCOPE_")}
    argv = [str(venv / "bin" / "tscope-verify"), *map(str, args)]
    if offline and os.geteuid() == 0 and shutil.which("unshare"):
        argv = [str(RUN_OFFLINE), *argv]
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


def test_venv_contains_only_the_verifier_and_its_two_dependencies(verifier_venv):
    out = subprocess.run([str(verifier_venv / "bin" / "python"), "-I", "-c",
                          "import importlib.metadata as m, json; print(json.dumps(sorted(d.metadata['Name'] for d in "
                          "m.distributions())))"], capture_output=True, text=True, check=True)
    assert {normalize_name(n) for n in json.loads(out.stdout)} == ALLOWED_DISTS


def test_verifies_product_artefacts_offline_without_the_product(verifier_venv, case_dir, tmp_path):
    # Produce real artefacts with the full product: two released versions, then closure.
    rs = ReportStore(Case(case_dir))
    for n in (10, 12):
        body = rs.new_body("scope", report_status="preliminary", counts={"unique_people": n})
        rs.save_draft("scope", body, pdf=b"%PDF-1.4 synthetic", attachments={"diff.json": b"{}"})
        rc, out, err = testing.run_cli(["--json", "release", "--case", str(case_dir), "--kind", "scope",
                                        "--approver", "ines"])
        assert rc == 0, err
    testing.login("ines")
    rc, out, err = testing.run_cli(["--json", "case", "close", "--case", str(case_dir), "--approver", "ines"])
    assert rc == 0, err
    cert = Path(json.loads(out)["certificate"])
    hospital_pub = tmp_path / "hospital.pub"
    shutil.copy(Home().hospital_public_key_path, hospital_pub)
    # A signed checksum file, signed the way release bundles are.
    rel = tmp_path / "release"
    rel.mkdir()
    (rel / "payload.txt").write_text("synthetic payload\n")
    generate_keypair(tmp_path / "rk" / "release.pem", rel / "release.pub", "pw")
    sums = f"{__import__('hashlib').sha256(b'synthetic payload' + bytes([10])).hexdigest()}  payload.txt\n".encode()
    (rel / "SHA256SUMS").write_bytes(sums)
    signer = load_signer("release", tmp_path / "rk" / "release.pem", "pw")
    (rel / "SHA256SUMS.sig").write_bytes(canonical_bytes(
        {"schema": "tripline.signatures/v1", "signatures": [signer.signature_entry("SHA256SUMS", sums)]}))

    kind_dir = case_dir / "reports" / "scope"
    work = tmp_path / "cwd"
    work.mkdir()
    checks = [
        ["report", kind_dir / "v0002", "--hospital-key", hospital_pub],
        ["chain", kind_dir, "--hospital-key", hospital_pub],
        ["audit", case_dir / "audit.log"],
        ["certificate", cert, "--hospital-key", hospital_pub],
        ["checksums", rel / "SHA256SUMS", "--sig", rel / "SHA256SUMS.sig", "--key", rel / "release.pub"],
    ]
    for args in checks:
        r = _run(verifier_venv, ["--json", *args], work)
        assert r.returncode == 0, (args[0], r.stdout, r.stderr)
        assert json.loads(r.stdout)["ok"] is True
    # tampering is detected by the stand-alone tool as well
    t = tmp_path / "tampered"
    shutil.copytree(kind_dir, t)
    for p in t.rglob("*"):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
    d = json.loads((t / "v0002" / "report.json").read_bytes())
    d["counts"]["unique_people"] = 11
    (t / "v0002" / "report.json").write_bytes(canonical_bytes(d))
    assert _run(verifier_venv, ["chain", t, "--hospital-key", hospital_pub], work).returncode == 1
    (rel / "payload.txt").write_text("changed\n")
    assert _run(verifier_venv, ["checksums", rel / "SHA256SUMS", "--sig", rel / "SHA256SUMS.sig", "--key",
                                rel / "release.pub"], work).returncode == 1


def test_running_the_verifier_never_imports_tripline_scope(verifier_venv, case_dir, tmp_path):
    probe = (
        "import sys, importlib.util\n"
        "from tscope_verify.cli import main\n"
        f"rc = main(['audit', {str(case_dir / 'audit.log')!r}])\n"
        "assert rc == 0, rc\n"
        "assert not [m for m in sys.modules if m.startswith('tripline_scope')]\n"
        "assert importlib.util.find_spec('tripline_scope') is None\n"
        "print('standalone ok')\n"
    )
    r = subprocess.run([str(verifier_venv / "bin" / "python"), "-I", "-c", probe], cwd=tmp_path,
                       capture_output=True, text=True)
    assert r.returncode == 0 and "standalone ok" in r.stdout, r.stdout + r.stderr
