"""Hashed locks: every runtime requirement pinned with == and hashed; no telemetry SDK in the closure."""

import os
import re
import subprocess
import sys
from pathlib import Path

import check_locks
from check_licences import FIRST_PARTY, parse_lock

ROOT = Path(__file__).resolve().parents[2]
REQ = ROOT / "requirements"


def test_every_runtime_requirement_pinned_with_hash():
    lock = parse_lock(REQ / "runtime.txt")
    assert len(lock) >= 30
    for e in lock.values():
        assert e["pinned"] and re.fullmatch(r"[0-9A-Za-z.+!]+", e["version"]), e["name"]
        assert e["hashes"], f"{e['name']} has no --hash"
        assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in e["hashes"]), e["name"]


def test_raw_lock_lines_are_pinned():
    # Independent of parse_lock: every requirement line in the file starts with name==version and a hash follows.
    text = (REQ / "runtime.txt").read_text()
    reqs = [ln for ln in text.splitlines() if ln and not ln.startswith((" ", "#", "-"))]
    assert reqs and all(re.match(r"^[A-Za-z0-9][A-Za-z0-9._\-]*==\S+ \\$", ln) for ln in reqs), reqs[:3]
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 2)[2])
    assert all("--hash=sha256:" in b for b in blocks if re.match(r"^[A-Za-z0-9]", b))


def test_all_locks_pass_checker():
    assert check_locks.main(["--root", str(ROOT)]) == 0


def test_first_party_packages_never_locked_from_an_index():
    for name in ("runtime.txt", "dev.txt"):
        lock = parse_lock(REQ / name)
        assert not FIRST_PARTY & set(lock), name
    # ...and the local verifier is what satisfies pyproject's requirement during locking
    assert (REQ / "local.in").read_text().strip().splitlines()[-1] == "./verify"


def test_runtime_lock_covers_both_pyprojects():
    lock = parse_lock(REQ / "runtime.txt")
    for dep in check_locks._deps(ROOT / "pyproject.toml") + check_locks._deps(ROOT / "verify" / "pyproject.toml"):
        key = check_locks._name(dep)
        assert key in FIRST_PARTY or key in lock, dep


def test_checker_rejects_unpinned_and_unhashed(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("foo>=1.0 \\\n    --hash=sha256:" + "a" * 64 + "\nbar==2.0\n"
                   "tripline-scope-verify==0.1.0 \\\n    --hash=sha256:" + "b" * 64 + "\n"
                   "opentelemetry-sdk==1.0 \\\n    --hash=sha256:" + "c" * 64 + "\n")
    errors = check_locks.check_lock_file(bad, required=["foo", "bar", "baz>=1"])
    text = "\n".join(errors)
    assert "foo is not pinned" in text
    assert "bar has no --hash" in text
    assert "first-party tripline-scope-verify" in text
    assert "telemetry package opentelemetry-sdk" in text
    assert "'baz>=1' is not in the lock" in text


def test_no_opentelemetry_sdk_or_exporter_in_runtime_closure():
    lock = parse_lock(REQ / "runtime.txt")
    otel = sorted(k for k in lock if k.startswith("opentelemetry"))
    # fastapi depends on the no-op API only; any SDK, exporter or instrumentation would be a telemetry path.
    assert otel == ["opentelemetry-api"], otel
    for forbidden in ("opentelemetry-sdk", "opentelemetry-proto", "opentelemetry-distro"):
        assert forbidden not in lock
    assert not [k for k in lock if k.startswith(("opentelemetry-exporter", "opentelemetry-instrumentation"))]
    assert not [k for k in lock if k in ("sentry-sdk", "ddtrace", "newrelic", "posthog", "logfire")]


def test_product_disables_otel_sdk_everywhere():
    code = "import os, tripline_scope; print(os.environ.get('OTEL_SDK_DISABLED'))"
    env = {k: v for k, v in os.environ.items() if not k.startswith("OTEL_")}
    env["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT / 'verify' / 'src'}"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "true"
    assert "OTEL_SDK_DISABLED=true" in (ROOT / "Dockerfile").read_text()
    assert 'OTEL_SDK_DISABLED: "true"' in (ROOT / "docker-compose.yml").read_text()
    assert "OTEL_SDK_DISABLED=true" in (ROOT / "bundle" / "install.sh").read_text()


def test_lock_targets_python_312_linux():
    script = (ROOT / "scripts" / "lock.sh").read_text()
    assert "--python-version 3.12" in script and "x86_64-manylinux" in script and "--generate-hashes" in script
