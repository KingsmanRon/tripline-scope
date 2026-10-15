"""Test and drill support: throw-away installations, users, sessions and an in-process CLI runner.

Used by the test suite, ``tscope drill`` and the demo. Never used for real cases.
"""

from __future__ import annotations

import contextlib
import io
import os
from dataclasses import dataclass
from pathlib import Path

PASSWORD = "Synthetic-Pass-2026!"
KEK_PASSPHRASE = "synthetic-kek-passphrase"
SIGNING_PASSPHRASE = "synthetic-signing-passphrase"
USERS = {"admin": "admin", "olivia": "operator", "rami": "reviewer", "ines": "approver"}


@dataclass
class Env:
    home_dir: Path
    session_file: Path

    def vars(self) -> dict[str, str]:
        return {
            "TSCOPE_HOME": str(self.home_dir),
            "TSCOPE_KEK_PASSPHRASE": KEK_PASSPHRASE,
            "TSCOPE_HOSPITAL_KEY_PASSPHRASE": SIGNING_PASSPHRASE,
            "TSCOPE_SESSION_FILE": str(self.session_file),
            "TSCOPE_PASSWORD": PASSWORD,
            "TSCOPE_NEW_USER_PASSWORD": PASSWORD,
            "TSCOPE_APPROVER_PASSWORD": PASSWORD,
        }

    def apply(self) -> None:
        os.environ.update(self.vars())
        os.environ.pop("TSCOPE_SESSION", None)


def run_cli(argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
    """Run ``tscope`` in-process; returns (exit code, stdout, stderr)."""
    import sys

    from tripline_scope.cli import main

    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = main(argv)
            except SystemExit as exc:  # argparse errors
                rc = int(exc.code or 0)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


def setup_installation(base: Path, *, hospital: str = "Synthetic Hospital") -> Env:
    """Create a home with an admin and the three case roles, all with :data:`PASSWORD`."""
    env = Env(base / "home", base / "session.token")
    env.apply()
    rc, out, err = run_cli(["init", "--hospital-name", hospital, "--admin", "admin"])
    assert rc == 0, err
    login("admin")
    for user, _role in USERS.items():
        if user == "admin":
            continue
        rc, out, err = run_cli(["user", "add", user])
        assert rc == 0, err
    return env


def login(user: str) -> None:
    rc, out, err = run_cli(["login", "--user", user])
    assert rc == 0, err


def open_case(base: Path, case_id: str = "CASE-TEST-001", *, mode: str = "incident") -> Path:
    login("admin")
    case_dir = base / case_id.lower()
    args = ["case", "init", str(case_dir), "--case-id", case_id, "--mode", mode,
            "--operator", "olivia", "--reviewer", "rami", "--approver", "ines"]
    if mode == "incident":
        args += ["--incident-start", "2026-09-01T00:00:00Z", "--incident-end", "2026-09-14T23:59:59Z"]
    rc, out, err = run_cli(args)
    assert rc == 0, err
    return case_dir
