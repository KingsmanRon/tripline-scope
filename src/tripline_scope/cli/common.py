"""Helpers shared by every module's CLI handlers."""

from __future__ import annotations

import os
import sys

from tripline_scope.core.auth import Identity, identity_provider
from tripline_scope.core.case import Case, find_case
from tripline_scope.core.errors import AuthenticationFailed, ConfigError
from tripline_scope.core.home import Home, get_secret


def home_of(args) -> Home:
    return Home(getattr(args, "home", None) or None)


def case_of(args) -> Case:
    return find_case(getattr(args, "case", None))


def add_case_arg(p, required: bool = False) -> None:
    p.add_argument("--case", required=required, help="case directory (default $TSCOPE_CASE or current directory)")


def read_password(args, env: str, prompt: str) -> str:
    if getattr(args, "password_stdin", False):
        pw = sys.stdin.readline().rstrip("\n")
        if not pw:
            raise ConfigError("empty password on stdin")
        return pw
    return get_secret(prompt, env)


def add_approver_args(p) -> None:
    p.add_argument("--approver", required=True, help="approver (Information Officer) username; signs in now")
    p.add_argument("--password-stdin", action="store_true", help="read the approver password from stdin")
    p.add_argument("--totp", help="approver TOTP code (or TSCOPE_APPROVER_TOTP)")


def approver_sign_in(args, home: Home, case: Case) -> Identity:
    """Fresh approver authentication for release/close; never reuses the operator's session."""
    pw = read_password(args, "TSCOPE_APPROVER_PASSWORD", f"Password for approver {args.approver}")
    totp = getattr(args, "totp", None) or os.environ.get("TSCOPE_APPROVER_TOTP")
    ident = identity_provider(home).authenticate(args.approver, pw, totp)
    required = set(home.config.get("require_totp_roles") or [])
    if "approver" in required and ident.auth_method != "password+totp":
        raise AuthenticationFailed("this installation requires TOTP for approvers")
    return ident
