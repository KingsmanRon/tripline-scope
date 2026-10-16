"""Local accounts (Argon2id), optional TOTP, sessions, and the seam for directory integration.

Directory (AD/LDAP) integration is out of scope for v0: implement :class:`IdentityProvider` and select it
with ``identity_provider`` in the installation config. Role assignment per case stays in ``case.yaml``.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import pyotp
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto
from .canonical import canonical_bytes
from .errors import AuthenticationFailed, ConfigError, PermissionDenied
from .home import Home
from .timeutil import iso, parse_utc, utcnow

SYSTEM_ROLES = {"admin"}
CASE_ROLES = ("operator", "reviewer", "approver")

_PH = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)
MIN_PASSWORD = 12


@dataclass(frozen=True)
class Identity:
    username: str
    system_roles: frozenset[str] = field(default_factory=frozenset)
    auth_method: str = "password"
    authenticated_at: str | None = None


class IdentityProvider(Protocol):
    def authenticate(self, username: str, password: str, totp: str | None = None) -> Identity: ...

    def exists(self, username: str) -> bool: ...


class UserStore:
    """``users.json`` in the installation home (mode 0600). No patient data; password hashes are Argon2id;
    TOTP secrets are AES-GCM encrypted under a key derived from the hospital KEK."""

    def __init__(self, home: Home):
        self.home = home
        self.path = home.users_path

    @contextmanager
    def _locked(self):
        lock = self.path.with_name("users.lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _load(self) -> dict:
        if not self.path.exists():
            return {"schema": "tripline.users/v1", "users": {}}
        return json.loads(self.path.read_bytes())

    def _save(self, doc: dict) -> None:
        tmp = self.path.with_name("users.json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(canonical_bytes(doc))
        os.replace(tmp, self.path)

    def _totp_key(self) -> bytes:
        return crypto.hkdf(self.home.kek(), b"tripline-totp-secrets")

    # ---------------------------------------------------------------- management
    def add(self, username: str, password: str, *, system_roles: list[str] | None = None, display: str = "") -> None:
        _validate_username(username)
        _validate_password(password)
        roles = sorted(set(system_roles or []))
        if not set(roles) <= SYSTEM_ROLES:
            raise ConfigError(f"unknown system role(s): {set(roles) - SYSTEM_ROLES}")
        with self._locked():
            doc = self._load()
            if username in doc["users"]:
                raise ConfigError("user already exists")
            doc["users"][username] = {
                "password_hash": _PH.hash(password),
                "system_roles": roles,
                "display": display[:80],
                "disabled": False,
                "created_at": iso(utcnow()),
                "failed": 0,
                "locked_until": None,
                "totp": None,
                "totp_last_step": None,
            }
            self._save(doc)

    def set_password(self, username: str, password: str) -> None:
        _validate_password(password)
        with self._locked():
            doc = self._load()
            u = self._get(doc, username)
            u["password_hash"] = _PH.hash(password)
            u["failed"] = 0
            u["locked_until"] = None
            self._save(doc)

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._locked():
            doc = self._load()
            self._get(doc, username)["disabled"] = disabled
            self._save(doc)

    def enroll_totp(self, username: str) -> str:
        """Create a TOTP secret; returns the provisioning URI to show the user once."""
        secret = pyotp.random_base32()
        nonce = os.urandom(12)
        ct = AESGCM(self._totp_key()).encrypt(nonce, secret.encode(), b"totp:" + username.encode())
        with self._locked():
            doc = self._load()
            self._get(doc, username)["totp"] = {"nonce": crypto.b64e(nonce), "ct": crypto.b64e(ct)}
            self._save(doc)
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Tripline Scope")

    def totp_secret(self, username: str) -> str | None:
        """For tests and the drill only: decrypt a user's TOTP secret."""
        u = self._get(self._load(), username)
        if not u.get("totp"):
            return None
        return AESGCM(self._totp_key()).decrypt(
            crypto.b64d(u["totp"]["nonce"]), crypto.b64d(u["totp"]["ct"]), b"totp:" + username.encode()
        ).decode()

    def exists(self, username: str) -> bool:
        return username in self._load()["users"]

    def list(self) -> list[dict]:
        doc = self._load()
        return [
            {"username": n, "system_roles": u["system_roles"], "disabled": u["disabled"], "totp": bool(u["totp"])}
            for n, u in sorted(doc["users"].items())
        ]

    @staticmethod
    def _get(doc: dict, username: str) -> dict:
        try:
            return doc["users"][username]
        except KeyError:
            raise ConfigError("unknown user") from None

    # ---------------------------------------------------------------- authentication
    def authenticate(self, username: str, password: str, totp: str | None = None) -> Identity:
        now = utcnow()
        with self._locked():
            doc = self._load()
            u = doc["users"].get(username)
            if u is None:
                _PH.hash(password)  # equalise timing
                raise AuthenticationFailed("authentication failed")
            if u["disabled"]:
                raise AuthenticationFailed("account disabled")
            if u["locked_until"] and parse_utc(u["locked_until"]) > now:
                raise AuthenticationFailed("account temporarily locked after repeated failures")
            ok = False
            try:
                ok = _PH.verify(u["password_hash"], password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                ok = False
            method = "password"
            if ok and u.get("totp"):
                secret = AESGCM(self._totp_key()).decrypt(
                    crypto.b64d(u["totp"]["nonce"]), crypto.b64d(u["totp"]["ct"]), b"totp:" + username.encode()
                ).decode()
                t = pyotp.TOTP(secret)
                step = int(now.timestamp()) // 30
                matched = None
                if totp:
                    for delta in (-1, 0, 1):
                        if secrets.compare_digest(t.at((step + delta) * 30), str(totp)):
                            matched = step + delta
                if matched is None or (u.get("totp_last_step") is not None and matched <= u["totp_last_step"]):
                    ok = False
                else:
                    u["totp_last_step"] = matched
                    method = "password+totp"
            if not ok:
                u["failed"] = int(u.get("failed", 0)) + 1
                if u["failed"] >= int(self.home.config.get("max_failed_logins", 5)):
                    u["locked_until"] = iso(now + dt.timedelta(minutes=int(self.home.config.get("lockout_minutes", 15))))
                    u["failed"] = 0
                self._save(doc)
                raise AuthenticationFailed("authentication failed")
            u["failed"] = 0
            u["locked_until"] = None
            if _PH.check_needs_rehash(u["password_hash"]):
                u["password_hash"] = _PH.hash(password)
            self._save(doc)
            return Identity(username, frozenset(u["system_roles"]), method, iso(now))


class LocalIdentityProvider:
    def __init__(self, home: Home):
        self.store = UserStore(home)

    def authenticate(self, username: str, password: str, totp: str | None = None) -> Identity:
        return self.store.authenticate(username, password, totp)

    def exists(self, username: str) -> bool:
        return self.store.exists(username)


def identity_provider(home: Home) -> IdentityProvider:
    kind = home.config.get("identity_provider", "local")
    if kind == "local":
        return LocalIdentityProvider(home)
    raise ConfigError(f"identity provider {kind!r} is not available in v0 (directory integration is a later seam)")


# -------------------------------------------------------------------- sessions
def _session_file() -> Path:
    return Path(os.environ.get("TSCOPE_SESSION_FILE") or Path.home() / ".tscope_session")


def create_session(home: Home, ident: Identity) -> str:
    token = secrets.token_urlsafe(32)
    hours = int(home.config.get("session_hours", 8))
    rec = {
        "username": ident.username,
        "system_roles": sorted(ident.system_roles),
        "auth_method": ident.auth_method,
        "authenticated_at": ident.authenticated_at,
        "expires_at": iso(utcnow() + dt.timedelta(hours=hours)),
    }
    home.sessions_dir.mkdir(exist_ok=True)
    p = home.sessions_dir / (hashlib.sha256(token.encode()).hexdigest() + ".json")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(canonical_bytes(rec))
    return token


def save_cli_token(token: str) -> Path:
    p = _session_file()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return p


def _token() -> str | None:
    tok = os.environ.get("TSCOPE_SESSION")
    if tok:
        return tok.strip()
    p = _session_file()
    return p.read_text().strip() if p.exists() else None


def current_identity(home: Home, *, required: bool = True) -> Identity | None:
    tok = _token()
    if not tok:
        if required:
            raise PermissionDenied("not signed in (run 'tscope login')")
        return None
    p = home.sessions_dir / (hashlib.sha256(tok.encode()).hexdigest() + ".json")
    if not p.exists():
        if required:
            raise PermissionDenied("session not found or revoked (run 'tscope login')")
        return None
    rec = json.loads(p.read_bytes())
    if parse_utc(rec["expires_at"]) <= utcnow():
        p.unlink(missing_ok=True)
        if required:
            raise PermissionDenied("session expired (run 'tscope login')")
        return None
    return Identity(rec["username"], frozenset(rec["system_roles"]), rec["auth_method"], rec["authenticated_at"])


def end_session(home: Home) -> None:
    tok = _token()
    if tok:
        (home.sessions_dir / (hashlib.sha256(tok.encode()).hexdigest() + ".json")).unlink(missing_ok=True)
    if not os.environ.get("TSCOPE_SESSION"):
        _session_file().unlink(missing_ok=True)


# -------------------------------------------------------------------- validation
def _validate_username(username: str) -> None:
    import re

    if not re.fullmatch(r"[a-z][a-z0-9._-]{1,31}", username):
        raise ConfigError("username must be 2-32 chars: lowercase letters, digits, . _ -")


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise ConfigError(f"password must be at least {MIN_PASSWORD} characters")
