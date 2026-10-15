"""The installation home: hospital configuration, KEK location, keystore, users, sessions and signing keys.

The home lives outside every case directory (default ``/var/lib/tripline`` in the bundle install,
``~/.tripline`` for development; override with ``TSCOPE_HOME``). It never contains patient data.
"""

from __future__ import annotations

import getpass
import os
import secrets
import sys
from functools import cached_property
from pathlib import Path

import yaml

from . import crypto
from .errors import ConfigError
from .keys import Signer, generate_keypair, load_public_key, load_signer

HOME_SCHEMA = "tripline.home/v1"


def default_home() -> Path:
    return Path(os.environ.get("TSCOPE_HOME") or Path.home() / ".tripline")


def get_secret(prompt: str, env: str, *, confirm: bool = False, allow_empty: bool = False) -> str | None:
    """Read a secret from the named environment variable (automation / demo) or an interactive prompt.

    Secrets are never written to logs, the audit log or any report.
    """
    val = os.environ.get(env)
    if val is not None:
        return val or (None if allow_empty else val)
    if not sys.stdin.isatty():
        if allow_empty:
            return None
        raise ConfigError(f"{prompt} required: set {env} or run interactively")
    val = getpass.getpass(f"{prompt}: ")
    if confirm and getpass.getpass(f"{prompt} (again): ") != val:
        raise ConfigError("entries did not match")
    if not val and not allow_empty:
        raise ConfigError(f"{prompt} must not be empty")
    return val or None


class Home:
    def __init__(self, root: Path | str | None = None):
        self.root = Path(root) if root else default_home()
        cfg_path = self.root / "config.yaml"
        if not cfg_path.is_file():
            raise ConfigError(f"no Tripline installation at {self.root} (run 'tscope init')")
        self.config = yaml.safe_load(cfg_path.read_text()) or {}
        if self.config.get("schema") != HOME_SCHEMA:
            raise ConfigError("unrecognised installation config")
        self._kek: bytes | None = None

    # ------------------------------------------------------------------ creation
    @classmethod
    def init(
        cls,
        root: Path | str,
        *,
        hospital_name: str,
        kek_path: Path | str | None = None,
        kek_passphrase: str | None,
        hospital_key_passphrase: str | None,
        keystore_dir: Path | str | None = None,
    ) -> Home:
        root = Path(root)
        if (root / "config.yaml").exists():
            raise ConfigError("installation already initialised")
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        for sub in ("keys", "sessions", "certificates", "profiles"):
            (root / sub).mkdir(exist_ok=True)
            os.chmod(root / sub, 0o700)
        kek_path = Path(kek_path) if kek_path else root / "kek" / "kek.json"
        keystore_dir = Path(keystore_dir) if keystore_dir else root / "keystore"
        (keystore_dir / "cases").mkdir(parents=True, exist_ok=True)
        os.chmod(keystore_dir, 0o700)
        crypto.create_kek_file(kek_path, kek_passphrase)
        priv = root / "keys" / "hospital_signing.pem"
        pub = root / "keys" / "hospital_signing.pub"
        generate_keypair(priv, pub, hospital_key_passphrase)
        cfg = {
            "schema": HOME_SCHEMA,
            "installation_id": secrets.token_hex(8),
            "hospital_name": hospital_name,
            "kek_path": str(kek_path.resolve()),
            "keystore_dir": str(keystore_dir.resolve()),
            "signing": {
                "hospital_private_key": str(priv.resolve()),
                "hospital_public_key": str(pub.resolve()),
                "provider_private_key": None,
                "provider_public_key": None,
                "provider_name": None,
            },
            "identity_provider": "local",
            "session_hours": 8,
            "max_failed_logins": 5,
            "lockout_minutes": 15,
            "require_totp_roles": [],
            "duckdb": {"memory_limit": None, "threads": None, "spill_dir": None, "spill_dir_encrypted": False},
            "swap_encrypted_attested": False,
        }
        (root / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
        os.chmod(root / "config.yaml", 0o600)
        return cls(root)

    def save_config(self) -> None:
        (self.root / "config.yaml").write_text(yaml.safe_dump(self.config, sort_keys=False))

    # ------------------------------------------------------------------ locations
    @property
    def keystore_dir(self) -> Path:
        return Path(self.config["keystore_dir"])

    @property
    def users_path(self) -> Path:
        return self.root / "users.json"

    @property
    def sessions_dir(self) -> Path:
        return self.root / "sessions"

    @property
    def certificates_dir(self) -> Path:
        return self.root / "certificates"

    @property
    def profiles_dir(self) -> Path:
        return self.root / "profiles"

    @property
    def audit_path(self) -> Path:
        return self.root / "audit.log"

    def wrapped_dek_path(self, case_id: str) -> Path:
        if not case_id.replace("-", "").replace("_", "").isalnum():
            raise ConfigError("invalid case id")
        return self.keystore_dir / "cases" / f"{case_id}.dek.json"

    # ------------------------------------------------------------------ keys
    def kek(self) -> bytes:
        if self._kek is None:
            import json

            path = Path(self.config["kek_path"])
            try:
                kdf = json.loads(path.read_bytes()).get("kdf")
            except FileNotFoundError:
                raise ConfigError("hospital KEK file not found (is the key media mounted?)") from None
            pw = get_secret("Hospital KEK passphrase", "TSCOPE_KEK_PASSPHRASE") if kdf != "none" else None
            self._kek = crypto.load_kek(path, pw)
        return self._kek

    def hospital_signer(self) -> Signer:
        pw = get_secret("Hospital signing key passphrase", "TSCOPE_HOSPITAL_KEY_PASSPHRASE", allow_empty=True)
        return load_signer("hospital", Path(self.config["signing"]["hospital_private_key"]), pw)

    def provider_signer(self) -> Signer | None:
        path = self.config["signing"].get("provider_private_key")
        if not path:
            return None
        pw = get_secret("Provider signing key passphrase", "TSCOPE_PROVIDER_KEY_PASSPHRASE", allow_empty=True)
        return load_signer("provider", Path(path), pw)

    @cached_property
    def hospital_public_key_path(self) -> Path:
        return Path(self.config["signing"]["hospital_public_key"])

    def trusted_hospital_keys(self):
        return [load_public_key(self.hospital_public_key_path)]

    def trusted_provider_keys(self):
        p = self.config["signing"].get("provider_public_key")
        return [load_public_key(p)] if p else None
