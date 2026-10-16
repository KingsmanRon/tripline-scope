"""Ed25519 signing keys (hospital, provider, release). Private keys are PKCS#8 PEM, passphrase-encrypted."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tscope_verify.keys import key_id, load_public_key, raw_public_bytes  # noqa: F401

from .errors import ConfigError


@dataclass
class Signer:
    role: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public_key)

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.private_key.sign(message)).decode("ascii")

    def signature_entry(self, signed_file: str, message: bytes) -> dict:
        return {
            "role": self.role,
            "alg": "Ed25519",
            "key_id": self.key_id,
            "public_key": base64.b64encode(raw_public_bytes(self.public_key)).decode("ascii"),
            "signed_file": signed_file,
            "signature": self.sign(message),
        }


def generate_keypair(private_path: Path, public_path: Path, passphrase: str | None) -> str:
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.exists():
        raise ConfigError(f"refusing to overwrite existing key {private_path.name}")
    key = Ed25519PrivateKey.generate()
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    public_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key_id(key.public_key())


def load_signer(role: str, private_path: Path, passphrase: str | None) -> Signer:
    try:
        data = Path(private_path).read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"{role} signing key not found (is the key media mounted?)") from None
    try:
        key = serialization.load_pem_private_key(data, password=passphrase.encode() if passphrase else None)
    except (ValueError, TypeError):
        raise ConfigError(f"{role} signing key could not be unlocked (wrong passphrase?)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError(f"{role} signing key is not Ed25519")
    return Signer(role=role, private_key=key)
