"""Ed25519 public-key loading, key identifiers and signature checks."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def raw_public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub: Ed25519PublicKey | bytes) -> str:
    """Key identifier: first 16 bytes (32 hex chars) of SHA-256 over the raw 32-byte public key."""
    raw = pub if isinstance(pub, bytes) else raw_public_bytes(pub)
    return hashlib.sha256(raw).hexdigest()[:32]


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(data)
    else:  # base64 of the raw 32 bytes
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(data.strip()))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))


def verify_signature(pub: Ed25519PublicKey, signature_b64: str, message: bytes) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError):
        return False
