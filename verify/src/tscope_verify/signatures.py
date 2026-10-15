"""Verification of ``signatures.json`` envelopes (detached Ed25519 signatures over exact file bytes)."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import NotCanonicalError, load_canonical
from .formats import SIGNATURES_SCHEMA
from .keys import key_id, public_key_from_b64, raw_public_bytes, verify_signature
from .result import Result


def load_signatures(path: Path) -> list[dict]:
    doc = load_canonical(path.read_bytes())
    if doc.get("schema") != SIGNATURES_SCHEMA:
        raise NotCanonicalError("unexpected signatures schema")
    sigs = doc.get("signatures")
    if not isinstance(sigs, list):
        raise NotCanonicalError("signatures must be a list")
    return sigs


def check_role_signature(
    result: Result,
    sigs: list[dict],
    role: str,
    base_dir: Path,
    trusted: list[Ed25519PublicKey] | None,
    *,
    required: bool,
    expected_file: str,
    trust_embedded: bool = False,
) -> None:
    entries = [s for s in sigs if s.get("role") == role]
    if not entries:
        result.add(f"{role} signature present", not required, "absent" + ("" if required else " (optional)"))
        return
    if len(entries) > 1:
        result.add(f"{role} signature unique", False, f"{len(entries)} {role} signatures")
        return
    s = entries[0]
    if s.get("alg") != "Ed25519":
        result.add(f"{role} signature algorithm", False, str(s.get("alg")))
        return
    if s.get("signed_file") != expected_file:
        result.add(f"{role} signature target", False, f"signs {s.get('signed_file')!r}, expected {expected_file!r}")
        return
    try:
        embedded = public_key_from_b64(s["public_key"])
    except Exception:  # noqa: BLE001 - any decoding failure is a verification failure
        result.add(f"{role} public key decodes", False)
        return
    if key_id(embedded) != s.get("key_id"):
        result.add(f"{role} key id matches key", False)
        return
    target = base_dir / expected_file
    if not target.is_file():
        result.add(f"{role} signed file exists", False, expected_file)
        return
    message = target.read_bytes()
    if trusted:
        trusted_raw = {raw_public_bytes(k) for k in trusted}
        pinned = raw_public_bytes(embedded) in trusted_raw
        result.add(f"{role} key is pinned/trusted", pinned, s.get("key_id", ""))
        if not pinned:
            return
    elif not trust_embedded:
        result.add(f"{role} key is pinned/trusted", False, f"no trusted key supplied (pass --{role}-key)")
        return
    else:
        result.add(f"{role} key is pinned/trusted", True, "WARNING: trusting embedded key " + s.get("key_id", ""))
    result.add(f"{role} signature valid", verify_signature(embedded, s.get("signature", ""), message), s.get("key_id", ""))
