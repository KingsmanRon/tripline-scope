"""Verification of signed destruction certificates."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import NotCanonicalError, load_canonical
from .formats import CERTIFICATE_FILE, CERTIFICATE_SCHEMA, CERTIFICATE_SIG_FILE, ROLE_HOSPITAL
from .result import Result
from .signatures import check_role_signature, load_signatures


def verify_certificate(
    path: str | Path, *, hospital_keys: list[Ed25519PublicKey] | None = None, trust_embedded: bool = False
) -> Result:
    path = Path(path)
    if path.is_dir():
        path = path / CERTIFICATE_FILE
    res = Result(subject=str(path))
    if not res.add("certificate exists", path.is_file()):
        return res
    try:
        cert = load_canonical(path.read_bytes())
        res.add("certificate is RFC 8785 canonical", True)
    except NotCanonicalError as exc:
        res.add("certificate is RFC 8785 canonical", False, str(exc))
        return res
    res.add("certificate schema", cert.get("schema") == CERTIFICATE_SCHEMA)
    res.add("case key destruction recorded", bool((cert.get("destroyed") or {}).get("case_key", {}).get("destroyed_at")))
    res.info.update(case_id=cert.get("case_id"), closed_at=cert.get("closed_at"))
    sig_path = path.with_name(CERTIFICATE_SIG_FILE)
    if not res.add("certificate signature file exists", sig_path.is_file()):
        return res
    try:
        sigs = load_signatures(sig_path)
    except (NotCanonicalError, ValueError) as exc:
        res.add("signature file well-formed", False, str(exc))
        return res
    check_role_signature(
        res, sigs, ROLE_HOSPITAL, path.parent, hospital_keys, required=True,
        expected_file=path.name, trust_embedded=trust_embedded,
    )
    return res
