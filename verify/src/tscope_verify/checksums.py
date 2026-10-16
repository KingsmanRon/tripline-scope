"""Verification of release bundle checksum files and their detached signature."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import NotCanonicalError, sha256_file
from .formats import ROLE_RELEASE
from .result import Result
from .signatures import check_role_signature, load_signatures


def verify_checksums(
    sums: str | Path, *, sig: str | Path, release_keys: list[Ed25519PublicKey] | None, check_files: bool = True,
    trust_embedded: bool = False,
) -> Result:
    sums = Path(sums)
    res = Result(subject=str(sums))
    if not res.add("checksum file exists", sums.is_file()):
        return res
    sig = Path(sig)
    try:
        sigs = load_signatures(sig)
    except (NotCanonicalError, ValueError, FileNotFoundError) as exc:
        res.add("signature file well-formed", False, type(exc).__name__)
        return res
    # The signature names the checksum file; verify against its bytes wherever it lives.
    entries = [s for s in sigs if s.get("role") == ROLE_RELEASE]
    if entries and entries[0].get("signed_file") != sums.name:
        res.add("signature targets checksum file", False)
        return res
    check_role_signature(
        res, sigs, ROLE_RELEASE, sums.parent, release_keys, required=True,
        expected_file=sums.name, trust_embedded=trust_embedded,
    )
    if check_files:
        bad = []
        n = 0
        for line in sums.read_text().splitlines():
            if not line.strip():
                continue
            digest, _, name = line.partition("  ")
            n += 1
            p = sums.parent / name
            if not p.is_file() or sha256_file(p) != digest:
                bad.append(name)
        res.add("all listed files match", not bad, f"{n} files" + (f"; mismatched: {', '.join(bad[:5])}" if bad else ""))
    return res
