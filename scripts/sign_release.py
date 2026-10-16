#!/usr/bin/env python3
"""Write SHA256SUMS for a bundle directory and sign it with the release Ed25519 key.

    sign_release.py BUNDLE_DIR

The release key is the passphrase-encrypted PKCS#8 PEM named by $RELEASE_KEY (passphrase in
$RELEASE_KEY_PASSPHRASE). When RELEASE_KEY is not set (local builds), an EPHEMERAL key is generated in a
fresh directory under the system temp dir, outside the repository, used once, and reported loudly; the
bundle's BUILDINFO.json then records ``release_key: ephemeral``. A key path inside the repository is refused.

Outputs in BUNDLE_DIR: release.pub (PEM), SHA256SUMS (``<sha256>  <relative path>`` for every other file,
sorted) and SHA256SUMS.sig (``tripline.signatures/v1``, role ``release``, Ed25519 over the exact bytes of
SHA256SUMS). Verify with: tscope-verify checksums SHA256SUMS --sig SHA256SUMS.sig --key release.pub
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT / "src", ROOT / "verify" / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from tripline_scope.core.canonical import canonical_bytes  # noqa: E402
from tripline_scope.core.keys import generate_keypair, load_signer  # noqa: E402
from tscope_verify import formats as F  # noqa: E402

EXCLUDE = {"SHA256SUMS", "SHA256SUMS.sig"}


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT)
        return True
    except ValueError:
        return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def write_sums(bundle: Path) -> bytes:
    lines = []
    for p in sorted(bundle.rglob("*")):
        rel = p.relative_to(bundle).as_posix()
        if p.is_symlink():
            raise SystemExit(f"refusing symlink in bundle: {rel}")
        if p.is_file() and rel not in EXCLUDE:
            if any(c.isspace() for c in rel):
                raise SystemExit(f"refusing file name with whitespace: {rel!r}")
            lines.append(f"{sha256_file(p)}  {rel}\n")
    data = "".join(lines).encode()
    (bundle / "SHA256SUMS").write_bytes(data)
    return data


def release_signer():
    key = os.environ.get("RELEASE_KEY")
    if key:
        if _inside_repo(Path(key)):
            raise SystemExit("RELEASE_KEY must not live inside the repository")
        return load_signer("release", Path(key), os.environ.get("RELEASE_KEY_PASSPHRASE") or None), False, None
    d = Path(tempfile.mkdtemp(prefix="tscope-ephemeral-release-key-"))
    if _inside_repo(d):
        raise SystemExit("temporary directory is inside the repository; set TMPDIR elsewhere")
    generate_keypair(d / "release_signing.pem", d / "release_signing.pub", None)
    return load_signer("release", d / "release_signing.pem", None), True, d


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    bundle = Path(argv[0])
    signer, ephemeral, keydir = release_signer()
    pub = signer.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (bundle / "release.pub").write_bytes(pub)
    info_path = bundle / "BUILDINFO.json"
    if info_path.exists():
        info = json.loads(info_path.read_text())
        info["release_key"] = "ephemeral" if ephemeral else "release"
        info["release_key_id"] = signer.key_id
        info_path.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    sums = write_sums(bundle)
    sig = canonical_bytes({"schema": F.SIGNATURES_SCHEMA, "signatures": [signer.signature_entry("SHA256SUMS", sums)]})
    (bundle / "SHA256SUMS.sig").write_bytes(sig)
    n = sums.count(b"\n")
    print(f"signed SHA256SUMS ({n} files) with release key {signer.key_id}")
    if ephemeral:
        print(f"WARNING: RELEASE_KEY not set: signed with an EPHEMERAL key generated in {keydir} (outside the "
              "repository). This bundle is for local testing only; delete that directory when done.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
