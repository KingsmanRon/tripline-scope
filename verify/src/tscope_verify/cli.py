"""``tscope-verify``: offline verification of Tripline Scope artefacts."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import verify_audit_log
from .certificate import verify_certificate
from .checksums import verify_checksums
from .keys import load_public_key
from .report import verify_chain, verify_version


def _keys(paths):
    return [load_public_key(p) for p in paths] if paths else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tscope-verify", description=__doc__)
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    sub = p.add_subparsers(dest="what", required=True)

    def add_keys(sp, provider=True):
        sp.add_argument("--hospital-key", action="append", help="trusted hospital Ed25519 public key (PEM)")
        if provider:
            sp.add_argument("--provider-key", action="append", help="trusted provider Ed25519 public key (PEM)")
            sp.add_argument("--require-provider", action="store_true", help="fail if no provider co-signature")
        sp.add_argument("--trust-embedded", action="store_true", help="accept the key embedded in the file (unsafe)")

    r = sub.add_parser("report", help="verify one released report version directory")
    r.add_argument("path")
    add_keys(r)
    c = sub.add_parser("chain", help="verify every version of one report kind and the hash chain")
    c.add_argument("path")
    add_keys(c)
    a = sub.add_parser("audit", help="verify a hash-chained audit log")
    a.add_argument("path")
    d = sub.add_parser("certificate", help="verify a signed destruction certificate")
    d.add_argument("path")
    add_keys(d, provider=False)
    s = sub.add_parser("checksums", help="verify a signed SHA256SUMS file and the files it lists")
    s.add_argument("path")
    s.add_argument("--sig", required=True)
    s.add_argument("--key", action="append", help="trusted release Ed25519 public key (PEM)")
    s.add_argument("--no-files", action="store_true")
    s.add_argument("--trust-embedded", action="store_true")
    return p


def run(args) -> int:
    if args.what == "report":
        res = verify_version(
            args.path, hospital_keys=_keys(args.hospital_key), provider_keys=_keys(args.provider_key),
            require_provider=args.require_provider, trust_embedded=args.trust_embedded,
        )
    elif args.what == "chain":
        res = verify_chain(
            args.path, hospital_keys=_keys(args.hospital_key), provider_keys=_keys(args.provider_key),
            require_provider=args.require_provider, trust_embedded=args.trust_embedded,
        )
    elif args.what == "audit":
        res = verify_audit_log(args.path)
    elif args.what == "certificate":
        res = verify_certificate(args.path, hospital_keys=_keys(args.hospital_key), trust_embedded=args.trust_embedded)
    else:
        res = verify_checksums(
            args.path, sig=args.sig, release_keys=_keys(args.key), check_files=not args.no_files,
            trust_embedded=args.trust_embedded,
        )
    print(json.dumps(res.as_dict(), indent=2) if args.json else res.render())
    return 0 if res.ok else 1


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
