"""Verification of released report versions and of the version chain for one report kind."""

from __future__ import annotations

import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import NotCanonicalError, load_canonical, sha256_file, sha256_hex
from .formats import (
    RELEASE_FILE,
    RELEASE_SCHEMA,
    REPORT_FILE,
    REPORT_SCHEMA,
    ROLE_HOSPITAL,
    ROLE_PROVIDER,
    SIGNATURES_FILE,
)
from .result import Result
from .signatures import check_role_signature, load_signatures

_VDIR = re.compile(r"^v(\d{4,})$")
_CONTROL_FILES = {REPORT_FILE, RELEASE_FILE, SIGNATURES_FILE}


def _listed_files(vdir: Path) -> set[str]:
    out = set()
    for p in vdir.rglob("*"):
        if p.is_file():
            out.add(p.relative_to(vdir).as_posix())
    return out


def verify_version(
    vdir: str | Path,
    *,
    hospital_keys: list[Ed25519PublicKey] | None = None,
    provider_keys: list[Ed25519PublicKey] | None = None,
    require_provider: bool = False,
    trust_embedded: bool = False,
) -> Result:
    vdir = Path(vdir)
    res = Result(subject=str(vdir))
    report_path = vdir / REPORT_FILE
    release_path = vdir / RELEASE_FILE
    sig_path = vdir / SIGNATURES_FILE
    for p in (report_path, release_path, sig_path):
        if not res.add(f"{p.name} exists", p.is_file()):
            return res
    report_bytes = report_path.read_bytes()
    try:
        report = load_canonical(report_bytes)
        res.add("report.json is RFC 8785 canonical", True)
    except NotCanonicalError as exc:
        res.add("report.json is RFC 8785 canonical", False, str(exc))
        return res
    try:
        release = load_canonical(release_path.read_bytes())
        res.add("release.json is RFC 8785 canonical", True)
    except NotCanonicalError as exc:
        res.add("release.json is RFC 8785 canonical", False, str(exc))
        return res
    report_sha = sha256_hex(report_bytes)
    res.info.update(
        report_sha256=report_sha,
        kind=report.get("kind"),
        version=report.get("version"),
        case_id=report.get("case_id"),
        previous_report_sha256=report.get("previous_report_sha256"),
    )
    res.add("report schema", report.get("schema") == REPORT_SCHEMA, str(report.get("schema")))
    res.add("release schema", release.get("schema") == RELEASE_SCHEMA, str(release.get("schema")))
    res.add("release binds report hash", release.get("report_sha256") == report_sha)
    for f in ("case_id", "kind", "version", "previous_report_sha256"):
        res.add(f"release.{f} matches report", release.get(f) == report.get(f), f"{release.get(f)!r} vs {report.get(f)!r}")
    m = _VDIR.match(vdir.name)
    if m:
        res.add("directory name matches version", int(m.group(1)) == report.get("version"))
    approval = release.get("approval") or {}
    res.add(
        "approval recorded",
        bool(approval.get("approver")) and bool(approval.get("approved_at")),
        f"approver={approval.get('approver')!r}",
    )
    operators = release.get("operators") or []
    res.add("approver is not an operator of this case", approval.get("approver") not in operators)
    artefacts = release.get("artefacts") or {}
    actual = _listed_files(vdir) - _CONTROL_FILES
    res.add("no unsigned files in version directory", actual <= set(artefacts), ", ".join(sorted(actual - set(artefacts))))
    for name, digest in sorted(artefacts.items()):
        p = vdir / name
        ok = p.is_file() and sha256_file(p) == digest
        res.add(f"artefact {name} hash", ok)
    try:
        sigs = load_signatures(sig_path)
    except (NotCanonicalError, ValueError) as exc:
        res.add("signatures.json well-formed", False, str(exc))
        return res
    check_role_signature(
        res, sigs, ROLE_HOSPITAL, vdir, hospital_keys, required=True, expected_file=RELEASE_FILE, trust_embedded=trust_embedded
    )
    check_role_signature(
        res,
        sigs,
        ROLE_PROVIDER,
        vdir,
        provider_keys,
        required=require_provider,
        expected_file=REPORT_FILE,
        trust_embedded=trust_embedded or not provider_keys,
    )
    unknown = [s.get("role") for s in sigs if s.get("role") not in (ROLE_HOSPITAL, ROLE_PROVIDER)]
    res.add("no unknown signature roles", not unknown, ", ".join(map(str, unknown)))
    return res


def verify_chain(
    kind_dir: str | Path,
    *,
    hospital_keys: list[Ed25519PublicKey] | None = None,
    provider_keys: list[Ed25519PublicKey] | None = None,
    require_provider: bool = False,
    trust_embedded: bool = False,
) -> Result:
    kind_dir = Path(kind_dir)
    res = Result(subject=str(kind_dir))
    vdirs = sorted(
        (int(m.group(1)), p) for p in kind_dir.iterdir() if p.is_dir() and (m := _VDIR.match(p.name))
    ) if kind_dir.is_dir() else []
    if not res.add("at least one released version", bool(vdirs)):
        return res
    numbers = [n for n, _ in vdirs]
    res.add("versions are contiguous from 1", numbers == list(range(1, len(numbers) + 1)), str(numbers))
    prev_sha = None
    case_id = None
    for n, p in vdirs:
        vr = verify_version(
            p,
            hospital_keys=hospital_keys,
            provider_keys=provider_keys,
            require_provider=require_provider,
            trust_embedded=trust_embedded,
        )
        res.extend(vr, prefix=f"v{n:04d}: ")
        sha = vr.info.get("report_sha256")
        res.add(
            f"v{n:04d}: previous_report_sha256 links to v{n - 1:04d}" if n > 1 else "v0001: chain starts at null",
            vr.info.get("previous_report_sha256") == prev_sha,
        )
        if case_id is None:
            case_id = vr.info.get("case_id")
        res.add(f"v{n:04d}: same case id", vr.info.get("case_id") == case_id)
        prev_sha = sha
    res.info["head_report_sha256"] = prev_sha
    res.info["versions"] = len(vdirs)
    return res
