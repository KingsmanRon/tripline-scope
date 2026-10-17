"""Versioned, signed, immutable reports (shared by every module).

Flow: a module builds a report body on top of :meth:`ReportStore.new_body` (which fixes ``case_id``, ``kind``,
``version`` and ``previous_report_sha256``), renders its PDF, and saves a **draft**. Drafts are not signed by
the hospital and are never sent anywhere. ``tscope release`` (approver sign-in required) turns a draft into
``reports/<kind>/v000N/`` with ``release.json`` (approval record + artefact hashes) signed by the hospital key;
a provider co-signature over ``report.json`` is carried from the draft if one was made. A released version is
never modified: a refinement is a new version whose ``previous_report_sha256`` links to the last one.

The on-disk format is defined by, and verified with, the stand-alone ``tscope_verify`` package.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from tscope_verify import formats as F
from tscope_verify.report import verify_chain, verify_version

from .auth import Identity
from .canonical import canonical_bytes, load_canonical, sha256_file, sha256_hex
from .case import Case
from .errors import ConfigError, IntegrityError, NotReady, PermissionDenied
from .keys import Signer
from .redact import find_identifier_like
from .timeutil import now_iso

KINDS = {"scope", "exposure", "paths", "readiness", "datamap", "drill", "investigation"}
_VDIR = re.compile(r"^v(\d{4,})$")
_ATTACH = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")

ReleaseHook = Callable[[Case, Path, Identity], None]
_release_hooks: dict[str, list[ReleaseHook]] = {}


def register_release_hook(kind: str, fn: ReleaseHook) -> None:
    _release_hooks.setdefault(kind, []).append(fn)


@dataclass
class Draft:
    kind: str
    draft_id: str
    path: Path
    version: int
    report_sha256: str


class ReportStore:
    def __init__(self, case: Case):
        self.case = case

    def kind_dir(self, kind: str) -> Path:
        if kind not in KINDS:
            raise ConfigError(f"unknown report kind {kind}")
        return self.case.dir("reports") / kind

    def versions(self, kind: str) -> list[tuple[int, Path]]:
        d = self.kind_dir(kind)
        if not d.exists():
            return []
        return sorted((int(m.group(1)), p) for p in d.iterdir() if p.is_dir() and (m := _VDIR.match(p.name)))

    def latest(self, kind: str) -> tuple[int, Path, str] | None:
        vs = self.versions(kind)
        if not vs:
            return None
        n, p = vs[-1]
        return n, p, sha256_file(p / F.REPORT_FILE)

    def load(self, kind: str, version: int | None = None) -> dict:
        vs = dict(self.versions(kind))
        if not vs:
            raise NotReady(f"no released {kind} report")
        p = vs[version if version is not None else max(vs)]
        return load_canonical((p / F.REPORT_FILE).read_bytes())

    def next_chain(self, kind: str) -> tuple[int, str | None]:
        last = self.latest(kind)
        return (1, None) if last is None else (last[0] + 1, last[2])

    def new_body(self, kind: str, **content) -> dict:
        version, prev = self.next_chain(kind)
        body = {
            "schema": F.REPORT_SCHEMA,
            "case_id": self.case.case_id,
            "kind": kind,
            "version": version,
            "previous_report_sha256": prev,
        }
        body.update(content)
        return body

    # ------------------------------------------------------------------ drafts
    def save_draft(
        self,
        kind: str,
        body: dict,
        *,
        pdf: bytes | None = None,
        attachments: dict[str, bytes] | None = None,
        provider: Signer | None = None,
        allow_identifier_like: bool = False,
    ) -> Draft:
        self.case.require_open()
        version, prev = self.next_chain(kind)
        for k, expected in (("schema", F.REPORT_SCHEMA), ("case_id", self.case.case_id), ("kind", kind),
                            ("version", version), ("previous_report_sha256", prev)):
            if body.get(k) != expected:
                raise IntegrityError(f"report body {k} does not match the current chain (rebuild the draft)")
        data = canonical_bytes(body)
        if not allow_identifier_like:
            kinds = find_identifier_like(data.decode("utf-8"))
            if kinds:
                raise IntegrityError(f"refusing to save a report containing identifier-like values ({sorted(set(kinds))})")
        sha = sha256_hex(data)
        draft_id = sha[:16]
        d = self.kind_dir(kind) / "drafts" / draft_id
        if d.exists():
            shutil.rmtree(d)
        (d / "attachments").mkdir(parents=True)
        (d / F.REPORT_FILE).write_bytes(data)
        if pdf is not None:
            (d / "report.pdf").write_bytes(pdf)
        for name, content in (attachments or {}).items():
            if not _ATTACH.match(name):
                raise ConfigError(f"bad attachment name {name!r}")
            (d / "attachments" / name).write_bytes(content)
        if provider is not None:
            entry = provider.signature_entry(F.REPORT_FILE, data)
            (d / "provider_signature.json").write_bytes(canonical_bytes(entry))
        return Draft(kind, draft_id, d, version, sha)

    def drafts(self, kind: str) -> list[Draft]:
        base = self.kind_dir(kind) / "drafts"
        out = []
        if base.exists():
            for d in sorted(base.iterdir()):
                if (d / F.REPORT_FILE).is_file():
                    body = load_canonical((d / F.REPORT_FILE).read_bytes())
                    out.append(Draft(kind, d.name, d, body["version"], sha256_file(d / F.REPORT_FILE)))
        return out

    def get_draft(self, kind: str, draft_id: str | None) -> Draft:
        ds = self.drafts(kind)
        if draft_id:
            ds = [d for d in ds if d.draft_id == draft_id]
        else:
            nxt, _ = self.next_chain(kind)
            ds = [d for d in ds if d.version == nxt]
            ds.sort(key=lambda d: d.path.stat().st_mtime)
            ds = ds[-1:]
        if not ds:
            raise NotReady(f"no current {kind} draft to release")
        return ds[0]

    # ------------------------------------------------------------------ release
    def release(
        self,
        kind: str,
        draft_id: str | None,
        *,
        approver: Identity,
        hospital: Signer,
        statement: str = "Approved for release by the Information Officer.",
    ) -> Path:
        self.case.require_open()
        if "approver" not in self.case.roles_of(approver.username):
            raise PermissionDenied("release requires a case approver")
        operators = sorted(self.case.audit.actors_with_role("operator", self.case.case_id)
                           | set(self.case.team().get("operators", [])))
        if approver.username in operators:
            raise PermissionDenied("separation of duties: the approver has acted as operator on this case")
        draft = self.get_draft(kind, draft_id)
        version, prev = self.next_chain(kind)
        data = (draft.path / F.REPORT_FILE).read_bytes()
        body = load_canonical(data)
        if body.get("version") != version or body.get("previous_report_sha256") != prev:
            raise IntegrityError("draft is stale: a newer version was released; rebuild the draft")
        final = self.kind_dir(kind) / F.version_dirname(version)
        tmp = self.kind_dir(kind) / f".{F.version_dirname(version)}.tmp"
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        (tmp / F.REPORT_FILE).write_bytes(data)
        artefacts = {}
        if (draft.path / "report.pdf").exists():
            shutil.copyfile(draft.path / "report.pdf", tmp / "report.pdf")
            artefacts["report.pdf"] = sha256_file(tmp / "report.pdf")
        att = draft.path / "attachments"
        if att.exists() and any(att.iterdir()):
            (tmp / "attachments").mkdir()
            for f in sorted(att.iterdir()):
                shutil.copyfile(f, tmp / "attachments" / f.name)
                artefacts[f"attachments/{f.name}"] = sha256_file(tmp / "attachments" / f.name)
        sigs = []
        provider_cosigned = False
        ps = draft.path / "provider_signature.json"
        if ps.exists():
            sigs.append(load_canonical(ps.read_bytes()))
            provider_cosigned = True
        release = {
            "schema": F.RELEASE_SCHEMA,
            "case_id": self.case.case_id,
            "kind": kind,
            "version": version,
            "report_sha256": sha256_hex(data),
            "previous_report_sha256": prev,
            "artefacts": artefacts,
            "approval": {
                "approver": approver.username,
                "approver_role": "approver",
                "approved_at": now_iso(),
                "authentication": approver.auth_method,
                "statement": statement[:300],
            },
            "operators": operators,
            "provider_cosigned": provider_cosigned,
        }
        rb = canonical_bytes(release)
        (tmp / F.RELEASE_FILE).write_bytes(rb)
        sigs.append(hospital.signature_entry(F.RELEASE_FILE, rb))
        (tmp / F.SIGNATURES_FILE).write_bytes(canonical_bytes({"schema": F.SIGNATURES_SCHEMA, "signatures": sigs}))
        if final.exists():
            raise IntegrityError("version directory already exists; refusing to overwrite")
        os.rename(tmp, final)
        for p in final.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o444)
        shutil.rmtree(draft.path, ignore_errors=True)
        for hook in _release_hooks.get(kind, []):
            hook(self.case, final, approver)
        return final

    # ------------------------------------------------------------------ verification
    def verify(self, kind: str, home, *, version: int | None = None):
        kw = dict(hospital_keys=home.trusted_hospital_keys(), provider_keys=home.trusted_provider_keys())
        if version is None:
            return verify_chain(self.kind_dir(kind), **kw)
        return verify_version(self.kind_dir(kind) / F.version_dirname(version), **kw)
