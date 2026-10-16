"""Case directories: layout, ``case.yaml``, team roles, legal hold and the case key.

Layout::

    <case>/case.yaml     case id, mode, incident window, team, sources (custody), declared gaps,
                         legal basis per source, column overrides, retention, legal hold
    <case>/state.json    open/closed status
    <case>/sources/      originals (read-only references or encrypted copies) + custody manifests
    <case>/work/         encrypted working data (*.tse)
    <case>/review/       encrypted review queue and decisions
    <case>/reports/      released, signed, versioned reports (no patient data) and drafts
    <case>/notify/       encrypted notification pack (exported only after approver release)
    <case>/audit.log     hash-chained audit log
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml

from . import crypto
from .audit import AuditLog
from .canonical import canonical_bytes, sha256_hex
from .errors import CaseClosed, ConfigError, IntegrityError, PermissionDenied
from .home import Home
from .timeutil import now_iso, parse_utc

CASE_SCHEMA = "tripline.case/v1"
CASE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-]{2,40}$")
SUBDIRS = ("sources", "work", "review", "reports", "notify")
MODES = ("incident", "readiness")


class Case:
    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()
        cfg = self.root / "case.yaml"
        if not cfg.is_file():
            raise ConfigError(f"not a case directory: {self.root}")
        self.config: dict = yaml.safe_load(cfg.read_text()) or {}
        if self.config.get("schema") != CASE_SCHEMA:
            raise ConfigError("unrecognised case.yaml")
        self._dek: bytes | None = None

    # ------------------------------------------------------------------ creation
    @classmethod
    def init(
        cls,
        root: Path | str,
        home: Home,
        *,
        case_id: str,
        mode: str,
        incident_start: str | None,
        incident_end: str | None,
        operators: list[str],
        reviewers: list[str],
        approvers: list[str],
        retain_reports_until: str | None = None,
        title: str = "",
    ) -> Case:
        root = Path(root)
        if not CASE_ID_RE.match(case_id):
            raise ConfigError("case id must be 3-41 chars of A-Z, 0-9 and '-' (no patient identifiers)")
        if mode not in MODES:
            raise ConfigError(f"mode must be one of {MODES}")
        if mode == "incident" and not (incident_start and incident_end):
            raise ConfigError("incident mode needs --incident-start and --incident-end")
        if incident_start and incident_end and parse_utc(incident_end) < parse_utc(incident_start):
            raise ConfigError("incident window ends before it starts")
        if root.exists() and any(root.iterdir()):
            raise ConfigError("case directory exists and is not empty")
        overlap = set(operators) & set(approvers)
        if overlap:
            raise PermissionDenied("separation of duties: the same person cannot be operator and approver on a case")
        if not approvers:
            raise ConfigError("a case needs at least one approver (Information Officer)")
        wrapped = home.wrapped_dek_path(case_id)
        if wrapped.exists():
            raise ConfigError("a case key for this case id already exists in the keystore")
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        for d in SUBDIRS:
            (root / d).mkdir()
            os.chmod(root / d, 0o700)
        dek = crypto.random_key()
        doc = crypto.wrap_dek(home.kek(), dek, case_id)
        doc["created_at"] = now_iso()
        wrapped.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(wrapped, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(canonical_bytes(doc))
        cfg = {
            "schema": CASE_SCHEMA,
            "case_id": case_id,
            "mode": mode,
            "title": title[:120],
            "installation_id": home.config["installation_id"],
            "created_at": now_iso(),
            "incident_window": {"start": incident_start, "end": incident_end},
            "team": {"operators": sorted(set(operators)), "reviewers": sorted(set(reviewers)),
                     "approvers": sorted(set(approvers))},
            "retention": {"retain_reports_until": retain_reports_until, "policy_ref": None},
            "legal_hold": {"active": False, "reason": None, "set_by": None, "set_at": None},
            "case_key": {"dek_id": doc["dek_id"], "kek_id": doc["kek_id"], "wrapped_key_file": str(wrapped)},
            "sources": [],
            "declared_gaps": [],
            "column_overrides": {},
            "relations": [],
        }
        (root / "case.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
        (root / "state.json").write_bytes(canonical_bytes({"status": "open", "closed_at": None}))
        return cls(root)

    # ------------------------------------------------------------------ basics
    @property
    def case_id(self) -> str:
        return self.config["case_id"]

    @property
    def mode(self) -> str:
        return self.config["mode"]

    def save(self) -> None:
        tmp = self.root / "case.yaml.tmp"
        tmp.write_text(yaml.safe_dump(self.config, sort_keys=False))
        os.replace(tmp, self.root / "case.yaml")

    def config_sha256(self) -> str:
        return sha256_hex(canonical_bytes(json.loads(json.dumps(self.config, default=str))))

    @property
    def audit(self) -> AuditLog:
        return AuditLog(self.root / "audit.log")

    def dir(self, name: str) -> Path:
        if name not in SUBDIRS:
            raise ValueError(name)
        return self.root / name

    @property
    def state(self) -> dict:
        p = self.root / "state.json"
        return json.loads(p.read_bytes()) if p.exists() else {"status": "open"}

    @property
    def is_closed(self) -> bool:
        return self.state.get("status") == "closed"

    def require_open(self) -> None:
        if self.is_closed:
            raise CaseClosed("case is closed; only verification and audit export are available")

    # ------------------------------------------------------------------ team
    def team(self) -> dict[str, list[str]]:
        return self.config["team"]

    def roles_of(self, username: str) -> set[str]:
        t = self.team()
        return {r for r, key in (("operator", "operators"), ("reviewer", "reviewers"), ("approver", "approvers"))
                if username in t.get(key, [])}

    def assign(self, username: str, role: str) -> None:
        key = {"operator": "operators", "reviewer": "reviewers", "approver": "approvers"}.get(role)
        if not key:
            raise ConfigError("role must be operator, reviewer or approver")
        roles = self.roles_of(username) | {role}
        if {"operator", "approver"} <= roles:
            raise PermissionDenied("separation of duties: the same person cannot be operator and approver on a case")
        if role == "approver" and username in self.audit.actors_with_role("operator", self.case_id):
            raise PermissionDenied("separation of duties: this person has already acted as operator on this case")
        if role == "operator" and username in self.audit.actors_with_role("approver", self.case_id):
            raise PermissionDenied("separation of duties: this person has already acted as approver on this case")
        lst = self.config["team"].setdefault(key, [])
        if username not in lst:
            lst.append(username)
            lst.sort()
        self.save()

    def unassign(self, username: str, role: str) -> None:
        key = {"operator": "operators", "reviewer": "reviewers", "approver": "approvers"}[role]
        lst = self.config["team"].get(key, [])
        if username in lst:
            lst.remove(username)
            self.save()

    # ------------------------------------------------------------------ keys
    def dek(self, home: Home) -> bytes:
        if self._dek is None:
            self.require_open()
            p = home.wrapped_dek_path(self.case_id)
            if not p.exists():
                raise IntegrityError("case key not found in the hospital keystore (destroyed or keystore not mounted)")
            doc = json.loads(p.read_bytes())
            dek = crypto.unwrap_dek(home.kek(), doc, self.case_id)
            if crypto.key_id(dek) != self.config["case_key"]["dek_id"]:
                raise IntegrityError("keystore holds a different key for this case id")
            self._dek = dek
        return self._dek

    def forget_key(self) -> None:
        self._dek = None

    # ------------------------------------------------------------------ legal hold / gaps
    @property
    def legal_hold(self) -> dict:
        return self.config.get("legal_hold") or {"active": False}

    def set_legal_hold(self, active: bool, reason: str | None, actor: str) -> None:
        self.config["legal_hold"] = {"active": bool(active), "reason": (reason or "")[:300] or None,
                                     "set_by": actor, "set_at": now_iso()}
        self.save()

    def add_gap(self, description: str, affects: list[str] | None = None) -> str:
        gaps = self.config.setdefault("declared_gaps", [])
        gid = f"GAP-{len(gaps) + 1:03d}"
        gaps.append({"gap_id": gid, "description": description[:500], "affects": affects or [], "declared_at": now_iso()})
        self.save()
        return gid

    def sources(self) -> list[dict]:
        return list(self.config.get("sources", []))

    def source(self, source_id: str) -> dict:
        for s in self.config.get("sources", []):
            if s["source_id"] == source_id:
                return s
        raise ConfigError(f"unknown source {source_id}")


def find_case(path: Path | str | None) -> Case:
    p = Path(path or os.environ.get("TSCOPE_CASE") or ".").resolve()
    return Case(p)
