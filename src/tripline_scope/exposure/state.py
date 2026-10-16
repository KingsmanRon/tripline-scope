"""Mutable state of one exposure scan, shared by the detectors: findings, assets, ownership and cross-links."""

from __future__ import annotations

import re

from .coverage import Recorder
from .manifest import Database, Manifest, Root
from .model import Finding, Keys


def norm_principal(name: str | None) -> str:
    """Comparison key for an account: lower case, ``DOMAIN\\`` prefix removed. UPNs keep their domain."""
    if not name:
        return ""
    s = str(name).strip().lower()
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    return s


def principal_aliases(name: str | None) -> set[str]:
    k = norm_principal(name)
    if not k:
        return set()
    out = {k}
    if "@" in k:
        local = k.split("@", 1)[0]
        out.add(local)
        if "#ext#" in k:
            out.add(local.split("_", 1)[0])
    return out


def principal_location(name: str) -> dict:
    """Display form of an account for reports: an ``@domain`` suffix is split off into ``principal_domain`` so
    staff UPNs are not rendered as e-mail addresses."""
    s = str(name).strip()
    if "@" in s and "\\" not in s:
        local, _, dom = s.partition("@")
        return {"principal": local, "principal_domain": dom.lower()}
    return {"principal": s, "principal_domain": None}


def norm_host(name: str | None) -> str | None:
    if not name:
        return None
    s = str(name).strip().strip("[]").lower()
    s = re.sub(r"^(tcp:|np:|lpc:)", "", s)
    s = s.split(",", 1)[0].split("\\", 1)[0]
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s or None


class ScanState:
    def __init__(self, manifest: Manifest, keys: Keys, rec: Recorder):
        self.m = manifest
        self.keys = keys
        self.rec = rec
        self.findings: dict[str, Finding] = {}
        self.source_for: dict[str, str] = {}
        self.secret_index: dict[str, list[str]] = {}
        self.credential_principals: list[dict] = []
        self.principal_rights: list[dict] = []     # A2 -> A5: effective rights per (database, principal)
        self.scanned_paths: dict[str, set[str]] = {}
        self.root_complete: dict[str, bool] = {}
        self.decl = {(norm_principal(p.name), p.database): p for p in manifest.principals}

    # ------------------------------------------------------------------ assets and ownership
    def asset_ref(self, asset_id: str | None, fallback_name: str | None = None, kind: str | None = None) -> dict:
        a = self.m.assets.assets.get(asset_id) if asset_id else None
        return {
            "asset_id": asset_id,
            "name": fallback_name,
            "kind": a.kind if a else kind,
            "criticality": a.criticality if a else None,
            "patient_data": bool(asset_id and asset_id in self.m.patient_data_assets),
        }

    def root_asset(self, root: Root) -> dict:
        aid = root.asset or self.m.assets.resolve(root.id)
        return self.asset_ref(aid, root.id, "share" if root.kind == "share" else "host")

    def db_asset(self, db: Database) -> dict:
        aid = db.asset or self.m.assets.resolve(db.name) or self.m.assets.resolve(db.id)
        ref = self.asset_ref(aid, db.id, "database")
        if db.patient_data:
            ref["patient_data"] = True
        return ref

    def resolve_target(self, server: str | None, database: str | None) -> dict | None:
        """Asset a credential grants access to (declared databases first, then the asset map)."""
        host = norm_host(server)
        dbn = (database or "").strip().lower() or None
        for d in self.m.databases:
            names = {d.name.lower(), d.id.lower()}
            if dbn and dbn in names and (not host or not d.server or norm_host(d.server) == host):
                return self.db_asset(d)
        for cand in (dbn, f"{host}/{dbn}" if host and dbn else None, host):
            if cand:
                aid = self.m.assets.resolve(cand)
                if aid:
                    return self.asset_ref(aid, cand)
        if host:
            for d in self.m.databases:
                if d.server and norm_host(d.server) == host:
                    return self.db_asset(d)
        return None

    def is_patient_asset(self, ref: dict | None) -> bool:
        return bool(ref and ref.get("patient_data"))

    def owner_for(self, explicit: str | None, asset_id: str | None) -> dict:
        if explicit:
            return {"owner": explicit, "basis": "declared in the scan manifest"}
        a = self.m.assets.assets.get(asset_id) if asset_id else None
        if a and a.owner:
            return {"owner": a.owner, "basis": "asset map"}
        return {"owner": self.m.owner, "basis": "scan owner (no specific owner declared)"}

    # ------------------------------------------------------------------ findings
    def add(self, f: Finding) -> Finding:
        f.finding_id = self.keys.finding_id([f.control_id, f.rule_id, *f.id_parts])
        cur = self.findings.get(f.finding_id)
        if cur is None:
            self.findings[f.finding_id] = f
            return f
        cur.evidence_ids = sorted(set(cur.evidence_ids) | set(f.evidence_ids))
        cur.source_ids = sorted(set(cur.source_ids) | set(f.source_ids))
        occ = cur.details.get("occurrences", 1) + f.details.get("occurrences", 1)
        cur.details["occurrences"] = occ
        lines = cur.details.get("lines")
        if lines is not None and f.location.get("line") and len(lines) < 10:
            lines.append(f.location["line"])
        return cur

    def evidence(self, unit: str, *parts) -> str:
        return self.keys.evidence_id([self.source_for.get(unit), unit, *parts])
