"""``logs.yaml`` (``tripline.logs-manifest/v1``): which hospital-exported logs to ingest and how to read them.

Example::

    schema: tripline.logs-manifest/v1
    defaults: {supplied_by: "Hospital IT (J. Mokoena)", received_at: "2026-09-15T08:00:00Z",
               legal_basis: "POPIA s22 investigation instructed by the Information Officer"}
    sources:
      - id: labsql-audit             # manifest-local label
        family: mssql_audit
        format: csv
        path: exports/labsql_audit.csv   # relative to this file; file or folder
        host: LABSQL01
        host_ips: [10.20.0.15]
        asset_id: AST-LABDB
        clock_offset_s: 0             # host clock minus true time (documented clock check)
        clock_uncertainty_s: 2
        coverage: {start: "2026-08-25T00:00:00Z", end: "2026-09-15T00:00:00Z",
                   databases: [LabDB01, LabDB02],   # what the audit specification covers (database sources)
                   missing: [{start: ..., end: ..., reason: "audit file rolled over"}]}
    corroborations:
      - id: COR-1
        kind: independently_confirmed_external_copy
        tables: [LabDB.dbo.Patients]
        evidence_ids: [SRC-009]       # registered sources (e.g. the leak sample) or manifest labels
        establishes: "An external copy contains records from LabDB.dbo.Patients."
        does_not_establish: "When or by which route the copy left the hospital."

Validation never echoes field values (they may be secrets or identifiers).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tripline_scope.core.errors import ConfigError
from tripline_scope.core.evidence import EXFILTRATION_EVIDENCE_KINDS
from tripline_scope.core.redact import scrub_text
from tripline_scope.core.timeutil import parse_utc

from .schema import FAMILIES, MANIFEST_SCHEMA
from .timenorm import ZoneSpec, parse_offset

FORMATS = {
    "mssql_audit": {"csv", "json", "jsonl"},
    "pg_log": {"csvlog", "jsonlog", "stderr"},
    "pgaudit": {"csvlog", "jsonlog", "stderr"},
    "iis": {"w3c"},
    "apache": {"combined", "common", "custom"},
    "nginx": {"combined", "common", "custom"},
    "win_security": {"evtx", "xml", "csv"},
    "entra_signin": {"json", "jsonl", "csv"},
    "vpn": {"csv", "jsonl", "json", "kv"},
    "firewall": {"csv", "jsonl", "json", "kv"},
    "proxy": {"csv", "jsonl", "json", "kv"},
    "generic": {"csv", "jsonl", "json", "kv"},
    "indicators": {"csv", "json", "jsonl"},
}
MAPPED_FAMILIES = {"vpn", "firewall", "proxy", "generic"}
# Formats whose specification fixes timestamps to UTC.
FORMAT_UTC = {"mssql_audit": "Z", "iis": "Z"}
_KNOWN_KEYS = {
    "id", "family", "format", "path", "timezone", "timezone_override", "clock_offset_s", "clock_uncertainty_s",
    "host", "host_ips", "asset_id", "supplied_by", "received_at", "legal_basis", "coverage", "mapping",
    "options", "source_id", "copy", "evidence_role", "label",
}


@dataclass
class SourceSpec:
    label: str
    family: str
    format: str
    path: Path
    zone: ZoneSpec
    host: str | None = None
    host_ips: list[str] = field(default_factory=list)
    asset_id: str | None = None
    supplied_by: str = ""
    received_at: str = ""
    legal_basis: str = ""
    coverage: dict = field(default_factory=dict)
    mapping: dict | None = None
    options: dict = field(default_factory=dict)
    source_id: str | None = None
    copy: bool = False
    evidence_role: str = "log"
    tz_note: str | None = None

    def describe(self) -> dict:
        """Manifest facts recorded with the source (no secrets; mapping kept for reproducibility)."""
        return {
            "label": self.label, "family": self.family, "format": self.format,
            "timezone": self.zone.zone, "tz_basis": self.zone.basis, "tz_note": self.tz_note,
            "clock_offset_s": self.zone.clock_offset_s, "clock_uncertainty_s": self.zone.clock_uncertainty_s,
            "host": self.host, "host_ips": list(self.host_ips), "asset_id": self.asset_id,
            "coverage": self.coverage, "mapping": self.mapping, "options": self.options,
        }


@dataclass
class Corroboration:
    corroboration_id: str
    kind: str
    tables: list[str]
    evidence_refs: list[str]
    establishes: str
    does_not_establish: str
    description: str
    observed_at: str | None
    path: Path | None
    evidence_role: str
    qualifies: bool

    def describe(self) -> dict:
        return {"corroboration_id": self.corroboration_id, "kind": self.kind, "tables": self.tables,
                "evidence_refs": self.evidence_refs, "establishes": self.establishes,
                "does_not_establish": self.does_not_establish, "description": self.description,
                "observed_at": self.observed_at, "qualifies_as_exfiltration_evidence": self.qualifies}


@dataclass
class Manifest:
    path: Path
    sources: list[SourceSpec]
    corroborations: list[Corroboration]
    raw: dict


def _err(where: str, msg: str) -> ConfigError:
    return ConfigError(f"logs manifest {where}: {msg}")


def _ts(value, where: str) -> str:
    try:
        return parse_utc(str(value)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as exc:
        raise _err(where, "must be an ISO-8601 timestamp with a time zone") from exc


def _coverage(cov, where: str) -> dict:
    if not cov:
        return {}
    if not isinstance(cov, dict):
        raise _err(where, "coverage must be a mapping")
    out = {"start": _ts(cov["start"], where + ".start") if cov.get("start") else None,
           "end": _ts(cov["end"], where + ".end") if cov.get("end") else None, "missing": []}
    dbs = cov.get("databases")
    if dbs is not None:
        if not isinstance(dbs, list) or not all(isinstance(x, str) and x for x in dbs):
            raise _err(where, "coverage.databases must be a list of database names (patterns allowed)")
        out["databases"] = [str(x)[:128] for x in dbs]
    for i, m in enumerate(cov.get("missing") or []):
        if not isinstance(m, dict) or not m.get("start") or not m.get("end"):
            raise _err(f"{where}.missing[{i}]", "needs start and end")
        out["missing"].append({"start": _ts(m["start"], f"{where}.missing[{i}].start"),
                               "end": _ts(m["end"], f"{where}.missing[{i}].end"),
                               "reason": scrub_text(str(m.get("reason") or "declared missing period"))[:200]})
    return out


def _zone(src: dict, family: str, where: str) -> tuple[ZoneSpec, str | None]:
    declared = src.get("timezone")
    override = bool(src.get("timezone_override"))
    abbrevs = {}
    for k, v in ((src.get("options") or {}).get("tz_abbreviations") or {}).items():
        off = parse_offset(str(v))
        if off is None:
            raise _err(where, "tz_abbreviations values must be fixed offsets such as +02:00")
        abbrevs[str(k).upper()] = off
    unc = src.get("clock_uncertainty_s")
    if unc is not None and (not isinstance(unc, int | float) or unc < 0):
        raise _err(where, "clock_uncertainty_s must be a non-negative number")
    offset = src.get("clock_offset_s", 0) or 0
    if not isinstance(offset, int | float):
        raise _err(where, "clock_offset_s must be a number (host clock minus true time, seconds)")
    note = None
    if family in FORMAT_UTC:
        fmt_zone = FORMAT_UTC[family]
        if declared and str(declared).strip().upper() not in ("Z", "UTC", "+00:00") and not override:
            note = ("declared zone ignored: this format records UTC; set timezone_override: true only if the "
                    "export was converted to local time")
            zone, basis = fmt_zone, "format"
        elif declared and override:
            zone, basis = str(declared), "manifest"
        else:
            zone, basis = fmt_zone, "format"
    elif declared:
        zone, basis = str(declared), "manifest"
    else:
        zone, basis = "unknown", "unknown"
    try:
        spec = ZoneSpec(zone=zone, basis=basis, clock_offset_s=float(offset),
                        clock_uncertainty_s=float(unc) if unc is not None else None, abbreviations=abbrevs)
    except ConfigError as exc:
        raise _err(where, str(exc)) from exc
    return spec, note


def load_manifest(path: Path | str) -> Manifest:
    path = Path(path).resolve()
    if not path.is_file():
        raise ConfigError("logs manifest not found")
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError("logs manifest is not valid YAML") from exc
    if doc.get("schema") != MANIFEST_SCHEMA:
        raise ConfigError(f"logs manifest schema must be {MANIFEST_SCHEMA}")
    defaults = doc.get("defaults") or {}
    base = path.parent
    sources: list[SourceSpec] = []
    labels: set[str] = set()
    for i, src in enumerate(doc.get("sources") or []):
        where = f"sources[{i}]"
        if not isinstance(src, dict):
            raise _err(where, "must be a mapping")
        unknown = set(src) - _KNOWN_KEYS
        if unknown:
            raise _err(where, f"unknown keys {sorted(unknown)}")
        family = src.get("family")
        if family not in FAMILIES:
            raise _err(where, f"family must be one of {list(FAMILIES)}")
        fmt = str(src.get("format") or "").lower()
        if fmt not in FORMATS[family]:
            raise _err(where, f"format for {family} must be one of {sorted(FORMATS[family])}")
        if not src.get("path"):
            raise _err(where, "path is required")
        p = Path(src["path"])
        p = (base / p).resolve() if not p.is_absolute() else p.resolve()
        if not p.exists():
            raise _err(where, "path does not exist")
        label = str(src.get("id") or src.get("label") or f"{family}-{i + 1}")[:60]
        if label in labels:
            raise _err(where, "duplicate id")
        labels.add(label)
        mapping = src.get("mapping")
        if family in MAPPED_FAMILIES:
            if not isinstance(mapping, dict) or not isinstance(mapping.get("fields"), dict):
                raise _err(where, f"{family} sources need a documented mapping with 'fields'")
            if "ts" not in mapping["fields"]:
                raise _err(where, "mapping.fields.ts (timestamp field) is required")
        if family == "apache" or family == "nginx":
            if fmt == "custom" and not (src.get("options") or {}).get("log_format"):
                raise _err(where, "custom web log format needs options.log_format")
        if family in ("pg_log", "pgaudit") and fmt == "stderr" and not (src.get("options") or {}).get("log_line_prefix"):
            raise _err(where, "stderr PostgreSQL logs need options.log_line_prefix (from postgresql.conf)")
        zone, note = _zone(src, family, where)
        merged = {k: src.get(k, defaults.get(k)) for k in ("supplied_by", "received_at", "legal_basis")}
        for k in ("supplied_by", "received_at", "legal_basis"):
            if not merged[k] or not str(merged[k]).strip():
                raise _err(where, f"{k} is required (chain of custody)")
        received = _ts(merged["received_at"], where + ".received_at")
        role = src.get("evidence_role") or ("reference_data" if family == "indicators" else "log")
        if role not in ("log", "reference_data"):
            raise _err(where, "evidence_role must be log or reference_data")
        sources.append(SourceSpec(
            label=label, family=family, format=fmt, path=p, zone=zone,
            host=str(src["host"])[:120] if src.get("host") else None,
            host_ips=[str(x) for x in (src.get("host_ips") or [])],
            asset_id=str(src["asset_id"]) if src.get("asset_id") else None,
            supplied_by=str(merged["supplied_by"])[:120], received_at=received,
            legal_basis=str(merged["legal_basis"])[:300], coverage=_coverage(src.get("coverage"), where + ".coverage"),
            mapping=mapping if isinstance(mapping, dict) else None, options=dict(src.get("options") or {}),
            source_id=str(src["source_id"]) if src.get("source_id") else None, copy=bool(src.get("copy")),
            evidence_role=role, tz_note=note,
        ))
    corrs: list[Corroboration] = []
    for i, c in enumerate(doc.get("corroborations") or []):
        where = f"corroborations[{i}]"
        if not isinstance(c, dict):
            raise _err(where, "must be a mapping")
        kind = str(c.get("kind") or "")
        refs = [str(x) for x in (c.get("evidence_ids") or [])]
        cpath = None
        if c.get("path"):
            cpath = Path(c["path"])
            cpath = (base / cpath).resolve() if not cpath.is_absolute() else cpath.resolve()
            if not cpath.exists():
                raise _err(where, "path does not exist")
        if not refs and cpath is None:
            raise _err(where, "a corroboration must cite evidence_ids or a path to the evidence")
        if not c.get("establishes"):
            raise _err(where, "state exactly what the evidence establishes ('establishes')")
        tables = [str(t) for t in (c.get("tables") or [])]
        if not tables:
            raise _err(where, "name the tables the evidence relates to")
        role = c.get("evidence_role") or ("leak_sample" if kind == "independently_confirmed_external_copy"
                                          else "reference_data")
        corrs.append(Corroboration(
            corroboration_id=str(c.get("id") or f"COR-{i + 1:03d}")[:40], kind=kind, tables=tables,
            evidence_refs=refs, establishes=scrub_text(str(c["establishes"]))[:500],
            does_not_establish=scrub_text(str(c.get("does_not_establish") or
                                              "Which individual records, when, or by which route."))[:500],
            description=scrub_text(str(c.get("description") or ""))[:300],
            observed_at=_ts(c["observed_at"], where + ".observed_at") if c.get("observed_at") else None,
            path=cpath, evidence_role=role, qualifies=kind in EXFILTRATION_EVIDENCE_KINDS,
        ))
    if not sources and not corrs:
        raise ConfigError("logs manifest lists no sources")
    return Manifest(path=path, sources=sources, corroborations=corrs, raw=doc)
