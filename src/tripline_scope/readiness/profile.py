"""Hospital profile: the tuned configuration Module C needs, saved without any patient data.

A profile (``<home>/profiles/<name>.yaml``) holds:

* ``column_mappings`` — per source label and table: column name → discovery category (from ``case.yaml``
  ``column_overrides`` and, when present, discovery outputs ``work/discovery/<SRC>.json``: names and categories
  only, never sampled values);
* ``matching`` — blocking rules, block-size cap, bands (thresholds), guards, over-merge limits, comparison
  thresholds, training settings and first-name variant rules.

Saving refuses anything that looks like an identifier and any key outside this schema.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from tripline_scope.core.errors import ConfigError, IntegrityError
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.timeutil import now_iso
from tripline_scope.scope import config as C

PROFILE_SCHEMA = "tripline.profile/v1"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")
MATCHING_KEYS = ("blocking", "bands", "guards", "over_merge", "comparisons", "training", "name_variants", "identity",
                 "minor_age_years", "contact")
DISCOVERY_KEYS = ("name", "category", "standard_field", "purpose", "override")


def _path(home, name: str) -> Path:
    if not NAME_RE.match(name):
        raise ConfigError("profile name: lowercase letters, digits, '.', '_' or '-' (max 41)")
    return Path(home.profiles_dir) / f"{name}.yaml"


def collect(case, store) -> dict:
    cfg = C.load(case)
    mappings: dict[str, dict] = {}
    labels = {s["source_id"]: s.get("label") or s["source_id"] for s in case.sources()}
    for sid, tables in (case.config.get("column_overrides") or {}).items():
        dst = mappings.setdefault(labels.get(sid, sid), {})
        for table, cols in (tables or {}).items():
            dst.setdefault(str(table), {}).update({str(c): str(cat) for c, cat in (cols or {}).items()})
    for s in case.sources():
        rel = f"work/discovery/{s['source_id']}.json"
        if store is not None and store.exists(rel):
            doc = store.read_json(rel)
            for table in doc.get("tables", [doc]) if isinstance(doc, dict) else []:
                tname = str(table.get("table") or table.get("name") or "table")
                cols = table.get("columns") or []
                dst = mappings.setdefault(labels[s["source_id"]], {}).setdefault(tname, {})
                for col in cols:
                    if isinstance(col, dict) and col.get("name") and col.get("category"):
                        dst.setdefault(str(col["name"]), str(col["category"]))
    return {"schema": PROFILE_SCHEMA, "source_case": case.case_id, "saved_at": now_iso(),
            "column_mappings": mappings, "matching": {k: cfg[k] for k in MATCHING_KEYS if k in cfg},
            "config_sha256": C.config_sha256(cfg)}


def check(profile: dict) -> None:
    if set(profile) - {"schema", "source_case", "saved_at", "column_mappings", "matching", "config_sha256", "name"}:
        raise IntegrityError("profile contains unexpected keys")
    if set(profile.get("matching") or {}) - set(MATCHING_KEYS):
        raise IntegrityError("profile matching section contains unexpected keys")
    text = yaml.safe_dump(profile, sort_keys=True)
    if find_identifier_like(text):
        raise IntegrityError("profile contains identifier-like values; refusing to save")
    for tables in (profile.get("column_mappings") or {}).values():
        for cols in tables.values():
            for col, cat in cols.items():
                if len(col) > 128 or len(cat) > 64:
                    raise IntegrityError("profile column mapping entries must be names and categories only")


def save(home, case, store, name: str) -> Path:
    prof = collect(case, store)
    prof["name"] = name
    check(prof)
    p = _path(home, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(prof, sort_keys=True))
    p.chmod(0o600)
    return p


def load(home, name: str) -> dict:
    p = _path(home, name)
    if not p.exists():
        raise ConfigError("no such profile")
    prof = yaml.safe_load(p.read_text()) or {}
    if prof.get("schema") != PROFILE_SCHEMA:
        raise ConfigError("unrecognised profile")
    check(prof)
    return prof


def apply(home, case, name: str) -> dict:
    prof = load(home, name)
    cfg = C.validate(C.deep_merge(C.DEFAULTS, prof.get("matching") or {}))
    case.config["matching"] = {k: cfg[k] for k in MATCHING_KEYS if k in cfg}
    case.config.setdefault("profile", {})
    case.config["profile"] = {"name": name, "config_sha256": C.config_sha256(cfg)}
    case.save()
    return prof


def list_profiles(home) -> list[str]:
    d = Path(home.profiles_dir)
    return sorted(p.stem for p in d.glob("*.yaml")) if d.exists() else []
