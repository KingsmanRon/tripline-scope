"""Scan manifest ``tripline.exposure-manifest/v1``: the authorised boundary of an exposure scan.

Everything the scan may read is declared here: read-only snapshot roots, database catalogue exports (or a
metadata-only read-only login), identity / sign-in / MFA exports and the supplier register, with ownership,
legal basis, an observation window and a data-processing budget. Nothing outside these paths is opened.
Relative paths resolve against the manifest's directory. Error messages never echo file contents.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tripline_scope.core.assets import AssetMap
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.timeutil import parse_utc

MANIFEST_SCHEMA = "tripline.exposure-manifest/v1"
ROOT_KINDS = ("web_root", "config", "share", "scripts", "repository")
DB_MODES = ("catalog_export", "live_metadata")
SUPPORTED_ENGINES = ("mssql", "postgres")
PRINCIPAL_TYPES = ("application", "service", "human", "dba", "supplier", "shared", "system")
ACCESS_LEVELS = ("none", "read", "write", "admin")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,40}$")

DEFAULT_BUDGET = {
    "max_files": 200_000,
    "max_total_bytes": 20 << 30,
    "max_file_bytes": 64 << 20,
    "max_seconds": 4 * 3600,
    "archive_max_depth": 2,
    "archive_max_members": 2_000,
    "archive_max_ratio": 100,
    "archive_max_total_bytes": 256 << 20,
    "max_rows_per_file": 1_000_000,
    "max_rows_inspected": 50_000,
}
_UNITS = {"": 1, "b": 1, "kb": 1000, "kib": 1 << 10, "mb": 1000**2, "mib": 1 << 20, "gb": 1000**3, "gib": 1 << 30,
          "tb": 1000**4, "tib": 1 << 40}


def parse_size(v) -> int:
    if isinstance(v, bool):
        raise ConfigError("budget sizes must be numbers or strings such as '64MiB'")
    if isinstance(v, int):
        return v
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([A-Za-z]*)\s*", str(v))
    if not m or m.group(2).lower() not in _UNITS:
        raise ConfigError("budget sizes must be numbers or strings such as '64MiB'")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


@dataclass
class Root:
    id: str
    path: Path
    kind: str
    asset: str | None = None
    owner: str | None = None
    exclusions: list[str] = field(default_factory=list)
    declared_path: str = ""


@dataclass
class Database:
    id: str
    engine: str
    name: str
    mode: str
    export: Path | None = None
    asset: str | None = None
    owner: str | None = None
    patient_data: bool | None = None
    server: str | None = None
    live: dict = field(default_factory=dict)
    declared_path: str = ""


@dataclass
class PrincipalDecl:
    name: str
    database: str | None
    type: str | None
    function: str | None
    expected_access: str | None


@dataclass
class Manifest:
    path: Path
    base_dir: Path
    raw: dict
    sha256: str
    scan_id: str
    owner: str
    legal_basis: str
    supplied_by: str
    received_at: str
    as_of: dt.datetime
    budget: dict
    roots: list[Root]
    databases: list[Database]
    identity: dict[str, Path]
    identity_asset: str | None
    signin_coverage: dict | None
    observation_window: dict | None
    exclusions: list[str]
    assets: AssetMap
    assets_path: Path | None
    assets_sha256: str | None
    patient_data_assets: set[str]
    accepted_risks: list[dict]
    accepted_risks_sha256: str | None
    principals: list[PrincipalDecl]
    stale_after_days: int
    suppress_test_fixtures: bool
    hospital_domains: list[str]

    def normalised(self) -> dict:
        """Manifest content as declared (relative paths kept), for the configuration hash."""
        return self.raw

    def input_paths(self) -> list[Path]:
        paths = [r.path for r in self.roots]
        paths += [d.export for d in self.databases if d.export]
        paths += list(self.identity.values())
        for p in (self.assets_path,):
            if p:
                paths.append(p)
        return paths


def _req(doc: dict, key: str, what: str = "manifest") -> str:
    v = doc.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        raise ConfigError(f"{what} needs '{key}'")
    return str(v)


def _path(base: Path, rel, what: str, *, directory: bool | None = None) -> Path:
    if not rel or not isinstance(rel, str):
        raise ConfigError(f"{what}: path missing")
    p = Path(rel)
    p = (base / p) if not p.is_absolute() else p
    p = Path(p).resolve()
    if not p.exists():
        raise ConfigError(f"{what}: declared path does not exist")
    if directory is True and not p.is_dir():
        raise ConfigError(f"{what}: declared path is not a directory")
    if directory is False and not p.is_file():
        raise ConfigError(f"{what}: declared path is not a file")
    return p


def _date_or_dt(v, what: str) -> dt.datetime:
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.UTC)
    if isinstance(v, dt.date):
        return dt.datetime(v.year, v.month, v.day, tzinfo=dt.UTC)
    try:
        s = str(v)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
            s += "T00:00:00Z"
        return parse_utc(s)
    except (ValueError, TypeError):
        raise ConfigError(f"{what}: not an ISO-8601 timestamp with time zone") from None


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _yaml_safe(doc):
    """Make YAML-native dates JSON-serialisable for hashing."""
    if isinstance(doc, dict):
        return {str(k): _yaml_safe(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_yaml_safe(v) for v in doc]
    if isinstance(doc, dt.datetime):
        return _iso(doc if doc.tzinfo else doc.replace(tzinfo=dt.UTC))
    if isinstance(doc, dt.date):
        return doc.isoformat()
    return doc


def load_manifest(path: Path | str) -> Manifest:
    path = Path(path).resolve()
    if not path.is_file():
        raise ConfigError("manifest file not found")
    data = path.read_bytes()
    try:
        doc = yaml.safe_load(data)
    except yaml.YAMLError:
        raise ConfigError("manifest is not valid YAML") from None
    if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA:
        raise ConfigError(f"manifest schema must be {MANIFEST_SCHEMA}")
    doc = _yaml_safe(doc)
    base = path.parent
    owner = _req(doc, "owner")[:200]
    legal_basis = _req(doc, "legal_basis")[:300]
    supplied_by = str(doc.get("supplied_by") or owner)[:120]
    received_at = _iso(_date_or_dt(_req(doc, "received_at"), "received_at"))
    as_of = _date_or_dt(doc.get("snapshot_taken_at") or received_at, "snapshot_taken_at")
    if "budget" not in doc or not isinstance(doc["budget"], dict):
        raise ConfigError("manifest needs a 'budget' (maximum data-processing budget)")
    budget = dict(DEFAULT_BUDGET)
    for k, v in doc["budget"].items():
        if k not in DEFAULT_BUDGET:
            raise ConfigError(f"unknown budget key '{k}'")
        budget[k] = parse_size(v) if k.endswith("bytes") else int(v)
        if budget[k] <= 0 and k != "archive_max_depth":
            raise ConfigError(f"budget '{k}' must be positive")
    ids: set[str] = set()

    def _uid(v, what):
        v = str(v or "")
        if not _ID.match(v):
            raise ConfigError(f"{what}: id must be 1-41 chars of letters, digits, '_', '.', '-'")
        if v in ids:
            raise ConfigError(f"{what}: duplicate id")
        ids.add(v)
        return v

    excl = [str(x) for x in (doc.get("exclusions") or [])]
    roots = []
    for i, r in enumerate(doc.get("roots") or []):
        what = f"roots[{i}]"
        kind = str(r.get("kind") or "")
        if kind not in ROOT_KINDS:
            raise ConfigError(f"{what}: kind must be one of {ROOT_KINDS}")
        roots.append(Root(id=_uid(r.get("id"), what), path=_path(base, r.get("path"), what, directory=True), kind=kind,
                          asset=r.get("asset"), owner=(str(r["owner"])[:120] if r.get("owner") else None),
                          exclusions=[str(x) for x in (r.get("exclusions") or [])], declared_path=str(r.get("path"))))
    dbs = []
    for i, d in enumerate(doc.get("databases") or []):
        what = f"databases[{i}]"
        mode = str(d.get("mode") or "catalog_export")
        if mode not in DB_MODES:
            raise ConfigError(f"{what}: mode must be one of {DB_MODES}")
        engine = str(d.get("engine") or "").lower()
        if not engine:
            raise ConfigError(f"{what}: engine missing")
        pd = d.get("patient_data")
        db = Database(id=_uid(d.get("id"), what), engine=engine, name=str(d.get("name") or d.get("id")), mode=mode,
                      asset=d.get("asset"), owner=(str(d["owner"])[:120] if d.get("owner") else None),
                      patient_data=None if pd is None else bool(pd), server=d.get("server"),
                      declared_path=str(d.get("export") or ""))
        if mode == "catalog_export":
            db.export = _path(base, d.get("export"), what)
        else:
            live = d.get("live") or {}
            for k in ("host", "port", "user", "password_env"):
                if not live.get(k):
                    raise ConfigError(f"{what}: live_metadata needs live.{k}")
            db.live = {"host": str(live["host"]), "port": int(live["port"]), "user": str(live["user"]),
                       "password_env": str(live["password_env"]), "database": str(live.get("database") or db.name),
                       "timeout_s": int(live.get("timeout_s") or 30), "max_rows": int(live.get("max_rows") or 200_000)}
        dbs.append(db)
    ident: dict[str, Path] = {}
    idoc = doc.get("identity") or {}
    for key in ("directory_export", "signin_export", "mfa_export", "supplier_register"):
        if idoc.get(key):
            ident[key] = _path(base, idoc[key], f"identity.{key}", directory=False)
    signin_cov = None
    if idoc.get("signin_coverage"):
        c = idoc["signin_coverage"]
        signin_cov = {"start": _iso(_date_or_dt(c.get("start"), "identity.signin_coverage.start")),
                      "end": _iso(_date_or_dt(c.get("end"), "identity.signin_coverage.end"))}
    window = None
    if doc.get("observation_window"):
        w = doc["observation_window"]
        s, e = _date_or_dt(w.get("start"), "observation_window.start"), _date_or_dt(w.get("end"), "observation_window.end")
        if e <= s:
            raise ConfigError("observation_window ends before it starts")
        window = {"start": _iso(s), "end": _iso(e)}
    if not (roots or dbs or ident):
        raise ConfigError("manifest declares no inputs (roots, databases or identity exports)")
    assets_path = _path(base, doc["assets"], "assets", directory=False) if doc.get("assets") else None
    assets = AssetMap.load(assets_path) if assets_path else AssetMap([])
    known_assets = set(assets.assets)
    for obj, what in [(r, f"root {r.id}") for r in roots] + [(d, f"database {d.id}") for d in dbs]:
        if obj.asset and obj.asset not in known_assets:
            resolved = assets.resolve(obj.asset)
            if not resolved:
                raise ConfigError(f"{what}: asset is not in the asset map")
            obj.asset = resolved
    pda = {str(a) for a in (doc.get("patient_data_assets") or [])}
    unknown = pda - known_assets
    if unknown:
        raise ConfigError("patient_data_assets lists assets that are not in the asset map")
    for d in dbs:
        if d.patient_data and d.asset:
            pda.add(d.asset)
    accepted, accepted_sha = [], None
    if doc.get("accepted_risks"):
        ap = _path(base, doc["accepted_risks"], "accepted_risks", directory=False)
        raw = ap.read_bytes()
        accepted_sha = hashlib.sha256(raw).hexdigest()
        try:
            adoc = _yaml_safe(yaml.safe_load(raw) or {})
        except yaml.YAMLError:
            raise ConfigError("accepted_risks register is not valid YAML") from None
        for i, a in enumerate(adoc.get("accepted_risks") or []):
            if not a.get("finding_id") or not a.get("accepted_by") or not a.get("reason"):
                raise ConfigError(f"accepted_risks[{i}] needs finding_id, accepted_by and reason")
            accepted.append({"finding_id": str(a["finding_id"]), "accepted_by": str(a["accepted_by"])[:120],
                             "reason": str(a["reason"])[:300],
                             "expires": str(a["expires"])[:10] if a.get("expires") else None,
                             "reference": str(a.get("reference") or "")[:120] or None})
    principals = []
    for i, p in enumerate(doc.get("principals") or []):
        what = f"principals[{i}]"
        t = p.get("type")
        if t is not None and t not in PRINCIPAL_TYPES:
            raise ConfigError(f"{what}: type must be one of {PRINCIPAL_TYPES}")
        ea = p.get("expected_access")
        if ea is not None and ea not in ACCESS_LEVELS:
            raise ConfigError(f"{what}: expected_access must be one of {ACCESS_LEVELS}")
        principals.append(PrincipalDecl(name=_req(p, "name", what), database=p.get("database"), type=t,
                                        function=(str(p["function"])[:120] if p.get("function") else None),
                                        expected_access=ea))
    return Manifest(
        path=path, base_dir=base, raw=doc, sha256=hashlib.sha256(data).hexdigest(),
        scan_id=str(doc.get("scan_id") or "exposure-scan")[:60], owner=owner, legal_basis=legal_basis,
        supplied_by=supplied_by, received_at=received_at, as_of=as_of, budget=budget, roots=roots, databases=dbs,
        identity=ident, identity_asset=idoc.get("asset"), signin_coverage=signin_cov, observation_window=window,
        exclusions=excl, assets=assets, assets_path=assets_path,
        assets_sha256=hashlib.sha256(assets_path.read_bytes()).hexdigest() if assets_path else None,
        patient_data_assets=pda, accepted_risks=accepted, accepted_risks_sha256=accepted_sha, principals=principals,
        stale_after_days=int(doc.get("stale_after_days") or 90),
        suppress_test_fixtures=bool(doc.get("suppress_test_fixtures", True)),
        hospital_domains=[str(x).lower() for x in (doc.get("hospital_domains") or [])],
    )


def config_sha256(m: Manifest, detector_config: dict) -> str:
    """Hash of the effective scan configuration: the declared manifest, the asset map, the accepted-risk register
    and the detector configuration (version, thresholds)."""
    return sha256_hex(canonical_bytes({"manifest": m.normalised(), "assets_sha256": m.assets_sha256,
                                       "accepted_risks_sha256": m.accepted_risks_sha256, "detectors": detector_config}))
