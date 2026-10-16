"""A2 (excessive privileges) and A4 (risky database configuration) from read-only catalogue exports.

Inputs are the result sets of :mod:`catalog_sql` (a JSON export or a directory of ``<query>.csv``), or the same
structure collected through a metadata-only read-only login (:mod:`collect`). Effective rights are derived
through role membership (nested roles, PostgreSQL inheritance, Windows-group logins expanded with the directory
export) and explicit grants with DENY taken into account. Where grants or memberships are missing from the export,
findings are labelled ``inference`` with lower confidence and the gap is listed. Each engine check is recorded as
``assessed``, ``not assessed`` (unsupported engine/option or query not exported) or ``unavailable`` (query failed,
e.g. permission denied); results are never invented.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from tripline_scope.core.redact import scrub_text

from .catalog_sql import CATALOG_SCHEMA
from .datacopies import PERSON_CATEGORIES, header_categories
from .manifest import Database
from .model import Finding
from .state import ScanState, norm_principal, principal_location

DETECTOR = "exposure.catalog/0.1.0"
LEVEL_ORDER = {"none": 0, "read": 1, "write": 2, "admin": 3}
_SYSTEM = {"sa", "postgres", "rdsadmin", "azure_superuser", "cloudsqladmin", "dbo", "guest", "information_schema", "sys", "public", "##ms_policyeventprocessinglogin##",
           "##ms_policytsqlexecutionlogin##", "##ms_agentsigningcertificate##", "nt authority\\system",
           "nt service\\mssqlserver", "nt service\\sqlserveragent", "nt service\\sqltelemetry", "nt service\\sqlwriter",
           "nt service\\winmgmt", "builtin\\administrators", "distributor_admin"}
_APP_TOKENS = {"app", "application", "api", "web", "iis", "apppool", "lis", "his", "ris", "pacs", "portal", "integration",
               "interface", "hl7", "fhir", "svc", "service", "sync", "etl", "batch", "job", "report", "reporting", "bi",
               "monitor", "monitoring", "backup", "audit", "analytics", "replication", "agent", "sched", "scheduler"}
_READISH = {"report", "reporting", "readonly", "ro", "reader", "bi", "monitor", "monitoring", "backup", "audit",
            "analytics", "dashboard", "query", "export"}
_SHARED = {"reception", "nurse", "nurses", "ward", "shared", "generic", "admin", "administrator", "temp", "test",
           "frontdesk", "front", "desk", "pharmacy", "casualty", "helpdesk", "lab", "clinic", "station", "doctors",
           "theatre", "users", "staff", "team"}
_SPLIT = re.compile(r"[^a-z0-9]+")


class Unrecognised(Exception):
    """An exported option has a value this version cannot interpret: the check is 'not assessed'."""


def _b(v) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "t", "yes", "y", "on"):
        return True
    if s in ("0", "false", "f", "no", "n", "off"):
        return False
    return None


def _s(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


# ------------------------------------------------------------------------------------------ loading
@dataclass
class Catalog:
    engine: str
    server: str | None
    database: str | None
    queries: dict[str, list[dict]]
    errors: dict[str, str] = field(default_factory=dict)
    truncated: set[str] = field(default_factory=set)

    def has(self, name: str) -> bool:
        return name in self.queries

    def rows(self, name: str) -> list[dict]:
        return self.queries.get(name) or []


def _norm_rows(rows) -> list[dict]:
    if isinstance(rows, dict) and "columns" in rows:
        cols = [str(c).lower() for c in rows["columns"]]
        return [{c: v for c, v in zip(cols, r, strict=False)} for r in rows.get("rows", [])]
    if isinstance(rows, list):
        return [{str(k).lower(): v for k, v in r.items()} for r in rows if isinstance(r, dict)]
    raise ValueError("bad rows")


def catalog_from_doc(doc: dict) -> Catalog:
    if not isinstance(doc, dict) or not isinstance(doc.get("queries", {}), dict):
        raise ValueError("not a catalogue export")
    if doc.get("schema") not in (None, CATALOG_SCHEMA):
        raise ValueError("unknown catalogue schema")
    engine = str(doc.get("engine") or "").lower()
    q = {str(k).lower(): _norm_rows(v) for k, v in (doc.get("queries") or {}).items()}
    errs = {str(k).lower(): scrub_text(str(v))[:160] for k, v in (doc.get("errors") or {}).items()}
    return Catalog(engine, _s(doc.get("server")), _s(doc.get("database")), q, errs,
                   {str(x).lower() for x in doc.get("truncated") or []})


def load_catalog(path: Path, max_bytes: int) -> Catalog:
    """Read a catalogue export (JSON file or directory of CSVs). Raises ValueError/OSError on malformed input."""
    if path.is_dir():
        meta: dict = {}
        for mname in ("_meta.json", "meta.json"):
            mp = path / mname
            if mp.is_file():
                meta = json.loads(mp.read_bytes()[:max_bytes])
        queries = {}
        for p in sorted(path.iterdir()):
            if p.suffix.lower() != ".csv" or p.is_symlink() or not p.is_file():
                continue
            if p.stat().st_size > max_bytes:
                raise ValueError("catalogue file exceeds the per-file budget")
            text = p.read_bytes().decode("utf-8-sig")
            rows = list(csv.DictReader(io.StringIO(text)))
            queries[p.stem.lower()] = [{str(k).strip().lower(): (v if v != "" else None) for k, v in r.items() if k}
                                       for r in rows]
        doc = {"schema": meta.get("schema"), "engine": meta.get("engine"), "server": meta.get("server"),
               "database": meta.get("database"), "queries": queries, "errors": meta.get("errors") or {},
               "truncated": meta.get("truncated") or []}
        return catalog_from_doc(doc)
    if path.stat().st_size > max_bytes:
        raise ValueError("catalogue file exceeds the per-file budget")
    return catalog_from_doc(json.loads(path.read_bytes()))


# ------------------------------------------------------------------------------------------ principal typing
def classify_principal(state: ScanState, name: str, db: Database, identity) -> tuple[str, str, object]:
    key = norm_principal(name)
    decl = state.decl.get((key, db.id)) or state.decl.get((key, None))
    if decl and decl.type:
        return decl.type, "declared in the scan manifest", decl
    if identity is not None and identity.is_supplier(name):
        return "supplier", identity.supplier_basis(name), decl
    if key in _SYSTEM or key.startswith("##") or key.startswith("nt service\\") or name.lower().startswith("nt service\\"):
        return "system", "built-in principal", decl
    acct = identity.account(name) if identity is not None else None
    if acct is not None and acct.account_type:
        t = acct.account_type
        mapped = {"service": "service", "application": "application", "shared": "shared", "user": "human",
                  "human": "human", "admin": "dba", "dba": "dba", "guest": "supplier", "external": "supplier",
                  "supplier": "supplier", "vendor": "supplier", "contractor": "supplier"}.get(t)
        if mapped:
            return mapped, "directory export account type", decl
    toks = set(_SPLIT.split(key)) - {""}
    if toks & _APP_TOKENS:
        return ("service" if toks & _READISH or toks & {"svc", "service", "etl", "batch", "job", "sync"} else
                "application"), "inferred from the principal name", decl
    if toks and all(re.sub(r"\d+$", "", t) in _SHARED or t.isdigit() for t in toks):
        return "shared", "inferred from a generic principal name", decl
    return "unknown", "function not declared", decl


def _readish(name: str) -> bool:
    return bool(set(_SPLIT.split(norm_principal(name))) & _READISH)


# ------------------------------------------------------------------------------------------ helpers
def _closure(edges: dict[str, set[str]], start: str) -> set[str]:
    seen, todo = set(), [start]
    while todo:
        x = todo.pop()
        for r in edges.get(x, ()):
            if r not in seen:
                seen.add(r)
                todo.append(r)
    return seen


def patient_tables(cat: Catalog, dbname: str | None) -> tuple[set[tuple[str, str]], bool]:
    """(schema, table) pairs whose column names identify people (names, ID numbers, dates of birth, contact
    details, patient keys); clinical lookup tables without a person link do not count. The second value says
    whether the column inventory was available at all."""
    if not cat.has("columns"):
        return set(), False
    cols: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in cat.rows("columns"):
        if dbname and r.get("database_name") and str(r["database_name"]).lower() != dbname:
            continue
        cols[(str(r.get("schema_name") or "").lower(), str(r.get("table_name") or "").lower())] |= header_categories(
            str(r.get("column_name") or ""))
    out = {k for k, cats in cols.items() if cats & PERSON_CATEGORIES}
    return out, True


@dataclass
class Right:
    principal: str
    key: str
    ptype: str
    ptype_basis: str
    decl: object
    level: str = "none"
    via: list[str] = field(default_factory=list)
    basis: str = "observation"
    uncertain: list[str] = field(default_factory=list)
    enabled: bool | None = None
    login_type: str | None = None
    has_login: bool = True
    capabilities: set[str] = field(default_factory=set)
    via_group: str | None = None

    def raise_to(self, level: str, why: str) -> None:
        if LEVEL_ORDER[level] > LEVEL_ORDER[self.level]:
            self.level = level
        if why not in self.via and len(self.via) < 12:
            self.via.append(why)


# ------------------------------------------------------------------------------------------ analysis driver
class DbAnalysis:
    def __init__(self, state: ScanState, db: Database, cat: Catalog, identity):
        self.state, self.db, self.cat, self.identity = state, db, cat, identity
        self.dbname = (cat.database or db.name).lower()
        self.unit = f"db:{db.id}"
        self.asset = state.db_asset(db)
        self.ptables, self.has_columns = patient_tables(cat, self.dbname)
        declared = db.patient_data
        if declared is None:
            self.patient = bool(self.ptables) or self.asset.get("patient_data")
            self.patient_basis = ("column names indicate personal/clinical data" if self.ptables else
                                  "asset declared as holding patient data" if self.patient else "not determined")
        else:
            self.patient = declared
            self.patient_basis = "declared in the scan manifest"
        if self.patient:
            self.asset["patient_data"] = True
        self.rights: list[Right] = []
        self.src = state.source_for.get(self.unit)

    # -------------------------------------------------------------- coverage-aware check runner
    def check(self, name: str, controls: str, needs: list[str], fn, optional: list[str] | None = None) -> None:
        unit = f"{self.unit}:{name}"
        missing = [q for q in needs if not self.cat.has(q) and q not in self.cat.errors]
        failed = [q for q in needs if q in self.cat.errors]
        if failed:
            self.state.rec.unavail(controls, unit, f"catalogue query {failed[0]} failed: {self.cat.errors[failed[0]]}")
            self.state.rec.missing_evidence(controls, unit, f"query {failed[0]} could not be read (inaccessible object)")
            return
        if missing:
            self.state.rec.not_assess(controls, unit, f"catalogue export lacks {', '.join(missing)}")
            self.state.rec.missing_evidence(controls, unit, f"catalogue export lacks {', '.join(missing)}")
            return
        try:
            detail = fn()
        except Unrecognised as exc:
            self.state.rec.not_assess(controls, unit, f"unrecognised value in export ({exc}); not interpreted")
            return
        for q in optional or []:
            if q in self.cat.errors:
                self.state.rec.missing_evidence(controls, unit, f"optional query {q} failed; check is partial")
            elif not self.cat.has(q):
                self.state.rec.missing_evidence(controls, unit, f"optional query {q} not exported; check is partial")
        self.state.rec.assess(controls, unit, detail)

    # -------------------------------------------------------------- finding helpers
    def location(self, **kw) -> dict:
        loc = {"type": "database", "database": self.db.id, "engine": self.db.engine, "catalog_name": self.db.name}
        principal = kw.pop("principal", None)
        if principal:
            loc.update(principal_location(principal))
        loc.update({k: v for k, v in kw.items() if v is not None})
        parts = [f"{self.db.id} ({self.db.engine})"]
        if loc.get("principal"):
            parts.append("principal " + loc["principal"] + (f" [{loc['principal_domain']}]" if loc.get("principal_domain") else ""))
        if loc.get("object"):
            parts.append(str(loc["object"]))
        loc["display"] = scrub_text(" ".join(parts))[:300]
        return loc

    def add(self, *, control: str, rule: str, title: str, impact: str, likelihood: str, rationale: dict, loc: dict,
            id_key: list, basis: str, confidence: float, reason: str, fix: str, check: str, caveats=None,
            details=None, evidence: list | None = None) -> Finding:
        unit = f"{self.unit}:{check}"
        f = Finding(control_id=control, rule_id=rule, title=title, impact=impact, likelihood=likelihood,
                    rationale=rationale, asset=dict(self.asset), location=loc, coverage_unit=unit,
                    id_parts=[self.db.id, *id_key], basis=basis, confidence=confidence, confidence_reason=reason,
                    fix_action=fix, source_ids=[self.src] if self.src else [],
                    evidence_ids=[self.state.evidence(self.unit, *(evidence or id_key))], caveats=list(caveats or []),
                    details=dict(details or {}),
                    ownership=self.state.owner_for(self.db.owner, self.asset.get("asset_id")), detector=DETECTOR)
        return self.state.add(f)

    # -------------------------------------------------------------- A2 (shared by engines)
    def privilege_findings(self) -> None:
        if self.db.patient_data is False:
            return
        patient_note = self.patient_basis
        unknown_patient = not self.patient
        for r in self.rights:
            if r.ptype in ("system", "supplier", "dba", "human") or r.level == "none":
                continue
            if r.enabled is False:
                continue
            decl_access = getattr(r.decl, "expected_access", None)
            basis = r.basis if r.ptype_basis.startswith(("declared", "directory")) else "inference"
            conf = 0.9 if basis == "observation" else 0.65
            conf -= 0.15 if r.uncertain else 0
            conf -= 0.1 if unknown_patient else 0
            caveats = list(r.uncertain)
            if unknown_patient:
                caveats.append("Whether this database holds patient data was not determined (no column inventory "
                               "or declaration).")
            if r.ptype_basis.startswith("inferred"):
                caveats.append("Principal type inferred from its name; declare it in the manifest to confirm.")
            details = {"effective_access": r.level, "derived_via": r.via, "principal_type": r.ptype,
                       "principal_type_basis": r.ptype_basis, "declared_function": getattr(r.decl, "function", None),
                       "declared_expected_access": decl_access, "patient_data_basis": patient_note,
                       "via_group": r.via_group}
            loc = self.location(principal=r.principal)
            if r.level == "admin" and r.ptype in ("application", "service") and decl_access != "admin":
                self.add(control="A2", rule="A2.app-admin-rights",
                         title="Application or service principal holds owner/admin rights on a patient database",
                         impact="high", likelihood="medium",
                         rationale={"impact": "full control of the database, including every patient record, its "
                                              "audit settings and grants",
                                    "likelihood": "application credentials are stored in configuration on servers "
                                                  "and are a common route to the database"},
                         loc=loc, id_key=["admin", r.key], basis=basis, confidence=max(conf, 0.3),
                         reason="derived from role membership and grants in the catalogue export", fix="reduce-database-role-grants",
                         check="principals", caveats=caveats, details=details)
            elif r.level == "admin" and r.ptype == "unknown":
                self.add(control="A2", rule="A2.admin-function-undeclared",
                         title="Owner/admin rights on a patient database held by a principal with no declared function",
                         impact="high", likelihood="low",
                         rationale={"impact": "full control of the database and its patient records",
                                    "likelihood": "may be a legitimate administrator; function is not documented"},
                         loc=loc, id_key=["admin-undeclared", r.key], basis="inference", confidence=max(conf - 0.1, 0.3),
                         reason="rights observed; justification unknown", fix="reduce-database-role-grants",
                         check="principals", caveats=caveats + ["Declare the principal's type and function in the "
                                                                "manifest to confirm or clear this finding."],
                         details=details)
            elif r.level == "write" and decl_access in ("read", "none"):
                self.add(control="A2", rule="A2.unjustified-write",
                         title="Write access to patient data beyond the principal's declared function",
                         impact="high", likelihood="medium",
                         rationale={"impact": "can alter or delete patient records (integrity) without need",
                                    "likelihood": f"declared function needs '{decl_access}' access only"},
                         loc=loc, id_key=["write", r.key], basis=r.basis, confidence=max(conf, 0.3),
                         reason="effective write rights compared with the declared expected access",
                         fix="reduce-database-role-grants", check="principals", caveats=caveats, details=details)
            elif r.level == "write" and decl_access is None and r.ptype == "service" and _readish(r.principal):
                self.add(control="A2", rule="A2.write-undeclared",
                         title="Write access held by a reporting/monitoring-type service principal (function not declared)",
                         impact="medium", likelihood="low",
                         rationale={"impact": "can alter patient records",
                                    "likelihood": "name suggests a read-only function; write rights look unnecessary"},
                         loc=loc, id_key=["write-undeclared", r.key], basis="inference", confidence=0.5,
                         reason="name-based inference; declare the expected access to confirm",
                         fix="reduce-database-role-grants", check="principals", caveats=caveats, details=details)
        for r in self.rights:
            if r.ptype == "shared" and r.level != "none" and r.enabled is not False:
                self.add(control="A2", rule="A2.shared-identity",
                         title="Shared or generic identity with access to patient data",
                         impact="high" if r.level == "admin" else "medium", likelihood="medium",
                         rationale={"impact": f"{r.level} access to patient data that cannot be attributed to a person",
                                    "likelihood": "shared credentials are passed between staff and rarely rotated"},
                         loc=self.location(principal=r.principal), id_key=["shared", r.key],
                         basis="observation" if r.ptype_basis.startswith(("declared", "directory")) else "inference",
                         confidence=0.85 if r.ptype_basis.startswith(("declared", "directory")) else 0.55,
                         reason=r.ptype_basis, fix="assign-individual-accounts", check="principals",
                         caveats=list(r.uncertain),
                         details={"effective_access": r.level, "derived_via": r.via, "principal_type_basis": r.ptype_basis})

    def export_rights(self) -> None:
        for r in self.rights:
            if r.level == "none" and not r.capabilities:
                continue
            self.state.principal_rights.append({
                "database": self.db.id, "asset_id": self.asset.get("asset_id"), "patient": bool(self.patient),
                "principal": r.principal, "key": r.key, "ptype": r.ptype, "level": r.level, "via": list(r.via),
                "basis": r.basis, "uncertain": list(r.uncertain), "enabled": r.enabled, "via_group": r.via_group,
                "login_type": r.login_type, "has_login": r.has_login, "capabilities": sorted(r.capabilities),
                "unit": f"{self.unit}:principals",
            })

    def run(self) -> None:
        raise NotImplementedError


# ------------------------------------------------------------------------------------------ SQL Server
_MSSQL_WRITE = {"INSERT", "UPDATE", "DELETE", "ALTER", "CONTROL", "TAKE OWNERSHIP"}
_SYS_SCHEMAS = {"sys", "information_schema"}


class MssqlAnalysis(DbAnalysis):
    def _db_rows(self, q: str) -> list[dict]:
        return [r for r in self.cat.rows(q)
                if not r.get("database_name") or str(r["database_name"]).lower() == self.dbname]

    def derive(self) -> str:
        cat = self.cat
        logins = {norm_principal(r.get("name")): r for r in cat.rows("server_principals")}
        by_sid = {str(r.get("sid")).lower(): r for r in cat.rows("server_principals") if r.get("sid")}
        srv_edges: dict[str, set[str]] = defaultdict(set)
        for r in cat.rows("server_role_members"):
            srv_edges[norm_principal(r.get("member_name"))].add(str(r.get("role_name") or "").lower())
        srv_perms: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for r in cat.rows("server_permissions"):
            srv_perms[norm_principal(r.get("grantee"))].add((str(r.get("permission_name") or "").upper(),
                                                             str(r.get("state_desc") or "").upper()))
        self.sysadmins = set()
        self.server_roles: dict[str, set[str]] = {}
        for k in set(logins) | set(srv_edges):
            roles = _closure(srv_edges, k)
            self.server_roles[k] = roles
            perms = srv_perms.get(k, set())
            if "sysadmin" in roles or ("CONTROL SERVER", "GRANT") in perms or ("CONTROL SERVER", "GRANT_WITH_GRANT_OPTION") in perms:
                self.sysadmins.add(k)
        dbrow = next((r for r in cat.rows("databases") if str(r.get("name") or "").lower() == self.dbname), None)
        owner_login = norm_principal(dbrow.get("owner_login")) if dbrow else None
        self.dbrow = dbrow
        users = {}
        for r in self._db_rows("database_principals"):
            t = str(r.get("type") or "").upper()
            if t in ("R", "A"):
                continue
            users[str(r.get("name"))] = r
        edges: dict[str, set[str]] = defaultdict(set)
        for r in self._db_rows("database_role_members"):
            edges[str(r.get("member_name")).lower()].add(str(r.get("role_name") or "").lower())
        perms: dict[str, list[dict]] = defaultdict(list)
        for r in self._db_rows("database_permissions"):
            perms[str(r.get("grantee") or "").lower()].append(r)
        no_members = not cat.has("database_role_members")
        no_grants = not cat.has("database_permissions")
        no_srv = not cat.has("server_role_members")
        unc = []
        if no_members:
            unc.append("Database role membership was not in the catalogue export: effective rights may be higher.")
        if no_grants:
            unc.append("Database permission grants were not in the catalogue export: effective rights may be higher.")
        if no_srv:
            unc.append("Server role membership was not in the catalogue export: sysadmin rights not determined.")
        mapped_logins = set()
        for uname, u in sorted(users.items()):
            ukey = uname.lower()
            if ukey in ("guest", "information_schema", "sys"):
                continue  # guest is assessed by the guest_access check
            auth = str(u.get("authentication_type_desc") or "").upper()
            login = None
            if u.get("login_name"):
                login = norm_principal(u["login_name"])
            elif u.get("sid") and str(u["sid"]).lower() in by_sid:
                login = norm_principal(by_sid[str(u["sid"]).lower()].get("name"))
            lrow = logins.get(login) if login else None
            display = str(lrow.get("name")) if lrow else uname
            ptype, pbasis, decl = classify_principal(self.state, display, self.db, self.identity)
            r = Right(display, norm_principal(display), ptype, pbasis, decl, uncertain=list(unc),
                      login_type=str((lrow or u).get("type") or "").upper() or None)
            r.has_login = bool(login) or auth in ("DATABASE", "NONE", "WINDOWS") or (
                not auth and str(u.get("type") or "").upper() != "S")
            if lrow is not None and _b(lrow.get("is_disabled")) is not None:
                r.enabled = not _b(lrow.get("is_disabled"))
            if login:
                mapped_logins.add(login)
            roles = _closure(edges, ukey) | {"public"}
            if login and login in self.sysadmins:
                r.raise_to("admin", "server-level sysadmin / CONTROL SERVER")
            if ukey == "dbo" or (owner_login and login == owner_login):
                r.raise_to("admin", "database owner")
            if "db_owner" in roles:
                r.raise_to("admin", "member of db_owner")
            if roles & {"db_securityadmin", "db_accessadmin"}:
                r.raise_to("admin", "member of " + ", ".join(sorted(roles & {"db_securityadmin", "db_accessadmin"})))
            if "db_datawriter" in roles:
                r.raise_to("write", "member of db_datawriter")
            if "db_ddladmin" in roles:
                r.raise_to("write", "member of db_ddladmin")
            if "db_datareader" in roles:
                r.raise_to("read", "member of db_datareader")
            self._apply_grants(r, [ukey, *sorted(roles)], perms)
            self.rights.append(r)
        # logins with server-level admin but no user mapping still control every database
        for k in sorted(self.sysadmins - mapped_logins):
            lrow = logins.get(k)
            if not lrow or str(lrow.get("type") or "").upper() == "R":
                continue
            name = lrow.get("name")
            ptype, pbasis, decl = classify_principal(self.state, name, self.db, self.identity)
            r = Right(name, k, ptype, pbasis, decl, uncertain=list(unc), login_type=str(lrow.get("type") or "").upper())
            r.enabled = not _b(lrow.get("is_disabled")) if _b(lrow.get("is_disabled")) is not None else None
            r.raise_to("admin", "server-level sysadmin / CONTROL SERVER")
            self.rights.append(r)
        self._expand_groups()
        for r in self.rights:
            for role in sorted(self.server_roles.get(r.key, set()) & {"bulkadmin", "serveradmin", "setupadmin",
                                                                       "securityadmin", "processadmin", "diskadmin",
                                                                       "dbcreator"}):
                r.capabilities.add(role)
        return f"{len(self.rights)} database principals evaluated"

    def _apply_grants(self, r: Right, grantees: list[str], perms: dict[str, list[dict]]) -> None:
        denied = set()
        for g in grantees:
            for p in perms.get(g, []):
                if str(p.get("state_desc") or "").upper() == "DENY":
                    denied.add((str(p.get("permission_name") or "").upper(), str(p.get("class_desc") or "").upper()))
        for g in grantees:
            for p in perms.get(g, []):
                state = str(p.get("state_desc") or "").upper()
                if state not in ("GRANT", "GRANT_WITH_GRANT_OPTION"):
                    continue
                perm = str(p.get("permission_name") or "").upper()
                cls = str(p.get("class_desc") or "").upper()
                if (perm, cls) in denied or (perm, "DATABASE") in denied:
                    continue
                schema = str(p.get("schema_name") or "").lower()
                obj = str(p.get("object_name") or "").lower()
                if schema in _SYS_SCHEMAS:
                    continue
                if cls == "OBJECT_OR_COLUMN" and self.has_columns and (schema, obj) not in self.ptables:
                    continue
                target = "database" if cls == "DATABASE" else f"{schema}.{obj}" if obj else f"schema {schema}"
                via = f"GRANT {perm} on {target}" + (f" (via {g})" if g != grantees[0] else "")
                if perm == "CONTROL" and cls == "DATABASE":
                    r.raise_to("admin", via)
                elif perm in ("ALTER ANY USER", "ALTER ANY ROLE", "ALTER ANY SCHEMA") and cls == "DATABASE":
                    r.raise_to("admin", via)
                elif perm in _MSSQL_WRITE:
                    r.raise_to("write", via)
                elif perm == "SELECT":
                    r.raise_to("read", via)

    def _expand_groups(self) -> None:
        if self.identity is None:
            for r in self.rights:
                if r.login_type == "G" and r.level != "none":
                    r.uncertain.append("Windows group login: group membership not supplied (no directory export).")
            return
        extra = []
        for r in self.rights:
            if r.login_type != "G":
                continue
            members = self.identity.group_members(r.principal)
            if members is None:
                r.uncertain.append("Windows group login: membership not present in the directory export.")
                continue
            for acct in members:
                ptype, pbasis, decl = classify_principal(self.state, acct.display, self.db, self.identity)
                m = Right(acct.display, acct.key, ptype, pbasis, decl, level=r.level,
                          via=[f"member of Windows group {r.principal}"] + r.via[:4], basis="inference",
                          uncertain=list(r.uncertain), enabled=acct.enabled, login_type="G-member",
                          via_group=r.principal)
                extra.append(m)
        self.rights.extend(extra)

    def run(self) -> None:
        st = self.state
        cat = self.cat
        derived = {}

        def principals():
            derived["detail"] = self.derive()
            return derived["detail"]

        self.check("principals", "A2", ["server_principals", "database_principals"], principals,
                   optional=["database_role_members", "database_permissions", "server_role_members", "columns"])
        if derived:
            for q, what in (("database_role_members", "role_membership"), ("database_permissions", "grants"),
                            ("server_role_members", "server_roles")):
                if not cat.has(q):
                    st.rec.unavail("A2", f"{self.unit}:{what}", f"{q} missing: effective rights derived without it "
                                   "(findings labelled inference)")
                else:
                    st.rec.assess("A2", f"{self.unit}:{what}")
            self.privilege_findings()
            self.orphaned_users()
            self.export_rights()
        cfg: dict[str, int | None] = {}

        def config_value(name):
            if not cfg:
                for r in cat.rows("configurations"):
                    v = r.get("value_in_use")
                    try:
                        cfg[str(r.get("name") or "").lower()] = int(str(v).strip()) if v is not None else None
                    except ValueError:
                        cfg[str(r.get("name") or "").lower()] = None
            if name not in cfg:
                raise Unrecognised(f"option '{name}' not present")
            if cfg[name] not in (0, 1):
                raise Unrecognised(f"option '{name}' has a non-boolean value")
            return cfg[name]

        app_sysadmins = sorted(r.principal for r in self.rights if r.level == "admin" and r.ptype in (
            "application", "service", "shared", "unknown", "supplier") and "server-level sysadmin / CONTROL SERVER" in r.via)

        def xp_cmdshell():
            if config_value("xp_cmdshell") == 1:
                self.add(control="A4", rule="A4.mssql-xp-cmdshell", title="xp_cmdshell enabled (database-originated "
                         "operating-system command execution)", impact="high",
                         likelihood="high" if app_sysadmins else "medium",
                         rationale={"impact": "any sysadmin session can run OS commands as the SQL Server service account",
                                    "likelihood": ("non-administrator principals hold sysadmin: " + ", ".join(app_sysadmins[:5]))
                                    if app_sysadmins else "requires a sysadmin session"},
                         loc=self.location(object="configuration xp_cmdshell"), id_key=["xp_cmdshell"],
                         basis="observation", confidence=0.95, reason="sys.configurations value_in_use = 1",
                         fix="disable-shell-execution", check="xp_cmdshell",
                         details={"option": "xp_cmdshell", "value_in_use": 1, "sysadmin_non_admin_principals": app_sysadmins[:10]})
            return "xp_cmdshell checked"

        def clr():
            on = config_value("clr enabled")
            try:
                strict = config_value("clr strict security")
            except Unrecognised:
                strict = None
            if on == 1 and strict != 1:
                self.add(control="A4", rule="A4.mssql-clr", title="CLR integration enabled without strict security",
                         impact="medium", likelihood="low",
                         rationale={"impact": "assemblies can run external code inside the database engine",
                                    "likelihood": "requires permission to create assemblies"},
                         loc=self.location(object="configuration clr enabled"), id_key=["clr"], basis="observation",
                         confidence=0.9, reason="sys.configurations", fix="disable-shell-execution", check="clr",
                         details={"clr_enabled": on, "clr_strict_security": strict})
            return "CLR options checked"

        def ole():
            if config_value("ole automation procedures") == 1:
                self.add(control="A4", rule="A4.mssql-ole-automation", title="OLE Automation procedures enabled",
                         impact="high", likelihood="low",
                         rationale={"impact": "COM objects (file system, shell) can be driven from T-SQL",
                                    "likelihood": "requires sysadmin or explicit grants"},
                         loc=self.location(object="configuration Ole Automation Procedures"), id_key=["ole"],
                         basis="observation", confidence=0.95, reason="sys.configurations",
                         fix="disable-shell-execution", check="ole_automation")
            return "OLE Automation checked"

        def adhoc():
            if config_value("ad hoc distributed queries") == 1:
                self.add(control="A4", rule="A4.mssql-adhoc-distributed", title="Ad hoc distributed queries enabled "
                         "(OPENROWSET/OPENDATASOURCE to arbitrary servers)", impact="medium", likelihood="medium",
                         rationale={"impact": "data can be pulled from or pushed to servers outside any declared link",
                                    "likelihood": "available to any principal allowed to use the providers"},
                         loc=self.location(object="configuration Ad Hoc Distributed Queries"), id_key=["adhoc"],
                         basis="observation", confidence=0.95, reason="sys.configurations",
                         fix="remove-cross-server-link", check="adhoc_distributed_queries")
            return "ad hoc distributed queries checked"

        def linked():
            logins = defaultdict(list)
            for r in cat.rows("linked_logins"):
                logins[str(r.get("linked_server") or "").lower()].append(r)
            for r in cat.rows("linked_servers"):
                name = str(r.get("name") or "")
                mapped = logins.get(name.lower(), [])
                fixed_all = [m for m in mapped if not m.get("local_principal") and _b(m.get("uses_self_credential")) is False
                             and m.get("remote_name")]
                caveats = [] if cat.has("linked_logins") else ["Linked-login mappings were not exported; the security "
                                                                "context used on the remote server is unknown."]
                self.add(control="A4", rule="A4.mssql-linked-server", title=f"Cross-server link to {name}",
                         impact="high" if fixed_all else "medium", likelihood="medium",
                         rationale={"impact": ("every local login reaches the remote server as one fixed remote login"
                                               if fixed_all else "queries can cross to another server"),
                                    "likelihood": "links are usable by any principal with access to them"},
                         loc=self.location(object=f"linked server {name}"), id_key=["linked", name.lower()],
                         basis="observation", confidence=0.9, reason="sys.servers is_linked = 1",
                         fix="remove-cross-server-link", check="linked_servers", caveats=caveats,
                         details={"product": _s(r.get("product")), "provider": _s(r.get("provider")),
                                  "rpc_out": _b(r.get("is_rpc_out_enabled")),
                                  "fixed_remote_login_for_all_logins": bool(fixed_all),
                                  "remote_logins": sorted({str(m.get("remote_name")) for m in mapped if m.get("remote_name")})[:10]})
            return f"{len(cat.rows('linked_servers'))} linked servers"

        def audit():
            audits = cat.rows("server_audits")
            enabled = [a for a in audits if _b(a.get("is_state_enabled"))]
            enabled_names = {str(a.get("name") or "").lower() for a in enabled}
            if not enabled:
                self.add(control="A4", rule="A4.mssql-audit-disabled", title="SQL Server auditing disabled",
                         impact="medium", likelihood="high",
                         rationale={"impact": "logins and access to patient tables are not recorded; incident scoping "
                                              "would have to assume the worst case",
                                    "likelihood": "no enabled server audit"},
                         loc=self.location(object="server audit"), id_key=["audit-disabled"], basis="observation",
                         confidence=0.9, reason="sys.server_audits has no enabled audit", fix="restore-auditing",
                         check="audit", details={"server_audits": len(audits), "enabled": 0})
                return "no enabled audit"
            gaps = []
            if cat.has("server_audit_specifications"):
                acts = {str(r.get("audit_action_name") or "").upper() for r in cat.rows("server_audit_specifications")
                        if _b(r.get("is_state_enabled")) and str(r.get("audit_name") or "").lower() in enabled_names}
                for need in ("FAILED_LOGIN_GROUP", "SUCCESSFUL_LOGIN_GROUP"):
                    if need not in acts:
                        gaps.append(f"server specification lacks {need}")
            if self.patient and cat.has("database_audit_specifications"):
                dacts = {str(r.get("audit_action_name") or "").upper() for r in self._db_rows("database_audit_specifications")
                         if _b(r.get("is_state_enabled"))}
                if not dacts & {"SCHEMA_OBJECT_ACCESS_GROUP", "SELECT", "DATABASE_OBJECT_ACCESS_GROUP"}:
                    gaps.append("no enabled database audit specification covers access to patient tables")
            if gaps:
                self.add(control="A4", rule="A4.mssql-audit-incomplete", title="SQL Server auditing incomplete",
                         impact="medium", likelihood="medium",
                         rationale={"impact": "some logins or patient-table access are not recorded", "likelihood": "; ".join(gaps)},
                         loc=self.location(object="audit specifications"), id_key=["audit-incomplete"],
                         basis="observation", confidence=0.85, reason="audit specification details", fix="restore-auditing",
                         check="audit", details={"gaps": gaps})
            return "audit configuration checked"

        def guest():
            if self.dbname in ("master", "tempdb", "msdb"):
                return "system database"
            for p in self._db_rows("database_permissions"):
                if str(p.get("grantee") or "").lower() == "guest" and str(p.get("permission_name") or "").upper() == "CONNECT" \
                        and str(p.get("state_desc") or "").upper().startswith("GRANT"):
                    self.add(control="A4", rule="A4.mssql-guest-enabled", title="Guest user enabled in a user database",
                             impact="high" if self.patient else "medium", likelihood="medium",
                             rationale={"impact": "any login on the server can enter the database with guest/public rights",
                                        "likelihood": "no database user mapping is needed"},
                             loc=self.location(object="user guest"), id_key=["guest"], basis="observation",
                             confidence=0.95, reason="CONNECT granted to guest", fix="revoke-public-access", check="guest_access")
            return "guest access checked"

        def public_grants():
            for p in self._db_rows("database_permissions"):
                if str(p.get("grantee") or "").lower() != "public":
                    continue
                perm = str(p.get("permission_name") or "").upper()
                cls = str(p.get("class_desc") or "").upper()
                schema_o, obj_o = str(p.get("schema_name") or ""), str(p.get("object_name") or "")
                schema, obj = schema_o.lower(), obj_o.lower()
                if not str(p.get("state_desc") or "").upper().startswith("GRANT") or schema in _SYS_SCHEMAS:
                    continue
                if perm not in _MSSQL_WRITE | {"SELECT"}:
                    continue
                if cls == "OBJECT_OR_COLUMN" and self.has_columns and (schema, obj) not in self.ptables:
                    continue
                target = "database" if cls == "DATABASE" else f"{schema_o}.{obj_o}" if obj else f"schema {schema_o}"
                self.add(control="A4", rule="A4.mssql-public-grant", title=f"{perm} granted to public on {target}",
                         impact="high", likelihood="medium",
                         rationale={"impact": "every database user (and guest, if enabled) inherits the grant",
                                    "likelihood": "no specific role membership is needed"},
                         loc=self.location(object=target), id_key=["public", perm, target.lower()], basis="observation",
                         confidence=0.9, reason="sys.database_permissions grantee public", fix="revoke-public-access",
                         check="public_grants")
            return "public grants checked"

        def trustworthy():
            r = self.dbrow
            if r is None:
                raise Unrecognised("database not in sys.databases export")
            if _b(r.get("is_trustworthy_on")):
                owner = norm_principal(r.get("owner_login"))
                high = owner in self.sysadmins or owner == "sa"
                self.add(control="A4", rule="A4.mssql-trustworthy", title="TRUSTWORTHY enabled on a user database",
                         impact="high" if high else "medium", likelihood="medium" if high else "low",
                         rationale={"impact": "db_owner members can escalate to the owner's server rights",
                                    "likelihood": "database owner holds sysadmin" if high else "owner is not sysadmin"},
                         loc=self.location(object="database option TRUSTWORTHY"), id_key=["trustworthy"],
                         basis="observation", confidence=0.9, reason="sys.databases is_trustworthy_on = 1",
                         fix="reduce-database-role-grants", check="trustworthy")
            return "TRUSTWORTHY checked"

        def sa_login():
            sa = next((r for r in cat.rows("server_principals") if str(r.get("name") or "").lower() == "sa"), None)
            if sa is None:
                return "sa renamed or absent"
            mixed = None
            if cat.has("server_info") and cat.rows("server_info"):
                v = _b(cat.rows("server_info")[0].get("integrated_security_only"))
                mixed = None if v is None else not v
            if _b(sa.get("is_disabled")) is False and mixed is not False:
                self.add(control="A4", rule="A4.mssql-sa-enabled", title="Built-in 'sa' login enabled with SQL "
                         "authentication", impact="high", likelihood="low",
                         rationale={"impact": "well-known sysadmin login, a password-guessing target, often shared",
                                    "likelihood": "depends on password strength and network reachability"},
                         loc=self.location(principal="sa"), id_key=["sa"], basis="observation" if mixed else "inference",
                         confidence=0.85 if mixed else 0.6, reason="sa enabled; authentication mode from server properties",
                         fix="disable-or-remove-account", check="sa_login",
                         caveats=[] if mixed else ["Authentication mode not exported; mixed mode assumed."])
            return "sa login checked"

        def services():
            for r in cat.rows("services"):
                acct = str(r.get("service_account") or "")
                low = acct.lower()
                if low in ("localsystem", "nt authority\\system", ".\\localsystem") or low.endswith("\\administrator") \
                        or "admin" in low.split("\\")[-1]:
                    self.add(control="A4", rule="A4.mssql-service-account", title="SQL Server service runs under a "
                             "highly privileged operating-system account", impact="high", likelihood="low",
                             rationale={"impact": "database compromise (e.g. via xp_cmdshell) yields that OS privilege",
                                        "likelihood": "requires a code-execution path in the engine"},
                             loc=self.location(object=f"service {r.get('servicename')}", principal=acct),
                             id_key=["service", str(r.get("servicename") or "").lower()], basis="observation",
                             confidence=0.9, reason="sys.dm_server_services", fix="review-service-account", check="service_accounts")
            return "service accounts checked"

        def password_policy():
            for r in cat.rows("sql_logins"):
                name = str(r.get("name") or "")
                if name.startswith("##") or _b(r.get("is_disabled")):
                    continue
                if _b(r.get("is_policy_checked")) is False:
                    self.add(control="A4", rule="A4.mssql-password-policy", title="SQL login exempt from the password policy",
                             impact="medium", likelihood="low",
                             rationale={"impact": "weak or non-expiring passwords allowed",
                                        "likelihood": "SQL logins are password-only (no MFA)"},
                             loc=self.location(principal=name), id_key=["policy", norm_principal(name)],
                             basis="observation", confidence=0.9, reason="sys.sql_logins is_policy_checked = 0",
                             fix="enforce-password-policy", check="password_policy")
            return "SQL login policy checked"

        def excess():
            for r in self.rights:
                if r.ptype not in ("application", "service", "shared", "unknown"):
                    continue
                for role in sorted(r.capabilities):
                    self.add(control="A4", rule="A4.mssql-excess-capability",
                             title=f"Non-administrator principal holds server role {role}",
                             impact="high" if role in ("securityadmin", "serveradmin") else "medium", likelihood="low",
                             rationale={"impact": f"{role} grants server-wide capabilities beyond database access",
                                        "likelihood": "exercised only if the principal's credential is misused"},
                             loc=self.location(principal=r.principal, object=f"server role {role}"),
                             id_key=["capability", r.key, role], basis="observation", confidence=0.85,
                             reason="sys.server_role_members", fix="reduce-database-role-grants", check="excess_capabilities")
            return "server role capabilities checked"

        def chaining():
            on = config_value("cross db ownership chaining") == 1
            if on or (self.dbrow and _b(self.dbrow.get("is_db_chaining_on"))):
                self.add(control="A4", rule="A4.mssql-cross-db-chaining", title="Cross-database ownership chaining enabled",
                         impact="medium", likelihood="low",
                         rationale={"impact": "permission checks can be bypassed across databases with a common owner",
                                    "likelihood": "requires objects crafted by a database owner"},
                         loc=self.location(object="cross db ownership chaining"), id_key=["chaining"],
                         basis="observation", confidence=0.85, reason="configuration or database option",
                         fix="reduce-database-role-grants", check="cross_db_chaining")
            return "ownership chaining checked"

        self.check("xp_cmdshell", "A4", ["configurations"], xp_cmdshell)
        self.check("clr", "A4", ["configurations"], clr)
        self.check("ole_automation", "A4", ["configurations"], ole)
        self.check("adhoc_distributed_queries", "A4", ["configurations"], adhoc)
        self.check("linked_servers", "A4", ["linked_servers"], linked, optional=["linked_logins"])
        self.check("audit", "A4", ["server_audits"], audit,
                   optional=["server_audit_specifications", "database_audit_specifications"])
        self.check("guest_access", "A4", ["database_permissions"], guest)
        self.check("public_grants", "A4", ["database_permissions"], public_grants, optional=["columns"])
        self.check("trustworthy", "A4", ["databases"], trustworthy)
        self.check("sa_login", "A4", ["server_principals"], sa_login, optional=["server_info"])
        self.check("service_accounts", "A4", ["services"], services)
        self.check("password_policy", "A4", ["sql_logins"], password_policy)
        if derived:
            self.check("excess_capabilities", "A4", ["server_role_members"], excess)
        self.check("cross_db_chaining", "A4", ["configurations", "databases"], chaining)

    def orphaned_users(self) -> None:
        for r in self.rights:
            if r.has_login or r.key in _SYSTEM or r.login_type in ("G-member",):
                continue
            self.add(control="A2", rule="A2.orphaned-user", title="Orphaned database user (no matching server login)",
                     impact="medium" if r.level in ("write", "admin") else "low", likelihood="low",
                     rationale={"impact": f"obsolete principal with {r.level} access remains in a patient database",
                                "likelihood": "re-mapped or re-created logins can inherit its rights"},
                     loc=self.location(principal=r.principal), id_key=["orphan", r.key], basis="observation",
                     confidence=0.8, reason="database user SID has no server login in the export",
                     fix="disable-or-remove-account", check="principals",
                     details={"effective_access": r.level, "derived_via": r.via})


# ------------------------------------------------------------------------------------------ PostgreSQL
_PG_WRITE = {"INSERT", "UPDATE", "DELETE", "TRUNCATE"}
_PG_BOOTSTRAP = {"postgres"}


class PostgresAnalysis(DbAnalysis):
    def derive(self) -> str:
        cat = self.cat
        roles = {str(r.get("rolname")): r for r in cat.rows("roles")}
        lower = {k.lower(): v for k, v in roles.items()}
        member_edges: dict[str, set[str]] = defaultdict(set)     # any membership (SET ROLE possible)
        inherit_edges: dict[str, set[str]] = defaultdict(set)    # privileges inherited
        for r in cat.rows("auth_members"):
            m, role = str(r.get("member_name") or "").lower(), str(r.get("role_name") or "").lower()
            member_edges[m].add(role)
            inh = _b(r.get("inherit_option"))
            if inh is None:
                inh = _b((lower.get(m) or {}).get("rolinherit"))
            if inh is not False:
                inherit_edges[m].add(role)
        privs: dict[str, list[dict]] = defaultdict(list)
        for p in cat.rows("table_privileges"):
            privs[str(p.get("grantee") or "").lower()].append(p)
        owners = defaultdict(set)
        for p in cat.rows("tables") or cat.rows("table_privileges"):
            owners[str(p.get("owner") or "").lower()].add((str(p.get("schema_name") or "").lower(),
                                                           str(p.get("table_name") or "").lower()))
        dbrow = next((r for r in cat.rows("databases") if str(r.get("name") or "").lower() == self.dbname), None)
        db_owner = str(dbrow.get("owner") or "").lower() if dbrow else None
        unc = []
        if not cat.has("auth_members"):
            unc.append("Role membership (pg_auth_members) was not in the catalogue export: effective rights may be higher.")
        if not cat.has("table_privileges"):
            unc.append("Table privileges were not in the catalogue export: effective rights may be higher.")
        self.capable: dict[str, set[str]] = {}
        for name, row in sorted(roles.items()):
            if not _b(row.get("rolcanlogin")):
                continue
            k = name.lower()
            ptype, pbasis, decl = classify_principal(self.state, name, self.db, self.identity)
            r = Right(name, k, ptype, pbasis, decl, uncertain=list(unc), login_type="LOGIN")
            r.enabled = True
            vu = _s(row.get("rolvaliduntil"))
            if vu and vu < self.state.m.as_of.strftime("%Y-%m-%dT%H:%M:%SZ"):
                r.enabled = False
            inherited = _closure(inherit_edges, k)
            memberships = _closure(member_edges, k)
            if _b(row.get("rolsuper")):
                r.raise_to("admin", "superuser")
                r.capabilities.add("copy_program")
            for m in sorted(memberships):
                if _b((lower.get(m) or {}).get("rolsuper")):
                    r.raise_to("admin", f"can SET ROLE to superuser role {m}")
                    r.basis = "inference"
            if db_owner and (k == db_owner or db_owner in inherited):
                r.raise_to("admin", "database owner")
            owned = set()
            for who in [k, *sorted(inherited)]:
                owned |= owners.get(who, set())
            powned = owned & self.ptables if self.has_columns else owned
            if powned:
                r.raise_to("admin", f"owns {len(powned)} patient table(s)")
            for cap, role in (("copy_program", "pg_execute_server_program"), ("read_server_files", "pg_read_server_files"),
                              ("write_server_files", "pg_write_server_files")):
                if role in memberships:
                    r.capabilities.add(cap)
            if "pg_write_all_data" in memberships:
                r.raise_to("write", "member of pg_write_all_data")
            if "pg_read_all_data" in memberships:
                r.raise_to("read", "member of pg_read_all_data")
            for flag, cap in (("rolreplication", "replication"), ("rolbypassrls", "bypassrls"),
                              ("rolcreaterole", "createrole")):
                if _b(row.get(flag)) and not _b(row.get("rolsuper")):
                    r.capabilities.add(cap)
            for g in [k, *sorted(inherited), "public"]:
                for p in privs.get(g, []):
                    key = (str(p.get("schema_name") or "").lower(), str(p.get("table_name") or "").lower())
                    if self.has_columns and key not in self.ptables:
                        continue
                    pt = str(p.get("privilege_type") or "").upper()
                    via = f"GRANT {pt} on {key[0]}.{key[1]}" + (f" (via {g})" if g != k else "")
                    if pt in _PG_WRITE:
                        r.raise_to("write", via)
                    elif pt == "SELECT":
                        r.raise_to("read", via)
            self.rights.append(r)
        return f"{len(self.rights)} login roles evaluated"

    def run(self) -> None:
        st = self.state
        cat = self.cat
        derived = {}

        def principals():
            derived["detail"] = self.derive()
            return derived["detail"]

        self.check("principals", "A2", ["roles"], principals, optional=["auth_members", "table_privileges", "columns", "tables"])
        if derived:
            for q, what in (("auth_members", "role_membership"), ("table_privileges", "grants")):
                if not cat.has(q):
                    st.rec.unavail("A2", f"{self.unit}:{what}", f"{q} missing: effective rights derived without it "
                                   "(findings labelled inference)")
                else:
                    st.rec.assess("A2", f"{self.unit}:{what}")
            self.privilege_findings()
            self.export_rights()
        settings = {str(r.get("name") or "").lower(): _s(r.get("setting")) for r in cat.rows("settings")}

        def copy_program():
            for r in self.rights:
                if "copy_program" not in r.capabilities or r.key in _PG_BOOTSTRAP or r.ptype == "dba" or r.enabled is False:
                    continue
                how = "superuser" if "superuser" in r.via else "member of pg_execute_server_program"
                self.add(control="A4", rule="A4.pg-copy-program",
                         title="Principal can run operating-system commands via COPY ... PROGRAM",
                         impact="high", likelihood="medium",
                         rationale={"impact": "database-originated shell execution as the PostgreSQL service account",
                                    "likelihood": f"held by a non-bootstrap login ({how})"},
                         loc=self.location(principal=r.principal, object="COPY ... PROGRAM"), id_key=["copy-program", r.key],
                         basis="observation", confidence=0.9, reason=how, fix="disable-shell-execution",
                         check="copy_program", details={"capability_via": how, "principal_type": r.ptype})
            return "COPY PROGRAM capability checked"

        def languages():
            for r in cat.rows("languages"):
                name = str(r.get("lanname") or "")
                if _b(r.get("lanpltrusted")) is False and name.lower() not in ("c", "internal", "sql") and _b(r.get("lanispl")) is not False:
                    self.add(control="A4", rule="A4.pg-untrusted-language", title=f"Untrusted procedural language {name} installed",
                             impact="high", likelihood="low",
                             rationale={"impact": "functions in this language run arbitrary code as the server OS user",
                                        "likelihood": "only superusers can create such functions"},
                             loc=self.location(object=f"language {name}"), id_key=["language", name.lower()],
                             basis="observation", confidence=0.9, reason="pg_language lanpltrusted = false",
                             fix="disable-shell-execution", check="untrusted_languages")
            return "languages checked"

        def audit_logging():
            need = ["log_statement", "log_connections", "shared_preload_libraries"]
            absent = [n for n in need if n not in settings]
            if absent:
                raise Unrecognised("settings missing: " + ", ".join(absent))
            libs = (settings.get("shared_preload_libraries") or "").lower()
            pgaudit = "pgaudit" in libs
            stmt = (settings.get("log_statement") or "none").lower()
            conns = _b(settings.get("log_connections"))
            if stmt not in ("none", "ddl", "mod", "all"):
                raise Unrecognised("log_statement has an unknown value")
            if not pgaudit and stmt == "none":
                self.add(control="A4", rule="A4.pg-audit-disabled", title="PostgreSQL audit logging disabled",
                         impact="medium", likelihood="high",
                         rationale={"impact": "access to patient tables and privilege changes are not recorded",
                                    "likelihood": "pgaudit not loaded and log_statement = none"},
                         loc=self.location(object="logging settings"), id_key=["audit-disabled"], basis="observation",
                         confidence=0.9, reason="pg_settings", fix="restore-auditing", check="audit_logging",
                         details={"pgaudit_loaded": False, "log_statement": stmt, "log_connections": conns})
            elif not pgaudit or conns is False:
                gaps = ([] if pgaudit else ["pgaudit not loaded (statement logging only)"]) + (
                    ["log_connections off"] if conns is False else [])
                self.add(control="A4", rule="A4.pg-audit-incomplete", title="PostgreSQL audit logging incomplete",
                         impact="medium", likelihood="medium",
                         rationale={"impact": "some access is not attributable", "likelihood": "; ".join(gaps)},
                         loc=self.location(object="logging settings"), id_key=["audit-incomplete"], basis="observation",
                         confidence=0.85, reason="pg_settings", fix="restore-auditing", check="audit_logging",
                         details={"gaps": gaps})
            return "logging settings checked"

        def links():
            exts = {str(r.get("extname") or "").lower() for r in cat.rows("extensions")}
            servers = cat.rows("foreign_servers")
            for s in servers:
                name = str(s.get("srvname") or "")
                users = sorted({str(m.get("usename")) for m in cat.rows("user_mappings")
                                if str(m.get("srvname") or "").lower() == name.lower()})
                self.add(control="A4", rule="A4.pg-foreign-server", title=f"Cross-server link (foreign server {name})",
                         impact="medium", likelihood="medium",
                         rationale={"impact": "queries can reach another database server",
                                    "likelihood": "usable by the mapped roles: " + (", ".join(users[:5]) or "none exported")},
                         loc=self.location(object=f"foreign server {name}"), id_key=["foreign", name.lower()],
                         basis="observation", confidence=0.9, reason="pg_foreign_server", fix="remove-cross-server-link",
                         check="cross_server_links", details={"wrapper": _s(s.get("fdwname")), "mapped_roles": users[:10]})
            if "dblink" in exts:
                self.add(control="A4", rule="A4.pg-dblink", title="dblink extension installed (ad hoc cross-server connections)",
                         impact="medium", likelihood="low",
                         rationale={"impact": "functions can open connections to arbitrary servers",
                                    "likelihood": "requires EXECUTE on dblink functions"},
                         loc=self.location(object="extension dblink"), id_key=["dblink"], basis="observation",
                         confidence=0.9, reason="pg_extension", fix="remove-cross-server-link", check="cross_server_links")
            return f"{len(servers)} foreign servers"

        def public_schema():
            for p in cat.rows("schema_privileges"):
                if str(p.get("grantee") or "").upper() == "PUBLIC" and str(p.get("privilege_type") or "").upper() == "CREATE":
                    sch = str(p.get("schema_name") or "")
                    self.add(control="A4", rule="A4.pg-public-schema-create", title=f"PUBLIC can create objects in schema {sch}",
                             impact="medium", likelihood="medium",
                             rationale={"impact": "any login can plant objects (e.g. trojan functions) other roles may run",
                                        "likelihood": "no role membership needed"},
                             loc=self.location(object=f"schema {sch}"), id_key=["public-create", sch.lower()],
                             basis="observation", confidence=0.9, reason="schema ACL", fix="revoke-public-access",
                             check="public_schema_create")
            return "schema ACLs checked"

        def public_tables():
            for p in cat.rows("table_privileges"):
                if str(p.get("grantee") or "").upper() != "PUBLIC":
                    continue
                key = (str(p.get("schema_name") or "").lower(), str(p.get("table_name") or "").lower())
                if self.has_columns and key not in self.ptables:
                    continue
                pt = str(p.get("privilege_type") or "").upper()
                if pt not in _PG_WRITE | {"SELECT"}:
                    continue
                self.add(control="A4", rule="A4.pg-public-table-grant", title=f"{pt} granted to PUBLIC on {key[0]}.{key[1]}",
                         impact="high", likelihood="medium",
                         rationale={"impact": "every login role can use the grant on patient data",
                                    "likelihood": "no role membership needed"},
                         loc=self.location(object=f"{key[0]}.{key[1]}"), id_key=["public", pt, *key], basis="observation",
                         confidence=0.9, reason="table ACL", fix="revoke-public-access", check="public_table_grants")
            return "table ACLs checked"

        def hba():
            rows = cat.rows("hba_rules")
            if not rows:
                raise Unrecognised("no rules exported")
            for r in rows:
                method = str(r.get("auth_method") or "").lower()
                typ = str(r.get("type") or "").lower()
                net = typ.startswith("host")
                if method == "trust" and net:
                    impact, likelihood, why = "high", "high", "network connections accepted without a password"
                elif method == "password" and net:
                    impact, likelihood, why = "medium", "medium", "passwords sent in clear text over the network"
                elif method == "trust":
                    impact, likelihood, why = "medium", "low", "local connections accepted without a password"
                else:
                    continue
                line = str(r.get("line_number") or "")
                self.add(control="A4", rule="A4.pg-hba-weak-auth", title=f"Weak client authentication ({method}, {typ})",
                         impact=impact, likelihood=likelihood, rationale={"impact": why, "likelihood": "rule is active"},
                         loc=self.location(object=f"pg_hba.conf line {line}"), id_key=["hba", typ, method,
                                                                                     str(r.get("database")), str(r.get("user_name"))],
                         basis="observation", confidence=0.9, reason="pg_hba_file_rules", fix="revoke-public-access",
                         check="hba_auth", details={"databases": _s(r.get("database")), "users": _s(r.get("user_name"))})
            return f"{len(rows)} client authentication rules"

        def excess():
            for r in self.rights:
                if r.ptype not in ("application", "service", "shared", "unknown") or r.enabled is False:
                    continue
                for cap in sorted(r.capabilities - {"copy_program"}):
                    self.add(control="A4", rule="A4.pg-excess-capability", title=f"Non-administrator login holds {cap}",
                             impact="high" if cap in ("write_server_files", "read_server_files", "bypassrls") else "medium",
                             likelihood="low",
                             rationale={"impact": f"{cap} goes beyond ordinary database access",
                                        "likelihood": "exercised only if the login's credential is misused"},
                             loc=self.location(principal=r.principal, object=cap), id_key=["capability", r.key, cap],
                             basis="observation", confidence=0.85, reason="role attributes and predefined role membership",
                             fix="reduce-database-role-grants", check="excess_capabilities")
            return "role capabilities checked"

        def password_encryption():
            if "password_encryption" not in settings:
                raise Unrecognised("password_encryption missing")
            if (settings.get("password_encryption") or "").lower() == "md5":
                self.add(control="A4", rule="A4.pg-md5-passwords", title="Passwords stored with MD5 instead of SCRAM",
                         impact="medium", likelihood="low",
                         rationale={"impact": "weaker password hashes", "likelihood": "requires access to pg_authid"},
                         loc=self.location(object="password_encryption"), id_key=["md5"], basis="observation",
                         confidence=0.9, reason="pg_settings", fix="enforce-password-policy", check="password_encryption")
            return "password hashing checked"

        if derived:
            self.check("copy_program", "A4", ["roles"], copy_program, optional=["auth_members"])
            self.check("excess_capabilities", "A4", ["roles"], excess, optional=["auth_members"])
        self.check("untrusted_languages", "A4", ["languages"], languages)
        self.check("audit_logging", "A4", ["settings"], audit_logging)
        self.check("cross_server_links", "A4", ["extensions", "foreign_servers"], links, optional=["user_mappings"])
        self.check("public_schema_create", "A4", ["schema_privileges"], public_schema)
        self.check("public_table_grants", "A4", ["table_privileges"], public_tables, optional=["columns"])
        self.check("hba_auth", "A4", ["hba_rules"], hba)
        self.check("password_encryption", "A4", ["settings"], password_encryption)


ANALYSERS = {"mssql": MssqlAnalysis, "postgres": PostgresAnalysis}
MSSQL_CHECKS = ["principals", "xp_cmdshell", "clr", "ole_automation", "adhoc_distributed_queries", "linked_servers",
                "audit", "guest_access", "public_grants", "trustworthy", "sa_login", "service_accounts",
                "password_policy", "excess_capabilities", "cross_db_chaining"]
POSTGRES_CHECKS = ["principals", "copy_program", "excess_capabilities", "untrusted_languages", "audit_logging",
                   "cross_server_links", "public_schema_create", "public_table_grants", "hba_auth", "password_encryption"]
CHECKS = {"mssql": MSSQL_CHECKS, "postgres": POSTGRES_CHECKS}


def analyse_database(state: ScanState, db: Database, cat: Catalog | None, identity, error: str | None = None) -> None:
    unit = f"db:{db.id}"
    if db.engine not in ANALYSERS:
        for c in ("A2", "A4"):
            state.rec.not_assess(c, unit, f"database engine '{scrub_text(db.engine)[:30]}' is not supported in this version: "
                                          "no checks were run")
        state.rec.missing_evidence("A4", unit, "unsupported engine: privileges and configuration not assessed")
        return
    if cat is None:
        for c in ("A2", "A4"):
            state.rec.unavail(c, unit, error or "catalogue export could not be read")
        return
    if cat.engine and cat.engine != db.engine:
        for c in ("A2", "A4"):
            state.rec.unavail(c, unit, "catalogue export engine does not match the manifest declaration")
        return
    for q in sorted(cat.truncated):
        state.rec.missing_evidence("A2", f"{unit}:{q}", "query result truncated at the row budget; rights may be incomplete")
    ANALYSERS[db.engine](state, db, cat, identity).run()
