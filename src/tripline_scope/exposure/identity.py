"""Identity inputs (directory, sign-in, MFA exports, supplier register) and the checks that need them.

* A5 supplier access: external/supplier identities that can reach patient-data stores, MFA evidence, privilege
  versus contract, contract expiry and inactivity.
* A2 identity checks: dormant privileged accounts, obsolete principals, shared identities seen in sign-ins.

Absent evidence is reported as ``unknown``, never as ``disabled`` or ``inactive``: dormancy and inactivity need an
explicit observation window in the manifest **and** sign-in evidence covering it.
"""

from __future__ import annotations

import csv
import datetime as dt
import functools
import io
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from tripline_scope.core.redact import scrub_text

from .model import Finding
from .state import ScanState, norm_principal, principal_aliases, principal_location

DETECTOR = "exposure.identity/0.1.0"
LEVEL_ORDER = {"none": 0, "read": 1, "write": 2, "admin": 3}
_PERMITTED = {"none": "none", "no": "none", "read": "read", "readonly": "read", "read-only": "read", "support": "read",
              "view": "read", "write": "write", "readwrite": "write", "read-write": "write", "admin": "admin",
              "administrator": "admin", "owner": "admin", "full": "admin"}
_SUPPLIER_TYPES = {"guest", "external", "supplier", "vendor", "contractor", "partner"}


def _h(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def _pick(row: dict, *names):
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    return None


def _bool(v) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "enabled", "enforced", "registered", "t", "on", "satisfied", "success",
             "multifactorauthentication", "mfa"):
        return True
    if s in ("0", "false", "no", "n", "disabled", "f", "off", "notregistered", "not registered",
             "singlefactorauthentication", "singlefactor", "single-factor", "none"):
        return False
    return None


def _ts(v) -> dt.datetime | None:
    if v in (None, ""):
        return None
    s = str(v).strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.UTC)
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def _date(v) -> dt.date | None:
    t = _ts(v)
    return t.date() if t else None


def read_records(path: Path, max_bytes: int) -> list[dict]:
    """CSV (header row) or JSON (list, or {"value": [...]} as exported from Graph). Keys are normalised."""
    if path.stat().st_size > max_bytes:
        raise ValueError("identity export exceeds the per-file budget")
    raw = path.read_bytes()
    if path.suffix.lower() == ".json" or raw.lstrip()[:1] in (b"[", b"{"):
        doc = json.loads(raw)
        if isinstance(doc, dict):
            doc = doc.get("value") or doc.get("records") or doc.get("items") or []
        if not isinstance(doc, list):
            raise ValueError("unexpected JSON structure")
        return [{_h(k): v for k, v in r.items()} for r in doc if isinstance(r, dict)]
    text = raw.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    if rows and None in rows[0]:
        raise ValueError("inconsistent CSV columns")
    return [{_h(k): (v if v != "" else None) for k, v in r.items() if k is not None} for r in rows]


@dataclass
class Account:
    key: str
    display: str
    aliases: set[str]
    enabled: bool | None = None
    account_type: str | None = None
    user_type: str | None = None
    company: str | None = None
    groups: set[str] = field(default_factory=set)
    last_logon: dt.datetime | None = None
    end_date: dt.date | None = None
    upn: str | None = None


@dataclass
class SignIn:
    ts: dt.datetime
    aliases: set[str]
    app: str | None
    mfa: bool | None
    success: bool | None
    device: str | None


@dataclass
class Supplier:
    supplier: str
    accounts: list[str]
    contract_ref: str | None
    contract_end: dt.date | None
    permitted: str | None
    permitted_assets: list[str]
    mfa_required: bool | None


class Identity:
    def __init__(self, state: ScanState):
        self.state = state
        self.accounts: dict[str, Account] = {}
        self.alias: dict[str, str | None] = {}
        self.signins: list[SignIn] = []
        self.signin_alias: dict[str, list[SignIn]] = defaultdict(list)
        self.coverage: tuple[dt.datetime, dt.datetime] | None = None
        self.mfa: dict[str, dict] = {}
        self.suppliers: list[Supplier] = []
        self.supplier_alias: dict[str, Supplier] = {}
        self.loaded: dict[str, bool] = {}

    # ------------------------------------------------------------------ loading
    def load(self) -> None:
        m, rec = self.state.m, self.state.rec
        for key, fn in (("directory_export", self._directory), ("signin_export", self._signins),
                        ("mfa_export", self._mfa), ("supplier_register", self._register)):
            unit = f"identity:{key}"
            path = m.identity.get(key)
            if not path:
                self.loaded[key] = False
                continue
            try:
                rows = read_records(path, m.budget["max_file_bytes"])
                fn(rows)
                self.loaded[key] = True
            except (ValueError, OSError, UnicodeDecodeError, csv.Error) as exc:
                rec.parser_failure(key, unit, key, type(exc).__name__)
                rec.unavail(("A2", "A5"), unit, "identity export could not be parsed (malformed input)")
                self.loaded[key] = False

    def _index(self, acct: Account) -> None:
        self.accounts[acct.key] = acct
        for a in acct.aliases:
            if a in self.alias and self.alias[a] != acct.key:
                self.alias[a] = None  # ambiguous alias: never guess
            else:
                self.alias[a] = acct.key

    def _directory(self, rows: list[dict]) -> None:
        for r in rows:
            sam = _pick(r, "samaccountname", "account", "login", "username", "user", "accountname")
            upn = _pick(r, "userprincipalname", "upn", "mail", "email")
            if not sam and not upn:
                continue
            display = str(sam or upn)
            aliases = principal_aliases(sam) | principal_aliases(upn)
            enabled = _bool(_pick(r, "enabled", "accountenabled", "isenabled"))
            if enabled is None and _pick(r, "disabled") is not None:
                d = _bool(_pick(r, "disabled"))
                enabled = None if d is None else not d
            if enabled is None and _pick(r, "useraccountcontrol") is not None:
                try:
                    enabled = not (int(str(_pick(r, "useraccountcontrol"))) & 2)
                except ValueError:
                    enabled = None
            groups = set()
            for g in re.split(r"[;|]", str(_pick(r, "groups", "memberof") or "")):
                g = g.strip()
                if not g:
                    continue
                cn = re.match(r"(?i)cn=([^,]+)", g)
                groups.add(norm_principal(cn.group(1) if cn else g))
            acct = Account(key=norm_principal(display), display=display, aliases=aliases, enabled=enabled,
                           account_type=(str(_pick(r, "accounttype", "type", "employeetype", "kind")).lower()
                                         if _pick(r, "accounttype", "type", "employeetype", "kind") else None),
                           user_type=str(_pick(r, "usertype")).lower() if _pick(r, "usertype") else None,
                           company=_pick(r, "company", "organisation", "organization", "vendor"),
                           groups=groups,
                           last_logon=_ts(_pick(r, "lastlogon", "lastlogontimestamp", "lastsignin", "lastsignindatetime",
                                                "lastlogondate")),
                           end_date=_date(_pick(r, "employmentend", "accountexpires", "enddate", "leavedate")),
                           upn=str(upn) if upn else None)
            self._index(acct)

    def _signins(self, rows: list[dict]) -> None:
        for r in rows:
            t = _ts(_pick(r, "timestamp", "createddatetime", "time", "eventtime", "datetime", "date"))
            who = _pick(r, "account", "userprincipalname", "upn", "user", "username", "samaccountname")
            if t is None or not who:
                continue
            res = _pick(r, "result", "status", "outcome")
            success = _bool(res)
            if success is None and _pick(r, "errorcode") is not None:
                success = str(_pick(r, "errorcode")).strip() == "0"
            si = SignIn(t, principal_aliases(who), _pick(r, "application", "appdisplayname", "resource",
                                                          "resourcedisplayname", "app", "system"),
                        _bool(_pick(r, "mfa", "mfaresult", "authenticationrequirement", "mfadetail", "multifactor")),
                        success, _pick(r, "device", "deviceid", "clientip", "ipaddress", "workstation", "client"))
            self.signins.append(si)
            for a in si.aliases:
                self.signin_alias[a].append(si)
        decl = self.state.m.signin_coverage
        if decl:
            self.coverage = (_ts(decl["start"]), _ts(decl["end"]))
        elif self.signins:
            self.coverage = (min(s.ts for s in self.signins), max(s.ts for s in self.signins))

    def _mfa(self, rows: list[dict]) -> None:
        for r in rows:
            who = _pick(r, "account", "userprincipalname", "upn", "user", "username", "samaccountname")
            if not who:
                continue
            reg = _bool(_pick(r, "mfaregistered", "ismfaregistered", "registered", "mfacapable", "ismfacapable"))
            state = _pick(r, "mfastate", "perusermfastate", "state", "strongauthenticationrequirements")
            entry = {"registered": reg, "state": str(state).lower() if state else None,
                     "methods": _pick(r, "methods", "methodsregistered", "authmethods")}
            for a in principal_aliases(who):
                self.mfa[a] = entry

    def _register(self, rows: list[dict]) -> None:
        for r in rows:
            accts = [a.strip() for a in re.split(r"[;|,]", str(_pick(r, "accounts", "account", "logins", "upn", "login")
                                                                or "")) if a.strip()]
            perm = _pick(r, "permittedaccess", "access", "accesslevel")
            s = Supplier(supplier=str(_pick(r, "supplier", "vendor", "company") or "unnamed supplier")[:80],
                         accounts=accts, contract_ref=_pick(r, "contractref", "contract", "contractid"),
                         contract_end=_date(_pick(r, "contractend", "enddate", "expires", "expiry")),
                         permitted=_PERMITTED.get(_h(perm), None) if perm else None,
                         permitted_assets=[a.strip() for a in re.split(r"[;|,]", str(_pick(r, "permittedassets", "assets",
                                                                                           "systems") or "")) if a.strip()],
                         mfa_required=_bool(_pick(r, "mfarequired")))
            self.suppliers.append(s)
            for a in accts:
                for al in principal_aliases(a):
                    self.supplier_alias[al] = s

    # ------------------------------------------------------------------ lookups used by catalog analysis
    def account(self, name: str | None) -> Account | None:
        for a in principal_aliases(name):
            k = self.alias.get(a)
            if k:
                return self.accounts[k]
        return None

    def supplier_of(self, name: str | None) -> Supplier | None:
        for a in principal_aliases(name):
            if a in self.supplier_alias:
                return self.supplier_alias[a]
        return None

    def _directory_supplier(self, acct: Account | None) -> str | None:
        if acct is None:
            return None
        if acct.user_type in _SUPPLIER_TYPES or (acct.account_type or "") in _SUPPLIER_TYPES:
            return "directory export marks the account as external/guest"
        if acct.upn and "#ext#" in acct.upn.lower():
            return "guest (#EXT#) account in the directory export"
        names = {s.supplier.lower() for s in self.suppliers}
        if acct.company and str(acct.company).lower() in names:
            return "directory company matches a supplier in the register"
        doms = self.state.m.hospital_domains
        if doms and acct.upn and "@" in acct.upn and acct.upn.rsplit("@", 1)[1].lower() not in doms:
            return "account domain is not a hospital domain"
        return None

    def is_supplier(self, name: str | None) -> bool:
        return self.supplier_of(name) is not None or self._directory_supplier(self.account(name)) is not None

    def supplier_basis(self, name: str | None) -> str:
        if self.supplier_of(name) is not None:
            return "listed in the supplier register"
        return self._directory_supplier(self.account(name)) or "unknown"

    def group_members(self, group: str) -> list[Account] | None:
        if not self.loaded.get("directory_export"):
            return None
        g = norm_principal(group)
        members = [a for a in self.accounts.values() if g in a.groups]
        if not members and not any(a.groups for a in self.accounts.values()):
            return None  # export carries no group data at all
        return sorted(members, key=lambda a: a.key)

    # ------------------------------------------------------------------ evidence helpers
    def window(self) -> tuple[dt.datetime, dt.datetime] | None:
        w = self.state.m.observation_window
        return (_ts(w["start"]), _ts(w["end"])) if w else None

    def window_covered(self) -> tuple[bool, str]:
        w = self.window()
        if w is None:
            return False, "no observation window declared in the manifest"
        if not self.loaded.get("signin_export") and not self.loaded.get("directory_export"):
            return False, "no sign-in or directory export supplied"
        if self.loaded.get("signin_export"):
            if not self.coverage:
                return False, "sign-in export holds no usable records"
            tol = dt.timedelta(days=1)
            if self.coverage[0] > w[0] + tol or self.coverage[1] < w[1] - tol:
                return False, (f"sign-in evidence covers {self.coverage[0].date()} to {self.coverage[1].date()}, not the "
                               f"whole observation window {w[0].date()} to {w[1].date()}")
            return True, "sign-in export covers the observation window"
        return False, "only directory last-logon attributes available (no sign-in export)"

    def activity(self, name: str, *, directory_account: bool) -> tuple[str, str | None, str]:
        """('active'|'inactive'|'unknown', last sign-in date or None, basis text)."""
        w = self.window()
        if w is None:
            return "unknown", None, "no observation window declared"
        aliases = principal_aliases(name)
        acct = self.account(name)
        if acct:
            aliases |= acct.aliases
        seen = [s for a in aliases for s in self.signin_alias.get(a, [])]
        ok = [s for s in seen if s.success is not False and w[0] <= s.ts <= w[1]]
        last = max((s.ts for s in seen if s.success is not False), default=None)
        covered, why = self.window_covered()
        if ok:
            return "active", max(s.ts for s in ok).date().isoformat(), "successful sign-ins inside the observation window"
        if covered and (directory_account or seen):
            if acct and acct.last_logon and acct.last_logon >= w[0]:
                return "active", acct.last_logon.date().isoformat(), "directory last-logon inside the window"
            return "inactive", last.date().isoformat() if last else None, ("no successful sign-in in the observation "
                                                                          "window; sign-in evidence covers it")
        if acct and acct.last_logon and not self.loaded.get("signin_export"):
            if acct.last_logon < w[0]:
                return "inactive", acct.last_logon.date().isoformat(), ("directory last-logon precedes the observation "
                                                                       "window (attribute can lag by up to 14 days)")
            return "active", acct.last_logon.date().isoformat(), "directory last-logon inside the window"
        return "unknown", last.date().isoformat() if last else None, why if not covered else (
            "account does not appear in the sign-in evidence (e.g. SQL-authenticated login)")

    def mfa_status(self, name: str, sql_login: bool) -> tuple[str, str, str]:
        """('verified'|'not_evidenced'|'unknown', basis, reason)."""
        if sql_login:
            return "not_evidenced", "inference", "SQL-authenticated login: password only, MFA is not possible"
        aliases = principal_aliases(name)
        acct = self.account(name)
        if acct:
            aliases |= acct.aliases
        w = self.window()
        sis = [s for a in aliases for s in self.signin_alias.get(a, []) if s.success is not False
               and (w is None or w[0] <= s.ts <= w[1])]
        if any(s.mfa is False for s in sis):
            return "not_evidenced", "observation", "single-factor sign-ins observed in the sign-in export"
        rec = next((self.mfa[a] for a in sorted(aliases) if a in self.mfa), None)
        if rec is None:
            if not self.loaded.get("mfa_export"):
                return "unknown", "unknown", "no MFA registration export supplied"
            return "unknown", "unknown", "no MFA record for this account in the MFA export"
        if rec["registered"] is True or (rec["state"] or "") in ("enforced",):
            if sis and all(s.mfa is True for s in sis):
                return "verified", "observation", "MFA registered and every sign-in in the window satisfied MFA"
            return "verified", "observation", "MFA registered/enforced according to the MFA export"
        if rec["registered"] is False or (rec["state"] or "") in ("disabled",):
            return "not_evidenced", "observation", "MFA export shows no registration"
        return "unknown", "unknown", "MFA fields empty in the MFA export"


# ------------------------------------------------------------------------------------------ analysis
def _asset_for(state: ScanState, rights: list[dict]) -> tuple[dict, list[str]]:
    ids = sorted({r["asset_id"] or r["database"] for r in rights})
    for r in sorted(rights, key=lambda x: (x["asset_id"] or "", x["database"])):
        if r["asset_id"]:
            return state.asset_ref(r["asset_id"], r["database"]), ids
    if rights:
        db = next(d for d in state.m.databases if d.id == rights[0]["database"])
        return state.db_asset(db), ids
    return state.asset_ref(state.m.identity_asset, "identity", "identity"), ids


def _loc(name: str, supplier: str | None = None) -> dict:
    loc = {"type": "identity"}
    loc.update(principal_location(name))
    if supplier:
        loc["supplier"] = supplier
    loc["display"] = scrub_text("identity " + loc["principal"] + (f" [{loc['principal_domain']}]" if loc.get(
        "principal_domain") else "") + (f" (supplier {supplier})" if supplier else ""))[:300]
    return loc


def _a5(state: ScanState, common: dict, rule, title, impact, likelihood, rationale, basis, conf, reason, fix,
        caveats=(), unit="identity:supplier_identities") -> Finding:
    f = Finding(control_id="A5", rule_id=rule, title=title, impact=impact, likelihood=likelihood, rationale=rationale,
                asset=dict(common["asset"]), location=dict(common["location"]), coverage_unit=unit,
                id_parts=list(common["id_parts"]), basis=basis, confidence=conf, confidence_reason=reason, fix_action=fix,
                source_ids=list(common["source_ids"]), evidence_ids=list(common["evidence_ids"]), caveats=list(caveats),
                details=dict(common["details"]), ownership=dict(common["ownership"]), detector=DETECTOR)
    return state.add(f)


def analyse_identity(state: ScanState, ident: Identity) -> None:
    rec = state.rec
    m = state.m
    rights_by_key: dict[str, list[dict]] = defaultdict(list)
    for r in state.principal_rights:
        if r["patient"] and r["level"] != "none":
            for a in principal_aliases(r["principal"]):
                rights_by_key[a].append(r)

    # ---------------------------------------------------------------- coverage bookkeeping
    if ident.loaded.get("supplier_register") or ident.loaded.get("directory_export"):
        rec.assess("A5", "identity:supplier_identities",
                   f"{len(ident.suppliers)} register entries; {len(ident.accounts)} directory accounts")
    elif "supplier_register" not in m.identity and "directory_export" not in m.identity:
        rec.not_assess("A5", "identity:supplier_identities", "no supplier register or directory export declared")
    for key, ctl, what in (("mfa_export", "A5", "identity:mfa"), ("signin_export", "A5", "identity:sign_ins")):
        if ident.loaded.get(key):
            rec.assess(ctl, what)
        elif key not in m.identity:
            rec.not_assess(ctl, what, f"no {key.replace('_', ' ')} declared")
            rec.missing_evidence(ctl, what, f"no {key.replace('_', ' ')}: related statuses are reported as unknown")
    covered, why = ident.window_covered()
    if covered:
        rec.assess(("A2", "A5"), "identity:activity", why)
    else:
        rec.not_assess(("A2", "A5"), "identity:activity", f"dormancy/inactivity not assessed: {why}")
        rec.missing_evidence("A2", "identity:activity", f"dormancy and inactivity reported as unknown: {why}")
    if ident.loaded.get("directory_export"):
        rec.assess("A2", "identity:obsolete_principals")
    else:
        rec.not_assess("A2", "identity:obsolete_principals", "no directory export: obsolete principals not assessed")

    # ---------------------------------------------------------------- supplier accounts
    candidates: dict[str, str] = {}
    for s in ident.suppliers:
        for a in s.accounts:
            candidates.setdefault(norm_principal(a), a)
    for acct in ident.accounts.values():
        if ident._directory_supplier(acct):
            candidates.setdefault(acct.key, acct.display)
    for r in state.principal_rights:
        if r["ptype"] == "supplier":
            candidates.setdefault(norm_principal(r["principal"]), r["principal"])
    mfa_unknown = 0
    unreached = 0
    for key in sorted(candidates):
        name = candidates[key]
        acct = ident.account(name)
        aliases = principal_aliases(name) | (acct.aliases if acct else set())
        rights = []
        for a in sorted(aliases):
            for r in rights_by_key.get(a, []):
                if r not in rights:
                    rights.append(r)
        app_hits = sorted({s.app for a in aliases for s in ident.signin_alias.get(a, []) if s.app and
                           (m.assets.resolve(s.app) in m.patient_data_assets)})
        sup = ident.supplier_of(name)
        declared_patient = bool(sup and any((m.assets.resolve(x) or x) in m.patient_data_assets for x in sup.permitted_assets))
        if not rights and not app_hits and not declared_patient:
            unreached += 1
            continue
        level = max((r["level"] for r in rights), key=lambda x: LEVEL_ORDER[x], default="none")
        reach_basis = ("observation" if any(not r["via_group"] for r in rights) else "inference" if rights else
                       "observation" if app_hits else "inference")
        sql_login = bool(rights) and all(r["login_type"] == "S" for r in rights) and acct is None
        asset, reach_ids = _asset_for(state, rights)
        if not rights and app_hits:
            aid = m.assets.resolve(app_hits[0])
            asset, reach_ids = state.asset_ref(aid, app_hits[0]), [aid]
        elif not rights and declared_patient:
            aid = next((m.assets.resolve(x) or x) for x in sup.permitted_assets if (m.assets.resolve(x) or x) in m.patient_data_assets)
            asset, reach_ids = state.asset_ref(aid, aid), [aid]
        enabled = acct.enabled if acct else (None if not rights else
                                             (False if all(r["enabled"] is False for r in rights) else
                                              True if any(r["enabled"] for r in rights) else None))
        mstat, mbasis, mreason = ident.mfa_status(name, sql_login)
        act, last, abasis = ident.activity(name, directory_account=acct is not None)
        contract = ("unknown" if sup is None else "expired" if sup.contract_end and sup.contract_end < m.as_of.date()
                    else "linked")
        details = {
            "supplier": sup.supplier if sup else None, "supplier_basis": ident.supplier_basis(name),
            "reachable_asset_ids": [x for x in reach_ids if x], "effective_access": level,
            "reach_basis": reach_basis, "derived_via": sorted({v for r in rights for v in r["via"]})[:8],
            "patient_apps_signed_into": app_hits[:5], "mfa": mstat, "mfa_basis": mreason,
            "last_sign_in": last, "activity": act, "activity_basis": abasis,
            "contract": contract, "contract_ref": sup.contract_ref if sup else None,
            "contract_end": sup.contract_end.isoformat() if sup and sup.contract_end else None,
            "permitted_access": sup.permitted if sup else None, "account_enabled": enabled,
        }
        if enabled is False:
            rec.count("A5", "disabled_supplier_accounts_skipped")
            continue
        loc = _loc(name, sup.supplier if sup else None)
        src = state.source_for.get("identity:supplier_register") or state.source_for.get("identity:directory_export")
        ev_unit = "identity:supplier_register" if sup else "identity:directory_export"

        common = {
            "asset": asset, "location": loc, "id_parts": [key], "details": details,
            "source_ids": sorted({x for x in [src] + [state.source_for.get(r["unit"].rsplit(":", 1)[0]) for r in rights] if x}),
            "evidence_ids": [state.evidence(ev_unit, key)], "ownership": state.owner_for(None, asset.get("asset_id")),
        }
        add = functools.partial(_a5, state, common)

        reach_txt = f"{level} access to patient-data store(s) {', '.join(x for x in reach_ids if x)}" if rights else (
            "signs in to a patient-data application" if app_hits else "contract grants access to patient-data assets")
        if mstat == "not_evidenced":
            add("A5.supplier-mfa-missing", "Supplier account reaching patient data without MFA evidence", "high",
                "high" if mbasis == "observation" and "single-factor" in mreason else "medium",
                {"impact": reach_txt, "likelihood": mreason}, mbasis, 0.85 if mbasis == "observation" else 0.6, mreason,
                "enforce-mfa", unit="identity:mfa")
        elif mstat == "unknown":
            mfa_unknown += 1
            add("A5.supplier-mfa-unknown", "MFA status unknown for a supplier account reaching patient data", "high",
                "low", {"impact": reach_txt, "likelihood": f"MFA evidence absent ({mreason}); reported as unknown, not as "
                                                         "disabled"}, "unknown", 0.5, mreason, "enforce-mfa",
                ["Absence of MFA evidence is not evidence that MFA is disabled."], unit="identity:mfa")
        if sup and sup.permitted and LEVEL_ORDER[level] > LEVEL_ORDER[sup.permitted]:
            add("A5.supplier-excess-privilege", "Supplier privileges exceed the contracted access", "high", "medium",
                {"impact": f"effective {level} access versus contracted '{sup.permitted}'",
                 "likelihood": "supplier credentials are used from outside the hospital's control"},
                "observation" if reach_basis == "observation" else "inference", 0.85 if reach_basis == "observation" else 0.6,
                "effective rights from the catalogue compared with the supplier register", "review-supplier-access")
        if sup is None:
            add("A5.supplier-no-contract", "External identity reaching patient data with no contract linkage", "medium",
                "medium", {"impact": reach_txt, "likelihood": "no owner or contract governs this access (contract: unknown)"},
                "inference", 0.6, ident.supplier_basis(name), "link-account-to-contract",
                ["Contract linkage is unknown: the account was not found in the supplier register."])
        elif contract == "expired":
            add("A5.supplier-contract-expired", "Supplier account still enabled after its contract ended", "high",
                "medium", {"impact": reach_txt, "likelihood": f"contract ended {sup.contract_end.isoformat()}"},
                "observation", 0.85, "contract end date in the supplier register", "review-supplier-access")
        if act == "inactive":
            add("A5.supplier-inactive", "Long-inactive supplier account retains access to patient data", "medium",
                "medium", {"impact": reach_txt, "likelihood": abasis}, "observation", 0.8, abasis,
                "disable-or-remove-account", unit="identity:activity")
    rec.count("A5", "supplier_accounts_considered", len(candidates))
    rec.count("A5", "supplier_accounts_without_patient_reach", unreached)
    if mfa_unknown:
        rec.missing_evidence("A5", "identity:mfa", "supplier accounts without MFA evidence (reported as unknown)",
                             mfa_unknown)

    # ---------------------------------------------------------------- A2 identity checks (non-supplier principals)
    seen: set[tuple[str, str]] = set()
    unknown_activity = 0
    for r in sorted(state.principal_rights, key=lambda x: (x["database"], x["key"])):
        if not r["patient"] or r["level"] == "none" or r["ptype"] in ("supplier", "system") or r["enabled"] is False:
            continue
        k = (r["database"], norm_principal(r["principal"]))
        if k in seen:
            continue
        seen.add(k)
        acct = ident.account(r["principal"])
        db = next(d for d in m.databases if d.id == r["database"])
        asset = state.db_asset(db)
        loc = {"type": "database", "database": db.id, "engine": db.engine, "catalog_name": db.name}
        loc.update(principal_location(r["principal"]))
        loc["display"] = scrub_text(f"{db.id} ({db.engine}) principal {loc['principal']}")[:300]
        base = dict(asset=asset, location=loc, source_ids=[x for x in [state.source_for.get(f"db:{db.id}")] if x],
                    ownership=state.owner_for(db.owner, asset.get("asset_id")), detector=DETECTOR)
        details = {"effective_access": r["level"], "derived_via": r["via"], "principal_type": r["ptype"]}
        obsolete_reason = None
        if acct is not None:
            if acct.enabled is False:
                obsolete_reason = "directory account is disabled but its database access remains"
            elif acct.end_date and acct.end_date < m.as_of.date():
                obsolete_reason = f"employment/account end date {acct.end_date.isoformat()} has passed"
        act, last, abasis = ident.activity(r["principal"], directory_account=acct is not None)
        if act == "unknown":
            unknown_activity += 1
        elif act == "inactive" and not obsolete_reason:
            state.add(Finding(control_id="A2", rule_id="A2.dormant-account",
                              title="Dormant account retains access to patient data",
                              impact="high" if r["level"] in ("admin", "write") else "medium", likelihood="medium",
                              rationale={"impact": f"{r['level']} access to patient data", "likelihood": abasis},
                              coverage_unit="identity:activity", id_parts=[db.id, k[1]], basis="observation",
                              confidence=0.8, confidence_reason=abasis, fix_action="disable-or-remove-account",
                              evidence_ids=[state.evidence("identity:signin_export", db.id, k[1])],
                              details={**details, "last_sign_in": last, "observation_window": m.observation_window},
                              **base))
        if acct is not None:
            if obsolete_reason:
                state.add(Finding(control_id="A2", rule_id="A2.obsolete-principal",
                                  title="Obsolete principal (leaver or disabled account) retains database access",
                                  impact="high" if r["level"] in ("admin", "write") else "medium", likelihood="medium",
                                  rationale={"impact": f"{r['level']} access to patient data", "likelihood": obsolete_reason},
                                  coverage_unit="identity:obsolete_principals", id_parts=[db.id, k[1]],
                                  basis="observation", confidence=0.85, confidence_reason=obsolete_reason,
                                  fix_action="disable-or-remove-account",
                                  evidence_ids=[state.evidence("identity:directory_export", db.id, k[1])],
                                  details=details, **base))
            devices = {s.device for a in acct.aliases for s in ident.signin_alias.get(a, []) if s.device}
            if len(devices) >= 5 and r["ptype"] not in ("application", "service", "shared"):
                state.add(Finding(control_id="A2", rule_id="A2.shared-identity",
                                  title="Shared or generic identity with access to patient data",
                                  impact="high" if r["level"] == "admin" else "medium", likelihood="medium",
                                  rationale={"impact": f"{r['level']} access that cannot be attributed to a person",
                                             "likelihood": f"signed in from {len(devices)} distinct devices/clients"},
                                  coverage_unit="identity:activity", id_parts=[db.id, "shared", k[1]], basis="inference",
                                  confidence=0.55, confidence_reason="many distinct devices in the sign-in export",
                                  fix_action="assign-individual-accounts",
                                  evidence_ids=[state.evidence("identity:signin_export", "shared", k[1])],
                                  details=details, **base))
        elif ident.loaded.get("directory_export") and r["login_type"] == "U":
            state.add(Finding(control_id="A2", rule_id="A2.obsolete-principal",
                              title="Windows login not found in the directory export (possibly obsolete)",
                              impact="medium", likelihood="low",
                              rationale={"impact": f"{r['level']} access to patient data",
                                         "likelihood": "account absent from the directory export; it may have been deleted"},
                              coverage_unit="identity:obsolete_principals", id_parts=[db.id, k[1]], basis="inference",
                              confidence=0.5, confidence_reason="absence from an export can also mean the export was filtered",
                              fix_action="disable-or-remove-account",
                              evidence_ids=[state.evidence("identity:directory_export", db.id, k[1])],
                              caveats=["The directory export may be filtered; confirm the account's status."],
                              details=details, **base))
    if unknown_activity:
        rec.missing_evidence("A2", "identity:activity", "principals with patient-data access whose activity is unknown",
                             unknown_activity)
