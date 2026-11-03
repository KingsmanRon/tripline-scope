"""Enterprise profile controls E1–E5 (financial systems), evaluated only when the manifest declares ``enterprise:``.

Healthcare scans never declare that block, so their findings, coverage and reports are unchanged. Each control
needs a specific declared input; when that input is not supplied the control is recorded as *not assessed* with
the reason ("insufficient evidence: ... not supplied"), never as failed and never as passed.

* **E1** privileged access to a financial system without an approved role mapping
  (``entitlements`` × ``role_mappings``);
* **E2** service or supplier accounts with privileges exceeding their declared operational requirement
  (``entitlements`` × ``operational_requirements``);
* **E3** financial data exports or backup copies outside the approved inventory (Module A's own A3 copy and backup
  detections, read-only, × ``data_inventory``) -- E3 sees only copies that A3 recognises;
* **E4** missing security-audit coverage for privileged financial-system operations (``audit_coverage``; a missing
  or ``unknown`` row is *insufficient evidence*, only an explicit ``no`` is a finding);
* **E5** supplier access still enabled after its authorised window (``supplier_access``; a sign-in after the window
  end raises the likelihood and is reported as observed).

Inputs are CSV or JSON exports read with the same bounded reader as the identity inputs; nothing is written,
validated against a live system or changed. Every finding carries the hashes of the inputs it was derived from.
"""

from __future__ import annotations

import datetime as dt
import re

from .identity import _date, _h, read_records
from .model import Finding
from .state import ScanState

DETECTOR = "exposure.enterprise/0.1.0"
CONTROLS = ("E1", "E2", "E3", "E4", "E5")
INPUT_KEYS = ("entitlements", "role_mappings", "operational_requirements", "data_inventory", "audit_coverage",
              "supplier_access")
LEVELS = {"none": 0, "read": 1, "write": 2, "admin": 3}
_LEVEL_ALIASES = {"privileged": "admin", "owner": "admin", "administrator": "admin", "dbo": "admin",
                  "sysadmin": "admin", "readwrite": "write", "modify": "write", "readonly": "read", "view": "read"}
DEFAULT_PRIVILEGED_OPERATIONS = ("privilege_change", "user_administration", "payment_release",
                                 "vendor_master_change", "audit_configuration_change")
DEFAULT_COPY_PATTERNS = (r"ledger", r"payment", r"payable", r"receivable", r"vendor", r"supplier[_\- ]?master",
                         r"payroll", r"journal", r"invoice", r"treasury", r"\beft\b", r"bank[_\- ]?(?:file|recon)",
                         r"general[_\- ]?ledger", r"\bgl[_\-]", r"\berp\b", r"finance")
_YES = {"yes", "y", "true", "1", "enabled", "on"}
_NO = {"no", "n", "false", "0", "disabled", "off"}


def _level(v) -> str | None:
    if v in (None, ""):
        return None
    s = re.sub(r"[^a-z]", "", str(v).lower())
    s = _LEVEL_ALIASES.get(s, s)
    return s if s in LEVELS else None


def _yn(v) -> bool | None:
    s = str(v or "").strip().lower()
    return True if s in _YES else False if s in _NO else None


def _acct(v) -> str | None:
    if v in (None, ""):
        return None
    a = str(v).strip().lower()
    return a.split("\\", 1)[1] if "\\" in a else a


def _pick(row: dict, *names):
    for n in names:
        if row.get(n) not in (None, ""):
            return row[n]
    return None


class EnterpriseInputs:
    """Loads the declared enterprise inputs (bounded); records parse failures as *unavailable*."""

    def __init__(self, state: ScanState):
        self.state = state
        self.decl = state.m.enterprise
        self.rows: dict[str, list[dict]] = {}
        self.failed: set[str] = set()

    def load(self) -> None:
        rec = self.state.rec
        for key in INPUT_KEYS:
            p = self.decl.inputs.get(key)
            if p is None:
                continue
            try:
                self.rows[key] = read_records(p, self.state.m.budget["max_file_bytes"])
            except Exception as exc:  # noqa: BLE001 - only the class is recorded
                self.failed.add(key)
                rec.parser_failure("enterprise", f"enterprise:{key}", key, type(exc).__name__)
                rec.unavail(_controls_for(key), f"enterprise:{key}", f"input could not be read ({type(exc).__name__})")

    def have(self, *keys) -> bool:
        return all(k in self.rows for k in keys)


def _controls_for(key: str) -> tuple:
    return {"entitlements": ("E1", "E2"), "role_mappings": ("E1",), "operational_requirements": ("E2",),
            "data_inventory": ("E3",), "audit_coverage": ("E4",), "supplier_access": ("E5",)}[key]


def _hashes(state: ScanState, *keys) -> dict:
    return {k: state.input_sha256.get(f"enterprise:{k}") for k in keys if state.input_sha256.get(f"enterprise:{k}")}


def _sources(state: ScanState, *keys) -> list[str]:
    return sorted({state.source_for[f"enterprise:{k}"] for k in keys if state.source_for.get(f"enterprise:{k}")})


def _finding(state, ctl, rule, title, impact, likelihood, rationale, asset_id, principal, unit, parts, basis, conf,
             reason, fix, keys, details, caveats=()) -> Finding:
    m = state.m
    loc = {"type": "identity" if principal else "asset", "display": (f"account {principal} on {asset_id}"
                                                                      if principal else f"asset {asset_id}")[:300]}
    if principal:
        loc["principal"] = principal
    f = Finding(control_id=ctl, rule_id=rule, title=title, impact=impact, likelihood=likelihood, rationale=rationale,
                asset=state.asset_ref(asset_id, asset_id), location=loc, coverage_unit=unit, id_parts=list(parts),
                basis=basis, confidence=conf, confidence_reason=reason, fix_action=fix,
                source_ids=_sources(state, *keys),
                evidence_ids=[state.evidence(f"enterprise:{keys[0]}", *parts)],
                caveats=list(caveats), details=dict(details, source_sha256=_hashes(state, *keys),
                                                    financial_asset=asset_id in m.enterprise.financial_assets),
                ownership=state.owner_for(None, asset_id), detector=DETECTOR)
    return state.add(f)


def analyse_enterprise(state: ScanState) -> None:
    m, rec = state.m, state.rec
    if m.enterprise is None:
        return
    inp = EnterpriseInputs(state)
    inp.load()
    fin = set(m.enterprise.financial_assets)
    resolve = m.assets.resolve
    ents = []
    for r in inp.rows.get("entitlements", []):
        asset = resolve(str(_pick(r, "asset", "assetid", "system") or "")) or _pick(r, "asset", "assetid", "system")
        ents.append({"account": _acct(_pick(r, "account", "principal", "user", "login")), "asset": asset,
                     "role": str(_pick(r, "role", "group", "entitlement") or "")[:80] or None,
                     "level": _level(_pick(r, "privilege", "level", "access")),
                     "type": str(_pick(r, "accounttype", "type") or "user").strip().lower()})
    fin_ents = [e for e in ents if e["account"] and e["asset"] in fin]

    # ------------------------------------------------------------------ E1
    if not inp.have("entitlements", "role_mappings"):
        missing = [k for k in ("entitlements", "role_mappings") if k not in inp.rows and k not in inp.failed]
        if missing:
            rec.not_assess("E1", "enterprise:role_mappings", "insufficient evidence: " + ", ".join(missing)
                           + " not supplied")
    else:
        approved = set()
        for r in inp.rows["role_mappings"]:
            a = resolve(str(_pick(r, "asset", "assetid", "system") or "")) or _pick(r, "asset", "assetid", "system")
            if _pick(r, "approvedby", "approver") and _acct(_pick(r, "account", "principal", "user")):
                approved.add((_acct(_pick(r, "account", "principal", "user")), a,
                              str(_pick(r, "role", "group") or "").lower() or None))
        n = 0
        for e in fin_ents:
            if e["level"] != "admin":
                continue
            n += 1
            role = (e["role"] or "").lower() or None
            if (e["account"], e["asset"], role) in approved or (role is None and any(
                    a == e["account"] and s == e["asset"] for a, s, _ in approved)):
                continue
            _finding(state, "E1", "E1.privileged-unmapped", "Privileged access to a financial system without an approved "
                     "role mapping", "high", "high" if e["type"] in ("service", "supplier") else "medium",
                     {"impact": f"{e['level']} access to financial system {e['asset']}",
                      "likelihood": "no approved role-mapping entry covers this privileged entitlement"},
                     e["asset"], e["account"], "enterprise:role_mappings", [e["account"], e["asset"], role],
                     "observation", 0.85, "entitlement export compared with the approved role-mapping register",
                     "map-or-remove-privileged-access", ("entitlements", "role_mappings"),
                     {"role": e["role"], "effective_access": e["level"], "account_type": e["type"]},
                     ["The mapping register may be incomplete; confirm with the system owner before removing access."])
        rec.assess("E1", "enterprise:role_mappings", f"{n} privileged financial-system entitlements compared")
        rec.count("E1", "privileged_entitlements", n)

    # ------------------------------------------------------------------ E2
    if not inp.have("entitlements", "operational_requirements"):
        missing = [k for k in ("entitlements", "operational_requirements") if k not in inp.rows and k not in inp.failed]
        if missing:
            rec.not_assess("E2", "enterprise:operational_requirements", "insufficient evidence: "
                           + ", ".join(missing) + " not supplied")
    else:
        req = {}
        for r in inp.rows["operational_requirements"]:
            a = resolve(str(_pick(r, "asset", "assetid", "system") or "")) or _pick(r, "asset", "assetid", "system")
            req[(_acct(_pick(r, "account", "principal", "user")), a)] = (
                _level(_pick(r, "maxprivilege", "requiredprivilege", "maximum", "required")),
                str(_pick(r, "justification", "purpose") or "")[:160] or None)
        n = 0
        for e in fin_ents:
            if e["type"] not in ("service", "supplier") or e["level"] is None:
                continue
            n += 1
            mx, why = req.get((e["account"], e["asset"]), (None, None))
            parts = [e["account"], e["asset"]]
            if (e["account"], e["asset"]) not in req:
                _finding(state, "E2", "E2.requirement-undeclared", f"{e['type'].capitalize()} account on a financial "
                         "system has no declared operational requirement", "medium", "medium",
                         {"impact": f"{e['level']} access to {e['asset']}",
                          "likelihood": "the requirement register has no entry for this account and system"},
                         e["asset"], e["account"], "enterprise:operational_requirements", parts, "observation", 0.7,
                         "entitlement export compared with the operational-requirement register",
                         "align-privileges-to-requirement", ("entitlements", "operational_requirements"),
                         {"effective_access": e["level"], "account_type": e["type"], "declared_maximum": None})
            elif mx is not None and LEVELS[e["level"]] > LEVELS[mx]:
                _finding(state, "E2", "E2.exceeds-requirement", f"{e['type'].capitalize()} account privileges exceed "
                         "its declared operational requirement", "high", "high" if e["type"] == "supplier" else "medium",
                         {"impact": f"effective {e['level']} versus declared maximum {mx} on {e['asset']}",
                          "likelihood": "excess rights on a non-personal account are used without an accountable "
                                        "person"}, e["asset"], e["account"], "enterprise:operational_requirements",
                         parts, "observation", 0.9, "entitlement compared with the declared maximum",
                         "align-privileges-to-requirement", ("entitlements", "operational_requirements"),
                         {"effective_access": e["level"], "declared_maximum": mx, "justification": why,
                          "account_type": e["type"]})
        rec.assess("E2", "enterprise:operational_requirements", f"{n} service/supplier entitlements compared")
        rec.count("E2", "service_or_supplier_entitlements", n)

    # ------------------------------------------------------------------ E3
    if "data_inventory" not in inp.rows:
        if "data_inventory" not in inp.failed:
            rec.not_assess("E3", "enterprise:data_inventory", "insufficient evidence: data_inventory not supplied")
    elif not m.roots:
        rec.not_assess("E3", "enterprise:data_inventory", "no snapshot roots declared: no copies could be observed")
    else:
        inv = [(str(_pick(r, "root", "rootid") or ""), str(_pick(r, "pathprefix", "path", "location") or "").strip("/"))
               for r in inp.rows["data_inventory"]]
        pats = [re.compile(p, re.I) for p in (m.enterprise.copy_patterns or DEFAULT_COPY_PATTERNS)]
        n_fin, n_inv = 0, 0
        for f in list(state.findings.values()):
            if f.control_id != "A3":
                continue
            path = str(f.location.get("path") or "")
            target = (f.target_asset or {}).get("asset_id") if f.target_asset else None
            is_fin = target in fin or any(p.search(path) for p in pats)
            if not is_fin:
                continue
            n_fin += 1
            root = f.location.get("root")
            if any(root == r and (not pre or path.startswith(pre)) for r, pre in inv):
                n_inv += 1
                continue
            g = _finding(state, "E3", "E3.copy-outside-inventory", "Financial data copy or backup outside the approved "
                         "inventory", "high" if f.impact == "high" or target in fin else "medium", f.likelihood,
                         {"impact": "copy of financial-system data (" + ("backup of " + target if target else
                                    "name matches a financial-data pattern") + ")",
                          "likelihood": "location is not in the approved data inventory; " + f.rationale.get("likelihood", "")},
                         (f.asset or {}).get("asset_id") or target, None, "enterprise:data_inventory",
                         [root, path, f.location.get("member")], f.basis, min(f.confidence, 0.85),
                         "Module A copy/backup detection compared with the approved inventory",
                         "inventory-or-remove-financial-copy", ("data_inventory",),
                         {"root": root, "path": path, "a3_finding": f.finding_id, "a3_rule": f.rule_id,
                          "target_asset": target},
                         ["Only copies that Module A's A3 detector recognises are considered.",
                          "Financial relevance is inferred from the target asset or the file name."])
            g.related_findings = sorted(set(g.related_findings) | {f.finding_id})
            f.related_findings = sorted(set(f.related_findings) | {g.finding_id})
        rec.assess("E3", "enterprise:data_inventory", f"{n_fin} financial copies considered, {n_inv} inventoried")
        rec.count("E3", "financial_copies_considered", n_fin)
        rec.count("E3", "financial_copies_inventoried", n_inv)

    # ------------------------------------------------------------------ E4
    if "audit_coverage" not in inp.rows:
        if "audit_coverage" not in inp.failed:
            rec.not_assess("E4", "enterprise:audit_coverage", "insufficient evidence: audit_coverage not supplied")
    else:
        ops = tuple(m.enterprise.privileged_operations or DEFAULT_PRIVILEGED_OPERATIONS)
        cov = {}
        for r in inp.rows["audit_coverage"]:
            a = resolve(str(_pick(r, "asset", "assetid", "system") or "")) or _pick(r, "asset", "assetid", "system")
            cov[(a, _h(_pick(r, "operation", "operationcategory") or ""))] = _yn(_pick(r, "audited", "enabled"))
        assessed = 0
        for asset in sorted(fin):
            for op in ops:
                v = cov.get((asset, _h(op)))
                unit = f"enterprise:audit_coverage:{asset}:{op}"
                if v is None:
                    rec.not_assess("E4", unit, "insufficient evidence: no explicit audit-coverage record for this "
                                               "operation (missing or 'unknown')", location=f"{asset} {op}")
                    continue
                assessed += 1
                rec.assess("E4", unit, "audit coverage declared")
                if v is False:
                    _finding(state, "E4", "E4.audit-not-enabled", "Privileged financial-system operation is not audited",
                             "high", "medium",
                             {"impact": f"{op} on {asset} would leave no security-audit record",
                              "likelihood": "the audit-coverage record states the operation is not audited"},
                             asset, None, unit, [asset, op], "observation", 0.85,
                             "explicit 'not audited' entry in the audit-coverage export", "audit-privileged-financial-operations",
                             ("audit_coverage",), {"operation": op},
                             ["Coverage as declared by the system owner; the system itself was not inspected."])
        rec.count("E4", "operation_checks_assessed", assessed)

    # ------------------------------------------------------------------ E5
    if "supplier_access" not in inp.rows:
        if "supplier_access" not in inp.failed:
            rec.not_assess("E5", "enterprise:supplier_access", "insufficient evidence: supplier_access not supplied")
    else:
        as_of = m.as_of.date() if isinstance(m.as_of, dt.datetime) else m.as_of
        reach = {e["account"]: e for e in fin_ents}
        n, unknown = 0, 0
        for r in inp.rows["supplier_access"]:
            acct = _acct(_pick(r, "account", "principal", "user"))
            end = _date(_pick(r, "windowend", "accessend", "end"))
            enabled = _yn(_pick(r, "enabled", "accountenabled", "status"))
            last = _date(_pick(r, "lastsignin", "lastlogon", "lastsignindate"))
            if not acct:
                continue
            n += 1
            if end is None or enabled is None:
                unknown += 1
                rec.not_assess("E5", f"enterprise:supplier_access:{acct}", "insufficient evidence: window end or "
                                                                            "enabled state not recorded")
                continue
            if enabled and end < as_of:
                e = reach.get(acct)
                asset = e["asset"] if e else (sorted(fin)[0] if fin else None)
                after = bool(last and last > end)
                _finding(state, "E5", "E5.supplier-window-exceeded", "Supplier access still enabled after its authorised "
                         "window" + (" (sign-in recorded after the window)" if after else ""),
                         "high" if e else "medium", "high" if after else "medium",
                         {"impact": (f"{e['level']} access to financial system {e['asset']}" if e else
                                     "supplier account with no financial-system entitlement in the export"),
                          "likelihood": (f"sign-in on {last.isoformat()} after the window ended {end.isoformat()}"
                                         if after else f"authorised window ended {end.isoformat()}")},
                         asset, acct, "enterprise:supplier_access", [acct], "observation", 0.9,
                         "supplier access register (window end, enabled state, last sign-in)", "end-supplier-access-window",
                         ("supplier_access",) + (("entitlements",) if e else ()),
                         {"supplier": str(_pick(r, "supplier", "company") or "")[:80] or None,
                          "window_end": end.isoformat(), "last_sign_in": last.isoformat() if last else None,
                          "sign_in_after_window": after})
        rec.assess("E5", "enterprise:supplier_access", f"{n} supplier access records compared"
                   + (f"; {unknown} lacked a window end or enabled state" if unknown else ""))
        rec.count("E5", "supplier_access_records", n)
