"""Urgent containment recommendations: advisory only.

Every recommendation names its evidence (event/path/anomaly ids), its basis and confidence, and carries
``requires_hospital_authorisation: true`` and ``executed: false``. Tripline Scope performs no containment
action of any kind: it does not disable accounts, rotate credentials, block addresses or change configuration.
Recommendations are cross-referenced to a Module A exposure report when one is supplied (by ``finding_id``,
``asset_id`` and ``location.principal``; never by secret values).
"""

from __future__ import annotations

import json
from pathlib import Path

from tripline_scope.core.canonical import sha256_hex
from tripline_scope.core.errors import ConfigError

from .config import account_matches
from .display import Display, safe_text
from .util import acct_key, stable_id

URGENCY = ["critical", "high", "medium", "low"]
NOTICE = ("Advisory only. Each recommendation requires authorisation by the hospital before anyone acts on it. "
          "Tripline Scope executes no containment action (it does not disable accounts, rotate credentials, block "
          "addresses or change systems).")


def load_exposure_report(path: str | None) -> dict | None:
    """Module A's released exposure report (``report.json`` or its version directory)."""
    if not path:
        return None
    p = Path(path)
    if p.is_dir():
        p = p / "report.json"
    if not p.is_file():
        raise ConfigError("exposure report not found")
    data = p.read_bytes()
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ConfigError("exposure report is not JSON") from exc
    if doc.get("kind") not in (None, "exposure"):
        raise ConfigError("the given report is not an exposure report")
    released = (p.parent / "release.json").is_file()
    return {"sha256": sha256_hex(data), "version": doc.get("version"), "released": released,
            "findings": [f for f in doc.get("findings", []) if isinstance(f, dict)]}


def _finding_ref(f: dict) -> dict:
    return {"finding_id": f.get("finding_id"), "control_id": f.get("control_id"), "asset_id": f.get("asset_id"),
            "severity": f.get("severity"), "state": f.get("state"), "title": safe_text(f.get("title"), 120)}


def build(analysis: dict, disp: Display, cfg: dict, exposure: dict | None) -> dict:
    recs: dict[str, dict] = {}
    units = {u["unit_id"]: u for u in analysis["units"]}
    anomalies = {x["anomaly_id"]: x for x in analysis["anomalies"]}
    host_asset = {}
    for s in analysis["inputs"].values():
        if s.get("host") and s.get("asset_id"):
            host_asset[str(s["host"]).lower().split(".")[0]] = s["asset_id"]
    findings = (exposure or {}).get("findings", [])

    def module_a(asset=None, account=None, controls=None):
        out = []
        for f in findings:
            if controls and f.get("control_id") not in controls:
                continue
            principal = ((f.get("location") or {}).get("principal") if isinstance(f.get("location"), dict) else None)
            if asset and f.get("asset_id") == asset:
                out.append(_finding_ref(f))
            elif account and principal and acct_key(principal, cfg["directory_domains"]) == acct_key(account, cfg["directory_domains"]):
                out.append(_finding_ref(f))
        return sorted(out, key=lambda x: str(x["finding_id"]))

    def add(category, key, action, urgency, *, target, evidence, paths=(), anomalies_=(), basis="observation",
            confidence=0.9, rationale="", caveats=(), refs=()):
        rid = stable_id("REC", category, key)
        r = recs.get(rid)
        if r is None:
            r = recs[rid] = {"rec_id": rid, "category": category, "action": action, "urgency": urgency,
                             "target": target, "rationale": rationale, "basis": basis, "confidence": round(confidence, 3),
                             "evidence_ids": [], "path_ids": [], "anomaly_ids": [], "module_a_refs": [],
                             "caveats": list(caveats), "requires_hospital_authorisation": True, "executed": False}
        if URGENCY.index(urgency) < URGENCY.index(r["urgency"]):
            r["urgency"] = urgency
        r["confidence"] = max(r["confidence"], round(confidence, 3))
        r["evidence_ids"] = sorted(set(r["evidence_ids"]) | set(evidence))[:30]
        r["path_ids"] = sorted(set(r["path_ids"]) | set(paths))
        r["anomaly_ids"] = sorted(set(r["anomaly_ids"]) | set(anomalies_))
        seen = {x["finding_id"] for x in r["module_a_refs"]}
        r["module_a_refs"] += [x for x in refs if x["finding_id"] not in seen]

    for p in analysis["paths"]:
        cls = p["consequence_class"]
        anoms = [anomalies[a] for a in p["anomalies"] if a in anomalies]
        sev = {a["severity"] for a in anoms}
        if cls == "access_observed" and "high" not in sev and not (p["anomalies"] and not p["service_account"]):
            continue
        urgency = ("critical" if cls in ("egress_suspected", "exfiltration_evidenced") else
                   "high" if cls == "export_or_staging_observed" or "high" in sev else "medium")
        acct = p["route"]["account"]
        ev = p["claim"]["evidence_ids"][:10]
        host = p["route"]["host"]
        asset = host_asset.get(host or "")
        if acct:
            add("accounts_to_review", acct, "Review this account's activity with its owner and, if it was not "
                "authorised, disable or suspend it.", urgency, target={"kind": "account", **disp.account(acct)},
                evidence=ev, paths=[p["path_id"]], anomalies_=p["anomalies"], confidence=p["confidence"],
                rationale=f"database route with outcome {cls}", refs=module_a(account=acct))
            if cls != "access_observed" or "high" in sev:
                add("credentials_to_rotate", acct, "Reset/rotate this account's credentials and revoke its sessions "
                    "after review.", urgency, target={"kind": "account", **disp.account(acct)}, evidence=ev,
                    paths=[p["path_id"]], anomalies_=p["anomalies"], confidence=p["confidence"],
                    rationale="account used on a route with export/egress or high-severity anomalies",
                    refs=module_a(account=acct, controls={"A1", "A2"}))
        for ua in p["upstream_accounts"]:
            if acct_key(ua, cfg["directory_domains"]) == acct_key(acct, cfg["directory_domains"]):
                continue
            add("accounts_to_review", ua, "Review this identity/VPN account linked upstream of the route (link "
                "label shown in the path) and, if not authorised, disable it.", urgency,
                target={"kind": "account", **disp.account(ua)}, evidence=ev, paths=[p["path_id"]], basis="inference",
                confidence=p["chain_confidence"], rationale="linked upstream of a sensitive-data route",
                caveats=["the upstream link may be correlated (an inference), see the path stages"])
        for st in p["stages"]:
            if st["stage"] == "network" and st["label"] in ("direct", "correlated") and cls != "access_observed":
                add("access_paths_to_close", f"vpn-db:{host}", "Restrict VPN address pools from reaching database "
                    "ports directly; require a managed jump host for database administration.", urgency,
                    target={"kind": "route", "description": f"VPN clients -> database host {host}", "asset_id": asset},
                    evidence=ev, paths=[p["path_id"]], basis="inference", confidence=st["confidence"],
                    rationale="database access from a VPN-assigned address", refs=module_a(asset=asset, controls={"A2", "A4", "A5"}))
        for dest in p["egress_destinations"]:
            ind = any(m["indicator_value"] == dest for m in analysis["indicator_matches"])
            add("addresses_to_investigate", f"dest:{dest}", "Investigate this outbound destination and, if the "
                "hospital authorises it, block it at the perimeter/proxy; preserve firewall and proxy records.",
                "critical" if ind else urgency, target={"kind": "address", "value": dest}, evidence=ev,
                paths=[p["path_id"]], basis="inference", confidence=0.6 if ind else 0.5,
                rationale="outbound flow after export/staging" + ("; matches a partner indicator" if ind else ""),
                caveats=["traffic content and the records carried are unknown",
                         "an indicator match is not attribution"])
        for a in anoms:
            if a["detector"] == "dump_export" and any(units.get(u, {}).get("flags") and "xp_cmdshell" in units[u]["flags"]
                                                      for u in a["unit_ids"]):
                add("access_paths_to_close", f"xp_cmdshell:{host}", "Disable xp_cmdshell and review who can enable it; "
                    "remove staged export files after evidence is preserved.", urgency,
                    target={"kind": "configuration", "description": f"xp_cmdshell on {host}", "asset_id": asset},
                    evidence=a["evidence_ids"][:10], paths=[p["path_id"]], anomalies_=[a["anomaly_id"]],
                    rationale="exports were run through xp_cmdshell", refs=module_a(asset=asset, controls={"A4"}))
    for a in analysis["anomalies"]:
        if a["detector"] == "auditing_disabled":
            add("access_paths_to_close", f"audit:{a['details'].get('scope')}", "Restore and protect audit configuration "
                "(restrict ALTER ... AUDIT / log clearing rights, alert on audit changes, forward logs off-host).",
                "high", target={"kind": "configuration", "description": f"auditing for {a['details'].get('scope')}"},
                evidence=a["evidence_ids"], anomalies_=[a["anomaly_id"]], rationale=a["claim"]["statement"])
            for acct in a["accounts"]:
                add("accounts_to_review", acct, "Review this account's activity with its owner and, if it was not "
                    "authorised, disable or suspend it.", "high", target={"kind": "account", **disp.account(acct)},
                    evidence=a["evidence_ids"], anomalies_=[a["anomaly_id"]], rationale="switched auditing off or "
                    "cleared a security log")
        elif a["detector"] == "privilege_grant":
            for acct in a["accounts"]:
                add("credentials_to_rotate", acct, "Revoke rights granted during the incident window unless approved, "
                    "and rotate the account's credentials.", "high" if a["severity"] == "high" else "medium",
                    target={"kind": "account", **disp.account(acct)}, evidence=a["evidence_ids"],
                    anomalies_=[a["anomaly_id"]], rationale=a["claim"]["statement"])
        elif a["detector"] == "web_admin_before_db":
            ips = sorted({units[u]["client_ip"] for u in a["unit_ids"] if u in units and units[u].get("client_ip")})
            paths_ = sorted(set(a.get("path_ids", [])))
            add("access_paths_to_close", f"web-admin:{a['unit_ids'][0] if a['unit_ids'] else ''}",
                "Restrict administrative and upload paths of the web application to internal networks; have the "
                "web server examined for uploaded scripts (host forensics).", "high" if a["severity"] == "high" else "medium",
                target={"kind": "route", "description": "external access to web admin/upload paths"},
                evidence=a["evidence_ids"], paths=paths_, anomalies_=[a["anomaly_id"]], basis=a["claim"]["basis"],
                confidence=a["claim"]["confidence"], rationale=a["claim"]["statement"])
            for ip in ips:
                shared = ip in analysis["shared_ips"]
                add("addresses_to_investigate", f"src:{ip}", "Investigate this source address" +
                    ("" if shared else " and, if the hospital authorises it, block it at the perimeter") + ".",
                    "high" if a["severity"] == "high" else "medium", target={"kind": "address", "value": ip},
                    evidence=a["evidence_ids"], anomalies_=[a["anomaly_id"]], basis="observation",
                    rationale="external address issued admin/upload requests",
                    caveats=[f"shared address ({analysis['shared_ips'][ip]} accounts): blocking would affect other "
                             "users"] if shared else [])
    for p in analysis["paths"]:
        if p["consequence_class"] in ("egress_suspected", "exfiltration_evidenced") or any(
                anomalies.get(x, {}).get("severity") == "high" for x in p["anomalies"]):
            for st in p["stages"]:
                if st["stage"] == "network" and st["label"] != "unresolved":
                    for uid in st["units"]:
                        u = units.get(uid)
                        if u and u.get("public_ip"):
                            ip = u["public_ip"]
                            shared = ip in analysis["shared_ips"]
                            add("addresses_to_investigate", f"src:{ip}", "Investigate this VPN source address" +
                                ("" if shared else " and, if the hospital authorises it, block it") + ".", "high",
                                target={"kind": "address", "value": ip}, evidence=u["evidence_ids"][:5],
                                paths=[p["path_id"]], basis="inference", confidence=st["confidence"],
                                rationale="VPN session linked to a high-impact route",
                                caveats=[f"shared address ({analysis['shared_ips'][ip]} accounts)"] if shared else [])
    service = [r for r in recs.values() if r["target"].get("kind") == "account"
               and account_matches(r["target"].get("label"), cfg["service_accounts"])]
    for r in service:
        r["caveats"].append("service account: coordinate with the application owner before any change")
    out = sorted(recs.values(), key=lambda r: (URGENCY.index(r["urgency"]), -r["confidence"], -len(r["evidence_ids"]),
                                              r["rec_id"]))
    for i, r in enumerate(out, 1):
        r["rank"] = i
    return {"notice": NOTICE, "recommendations": out,
            "module_a": ({"status": "cross-referenced", "report_sha256": exposure["sha256"],
                          "report_version": exposure["version"], "released": exposure["released"],
                          "findings_considered": len(findings)} if exposure else
                         {"status": "not supplied", "note": "no Module A exposure report was given (--exposure-report)"})}
