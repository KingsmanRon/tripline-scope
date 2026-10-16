"""Anomaly detectors. Each exposes its assumptions, the baseline it used (or why it was not applied) and its
false-positive caveats; findings are leads for investigators, never conclusions.

Detectors: first-seen sensitive access (within known historical coverage), bulk reads against a measured
per-table baseline (only where row counts are logged), off-hours access per the hospital's configured hours,
dump/export commands, newly granted rights, auditing disabled / logs cleared, new source locations (sign-in
country, VPN address, database client/application) and web admin/upload requests preceding database access.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from zoneinfo import ZoneInfo

from tripline_scope.core.evidence import Basis, Claim, Consequence, TimePrecision

from .config import account_matches, norm_table
from .schema import DB_FAMILIES
from .util import iso, stable_id

VERSION = "1.0"
SEVERITY_WEIGHT = {"high": 20, "medium": 8, "low": 2}

INFO = {
    "first_seen_sensitive_access": {
        "description": "An account accessed a sensitive table it had not accessed during the baseline period.",
        "assumptions": ["baseline period has database audit coverage for the table's source",
                        "account names compared case-insensitively after removing the domain prefix"],
        "false_positive_caveats": ["new staff, new duties, rare reports or month-end work",
                                   "baseline shorter than the account's normal cycle"]},
    "bulk_read": {
        "description": "Rows returned by one statement far exceed the table's measured baseline.",
        "assumptions": ["threshold = max(min_rows, factor x 95th percentile of rows per statement in the baseline)",
                        "applies only where the log records rows (volume unknown otherwise)"],
        "false_positive_caveats": ["legitimate reports, migrations and data-quality jobs",
                                   "rows returned are per statement, not distinct patient records"]},
    "off_hours": {
        "description": "Sensitive-table access by a non-service account outside the hospital's configured hours.",
        "assumptions": ["hospital_hours from case.yaml; service_accounts are exempt"],
        "false_positive_caveats": ["laboratories run 24/7; on-call and shift staff work at night",
                                   "clock offsets near the boundary"]},
    "dump_export": {
        "description": "Dump, export, backup, bcp/COPY TO, SELECT INTO or file staging was observed.",
        "assumptions": ["export commands are recognised from statements, audit action ids and file writes with "
                        "configured staging extensions"],
        "false_positive_caveats": ["scheduled backups and approved extracts (declare them as known_jobs)",
                                   "file names and contents are not inspected"]},
    "privilege_grant": {
        "description": "Rights were granted, role/group membership added or accounts created/changed.",
        "assumptions": ["recognised from GRANT/role statements, audit actions and Windows 4720/4728/4732/4756..."],
        "false_positive_caveats": ["routine administration and joiner/mover changes"]},
    "auditing_disabled": {
        "description": "Auditing was switched off or a security log was cleared.",
        "assumptions": ["the gap lasts until a matching re-enable event, else to the end of coverage"],
        "false_positive_caveats": ["maintenance windows and audit reconfiguration"]},
    "new_source_location": {
        "description": "Sign-in country, VPN public address or database client/application not seen for the "
                       "account during the baseline.",
        "assumptions": ["only accounts with baseline activity are compared",
                        "VPN public addresses are compared as IPv4 /16 ranges; sign-ins by exported country"],
        "false_positive_caveats": ["travel, new devices, ISP address changes, new tools"]},
    "web_admin_before_db": {
        "description": "Admin/upload requests or a never-before-seen script resource on a web server, with the "
                       "database access they precede when linked by edges.",
        "assumptions": ["admin paths from web_admin_patterns; new scripts = script extensions first seen in the window"],
        "false_positive_caveats": ["administrators using the portal; deployments of new pages",
                                   "a web shell is not confirmed without host evidence"]},
}


def _claim(aid, statement, basis, a, u_list, *, obs, cls, conf, reason, lim=None, caveats=None) -> dict:
    ev = [e for u in u_list for e in u["events"][:5]][:30]
    starts = [u["start"] for u in u_list if u["start"]]
    ends = [u["end"] for u in u_list if u["end"]]
    return Claim(claim_id=aid, statement=statement, basis=basis, source_ids=sorted({u["source_id"] for u in u_list}),
                 evidence_ids=ev, parser=f"detector/{VERSION}", time_precision=TimePrecision.SECOND,
                 confidence=conf, confidence_reason=reason, observation_type=obs, consequence_class=cls,
                 source_time_window=[iso(min(starts)) if starts else None, iso(max(ends)) if ends else None],
                 limitations=lim or [], caveats=caveats or []).to_dict()


def _anomaly(det, title, severity, units, claim, **details) -> dict:
    info = INFO[det]
    accts = sorted({u["account"] for u in units if u.get("account")})
    return {"anomaly_id": claim["claim_id"], "detector": det, "detector_version": VERSION, "title": title,
            "severity": severity, "unit_ids": sorted(u["unit_id"] for u in units), "accounts": accts,
            "evidence_ids": claim["evidence_ids"], "first": claim["source_time_window"][0],
            "last": claim["source_time_window"][1], "claim": claim, "details": details,
            "assumptions": info["assumptions"], "false_positive_caveats": info["false_positive_caveats"]}


def _baseline_cover(a) -> dict[str, float]:
    """Seconds of baseline coverage per source."""
    out = {}
    for sid, ivs in a.source_cover.items():
        s = 0.0
        for x, y in ivs:
            lo, hi = max(x, a.b0), min(y, a.b1)
            if hi > lo:
                s += (hi - lo).total_seconds()
        out[sid] = s
    return out


def run_all(a) -> tuple[list[dict], dict]:
    anomalies: list[dict] = []
    info = {}
    db_units = [u for u in a.units.values() if u["type"] == "db_session"]
    bcov = _baseline_cover(a)
    min_s = float(a.cfg["baseline"].get("min_days", 3)) * 86400
    base_ok = {sid for sid, s in bcov.items() if s >= min_s}
    fams = ",".join(f"'{f}'" for f in DB_FAMILIES)
    bw = [a.b0, a.b1]

    # ---------------------------------------------------------------- first-seen sensitive access
    rows = a.q(f"SELECT DISTINCT account, unnest(objects) AS o, database, source_id FROM ev WHERE source_family IN ({fams}) "
               "AND consequence_class IN ('access_observed','export_or_staging_observed') AND ts_utc >= ? AND ts_utc < ?", bw)
    seen = set()
    for r in rows:
        o = r["o"]
        full = o if o.count(".") >= 2 or not r["database"] else f"{r['database']}.{o}"
        seen.add((a._key(r["account"]), norm_table(full)))
    groups = defaultdict(lambda: {"units": [], "tables": set()})
    skipped = 0
    for u in db_units:
        if u["source_id"] not in base_ok:
            skipped += 1
            continue
        new = [t["table"] for k, t in u["tables"].items() if a.sensitive.matches(k) and (u["acct_key"], k) not in seen]
        if new:
            g = groups[(u["acct_key"], u["source_id"])]
            g["units"].append(u)
            g["tables"] |= set(new)
    for (ak, sid), g in sorted(groups.items(), key=lambda x: (x[0][0] or "", x[0][1])):
        aid = stable_id("ANOM", "first_seen", ak, sid)
        c = _claim(aid, f"First-seen access to {len(g['tables'])} sensitive table(s) by an account with no such access in "
                   "the baseline period.", Basis.INFERENCE, a, g["units"], obs="first_seen_access",
                   cls=Consequence.ACCESS_OBSERVED, conf=0.7, reason="comparison with the covered baseline period")
        anomalies.append(_anomaly("first_seen_sensitive_access", "First-seen sensitive table access", "medium",
                                  g["units"], c, tables=sorted(g["tables"])))
    info["first_seen_sensitive_access"] = {**INFO["first_seen_sensitive_access"], "status": "applied" if base_ok else
                                           "not_assessed: no source has the minimum baseline coverage",
                                           "baseline": {"start": iso(a.b0), "end": iso(a.b1), "sources": sorted(base_ok),
                                                        "min_days": a.cfg["baseline"].get("min_days", 3)},
                                           "sessions_without_baseline_coverage": skipped}

    # ---------------------------------------------------------------- bulk reads
    br = a.cfg["bulk_read"]
    base = a.q(f"SELECT lower(o) AS t, quantile_cont(rows, 0.95) AS p95, count(*) AS n FROM (SELECT unnest(objects) AS o, "
               f"rows FROM ev WHERE source_family IN ({fams}) AND observation_type = 'select' AND rows IS NOT NULL "
               "AND outcome != 'failure' AND ts_utc >= ? AND ts_utc < ?) GROUP BY 1", bw)
    thresholds = {r["t"]: max(float(br["min_rows"]), float(br["factor"]) * float(r["p95"] or 0)) for r in base if r["n"] >= 20}
    flagged, unknown_volume = defaultdict(list), defaultdict(int)
    for u in db_units:
        for k, t in u["tables"].items():
            if not a.sensitive.matches(k) or "select" not in t["observations"]:
                continue
            if t["select_rows_unknown"]:
                unknown_volume[t["table"]] += 1
                continue
            thr = thresholds.get(k)
            if thr is not None and t["select_statements"] and t["select_rows"] / t["select_statements"] > thr:
                flagged[u["unit_id"]].append({"table": t["table"], "rows_logged": t["select_rows"],
                                              "statements": t["select_statements"], "threshold": round(thr, 1)})
    for uid, items in sorted(flagged.items()):
        u = a.units[uid]
        aid = stable_id("ANOM", "bulk", uid)
        c = _claim(aid, f"Rows returned exceed the measured baseline for {len(items)} sensitive table(s).", Basis.INFERENCE,
                   a, [u], obs="bulk_read", cls=Consequence.ACCESS_OBSERVED, conf=0.75,
                   reason="row counts as logged compared with the per-table baseline",
                   lim=["rows returned are not distinct patient records"])
        anomalies.append(_anomaly("bulk_read", "Bulk read against baseline", "high", [u], c, tables=items))
    info["bulk_read"] = {**INFO["bulk_read"], "status": "applied" if thresholds else
                         "not_assessed: no table has a baseline of logged row counts",
                         "baseline": {"start": iso(a.b0), "end": iso(a.b1), "tables_with_baseline": len(thresholds),
                                      "factor": br["factor"], "min_rows": br["min_rows"]},
                         "sessions_with_volume_unknown": dict(sorted(unknown_volume.items()))}

    # ---------------------------------------------------------------- off-hours
    hh = a.cfg.get("hospital_hours")
    if hh:
        tz = ZoneInfo(hh["timezone"])

        def inside(t: dt.datetime) -> bool:
            lt = t.astimezone(tz)
            spec = hh.get("weekdays") if lt.weekday() < 5 else (hh.get("saturday") if lt.weekday() == 5 else hh.get("sunday"))
            if not spec:
                return False
            s, e = spec.split("-")
            return s <= lt.strftime("%H:%M") < e

        for u in db_units:
            if account_matches(u["account"], a.cfg["service_accounts"]):
                continue
            times = [t[b] for k, t in u["tables"].items() if a.sensitive.matches(k) for b in ("first", "last") if t[b]]
            if times and not all(inside(t) for t in times):
                aid = stable_id("ANOM", "offhours", u["unit_id"])
                c = _claim(aid, "Sensitive-table access outside the hospital's configured hours.", Basis.OBSERVATION, a, [u],
                           obs="off_hours_access", cls=Consequence.ACCESS_OBSERVED, conf=0.8,
                           reason="logged times compared with configured hours")
                anomalies.append(_anomaly("off_hours", "Off-hours sensitive access", "medium", [u], c,
                                          local_timezone=hh["timezone"]))
        info["off_hours"] = {**INFO["off_hours"], "status": "applied", "baseline": {"hospital_hours": hh}}
    else:
        info["off_hours"] = {**INFO["off_hours"], "status": "not_assessed: hospital_hours not configured", "baseline": None}

    # ---------------------------------------------------------------- dump / export
    for u in sorted((x for x in a.units.values() if x["exports"]), key=lambda x: x["unit_id"]):
        ops = sorted({x["operation"] or x["observation"] for x in u["exports"]})
        known = [j for j in a.cfg["known_jobs"] if account_matches(u["account"], [j["account"]])
                 and (not j.get("operations") or set(ops) <= {str(o) for o in j["operations"]})]
        aid = stable_id("ANOM", "export", u["unit_id"])
        c = _claim(aid, f"Export/staging command(s) observed: {', '.join(ops)}.", Basis.OBSERVATION, a, [u],
                   obs="dump_export", cls=Consequence.EXPORT_OR_STAGING_OBSERVED, conf=0.9,
                   reason="statement/audit action or file write recorded by the log",
                   lim=["indicates creation of a copy, not transmission beyond the hospital"])
        anomalies.append(_anomaly("dump_export", "Dump/export command" + (" (declared known job)" if known else ""),
                                  "low" if known else "high", [u], c, operations=ops,
                                  known_job=known[0]["reason"] if known else None,
                                  objects=sorted({o for x in u["exports"] for o in x["objects"]})[:20]))
    info["dump_export"] = {**INFO["dump_export"], "status": "applied",
                           "baseline": {"known_jobs": len(a.cfg["known_jobs"]),
                                        "staging_extensions": a.cfg["staging_extensions"]}}

    # ---------------------------------------------------------------- privilege grants
    priv_ids = sorted({e for u in a.units.values() for e in u["privilege_events"]})
    details = {r["event_id"]: r for r in a.q("SELECT event_id, operation, observation_type FROM ev WHERE list_contains(?, event_id)",
                                              [priv_ids])} if priv_ids else {}
    for u in sorted((x for x in a.units.values() if x["privilege_events"]), key=lambda x: x["unit_id"]):
        ops = sorted({details[e]["operation"] for e in u["privilege_events"] if e in details})
        sev = "high" if any(o in ("role_membership_or_attribute", "group_member_added", "sp_addsrvrolemember",
                                  "user_superuser", "grant") for o in ops) else "medium"
        aid = stable_id("ANOM", "priv", u["unit_id"])
        c = _claim(aid, f"Rights or accounts changed: {', '.join(ops)}.", Basis.OBSERVATION, a, [u], obs="privilege_change",
                   cls=None, conf=0.9, reason="statement/audit action or Windows event recorded by the log")
        anomalies.append(_anomaly("privilege_grant", "Newly granted rights / account change", sev, [u], c, operations=ops))
    info["privilege_grant"] = {**INFO["privilege_grant"], "status": "applied", "baseline": None}

    # ---------------------------------------------------------------- auditing disabled
    ev_unit = {e: u for u in a.units.values() for e in u["events"]}
    for g in a.audit_gaps:
        u = ev_unit.get(g["event_id"])
        aid = stable_id("ANOM", "audit", g["event_id"])
        units = [u] if u else []
        scope = f"database {g['database']}" if g.get("database") else f"host {g['host']}"
        stmt = ("Security log cleared on " + scope) if g["kind"] == "log_cleared" else f"Auditing switched off for {scope}."
        c = Claim(claim_id=aid, statement=stmt, basis=Basis.OBSERVATION, source_ids=[g["source_id"]],
                  evidence_ids=[g["event_id"]], parser=f"detector/{VERSION}", time_precision=TimePrecision.SECOND,
                  confidence=0.9, confidence_reason="audit-change record in the log", observation_type=g["kind"],
                  consequence_class=Consequence.UNDETERMINED, source_time_window=[iso(g["start"]), iso(g["end"])],
                  limitations=["activity during the gap is not determinable from these logs"]).to_dict()
        an = _anomaly("auditing_disabled", "Auditing disabled" if g["kind"] != "log_cleared" else "Security log cleared",
                      "high", units, c, scope=scope, open_ended=bool(g.get("open_ended")))
        an["first"], an["last"] = iso(g["start"]), iso(g["end"])
        anomalies.append(an)
    info["auditing_disabled"] = {**INFO["auditing_disabled"], "status": "applied", "baseline": None}

    # ---------------------------------------------------------------- new source locations
    base_loc = defaultdict(set)
    for r in a.q("SELECT account, location FROM ev WHERE source_family = 'entra_signin' AND location IS NOT NULL AND "
                 "ts_utc >= ? AND ts_utc < ?", bw):
        base_loc[a._key(r["account"])].add(_country(r["location"]))
    base_vpn = defaultdict(set)
    for r in a.q("SELECT account, remote_ip FROM ev WHERE source_family = 'vpn' AND remote_ip IS NOT NULL AND "
                 "ts_utc >= ? AND ts_utc < ?", bw):
        base_vpn[a._key(r["account"])].add(_net16(r["remote_ip"]))
    base_db = defaultdict(set)
    for r in a.q(f"SELECT DISTINCT account, client_host, remote_ip, application FROM ev WHERE source_family IN ({fams}) AND "
                 "ts_utc >= ? AND ts_utc < ?", bw):
        base_db[a._key(r["account"])].add(((r["client_host"] or r["remote_ip"] or "").lower(), (r["application"] or "").lower()))
    have_base = bool(base_loc or base_vpn or base_db)
    for u in sorted(a.units.values(), key=lambda x: x["unit_id"]):
        k = u["acct_key"]
        if not k:
            continue
        what = None
        if u["type"] == "signin" and u.get("location") and k in base_loc and _country(u["location"]) not in base_loc[k]:
            what = ("sign-in country", _country(u["location"]))
        elif u["type"] == "vpn_session" and u.get("public_ip") and k in base_vpn and _net16(u["public_ip"]) not in base_vpn[k]:
            what = ("VPN public address range", _net16(u["public_ip"]))
        elif u["type"] == "db_session" and k in base_db and u["tables"] and \
                ((u.get("client_host") or u.get("client_ip") or "").lower(), (u.get("application") or "").lower()) not in base_db[k]:
            what = ("database client/application", None)
        if what:
            aid = stable_id("ANOM", "newloc", u["unit_id"])
            c = _claim(aid, f"New {what[0]} for the account compared with the baseline.", Basis.INFERENCE, a, [u],
                       obs="new_source_location", cls=None, conf=0.6, reason="comparison with baseline activity")
            anomalies.append(_anomaly("new_source_location", f"New source location ({what[0]})", "medium", [u], c,
                                      attribute=what[0], value=what[1]))
    info["new_source_location"] = {**INFO["new_source_location"], "status": "applied" if have_base else
                                   "not_assessed: no baseline activity", "baseline": {"start": iso(a.b0), "end": iso(a.b1)}}

    # ---------------------------------------------------------------- web admin/upload before database access
    incoming = defaultdict(list)
    outgoing = defaultdict(list)
    for e in a.edges:
        outgoing[e["from"]].append(e)
        incoming[e["to"]].append(e)

    def reaches_db(uid, depth=0, seen=None):
        seen = seen or set()
        if depth > 4 or uid in seen:
            return []
        seen.add(uid)
        out = []
        for e in outgoing.get(uid, []):
            t = a.units[e["to"]]
            if t["type"] == "db_session" and t["tables"]:
                out.append((t, e["label"]))
            out += reaches_db(e["to"], depth + 1, seen)
        return out

    webs = defaultdict(list)
    for u in a.units.values():
        if u["type"] == "web_request" and (u.get("admin") or u.get("new_script")):
            fronted = any(e["join"] == "web_request_id" and a.units[e["from"]].get("entry")
                          for e in incoming.get(u["unit_id"], []))
            if not fronted:      # the gateway record of the same request already represents it
                webs[(u["source_id"], u.get("client_ip"))].append(u)
    for (sid, ip), us in sorted(webs.items(), key=lambda x: (x[0][0], x[0][1] or "")):
        us.sort(key=lambda x: (x["start"] or a.w0, x["unit_id"]))
        linked = []
        for u in us:
            linked += [(d["unit_id"], lbl) for d, lbl in reaches_db(u["unit_id"])]
        uploads = [u for u in us if (u.get("method") or "").upper() in ("POST", "PUT") and (u.get("bytes_received") or 0) > 0]
        sev = "high" if linked else ("medium" if uploads or any(u.get("new_script") for u in us) else "low")
        aid = stable_id("ANOM", "web", sid, ip)
        stmt = (f"{len(us)} admin/upload or new-script request(s) from one address"
                + (f", preceding database access linked through {len(set(linked))} chain(s) (labels: "
                   f"{', '.join(sorted({lbl for _x, lbl in linked}))})." if linked else "; no database access linked."))
        c = _claim(aid, stmt, Basis.OBSERVATION if not linked else Basis.INFERENCE, a, us, obs="web_admin_upload",
                   cls=None, conf=0.8 if not linked else 0.5,
                   reason="web server records" + ("; link to database access is an inference" if linked else ""),
                   lim=["a web shell or compromise is not confirmed without host evidence"])
        anomalies.append(_anomaly("web_admin_before_db", "Web admin/upload activity" + (" before database access" if linked
                                                                                         else ""), sev, us, c,
                                  uploads=len(uploads), new_scripts=sorted({u["url_path"] for u in us if u.get("new_script")}),
                                  linked_db_units=sorted({x for x, _ in linked})))
    info["web_admin_before_db"] = {**INFO["web_admin_before_db"], "status": "applied",
                                   "baseline": {"admin_patterns": a.cfg["web_admin_patterns"],
                                                "script_extensions": a.cfg["web_script_extensions"]}}
    anomalies.sort(key=lambda x: (-SEVERITY_WEIGHT[x["severity"]], x["first"] or "", x["anomaly_id"]))
    for name in info:
        info[name]["detector"] = name
        info[name]["version"] = VERSION
    return anomalies, dict(sorted(info.items()))


def _country(loc: str | None) -> str:
    if not loc:
        return ""
    s = str(loc)
    if "/" in s:
        return s.split("/", 1)[0].strip().upper()
    return s.rsplit(",", 1)[-1].strip().upper()


def _net16(ip: str | None) -> str:
    """IPv4 /16 (home ISP addresses change within a range; /24 would flag routine changes)."""
    if not ip:
        return ""
    parts = ip.split(".")
    return ".".join(parts[:2]) + ".0.0/16" if len(parts) == 4 else ip

