"""Financial-access investigation: who reached the financial application, how, with which privileges, and what
happened to the transactions they touched.

Inputs are Module B's own normalised, encrypted events (``work/paths/events``: Windows security, Entra ID sign-ins,
VPN, financial-application audit, bank settlement) plus the **released, verified** ``paths`` report (anomalies)
and, optionally, the released ``exposure`` report (credential and privilege exposure). Nothing is re-parsed and no
source is read again. The analysis configuration (``tripline.financial-config/v1``) declares supplier accounts and
their authorised windows, privileged groups, approved privileged accounts, directory member names and correlation
windows.

For each financial-application session (``FSN-``) the upstream chain is labelled with Module B's vocabulary:

* ``observed`` -- recorded by the system concerned (the application session itself; privilege events);
* ``direct`` -- joined on an identifier both records carry (application ``idp_correlation_id`` = sign-in
  correlation id; VPN ``auth_ref`` = sign-in request id);
* ``correlated`` -- same account inside a configured time window: an inference, never upgraded;
* ``unresolved`` -- no qualifying record; the reason is given.

Credential exposure (Module A) is listed as *potential* exposure only. A session is *suspicious* only for the
documented reasons in :data:`REASONS`. Transaction states come from :mod:`.transactions`. Every number in the
result is a count or a sum of input records.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from collections import defaultdict
from pathlib import Path

import yaml

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError, IntegrityError, NotReady
from tripline_scope.core.reports import ReportStore
from tripline_scope.paths.display import Display
from tripline_scope.paths.util import acct_key, as_utc

from . import transactions as T

CONFIG_SCHEMA = "tripline.financial-config/v1"
ANALYSIS_SCHEMA = "tripline.financial-analysis/v1"
METHOD_VERSION = "financial/0.1.0"
WORK = "work/financial"
DEFAULT_CORRELATION = {"signin_to_app_s": 3600, "logon_to_app_s": 3600, "vpn_to_app_s": 3600,
                       "privilege_before_session_s": 86400}
REASONS = {
    "supplier_outside_window": "supplier account active outside its authorised access window",
    "privilege_granted_before_session": "account received a privileged-group membership or application role shortly "
                                        "before or during the session, and is not an approved privileged account",
    "signin_without_mfa": "the linked identity-provider sign-in has no MFA evidence",
    "external_signin": "the linked sign-in came from an address outside the organisation's private ranges",
    "module_b_anomaly": "Module B flagged an anomaly for this account in the released paths report",
}
_CONFIG_KEYS = {"schema", "directory_domains", "supplier_accounts", "privileged_groups", "approved_privileged_accounts",
                "directory_members", "correlation", "incident_window"}


def load_config(path: Path | str) -> tuple[dict, str]:
    p = Path(path)
    if not p.is_file():
        raise ConfigError("financial config file not found")
    raw = p.read_bytes()
    try:
        doc = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        raise ConfigError("financial config is not valid YAML") from None
    if not isinstance(doc, dict) or doc.get("schema") != CONFIG_SCHEMA:
        raise ConfigError(f"financial config must declare schema: {CONFIG_SCHEMA}")
    unknown = set(doc) - _CONFIG_KEYS
    if unknown:
        raise ConfigError(f"financial config: unknown keys {sorted(unknown)}")
    corr = dict(DEFAULT_CORRELATION)
    for k, v in (doc.get("correlation") or {}).items():
        if k not in DEFAULT_CORRELATION or not isinstance(v, int) or not 0 < v <= 7 * 86400:
            raise ConfigError(f"financial config: correlation.{k} must be one of {sorted(DEFAULT_CORRELATION)} "
                              "with a positive number of seconds (at most 7 days)")
        corr[k] = v
    sup = []
    for i, s in enumerate(doc.get("supplier_accounts") or []):
        if not isinstance(s, dict) or not s.get("account"):
            raise ConfigError(f"financial config: supplier_accounts[{i}] needs an account")
        sup.append({"account": str(s["account"]), "supplier": str(s.get("supplier") or "")[:80] or None,
                    "window_start": _day(s.get("window_start"), f"supplier_accounts[{i}].window_start"),
                    "window_end": _day(s.get("window_end"), f"supplier_accounts[{i}].window_end")})
    cfg = {"schema": CONFIG_SCHEMA, "directory_domains": [str(d).lower() for d in doc.get("directory_domains") or []],
           "supplier_accounts": sup, "privileged_groups": [str(g) for g in doc.get("privileged_groups") or []],
           "approved_privileged_accounts": [str(a) for a in doc.get("approved_privileged_accounts") or []],
           "directory_members": {str(k): str(v) for k, v in (doc.get("directory_members") or {}).items()},
           "correlation": corr}
    return cfg, sha256_hex(raw)


def _day(v, what) -> str | None:
    if v in (None, ""):
        return None
    try:
        return dt.date.fromisoformat(str(v)[:10]).isoformat()
    except ValueError:
        raise ConfigError(f"financial config: {what} is not a date (YYYY-MM-DD)") from None


# Internal address space (RFC 1918, RFC 4193, loopback, link-local). ``ipaddress.is_private`` is not used: it also
# covers documentation and other reserved ranges, which are not the organisation's network.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10")]


def _private(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(a.version == n.version and a in n for n in _INTERNAL)


def _iso(t) -> str | None:
    t = as_utc(t)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


class _Ids:
    """Opaque, case-keyed ids for released output (account names, session and transaction references are never
    put in a report)."""

    def __init__(self, store, domains):
        self.fp = store.fingerprinter("financial-ids")
        self.disp = Display(store, domains)

    def make(self, prefix: str, *parts) -> str:
        return f"{prefix}-" + self.fp("\x1f".join(str(p) for p in parts))[:12]


def _events(store, families: set[str], columns: list[str]) -> list[dict]:
    rels = store.list("work/paths/events")
    if not rels:
        return []
    tbl = store.read_tables(rels, columns=columns)
    rows = tbl.to_pylist()
    return [r for r in rows if r["source_family"] in families]


def _sources(store) -> dict:
    return store.read_json("work/paths/sources.json") if store.exists("work/paths/sources.json") else {}


def _coverage(store, sid: str) -> dict:
    rel = f"work/paths/coverage/{sid}.json"
    return store.read_json(rel) if store.exists(rel) else {}


def released_ref(case, home, kind: str, required: bool) -> tuple[dict | None, dict | None]:
    """(reference, body) of the latest released version of ``kind``, chain-verified; None if absent and optional."""
    rs = ReportStore(case)
    latest = rs.latest(kind)
    if latest is None:
        if required:
            raise NotReady(f"release the {kind} report first (tscope release --kind {kind})")
        return None, None
    if not rs.verify(kind, home).ok:
        raise IntegrityError(f"released {kind} reports failed verification; refusing to use them")
    n, _, sha = latest
    return {"kind": kind, "version": n, "report_sha256": sha}, rs.load(kind, n)


def analyse(case, home, store, cfg: dict, cfg_sha: str) -> dict:
    """Run the financial-access and transaction-evidence analysis; writes ``work/financial/analysis.json``."""
    paths_ref, paths_body = released_ref(case, home, "paths", required=True)
    expo_ref, expo_body = released_ref(case, home, "exposure", required=False)
    domains = sorted(set(cfg["directory_domains"]) | set((case.config.get("paths") or {}).get("directory_domains") or []))
    ids = _Ids(store, domains)
    K = lambda a: acct_key(a, domains)  # noqa: E731
    corr = cfg["correlation"]
    srcs = _sources(store)
    fam = defaultdict(list)
    for sid, s in srcs.items():
        fam[s.get("family")].append(sid)
    cols = ["event_id", "source_id", "source_family", "ordinal", "ts_utc", "host", "account", "application",
            "session_id", "request_id", "remote_ip", "operation", "observation_type", "outcome", "mfa", "object_name",
            "event_code", "correlation_id", "target_account", "client_host", "flags", "txn_ref", "approval_ref",
            "evidence_ref", "amount_minor", "currency", "counterparty_ref", "assigned_ip"]
    ev = _events(store, {"fin_app_audit", "bank_settlement", "entra_signin", "vpn", "win_security"}, cols)
    for e in ev:
        e["ts_utc"] = as_utc(e["ts_utc"])
    fin = [e for e in ev if e["source_family"] == "fin_app_audit"]
    bank = [e for e in ev if e["source_family"] == "bank_settlement"]
    signins = [e for e in ev if e["source_family"] == "entra_signin"]
    vpn = [e for e in ev if e["source_family"] == "vpn" and e["observation_type"] == "vpn_connect"]
    win = [e for e in ev if e["source_family"] == "win_security"]
    if not fam.get("fin_app_audit"):
        raise NotReady("no fin_app_audit source has been ingested (tscope paths ingest with a fin_app_audit source)")

    # ------------------------------------------------------------------ declared accounts
    supplier = {K(s["account"]): s for s in cfg["supplier_accounts"]}
    approved_priv = {K(a) for a in cfg["approved_privileged_accounts"]}
    member_fp = store.fingerprinter("paths-file")
    dn_to_acct = {"dn:" + member_fp(dn.lower())[:12]: K(a) for a, dn in cfg["directory_members"].items()}
    priv_groups = {g.lower() for g in cfg["privileged_groups"]}

    def member_acct(e) -> str | None:
        t = e.get("target_account")
        if not t:
            return None
        if t.startswith("dn:"):
            return dn_to_acct.get(t)
        return K(t)

    # ------------------------------------------------------------------ privilege events (observed)
    priv_events = []
    for e in win + fin:
        obs = e["observation_type"]
        if obs not in ("privilege_change", "special_privileges"):
            continue
        if e["outcome"] == "failure":
            continue
        if obs == "privilege_change" and e["source_family"] == "win_security":
            grp = (e.get("object_name") or "").split("\\")[-1].lower()
            if priv_groups and grp not in priv_groups:
                continue
        acct = member_acct(e) if obs == "privilege_change" else K(e["account"])
        priv_events.append({"pev_id": ids.make("PEV", e["event_id"]), "event": e["event_id"], "ts": e["ts_utc"],
                            "kind": "privilege_granted" if obs == "privilege_change" else "special_privileges_used",
                            "family": e["source_family"], "host": e.get("host"),
                            "account": acct, "account_ref": ids.disp.ref(acct) if acct else None,
                            "by_ref": ids.disp.ref(e["account"]) if obs == "privilege_change" else None,
                            "target": (e.get("object_name") or "")[:80] or None,
                            "resolved": acct is not None})
    privileged_accounts = {p["account"] for p in priv_events if p["account"]}

    # ------------------------------------------------------------------ application sessions
    sess = defaultdict(list)
    for e in fin:
        if e["operation"] is None:
            continue
        key = (e["source_id"], K(e["account"]), e.get("session_id") or f"no-session:{e['event_id']}")
        sess[key].append(e)
    anomaly_refs = defaultdict(list)
    for a in (paths_body.get("anomalies") or []):
        for acc in a.get("accounts") or []:
            if isinstance(acc, dict) and acc.get("account_ref"):
                anomaly_refs[acc["account_ref"]].append(a.get("anomaly_id"))
    by_corr = {e["correlation_id"]: e for e in signins if e.get("correlation_id")}
    by_req = {e["request_id"]: e for e in signins if e.get("request_id")}
    sessions, session_index, susp_sessions = [], {}, {}
    for (sid, acct, sref), evs in sorted(sess.items(), key=lambda kv: min(_tkey(e) for e in kv[1])):
        evs.sort(key=_tkey)
        start = next((e["ts_utc"] for e in evs if e["ts_utc"]), None)
        end = next((e["ts_utc"] for e in reversed(evs) if e["ts_utc"]), None)
        fsn = ids.make("FSN", sid, acct, sref)
        session_index[(sid, acct, sref)] = fsn
        links = {}
        # identity provider
        si, label, reason = None, "unresolved", "no sign-in record for this account in the window"
        direct = [by_corr.get(e["correlation_id"]) or by_req.get(e["correlation_id"]) for e in evs if e.get("correlation_id")]
        direct = [d for d in direct if d]
        if direct:
            si, label, reason = direct[0], "direct", "the application records the identity-provider correlation id"
        elif start:
            cands = [s for s in signins if K(s["account"]) == acct and s["outcome"] == "success" and s["ts_utc"]
                     and dt.timedelta(0) <= start - s["ts_utc"] <= dt.timedelta(seconds=corr["signin_to_app_s"])]
            if cands:
                si = max(cands, key=lambda s: s["ts_utc"])
                label = "correlated"
                reason = (f"same account signed in {int((start - si['ts_utc']).total_seconds())} s before the session"
                          + (f" ({len(cands)} candidate sign-ins)" if len(cands) > 1 else ""))
        elif not signins:
            reason = "no identity-provider sign-in source supplied"
        if not fam.get("entra_signin"):
            reason = "no identity-provider sign-in source supplied"
        links["identity"] = {"label": label, "reason": reason, "evidence": [si["event_id"]] if si else []}
        # remote access
        v, vlabel, vreason = None, "unresolved", ("no VPN source supplied" if not fam.get("vpn") else
                                                 "no VPN session for this account before the session")
        if si and si.get("request_id"):
            vd = [x for x in vpn if x.get("request_id") and x["request_id"] in (si["request_id"], si.get("correlation_id"))]
            if vd:
                v, vlabel, vreason = vd[0], "direct", "the VPN session records the sign-in request id"
        if v is None and start:
            vc = [x for x in vpn if K(x["account"]) == acct and x["ts_utc"]
                  and dt.timedelta(0) <= start - x["ts_utc"] <= dt.timedelta(seconds=corr["vpn_to_app_s"])]
            if vc:
                v = max(vc, key=lambda x: x["ts_utc"])
                vlabel, vreason = "correlated", "same account connected to the VPN before the session"
        links["remote_access"] = {"label": vlabel, "reason": vreason, "evidence": [v["event_id"]] if v else []}
        # host logon on the application server
        app_host = (evs[0].get("host") or "").lower()
        lg = [x for x in win if x["observation_type"] in ("login_success", "logon") and K(x["account"]) == acct
              and x["ts_utc"] and start and (x.get("host") or "").lower().split(".")[0] == app_host.split(".")[0]
              and dt.timedelta(0) <= start - x["ts_utc"] <= dt.timedelta(seconds=corr["logon_to_app_s"])]
        links["host_logon"] = ({"label": "correlated", "reason": "same account logged on to the application server "
                                                                 "before the session", "evidence": [lg[-1]["event_id"]]}
                               if lg else {"label": "unresolved", "reason": "no logon record for this account on the "
                                                                            "application server before the session",
                                           "evidence": []})
        # privileges
        win_p = [p for p in priv_events if p["account"] == acct and p["ts"] and start
                 and dt.timedelta(seconds=-(corr["privilege_before_session_s"])) <= p["ts"] - start
                 <= (end - start if end else dt.timedelta(0)) + dt.timedelta(seconds=60)]
        links["privilege"] = ({"label": "observed", "reason": "privilege events recorded for this account around the "
                                                              "session (correlated to the session by account and time)",
                               "evidence": [p["event"] for p in win_p]}
                              if win_p else {"label": "none_observed", "reason": "no privilege grant or special-privilege "
                                                                                "event for this account in the window",
                                             "evidence": []})
        # reasons
        reasons = []
        sup = supplier.get(acct)
        if sup and start:
            d = start.date().isoformat()
            if (sup["window_end"] and d > sup["window_end"]) or (sup["window_start"] and d < sup["window_start"]):
                reasons.append("supplier_outside_window")
        if any(p["kind"] == "privilege_granted" for p in win_p) and acct not in approved_priv:
            reasons.append("privilege_granted_before_session")
        if si and si.get("mfa") == "false":
            reasons.append("signin_without_mfa")
        if si and _private(si.get("remote_ip")) is False:
            reasons.append("external_signin")
        ref = ids.disp.ref(acct)
        if anomaly_refs.get(ref):
            reasons.append("module_b_anomaly")
        actions = defaultdict(int)
        for e in evs:
            actions[e["operation"]] += 1
        rec = {"session_id": fsn, "account_ref": ref, "account_label": ids.disp.label(acct),
               "account_type": "supplier" if sup else "privileged (approved)" if acct in approved_priv else "user",
               "source_id": sid, "first_event_utc": _iso(start), "last_event_utc": _iso(end), "events": len(evs),
               "actions": dict(sorted(actions.items())), "links": links, "suspicious_reasons": reasons,
               "privileged": acct in privileged_accounts, "anomalies": sorted(set(anomaly_refs.get(ref, []))),
               "evidence_ids": [e["event_id"] for e in evs][:200]}
        sessions.append(rec)
        if reasons:
            susp_sessions[fsn] = reasons

    # ------------------------------------------------------------------ transactions
    txfp = store.fingerprinter("financial-txn")
    txid = lambda r: "TXN-" + txfp(r)[:12]  # noqa: E731
    tev = []
    for e in fin:
        key = (e["source_id"], K(e["account"]), e.get("session_id") or f"no-session:{e['event_id']}")
        tev.append({"ref": e["event_id"], "event_id": e.get("event_code"), "source_system": e.get("application"),
                    "ts_utc": e["ts_utc"], "ordinal": e["ordinal"], "action": e["operation"], "outcome": e["outcome"],
                    "actor": ids.disp.ref(K(e["account"])), "session_ref": session_index.get(key),
                    "target_ref": e.get("object_name"), "transaction_ref": e.get("txn_ref"),
                    "approval_ref": e.get("approval_ref"), "amount_minor": e.get("amount_minor"),
                    "currency": e.get("currency"), "payee_ref": e.get("counterparty_ref"),
                    "flags": list(e.get("flags") or [])})
    settles = []
    for e in bank:
        out = next((f.split(":", 1)[1] for f in (e.get("flags") or []) if f.startswith("settlement_outcome:")), "unknown")
        settles.append({"ref": e["event_id"], "source_id": e["source_id"], "transaction_ref": e.get("txn_ref"),
                        "amount_minor": e.get("amount_minor"), "currency": e.get("currency"), "outcome": out,
                        "value_date": _iso(e["ts_utc"])})
    priv_refs = {ids.disp.ref(a) for a in privileged_accounts}
    tx = T.analyse(tev, settles, app_source_ids=set(fam.get("fin_app_audit", [])), suspicious_sessions=susp_sessions,
                   privileged_actors=priv_refs)
    refs = {}
    for t in tx["transactions"]:
        refs[txid(t["transaction"])] = t["transaction"]
        t["transaction_id"] = txid(t["transaction"])
    for s in sessions:
        s["transactions"] = sorted({t["transaction_id"] for t in tx["transactions"] if s["session_id"] in t["sessions"]})

    # ------------------------------------------------------------------ evidence gaps
    gaps = []
    if not fam.get("bank_settlement"):
        gaps.append(_gap(ids, "settlement_evidence_not_supplied", None, "no independent settlement source (bank "
                         "statement) was supplied: whether any payment settled cannot be determined"))
    for f, why in (("entra_signin", "identity-provider sign-ins"), ("vpn", "remote-access (VPN) sessions"),
                   ("win_security", "Windows security events")):
        if not fam.get(f):
            gaps.append(_gap(ids, "source_family_missing", None, f"no {why} were supplied: those links stay unresolved"))
    susp_spans = [(as_utc(s["first_event_utc"]), as_utc(s["last_event_utc"]), s["session_id"]) for s in sessions
                  if s["suspicious_reasons"]]
    for sid in fam.get("fin_app_audit", []) + fam.get("bank_settlement", []):
        cov = _coverage(store, sid)
        if cov.get("parse_failures"):
            gaps.append(_gap(ids, "parse_failures", sid, f"{cov['parse_failures']} record(s) could not be read and are "
                             "not part of the analysis", samples=cov.get("failure_samples", [])[:10]))
        for m in (cov.get("declared_coverage") or {}).get("missing") or []:
            ms, me = as_utc(m.get("start")), as_utc(m.get("end"))
            hit = [fsn for a, b, fsn in susp_spans if a and b and ms and me and a <= me and ms <= b + dt.timedelta(hours=12)]
            gaps.append(_gap(ids, "declared_missing_period", sid, (m.get("reason") or "declared missing period")[:200],
                             start=_iso(ms), end=_iso(me), overlaps_sessions=hit))
    dup = tx["duplicates"]
    if dup["conflicting_duplicate_ids"]:
        gaps.append(_gap(ids, "conflicting_duplicates", None, f"{dup['conflicting_duplicate_ids']} source event id(s) "
                         "appear more than once with different content; those records establish no transition"))

    # ------------------------------------------------------------------ impact determination
    impact = determine_impact(tx, sessions, gaps)

    # ------------------------------------------------------------------ credential and privilege exposure (A)
    exposure = []
    accts_seen = {s["account_ref"] for s in sessions}
    for f in (expo_body or {}).get("findings", []):
        if f.get("control_id") not in ("A1", "A2", "A5", "E1", "E2", "E5") or f.get("state") == "mitigated":
            continue
        principal = (f.get("location") or {}).get("principal")
        ref = ids.disp.ref(K(principal)) if principal else None
        exposure.append({"finding_id": f["finding_id"], "control_id": f["control_id"], "rule_id": f["rule_id"],
                         "severity": f["severity"], "account_ref": ref,
                         "account_in_financial_activity": bool(ref and ref in accts_seen),
                         "asset_id": (f.get("asset") or {}).get("asset_id")})

    result = {
        "schema": ANALYSIS_SCHEMA, "method_version": METHOD_VERSION, "config_sha256": cfg_sha,
        "references": [r for r in (paths_ref, expo_ref) if r],
        "inputs": {"sources": [{"source_id": sid, "family": srcs[sid].get("family"), "label": srcs[sid].get("label"),
                                "asset_id": srcs[sid].get("asset_id"),
                                "completeness": _coverage(store, sid).get("completeness"),
                                "events": _coverage(store, sid).get("events"),
                                "parse_failures": _coverage(store, sid).get("parse_failures")}
                               for sid in sorted(srcs) if srcs[sid].get("family") in
                               ("fin_app_audit", "bank_settlement", "entra_signin", "vpn", "win_security")],
                   "duplicates": dup, "events_without_transaction_ref": tx["events_without_transaction_ref"],
                   "settlements_without_transaction": len(tx["settlements_without_transaction"])},
        "sessions": sessions, "privilege_events": [{k: v for k, v in p.items() if k not in ("account",)} | {"ts": _iso(p["ts"])}
                                                   for p in priv_events],
        "transactions": [_public_tx(t) for t in tx["transactions"]],
        "counts": tx["counts"] | {"sessions": len(sessions), "suspicious_sessions": len(susp_sessions),
                                  "privilege_events": len(priv_events)},
        "gaps": gaps, "financial_impact": impact, "exposure": exposure,
    }
    store.write_json(f"{WORK}/analysis.json", result)
    store.write_json(f"{WORK}/refs.json", {"transactions": refs})   # encrypted: for authorised investigators only
    return result


def _tkey(e):
    t = e.get("ts_utc")
    return (t is None, t or dt.datetime.min.replace(tzinfo=dt.UTC), e.get("ordinal") or 0)


def _gap(ids, kind, sid, text, **extra) -> dict:
    return {"gap_id": ids.make("FGP", kind, sid, text), "kind": kind, "source_id": sid, "description": text, **extra}


def _public_tx(t: dict) -> dict:
    """Released form: the raw transaction reference is replaced by its keyed TXN- id; actors and sessions are
    already opaque refs."""
    out = {k: v for k, v in t.items() if k not in ("transaction",)}
    return out


def determine_impact(tx: dict, sessions: list[dict], gaps: list[dict]) -> dict:
    """Overall statement on financial impact, from the evidence categories of *suspicious* transactions."""
    sus = [t for t in tx["transactions"] if t["suspicious"]]
    cats = {t["category"] for t in sus}
    outage = [g for g in gaps if g["kind"] == "declared_missing_period" and g.get("overlaps_sessions")]
    no_settle = any(g["kind"] == "settlement_evidence_not_supplied" for g in gaps)
    susp_sessions = [s for s in sessions if s["suspicious_reasons"]]
    lim = []
    if outage:
        lim.append("the financial application's audit trail has a declared gap overlapping a suspicious session")
    if no_settle:
        lim.append("no independent settlement evidence was supplied")
    if "settled_corroborated" in cats:
        status = "settlement_corroborated"
        text = ("At least one suspicious transaction reached settlement, corroborated by an independent settlement "
                "record with the identical reference, amount and currency.")
    elif cats & {"posted", "released_not_posted", "reversed"}:
        status = "released_or_posted_not_settled"
        text = ("Suspicious transactions were released or posted, but no independent settlement record corroborates "
                "that funds moved.")
    elif cats & {"approved_not_released", "pending_approval", "initiated"}:
        status = "initiated_not_released"
        text = "Suspicious transactions were initiated but the evidence does not show them released."
    elif cats == {"rejected_or_stopped"}:
        status = "attempted_and_stopped"
        text = "Suspicious payment attempts were recorded and rejected or stopped; none is shown released."
    elif cats & {"undetermined"}:
        status = "not_determinable"
        text = "The records for suspicious transactions are contradictory or incomplete."
    elif susp_sessions and (outage or no_settle):
        status = "not_determinable"
        text = ("Suspicious privileged access to the financial application is evidenced, but gaps in the evidence "
                "prevent a determination of financial impact.")
    elif susp_sessions:
        status = "no_suspicious_transaction_in_available_evidence"
        text = ("No transaction linked to a suspicious session appears in the supplied evidence. This is not proof "
                "that none occurred.")
    else:
        status = "no_suspicious_session_identified"
        text = "No session met the documented suspicion criteria in the supplied evidence."
    if lim and status not in ("settlement_corroborated", "not_determinable"):
        text += " Limitations: " + "; ".join(lim) + "."
    if status == "not_determinable" and lim:
        text += " (" + "; ".join(lim) + ")"
    return {"status": status, "statement": text, "limitations": lim,
            "suspicious_transactions_by_category": {c: sum(1 for t in sus if t["category"] == c) for c in sorted(cats)},
            "basis": "categories of transactions linked to suspicious sessions or carrying approval indicators; see "
                     "the evidence rule"}


def analysis_sha(result: dict) -> str:
    return sha256_hex(canonical_bytes(result))

