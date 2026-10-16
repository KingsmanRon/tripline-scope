"""``tscope paths analyse``: units, edges, paths, gaps, anomalies, indicator matches and per-table outcomes.

Vocabulary:

* a **unit** groups events that share an exact identifier inside one source (a database session, a Windows
  logon session, a VPN session) or is a single record (a sign-in, a web request, a flow);
* an **edge** joins two units: ``direct`` on an exact shared identifier (request id, sign-in request /
  correlation id, VPN session id), ``correlated`` when joined only by address/account and an explicitly
  configured, bounded time window (an inference, always below direct confidence), never on proximity alone;
* a **path** is an access route (database account + client + application + server) to sensitive data, with
  the upstream units reachable over edges and the egress flows linked after export/staging; each stage is
  ``direct``, ``correlated`` or ``unresolved`` (evidence stops there).

Consequence classes follow the evidence-of-access versus evidence-of-theft rule: SELECT/DML -> access;
dump/export/staging -> export_or_staging_observed; a linked outbound flow after staging -> egress_suspected
(never more, whatever the bytes); exfiltration_evidenced only from a qualifying corroboration; auditing off ->
undetermined + gap.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import ipaddress
from collections import Counter, defaultdict

from tripline_scope.core import duck
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.evidence import (
    EXFILTRATION_EVIDENCE_KINDS,
    Basis,
    Claim,
    Consequence,
    EdgeLabel,
    TimePrecision,
    strongest,
)

from . import detectors
from .config import NetMatcher, TableMatcher, account_matches, config_sha256, norm_table
from .schema import ANALYSIS_SCHEMA, DB_FAMILIES, FLOW_FAMILIES, METHOD_VERSION, WEB_FAMILIES
from .util import (
    SYSTEM_LOGON_IDS,
    UTC,
    acct_key,
    as_utc,
    canon_host,
    clip,
    iso,
    merge_intervals,
    stable_id,
    subtract_intervals,
)

DIRECT_CONFIDENCE = 0.95
CORRELATED_CAP = 0.8
MAX_EVIDENCE = 40
_EXPORT_OBS = {"dump_export", "select_into", "file_staged"}
_CLASS_WEIGHT = {"exfiltration_evidenced": 5, "egress_suspected": 4, "export_or_staging_observed": 3,
                 "access_observed": 1, "undetermined": 0}


def _td(s) -> dt.timedelta:
    return dt.timedelta(seconds=float(s or 0))


class Analysis:
    def __init__(self, case, store, home, cfg: dict, w0: dt.datetime, w1: dt.datetime):
        self.case, self.store, self.home, self.cfg = case, store, home, cfg
        self.w0, self.w1 = w0, w1
        self.corr = cfg["correlation"]
        self.dirdom = cfg["directory_domains"]
        self.sensitive = TableMatcher(cfg["sensitive_tables"])
        self.internal = NetMatcher(cfg["internal_networks"])
        self.units: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.limitations: list[str] = []
        self.assumptions: list[str] = []

    # ================================================================================================ load
    def load(self) -> None:
        st = self.store
        self.sources = st.read_json("work/paths/sources.json") if st.exists("work/paths/sources.json") else {}
        self.coverage = {}
        for rel in st.list("work/paths/coverage"):
            c = st.read_json(rel)
            self.coverage[c["source_id"]] = c
        self.corroborations = (st.read_json("work/paths/corroborations.json")["corroborations"]
                               if st.exists("work/paths/corroborations.json") else [])
        self.indicators, self.indicators_rejected = [], []
        for rel in st.list("work/paths/indicators"):
            doc = st.read_json(rel)
            self.indicators += doc.get("indicators", [])
            self.indicators_rejected += [{"source_id": doc["source_id"], **r} for r in doc.get("rejected", [])]
        rels = st.list("work/paths/events")
        self.con = duck.connect(lock=False)
        self.con.execute("SET TimeZone = 'UTC'")
        self.con.execute("SET lock_configuration = true")
        if rels:
            tbl = st.read_tables(rels)
        else:
            from .schema import EVENT_SCHEMA

            tbl = EVENT_SCHEMA.empty_table()
        # DuckDB returns zone-aware timestamps only through pytz (not a dependency): keep UTC instants as naive
        # UTC columns here and re-tag them as UTC in Python (``as_utc``).
        import pyarrow as pa

        for name in ("ts_utc", "ts_utc_min", "ts_utc_max"):
            i = tbl.schema.get_field_index(name)
            tbl = tbl.set_column(i, name, tbl.column(name).cast(pa.timestamp("us")))
        self.con.register("ev", tbl)
        self.n_events = tbl.num_rows
        self.host_ips: dict[str, set[str]] = defaultdict(set)
        self.ip_host: dict[str, str] = {}
        for s in self.sources.values():
            h = canon_host(s.get("host"))
            for ip in s.get("host_ips") or []:
                if h:
                    self.host_ips[h].add(ip)
                    self.ip_host[ip] = h
        self.source_host = {sid: canon_host(s.get("host")) for sid, s in self.sources.items()}
        b = self.cfg["baseline"]
        starts = [as_utc(c["declared_coverage"]["start"]) for c in self.coverage.values()
                  if (c.get("declared_coverage") or {}).get("start")]
        firsts = [as_utc(c["first_event_utc"]) for c in self.coverage.values() if c.get("first_event_utc")]
        self.b0 = as_utc(b["start"]) if b.get("start") else (min(starts + firsts) if (starts or firsts) else self.w0)
        self.b1 = min(as_utc(b["end"]) if b.get("end") else self.w0, self.w0)

    def q(self, sql: str, params: list | None = None) -> list[dict]:
        params = [p.astimezone(UTC).replace(tzinfo=None) if isinstance(p, dt.datetime) and p.tzinfo else p
                  for p in (params or [])]
        cur = self.con.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]

    def _unc(self, value) -> float:
        if value is None:
            return float(self.corr["unknown_clock_uncertainty_s"])
        return float(value)

    def _key(self, account):
        return acct_key(account, self.dirdom)

    def _external(self, ip) -> bool:
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        return self.internal.contains(ip) is False

    # ================================================================================================ units
    def _new_unit(self, utype: str, ev: dict) -> dict:
        uid = f"U:{ev['source_id']}:{ev['ordinal']}"
        u = {"unit_id": uid, "type": utype, "family": ev["source_family"], "source_id": ev["source_id"],
             "host": canon_host(ev.get("host")) or self.source_host.get(ev["source_id"]), "account": ev.get("account"),
             "acct_key": self._key(ev.get("account")), "session_id": ev.get("session_id"), "request_ids": set(),
             "client_ip": ev.get("remote_ip"), "client_host": ev.get("client_host"), "application": ev.get("application"),
             "start": as_utc(ev.get("ts_utc")), "end": as_utc(ev.get("ts_utc")), "tmin": as_utc(ev.get("ts_utc_min")),
             "tmax": as_utc(ev.get("ts_utc_max")), "unc": ev.get("ts_uncertainty_s"), "events": [], "event_count": 0,
             "accounts": Counter(), "observations": Counter(), "flags": set(), "tables": {}, "exports": [],
             "privilege_events": [], "audit_events": [], "time_resolved": ev.get("ts_utc") is not None,
             "logon_id": ev.get("logon_id")}
        self.units[uid] = u
        return u

    def _absorb(self, u: dict, ev: dict) -> None:
        t = as_utc(ev.get("ts_utc"))
        if t is not None:
            u["start"] = t if u["start"] is None or t < u["start"] else u["start"]
            u["end"] = t if u["end"] is None or t > u["end"] else u["end"]
        else:
            u["time_resolved"] = False
        for k in ("tmin", "tmax"):
            v = as_utc(ev.get(f"ts_utc_{k[1:]}"))
            if v is not None:
                if u[k] is None or (k == "tmin" and v < u[k]) or (k == "tmax" and v > u[k]):
                    u[k] = v
        if ev.get("ts_uncertainty_s") is None:
            u["unc"] = None if u["unc"] is None else u["unc"]
        if len(u["events"]) < MAX_EVIDENCE:
            u["events"].append(ev["event_id"])
        u["event_count"] += 1
        if ev.get("account"):
            u["accounts"][ev["account"]] += 1
            if not u["account"]:
                u["account"], u["acct_key"] = ev["account"], self._key(ev["account"])
        for k in ("client_ip", "client_host", "application", "session_id"):
            src = "remote_ip" if k == "client_ip" else k
            if not u.get(k) and ev.get(src):
                u[k] = ev[src]
        if ev.get("request_id"):
            u["request_ids"].add(ev["request_id"])
        obs = ev.get("observation_type") or "other"
        u["observations"][obs] += 1
        for f in ev.get("flags") or []:
            if f in ("schema_assumed", "impersonation", "dump_tool_session", "xp_cmdshell", "backup_to_url",
                     "session_from_pid_tracking", "time_zone_unknown", "dst_ambiguous"):
                u["flags"].add(f)
        cls = ev.get("consequence_class")
        objs = list(ev.get("objects") or [])
        db = ev.get("database")
        if cls in ("access_observed", "export_or_staging_observed") and obs != "file_staged":
            if obs == "dump_export" and objs and all("." not in o for o in objs):
                # database-level copy (e.g. BACKUP DATABASE): every sensitive table of that database
                dbname = objs[0]
                u["flags"].add("database_level_copy")
                objs = [t for t in self.declared_tables if t.split(".")[0].lower() == dbname.lower()] or [f"{dbname}.*"]
            for o in objs:
                full = o if o.count(".") >= 2 or not db else f"{db}.{o}"
                key = norm_table(full)
                tb = u["tables"].setdefault(key, {"table": full, "ops": Counter(), "observations": set(), "rows": 0,
                                                  "rows_unknown": False, "first": t, "last": t, "events": [],
                                                  "classes": set(), "statements": 0, "time_resolved": True,
                                                  "select_rows": 0, "select_statements": 0, "select_rows_unknown": False})
                tb["ops"][ev.get("operation") or "?"] += 1
                tb["observations"].add(obs)
                tb["classes"].add(cls)
                tb["statements"] += 1
                if ev.get("rows") is None:
                    tb["rows_unknown"] = True
                else:
                    tb["rows"] += int(ev["rows"])
                if obs == "select":
                    tb["select_statements"] += 1
                    if ev.get("rows") is None:
                        tb["select_rows_unknown"] = True
                    else:
                        tb["select_rows"] += int(ev["rows"])
                if t is None:
                    tb["time_resolved"] = False
                else:
                    tb["first"] = t if tb["first"] is None or t < tb["first"] else tb["first"]
                    tb["last"] = t if tb["last"] is None or t > tb["last"] else tb["last"]
                if len(tb["events"]) < MAX_EVIDENCE:
                    tb["events"].append(ev["event_id"])
        if obs in _EXPORT_OBS and cls == "export_or_staging_observed":
            u["exports"].append({"event_id": ev["event_id"], "ts": t, "operation": ev.get("operation"),
                                 "observation": obs, "objects": objs, "object_ref": ev.get("object_name")})
        if obs in ("privilege_change", "account_change"):
            u["privilege_events"].append(ev["event_id"])
        if obs in ("auditing_disabled", "log_cleared", "auditing_enabled"):
            u["audit_events"].append(ev["event_id"])

    def _finish_unit(self, u: dict) -> None:
        u["request_ids"] = sorted(u["request_ids"])
        u["flags"] = sorted(u["flags"])
        u["consequence"] = str(strongest(c for tb in u["tables"].values() for c in tb["classes"])) if u["tables"] else None

    def build_units(self) -> None:
        w = [self.w0, self.w1]
        self.declared_tables = [p for p in self.cfg["sensitive_tables"] if not any(c in p for c in "*?[")]
        cols = ("event_id, source_id, source_family, ordinal, ts_utc, ts_utc_min, ts_utc_max, ts_uncertainty_s, host, "
                "account, application, session_id, request_id, correlation_id, logon_id, remote_ip, client_host, "
                "assigned_ip, operation, observation_type, database, objects, rows, bytes, bytes_received, outcome, "
                "consequence_class, flags, event_code, target_account, object_name, dest_ip, dest_port, domain, "
                "url_path, method, http_status, mfa, location")
        inw = "ts_utc_max >= ? AND ts_utc_min <= ?"
        fams = ",".join(f"'{f}'" for f in DB_FAMILIES)
        gap = _td(self.corr["session_gap_s"])
        # ---- database sessions (session id reused after logout / login / long silence -> new unit)
        cur: dict[tuple, dict] = {}
        last_obs: dict[tuple, str] = {}
        for ev in self.q(f"SELECT {cols} FROM ev WHERE source_family IN ({fams}) AND {inw} ORDER BY source_id, ordinal", w):
            sid = ev.get("session_id")
            if not sid:
                u = self._new_unit("db_session", ev)
                u["flags"].add("no_session_id")
                self._absorb(u, ev)
                continue
            k = (ev["source_id"], canon_host(ev.get("host")), sid)
            u = cur.get(k)
            t = as_utc(ev.get("ts_utc"))
            if (u is None or ev.get("observation_type") == "login_success" and u["event_count"] > 0
                    and ev["source_family"] == "mssql_audit"
                    or last_obs.get(k) == "logoff" or (t and u["end"] and t - u["end"] > gap)):
                u = self._new_unit("db_session", ev)
                cur[k] = u
            self._absorb(u, ev)
            last_obs[k] = ev.get("observation_type")
        # ---- Windows logon sessions
        curw: dict[tuple, dict] = {}
        for ev in self.q(f"SELECT {cols} FROM ev WHERE source_family = 'win_security' AND {inw} ORDER BY source_id, ordinal", w):
            lid = ev.get("logon_id")
            utype = "host_file" if ev.get("observation_type") == "file_staged" else "win_logon"
            if not lid or lid in SYSTEM_LOGON_IDS or utype == "host_file":
                u = self._new_unit(utype, ev)
                self._absorb(u, ev)
                continue
            k = (ev["source_id"], canon_host(ev.get("host")), lid)
            u = curw.get(k)
            if u is None or (ev.get("observation_type") == "login_success" and u["observations"].get("login_success")):
                u = self._new_unit("win_logon", ev)
                curw[k] = u
            if ev.get("observation_type") in ("login_success", "login_failure") and ev.get("remote_ip"):
                u["client_ip"] = ev["remote_ip"]
                if ev.get("account"):
                    u["account"], u["acct_key"] = ev["account"], self._key(ev["account"])
            self._absorb(u, ev)
        # ---- VPN sessions
        curv: dict[tuple, dict] = {}
        for ev in self.q(f"SELECT {cols} FROM ev WHERE source_family = 'vpn' AND {inw} ORDER BY source_id, ordinal", w):
            sid = ev.get("session_id")
            k = (ev["source_id"], sid)
            u = curv.get(k) if sid else None
            if u is None:
                u = self._new_unit("vpn_session", ev)
                u.update(public_ip=ev.get("remote_ip"), assigned_ip=None, connect=None, disconnect=None)
                if sid:
                    curv[k] = u
            self._absorb(u, ev)
            u["public_ip"] = u.get("public_ip") or ev.get("remote_ip")
            u["assigned_ip"] = u.get("assigned_ip") or ev.get("assigned_ip")
            t = as_utc(ev.get("ts_utc"))
            if ev.get("observation_type") == "vpn_connect" and u["connect"] is None:
                u["connect"] = t
            if ev.get("observation_type") == "vpn_disconnect":
                u["disconnect"] = t
        for u in self.units.values():
            if u["type"] == "vpn_session":
                u["client_ip"] = u["public_ip"]
                u["lease_start"] = u["connect"] or u["start"]
                u["lease_end"] = u["disconnect"]
        # ---- sign-ins (one unit per record)
        for ev in self.q(f"SELECT {cols} FROM ev WHERE source_family = 'entra_signin' AND {inw} ORDER BY source_id, ordinal", w):
            u = self._new_unit("signin", ev)
            self._absorb(u, ev)
            u.update(correlation_id=ev.get("correlation_id"), mfa=ev.get("mfa") or "unknown", location=ev.get("location"),
                     outcome=ev.get("outcome"))
        # ---- web requests: only those that matter (admin/upload/new script, linked by request id, known IPs)
        self._web_units(cols, inw, w)
        for u in self.units.values():
            self._finish_unit(u)
        # ---- flows (after the other units: candidate sources depend on export/staging units)
        self._flow_units(cols, inw, w)

    def _web_units(self, cols, inw, w):
        fams = ",".join(f"'{f}'" for f in WEB_FAMILIES)
        pats = [str(p).lower() for p in self.cfg["web_admin_patterns"]]
        exts = {str(x).lower() for x in self.cfg["web_script_extensions"]}
        paths = [r["url_path"] for r in self.q(
            f"SELECT DISTINCT url_path FROM ev WHERE source_family IN ({fams}) AND url_path IS NOT NULL AND {inw}", w)]
        admin = {p for p in paths if any(fnmatch.fnmatchcase(p.lower(), pat) for pat in pats)}
        first_seen = self.q(f"SELECT url_path, min(ts_utc) AS first FROM ev WHERE source_family IN ({fams}) "
                            "AND url_path IS NOT NULL GROUP BY url_path")
        scripts_new = {r["url_path"] for r in first_seen
                       if r["url_path"].rsplit(".", 1)[-1].lower() in exts and r["first"] is not None
                       and self.w0 <= as_utc(r["first"]) <= self.w1 and as_utc(r["first"]) > self.b0 + dt.timedelta(days=1)}
        self.web_admin_paths, self.web_new_scripts = admin, scripts_new
        db_rids = {r["request_id"] for r in self.q(
            f"SELECT DISTINCT request_id FROM ev WHERE source_family IN ({','.join(repr(f) for f in DB_FAMILIES)}) "
            f"AND request_id IS NOT NULL AND {inw}", w)}
        ind_ips = {i["value"] for i in self.indicators if i["type"] == "ip"}
        interesting = sorted(admin | scripts_new)
        sel = self.q(f"SELECT {cols} FROM ev WHERE source_family IN ({fams}) AND {inw} AND "
                     "(list_contains(?, url_path) OR list_contains(?, request_id) OR list_contains(?, remote_ip)) "
                     "ORDER BY source_id, ordinal", w + [interesting, sorted(db_rids), sorted(ind_ips)])
        rids = sorted({e["request_id"] for e in sel if e.get("request_id")})
        seen = {e["event_id"] for e in sel}
        if rids:
            for e in self.q(f"SELECT {cols} FROM ev WHERE source_family IN ({fams}) AND list_contains(?, request_id) "
                            f"AND {inw}", [rids] + w):
                if e["event_id"] not in seen:
                    sel.append(e)
                    seen.add(e["event_id"])
        for ev in sel:
            u = self._new_unit("web_request", ev)
            self._absorb(u, ev)
            u.update(url_path=ev.get("url_path"), method=ev.get("method"), http_status=ev.get("http_status"),
                     bytes_received=ev.get("bytes_received"), bytes=ev.get("bytes"),
                     admin=ev.get("url_path") in admin, new_script=ev.get("url_path") in scripts_new,
                     entry=self._external(ev.get("remote_ip")))

    def _flow_units(self, cols, inw, w):
        fams = ",".join(f"'{f}'" for f in FLOW_FAMILIES)
        src_ips: set[str] = set()
        for u in self.units.values():
            if u["exports"] or u["type"] == "host_file":
                src_ips |= self.host_ips.get(u["host"] or "", set())
                if u.get("client_ip"):
                    src_ips.add(u["client_ip"])
        ind_ips = {i["value"] for i in self.indicators if i["type"] == "ip"}
        ind_doms = {i["value"] for i in self.indicators if i["type"] == "domain"}
        dests = self.q(f"SELECT DISTINCT dest_ip FROM ev WHERE source_family IN ({fams}) AND dest_ip IS NOT NULL AND {inw}", w)
        external = sorted(r["dest_ip"] for r in dests if self._external(r["dest_ip"]))
        rows = self.q(
            f"SELECT {cols} FROM ev WHERE source_family IN ({fams}) AND {inw} AND "
            "((list_contains(?, remote_ip) AND (list_contains(?, dest_ip) OR (dest_ip IS NULL AND domain IS NOT NULL)) "
            "AND coalesce(bytes, 0) >= ?) OR list_contains(?, dest_ip) OR list_contains(?, domain)) ORDER BY source_id, ordinal",
            w + [sorted(src_ips), external, int(self.cfg["egress_min_bytes"]), sorted(ind_ips), sorted(ind_doms)])
        for ev in rows:
            u = self._new_unit("flow", ev)
            self._absorb(u, ev)
            u.update(dest_ip=ev.get("dest_ip"), dest_port=ev.get("dest_port"), domain=ev.get("domain"),
                     bytes=ev.get("bytes"), method=ev.get("method"), url_path=ev.get("url_path"))
            self._finish_unit(u)

    # ================================================================================================ edges
    def _edge(self, frm: dict, to: dict, label: EdgeLabel, join: str, conf: float, reason: str, *, flags=(),
              window: dict | None = None) -> dict:
        if label != EdgeLabel.DIRECT:
            conf = min(conf, CORRELATED_CAP)
        e = {"edge_id": stable_id("E", frm["unit_id"], to["unit_id"], join), "from": frm["unit_id"], "to": to["unit_id"],
             "label": str(label), "basis": str(Basis.OBSERVATION if label == EdgeLabel.DIRECT else Basis.INFERENCE),
             "join": join, "confidence": round(conf, 3), "confidence_reason": reason, "flags": sorted(set(flags)),
             "window": window, "evidence_ids": (frm["events"][:3] + to["events"][:3])}
        self.edges.append(e)
        return e

    def shared_ips(self) -> dict[str, int]:
        k = int(self.corr["shared_ip_min_accounts"])
        rows = self.q("SELECT remote_ip, list(DISTINCT account) AS accts FROM ev WHERE remote_ip IS NOT NULL AND "
                      "account IS NOT NULL AND source_family IN ('entra_signin','vpn','iis','nginx','apache','proxy') "
                      "AND ts_utc_max >= ? AND ts_utc_min <= ? GROUP BY remote_ip", [self.b0, self.w1])
        out = {}
        for r in rows:
            if not self._external(r["remote_ip"]):
                continue
            keys = {self._key(a) for a in r["accts"]}
            if len(keys) >= k:
                out[r["remote_ip"]] = len(keys)
        for ip in self.cfg["shared_ips"]:
            out[str(ip)] = max(out.get(str(ip), 0), k)
        return out

    def build_edges(self) -> None:
        C = self.corr
        U = self.units
        self.shared = self.shared_ips()
        by_type: dict[str, list[dict]] = defaultdict(list)
        for u in U.values():
            by_type[u["type"]].append(u)
        for lst in by_type.values():
            lst.sort(key=lambda x: (x["start"] or self.w0, x["unit_id"]))
        signin_by_id: dict[str, list[dict]] = defaultdict(list)
        for s in by_type["signin"]:
            for rid in s["request_ids"]:
                signin_by_id[rid].append(s)
            if s.get("correlation_id"):
                signin_by_id[s["correlation_id"]].append(s)
        # 1. sign-in -> VPN: direct on the identity-provider request/correlation id carried by the VPN
        direct_vpn = set()
        for v in by_type["vpn_session"]:
            for rid in v["request_ids"]:
                for s in signin_by_id.get(rid, []):
                    self._edge(s, v, EdgeLabel.DIRECT, "signin_request_id", DIRECT_CONFIDENCE,
                               "exact identity-provider request id recorded by the VPN for this session")
                    direct_vpn.add(v["unit_id"])
        # 2. sign-in -> VPN: correlated on the same account within the configured window
        for v in by_type["vpn_session"]:
            if v["unit_id"] in direct_vpn or not v["acct_key"] or v["lease_start"] is None:
                continue
            win = _td(C["signin_to_vpn_s"])
            cands = [s for s in by_type["signin"] if s["acct_key"] == v["acct_key"] and s["start"] is not None
                     and s.get("outcome") != "failure"
                     and v["lease_start"] - win - _td(self._unc(s["unc"]) + self._unc(v["unc"])) <= s["start"]
                     <= v["lease_start"] + _td(self._unc(s["unc"]) + self._unc(v["unc"]))]
            for s in cands:
                same_ip = s["client_ip"] and s["client_ip"] == v["public_ip"]
                shared = same_ip and s["client_ip"] in self.shared
                conf = 0.6 + (0.1 if same_ip and not shared else 0.0)
                flags = ["account_name_normalised"] if (s["account"] or "").lower() != (v["account"] or "").lower() else []
                why = [f"same account within {int(C['signin_to_vpn_s'])} s before the VPN session; no shared identifier"]
                if shared:
                    conf *= 0.5
                    flags.append("shared_ip")
                    why.append(f"public address shared by {self.shared[s['client_ip']]} accounts")
                if len(cands) > 1:
                    conf /= len(cands)
                    flags.append(f"ambiguous:{len(cands)}")
                    why.append(f"{len(cands)} candidate sign-ins")
                if s["unc"] is None or v["unc"] is None:
                    conf -= 0.05
                    why.append("clock uncertainty not documented for a source (assumed)")
                gap_s = (v["lease_start"] - s["start"]).total_seconds()
                self._edge(s, v, EdgeLabel.CORRELATED, "account_time_window", conf, "; ".join(why), flags=flags,
                           window={"configured_s": C["signin_to_vpn_s"], "observed_gap_s": round(gap_s, 1)})
        # 3. VPN-assigned address -> downstream sessions (database, Windows logon, web) inside the lease
        by_assigned: dict[str, list[dict]] = defaultdict(list)
        for v in by_type["vpn_session"]:
            if v.get("assigned_ip"):
                by_assigned[v["assigned_ip"]].append(v)
        for u in by_type["db_session"] + by_type["win_logon"] + by_type["web_request"]:
            ip = u.get("client_ip")
            if not ip or ip not in by_assigned or u["start"] is None:
                continue
            matches = []
            for v in by_assigned[ip]:
                tol = _td(C["vpn_lease_tolerance_s"] + self._unc(v["unc"]) + self._unc(u["unc"]))
                end = v["lease_end"]
                open_end = end is None
                if open_end:
                    end = v["lease_start"] + dt.timedelta(hours=24)
                if v["lease_start"] - tol <= u["start"] <= end + tol:
                    matches.append((v, open_end))
            for v, open_end in matches:
                conf, why, flags = 0.75, ["client address was assigned to this VPN session at that time (lease)"], []
                if open_end:
                    conf -= 0.1
                    why.append("VPN disconnect not logged; lease assumed to last at most 24 h")
                    flags.append("lease_end_assumed")
                if len(matches) > 1:
                    conf /= len(matches)
                    flags.append(f"ambiguous:{len(matches)}")
                if v["unc"] is None or u["unc"] is None:
                    conf -= 0.05
                    why.append("clock uncertainty not documented for a source (assumed)")
                self._edge(v, u, EdgeLabel.CORRELATED, "vpn_lease", conf, "; ".join(why), flags=flags,
                           window={"configured_s": C["vpn_lease_tolerance_s"], "lease_start": iso(v["lease_start"]),
                                   "lease_end": iso(v["lease_end"])})
        # 4. web requests sharing a request id (gateway -> backend), and web -> database (session context)
        web_by_rid: dict[str, list[dict]] = defaultdict(list)
        for wq in by_type["web_request"]:
            for rid in wq["request_ids"]:
                web_by_rid[rid].append(wq)
        for ws in web_by_rid.values():
            for a in ws:
                for b in ws:
                    if a is b or a["source_id"] == b["source_id"]:
                        continue
                    a_ips = self.host_ips.get(self.source_host.get(a["source_id"]) or "", set())
                    if b.get("client_ip") in a_ips or (a.get("entry") and not b.get("entry")):
                        self._edge(a, b, EdgeLabel.DIRECT, "web_request_id", DIRECT_CONFIDENCE,
                                   "exact request id forwarded from the gateway to the backend")
        for d in by_type["db_session"]:
            for rid in d["request_ids"]:
                for wq in web_by_rid.get(rid, []):
                    if wq.get("entry") and any(x for x in web_by_rid[rid] if not x.get("entry")):
                        continue
                    self._edge(wq, d, EdgeLabel.DIRECT, "request_id_in_session_context", DIRECT_CONFIDENCE,
                               "exact web request id recorded in the database session context")
        # 5. external web activity -> VPN session from the same public address (bounded window)
        for wq in by_type["web_request"]:
            if not wq.get("entry") or wq["start"] is None:
                continue
            for v in by_type["vpn_session"]:
                if v.get("public_ip") != wq["client_ip"] or v["lease_start"] is None:
                    continue
                gap_s = (v["lease_start"] - wq["start"]).total_seconds()
                if 0 <= gap_s <= C["web_to_vpn_s"]:
                    conf, flags = 0.45, []
                    why = [f"same public address within {int(C['web_to_vpn_s'])} s before the VPN session"]
                    if wq["client_ip"] in self.shared:
                        conf *= 0.5
                        flags.append("shared_ip")
                        why.append(f"address shared by {self.shared[wq['client_ip']]} accounts")
                    self._edge(wq, v, EdgeLabel.CORRELATED, "public_ip_time_window", conf, "; ".join(why), flags=flags,
                               window={"configured_s": C["web_to_vpn_s"], "observed_gap_s": round(gap_s, 1)})
        # 6. Windows network logon on the database host from the client address -> database session
        logons = defaultdict(list)
        for wl in by_type["win_logon"]:
            if wl.get("client_ip") and wl["observations"].get("login_success"):
                logons[(wl["host"], wl["client_ip"])].append(wl)
        for d in by_type["db_session"]:
            cands = [wl for wl in logons.get((d["host"], d.get("client_ip")), [])
                     if d["start"] and wl["start"] and abs((d["start"] - wl["start"]).total_seconds())
                     <= C["host_logon_to_db_s"] + self._unc(d["unc"]) + self._unc(wl["unc"])]
            for wl in cands:
                conf = 0.6 / len(cands)
                flags = [f"ambiguous:{len(cands)}"] if len(cands) > 1 else []
                if wl["acct_key"] and d["acct_key"] and wl["acct_key"] != d["acct_key"]:
                    conf *= 0.5
                    flags.append("account_differs")
                self._edge(wl, d, EdgeLabel.CORRELATED, "host_logon_address_time", conf,
                           f"network logon on the same host from the same address within {int(C['host_logon_to_db_s'])} s",
                           flags=flags, window={"configured_s": C["host_logon_to_db_s"]})
        # 7. export on a database host -> file staged on that host shortly after
        files = defaultdict(list)
        for hf in by_type["host_file"]:
            files[hf["host"]].append(hf)
        link = float(C["staging_link_s"])
        for d in by_type["db_session"]:
            for x in d["exports"]:
                if x["ts"] is None:
                    continue
                for hf in files.get(d["host"], []):
                    if hf["start"] and 0 <= (hf["start"] - x["ts"]).total_seconds() <= link + self._unc(hf["unc"]):
                        self._edge(d, hf, EdgeLabel.CORRELATED, "export_then_file_on_host", 0.6,
                                   f"file with a staging extension written on the database host within {int(link)} s "
                                   "of an export command; content not verified", window={"configured_s": link})
        # 8. export/staging -> outbound flow from the same host or client (bounded window): egress_suspected
        flows_by_src = defaultdict(list)
        for f in by_type["flow"]:
            if f.get("client_ip"):
                flows_by_src[f["client_ip"]].append(f)
        ind_vals = {i["value"] for i in self.indicators}
        linked_files = {e["to"] for e in self.edges if e["join"] == "export_then_file_on_host"}
        stagers = [u for u in by_type["db_session"] if u["exports"]] + \
            [h for h in by_type["host_file"] if h["unit_id"] not in linked_files]
        for f in by_type["flow"]:
            if f["start"] is None:
                continue
            cands = []
            for s in stagers:
                ips = set(self.host_ips.get(s["host"] or "", set()))
                if s["type"] == "db_session" and s.get("client_ip"):
                    ips.add(s["client_ip"])
                if f["client_ip"] not in ips:
                    continue
                ts = [x["ts"] for x in s["exports"] if x["ts"]] if s["type"] == "db_session" else [s["start"]]
                tol = self._unc(s["unc"]) + self._unc(f["unc"])
                ok = [t for t in ts if t and -tol <= (f["start"] - t).total_seconds() <= C["data_to_egress_s"] + tol]
                if ok:
                    cands.append((s, min(ok)))
            for s, t in cands:
                conf = 0.5
                why = [f"outbound flow from the same host within {int(C['data_to_egress_s'])} s after export/staging; "
                       "payload and destination content unknown"]
                flags = []
                if f.get("dest_ip") in ind_vals or f.get("domain") in ind_vals:
                    conf += 0.1
                    flags.append("indicator_match")
                    why.append("destination matches a partner indicator (not attribution)")
                if len(cands) > 1:
                    conf /= len(cands) ** 0.5
                    flags.append(f"ambiguous:{len(cands)}")
                self._edge(s, f, EdgeLabel.CORRELATED, "staging_then_outbound_flow", conf, "; ".join(why), flags=flags,
                           window={"configured_s": C["data_to_egress_s"],
                                   "observed_gap_s": round((f["start"] - t).total_seconds(), 1)})
        self.edges.sort(key=lambda e: e["edge_id"])
        seen, uniq = set(), []
        for e in self.edges:
            if e["edge_id"] not in seen:
                seen.add(e["edge_id"])
                uniq.append(e)
        self.edges = uniq

    # ================================================================================================ gaps
    def build_gaps(self) -> None:
        gaps: list[dict] = []
        W0, W1 = self.w0, self.w1

        def add(kind, desc, *, source_id=None, host=None, database=None, start=None, end=None, basis="observation",
                evidence=None, scope="source"):
            gaps.append({"gap_id": stable_id("GAP", kind, source_id, host, database, iso(start), iso(end)), "kind": kind,
                         "scope": scope, "source_id": source_id, "host": host, "database": database, "start": iso(start),
                         "end": iso(end), "basis": basis, "consequence_class": str(Consequence.UNDETERMINED),
                         "description": desc, "evidence_ids": evidence or []})

        if not self.coverage:
            add("no_log_sources", "No access-path logs were ingested: access, export and egress are not assessable.",
                start=W0, end=W1, basis="observation", scope="case")
        fam_groups = {"database audit": DB_FAMILIES, "network/VPN": ("vpn",), "egress (firewall/proxy)": FLOW_FAMILIES,
                      "identity sign-in": ("entra_signin",), "Windows security": ("win_security",), "web server": WEB_FAMILIES}
        have = {c["family"] for c in self.coverage.values()}
        for name, fams in fam_groups.items():
            if not have & set(fams):
                add("no_source_family", f"No {name} logs were supplied; links through this layer cannot be assessed.",
                    start=W0, end=W1, scope="family")
        self.source_cover: dict[str, list[tuple]] = {}
        for sid, c in sorted(self.coverage.items()):
            if c["family"] == "indicators":
                continue
            dc = c.get("declared_coverage") or {}
            start = as_utc(dc.get("start")) if dc.get("start") else as_utc(c.get("first_event_utc"))
            end = as_utc(dc.get("end")) if dc.get("end") else as_utc(c.get("last_event_utc"))
            if not dc:
                add("coverage_undeclared", "Coverage period not declared by the supplier; first/last events used.",
                    source_id=sid, start=start, end=end, basis="inference")
            covered = [(start, end)] if start and end else []
            minus = []
            if start and start > W0:
                add("outside_coverage", "Source does not cover the start of the analysis window.", source_id=sid,
                    start=W0, end=min(start, W1))
            if end and end < W1:
                add("outside_coverage", "Source does not cover the end of the analysis window.", source_id=sid,
                    start=max(end, W0), end=W1)
            for m in dc.get("missing") or []:
                a, b = as_utc(m["start"]), as_utc(m["end"])
                minus.append((a, b))
                add("declared_missing", f"Declared missing period: {m.get('reason') or 'not stated'}.", source_id=sid,
                    start=a, end=b, basis="observation")
            if c.get("events_without_resolvable_time"):
                add("time_zone_unknown", f"{c['events_without_resolvable_time']} records have no resolvable time zone and "
                    "cannot be placed on the UTC timeline (shown only as possibly inside the window).", source_id=sid,
                    start=W0, end=W1)
            if c.get("parse_failures"):
                add("parse_failures", f"{c['parse_failures']} records could not be parsed (see coverage record).",
                    source_id=sid)
            for s in self._silences(sid, c, covered, minus):
                minus.append(s)
                add("possible_missing_period", "Source is silent far longer than its normal event rate (possible "
                    "missing logs; not proof).", source_id=sid, start=s[0], end=s[1], basis="inference")
            self.source_cover[sid] = subtract_intervals(covered, minus)
        # auditing switched off / logs cleared, with scope
        self.audit_gaps: list[dict] = []
        rows = self.q("SELECT event_id, source_id, source_family, ordinal, ts_utc, host, database, operation, "
                      "observation_type, outcome, session_id FROM ev WHERE observation_type IN "
                      "('auditing_disabled','auditing_enabled','log_cleared','auditing_state_changed') "
                      "AND ts_utc IS NOT NULL ORDER BY source_id, ts_utc, ordinal")
        for r in rows:
            if r["observation_type"] not in ("auditing_disabled", "log_cleared") or r["outcome"] == "failure":
                continue
            t = as_utc(r["ts_utc"])
            host = canon_host(r.get("host")) or self.source_host.get(r["source_id"])
            op = r.get("operation") or ""
            db_scope = r.get("database") if ("database_audit" in op or op == "set_audit_setting") else None
            if r["observation_type"] == "log_cleared":
                add("log_cleared", "Security log cleared on the host: earlier local records may be missing; the extent "
                    "is unknown.", source_id=r["source_id"], host=host, end=t, evidence=[r["event_id"]], scope="host")
                self.audit_gaps.append({"source_id": r["source_id"], "host": host, "database": None, "start": None,
                                        "end": t, "kind": "log_cleared", "event_id": r["event_id"]})
                continue
            end, enabled_by = None, None
            for r2 in rows:
                t2 = as_utc(r2["ts_utc"])
                if r2["observation_type"] != "auditing_enabled" or t2 <= t or r2["source_id"] != r["source_id"]:
                    continue
                op2 = r2.get("operation") or ""
                if db_scope and not (r2.get("database") or "").lower() == db_scope.lower():
                    continue
                if not db_scope and "database_audit" in op2:
                    continue
                end, enabled_by = t2, r2["event_id"]
                break
            if op == "set_audit_setting" and r.get("session_id"):
                last = self.q("SELECT max(ts_utc) AS t FROM ev WHERE source_id = ? AND session_id = ?",
                              [r["source_id"], r["session_id"]])
                end = as_utc(last[0]["t"]) if last and last[0]["t"] else end
            cov = self.source_cover.get(r["source_id"]) or []
            open_end = end is None
            if open_end:
                end = max([b for _a, b in cov] + [W1])
            scope_txt = f"database {db_scope}" if db_scope else f"host {host}"
            add("auditing_disabled", f"Auditing was switched off for {scope_txt}"
                + ("; no re-enable event was found (open-ended)." if open_end else " until it was re-enabled."),
                source_id=r["source_id"], host=host, database=db_scope, start=t, end=end,
                evidence=[r["event_id"]] + ([enabled_by] if enabled_by else []), scope="database" if db_scope else "host")
            self.audit_gaps.append({"source_id": r["source_id"], "host": host, "database": db_scope, "start": t, "end": end,
                                    "kind": "auditing_disabled", "event_id": r["event_id"], "open_ended": open_end})
        gaps.sort(key=lambda g: (g["start"] or "", g["kind"], g["gap_id"]))
        self.gaps = gaps

    def _silences(self, sid, c, covered, minus) -> list[tuple]:
        if not covered or not c.get("events"):
            return []
        a, b = covered[0]
        days = max((b - a).total_seconds() / 86400.0, 1e-6)
        rate = c["events"] / days
        if rate < 50:
            return []
        thr = max(float(self.cfg["silence_gap_s"]), 10 * 86400.0 / rate)
        rows = self.q("SELECT prev, t FROM (SELECT ts_utc AS t, lag(ts_utc) OVER (ORDER BY ts_utc) AS prev FROM ev "
                      "WHERE source_id = ? AND ts_utc IS NOT NULL) WHERE prev IS NOT NULL AND "
                      "epoch(t) - epoch(prev) > ?", [sid, thr])
        out = []
        for r in rows:
            s = (as_utc(r["prev"]), as_utc(r["t"]))
            if any(m[0] <= s[1] and s[0] <= m[1] for m in minus):
                continue  # already explained by a declared gap
            out.append(s)
        return out

    # ================================================================================================ paths
    def build_paths(self) -> None:
        U = self.units
        incoming: dict[str, list[dict]] = defaultdict(list)
        outgoing: dict[str, list[dict]] = defaultdict(list)
        for e in self.edges:
            incoming[e["to"]].append(e)
            outgoing[e["from"]].append(e)
        routes: dict[tuple, list[dict]] = defaultdict(list)
        for u in U.values():
            if u["type"] == "db_session":
                sens = [k for k in u["tables"] if self.sensitive.matches(k)]
                if not sens and not u["exports"]:
                    continue
                key = (u["source_id"], u["host"], u["acct_key"] or "?", u.get("client_ip") or u.get("client_host") or "?",
                       (u.get("application") or "?").lower())
                routes[key].append(u)
            elif u["type"] == "host_file" and not incoming.get(u["unit_id"]):
                routes[(u["source_id"], u["host"], u["acct_key"] or "?", "file-staging", "")].append(u)
        corr_by_table = defaultdict(list)
        for c in self.corroborations:
            for t in c.get("tables", []):
                corr_by_table[norm_table(t)].append(c)
        paths = []
        for key, sessions in routes.items():
            sessions.sort(key=lambda x: (x["start"] or self.w0, x["unit_id"]))
            sids = {s["unit_id"] for s in sessions}
            # upstream
            up_units, up_edges, frontier, depth = {}, {}, list(sids), 0
            while frontier and depth < 5:
                nxt = []
                for uid in frontier:
                    for e in incoming.get(uid, []):
                        if e["from"] in sids or e["edge_id"] in up_edges:
                            continue
                        up_edges[e["edge_id"]] = e
                        if e["from"] not in up_units:
                            up_units[e["from"]] = U[e["from"]]
                            nxt.append(e["from"])
                frontier, depth = nxt, depth + 1
            # downstream: staging files and egress flows
            down_edges, staged = {}, {}
            for uid in sids:
                for e in outgoing.get(uid, []):
                    down_edges[e["edge_id"]] = e
                    if U[e["to"]]["type"] == "host_file":
                        staged[e["to"]] = U[e["to"]]
                        for e2 in outgoing.get(e["to"], []):
                            down_edges[e2["edge_id"]] = e2
            egress = {e["to"]: U[e["to"]] for e in down_edges.values() if U[e["to"]]["type"] == "flow"}
            paths.append(self._path(key, sessions, up_units, up_edges, down_edges, staged, egress, corr_by_table))
        paths.sort(key=lambda p: (-p["rank_score"], p["first_activity"] or "", p["path_id"]))
        for i, p in enumerate(paths, 1):
            p["rank"] = i
        self.paths = paths

    def _stage(self, u: dict) -> str:
        """Chain stage of an upstream unit: web/identity -> network -> host/application -> database."""
        t = u["type"]
        if t == "signin" or (t == "web_request" and u.get("entry")):
            return "web_identity"
        if t == "vpn_session":
            return "network"
        if t in ("win_logon", "web_request"):
            return "host_application"
        return t

    def _path(self, key, sessions, up_units, up_edges, down_edges, staged, egress, corr_by_table) -> dict:
        tables: dict[str, dict] = {}
        for s in sessions:
            for k, tb in s["tables"].items():
                agg = tables.setdefault(k, {"table": tb["table"], "sensitive": self.sensitive.matches(k), "ops": Counter(),
                                            "observations": set(), "rows": 0, "rows_unknown": False, "first": None,
                                            "last": None, "classes": set(), "evidence_ids": [], "sessions": set(),
                                            "time_resolved": True})
                agg["ops"].update(tb["ops"])
                agg["observations"] |= tb["observations"]
                agg["rows"] += tb["rows"]
                agg["rows_unknown"] |= tb["rows_unknown"]
                agg["classes"] |= tb["classes"]
                agg["sessions"].add(s["unit_id"])
                agg["time_resolved"] &= tb["time_resolved"]
                for b in ("first", "last"):
                    v = tb[b]
                    if v is not None and (agg[b] is None or (v < agg[b] if b == "first" else v > agg[b])):
                        agg[b] = v
                agg["evidence_ids"] = (agg["evidence_ids"] + tb["events"])[:MAX_EVIDENCE]
        flows_after = sorted(f["start"] for f in egress.values() if f["start"])
        egress_edges = [e for e in down_edges.values() if self.units[e["to"]]["type"] == "flow"]
        for k, agg in tables.items():
            exported_at = [x["ts"] for s in sessions for x in s["exports"]
                           if x["ts"] and any(norm_table(o) == k or norm_table(o).endswith("." + k.split(".")[-1])
                                              and norm_table(o).split(".")[0] == k.split(".")[0] for o in x["objects"])]
            if exported_at and flows_after and any(f >= min(exported_at) - dt.timedelta(minutes=5) for f in flows_after):
                agg["classes"].add(str(Consequence.EGRESS_SUSPECTED))
                agg["egress_linked"] = True
            agg["consequence_class"] = str(strongest(agg["classes"]))
            agg["corroborations"] = [c["corroboration_id"] for c in corr_by_table.get(k, [])]
        sens = {k: t for k, t in tables.items() if t["sensitive"]}
        relevant = sens or tables
        if staged and not tables:
            cls = Consequence.EXPORT_OR_STAGING_OBSERVED
        else:
            cls = strongest(t["consequence_class"] for t in relevant.values()) if relevant else Consequence.UNDETERMINED
        # chain stages
        stage_units: dict[str, list] = defaultdict(list)
        for u in up_units.values():
            stage_units[self._stage(u)].append(u)
        stage_edges: dict[str, list] = defaultdict(list)
        for e in up_edges.values():
            stage_edges[self._stage(self.units[e["from"]])].append(e)
        first = sessions[0]
        stages = []
        for st in ("web_identity", "network", "host_application"):
            es = stage_edges.get(st, [])
            if not es:
                stages.append({"stage": st, "label": str(EdgeLabel.UNRESOLVED), "confidence": 0.0, "units": [],
                               "reason": self._unresolved_reason(st, first)})
                continue
            best = max(es, key=lambda e: (e["label"] == "direct", e["confidence"]))
            froms = sorted({e["from"] for e in es})
            stages.append({"stage": st, "label": best["label"], "confidence": best["confidence"], "units": froms[:10],
                           "unit_count": len(froms), "unit_types": sorted({self.units[f]["type"] for f in froms}),
                           "alternatives": len(froms), "reason": best["confidence_reason"]})
        stages.append({"stage": "database", "label": "observed", "confidence": DIRECT_CONFIDENCE,
                       "units": [s["unit_id"] for s in sessions[:10]], "unit_count": len(sessions),
                       "reason": "database audit/log records of this route"})
        if staged:
            se = [e for e in down_edges.values() if self.units[e["to"]]["type"] == "host_file"]
            stages.append({"stage": "staging", "label": "correlated" if se else "observed",
                           "confidence": max([e["confidence"] for e in se] or [DIRECT_CONFIDENCE]),
                           "units": sorted(staged)[:10], "unit_count": len(staged),
                           "reason": se[0]["confidence_reason"] if se else "file staging observed on the host"})
        if egress_edges:
            best = max(egress_edges, key=lambda e: e["confidence"])
            stages.append({"stage": "egress", "label": best["label"], "confidence": best["confidence"],
                           "units": sorted(egress)[:10], "unit_count": len(egress), "reason": best["confidence_reason"]})
        else:
            has_exports = any(s["exports"] for s in sessions) or bool(staged)
            stages.append({"stage": "egress", "label": str(EdgeLabel.UNRESOLVED), "confidence": 0.0, "units": [],
                           "reason": self._egress_reason(has_exports)})
        resolved = [s for s in stages if s["label"] in ("direct", "correlated")]
        weakest = min(resolved, key=lambda s: s["confidence"]) if resolved else None
        chain_conf = weakest["confidence"] if weakest else 0.0
        accounts = sorted({a for s in sessions for a in s["accounts"]})
        upstream_accounts = sorted({u["account"] for u in up_units.values() if u.get("account")})
        anchor = {"source_id": key[0], "host": key[1], "account": first["account"], "client_ip": first.get("client_ip"),
                  "client_host": first.get("client_host"), "application": first.get("application")}
        starts = [s["start"] for s in sessions if s["start"]]
        ends = [s["end"] for s in sessions if s["end"]]
        pid = stable_id("PATH", *key)
        tmins = [s["tmin"] for s in sessions if s["tmin"]]
        tmaxs = [s["tmax"] for s in sessions if s["tmax"]]
        limitations = []
        if any(t["rows_unknown"] for t in relevant.values()):
            limitations.append("volume unknown: the log does not record rows/bytes for some statements")
        if cls in (Consequence.ACCESS_OBSERVED,) and relevant:
            limitations.append("SELECT is not proof of extraction; data returned to the client is not visible after the "
                               "query (endpoint evidence needed)")
        if egress_edges:
            limitations.append("outbound flows are linked by host and time only; their content and which records they "
                               "carried are unknown")
        if any(t.get("corroborations") for t in relevant.values()):
            limitations.append("a corroboration exists for at least one table; logs do not establish that this path "
                               "carried the corroborated copy")
        if not resolved:
            limitations.append("no upstream evidence links this database access to a sign-in, VPN session or host logon")
        limitations.append("does not establish the initial intrusion vector (no endpoint evidence)")
        claim = Claim(
            claim_id=pid, statement=self._path_statement(cls, relevant),
            basis=Basis.OBSERVATION, source_ids=sorted({s["source_id"] for s in sessions}),
            evidence_ids=[e for t in relevant.values() for e in t["evidence_ids"]][:MAX_EVIDENCE] or first["events"][:5],
            parser=METHOD_VERSION, time_precision=TimePrecision.SECOND if all(s["time_resolved"] for s in sessions)
            else TimePrecision.UNKNOWN, confidence=DIRECT_CONFIDENCE if relevant else 0.5,
            confidence_reason="database records of the access itself; attribution beyond the logged account depends on "
                              "the chain stages", observation_type=",".join(sorted({o for t in relevant.values()
                                                                                    for o in t["observations"]})) or None,
            consequence_class=cls, source_time_window=[iso(min(starts)) if starts else None,
                                                      iso(max(ends)) if ends else None],
            limitations=limitations,
        )
        score = _CLASS_WEIGHT.get(str(cls), 0) * 100 + len(egress) * 5 + len(staged) * 3 + \
            sum(1 for t in relevant.values() if t["sensitive"]) * 2 + (0 if account_matches(first["account"], self.cfg["service_accounts"]) else 10)
        return {
            "path_id": pid, "route": anchor, "sessions": [s["unit_id"] for s in sessions[:50]], "session_count": len(sessions),
            "first_activity": iso(min(starts)) if starts else None, "last_activity": iso(max(ends)) if ends else None,
            "earliest_supported": iso(min(tmins)) if tmins else None,
            "latest_supported": iso(max(tmaxs)) if tmaxs else None,
            "tables": [self._table_out(t) for k, t in sorted(tables.items())],
            "consequence_class": str(cls), "observation_type": claim.observation_type, "stages": stages,
            "edges": sorted(list(up_edges) + list(down_edges)), "confidence": claim.confidence,
            "chain_confidence": round(chain_conf, 3),
            "chain_confidence_reason": (f"weakest resolved stage: {weakest['stage']} ({weakest['label']}, "
                                        f"{weakest['confidence']})" if weakest else "no stage beyond the database is resolved"),
            "accounts": accounts, "upstream_accounts": upstream_accounts,
            "service_account": account_matches(first["account"], self.cfg["service_accounts"]),
            "staged_files": sorted(staged)[:10], "egress_units": sorted(egress)[:20],
            "egress_bytes_logged": sum(int(f.get("bytes") or 0) for f in egress.values()) or None,
            "egress_destinations": sorted({f.get("dest_ip") or f.get("domain") for f in egress.values()} - {None}),
            "claim": claim.to_dict(), "limitations": limitations, "rank_score": score, "anomalies": [],
            "indicator_matches": [],
        }

    def _table_out(self, t: dict) -> dict:
        return {"table": t["table"], "sensitive": t["sensitive"], "operations": dict(sorted(t["ops"].items())),
                "observation_types": sorted(t["observations"]), "consequence_class": t["consequence_class"],
                "rows_logged": None if t["rows_unknown"] and not t["rows"] else t["rows"],
                "volume": "volume unknown" if t["rows_unknown"] else "rows as logged",
                "first": iso(t["first"]), "last": iso(t["last"]), "evidence_ids": t["evidence_ids"][:20],
                "corroborations": t.get("corroborations", []), "egress_linked": bool(t.get("egress_linked"))}

    def _path_statement(self, cls, tables) -> str:
        n = len(tables)
        base = {
            Consequence.ACCESS_OBSERVED: f"Logged read/modify access to {n} table(s); no export or egress linked.",
            Consequence.EXPORT_OR_STAGING_OBSERVED: f"Export or staging of data from {n} table(s) observed; no linked "
                                                    "egress beyond the hospital.",
            Consequence.EGRESS_SUSPECTED: f"Export/staging of {n} table(s) followed by outbound flow(s) compatible with "
                                          "exfiltration; payload and records carried are unknown.",
        }
        return base.get(cls, "Outcome cannot be determined from the available logs.")

    def _unresolved_reason(self, stage: str, u: dict) -> str:
        have = {c["family"] for c in self.coverage.values()}
        if stage == "network":
            if "vpn" not in have:
                return "no VPN logs supplied"
            return "no VPN session was assigned the client address at that time (client may be on the internal network)"
        if stage == "web_identity":
            if "entra_signin" not in have and not have & set(WEB_FAMILIES):
                return "no sign-in or web logs supplied"
            return "no sign-in or external web request linked by identifier or configured window"
        if "win_security" not in have and not have & set(WEB_FAMILIES):
            return "no Windows security or web logs supplied"
        return "no host logon or web application request from the client address within the configured window"

    def _egress_reason(self, has_exports: bool) -> str:
        have = {c["family"] for c in self.coverage.values()}
        if not have & set(FLOW_FAMILIES):
            return "no firewall/proxy logs supplied: egress not assessable"
        if not has_exports:
            return "no export/staging on this route; egress is linked only after staging"
        return "no outbound flow from the host/client within the configured window after export (in covered periods)"

    # ================================================================================================ tables
    def build_tables(self) -> None:
        W0, W1 = self.w0, self.w1
        names: dict[str, str] = {norm_table(t): t for t in self.declared_tables}
        observed = self.q("SELECT DISTINCT unnest(objects) AS o, database FROM ev WHERE len(objects) > 0")
        for r in observed:
            o = r["o"]
            full = o if o.count(".") >= 2 or not r["database"] else f"{r['database']}.{o}"
            if self.sensitive.matches(full):
                names.setdefault(norm_table(full), full)
        db_sources = {sid: c for sid, c in self.coverage.items() if c["family"] in DB_FAMILIES}
        seen_dbs = defaultdict(set)
        for r in self.q("SELECT DISTINCT source_id, lower(database) AS d FROM ev WHERE database IS NOT NULL"):
            seen_dbs[r["source_id"]].add(r["d"])
        per_table_units = defaultdict(list)
        for u in self.units.values():
            if u["type"] == "db_session":
                for k in u["tables"]:
                    per_table_units[k].append(u)
        path_class = defaultdict(list)
        path_of_unit = {}
        for p in self.paths:
            for t in p["tables"]:
                path_class[norm_table(t["table"])].append((p["path_id"], t["consequence_class"]))
            for s in p["sessions"]:
                path_of_unit[s] = p["path_id"]
        corr_by_table = defaultdict(list)
        for c in self.corroborations:
            for t in c.get("tables", []):
                corr_by_table[norm_table(t)].append(c)
        out = []
        for k in sorted(names):
            name = names[k]
            db = name.split(".")[0].lower()
            covering = []
            for sid, c in db_sources.items():
                dbs = (c.get("declared_coverage") or {}).get("databases")
                if dbs is not None:
                    if any(fnmatch.fnmatchcase(db, str(x).lower()) for x in dbs):
                        covering.append(sid)
                elif db in seen_dbs.get(sid, set()):
                    covering.append(sid)
            cover = []
            for sid in covering:
                ivs = list(self.source_cover.get(sid) or [])
                minus = [(g["start"] or W0, g["end"]) for g in self.audit_gaps
                         if g["source_id"] == sid and g["kind"] == "auditing_disabled"
                         and (g["database"] is None or g["database"].lower() == db)]
                cover += subtract_intervals(ivs, minus)
            cover = clip(merge_intervals(cover), W0, W1)
            not_assessable = subtract_intervals([(W0, W1)], cover)
            units = per_table_units.get(k, [])
            windows = []
            # observed windows: cluster events of this table by time
            pts = sorted((u["tables"][k]["first"], u["tables"][k]["last"], u) for u in units if u["tables"][k]["first"])
            gap = _td(self.corr["session_gap_s"])
            cur = None
            for a, b, u in pts:
                if cur and a - cur["end"] <= gap:
                    cur["end"] = max(cur["end"], b)
                    cur["units"].append(u)
                else:
                    cur = {"start": a, "end": b, "units": [u]}
                    windows.append(cur)
            wout = []
            for wnd in windows:
                us = wnd["units"]
                classes = {c for u in us for c in u["tables"][k]["classes"]}
                wout.append({"window_class": "confirmed", "start": iso(wnd["start"]), "end": iso(wnd["end"]),
                             "basis": str(Basis.OBSERVATION), "consequence_class": str(strongest(classes)),
                             "accounts": sorted({u["account"] for u in us if u["account"]}),
                             "sessions": sorted(u["unit_id"] for u in us)[:20], "session_count": len(us),
                             "paths": sorted({path_of_unit[u["unit_id"]] for u in us if u["unit_id"] in path_of_unit}),
                             "evidence_ids": [e for u in us for e in u["tables"][k]["events"]][:MAX_EVIDENCE],
                             "rows_logged": sum(u["tables"][k]["rows"] for u in us),
                             "volume_unknown": any(u["tables"][k]["rows_unknown"] for u in us),
                             "time_uncertainty_s": max(self._unc(u["unc"]) for u in us)})
            unresolved_time = [u for u in units if not u["tables"][k]["time_resolved"]]
            for u in unresolved_time:
                wout.append({"window_class": "possible", "start": iso(u["tmin"]), "end": iso(u["tmax"]),
                             "basis": str(Basis.INFERENCE), "consequence_class": str(strongest(u["tables"][k]["classes"])),
                             "accounts": [u["account"]] if u["account"] else [], "sessions": [u["unit_id"]],
                             "evidence_ids": u["tables"][k]["events"][:10],
                             "reason": "event time could not be resolved to UTC; bounds cover every possible offset"})
            for a, b in not_assessable:
                reason = []
                for g in self.audit_gaps:
                    if g["kind"] == "auditing_disabled" and g["start"] and g["start"] < b and g["end"] > a and \
                            (g["database"] is None or g["database"].lower() == db):
                        reason.append("auditing disabled")
                if not covering:
                    reason.append("no database audit source covers this database")
                wout.append({"window_class": "not_assessable", "start": iso(a), "end": iso(b),
                             "basis": str(Basis.OBSERVATION) if reason else str(Basis.UNKNOWN),
                             "consequence_class": str(Consequence.UNDETERMINED),
                             "reason": "; ".join(sorted(set(reason))) or "outside covered log periods (declared gaps, "
                                                                         "coverage limits or silence)"})
            wout.sort(key=lambda x: (x["start"] or "", x["window_class"]))
            classes = [w["consequence_class"] for w in wout if w["window_class"] in ("confirmed", "possible")]
            for _pid, c in path_class.get(k, []):
                classes.append(c)
            corrs = corr_by_table.get(k, [])
            qualifying = [c for c in corrs if c.get("qualifies_as_exfiltration_evidence") and c.get("evidence_ids")
                          and c.get("kind") in EXFILTRATION_EVIDENCE_KINDS]
            if qualifying:
                cls = Consequence.EXFILTRATION_EVIDENCED
            elif classes:
                cls = strongest(classes)
            elif not_assessable:
                cls = Consequence.UNDETERMINED
            else:
                cls = None
            wc = [w["window_class"] for w in wout]
            window_class = next((c for c in ("confirmed", "possible", "not_assessable") if c in wc), "none_observed")
            claim = self._table_claim(name, cls, wout, qualifying, covering)
            out.append({"table": name, "database": name.split(".")[0], "sensitive": True,
                        "declared": k in {norm_table(t) for t in self.declared_tables},
                        "consequence_class": str(cls) if cls else None,
                        "status": "no_access_observed" if cls is None else "assessed",
                        "window_class": window_class, "window_classes": sorted(set(wc)), "windows": wout,
                        "covering_sources": covering,
                        "coverage": [{"start": iso(a), "end": iso(b)} for a, b in cover],
                        "paths": sorted({p for p, _ in path_class.get(k, [])}),
                        "corroborations": [c["corroboration_id"] for c in corrs], "claim": claim})
        self.tables = out

    def _table_claim(self, name, cls, windows, qualifying, covering) -> dict:
        conf_w = [w for w in windows if w["window_class"] == "confirmed"]
        ev = [e for w in windows for e in w.get("evidence_ids", [])][:MAX_EVIDENCE]
        lim = []
        if any(w["window_class"] == "not_assessable" for w in windows):
            lim.append("some periods are not assessable (auditing off, missing or uncovered logs)")
        if any(w.get("volume_unknown") for w in conf_w):
            lim.append("volume unknown for some access (no row counts logged)")
        if cls == Consequence.EXFILTRATION_EVIDENCED:
            c = qualifying[0]
            return Claim(
                claim_id=stable_id("CLM", name), statement=f"Exfiltration evidenced for {name}: {c['establishes']} "
                f"It does not establish: {c['does_not_establish']}", basis=Basis.OBSERVATION,
                source_ids=sorted({s for q in qualifying for s in q["evidence_ids"]}),
                evidence_ids=sorted({s for q in qualifying for s in q["evidence_ids"]}), parser=METHOD_VERSION,
                time_precision=TimePrecision.UNKNOWN, confidence=0.9,
                confidence_reason="independently verifiable evidence supplied and cited (corroboration "
                                  + ", ".join(q["corroboration_id"] for q in qualifying) + ")",
                observation_type="corroborated_external_copy", consequence_class=Consequence.EXFILTRATION_EVIDENCED,
                exfiltration_evidence_kind=c["kind"], limitations=lim + ["patient-level contents are established only "
                                                                         "as far as the corroboration states"],
            ).to_dict()
        if cls is None:
            return Claim(claim_id=stable_id("CLM", name), statement=f"No access to {name} observed in covered periods.",
                         basis=Basis.OBSERVATION, source_ids=covering, evidence_ids=[], parser=METHOD_VERSION,
                         time_precision=TimePrecision.UNKNOWN, confidence=0.7,
                         confidence_reason="audit coverage declared for this database and complete for the window; "
                                           "database audit does not see file-level copies of database files",
                         observation_type="none", consequence_class=None,
                         limitations=["absence of logged access is not proof that no copy was made"]).to_dict()
        return Claim(claim_id=stable_id("CLM", name),
                     statement={"access_observed": f"Logged access to {name}; no export observed.",
                                "export_or_staging_observed": f"Export or staging of {name} observed; no linked egress.",
                                "egress_suspected": f"Export of {name} followed by outbound flow(s) of unknown content.",
                                "undetermined": f"Access to {name} cannot be determined for some or all of the window."
                                }[str(cls)],
                     basis=Basis.OBSERVATION if conf_w else Basis.UNKNOWN,
                     source_ids=covering, evidence_ids=ev, parser=METHOD_VERSION, time_precision=TimePrecision.SECOND
                     if conf_w else TimePrecision.UNKNOWN, confidence=0.9 if conf_w else 0.3,
                     confidence_reason="database audit records" if conf_w else "logging gaps prevent a determination",
                     observation_type="table_access_summary", consequence_class=cls,
                     source_time_window=[conf_w[0]["start"] if conf_w else None, conf_w[-1]["end"] if conf_w else None],
                     limitations=lim).to_dict()

    # ================================================================================================ indicators
    def match_indicators(self) -> None:
        matches = []
        nets = [(i, ipaddress.ip_network(i["value"])) for i in self.indicators if i["type"] == "cidr"]
        ips = {i["value"]: i for i in self.indicators if i["type"] == "ip"}
        doms = {i["value"]: i for i in self.indicators if i["type"] == "domain"}
        hashes = {i["value"]: i for i in self.indicators if i["type"] in ("sha256", "sha1", "md5")}
        if not self.indicators:
            self.indicator_matches = []
            return
        rows = self.q("SELECT event_id, source_id, source_family, ts_utc, ts_utc_min, ts_utc_max, remote_ip, dest_ip, "
                      "domain, file_hash FROM ev WHERE ts_utc_max >= ? AND ts_utc_min <= ? AND (remote_ip IS NOT NULL OR "
                      "dest_ip IS NOT NULL OR domain IS NOT NULL OR file_hash IS NOT NULL)", [self.w0, self.w1]) \
            if (nets or ips or doms or hashes) else []
        for r in rows:
            hits = []
            for fld in ("remote_ip", "dest_ip"):
                v = r.get(fld)
                if not v:
                    continue
                if v in ips:
                    hits.append((ips[v], fld))
                for ind, net in nets:
                    try:
                        if ipaddress.ip_address(v) in net:
                            hits.append((ind, fld))
                    except ValueError:
                        pass
            d = (r.get("domain") or "").lower()
            if d:
                for dv, ind in doms.items():
                    if d == dv or d.endswith("." + dv):
                        hits.append((ind, "domain"))
            if r.get("file_hash") and r["file_hash"].lower() in hashes:
                hits.append((hashes[r["file_hash"].lower()], "file_hash"))
            for ind, fld in hits:
                vf, vt = as_utc(ind.get("valid_from")), as_utc(ind.get("valid_to"))
                t = as_utc(r["ts_utc"])
                if t is not None:
                    inside = (vf is None or t >= vf) and (vt is None or t <= vt)
                    status = "within_validity" if inside else "outside_validity"
                else:
                    status = "time_unresolved"
                if status == "outside_validity":
                    continue
                matches.append({"match_id": stable_id("IM", ind["indicator_id"], r["event_id"]),
                                "indicator_id": ind["indicator_id"], "indicator_type": ind["type"],
                                "indicator_value": ind["value"], "provenance": ind["provenance"],
                                "reference": ind.get("reference"), "valid_from": ind.get("valid_from"),
                                "valid_to": ind.get("valid_to"), "event_id": r["event_id"], "source_id": r["source_id"],
                                "family": r["source_family"], "field": fld, "ts_utc": iso(t), "validity": status,
                                "statement": "indicator match: the record contains a value supplied by a partner as an "
                                             "indicator; this is not attribution", "basis": "observation"})
        matches.sort(key=lambda m: (m["ts_utc"] or "", m["match_id"]))
        self.indicator_matches = matches
        ev_units = {}
        for u in self.units.values():
            for e in u["events"]:
                ev_units[e] = u["unit_id"]
        by_unit = defaultdict(list)
        for m in matches:
            if m["event_id"] in ev_units:
                by_unit[ev_units[m["event_id"]]].append(m["match_id"])
        for p in self.paths:
            ids = set(p["sessions"]) | set(p["egress_units"]) | {x for e in p["edges"] for x in self._edge_units(e)}
            p["indicator_matches"] = sorted({m for uid in ids for m in by_unit.get(uid, [])})

    def _edge_units(self, edge_id):
        e = self._edge_index.get(edge_id)
        return (e["from"], e["to"]) if e else ()

    # ================================================================================================ run
    def run(self) -> dict:
        self.load()
        self.build_gaps()
        self.build_units()
        self.build_edges()
        self._edge_index = {e["edge_id"]: e for e in self.edges}
        self.build_paths()
        self.build_tables()
        self.match_indicators()
        self.anomalies, self.detector_info = detectors.run_all(self)
        for a in self.anomalies:
            for p in self.paths:
                if set(a["unit_ids"]) & (set(p["sessions"]) | set(p["egress_units"]) | set(p["staged_files"])
                                         | {x for e in p["edges"] for x in self._edge_units(e)}):
                    p["anomalies"].append(a["anomaly_id"])
                    a.setdefault("path_ids", []).append(p["path_id"])
        for p in self.paths:
            p["rank_score"] += sum(detectors.SEVERITY_WEIGHT.get(a["severity"], 0) for a in self.anomalies
                                   if a["anomaly_id"] in p["anomalies"])
        self.paths.sort(key=lambda p: (-p["rank_score"], p["first_activity"] or "", p["path_id"]))
        for i, p in enumerate(self.paths, 1):
            p["rank"] = i
        return self.result()

    def _unit_out(self, u: dict) -> dict:
        keep = ("unit_id", "type", "family", "source_id", "host", "account", "session_id", "request_ids", "client_ip",
                "client_host", "application", "event_count", "flags", "consequence", "public_ip", "assigned_ip",
                "dest_ip", "dest_port", "domain", "bytes", "url_path", "method", "http_status", "mfa", "location",
                "outcome", "correlation_id", "entry", "admin", "new_script", "bytes_received")
        d = {k: u.get(k) for k in keep if k in u}
        d["logon_id"] = u.get("logon_id") if u["type"] in ("win_logon", "host_file") else None
        d.update(start=iso(u["start"]), end=iso(u["end"]), earliest=iso(u["tmin"]), latest=iso(u["tmax"]),
                 evidence_ids=u["events"][:20], observations=dict(sorted(u["observations"].items())),
                 tables=sorted(t["table"] for t in u["tables"].values()), exports=len(u["exports"]),
                 time_uncertainty_s=u["unc"])
        if u["type"] == "vpn_session":
            d.update(lease_start=iso(u.get("lease_start")), lease_end=iso(u.get("lease_end")))
        return d

    def result(self) -> dict:
        used_units = set()
        for e in self.edges:
            used_units |= {e["from"], e["to"]}
        for p in self.paths:
            used_units |= set(p["sessions"]) | set(p["egress_units"]) | set(p["staged_files"])
        for a in self.anomalies:
            used_units |= set(a["unit_ids"])
        units = [self._unit_out(self.units[u]) for u in sorted(used_units) if u in self.units]
        unit_types = Counter(u["type"] for u in self.units.values())
        return {
            "schema": ANALYSIS_SCHEMA, "method_version": METHOD_VERSION, "case_id": self.case.case_id,
            "window": {"start": iso(self.w0), "end": iso(self.w1)},
            "baseline": {"start": iso(self.b0), "end": iso(self.b1)},
            "config_sha256": config_sha256(self.cfg), "config": self.cfg,
            "inputs": {sid: {k: s.get(k) for k in ("label", "family", "format", "parser", "files", "manifest_sha256",
                                                   "timezone", "tz_basis", "tz_note", "clock_offset_s",
                                                   "clock_uncertainty_s", "host", "asset_id", "evidence_role")}
                       for sid, s in sorted(self.sources.items())},
            "coverage": [self.coverage[s] for s in sorted(self.coverage)],
            "events_total": self.n_events, "unit_counts": dict(sorted(unit_types.items())),
            "shared_ips": dict(sorted(self.shared.items())), "gaps": self.gaps, "units": units, "edges": self.edges,
            "paths": self.paths, "tables": self.tables, "anomalies": self.anomalies, "detectors": self.detector_info,
            "indicator_matches": self.indicator_matches[:2000], "indicator_match_total": len(self.indicator_matches),
            "indicators": [{k: i[k] for k in ("indicator_id", "type", "value", "provenance", "reference", "valid_from",
                                               "valid_to", "flags")} for i in self.indicators],
            "indicators_rejected": self.indicators_rejected, "corroborations": self.corroborations,
        }


def run_analysis(ctx, window: tuple[dt.datetime, dt.datetime]) -> dict:
    from .config import load_config

    case, store = ctx.case, ctx.store
    cfg = load_config(case)
    a = Analysis(case, store, ctx.home, cfg, window[0].astimezone(UTC), window[1].astimezone(UTC))
    result = a.run()
    sha = store.write_json("work/paths/analysis.json", result)
    ctx.output("analysis", sha)
    result["_sha256"] = sha256_hex(canonical_bytes({k: v for k, v in result.items() if not k.startswith("_")}))
    return result
