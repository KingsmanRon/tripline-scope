"""Synthetic multi-source incident with ground truth (tests, drill, demo). Entirely invented data.

Estate: SQL Server instances LABSQL01 (LabDB01-05) and LABSQL02 (LabDB06-10), each database holding
``dbo.patients``, ``dbo.admissions``, ``dbo.billing`` and ``dbo.results``; PostgreSQL LISPG01 (``lis``); LIS
application server LISAPP01; results portal WEB01 (IIS) behind gateway GW01 (Nginx); DC01; VPN; firewall;
proxy; an instrument-middleware log with an unknown time zone; partner indicators.

Scenarios (``--scenario``):

* ``demo`` -- the attacker reads and exports LabDB03 and LabDB07 ``patients``/``admissions`` and two large
  outbound flows of unknown content follow (``egress_suspected``); LabDB07 ``results`` is read only; database
  auditing is switched off on LabDB09 (``not_assessable``). No corroboration: nothing is
  ``exfiltration_evidenced``.
* ``acceptance`` -- ``demo`` plus a corroborated external copy of LabDB07 ``patients``
  (``exfiltration_evidenced`` for that table only). The five access-versus-theft fixtures are: (i) ordinary
  SELECT of LabDB01 ``results`` by a DBA, (ii) local export of LabDB05 ``billing`` with no egress, (iii)
  LabDB03 ``patients``/``admissions`` exported then an outbound flow of unknown payload, (iv) LabDB07
  ``patients`` corroborated external copy, (v) LabDB09 auditing disabled.

Hard cases: mixed time zones (UTC, +02:00 offsets, SAST abbreviations, local VPN time, epoch firewall time,
an unknown-zone source), a documented +95 s firewall clock offset, several users behind one NAT address, SQL
rows without session ids, sign-ins with unknown MFA, a SQL session with no upstream evidence, harmless nightly
bulk imports and a declared firewall gap.

Usage: ``python -m tripline_scope.paths.synthetic --out DIR [--scenario demo|acceptance] [--scale N]``.
Writes ``DIR/logs.yaml`` (with ``paths:`` settings incl. ``sensitive_tables``), the logs and
``DIR/ground_truth.json``.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import random
import uuid
from pathlib import Path

import yaml

UTC = dt.UTC
SAST = dt.timedelta(hours=2)
START = dt.datetime(2026, 8, 25, tzinfo=UTC)
END = dt.datetime(2026, 9, 15, tzinfo=UTC)
WINDOW = ("2026-09-01T00:00:00Z", "2026-09-14T23:59:59Z")
TABLES = ("patients", "admissions", "billing", "results")
DBS = [f"LabDB{i:02d}" for i in range(1, 11)]
SERVERS = {"LABSQL01": "10.20.0.15", "LABSQL02": "10.20.0.16"}
DB_SERVER = {db: ("LABSQL01" if i < 5 else "LABSQL02") for i, db in enumerate(DBS)}
APP_DBS = DBS[:8]                       # LabDB09 = archive (no app traffic), LabDB10 = untouched
ATTACKER_IP = "102.65.33.7"
NAT_IP = "196.21.10.5"
HOSPITAL_EGRESS = "41.0.0.20"
EXFIL_DEST = "185.220.101.47"
FW_SKEW = 95
SQL_CMDLINE_SECRET = "Synthetic-CmdLine-Secret-7731"  # noqa: S105 - planted to prove it is never read


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _t(day: str, hh: int, mm: int, ss: int = 0) -> dt.datetime:
    y, m, d = (int(x) for x in day.split("-"))
    return dt.datetime(y, m, d, hh, mm, ss, tzinfo=UTC)


class _Sql:
    """Accumulates fn_get_audit_file rows for one instance."""

    COLS = ["event_time", "sequence_number", "action_id", "succeeded", "session_id", "server_principal_name",
            "session_server_principal_name", "target_server_principal_name", "server_instance_name",
            "database_name", "schema_name", "object_name", "statement", "client_ip", "host_name",
            "application_name", "response_rows", "affected_rows", "session_context"]

    def __init__(self, instance: str, with_rows: bool):
        self.instance = instance
        self.with_rows = with_rows
        self.rows: list[dict] = []

    def add(self, ts, action, spid, account, *, db="", schema="", obj="", statement="", client_ip="",
            host_name="", app="", rows=None, affected=None, ctx="", ok=True, target=""):
        self.rows.append({
            "event_time": ts, "sequence_number": 1, "action_id": action, "succeeded": 1 if ok else 0,
            "session_id": spid, "server_principal_name": account, "session_server_principal_name": account,
            "target_server_principal_name": target, "server_instance_name": self.instance, "database_name": db,
            "schema_name": schema, "object_name": obj, "statement": statement, "client_ip": client_ip,
            "host_name": host_name, "application_name": app,
            "response_rows": rows if self.with_rows else None, "affected_rows": affected if self.with_rows else None,
            "session_context": ctx,
        })

    def session(self, start, spid, account, client_ip, host_name, app, stmts, *, logout_after=None):
        """stmts: list of (offset_s, action, db, table, statement, rows, affected, session_context)."""
        self.add(start, "LGIS", spid, account, client_ip=client_ip, host_name=host_name, app=app)
        last = start
        for off, action, db, table, statement, rows, affected, ctx in stmts:
            ts = start + dt.timedelta(seconds=off)
            last = max(last, ts)
            self.add(ts, action, spid, account, db=db, schema="dbo" if table else "", obj=table or "",
                     statement=statement, client_ip=client_ip, host_name=host_name, app=app, rows=rows,
                     affected=affected, ctx=ctx)
        self.add(last + dt.timedelta(seconds=logout_after or 5), "LGO", spid, account, client_ip=client_ip,
                 host_name=host_name, app=app)


class Generator:
    def __init__(self, out: Path, scenario: str = "acceptance", scale: int = 20_000, seed: int = 20260903):
        if scenario not in ("demo", "acceptance"):
            raise ValueError("scenario must be demo or acceptance")
        self.out = Path(out)
        self.scenario = scenario
        self.scale = max(2_000, int(scale))
        self.rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
        self.sql = {"LABSQL01": _Sql("LABSQL01", with_rows=True), "LABSQL02": _Sql("LABSQL02", with_rows=False)}
        self.pg: list[tuple] = []
        self.iis: list[tuple] = []
        self.nginx: list[tuple] = []
        self.win: dict[str, list[dict]] = {"DC01": [], "LABSQL01": [], "LABSQL02": []}
        self.entra_json: list[dict] = []
        self.entra_csv: list[dict] = []
        self.vpn: list[dict] = []
        self.fw: list[dict] = []
        self.proxy: list[dict] = []
        self.mw: list[str] = []
        self.truth: dict = {}
        self._rid = 9000
        self._spid = {"LABSQL01": 51, "LABSQL02": 51}
        self._logon = 0x3e8000
        self._pgpid = 21000

    # ------------------------------------------------------------------ helpers
    def spid(self, inst):
        self._spid[inst] = 51 + ((self._spid[inst] - 50) % 140)
        return str(self._spid[inst])

    def logon_id(self):
        self._logon += self.rng.randint(1, 4000)
        return hex(self._logon)

    def win_event(self, host, ts, eid, **data):
        self.win[host].append({"ts": ts, "EventID": eid, "data": data})

    def fw_flow(self, ts, src, dst, port, out_bytes, in_bytes, action="allow"):
        self.fw.append({"ts": ts, "src": src, "dst": dst, "port": port, "out": out_bytes, "in": in_bytes,
                        "action": action})

    def signin(self, ts, upn, ip, *, app="Office 365", country="ZA", city="Johannesburg", mfa="multi",
               csv_export=False, request_id=None, ok=True):
        rid = request_id or _uuid(self.rng)
        corr = _uuid(self.rng)
        if csv_export:
            self.entra_csv.append({"ts": ts, "rid": rid, "corr": corr, "upn": upn, "app": app, "ip": ip,
                                   "loc": f"{city}, {country}", "ok": ok})
        else:
            rec = {"createdDateTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "id": rid, "correlationId": corr,
                   "userPrincipalName": upn, "userDisplayName": "Synthetic Person", "appDisplayName": app,
                   "ipAddress": ip, "clientAppUsed": "Browser",
                   "location": {"city": city, "state": "", "countryOrRegion": country},
                   "status": {"errorCode": 0 if ok else 50126, "failureReason": None if ok else "Invalid password"}}
            if mfa == "multi":
                rec["authenticationRequirement"] = "multiFactorAuthentication"
                rec["mfaDetail"] = {"authMethod": "Mobile app notification", "authDetail": None}
            elif mfa == "single":
                rec["authenticationRequirement"] = "singleFactorAuthentication"
            self.entra_json.append(rec)
        return rid

    def vpn_session(self, start, end, user, public_ip, assigned, session_id, auth_ref=""):
        self.vpn.append({"ts": start, "event": "session-start", "user": user, "session": session_id,
                         "public_ip": public_ip, "tunnel_ip": assigned, "auth_ref": auth_ref, "bytes_in": "",
                         "bytes_out": ""})
        self.vpn.append({"ts": end, "event": "session-end", "user": user, "session": session_id,
                         "public_ip": public_ip, "tunnel_ip": assigned, "auth_ref": "",
                         "bytes_in": self.rng.randint(10_000, 9_000_000), "bytes_out": self.rng.randint(10_000, 900_000)})

    def web(self, ts, client_ip, method, path, status, *, user="-", out_bytes=None, in_bytes=None,
            query="", via_gateway=True, rid=None):
        rid = rid or f"r{self._next_rid()}"
        ob = out_bytes if out_bytes is not None else self.rng.randint(800, 40_000)
        ib = in_bytes if in_bytes is not None else self.rng.randint(200, 900)
        if via_gateway:
            self.nginx.append((ts, client_ip, user, method, path + (f"?{query}" if query else ""), status, ob, rid))
        self.iis.append((ts, "10.20.0.41" if via_gateway else client_ip, user, method, path, query, status, ob, ib,
                         rid if via_gateway else "-"))
        return rid

    def _next_rid(self):
        self._rid += 1
        return f"{self._rid:06d}{self.rng.randint(100000, 999999)}"

    # ------------------------------------------------------------------ background
    def background(self):
        rng = self.rng
        days = (END - START).days
        per_day = self.scale / days
        staff = ["n.dlamini", "z.patel", "k.smith", "l.vanwyk", "s.naidoo", "it.mokoena", "dba.khumalo", "t.naidoo"]
        portal_users = [f"pp_{10000 + i}" for i in range(40)] + ["synthetic.portal.user@example.com",
                                                                  "another.portal.user@example.com"]
        for d in range(days):
            day = START + dt.timedelta(days=d)
            # staff sign-ins from the hospital egress (a legitimately shared address)
            for u in staff:
                if rng.random() < 0.85:
                    t = day + dt.timedelta(hours=5, minutes=rng.randint(0, 120))
                    self.signin(t, f"{u}@lab.example", HOSPITAL_EGRESS)
                    self.win_event("DC01", t + dt.timedelta(seconds=3), 4768, TargetUserName=u, TargetDomainName="LAB",
                                   IpAddress=f"::ffff:10.20.1.{20 + staff.index(u)}", Status="0x0")
            # staff working from home over the VPN (sign-in request id carried by the VPN as auth_ref)
            for i, u in enumerate(("n.dlamini", "l.vanwyk", "s.naidoo")):
                if rng.random() < 0.4:
                    t = day + dt.timedelta(hours=16, minutes=rng.randint(0, 180))
                    home_ip = f"105.{30 + i}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                    rid = self.signin(t, f"{u}@lab.example", home_ip, app="Lab VPN")
                    self.vpn_session(t + dt.timedelta(seconds=30), t + dt.timedelta(minutes=rng.randint(20, 120)), u,
                                     home_ip, f"10.8.0.{40 + i}", f"VPN-{d:02d}{i}{rng.randint(100, 999)}", auth_ref=rid)
            # LIS application reads, around the clock (the lab runs 24/7)
            n_sessions = max(4, int(per_day * 0.30 / 6))
            for _ in range(n_sessions):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                db = rng.choice(APP_DBS)
                inst = DB_SERVER[db]
                stmts = []
                for k in range(rng.randint(2, 7)):
                    table = rng.choice(("results", "patients"))
                    stmts.append((k * 2 + 1, "SL", db, table,
                                   f"SELECT TOP 20 * FROM dbo.{table} WHERE specimen_ref = @p0 AND id > {rng.randint(1, 99999)}",
                                   rng.randint(1, 40), None, ""))
                self.sql[inst].session(t, self.spid(inst), "LAB\\svc_lis_app", "10.20.0.30", "LISAPP01", "LabLIS", stmts)
            # nightly harmless bulk import (23:30 UTC = 01:30 SAST)
            for db in APP_DBS[:4]:
                t = day + dt.timedelta(hours=23, minutes=30, seconds=rng.randint(0, 600))
                inst = DB_SERVER[db]
                self.sql[inst].session(t, self.spid(inst), "LAB\\svc_lis_import", "10.20.0.30", "LISAPP01", "LISImport", [
                    (30, "IN", db, "results", "BULK INSERT dbo.results FROM 'E:\\lis\\import\\results_nightly.csv' "
                                              "WITH (FIELDTERMINATOR = ',')", None, rng.randint(15_000, 25_000), "")])
            # portal: web requests through the gateway, some with database queries carrying the request id
            n_web = max(10, int(per_day * 0.28 / 2))
            for _ in range(n_web):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                if rng.random() < 0.15:
                    ip, user = NAT_IP, rng.choice(portal_users)
                else:
                    ip, user = f"105.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}", rng.choice(portal_users)
                path = rng.choice(["/portal/results/view", "/portal/results/list", "/portal/home",
                                   f"/portal/results/{rng.randint(100000, 999999)}/pdf"])
                rid = self.web(t, ip, "GET", path, 200, user=user, query=f"session={_uuid(rng)[:8]}")
                if "results" in path and rng.random() < 0.8:
                    db = rng.choice(APP_DBS)
                    inst = DB_SERVER[db]
                    ctx = f"request_id={rid}" if rng.random() < 0.7 else ""
                    self.sql[inst].session(t + dt.timedelta(milliseconds=300), self.spid(inst), "LAB\\svc_portal",
                                           "10.20.0.40", "WEB01", "LabPortal",
                                           [(0.2, "SL", db, "results", "SELECT * FROM dbo.results WHERE portal_user = @u",
                                             rng.randint(1, 12), None, ctx)], logout_after=1)
            # Windows background on the database servers (service logons) and DC
            for host in ("LABSQL01", "LABSQL02"):
                for _ in range(max(2, int(per_day * 0.03))):
                    t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                    lid = self.logon_id()
                    self.win_event(host, t, 4624, TargetUserName="svc_lis_app", TargetDomainName="LAB", TargetLogonId=lid,
                                   LogonType="3", IpAddress="10.20.0.30", WorkstationName="LISAPP01",
                                   AuthenticationPackageName="Kerberos")
                    self.win_event(host, t + dt.timedelta(minutes=10), 4634, TargetUserName="svc_lis_app",
                                   TargetDomainName="LAB", TargetLogonId=lid)
            # PostgreSQL LIS middleware
            for _ in range(max(3, int(per_day * 0.05 / 4))):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                self.pg_session(t, "lis_app", "10.20.0.30", "lis-middleware",
                                [("READ", "SELECT", "public.specimens", "SELECT * FROM specimens WHERE barcode = $1")])
            # firewall: ordinary outbound and internal flows (declared rotation gap on 2026-09-08 00:00-06:00)
            for _ in range(max(5, int(per_day * 0.2))):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                if _t("2026-09-08", 0, 0) <= t < _t("2026-09-08", 6, 0):
                    continue
                src = rng.choice(["10.20.1.21", "10.20.1.35", "10.20.0.30", "10.20.0.40", "10.20.1.24"])
                if rng.random() < 0.6:
                    self.fw_flow(t, src, rng.choice(["13.107.4.50", "20.190.128.10", "52.96.0.12"]), 443,
                                 rng.randint(2_000, 300_000), rng.randint(5_000, 2_000_000))
                else:
                    self.fw_flow(t, src, rng.choice(["10.20.0.15", "10.20.0.16", "10.20.0.25"]),
                                 rng.choice([1433, 5432, 445]), rng.randint(1_000, 90_000), rng.randint(1_000, 400_000))
            # proxy
            for _ in range(max(2, int(per_day * 0.02))):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                self.proxy.append({"time": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "client": "10.20.1.24", "user": "LAB\\l.vanwyk",
                                   "method": "GET", "url": f"https://updates.example.net/feed?token={_uuid(rng)}",
                                   "status": 200, "sent": rng.randint(200, 900), "received": rng.randint(1_000, 90_000)})
            # instrument middleware (unknown time zone)
            for _ in range(max(2, int(per_day * 0.02))):
                t = day + dt.timedelta(seconds=rng.randint(0, 86_000))
                self.mw.append(f"time=\"{(t + SAST).strftime('%Y-%m-%d %H:%M:%S')}\" event=result_upload instrument=AN-{rng.randint(1, 9)} "
                               f"user=lis_app status=ok")

    def pg_session(self, start, user, ip, app, audits, *, db="lis"):
        self._pgpid += self.rng.randint(1, 50)
        pid = self._pgpid
        sid = f"{int(start.timestamp()):x}.{pid:x}"
        port = self.rng.randint(40000, 60000)
        self.pg.append((start, pid, "[unknown]", "[unknown]", f"{ip}({port})", sid, "LOG",
                        f"connection received: host={ip} port={port}"))
        self.pg.append((start + dt.timedelta(milliseconds=40), pid, user, db, f"{ip}({port})", sid, "LOG",
                        f"connection authorized: user={user} database={db} application_name={app}"))
        t = start
        for i, (cls, cmd, obj, stmt) in enumerate(audits, 1):
            t = t + dt.timedelta(seconds=1)
            esc = stmt.replace('"', '""')
            self.pg.append((t, pid, user, db, f"{ip}({port})", sid, "LOG",
                            f'AUDIT: SESSION,{i},1,{cls},{cmd},TABLE,{obj},"{esc}",<not logged>'))
        self.pg.append((t + dt.timedelta(seconds=2), pid, user, db, f"{ip}({port})", sid, "LOG",
                        f"disconnection: session time: 0:00:0{len(audits) + 2}.000 user={user} database={db} "
                        f"host={ip} port={port}"))
        return sid

    # ------------------------------------------------------------------ scenarios
    def scenarios(self):
        rng = self.rng
        T = self.truth
        T["expected_direct_edges"] = []
        T["expected_correlated_edges"] = []
        T["expected_absent_edges"] = []
        T["expected_no_direct_edges_for"] = []
        T["expected_unresolved_upstream"] = []

        # baseline familiarity: DBA and z.patel accessed their tables before the incident window
        for day, who, ip, db in (("2026-08-27", "dba.khumalo", "10.20.1.21", "LabDB01"),
                                 ("2026-08-28", "z.patel", "10.20.1.22", "LabDB02")):
            inst = DB_SERVER[db]
            self.sql[inst].session(_t(day, 8, 0), self.spid(inst), f"LAB\\{who}", ip, "WS-" + who.split(".")[0].upper(),
                                   "Microsoft SQL Server Management Studio - Query",
                                   [(5, "SL", db, "results", "SELECT TOP 50 * FROM dbo.results", 50, None, "")])

        # (i) ordinary SELECT, no export -------------------------------------------------------------------
        t = _t("2026-09-02", 7, 15)
        lid = self.logon_id()
        self.win_event("LABSQL01", t - dt.timedelta(seconds=20), 4624, TargetUserName="dba.khumalo", TargetDomainName="LAB",
                       TargetLogonId=lid, LogonType="3", IpAddress="10.20.1.21", WorkstationName="WS-DBA01",
                       AuthenticationPackageName="Kerberos")
        self.sql["LABSQL01"].session(t, self.spid("LABSQL01"), "LAB\\dba.khumalo", "10.20.1.21", "WS-DBA01",
                                     "Microsoft SQL Server Management Studio - Query",
                                     [(10, "SL", "LabDB01", "results", "SELECT TOP 100 * FROM LabDB01.dbo.results ORDER BY id DESC",
                                       100, None, "")])

        # (ii) local export, no egress -----------------------------------------------------------------------
        t = _t("2026-09-05", 10, 0)
        bcp = "EXEC xp_cmdshell 'bcp LabDB05.dbo.billing out D:\\finance\\billing_0905.csv -c -T'"
        self.sql["LABSQL01"].session(t, self.spid("LABSQL01"), "LAB\\it.mokoena", "10.20.1.35", "WS-FIN02",
                                     "Microsoft SQL Server Management Studio - Query",
                                     [(20, "EX", "master", "", bcp, None, None, "")])
        self.win_event("LABSQL01", t + dt.timedelta(seconds=21), 4688, SubjectUserName="svc_sql", SubjectDomainName="LAB",
                       SubjectLogonId="0x3e7", NewProcessName="C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\bcp.exe",
                       CommandLine=f"bcp LabDB05.dbo.billing out D:\\finance\\billing_0905.csv -P {SQL_CMDLINE_SECRET}")
        self.win_event("LABSQL01", t + dt.timedelta(seconds=40), 4663, SubjectUserName="svc_sql", SubjectDomainName="LAB",
                       SubjectLogonId="0x3e7", ObjectType="File", ObjectName="D:\\finance\\billing_0905.csv",
                       AccessMask="0x2", ProcessName="C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\bcp.exe")

        # NAT: two staff behind one public address, overlapping VPN sessions --------------------------------
        t = _t("2026-09-06", 17, 30)
        z_rid = self.signin(t, "z.patel@lab.example", NAT_IP, app="Lab VPN")
        k_rid = self.signin(t + dt.timedelta(seconds=40), "k.smith@lab.example", NAT_IP, app="Lab VPN")
        self.vpn_session(t + dt.timedelta(seconds=60), t + dt.timedelta(hours=2), "z.patel", NAT_IP, "10.8.0.31", "VPN-7790")
        self.vpn_session(t + dt.timedelta(seconds=90), t + dt.timedelta(hours=1), "k.smith", NAT_IP, "10.8.0.32", "VPN-7791",
                         auth_ref=k_rid)
        self.sql["LABSQL01"].session(t + dt.timedelta(minutes=20), self.spid("LABSQL01"), "LAB\\z.patel", "10.8.0.31",
                                     "LT-ZPATEL", "Microsoft SQL Server Management Studio - Query",
                                     [(5, "SL", "LabDB02", "results", "SELECT TOP 50 * FROM dbo.results WHERE ward = 'W3'",
                                       50, None, "")])
        T["expected_correlated_edges"] += [
            {"from": {"family": "vpn", "session_id": "VPN-7790"},
             "to": {"family": "mssql_audit", "account": "LAB\\z.patel"}, "why": "VPN-assigned address lease"},
            {"from": {"family": "entra_signin", "request_id": z_rid}, "to": {"family": "vpn", "session_id": "VPN-7790"},
             "why": "same account within the sign-in window; no shared identifier"},
        ]
        T["expected_direct_edges"].append(
            {"from": {"family": "entra_signin", "request_id": k_rid}, "to": {"family": "vpn", "session_id": "VPN-7791"},
             "join": "request_id"})
        T["expected_absent_edges"] += [
            {"from": {"family": "entra_signin", "request_id": k_rid}, "to": {"family": "vpn", "session_id": "VPN-7790"}},
            {"from": {"family": "entra_signin", "request_id": z_rid}, "to": {"family": "vpn", "session_id": "VPN-7791"}},
            {"from": {"family": "vpn", "session_id": "VPN-7791"}, "to": {"family": "mssql_audit", "account": "LAB\\z.patel"}},
        ]
        T["shared_ips"] = [NAT_IP, HOSPITAL_EGRESS]

        # rows without session ids -------------------------------------------------------------------------
        t = _t("2026-09-07", 9, 40)
        for k in range(3):
            self.sql["LABSQL01"].add(t + dt.timedelta(seconds=k * 30), "SL", "", "LAB\\analyst.mthembu", db="LabDB04",
                                     schema="dbo", obj="results", statement="SELECT COUNT(*) FROM dbo.results",
                                     client_ip="10.20.1.50", host_name="WS-AN05", app="Excel", rows=1)
        T["expected_no_direct_edges_for"].append({"family": "mssql_audit", "account": "LAB\\analyst.mthembu"})

        # SQL session with no upstream evidence ------------------------------------------------------------
        t = _t("2026-09-09", 11, 5)
        self.sql["LABSQL02"].session(t, self.spid("LABSQL02"), "LAB\\vendor.support", "10.20.9.99", "VENDOR-JUMP",
                                     "sqlcmd", [(3, "SL", "LabDB06", "billing", "SELECT TOP 10 * FROM dbo.billing", None, None, "")])
        T["expected_unresolved_upstream"].append({"family": "mssql_audit", "account": "LAB\\vendor.support"})

        # attacker -----------------------------------------------------------------------------------------
        t0 = _t("2026-09-03", 22, 40)
        for k, (m, p, st, ib) in enumerate([("GET", "/portal/admin/", 302, 300), ("GET", "/portal/admin/login", 200, 400),
                                             ("POST", "/portal/admin/upload.aspx", 200, 48_213),
                                             ("GET", "/portal/uploads/rpt.aspx", 200, 350)]):
            rid = self.web(t0 + dt.timedelta(seconds=k * 70), ATTACKER_IP, m, p, st, in_bytes=ib)
            if k == 2:
                T["expected_direct_edges"].append({"from": {"family": "nginx", "request_id": rid},
                                                   "to": {"family": "iis", "request_id": rid}, "join": "request_id"})
        att_rid = self.signin(_t("2026-09-03", 23, 5), "t.naidoo@lab.example", ATTACKER_IP, app="Lab VPN",
                              country="NL", city="Amsterdam", csv_export=True)
        self.vpn_session(_t("2026-09-03", 23, 6), _t("2026-09-04", 1, 5), "t.naidoo", ATTACKER_IP, "10.8.0.23",
                         "VPN-7781", auth_ref=att_rid)
        T["expected_direct_edges"].append({"from": {"family": "entra_signin", "request_id": att_rid},
                                           "to": {"family": "vpn", "session_id": "VPN-7781"}, "join": "request_id"})
        lid = "0x8a3f21"
        t = _t("2026-09-03", 23, 10)
        self.win_event("LABSQL01", t, 4624, TargetUserName="t.naidoo", TargetDomainName="LAB", TargetLogonId=lid,
                       LogonType="3", IpAddress="10.8.0.23", WorkstationName="DESKTOP-7Q2M1",
                       AuthenticationPackageName="NTLM")
        self.win_event("LABSQL01", t + dt.timedelta(seconds=1), 4672, SubjectUserName="t.naidoo", SubjectDomainName="LAB",
                       SubjectLogonId=lid)
        self.win_event("DC01", _t("2026-09-03", 23, 20), 4732, SubjectUserName="t.naidoo", SubjectDomainName="LAB",
                       SubjectLogonId="0x51a2b", MemberName="CN=T Naidoo,OU=Staff,DC=lab,DC=example",
                       TargetUserName="SQL-Admins", TargetDomainName="LAB")
        ssms = "Microsoft SQL Server Management Studio - Query"
        a = "LAB\\t.naidoo"
        self.sql["LABSQL01"].session(_t("2026-09-03", 23, 12), "61", a, "10.8.0.23", "DESKTOP-7Q2M1", ssms, [
            (30, "SL", "LabDB03", "patients", "SELECT * FROM LabDB03.dbo.patients", 15_022, None, ""),
            (95, "SL", "LabDB03", "admissions", "SELECT * FROM LabDB03.dbo.admissions", 30_110, None, ""),
            (240, "APRL", "master", "", "ALTER SERVER ROLE sysadmin ADD MEMBER [LAB\\t.naidoo]", None, None, ""),
            (1080, "EX", "master", "", "EXEC xp_cmdshell 'bcp \"SELECT * FROM LabDB03.dbo.patients\" queryout D:\\temp\\p3.dat -c -T'",
             None, None, ""),
            (1150, "EX", "master", "", "EXEC xp_cmdshell 'bcp \"SELECT * FROM LabDB03.dbo.admissions\" queryout D:\\temp\\a3.dat -c -T'",
             None, None, ""),
        ], logout_after=60)
        for k, name in enumerate(("p3.dat", "a3.dat")):
            self.win_event("LABSQL01", _t("2026-09-03", 23, 31) + dt.timedelta(seconds=70 * k), 4663, SubjectUserName="svc_sql",
                           SubjectDomainName="LAB", SubjectLogonId="0x3e7", ObjectType="File", ObjectName=f"D:\\temp\\{name}",
                           AccessMask="0x2", ProcessName="C:\\Windows\\System32\\bcp.exe")
        self.sql["LABSQL02"].session(_t("2026-09-03", 23, 40), "72", a, "10.8.0.23", "DESKTOP-7Q2M1", ssms, [
            (20, "SL", "LabDB07", "patients", "SELECT * FROM LabDB07.dbo.patients", None, None, ""),
            (60, "SL", "LabDB07", "admissions", "SELECT * FROM LabDB07.dbo.admissions", None, None, ""),
            (90, "SL", "LabDB07", "results", "SELECT * FROM LabDB07.dbo.results", None, None, ""),
            (600, "EX", "master", "", "EXEC xp_cmdshell 'bcp \"SELECT * FROM LabDB07.dbo.patients\" queryout D:\\temp\\p7.dat -c -T'",
             None, None, ""),
            (660, "EX", "master", "", "EXEC xp_cmdshell 'bcp \"SELECT * FROM LabDB07.dbo.admissions\" queryout D:\\temp\\a7.dat -c -T'",
             None, None, ""),
            (1800, "AL", "LabDB09", "", "ALTER DATABASE AUDIT SPECIFICATION [LabDB09_audit] WITH (STATE = OFF)", None, None, ""),
        ], logout_after=30)
        self.sql["LABSQL02"].add(_t("2026-09-04", 7, 30), "AL", "65", "LAB\\dba.khumalo", db="LabDB09",
                                 statement="ALTER DATABASE AUDIT SPECIFICATION [LabDB09_audit] WITH (STATE = ON)",
                                 client_ip="10.20.1.21", host_name="WS-DBA01", app=ssms)
        T["audit_off"] = {"database": "LabDB09", "host": "LABSQL02", "start": "2026-09-04T00:10:00Z",
                          "end": "2026-09-04T07:30:00Z"}
        pg_sid = self.pg_session(_t("2026-09-03", 23, 50), "t_naidoo", "10.8.0.23", "psql", [
            ("READ", "SELECT", "public.patient_index", "SELECT * FROM patient_index")])
        # egress of unknown content (firewall clock runs 95 s fast; the log shows the skewed time)
        self.fw_flow(_t("2026-09-04", 0, 35), "10.20.0.15", EXFIL_DEST, 443, 2_147_000_000, 1_200_000)
        self.fw_flow(_t("2026-09-04", 0, 52), "10.20.0.16", EXFIL_DEST, 443, 3_400_000_000, 1_900_000)
        self.win_event("LABSQL01", _t("2026-09-04", 1, 0), 1102, SubjectUserName="t.naidoo", SubjectDomainName="LAB",
                       SubjectLogonId=lid)
        self.mw.append(f"time=\"{(_t('2026-09-04', 0, 5) + SAST).strftime('%Y-%m-%d %H:%M:%S')}\" event=export_request "
                       f"instrument=AN-3 user=lis_admin status=ok")
        T["expected_direct_edges"] += []
        T["expected_correlated_edges"] += [
            {"from": {"family": "vpn", "session_id": "VPN-7781"},
             "to": {"family": "mssql_audit", "account": a, "host": "labsql01"}, "why": "VPN-assigned address lease"},
            {"from": {"family": "vpn", "session_id": "VPN-7781"},
             "to": {"family": "mssql_audit", "account": a, "host": "labsql02"}, "why": "VPN-assigned address lease"},
            {"from": {"family": "vpn", "session_id": "VPN-7781"},
             "to": {"family": "pg_log", "session_id": pg_sid}, "why": "VPN-assigned address lease"},
            {"from": {"family": "vpn", "session_id": "VPN-7781"},
             "to": {"family": "win_security", "logon_id": lid}, "why": "VPN-assigned address lease"},
            {"from": {"family": "mssql_audit", "account": a, "host": "labsql01"},
             "to": {"family": "firewall", "dest_ip": EXFIL_DEST}, "why": "outbound flow after export from the same host"},
            {"from": {"family": "mssql_audit", "account": a, "host": "labsql02"},
             "to": {"family": "firewall", "dest_ip": EXFIL_DEST}, "why": "outbound flow after export from the same host"},
        ]

        # proxy record with a query string carrying a token (must be stripped)
        self.proxy.append({"time": "2026-09-04T00:20:00Z", "client": "10.20.0.15", "user": "LAB\\svc_sql", "method": "POST",
                           "url": f"https://paste.example.org/upload?api_key={_uuid(rng)}", "status": 200,
                           "sent": 18_000, "received": 900})

        tables = {f"{db}.dbo.{t}": None for db in DBS for t in TABLES}
        exp = {
            "LabDB01.dbo.results": "access_observed",
            "LabDB05.dbo.billing": "export_or_staging_observed",
            "LabDB03.dbo.patients": "egress_suspected",
            "LabDB03.dbo.admissions": "egress_suspected",
            "LabDB07.dbo.patients": "egress_suspected",
            "LabDB07.dbo.admissions": "egress_suspected",
            "LabDB07.dbo.results": "access_observed",
            "LabDB09.dbo.patients": "undetermined",
            "LabDB09.dbo.admissions": "undetermined",
            "LabDB09.dbo.billing": "undetermined",
            "LabDB09.dbo.results": "undetermined",
            "lis.public.patient_index": "access_observed",
        }
        if self.scenario == "acceptance":
            exp["LabDB07.dbo.patients"] = "exfiltration_evidenced"
        tables.update(exp)
        T["expected_table_classes"] = exp
        T["expected_window_classes"] = {f"LabDB09.dbo.{t}": "not_assessable" for t in TABLES}
        T["expected_window_classes"].update({"LabDB01.dbo.results": "confirmed", "LabDB03.dbo.patients": "confirmed"})
        T["no_access_observed_tables"] = [f"LabDB10.dbo.{t}" for t in TABLES]
        T["fixtures"] = {
            "i_select_no_export": {"table": "LabDB01.dbo.results", "account": "LAB\\dba.khumalo",
                                   "expected_path_class": "access_observed"},
            "ii_local_export_no_egress": {"table": "LabDB05.dbo.billing", "account": "LAB\\it.mokoena",
                                          "expected_path_class": "export_or_staging_observed"},
            "iii_outbound_unknown_payload": {"table": "LabDB03.dbo.patients", "account": a,
                                             "expected_path_class": "egress_suspected"},
            "iv_corroborated_external_copy": {"table": "LabDB07.dbo.patients",
                                              "expected_table_class": exp["LabDB07.dbo.patients"]},
            "v_auditing_disabled": {"database": "LabDB09", "expected_table_class": "undetermined",
                                    "expected_window_class": "not_assessable"},
        }
        T["harmless"] = {"accounts": ["LAB\\svc_lis_import"], "never": ["dump_export", "export_or_staging_observed"]}
        T["indicator"] = {"value": EXFIL_DEST, "rejected_without_provenance": 1}
        T["secrets_never_in_outputs"] = [SQL_CMDLINE_SECRET, "api_key=", "session=", "synthetic.portal.user@example.com",
                                         "Synthetic Person", "SELECT * FROM", "bcp ", "D:\\temp\\p3.dat"]
        T["gaps"] = [
            {"kind": "auditing_disabled", "database": "LabDB09"},
            {"kind": "log_cleared", "host": "labsql01"},
            {"kind": "time_zone_unknown", "label": "middleware"},
            {"kind": "declared_missing", "label": "firewall"},
        ]

    # ------------------------------------------------------------------ writers
    def write(self) -> dict:
        out = self.out
        for sub in ("mssql", "pg", "web/iis", "web/nginx", "windows", "identity", "network", "apps", "intel", "evidence"):
            (out / sub).mkdir(parents=True, exist_ok=True)
        counts = {}
        # SQL Server: LABSQL01 as CSV (with row counts), LABSQL02 as JSON (no row counts)
        rows = sorted(self.sql["LABSQL01"].rows, key=lambda r: r["event_time"])
        with open(out / "mssql/labsql01_audit.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(_Sql.COLS)
            for i, r in enumerate(rows, 1):
                r = dict(r, sequence_number=i, event_time=r["event_time"].strftime("%Y-%m-%d %H:%M:%S.%f") + "0")
                w.writerow(["" if r[c] is None else r[c] for c in _Sql.COLS])
        counts["mssql_labsql01"] = len(rows)
        rows2 = sorted(self.sql["LABSQL02"].rows, key=lambda r: r["event_time"])
        items = []
        for i, r in enumerate(rows2, 1):
            d = {k: v for k, v in r.items() if k not in ("response_rows", "affected_rows") and v not in ("", None)}
            d["event_time"] = r["event_time"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "0"
            d["sequence_number"] = i
            items.append(d)
        (out / "mssql/labsql02_audit.json").write_text(json.dumps(items, indent=0))
        counts["mssql_labsql02"] = len(items)
        # PostgreSQL stderr, log_line_prefix '%m [%p] %q%u@%d %r %c ', SAST abbreviation
        with open(out / "pg/postgresql-2026-09.log", "w") as fh:
            for ts, pid, user, db, remote, sid, sev, msg in sorted(self.pg, key=lambda x: x[0]):
                local = (ts + SAST).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " SAST"
                fh.write(f"{local} [{pid}] {user}@{db} {remote} {sid} {sev}:  {msg}\n")
            # a background-process line (no session part after %q) and a malformed line
            fh.write("2026-09-10 03:00:00.000 SAST [17] LOG:  checkpoint starting: time\n")
        counts["pg"] = len(self.pg) + 1
        # IIS: one W3C file per day (directory source)
        by_day: dict[str, list] = {}
        for rec in sorted(self.iis, key=lambda x: x[0]):
            by_day.setdefault(rec[0].strftime("%y%m%d"), []).append(rec)
        for day, recs in by_day.items():
            with open(out / f"web/iis/u_ex{day}.log", "w") as fh:
                fh.write("#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n")
                fh.write(f"#Date: {recs[0][0].strftime('%Y-%m-%d')} 00:00:00\n")
                fh.write("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
                         "cs(User-Agent) cs(X-Request-ID) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken\n")
                for ts, cip, user, m, path, q, st, ob, ib, rid in recs:
                    fh.write(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} 10.20.0.40 {m} {path} {q or '-'} 443 {user} {cip} "
                             f"Mozilla/5.0+(Windows+NT+10.0) {rid} {st} 0 0 {ob} {ib} {self.rng.randint(5, 900)}\n")
        counts["iis"] = len(self.iis)
        with open(out / "web/nginx/access.log", "w") as fh:
            for ts, ip, user, m, path, st, ob, rid in sorted(self.nginx, key=lambda x: x[0]):
                local = (ts + SAST).strftime("%d/%b/%Y:%H:%M:%S +0200")
                fh.write(f'{ip} - {user} [{local}] "{m} {path} HTTP/1.1" {st} {ob} "-" "Mozilla/5.0 (X11)" {rid}\n')
        counts["nginx"] = len(self.nginx)
        # Windows: DC01 + LABSQL02 as wevtutil XML, LABSQL01 as the documented CSV export
        for host in ("DC01", "LABSQL02"):
            with open(out / f"windows/{host.lower()}_security.xml", "w") as fh:
                fh.write(_win_xml(host, sorted(self.win[host], key=lambda e: e["ts"])))
        cols = ["TimeCreated", "EventID", "Computer", "RecordId", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
                "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "IpAddress", "WorkstationName",
                "AuthenticationPackageName", "ProcessName", "NewProcessName", "CommandLine", "ObjectType", "ObjectName",
                "AccessMask", "MemberName", "Status"]
        with open(out / "windows/labsql01_security.csv", "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            for i, e in enumerate(sorted(self.win["LABSQL01"], key=lambda e: e["ts"]), 1):
                row = {"TimeCreated": e["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z", "EventID": e["EventID"],
                       "Computer": "LABSQL01.lab.example", "RecordId": 500000 + i, **e["data"]}
                w.writerow([row.get(c, "") for c in cols])
        counts["windows"] = sum(len(v) for v in self.win.values())
        # Entra
        (out / "identity/entra_signins.json").write_text(json.dumps({"value": sorted(self.entra_json, key=lambda r: r["createdDateTime"])}))
        with open(out / "identity/entra_signins_portal.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["Date (UTC)", "Request ID", "Correlation ID", "User", "Username", "Application", "IP address",
                        "Location", "Status", "Sign-in error code"])
            for r in self.entra_csv:
                w.writerow([r["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"), r["rid"], r["corr"], "Synthetic Person", r["upn"],
                            r["app"], r["ip"], r["loc"], "Success" if r["ok"] else "Failure", "0" if r["ok"] else "50126"])
        counts["entra"] = len(self.entra_json) + len(self.entra_csv)
        # VPN (local SAST time, no zone in the text)
        with open(out / "network/vpn_sessions.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["time", "event", "user", "session", "public_ip", "tunnel_ip", "auth_ref", "bytes_in", "bytes_out",
                        "password_hint"])
            for r in sorted(self.vpn, key=lambda r: r["ts"]):
                w.writerow([(r["ts"] + SAST).strftime("%Y-%m-%d %H:%M:%S"), r["event"], r["user"], r["session"],
                            r["public_ip"], r["tunnel_ip"], r["auth_ref"], r["bytes_in"], r["bytes_out"], "hunter2-not-read"])
        counts["vpn"] = len(self.vpn)
        with open(out / "network/firewall.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["epoch", "action", "src_ip", "dst_ip", "dst_port", "proto", "bytes_sent", "bytes_recv"])
            for r in sorted(self.fw, key=lambda r: r["ts"]):
                w.writerow([int(r["ts"].timestamp()) + FW_SKEW, r["action"], r["src"], r["dst"], r["port"], "tcp", r["out"], r["in"]])
        counts["firewall"] = len(self.fw)
        with open(out / "network/proxy.jsonl", "w") as fh:
            for r in sorted(self.proxy, key=lambda r: r["time"]):
                fh.write(json.dumps(r) + "\n")
        counts["proxy"] = len(self.proxy)
        (out / "apps/middleware.log").write_text("\n".join(self.mw) + "\n")
        counts["middleware"] = len(self.mw)
        with open(out / "intel/indicators.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "value", "provenance", "valid_from", "valid_to", "reference", "description"])
            w.writerow(["ip", EXFIL_DEST, "Partner IR firm (synthetic), report PIR-2026-117", "2026-08-01T00:00:00Z",
                        "2026-12-31T23:59:59Z", "PIR-2026-117", "staging server observed in a related intrusion"])
            w.writerow(["domain", "paste.example.org", "Partner IR firm (synthetic), report PIR-2026-117",
                        "2026-08-01T00:00:00Z", "2026-12-31T23:59:59Z", "PIR-2026-117", "paste site"])
            w.writerow(["ip", "198.51.100.77", "", "2026-08-01T00:00:00Z", "2026-12-31T23:59:59Z", "", "no provenance"])
        if self.scenario == "acceptance":
            with open(out / "evidence/leak_sample_index.csv", "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["sample_row", "matched_table"])
                for i in range(25):
                    w.writerow([i + 1, "LabDB07.dbo.patients"])
        manifest = self.manifest()
        (out / "logs.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
        self.truth.update({"scenario": self.scenario, "window": {"start": WINDOW[0], "end": WINDOW[1]},
                           "counts": counts, "total_events": sum(counts.values())})
        (out / "ground_truth.json").write_text(json.dumps(self.truth, indent=2, sort_keys=True))
        return self.truth

    def manifest(self) -> dict:
        cov = {"start": "2026-08-25T00:00:00Z", "end": "2026-09-15T00:00:00Z"}
        src = [
            {"id": "labsql01-audit", "family": "mssql_audit", "format": "csv", "path": "mssql/labsql01_audit.csv",
             "host": "LABSQL01", "host_ips": [SERVERS["LABSQL01"]], "asset_id": "AST-LABSQL01", "clock_uncertainty_s": 2,
             "coverage": cov},
            {"id": "labsql02-audit", "family": "mssql_audit", "format": "json", "path": "mssql/labsql02_audit.json",
             "host": "LABSQL02", "host_ips": [SERVERS["LABSQL02"]], "asset_id": "AST-LABSQL02", "clock_uncertainty_s": 2,
             "coverage": cov},
            {"id": "lispg01", "family": "pgaudit", "format": "stderr", "path": "pg/postgresql-2026-09.log", "host": "LISPG01",
             "host_ips": ["10.20.0.25"], "asset_id": "AST-LISPG01", "clock_uncertainty_s": 1, "coverage": cov,
             "options": {"log_line_prefix": "%m [%p] %q%u@%d %r %c "}},
            {"id": "web01-iis", "family": "iis", "format": "w3c", "path": "web/iis", "host": "WEB01",
             "host_ips": ["10.20.0.40"], "asset_id": "AST-WEB01", "clock_uncertainty_s": 1, "coverage": cov},
            {"id": "gw01-nginx", "family": "nginx", "format": "custom", "path": "web/nginx/access.log", "host": "GW01",
             "host_ips": ["10.20.0.41"], "asset_id": "AST-GW01", "clock_uncertainty_s": 1, "coverage": cov,
             "options": {"log_format": '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                                       '"$http_referer" "$http_user_agent" $request_id'}},
            {"id": "dc01-security", "family": "win_security", "format": "xml", "path": "windows/dc01_security.xml",
             "host": "DC01", "host_ips": ["10.20.0.5"], "asset_id": "AST-DC01", "coverage": cov},
            {"id": "labsql01-security", "family": "win_security", "format": "csv", "path": "windows/labsql01_security.csv",
             "host": "LABSQL01", "host_ips": [SERVERS["LABSQL01"]], "asset_id": "AST-LABSQL01", "coverage": cov},
            {"id": "labsql02-security", "family": "win_security", "format": "xml", "path": "windows/labsql02_security.xml",
             "host": "LABSQL02", "host_ips": [SERVERS["LABSQL02"]], "asset_id": "AST-LABSQL02", "coverage": cov},
            {"id": "entra", "family": "entra_signin", "format": "json", "path": "identity/entra_signins.json", "coverage": cov},
            {"id": "entra-portal-csv", "family": "entra_signin", "format": "csv", "path": "identity/entra_signins_portal.csv",
             "coverage": cov},
            {"id": "vpn", "family": "vpn", "format": "csv", "path": "network/vpn_sessions.csv", "host": "VPN01",
             "timezone": "Africa/Johannesburg", "coverage": cov,
             "mapping": {"timestamp_format": "%Y-%m-%d %H:%M:%S",
                         "fields": {"ts": "time", "operation": "event", "account": "user", "session_id": "session",
                                    "remote_ip": "public_ip", "assigned_ip": "tunnel_ip", "request_id": "auth_ref",
                                    "bytes": "bytes_in", "bytes_received": "bytes_out"},
                         "operation_map": {"session-start": "vpn_connect", "session-end": "vpn_disconnect"}}},
            {"id": "firewall", "family": "firewall", "format": "csv", "path": "network/firewall.csv", "host": "FW01",
             "timezone": "UTC", "clock_offset_s": FW_SKEW, "clock_uncertainty_s": 5,
             "coverage": dict(cov, missing=[{"start": "2026-09-08T00:00:00Z", "end": "2026-09-08T06:00:00Z",
                                             "reason": "firewall log rotation lost"}]),
             "mapping": {"timestamp_format": "epoch_s",
                         "fields": {"ts": "epoch", "outcome": "action", "remote_ip": "src_ip", "dest_ip": "dst_ip",
                                    "dest_port": "dst_port", "bytes": "bytes_sent", "bytes_received": "bytes_recv"},
                         "outcome_map": {"allow": "success", "deny": "failure"},
                         "constants": {"operation": "flow"}}},
            {"id": "proxy", "family": "proxy", "format": "jsonl", "path": "network/proxy.jsonl", "host": "PRX01",
             "coverage": cov,
             "mapping": {"fields": {"ts": "time", "remote_ip": "client", "account": "user", "method": "method",
                                    "url": "url", "http_status": "status", "bytes": "sent", "bytes_received": "received"},
                         "constants": {"operation": "proxy_request"}}},
            {"id": "middleware", "family": "generic", "format": "kv", "path": "apps/middleware.log", "host": "LISAPP01",
             "timezone": "unknown",
             "mapping": {"timestamp_format": "%Y-%m-%d %H:%M:%S",
                         "fields": {"ts": "time", "operation": "event", "account": "user", "outcome": "status"},
                         "outcome_map": {"ok": "success"}}},
            {"id": "partner-indicators", "family": "indicators", "format": "csv", "path": "intel/indicators.csv",
             "supplied_by": "Partner IR firm (synthetic) via the Information Officer"},
        ]
        doc = {
            "schema": "tripline.logs-manifest/v1",
            "defaults": {"supplied_by": "Synthetic Hospital IT", "received_at": "2026-09-15T08:00:00Z",
                         "legal_basis": "POPIA s22 investigation instructed by the Information Officer (synthetic)"},
            "paths": {
                "sensitive_tables": [f"LabDB{i:02d}.dbo.{t}" for i in range(1, 11) for t in TABLES]
                + ["lis.public.patient_index", "lis.public.specimens"],
                "directory_domains": ["lab.example"],
                "service_accounts": ["lab\\svc_*", "svc_*", "lis_app"],
                "known_jobs": [{"account": "LAB\\svc_lis_import", "operations": ["bulk_insert"],
                                "reason": "nightly LIS results import"}],
                "hospital_hours": {"timezone": "Africa/Johannesburg", "weekdays": "07:00-18:00", "saturday": "08:00-13:00"},
                "baseline": {"start": "2026-08-25T00:00:00Z", "end": "2026-08-31T23:59:59Z", "min_days": 3},
            },
            "sources": src,
        }
        if self.scenario == "acceptance":
            doc["corroborations"] = [{
                "id": "COR-001", "kind": "independently_confirmed_external_copy", "path": "evidence/leak_sample_index.csv",
                "evidence_role": "leak_sample", "tables": ["LabDB07.dbo.patients"],
                "establishes": "An external copy received through counsel contains records that the hospital's analyst "
                               "matched to LabDB07.dbo.patients.",
                "does_not_establish": "Which route or session moved the data, when it left, or that other tables left.",
                "observed_at": "2026-09-12T09:00:00Z"}]
        return doc


def _win_xml(host: str, events: list[dict]) -> str:
    buf = io.StringIO()
    buf.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
    for i, e in enumerate(events, 1):
        ts = e["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        buf.write("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                  "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
                  f"<EventID>{e['EventID']}</EventID><Version>0</Version><Level>0</Level><Task>0</Task><Opcode>0</Opcode>"
                  f"<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{ts}'/>"
                  f"<EventRecordID>{700000 + i}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/>"
                  f"<Channel>Security</Channel><Computer>{host}.lab.example</Computer><Security/></System>")
        if e["EventID"] == 1102:
            buf.write("<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>")
            for k, v in e["data"].items():
                buf.write(f"<{k}>{_x(v)}</{k}>")
            buf.write("</LogFileCleared></UserData>")
        else:
            buf.write("<EventData>")
            for k, v in e["data"].items():
                buf.write(f"<Data Name='{k}'>{_x(v)}</Data>")
            buf.write("</EventData>")
        buf.write("</Event>\n")
    buf.write("</Events>\n")
    return buf.getvalue()


def _x(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate(out: Path | str, scenario: str = "acceptance", scale: int = 20_000, seed: int = 20260903) -> dict:
    g = Generator(Path(out), scenario, scale, seed)
    g.background()
    g.scenarios()
    return g.write()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tripline_scope.paths.synthetic",
                                description="Write a synthetic multi-source incident (logs, logs.yaml, ground truth)")
    p.add_argument("--out", required=True)
    p.add_argument("--scenario", choices=["demo", "acceptance"], default="demo")
    p.add_argument("--scale", type=int, default=20_000, help="approximate number of background events")
    p.add_argument("--seed", type=int, default=20260903)
    a = p.parse_args(argv)
    truth = generate(a.out, a.scenario, a.scale, a.seed)
    print(json.dumps({"out": str(Path(a.out).resolve()), "scenario": truth["scenario"],
                      "total_events": truth["total_events"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
