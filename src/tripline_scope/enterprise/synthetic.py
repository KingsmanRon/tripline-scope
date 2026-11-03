"""Synthetic utility enterprise for the enterprise-profile demonstration and tests (all data fictional).

"Synthetic Utility Ltd" (``utility.example``) is a made-up company. Every host, account, address, bank reference
and amount below is invented for testing: internal addresses are private ranges, external addresses come from the
documentation ranges (RFC 5737), domains end in ``.example`` (RFC 2606). It is not modelled on, and does not
reconstruct, any real organisation or incident.

Scenarios (``--scenario``):

* ``a`` -- suspicious privileged access through a supplier identity; the financial application's audit trail has
  a declared outage during the session and no settlement evidence is supplied: financial impact **not
  determinable**;
* ``b`` -- the same access, plus an attempted unauthorised payment that is **rejected** by an approver, with a
  release attempt **denied** by the application; the bank statement shows no settlement;
* ``c`` -- the same access, plus a payment that was approved by the creating account itself, released, posted and
  **independently settled** (bank statement, exact amount and reference), and a second (USD) payment that the
  application marks as settled but that has **no** independent settlement record.

Stages written: exposure estate (``estate/``: roots, enterprise inputs, ``manifest.yaml``), incident logs
(``logs/``: Windows security, Entra ID sign-ins, VPN, SQL Server audit, financial-application audit, bank
statement, ``logs.yaml``), ``financial.yaml`` (the enterprise analysis configuration) and ``ground_truth.json``.

    python -m tripline_scope.enterprise.synthetic --out DIR --scenario a|b|c [--attest]
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import random
from pathlib import Path

import yaml

UTC = dt.UTC
SAST = dt.timedelta(hours=2)
DOMAIN = "utility.example"
NB = "UTIL"
INCIDENT = ("2026-09-01T00:00:00Z", "2026-09-14T23:59:59Z")
COVER = {"start": "2026-08-25T00:00:00Z", "end": "2026-09-15T00:00:00Z"}
HOSTS = {"DC01": "10.60.0.5", "FIN-APP-01": "10.60.1.10", "FIN-DB-01": "10.60.1.20", "WS-FIN07": "10.60.5.37",
         "VPN-01": "10.60.0.2"}
ATTACKER_IP = "203.0.113.50"          # documentation range
VPN_POOL_IP = "10.60.200.23"
SUPPLIER = "vendor01"                 # VENDOR-01's identity (fictional external service provider)
CLERKS = ["fin.clerk01", "fin.clerk02", "fin.clerk03"]
APPROVERS = ["fin.approver01", "fin.approver02"]
FIN_TABLES = ["FINDB.dbo.vendor_master", "FINDB.dbo.vendor_bank_details", "FINDB.dbo.payment_batches",
              "FINDB.dbo.gl_postings"]
SCENARIOS = ("a", "b", "c")


def _t(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid(rng: random.Random) -> str:
    h = f"{rng.getrandbits(128):032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class Gen:
    def __init__(self, out: Path, scenario: str, seed: int = 20260905):
        if scenario not in SCENARIOS:
            raise ValueError("scenario must be a, b or c")
        self.out, self.sc = Path(out), scenario
        self.rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
        self.win: dict[str, list[dict]] = {"DC01": [], "FIN-APP-01": [], "WS-FIN07": []}
        self.entra: list[dict] = []
        self.vpn: list[dict] = []
        self.sql: list[dict] = []
        self.fin: list[dict] = []
        self.bank: list[dict] = []
        self.n = 0
        self.truth: dict = {"scenario": scenario, "synthetic": True, "transactions": {}, "suspicious": [],
                            "settled_corroborated": [], "exposure_rules": [], "links": {},
                            "secrets_never_in_outputs": []}

    # ------------------------------------------------------------------ primitives
    def wev(self, host, ts, eid, **data):
        self.win[host].append({"ts": ts, "EventID": eid, "data": data})

    def signin(self, ts, user, ip, *, mfa=True, ok=True, app="Synthetic ERP"):
        rid, corr = _uuid(self.rng), _uuid(self.rng)
        rec = {"createdDateTime": _iso(ts), "id": rid, "correlationId": corr, "userPrincipalName": f"{user}@{DOMAIN}",
               "userDisplayName": "Synthetic User", "appDisplayName": app, "ipAddress": ip, "clientAppUsed": "Browser",
               "location": {"city": "Testville", "state": "", "countryOrRegion": "ZA" if ip.startswith("10.") else "XX"},
               "status": {"errorCode": 0 if ok else 50126, "failureReason": None if ok else "Invalid password"}}
        if mfa:
            rec["authenticationRequirement"] = "multiFactorAuthentication"
            rec["mfaDetail"] = {"authMethod": "Mobile app notification", "authDetail": None}
        else:
            rec["authenticationRequirement"] = "singleFactorAuthentication"
        self.entra.append(rec)
        return rid, corr

    def fev(self, ts, actor, action, outcome="success", *, session=None, target=None, txn=None, approval=None,
            amount=None, currency=None, payee=None, corr=None, client=None, target_account=None):
        self.n += 1
        self.fin.append({k: v for k, v in {
            "event_id": f"FA-{self.n:06d}", "timestamp": _iso(ts), "source_system": "SYNTH-ERP",
            "actor_reference": f"{NB}\\{actor}", "action": action, "outcome": outcome,
            "evidence_source_id": "ERP-AUDIT-EXPORT-01", "session_reference": session, "target_reference": target,
            "transaction_reference": txn, "approval_reference": approval, "amount": amount, "currency": currency,
            "payee_reference": payee, "idp_correlation_id": corr, "client_host": client,
            "target_account": target_account}.items() if v is not None})

    def sqlev(self, ts, action, spid, account, *, obj="", rows=None, client_ip="", host="", ok=True):
        self.sql.append({"event_time": ts, "action_id": action, "succeeded": 1 if ok else 0, "session_id": spid,
                         "server_principal_name": account, "session_server_principal_name": account,
                         "target_server_principal_name": "", "server_instance_name": "FIN-DB-01",
                         "database_name": "FINDB" if obj else "", "schema_name": "dbo" if obj else "",
                         "object_name": obj.split(".")[-1] if obj else "",
                         "statement": f"SELECT * FROM dbo.{obj.split('.')[-1]}" if action == "SL" else "",
                         "client_ip": client_ip, "host_name": host, "application_name": "Synthetic ERP",
                         "response_rows": rows, "affected_rows": None, "session_context": ""})

    # ------------------------------------------------------------------ background business activity
    def background(self):
        rng = self.rng
        day0 = _t("2026-08-26T07:00:00Z")
        for d in range(20):
            day = day0 + dt.timedelta(days=d)
            if day.weekday() >= 5:
                continue
            for i, clerk in enumerate(CLERKS):
                ts = day + dt.timedelta(minutes=rng.randrange(0, 300))
                rid, corr = self.signin(ts - dt.timedelta(minutes=2), clerk, HOSTS["WS-FIN07"] if i == 0 else f"10.60.5.{40 + i}")
                self.wev("FIN-APP-01", ts - dt.timedelta(minutes=1), 4624, TargetUserName=clerk, TargetDomainName=NB,
                         TargetLogonId=f"0x{rng.getrandbits(24):x}", LogonType="3", IpAddress=HOSTS["WS-FIN07"],
                         WorkstationName="WS-FIN07")
                sess = f"S-{rng.getrandbits(32):08x}"
                ref = f"PAY-{26000 + d * 10 + i}"
                amt = f"{rng.randrange(10_000, 900_000)}.{rng.randrange(100):02d}"
                payee = f"PAYEE-{rng.randrange(100, 140)}"
                self.fev(ts, clerk, "payment_created", session=sess, target="payment", txn=ref, amount=amt,
                         currency="ZAR", payee=payee, corr=corr, client="WS-FIN07")
                self.fev(ts + dt.timedelta(minutes=3), clerk, "approval_submitted", session=sess, target="payment",
                         txn=ref, approval=f"APR-{ref}", amount=amt, currency="ZAR")
                appr = APPROVERS[(d + i) % 2]
                at = ts + dt.timedelta(hours=1)
                _, acorr = self.signin(at - dt.timedelta(minutes=1), appr, "10.60.5.60")
                asess = f"S-{rng.getrandbits(32):08x}"
                self.fev(at, appr, "approval_completed", session=asess, target="payment", txn=ref,
                         approval=f"APR-{ref}", amount=amt, currency="ZAR", corr=acorr)
                self.fev(at + dt.timedelta(minutes=5), appr, "payment_released", session=asess, target="payment",
                         txn=ref, amount=amt, currency="ZAR")
                self.fev(at + dt.timedelta(hours=2), "svc_finbatch", "ledger_posted", session="BATCH", target="ledger",
                         txn=ref, amount=amt, currency="ZAR")
                self.truth["transactions"][ref] = {"expected_category": "settled_corroborated" if self.sc != "a"
                                                   else "posted", "suspicious": False}
                if self.sc != "a":
                    self.bank.append({"stmt_line": f"BNK-{len(self.bank) + 1:05d}", "booked": _iso(at + dt.timedelta(days=1)),
                                      "end_to_end_ref": ref, "amount": amt, "ccy": "ZAR", "status": "SETTLED",
                                      "bank_ref": f"BR{rng.getrandbits(40):010x}", "doc": "BANK-STMT-SEP-2026"})
                # routine database reads by the application service account
                spid = rng.randrange(60, 400)
                self.sqlev(at, "LGIS", spid, f"{NB}\\svc_finbatch", client_ip=HOSTS["FIN-APP-01"], host="FIN-APP-01")
                self.sqlev(at + dt.timedelta(seconds=20), "SL", spid, f"{NB}\\svc_finbatch",
                           obj="FINDB.dbo.payment_batches", rows=rng.randrange(1, 40), client_ip=HOSTS["FIN-APP-01"],
                           host="FIN-APP-01")
                self.sqlev(at + dt.timedelta(seconds=40), "LGO", spid, f"{NB}\\svc_finbatch",
                           client_ip=HOSTS["FIN-APP-01"], host="FIN-APP-01")

    # ------------------------------------------------------------------ the incident (all scenarios)
    def incident(self):
        # STAGE 3a: unauthorised remote-access software on a finance workstation (process name only is logged)
        t0 = _t("2026-09-04T19:41:00Z")
        self.wev("WS-FIN07", t0, 4624, TargetUserName=CLERKS[0], TargetDomainName=NB, TargetLogonId="0x5a1f02",
                 LogonType="2", IpAddress="-", WorkstationName="WS-FIN07")
        self.wev("WS-FIN07", t0 + dt.timedelta(minutes=2), 4688, SubjectUserName=CLERKS[0], SubjectDomainName=NB,
                 SubjectLogonId="0x5a1f02", NewProcessName="C:\\Users\\Public\\remoteassist.exe")
        # STAGE 3b: the supplier identity signs in from outside, without MFA, after its access window ended
        t1 = _t("2026-09-05T22:10:00Z")
        rid, corr = self.signin(t1, SUPPLIER, ATTACKER_IP, mfa=False)
        self.vpn.append({"ts": t1 + dt.timedelta(minutes=2), "event": "session-start", "user": f"{SUPPLIER}@{DOMAIN}",
                         "session": "VPN-77812", "public_ip": ATTACKER_IP, "tunnel_ip": VPN_POOL_IP, "auth_ref": rid})
        self.vpn.append({"ts": t1 + dt.timedelta(minutes=95), "event": "session-end", "user": f"{SUPPLIER}@{DOMAIN}",
                         "session": "VPN-77812", "public_ip": ATTACKER_IP, "tunnel_ip": VPN_POOL_IP, "auth_ref": rid})
        self.wev("FIN-APP-01", t1 + dt.timedelta(minutes=4), 4624, TargetUserName=SUPPLIER, TargetDomainName=NB,
                 TargetLogonId="0x9c3d11", LogonType="10", IpAddress=VPN_POOL_IP, WorkstationName="UNKNOWN-PC")
        # STAGE 3c: privilege escalation: the supplier account is added to the payments administrators group and
        # exercises special privileges on the application server
        t2 = t1 + dt.timedelta(minutes=8)
        self.wev("DC01", t2, 4728, SubjectUserName="it.admin01", SubjectDomainName=NB, SubjectLogonId="0x3e7",
                 TargetUserName="FIN-Payments-Admins", TargetDomainName=NB,
                 MemberName=f"CN={SUPPLIER},OU=Suppliers,DC=utility,DC=example")
        self.wev("FIN-APP-01", t2 + dt.timedelta(minutes=1), 4672, SubjectUserName=SUPPLIER, SubjectDomainName=NB,
                 SubjectLogonId="0x9c3d11")
        # STAGE 4: the financial application session (direct link: it records the identity provider correlation id)
        s = "S-SUP-0905"
        t3 = t2 + dt.timedelta(minutes=5)
        self.fev(t3, SUPPLIER, "role_assigned", session=s, target="role:AP_RELEASE", corr=corr, client="UNKNOWN-PC",
                 target_account=f"{NB}\\{SUPPLIER}")
        self.fev(t3 + dt.timedelta(minutes=2), SUPPLIER, "view_vendor_master", session=s, target="vendor_master",
                 corr=corr)
        spid = 913
        self.sqlev(t3 + dt.timedelta(minutes=3), "LGIS", spid, f"{NB}\\{SUPPLIER}", client_ip=VPN_POOL_IP, host="UNKNOWN-PC")
        self.sqlev(t3 + dt.timedelta(minutes=3, seconds=30), "SL", spid, f"{NB}\\{SUPPLIER}",
                   obj="FINDB.dbo.vendor_bank_details", rows=412, client_ip=VPN_POOL_IP, host="UNKNOWN-PC")
        self.sqlev(t3 + dt.timedelta(minutes=6), "LGO", spid, f"{NB}\\{SUPPLIER}", client_ip=VPN_POOL_IP, host="UNKNOWN-PC")
        self.truth["links"] = {"session": s, "identity": "direct", "privilege_grant_observed": True,
                               "supplier_outside_window": True}
        t4 = t3 + dt.timedelta(minutes=10)
        if self.sc == "a":
            self.fev(t4, SUPPLIER, "view_payment_batch", session=s, target="payment_batches", corr=corr)
            self.truth["impact"] = "not_determinable"
        elif self.sc == "b":
            ref = "PAY-90017"
            self.fev(t4, SUPPLIER, "payee_modified", session=s, target="vendor:V-1003", payee="PAYEE-ATTACKER-1")
            self.fev(t4 + dt.timedelta(minutes=2), SUPPLIER, "payment_created", session=s, target="payment", txn=ref,
                     amount="4850000.00", currency="ZAR", payee="PAYEE-ATTACKER-1")
            self.fev(t4 + dt.timedelta(minutes=4), SUPPLIER, "approval_submitted", session=s, target="payment", txn=ref,
                     approval="APR-PAY-90017", amount="4850000.00", currency="ZAR")
            self.fev(t4 + dt.timedelta(minutes=5), SUPPLIER, "payment_released", "denied", session=s, target="payment",
                     txn=ref, amount="4850000.00", currency="ZAR")
            at = _t("2026-09-06T07:35:00Z")
            _, acorr = self.signin(at - dt.timedelta(minutes=1), APPROVERS[0], "10.60.5.60")
            self.fev(at, APPROVERS[0], "approval_rejected", session="S-APR-0906", target="payment", txn=ref,
                     approval="APR-PAY-90017", amount="4850000.00", currency="ZAR", corr=acorr)
            self.truth["transactions"][ref] = {"expected_category": "rejected_or_stopped", "suspicious": True,
                                               "amount_minor": 485000000, "currency": "ZAR"}
            self.truth["suspicious"].append(ref)
            self.truth["impact"] = "attempt_rejected"
        else:
            ref, ref2 = "PAY-90231", "PAY-90232"
            self.fev(t4, SUPPLIER, "payee_modified", session=s, target="vendor:V-1007", payee="PAYEE-ATTACKER-2")
            self.fev(t4 + dt.timedelta(minutes=2), SUPPLIER, "payment_created", session=s, target="payment", txn=ref,
                     amount="1275400.00", currency="ZAR", payee="PAYEE-ATTACKER-2")
            self.fev(t4 + dt.timedelta(minutes=3), SUPPLIER, "approval_submitted", session=s, target="payment", txn=ref,
                     approval="APR-PAY-90231", amount="1275400.00", currency="ZAR")
            self.fev(t4 + dt.timedelta(minutes=6), SUPPLIER, "approval_completed", session=s, target="payment", txn=ref,
                     approval="APR-PAY-90231", amount="1275400.00", currency="ZAR")
            self.fev(t4 + dt.timedelta(minutes=8), SUPPLIER, "payment_released", session=s, target="payment", txn=ref,
                     amount="1275400.00", currency="ZAR")
            self.fev(t4 + dt.timedelta(minutes=40), "svc_finbatch", "ledger_posted", session="BATCH", target="ledger",
                     txn=ref, amount="1275400.00", currency="ZAR")
            self.bank.append({"stmt_line": f"BNK-{len(self.bank) + 1:05d}", "booked": "2026-09-07T09:00:00Z",
                              "end_to_end_ref": ref, "amount": "1275400.00", "ccy": "ZAR", "status": "SETTLED",
                              "bank_ref": "BR00a91c7e55", "doc": "BANK-STMT-SEP-2026"})
            # a second payment in another currency: the application says "settled", the bank statement does not
            for k, (a, cur) in enumerate([("18500.00", "USD")]):
                base = t4 + dt.timedelta(minutes=12 + k)
                self.fev(base, SUPPLIER, "payment_created", session=s, target="payment", txn=ref2, amount=a, currency=cur,
                         payee="PAYEE-ATTACKER-3")
                self.fev(base + dt.timedelta(minutes=1), SUPPLIER, "approval_submitted", session=s, target="payment",
                         txn=ref2, approval="APR-PAY-90232", amount=a, currency=cur)
                self.fev(base + dt.timedelta(minutes=2), SUPPLIER, "approval_completed", session=s, target="payment",
                         txn=ref2, approval="APR-PAY-90232", amount=a, currency=cur)
                self.fev(base + dt.timedelta(minutes=3), SUPPLIER, "payment_released", session=s, target="payment",
                         txn=ref2, amount=a, currency=cur)
                self.fev(base + dt.timedelta(minutes=45), "svc_finbatch", "ledger_posted", session="BATCH",
                         target="ledger", txn=ref2, amount=a, currency=cur)
                self.fev(base + dt.timedelta(hours=20), "svc_finbatch", "settlement_confirmed", session="BATCH",
                         target="payment", txn=ref2, amount=a, currency=cur)
            self.truth["transactions"][ref] = {"expected_category": "settled_corroborated", "suspicious": True,
                                               "amount_minor": 127540000, "currency": "ZAR"}
            self.truth["transactions"][ref2] = {"expected_category": "posted", "suspicious": True,
                                                "amount_minor": 1850000, "currency": "USD"}
            self.truth["suspicious"] += [ref, ref2]
            self.truth["settled_corroborated"].append(ref)
            self.truth["impact"] = "settlement_corroborated"
        # malformed and duplicate records in every scenario (adapter robustness)
        self.fin.append({"event_id": "FA-BAD-1", "timestamp": "not-a-time", "source_system": "SYNTH-ERP",
                         "actor_reference": f"{NB}\\{CLERKS[1]}", "action": "payment_created", "outcome": "success",
                         "evidence_source_id": "ERP-AUDIT-EXPORT-01"})
        self.fin.append(dict(self.fin[0]))       # exact duplicate of the first record
        self.truth["parse_failures_min"] = 1
        self.truth["exact_duplicates"] = 1

    # ------------------------------------------------------------------ writers
    def write_logs(self) -> Path:
        d = self.out / "logs"
        for sub in ("windows", "identity", "network", "mssql", "finapp", "bank"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        cols = ["TimeCreated", "EventID", "Computer", "RecordId", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
                "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "IpAddress", "WorkstationName",
                "NewProcessName", "MemberName"]
        for host, evs in self.win.items():
            with open(d / f"windows/{host.lower()}_security.csv", "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                for i, e in enumerate(sorted(evs, key=lambda e: e["ts"]), 1):
                    row = {"TimeCreated": e["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z", "EventID": e["EventID"],
                           "Computer": f"{host}.{DOMAIN}", "RecordId": 100000 + i, **e["data"]}
                    w.writerow([row.get(c, "") for c in cols])
        (d / "identity/entra_signins.json").write_text(json.dumps(
            {"value": sorted(self.entra, key=lambda r: r["createdDateTime"])}))
        with open(d / "network/vpn_sessions.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["time", "event", "user", "session", "public_ip", "tunnel_ip", "auth_ref", "secret_hint"])
            for r in sorted(self.vpn, key=lambda r: r["ts"]):
                w.writerow([(r["ts"] + SAST).strftime("%Y-%m-%d %H:%M:%S"), r["event"], r["user"], r["session"],
                            r["public_ip"], r["tunnel_ip"], r["auth_ref"], "never-read-by-the-adapter"])
        sql_cols = ["event_time", "sequence_number", "action_id", "succeeded", "session_id", "server_principal_name",
                    "session_server_principal_name", "target_server_principal_name", "server_instance_name",
                    "database_name", "schema_name", "object_name", "statement", "client_ip", "host_name",
                    "application_name", "response_rows", "affected_rows", "session_context"]
        with open(d / "mssql/findb01_audit.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(sql_cols)
            for i, r in enumerate(sorted(self.sql, key=lambda r: r["event_time"]), 1):
                r = dict(r, sequence_number=i, event_time=r["event_time"].strftime("%Y-%m-%d %H:%M:%S.%f") + "0")
                w.writerow(["" if r.get(c) is None else r[c] for c in sql_cols])
        with open(d / "finapp/erp_audit.jsonl", "w") as fh:
            for r in self.fin:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        fin_cov = dict(COVER)
        if self.sc == "a":
            fin_cov["missing"] = [{"start": "2026-09-05T22:40:00Z", "end": "2026-09-05T23:30:00Z",
                                   "reason": "financial application audit export interrupted (synthetic)"}]
        sources = [
            {"id": "dc01-security", "family": "win_security", "format": "csv", "path": "windows/dc01_security.csv",
             "host": "DC01", "host_ips": [HOSTS["DC01"]], "asset_id": "AST-DC01", "coverage": COVER},
            {"id": "finapp01-security", "family": "win_security", "format": "csv",
             "path": "windows/fin-app-01_security.csv", "host": "FIN-APP-01", "host_ips": [HOSTS["FIN-APP-01"]],
             "asset_id": "AST-FIN-APP01", "coverage": COVER},
            {"id": "wsfin07-security", "family": "win_security", "format": "csv", "path": "windows/ws-fin07_security.csv",
             "host": "WS-FIN07", "host_ips": [HOSTS["WS-FIN07"]], "asset_id": "AST-WS-FIN07", "coverage": COVER},
            {"id": "idp01-entra", "family": "entra_signin", "format": "json", "path": "identity/entra_signins.json",
             "asset_id": "AST-IDP01", "coverage": COVER},
            {"id": "vpn01", "family": "vpn", "format": "csv", "path": "network/vpn_sessions.csv", "host": "VPN-01",
             "timezone": "Africa/Johannesburg", "asset_id": "AST-VPN01", "coverage": COVER,
             "mapping": {"timestamp_format": "%Y-%m-%d %H:%M:%S",
                         "fields": {"ts": "time", "operation": "event", "account": "user", "session_id": "session",
                                    "remote_ip": "public_ip", "assigned_ip": "tunnel_ip", "request_id": "auth_ref"},
                         "operation_map": {"session-start": "vpn_connect", "session-end": "vpn_disconnect"}}},
            {"id": "findb01-audit", "family": "mssql_audit", "format": "csv", "path": "mssql/findb01_audit.csv",
             "host": "FIN-DB-01", "host_ips": [HOSTS["FIN-DB-01"]], "asset_id": "AST-FIN-DB01",
             "clock_uncertainty_s": 2, "coverage": dict(COVER, databases=["FINDB"])},
            {"id": "erp-audit", "family": "fin_app_audit", "format": "jsonl", "path": "finapp/erp_audit.jsonl",
             "host": "FIN-APP-01", "asset_id": "AST-FIN-APP01", "coverage": fin_cov,
             "mapping": {"action_map": {"view_vendor_master": "other", "view_payment_batch": "other"}}},
        ]
        if self.bank:
            with open(d / "bank/bank_statement.csv", "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["stmt_line", "booked", "end_to_end_ref", "amount", "ccy", "status", "bank_ref", "doc",
                            "beneficiary_account"])
                for r in self.bank:
                    acct = "62000000" + str(self.rng.randrange(1000, 9999))
                    self.truth["secrets_never_in_outputs"] += [acct, r["bank_ref"]]
                    w.writerow([r["stmt_line"], r["booked"], r["end_to_end_ref"], r["amount"], r["ccy"], r["status"],
                                r["bank_ref"], r["doc"], acct])
            sources.append({"id": "bank-statement", "family": "bank_settlement", "format": "csv",
                            "path": "bank/bank_statement.csv", "supplied_by": "Synthetic Bank (via Finance)",
                            "coverage": COVER,
                            "mapping": {"fields": {"event_id": "stmt_line", "timestamp": "booked",
                                                   "transaction_reference": "end_to_end_ref", "amount": "amount",
                                                   "currency": "ccy", "outcome": "status", "bank_reference": "bank_ref",
                                                   "evidence_source_id": "doc"},
                                        "outcome_map": {"SETTLED": "settled", "RETURNED": "returned"}}})
        doc = {"schema": "tripline.logs-manifest/v1",
               "defaults": {"supplied_by": "Synthetic Utility IT (synthetic)", "received_at": "2026-09-15T08:00:00Z",
                            "legal_basis": "internal forensic investigation instructed by the CISO (synthetic)"},
               "paths": {"sensitive_tables": FIN_TABLES, "directory_domains": [DOMAIN],
                         "service_accounts": [f"{NB.lower()}\\svc_*", "svc_*"],
                         "hospital_hours": {"timezone": "Africa/Johannesburg", "weekdays": "07:00-18:00"},
                         "baseline": {"start": "2026-08-25T00:00:00Z", "end": "2026-08-31T23:59:59Z", "min_days": 3}},
               "sources": sources}
        (d / "logs.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
        return d

    def write_estate(self) -> Path:
        d = self.out / "estate"
        for sub in ("roots/scripts/finance", "roots/share/Finance/Approved", "roots/share/Backups", "enterprise"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        rng = self.rng
        # a plaintext credential for the finance batch service account in a deployment script (A1)
        pw = f"Synth-{rng.getrandbits(48):012x}-Pw!"
        self.truth["secrets_never_in_outputs"].append(pw)
        (d / "roots/scripts/finance/deploy_payment_batch.ps1").write_text(
            "$server = 'FIN-DB-01'\n$user = 'UTIL\\svc_finbatch'\n"
            f"$password = '{pw}'\nInvoke-Batch -Server $server\n")
        hdr = "payee_name,contact_email,bank_account,branch_code,amount\n"
        accts = [f"62{rng.randrange(10**8, 10**9)}" for _ in range(40)]
        self.truth["secrets_never_in_outputs"] += accts
        rows = "".join(f"Synthetic Payee {i},payee{i}@vendors.example,{accts[i]},250655,"
                       f"{rng.randrange(1000, 90000)}.00\n" for i in range(40))
        (d / "roots/share/Finance/ap_payments_export_2026-09.csv").write_text(hdr + rows)          # outside inventory
        (d / "roots/share/Finance/Approved/ap_payments_2026-08.csv").write_text(hdr + rows)         # inventoried
        (d / "roots/share/Backups/FINDB_full_20260901.bak").write_bytes(b"TAPE" + bytes(rng.randrange(256)
                                                                                         for _ in range(8192)))
        e = d / "enterprise"
        _csv(e / "entitlements.csv", ["account", "asset", "role", "privilege", "account_type"], [
            [f"{NB}\\fin.approver01", "AST-FIN-APP01", "AP_APPROVER", "admin", "user"],
            [f"{NB}\\{SUPPLIER}", "AST-FIN-APP01", "SUPPORT_ADMIN", "admin", "supplier"],
            [f"{NB}\\svc_finbatch", "AST-FIN-DB01", "db_datawriter", "write", "service"],
            [f"{NB}\\svc_report", "AST-FIN-DB01", "db_datareader", "read", "service"],
            [f"{NB}\\fin.clerk01", "AST-FIN-APP01", "AP_CLERK", "write", "user"]])
        _csv(e / "role_mappings.csv", ["account", "asset", "role", "approved_by", "approved_on"], [
            [f"{NB}\\fin.approver01", "AST-FIN-APP01", "AP_APPROVER", "CFO (synthetic)", "2026-01-10"]])
        _csv(e / "operational_requirements.csv", ["account", "asset", "max_privilege", "justification"], [
            [f"{NB}\\svc_finbatch", "AST-FIN-DB01", "read", "reads payment batches for posting (synthetic)"],
            [f"{NB}\\{SUPPLIER}", "AST-FIN-APP01", "read", "application support, read-only (synthetic)"]])
        _csv(e / "data_inventory.csv", ["root", "path_prefix", "purpose", "owner"], [
            ["share", "Finance/Approved", "approved AP payment archive", "Finance (synthetic)"]])
        _csv(e / "audit_coverage.csv", ["asset", "operation", "audited", "evidence"], [
            ["AST-FIN-APP01", "payment_release", "yes", "ERP audit policy (synthetic)"],
            ["AST-FIN-APP01", "vendor_master_change", "no", "ERP audit policy (synthetic)"],
            ["AST-FIN-APP01", "privilege_change", "unknown", ""],
            ["AST-FIN-DB01", "privilege_change", "yes", "SQL audit spec (synthetic)"]])
        _csv(e / "supplier_access.csv", ["account", "supplier", "window_start", "window_end", "enabled", "last_sign_in"], [
            [f"{NB}\\{SUPPLIER}", "VENDOR-01 (fictional service provider)", "2026-06-01", "2026-08-31", "yes",
             "2026-09-05"]])
        assets = {"assets": [
            {"asset_id": "AST-FIN-APP01", "kind": "application", "names": ["FIN-APP-01", "fin-app-01"],
             "owner": "Finance IT (synthetic)", "criticality": "high"},
            {"asset_id": "AST-FIN-DB01", "kind": "database", "names": ["FIN-DB-01", "fin-db-01", "FINDB"],
             "owner": "Finance IT (synthetic)", "criticality": "high"},
            {"asset_id": "AST-IDP01", "kind": "identity", "names": ["IDP-01"], "criticality": "high"},
            {"asset_id": "AST-VPN01", "kind": "network", "names": ["VPN-01"], "criticality": "high"},
            {"asset_id": "AST-DC01", "kind": "host", "names": ["DC01"], "criticality": "high"},
            {"asset_id": "AST-WS-FIN07", "kind": "host", "names": ["WS-FIN07"], "criticality": "medium"},
            {"asset_id": "AST-AUDIT01", "kind": "host", "names": ["AUDIT-01"], "criticality": "high"},
            {"asset_id": "AST-SHARE01", "kind": "share", "names": ["FS-01"], "criticality": "medium"},
        ]}
        (d / "assets.yaml").write_text(yaml.safe_dump(assets, sort_keys=False))
        man = {"schema": "tripline.exposure-manifest/v1", "scan_id": "synthetic-utility-exposure",
               "owner": "CISO (synthetic)", "legal_basis": "internal security assessment (synthetic)",
               "supplied_by": "Synthetic Utility IT", "received_at": "2026-09-15T08:00:00Z",
               "snapshot_taken_at": "2026-09-15T06:00:00Z", "assets": "assets.yaml",
               "budget": {"max_files": 1000, "max_total_bytes": "64MiB", "max_file_bytes": "2MiB", "max_seconds": 300,
                          "archive_max_depth": 1, "archive_max_members": 50, "archive_max_ratio": 100,
                          "archive_max_total_bytes": "16MiB"},
               "roots": [{"id": "scripts", "kind": "scripts", "path": "roots/scripts", "asset": "AST-FIN-APP01"},
                         {"id": "share", "kind": "share", "path": "roots/share", "asset": "AST-SHARE01"}],
               "enterprise": {"financial_assets": ["AST-FIN-APP01", "AST-FIN-DB01"],
                              "entitlements": "enterprise/entitlements.csv",
                              "role_mappings": "enterprise/role_mappings.csv",
                              "operational_requirements": "enterprise/operational_requirements.csv",
                              "data_inventory": "enterprise/data_inventory.csv",
                              "audit_coverage": "enterprise/audit_coverage.csv",
                              "supplier_access": "enterprise/supplier_access.csv"}}
        (d / "manifest.yaml").write_text(yaml.safe_dump(man, sort_keys=False))
        self.truth["exposure_rules"] = sorted([
            "E1.privileged-unmapped", "E2.exceeds-requirement", "E3.copy-outside-inventory", "E4.audit-not-enabled",
            "E5.supplier-window-exceeded"])
        self.truth["exposure_not_flagged"] = {"E1": [f"{NB.lower()}\\fin.approver01".split("\\")[1]],
                                              "E3": ["Finance/Approved/ap_payments_2026-08.csv"]}
        return d

    def write_config(self) -> Path:
        cfg = {"schema": "tripline.financial-config/v1",
               "directory_domains": [DOMAIN],
               "supplier_accounts": [{"account": f"{NB}\\{SUPPLIER}", "supplier": "VENDOR-01 (fictional)",
                                      "window_start": "2026-06-01", "window_end": "2026-08-31"}],
               "privileged_groups": ["FIN-Payments-Admins", "Domain Admins"],
               "approved_privileged_accounts": [f"{NB}\\fin.approver01", f"{NB}\\fin.approver02"],
               "directory_members": {f"{NB}\\{SUPPLIER}": f"CN={SUPPLIER},OU=Suppliers,DC=utility,DC=example"},
               "correlation": {"signin_to_app_s": 3600, "logon_to_app_s": 3600, "privilege_before_session_s": 86400}}
        p = self.out / "financial.yaml"
        p.write_text(yaml.safe_dump(cfg, sort_keys=False))
        return p


def _csv(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def generate(out: Path | str, scenario: str = "c", seed: int = 20260905) -> dict:
    g = Gen(Path(out), scenario, seed)
    g.out.mkdir(parents=True, exist_ok=True)
    g.background()
    g.incident()
    g.write_estate()
    g.write_logs()
    g.write_config()
    # raw business references must never appear in released outputs (only keyed TXN-/CPTY- refs)
    g.truth["secrets_never_in_outputs"] += sorted(g.truth["transactions"]) + sorted(
        {r["payee_reference"] for r in g.fin if r.get("payee_reference")}) + ["never-read-by-the-adapter"]
    (g.out / "ground_truth.json").write_text(json.dumps(g.truth, indent=2, sort_keys=True))
    return g.truth


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="synthetic utility enterprise (fictional) for the enterprise profile")
    p.add_argument("--out", required=True)
    p.add_argument("--scenario", choices=SCENARIOS, default="c")
    p.add_argument("--seed", type=int, default=20260905)
    p.add_argument("--attest", action="store_true", help="record the outputs in the synthetic-origin registry")
    a = p.parse_args(argv)
    truth = generate(a.out, a.scenario, a.seed)
    if a.attest:
        from tripline_scope.core.home import Home
        from tripline_scope.investigator.synthetic import attest_outputs

        n = attest_outputs(Home(), "enterprise-synthetic", {"scenario": a.scenario, "seed": a.seed}, [Path(a.out)])
        print(f"attested {n} files")
    # counts only: raw business references stay in the generated inputs and ground_truth.json
    print(json.dumps({"scenario": truth["scenario"], "suspicious_transactions": len(truth["suspicious"]),
                      "out": str(a.out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
