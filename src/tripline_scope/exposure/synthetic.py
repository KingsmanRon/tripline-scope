"""Synthetic Module A fixtures (tests, drills, demo). Never used on real data.

``build(out, variant)`` writes a complete scan input set: snapshot roots (IIS web root with a minified bundle,
proxy configuration, a file share with stale exports, backups and archives, a repository with history), catalogue
exports (SQL Server JSON, PostgreSQL CSV directory, an unsupported engine), identity exports with gaps, a
supplier register, an asset map and the manifest, plus ``ground_truth.json`` (outside every root) listing the
seeded secrets, seeded SA ID numbers and the expected findings. ``variant="fixed"`` remediates a subset of the
flaws so a re-scan shows verified ``mitigated`` deltas; with the same seed every unchanged secret is identical.

All secret-shaped values are generated from a seeded PRNG at build time; none is a real credential.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import io
import json
import os
import random
import string
import zipfile
import zlib
from pathlib import Path

import yaml

from tripline_scope.core.identifiers import make_sa_id, parse_sa_id

AS_OF = "2026-10-01T00:00:00Z"
RECENT = dt.datetime(2026, 9, 20, 8, 0, tzinfo=dt.UTC).timestamp()
STALE = dt.datetime(2025, 1, 15, 8, 0, tzinfo=dt.UTC).timestamp()
FIRST = ["Thandi", "Sipho", "Lerato", "Johan", "Ayesha", "Pieter", "Nomsa", "Kagiso", "Fatima", "Riaan", "Zanele",
         "Themba", "Annelie", "Bongani", "Precious", "Mohammed"]
LAST = ["Nkosi", "Botha", "Mokoena", "Naidoo", "van der Merwe", "Dlamini", "Pillay", "Khumalo", "Smit", "Mahlangu",
        "Govender", "Jacobs", "Ndlovu", "Fourie"]
TESTS = [("FBC", "Full blood count"), ("HBA1C", "HbA1c"), ("CD4", "CD4 count"), ("UE", "Urea and electrolytes")]
ICD = ["E11.9", "B20", "I10", "J45.9", "N18.3"]


class _Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)  # noqa: S311 - deterministic synthetic fixtures by design
        self.secrets: dict[str, str] = {}
        self.ids: list[str] = []

    def s(self, alphabet: str, n: int) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def secret(self, name: str, value: str) -> str:
        self.secrets[name] = value
        return value

    def password(self, name: str) -> str:
        v = self.s(string.ascii_letters, 4) + "-" + self.s(string.ascii_letters + string.digits, 10) + self.rng.choice("!#%")
        return self.secret(name, v)

    def sa_id(self) -> str:
        d = dt.date(1940, 1, 1) + dt.timedelta(days=self.rng.randrange(0, 365 * 80))
        v = make_sa_id(d, self.rng.randrange(0, 10000), citizenship=self.rng.choice([0, 0, 0, 1]))
        self.ids.append(v)
        return v

    def non_id13(self) -> str:
        while True:
            v = self.s(string.digits, 13)
            if not parse_sa_id(v).valid:
                return v

    def person(self) -> dict:
        sid = self.sa_id()
        p = parse_sa_id(sid)
        return {"id": sid, "first": self.rng.choice(FIRST), "last": self.rng.choice(LAST),
                "dob": p.dob(dt.date(2026, 10, 1)).isoformat()}


def _write(path: Path, data: bytes | str, mtime: float = RECENT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    os.utime(path, (mtime, mtime))
    return path


def _csv(rows: list[list]) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    return buf.getvalue()


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zi = zipfile.ZipInfo(name, date_time=(2024, 6, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    return buf.getvalue()


def _pem(g: _Gen) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes(g.rng.randrange(256) for _ in range(32)))
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    body = "".join(pem.strip().splitlines()[1:-1])
    g.secret("repo_private_key_body", body)
    return pem


# ------------------------------------------------------------------------------------------ roots
def _web_root(base: Path, g: _Gen, fixed: bool, truth: list) -> None:
    w = base / "wwwroot"
    pw_lab = g.password("web_config_lab_app")
    pw_smtp = g.password("web_config_smtp")
    vkey = g.secret("machine_validation_key", g.s("0123456789ABCDEF", 128))
    dkey = g.secret("machine_decryption_key", g.s("0123456789ABCDEF", 64))
    conn = ("Server=LABSQL01;Database=LabDB;Integrated Security=true;" if fixed else
            f"Server=LABSQL01;Database=LabDB;User ID=lab_app;Password={pw_lab};")
    _write(w / "web.config", f"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="LabDb" connectionString="{conn}" providerName="System.Data.SqlClient" />
    <add name="Reporting" connectionString="Server=LABSQL01;Database=LabDB;Integrated Security=true;" />
  </connectionStrings>
  <appSettings>
    <add key="SmtpPassword" value="{pw_smtp}" />
    <add key="PasswordMinLength" value="12" />
    <add key="PaymentApiKey" value="${{PAYMENT_API_KEY}}" />
  </appSettings>
  <system.web>
    <machineKey validationKey="{vkey}" decryptionKey="{dkey}" validation="HMACSHA256" decryption="AES" />
  </system.web>
</configuration>
""")
    if not fixed:
        truth.append({"rule_id": "A1.db-connection-password", "root": "web01", "path": "wwwroot/web.config",
                      "severity": "high", "fixed_in_variant": True})
    truth += [{"rule_id": "A1.generic-password", "root": "web01", "path": "wwwroot/web.config", "severity": "medium"},
              {"rule_id": "A1.aspnet-machine-key", "root": "web01", "path": "wwwroot/web.config", "severity": "high"}]
    gkey = g.secret("bundle_google_key", "AIza" + g.s(string.ascii_letters + string.digits + "_-", 35))
    hexkey = g.secret("bundle_api_key", g.s("0123456789abcdef", 40))
    stripe_test = g.secret("bundle_stripe_test_key", "sk_" + "test_" + g.s(string.ascii_letters + string.digits, 24))
    filler = ";".join(f"function f{i}(a,b){{return a*{i}+b}}" for i in range(400))
    _write(w / "js" / "app.min.js",
           f'!function(){{"use strict";var e={{apiBase:"/api/v2",mapsKey:"{gkey}",payKey:"{stripe_test}",'
           f'password:n.value,token:t,passwordField:"input#pwd"}};{filler};fetch(e.apiBase,{{headers:'
           f'{{"x-api-key":"{hexkey}","Content-Type":"application/json"}}}})}}();\n')
    truth += [{"rule_id": "A1.google-api-key", "root": "web01", "path": "wwwroot/js/app.min.js", "severity": "high"},
              {"rule_id": "A1.generic-secret", "root": "web01", "path": "wwwroot/js/app.min.js", "severity": "high"}]
    uuid = f"{g.s('0123456789abcdef', 8)}-{g.s('0123456789abcdef', 4)}-4{g.s('0123456789abcdef', 3)}-a{g.s('0123456789abcdef', 3)}-{g.s('0123456789abcdef', 12)}"
    _write(w / "js" / "vendor.min.js",
           '!function(){var o={passwordField:"#pwd",password:e.value,token:t,tokenUrl:"/oauth/token",'
           f'clientId:"{uuid}",api_key_name:"X-Key",integrity:"sha384-{g.s(string.ascii_letters + string.digits, 64)}",'
           'secret:o.secret,authMode:"pkce"};return o}();\n')
    if not fixed:
        pw_env = g.password("env_db_password")
        app_key = g.secret("env_app_key", base64.b64encode(bytes(g.rng.randrange(256) for _ in range(32))).decode())
        _write(w / ".env", f"APP_ENV=production\nDB_HOST=pathdb.hosp.example\nDB_PASSWORD={pw_env}\nAPP_KEY=base64:{app_key}\n")
        truth += [{"rule_id": "A1.generic-password", "root": "web01", "path": "wwwroot/.env", "severity": "high",
                   "fixed_in_variant": True},
                  {"rule_id": "A1.generic-signing-key", "root": "web01", "path": "wwwroot/.env", "severity": "critical",
                   "fixed_in_variant": True}]
    else:
        g.password("env_db_password")
        g.secret("env_app_key", base64.b64encode(bytes(g.rng.randrange(256) for _ in range(32))).decode())
    pw_php = g.password("php_db_password")
    salt = g.secret("php_auth_key", g.s(string.ascii_letters + string.digits + "!@#%^&*()-_[]{}<>~+=,.;:/?|", 64))
    _write(w / "config.php", f"<?php\ndefine('DB_NAME', 'portal');\ndefine('DB_USER', 'portal');\n"
                             f"define('DB_PASSWORD', '{pw_php}');\ndefine('AUTH_KEY', '{salt}');\n")
    truth += [{"rule_id": "A1.generic-password", "root": "web01", "path": "wwwroot/config.php", "severity": "medium"},
              {"rule_id": "A1.generic-secret", "root": "web01", "path": "wwwroot/config.php", "severity": "medium"}]
    fixture_pw = g.password("test_fixture_password")
    _write(w / "tests" / "fixtures" / "web.config",
           f'<add name="T" connectionString="Server=testdb;Database=Test;User ID=t;Password={fixture_pw};" />\n')
    _write(w / "docs" / "example.env", "DB_PASSWORD=changeme\nAPI_KEY=your_api_key_here\nTOKEN=${TOKEN}\n")
    excluded = g.password("excluded_node_modules_secret")
    _write(w / "node_modules" / "lib" / "config.js", f'module.exports={{password:"{excluded}"}};\n')
    rows = [["PatientNo", "ID Number", "Surname", "First Name", "DOB"]]
    for i in range(12):
        p = g.person()
        rows.append([f"P{1000 + i}", p["id"], p["last"], p["first"], p["dob"]])
    _write(w / "downloads" / "patient_list.csv", _csv(rows))
    truth.append({"rule_id": "A3.data-copy", "root": "web01", "path": "wwwroot/downloads/patient_list.csv",
                  "severity": "critical"})
    (w / "js" / "current").symlink_to(".", target_is_directory=True)
    (w / "escape").symlink_to(Path("..") / ".." / ".." / "outside", target_is_directory=True)


def _proxy_root(base: Path, g: _Gen, truth: list) -> None:
    basic = base64.b64encode(f"proxyuser:{g.password('nginx_basic_password')}".encode()).decode()
    fcgi = g.password("nginx_fastcgi_password")
    _write(base / "nginx" / "nginx.conf", f"""server {{
    listen 443 ssl;
    location /lis/ {{
        proxy_pass http://lis.hosp.example:8080/;
        proxy_set_header Authorization "Basic {basic}";
    }}
    location ~ \\.php$ {{
        fastcgi_param DB_PASSWORD {fcgi};
    }}
}}
""")
    setenv = g.password("apache_setenv_password")
    _write(base / "apache2" / "sites-enabled" / "portal.conf",
           f'<VirtualHost *:443>\n  ServerName portal.hosp.example\n  SetEnv DB_PASS "{setenv}"\n</VirtualHost>\n')
    truth += [{"rule_id": "A1.basic-auth-header", "root": "proxy01", "path": "nginx/nginx.conf", "severity": "low"},
              {"rule_id": "A1.generic-password", "root": "proxy01", "path": "nginx/nginx.conf", "severity": "low"},
              {"rule_id": "A1.generic-password", "root": "proxy01", "path": "apache2/sites-enabled/portal.conf",
               "severity": "low"}]


def _share_root(base: Path, g: _Gen, fixed: bool, truth: list) -> None:
    ex = base / "Lab" / "Exports"
    rows = [["PatientNo", "ID Number", "Surname", "First Name", "DOB", "Test", "Result"]]
    for i in range(150):
        p = g.person()
        t = g.rng.choice(TESTS)
        rows.append([f"P{2000 + i}", p["id"], p["last"], p["first"], p["dob"], t[0], str(round(g.rng.uniform(1, 20), 1))])
    if not fixed:
        _write(ex / "patients_2025-01.csv", _csv(rows), STALE)
        truth.append({"rule_id": "A3.data-copy", "root": "share01", "path": "Lab/Exports/patients_2025-01.csv",
                      "severity": "high", "fixed_in_variant": True, "details": {"id_assessment": "confirmed",
                                                                                "record_count_band": "100-999",
                                                                                "stale": True}})
    acc = [["accession_no", "specimen", "received"]] + [[g.non_id13(), g.rng.choice(["blood", "urine", "swab"]),
                                                          "2026-08-0" + str(g.rng.randrange(1, 9))] for _ in range(200)]
    _write(ex / "accessions_2026.csv", _csv(acc))
    _write(ex / "numbers_only.csv", _csv([["ref"]] + [[g.non_id13()] for _ in range(300)]))
    unl = [[g.sa_id(), g.s(string.ascii_uppercase, 3) + g.s(string.digits, 4)] for _ in range(40)]
    _write(ex / "unlabelled.csv", _csv(unl))
    truth.append({"rule_id": "A3.data-copy", "root": "share01", "path": "Lab/Exports/unlabelled.csv", "severity": "high",
                  "details": {"id_assessment": "probable"}, "basis": "inference"})
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Claims"
    ws.append(["Member No", "Medical Aid", "ID Number", "Name", "Amount"])
    for _ in range(40):
        p = g.person()
        ws.append([g.s(string.digits, 9), g.rng.choice(["Scheme A", "Scheme B"]), p["id"], f"{p['first']} {p['last']}",
                   round(g.rng.uniform(100, 5000), 2)])
    buf = io.BytesIO()
    wb.save(buf)
    _write(base / "Finance" / "claims_2024.xlsx", buf.getvalue(), STALE)
    truth.append({"rule_id": "A3.data-copy", "root": "share01", "path": "Finance/claims_2024.xlsx", "severity": "high",
                  "details": {"id_assessment": "confirmed"}})
    feed = [{"id_number": (p := g.person())["id"], "surname": p["last"], "icd10": g.rng.choice(ICD)} for _ in range(25)]
    _write(base / "Reports" / "results_feed.json", json.dumps({"results": feed}, indent=1))
    truth.append({"rule_id": "A3.data-copy", "root": "share01", "path": "Reports/results_feed.json", "severity": "high"})
    _write(base / "Backups" / "LabDB_2025_06.bak", b"TAPE" + bytes(g.rng.randrange(256) for _ in range(65532)), STALE)
    _write(base / "Backups" / "pathdb_2025.dump", b"PGDMP\x01\x0f\x00\x04\x08\x01" + bytes(g.rng.randrange(256) for _ in range(30000)))
    truth += [{"rule_id": "A3.database-backup", "root": "share01", "path": "Backups/LabDB_2025_06.bak", "severity": "high"},
              {"rule_id": "A3.database-backup", "root": "share01", "path": "Backups/pathdb_2025.dump", "severity": "high"}]
    old = [["ID Number", "Surname", "First Name"]] + [[(p := g.person())["id"], p["last"], p["first"]] for _ in range(30)]
    _write(base / "Archive" / "old_extract.zip", _zip({"extract/patients_2023.csv": _csv(old).encode()}))
    truth.append({"rule_id": "A3.data-copy", "root": "share01", "path": "Archive/old_extract.zip",
                  "member": "extract/patients_2023.csv", "severity": "high"})
    deep = [["ID Number", "Surname"]] + [[(p := g.person())["id"], p["last"]] for _ in range(20)]
    lvl3 = _zip({"deep/patients.csv": _csv(deep).encode()})
    lvl2 = _zip({"level2.zip": lvl3})
    lvl1 = _zip({"level1.zip": lvl2})
    _write(base / "Archive" / "nested.zip", lvl1)
    _write(base / "Archive" / "bomb.zip", _zip({"zeros.csv": b"0" * (20 << 20)}))
    _write(base / "Archive" / "legacy_export.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(g.rng.randrange(256) for _ in range(4000)))
    truth.append({"rule_id": "A3.opaque-archive", "root": "share01", "path": "Archive/legacy_export.7z", "severity": "medium"})
    _write(base / "Malformed" / "broken.xlsx", b"PK\x03\x04" + bytes(g.rng.randrange(256) for _ in range(2000)))
    _write(base / "Malformed" / "broken.json", '{"records": [{"id_number": "x", ')
    big = base / "Large" / "huge_export.csv"
    big.parent.mkdir(parents=True, exist_ok=True)
    with open(big, "wb") as fh:
        fh.truncate(3 << 20)
    os.utime(big, (RECENT, RECENT))
    os.mkfifo(base / "Lab" / "pipe")
    decoy = (base / ".." / ".." / "outside" / "secret.config").resolve()
    (base / "link_to_decoy.config").symlink_to(decoy)


def _git_loose(content: bytes) -> tuple[str, bytes]:
    import hashlib

    raw = b"blob " + str(len(content)).encode() + b"\x00" + content
    sha = hashlib.sha1(raw).hexdigest()  # noqa: S324 - git object naming, not security
    return sha, zlib.compress(raw)


def _repo_root(base: Path, g: _Gen, truth: list) -> None:
    django = g.secret("django_secret_key", g.s(string.ascii_lowercase + string.digits + "!@#$%^&*(-_=+)", 50))
    _write(base / "app" / "settings.py", f"import os\nSECRET_KEY = '{django}'\nDEBUG = False\n"
                                         "DATABASES = {'default': {'PASSWORD': os.environ.get('DB_PASSWORD')}}\n")
    truth.append({"rule_id": "A1.generic-secret", "root": "repo01", "path": "app/settings.py", "severity": "medium"})
    _write(base / "deploy" / "id_ed25519", _pem(g))
    truth.append({"rule_id": "A1.private-key", "root": "repo01", "path": "deploy/id_ed25519", "severity": "high"})
    ps = g.password("deploy_ps_password")
    sqlcmd = g.password("deploy_sqlcmd_password")
    _write(base / "deploy" / "deploy.ps1", f'$pw = ConvertTo-SecureString "{ps}" -AsPlainText -Force\n'
                                           f"sqlcmd -S LABSQL01 -U svc_backup -P '{sqlcmd}' -Q \"BACKUP DATABASE LabDB TO DISK='D:\\b.bak'\"\n")
    truth += [{"rule_id": "A1.powershell-plaintext", "root": "repo01", "path": "deploy/deploy.ps1", "severity": "medium"},
              {"rule_id": "A1.cli-password", "root": "repo01", "path": "deploy/deploy.ps1", "severity": "high"}]
    tok = g.secret("git_remote_token", "ghp_" + g.s(string.ascii_letters + string.digits, 36))
    _write(base / ".git" / "config", f'[core]\n\tbare = false\n[remote "origin"]\n\turl = https://ci-bot:{tok}@git.hosp.example/lis/app.git\n')
    truth.append({"rule_id": "A1.github-token", "root": "repo01", "path": ".git/config", "severity": "medium"})
    akid = g.secret("aws_key_id", "AKIA" + g.s("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16))
    asec = g.secret("aws_secret", g.s(string.ascii_letters + string.digits + "/+", 40))
    sha, obj = _git_loose(f"[default]\naws_access_key_id = {akid}\naws_secret_access_key = {asec}\n".encode())
    _write(base / ".git" / "objects" / sha[:2] / sha[2:], obj)
    truth += [{"rule_id": "A1.aws-secret-key", "root": "repo01", "path": f".git/objects/{sha[:2]}/{sha[2:]}",
               "member": "blob", "severity": "high"},
              {"rule_id": "A1.aws-access-key-id", "root": "repo01", "path": f".git/objects/{sha[:2]}/{sha[2:]}",
               "member": "blob", "severity": "low"}]
    _write(base / ".git" / "objects" / "pack" / "pack-0001.pack", b"PACK\x00\x00\x00\x02" + bytes(64))
    tpw = g.password("repo_test_password")
    _write(base / "tests" / "test_settings.py", f"PASSWORD = '{tpw}'\n")


# ------------------------------------------------------------------------------------------ catalogues
def _mssql_catalog(fixed: bool) -> dict:
    sp = [("sa", "S", 0, "0x01"), ("lab_app", "S", 0, "0x10"), ("lab_reporting", "S", 0, "0x11"),
          ("etl_report", "S", 0, "0x12"), ("vendor_support", "S", 0, "0x13"), ("HOSP\\svc_backup", "U", 0, "0x14"),
          ("HOSP\\jdoe", "U", 0, "0x15"), ("HOSP\\mleft", "U", 0, "0x16"), ("HOSP\\olduser", "U", 0, "0x17"),
          ("HOSP\\tmokoena", "U", 0, "0x18"), ("HOSP\\reception", "U", 0, "0x19"), ("HOSP\\LabVendors", "G", 0, "0x1A"),
          ("sysadmin", "R", 0, None), ("securityadmin", "R", 0, None), ("bulkadmin", "R", 0, None), ("public", "R", 0, None)]
    q: dict = {
        "server_info": [{"product_version": "16.0.4305.5", "edition": "Developer Edition (64-bit)",
                         "integrated_security_only": 0, "server_name": "LABSQL01"}],
        "server_principals": [{"name": n, "type": t, "is_disabled": d, "sid": s} for n, t, d, s in sp],
        "sql_logins": [{"name": "sa", "is_policy_checked": 1, "is_expiration_checked": 1, "is_disabled": 0},
                       {"name": "lab_app", "is_policy_checked": 0, "is_expiration_checked": 0, "is_disabled": 0},
                       {"name": "lab_reporting", "is_policy_checked": 1, "is_expiration_checked": 0, "is_disabled": 0},
                       {"name": "etl_report", "is_policy_checked": 1, "is_expiration_checked": 0, "is_disabled": 0},
                       {"name": "vendor_support", "is_policy_checked": 1, "is_expiration_checked": 1, "is_disabled": 0}],
        "server_role_members": [{"role_name": "sysadmin", "member_name": m} for m in ("sa", "lab_app", "HOSP\\jdoe")]
                               + [{"role_name": "bulkadmin", "member_name": "etl_report"}],
        "server_permissions": [{"grantee": "HOSP\\svc_backup", "class_desc": "SERVER", "permission_name": "CONTROL SERVER",
                                "state_desc": "GRANT"}] + [{"grantee": n, "class_desc": "SERVER",
                                                            "permission_name": "CONNECT SQL", "state_desc": "GRANT"}
                                                           for n, t, _, _ in sp if t != "R"],
        "databases": [{"name": "master", "owner_login": "sa", "is_trustworthy_on": 1, "is_db_chaining_on": 1},
                      {"name": "LabDB", "owner_login": "sa", "is_trustworthy_on": 0 if fixed else 1, "is_db_chaining_on": 0}],
        "configurations": [{"name": "xp_cmdshell", "value_in_use": 0 if fixed else 1},
                           {"name": "clr enabled", "value_in_use": 0}, {"name": "clr strict security", "value_in_use": 1},
                           {"name": "Ole Automation Procedures", "value_in_use": 0},
                           {"name": "Ad Hoc Distributed Queries", "value_in_use": 0},
                           {"name": "cross db ownership chaining", "value_in_use": 0}],
        "linked_servers": [{"name": "FINSQL02", "product": "SQL Server", "provider": "SQLNCLI", "data_source": "FINSQL02",
                            "is_rpc_out_enabled": 1, "is_data_access_enabled": 1}],
        "linked_logins": [{"linked_server": "FINSQL02", "uses_self_credential": 0, "remote_name": "fin_link",
                           "local_principal": None}],
        "server_audits": [{"name": "HospitalAudit", "type_desc": "FILE", "on_failure_desc": "CONTINUE",
                           "is_state_enabled": 1}] if fixed else [],
        "server_audit_specifications": [{"specification": "Logins", "audit_name": "HospitalAudit", "is_state_enabled": 1,
                                         "audit_action_name": a} for a in ("FAILED_LOGIN_GROUP", "SUCCESSFUL_LOGIN_GROUP")]
        if fixed else [],
        "database_audit_specifications": [{"database_name": "LabDB", "specification": "PatientAccess",
                                           "is_state_enabled": 1, "audit_action_name": "SCHEMA_OBJECT_ACCESS_GROUP"}]
        if fixed else [],
        "credentials": [],
        "services": [{"servicename": "SQL Server (MSSQLSERVER)", "service_account": "LocalSystem", "status_desc": "Running"},
                     {"servicename": "SQL Server Agent (MSSQLSERVER)", "service_account": "NT Service\\SQLSERVERAGENT",
                      "status_desc": "Running"}],
    }
    users = [("dbo", "S", "INSTANCE", "sa", "0x01"), ("guest", "S", "NONE", None, "0x00"),
             ("lab_app", "S", "INSTANCE", "lab_app", "0x10"), ("lab_reporting", "S", "INSTANCE", "lab_reporting", "0x11"),
             ("etl_report", "S", "INSTANCE", "etl_report", "0x12"), ("vendor_support", "S", "INSTANCE", "vendor_support", "0x13"),
             ("HOSP\\mleft", "U", "WINDOWS", "HOSP\\mleft", "0x16"), ("HOSP\\olduser", "U", "WINDOWS", "HOSP\\olduser", "0x17"),
             ("HOSP\\tmokoena", "U", "WINDOWS", "HOSP\\tmokoena", "0x18"),
             ("HOSP\\reception", "U", "WINDOWS", "HOSP\\reception", "0x19"),
             ("HOSP\\LabVendors", "G", "WINDOWS", "HOSP\\LabVendors", "0x1A"), ("orphan_user", "S", "INSTANCE", None, "0x99")]
    q["database_principals"] = [{"database_name": "LabDB", "name": n, "type": t, "authentication_type_desc": a,
                                 "login_name": ln, "sid": s, "is_fixed_role": 0} for n, t, a, ln, s in users] + [
        {"database_name": "LabDB", "name": r, "type": "R", "authentication_type_desc": "NONE", "login_name": None,
         "sid": None, "is_fixed_role": 1 if r != "public" else 0}
        for r in ("db_owner", "db_datareader", "db_datawriter", "db_ddladmin", "public")]
    readers = ["lab_reporting", "etl_report", "vendor_support", "HOSP\\mleft", "HOSP\\olduser", "HOSP\\tmokoena",
               "HOSP\\reception", "HOSP\\LabVendors", "orphan_user"]
    writers = ["etl_report"] + ([] if fixed else ["vendor_support"])
    q["database_role_members"] = ([{"database_name": "LabDB", "role_name": "db_owner", "member_name": "lab_app"}]
                                  + [{"database_name": "LabDB", "role_name": "db_datareader", "member_name": m} for m in readers]
                                  + [{"database_name": "LabDB", "role_name": "db_datawriter", "member_name": m} for m in writers])
    perms = [{"database_name": "LabDB", "grantee": n, "class_desc": "DATABASE", "permission_name": "CONNECT",
              "state_desc": "GRANT", "schema_name": None, "object_name": None}
             for n, *_ in users if n not in ("dbo", "guest")]
    if not fixed:
        perms.append({"database_name": "LabDB", "grantee": "guest", "class_desc": "DATABASE", "permission_name": "CONNECT",
                      "state_desc": "GRANT", "schema_name": None, "object_name": None})
    perms.append({"database_name": "LabDB", "grantee": "public", "class_desc": "OBJECT_OR_COLUMN",
                  "permission_name": "SELECT", "state_desc": "GRANT", "schema_name": "dbo", "object_name": "Results"})
    perms.append({"database_name": "LabDB", "grantee": "public", "class_desc": "OBJECT_OR_COLUMN",
                  "permission_name": "SELECT", "state_desc": "GRANT", "schema_name": "sys", "object_name": "objects"})
    q["database_permissions"] = perms
    q["tables"] = [{"database_name": "LabDB", "schema_name": "dbo", "table_name": t, "row_estimate": n}
                   for t, n in (("Patients", 48211), ("Results", 912334), ("TestCatalog", 412))]
    q["columns"] = [{"database_name": "LabDB", "schema_name": "dbo", "table_name": t, "column_name": c}
                    for t, cs in (("Patients", ["PatientID", "IDNumber", "Surname", "FirstName", "DOB"]),
                                  ("Results", ["PatientID", "TestCode", "Result", "ICD10"]),
                                  ("TestCatalog", ["TestCode", "Description"])) for c in cs]
    return {"schema": "tripline.exposure-catalog/v1", "engine": "mssql", "server": "LABSQL01", "database": "LabDB",
            "queries": q, "errors": {}}


def _pg_catalog(d: Path) -> None:
    def w(name, rows):
        if not rows:
            return
        _write(d / f"{name}.csv", _csv([list(rows[0].keys())] + [["" if v is None else v for v in r.values()] for r in rows]))

    roles = [("postgres", "t", "t"), ("path_app", "t", "t"), ("path_report", "f", "t"), ("path_etl", "f", "t"),
             ("pg_execute_server_program", "f", "f"), ("pg_read_all_data", "f", "f")]
    w("roles", [{"rolname": n, "rolsuper": s, "rolinherit": "t", "rolcreaterole": "f", "rolcreatedb": "f",
                 "rolcanlogin": lg, "rolreplication": "f", "rolbypassrls": "f", "rolconnlimit": -1, "rolvaliduntil": None}
                for n, s, lg in roles])
    w("auth_members", [{"role_name": "pg_execute_server_program", "member_name": "path_etl", "admin_option": "false",
                        "inherit_option": "true"}])
    w("databases", [{"name": "pathdb", "owner": "postgres", "datallowconn": "t"}])
    tp = []
    for t in ("patients", "results"):
        for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            tp.append({"schema_name": "public", "table_name": t, "relkind": "r", "owner": "postgres", "grantee": "postgres",
                       "privilege_type": priv, "is_grantable": "YES"})
            tp.append({"schema_name": "public", "table_name": t, "relkind": "r", "owner": "postgres", "grantee": "path_app",
                       "privilege_type": priv, "is_grantable": "NO"})
        tp.append({"schema_name": "public", "table_name": t, "relkind": "r", "owner": "postgres", "grantee": "path_report",
                   "privilege_type": "SELECT", "is_grantable": "NO"})
    tp.append({"schema_name": "public", "table_name": "results", "relkind": "r", "owner": "postgres", "grantee": "PUBLIC",
               "privilege_type": "SELECT", "is_grantable": "NO"})
    tp.append({"schema_name": "public", "table_name": "lab_codes", "relkind": "r", "owner": "postgres", "grantee": "PUBLIC",
               "privilege_type": "SELECT", "is_grantable": "NO"})
    w("table_privileges", tp)
    w("schema_privileges", [{"schema_name": "public", "owner": "pg_database_owner", "grantee": "PUBLIC", "privilege_type": p}
                            for p in ("USAGE", "CREATE")])
    w("tables", [{"schema_name": "public", "table_name": t, "owner": "postgres", "row_estimate": n, "relrowsecurity": "f"}
                 for t, n in (("patients", 22100), ("results", 301000), ("lab_codes", 90))])
    w("columns", [{"schema_name": "public", "table_name": t, "column_name": c}
                  for t, cs in (("patients", ["id_number", "surname", "first_name", "dob"]),
                                ("results", ["patient_id", "icd10", "result"]),
                                ("lab_codes", ["code", "description"])) for c in cs])
    w("settings", [{"name": n, "setting": v, "source": "configuration file"} for n, v in
                   (("log_connections", "off"), ("log_statement", "none"), ("shared_preload_libraries", ""),
                    ("password_encryption", "scram-sha-256"), ("ssl", "on"), ("logging_collector", "on"))])
    w("extensions", [{"extname": e, "extversion": v} for e, v in (("plpgsql", "1.0"), ("dblink", "1.2"),
                                                                    ("postgres_fdw", "1.1"))])
    w("languages", [{"lanname": n, "lanpltrusted": t, "lanispl": p} for n, t, p in
                    (("internal", "f", "f"), ("c", "f", "f"), ("sql", "t", "f"), ("plpgsql", "t", "t"),
                     ("plpython3u", "f", "t"))])
    w("foreign_servers", [{"srvname": "fin_server", "fdwname": "postgres_fdw", "owner": "postgres",
                           "target": "host=finpg01,dbname=finance"}])
    w("user_mappings", [{"srvname": "fin_server", "usename": "path_app"}])
    w("server_info", [{"server_version": "16.4", "database_name": "pathdb"}])
    _write(d / "_meta.json", json.dumps({"schema": "tripline.exposure-catalog/v1", "engine": "postgres",
                                         "server": "PATHPG01", "database": "pathdb",
                                         "errors": {"hba_rules": "permission denied for view pg_hba_file_rules"}}))


# ------------------------------------------------------------------------------------------ identity
def _identity(d: Path, fixed: bool) -> None:
    dom, sx, ms, hb = "hosp.example", "supplierx.example", "medisoft.example", "healthbi.example"
    accts = [
        ("jdoe", dom, "true", "user", "Member", "Hospital", "SQL Admins", "2026-09-28", ""),
        ("mleft", dom, "false", "user", "Member", "Hospital", "Lab Staff", "2026-03-30", "2026-03-31"),
        ("svc_backup", dom, "true", "service", "Member", "Hospital", "Backup Operators", "2026-09-30", ""),
        ("tmokoena", dom, "true", "user", "Member", "Hospital", "Lab Staff", "2025-11-20", ""),
        ("reception", dom, "true", "shared", "Member", "Hospital", "Front Desk", "2026-09-29", ""),
        ("tech1", sx, "true", "user", "Guest", "SupplierX", "LabVendors", "2026-09-25", ""),
        ("tech2", sx, "true", "user", "Guest", "SupplierX", "LabVendors", "2026-02-10", ""),
        ("tech3", ms, "true", "user", "Guest", "MediSoft", "LabVendors", "2026-09-15", ""),
        ("ext_consult", hb, "true", "user", "Guest", "HealthBI", "", "2026-09-20", ""),
    ]
    _write(d / "directory.csv", _csv([["sAMAccountName", "userPrincipalName", "enabled", "accountType", "userType",
                                       "company", "groups", "lastLogon", "employmentEnd"]]
                                     + [[a, f"{a}@{dm}", e, t, ut, c, g, ll, end] for a, dm, e, t, ut, c, g, ll, end in accts]))
    rows = [["timestamp", "userPrincipalName", "appDisplayName", "authenticationRequirement", "status", "deviceId"]]

    def si(day, who, app, mfa, dev, status="success"):
        rows.append([f"{day}T08:{len(rows) % 60:02d}:00Z", who, app, mfa, status, dev])

    mf, sf = "multiFactorAuthentication", "singleFactorAuthentication"
    si("2026-04-01", f"jdoe@{dom}", "Azure Portal", mf, "dev-jd1")
    for m in range(4, 10):
        si(f"2026-{m:02d}-10", f"jdoe@{dom}", "Azure Portal", mf, "dev-jd1")
        si(f"2026-{m:02d}-12", f"tech1@{sx}", "LIS Portal", mf, "dev-t1")
        si(f"2026-{m:02d}-14", f"tech3@{ms}", "LIS Portal", sf, "dev-t3")
        si(f"2026-{m:02d}-15", f"ext_consult@{hb}", "LIS Portal", mf, "dev-ec")
    for i in range(6):
        si(f"2026-0{4 + i}-20", f"reception@{dom}", "LIS Portal", sf, f"ward-pc-{i}")
    si("2026-09-30", f"jdoe@{dom}", "Azure Portal", mf, "dev-jd1")
    _write(d / "signins.csv", _csv(rows))
    mfa = [["userPrincipalName", "isMfaRegistered", "methodsRegistered"], [f"jdoe@{dom}", "true", "authenticator"],
           [f"tech1@{sx}", "true", "authenticator"], [f"tech3@{ms}", "false", ""], [f"ext_consult@{hb}", "true", "fido2"],
           [f"svc_backup@{dom}", "", ""]]
    if fixed:
        mfa.append([f"tech2@{sx}", "true", "authenticator"])
    _write(d / "mfa.csv", _csv(mfa))
    _write(d / "suppliers.csv", _csv([
        ["supplier", "accounts", "contract_ref", "contract_end", "permitted_access", "permitted_assets", "mfa_required"],
        ["SupplierX", "tech1;tech2;vendor_support", "SX-2024-17", "2027-12-31", "read", "AST-LABDB", "true"],
        ["MediSoft", "tech3", "MS-2023-02", "2026-06-30", "read", "AST-LABDB", "true"]]))


ASSETS = [
    {"asset_id": "AST-WEB01", "kind": "host", "names": ["web01", "portal.hosp.example"], "owner": "Web team",
     "criticality": "medium"},
    {"asset_id": "AST-PROXY01", "kind": "host", "names": ["proxy01"], "owner": "Infrastructure", "criticality": "medium"},
    {"asset_id": "AST-FS01", "kind": "share", "names": ["share01", "fileserver01"], "owner": "Lab operations",
     "criticality": "medium"},
    {"asset_id": "AST-REPO-LIS", "kind": "application", "names": ["repo01"], "owner": "LIS development",
     "criticality": "medium"},
    {"asset_id": "AST-LABDB", "kind": "database", "names": ["LABSQL01", "LabDB"], "owner": "Lab systems team",
     "criticality": "high"},
    {"asset_id": "AST-PATHDB", "kind": "database", "names": ["PATHPG01", "pathdb"], "owner": "Pathology IT",
     "criticality": "high"},
    {"asset_id": "AST-LIS", "kind": "application", "names": ["LIS Portal", "lis.hosp.example"], "owner": "Lab systems team",
     "criticality": "high"},
    {"asset_id": "AST-FINSQL", "kind": "database", "names": ["FINSQL02"], "owner": "Finance IT", "criticality": "medium"},
    {"asset_id": "AST-ENTRA", "kind": "identity", "names": ["entra"], "owner": "Identity team", "criticality": "high"},
]


def manifest_doc(snapshot: str = "snapshot", budget: dict | None = None) -> dict:
    return {
        "schema": "tripline.exposure-manifest/v1",
        "scan_id": "SYNTH-EXPOSURE",
        "owner": "Synthetic Hospital IT Security",
        "legal_basis": "POPIA s19 security safeguards: authorised readiness assessment (synthetic)",
        "supplied_by": "Synthetic Hospital IT",
        "received_at": "2026-10-01T06:00:00Z",
        "snapshot_taken_at": AS_OF,
        "budget": budget or {"max_files": 5000, "max_total_bytes": "512MiB", "max_file_bytes": "2MiB",
                             "max_seconds": 600, "archive_max_depth": 2, "archive_max_members": 200,
                             "archive_max_ratio": 100, "archive_max_total_bytes": "64MiB"},
        "observation_window": {"start": "2026-04-01T00:00:00Z", "end": "2026-09-30T23:59:59Z"},
        "stale_after_days": 180,
        "hospital_domains": ["hosp.example"],
        "exclusions": ["**/node_modules/**"],
        "roots": [
            {"id": "web01", "path": f"{snapshot}/web01", "kind": "web_root", "asset": "AST-WEB01", "owner": "Web team"},
            {"id": "proxy01", "path": f"{snapshot}/proxy01", "kind": "config", "asset": "AST-PROXY01"},
            {"id": "share01", "path": f"{snapshot}/share01", "kind": "share", "asset": "AST-FS01", "owner": "Lab operations"},
            {"id": "repo01", "path": f"{snapshot}/repo01", "kind": "repository", "asset": "AST-REPO-LIS"},
        ],
        "databases": [
            {"id": "labdb", "engine": "mssql", "name": "LabDB", "server": "LABSQL01", "asset": "AST-LABDB",
             "patient_data": True, "export": "catalog/labdb_mssql.json", "owner": "Lab systems team"},
            {"id": "pathdb", "engine": "postgres", "name": "pathdb", "server": "PATHPG01", "asset": "AST-PATHDB",
             "patient_data": True, "export": "catalog/pathdb_pg"},
            {"id": "risdb", "engine": "oracle", "name": "RIS", "export": "catalog/ris_oracle.json"},
        ],
        "identity": {"directory_export": "identity/directory.csv", "signin_export": "identity/signins.csv",
                     "mfa_export": "identity/mfa.csv", "supplier_register": "identity/suppliers.csv",
                     "signin_coverage": {"start": "2026-04-01T00:00:00Z", "end": "2026-09-30T23:59:59Z"},
                     "asset": "AST-ENTRA"},
        "assets": "assets.yaml",
        "accepted_risks": "accepted_risks.yaml",
        "patient_data_assets": ["AST-LABDB", "AST-PATHDB", "AST-LIS"],
        "principals": [
            {"name": "lab_app", "database": "labdb", "type": "application", "function": "LIS application",
             "expected_access": "write"},
            {"name": "lab_reporting", "database": "labdb", "type": "application", "function": "Reporting service",
             "expected_access": "read"},
            {"name": "etl_report", "database": "labdb", "type": "service", "function": "Nightly reporting extract",
             "expected_access": "read"},
            {"name": "HOSP\\jdoe", "type": "dba", "function": "Database administrator"},
            {"name": "path_app", "database": "pathdb", "type": "application", "function": "Pathology application",
             "expected_access": "write"},
            {"name": "path_report", "database": "pathdb", "type": "application", "expected_access": "read"},
            {"name": "path_etl", "database": "pathdb", "type": "service", "expected_access": "read"},
        ],
    }


DB_TRUTH = [
    ("A2.app-admin-rights", "labdb", "lab_app", "critical"),
    ("A2.app-admin-rights", "labdb", "HOSP\\svc_backup", "critical"),
    ("A2.unjustified-write", "labdb", "etl_report", "high"),
    ("A2.obsolete-principal", "labdb", "HOSP\\mleft", "medium"),
    ("A2.obsolete-principal", "labdb", "HOSP\\olduser", "low"),
    ("A2.dormant-account", "labdb", "HOSP\\tmokoena", "medium"),
    ("A2.shared-identity", "labdb", "HOSP\\reception", "medium"),
    ("A2.orphaned-user", "labdb", "orphan_user", "low"),
    ("A2.app-admin-rights", "pathdb", "path_app", "high"),
    ("A4.mssql-xp-cmdshell", "labdb", None, "critical"),
    ("A4.mssql-linked-server", "labdb", None, "high"),
    ("A4.mssql-audit-disabled", "labdb", None, "high"),
    ("A4.mssql-guest-enabled", "labdb", None, "high"),
    ("A4.mssql-public-grant", "labdb", None, "high"),
    ("A4.mssql-trustworthy", "labdb", None, "high"),
    ("A4.mssql-sa-enabled", "labdb", "sa", "medium"),
    ("A4.mssql-service-account", "labdb", None, "medium"),
    ("A4.mssql-excess-capability", "labdb", "etl_report", "low"),
    ("A4.pg-copy-program", "pathdb", "path_app", "high"),
    ("A4.pg-copy-program", "pathdb", "path_etl", "high"),
    ("A4.pg-untrusted-language", "pathdb", None, "medium"),
    ("A4.pg-audit-disabled", "pathdb", None, "high"),
    ("A4.pg-foreign-server", "pathdb", None, "medium"),
    ("A4.pg-dblink", "pathdb", None, "low"),
    ("A4.pg-public-schema-create", "pathdb", None, "medium"),
    ("A4.pg-public-table-grant", "pathdb", None, "high"),
    ("A5.supplier-mfa-missing", None, "tech3", "critical"),
    ("A5.supplier-contract-expired", None, "tech3", "high"),
    ("A5.supplier-mfa-unknown", None, "tech2", "medium"),
    ("A5.supplier-inactive", None, "tech2", "medium"),
    ("A5.supplier-mfa-missing", None, "vendor_support", "high"),
    ("A5.supplier-excess-privilege", None, "vendor_support", "high"),
    ("A5.supplier-no-contract", None, "ext_consult", "medium"),
]
FIXED_DB = {("A4.mssql-xp-cmdshell", "labdb", None), ("A4.mssql-audit-disabled", "labdb", None),
            ("A4.mssql-guest-enabled", "labdb", None), ("A4.mssql-trustworthy", "labdb", None),
            ("A5.supplier-mfa-unknown", None, "tech2"), ("A5.supplier-excess-privilege", None, "vendor_support")}
ABSENT = [  # least-privilege and evidence-gap cases that must NOT produce these findings
    ("A2", "labdb", "lab_reporting"), ("A2", "pathdb", "path_report"), ("A5", None, "tech1"),
    ("A2.dormant-account", "labdb", "HOSP\\svc_backup"), ("A2", "labdb", "HOSP\\jdoe"),
]


def build(out: Path | str, variant: str = "baseline", seed: int = 20261001) -> dict:
    """Write the synthetic input set under ``out`` and return the ground truth (also saved as ground_truth.json)."""
    if variant not in ("baseline", "fixed"):
        raise ValueError("variant must be baseline or fixed")
    out = Path(out)
    fixed = variant == "fixed"
    g = _Gen(seed)
    truth: list[dict] = []
    snap = out / "snapshot"
    (out / "outside").mkdir(parents=True, exist_ok=True)
    decoy = g.password("decoy_outside_secret")
    _write(out / "outside" / "secret.config", f'<add key="DbPassword" value="{decoy}" />\n')
    _web_root(snap / "web01", g, fixed, truth)
    _proxy_root(snap / "proxy01", g, truth)
    _share_root(snap / "share01", g, fixed, truth)
    _repo_root(snap / "repo01", g, truth)
    cat = out / "catalog"
    _write(cat / "labdb_mssql.json", json.dumps(_mssql_catalog(fixed), indent=1))
    _pg_catalog(cat / "pathdb_pg")
    _write(cat / "ris_oracle.json", json.dumps({"schema": "tripline.exposure-catalog/v1", "engine": "oracle",
                                                "queries": {"dba_users": [{"username": "RIS_APP"}]}}))
    _identity(out / "identity", fixed)
    _write(out / "assets.yaml", yaml.safe_dump({"assets": ASSETS}, sort_keys=False))
    _write(out / "accepted_risks.yaml", yaml.safe_dump({"accepted_risks": []}))
    _write(out / "manifest.yaml", yaml.safe_dump(manifest_doc(), sort_keys=False))
    db_truth = []
    for rule, db, principal, sev in DB_TRUTH:
        if fixed and (rule, db, principal) in FIXED_DB:
            continue
        db_truth.append({"rule_id": rule, "database": db, "principal": principal, "severity": sev,
                         "fixed_in_variant": (rule, db, principal) in FIXED_DB})
    gt = {"variant": variant, "seed": seed, "secrets": g.secrets, "sa_ids": g.ids, "file_findings": truth,
          "db_findings": db_truth, "absent": ABSENT, "decoy_dir": str((out / "outside").resolve()),
          "excluded_dir": str((snap / "web01" / "wwwroot" / "node_modules").resolve())}
    _write(out / "ground_truth.json", json.dumps(gt, indent=1))
    return gt


def build_scale_tree(out: Path | str, n_files: int = 20000, seed: int = 7) -> Path:
    """A large synthetic tree (mostly benign config/text/CSV files, a few seeded secrets and exports) plus a
    manifest scanning it. Returns the manifest path."""
    out = Path(out)
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic fixtures by design
    root = out / "snapshot" / "bigshare"
    per_dir = 200
    for i in range(n_files):
        d = root / f"dept{i // (per_dir * 20):02d}" / f"dir{(i // per_dir) % 20:02d}"
        kind = i % 10
        if i % 997 == 0:
            name, body = f"app{i}.config", f'<add key="DbPassword" value="Sc4le-{rng.getrandbits(48):x}!" />\n'
        elif i % 1499 == 0:
            rows = [["ID Number", "Surname"]] + [[make_sa_id(dt.date(1980, 1, 1) + dt.timedelta(days=rng.randrange(9000)),
                                                             rng.randrange(10000)), rng.choice(LAST)] for _ in range(25)]
            name, body = f"extract{i}.csv", _csv(rows)
        elif kind < 4:
            name, body = f"settings{i}.ini", "\n".join(f"key{k}=value{rng.randrange(1000)}" for k in range(20)) + "\n"
        elif kind < 7:
            name, body = f"notes{i}.txt", " ".join(rng.choice(LAST) for _ in range(60)) + "\n"
        elif kind < 9:
            name, body = f"data{i}.csv", _csv([["code", "count"]] + [[f"C{rng.randrange(999)}", rng.randrange(100)]
                                                                      for _ in range(30)])
        else:
            name, body = f"bundle{i}.js", "var a=" + json.dumps({f"k{k}": rng.randrange(9999) for k in range(80)}) + ";\n"
        _write(d / name, body)
    doc = manifest_doc(budget={"max_files": n_files + 100, "max_total_bytes": "4GiB", "max_file_bytes": "8MiB",
                               "max_seconds": 3600})
    doc.update({"scan_id": "SYNTH-SCALE", "roots": [{"id": "bigshare", "path": "snapshot/bigshare", "kind": "share"}],
                "databases": [], "identity": {}, "principals": [], "assets": None, "accepted_risks": None,
                "patient_data_assets": []})
    doc = {k: v for k, v in doc.items() if v not in (None, {}, [])}
    doc["budget"] = {"max_files": n_files + 100, "max_total_bytes": "4GiB", "max_file_bytes": "8MiB", "max_seconds": 3600}
    _write(out / "manifest.yaml", yaml.safe_dump(doc, sort_keys=False))
    return out / "manifest.yaml"
