"""Parser and normalisation unit tests for documented format variants."""

import datetime as dt
import io
import json

import pytest

from tripline_scope.core.errors import ConfigError
from tripline_scope.paths.ingest import event_consequence
from tripline_scope.paths.parsers import entra, generic, indicators, mssql, postgres, web, windows
from tripline_scope.paths.parsers.base import ParseContext, safe_url_path
from tripline_scope.paths.sqlops import classify
from tripline_scope.paths.timenorm import ZoneSpec, normalise, parse_iso


def ctx(family, fmt, options=None, mapping=None):
    return ParseContext(source_id="SRC-T", family=family, fmt=fmt, host="H1", options=options or {}, mapping=mapping,
                        sql_fp=lambda s: "fp" + str(len(s)), file_fp=lambda s: "f" * 16)


def run(mod, c, text, name="f.log"):
    return list(mod.parse(c, io.BytesIO(text.encode() if isinstance(text, str) else text), name))


def test_sql_classifier_cases():
    cases = {
        "SELECT * FROM dbo.Patients p JOIN dbo.Results r ON 1=1": ("select", ["dbo.Patients", "dbo.Results"]),
        "BACKUP DATABASE [LabDB] TO DISK = N'x.bak'": ("dump_export", ["LabDB"]),
        "COPY public.results TO STDOUT": ("dump_export", ["public.results"]),
        "COPY public.results FROM STDIN": ("bulk_import", ["public.results"]),
        "SELECT * INTO dbo.stage FROM dbo.Patients": ("select_into", ["dbo.stage", "dbo.Patients"]),
        "ALTER SERVER AUDIT a WITH (STATE = OFF)": ("auditing_disabled", []),
        "ALTER SYSTEM SET pgaudit.log = 'none'": ("auditing_disabled", []),
        "GRANT SELECT ON dbo.Patients TO x": ("privilege_change", ["dbo.Patients"]),
        "EXEC xp_cmdshell 'bcp LabDB.dbo.Billing out c:\\b.csv -T'": ("dump_export", ["LabDB.dbo.Billing"]),
    }
    for sql, (obs, objs) in cases.items():
        info = classify(sql)
        assert info.observation_type == obs, sql
        assert info.objects == objs, sql
    info = classify("SELECT name FROM patients WHERE sa_id = '8001015009087'")
    assert "8001015009087" not in info.normalised and "?" in info.normalised
    assert classify("not sql at all ((( '").operation in ("not", "unparsed", "unknown")


def test_event_consequence_rule():
    assert event_consequence("select", ["t"], "success") == "access_observed"
    assert event_consequence("select", ["t"], "failure") == "not_applicable"      # denied query: no access
    assert event_consequence("select", [], "success") == "not_applicable"
    assert event_consequence("dump_export", [], "success") == "export_or_staging_observed"
    assert event_consequence("auditing_disabled", [], "success") == "undetermined"
    assert event_consequence("sign_in", [], "success") == "not_applicable"


def test_time_rules():
    utc = ZoneSpec("Z", "format")
    v, p, abbr = parse_iso("2026-09-03 23:12:04.1234567")
    r = normalise(v, p, utc)
    assert r.tz_original == "Z" and r.tz_basis == "format" and r.precision == "millisecond"
    jhb = ZoneSpec("Africa/Johannesburg", "manifest", clock_offset_s=30, clock_uncertainty_s=5)
    v, p, _ = parse_iso("2026-09-04 01:00:00")
    r = normalise(v, p, jhb)
    assert r.ts_utc == dt.datetime(2026, 9, 3, 22, 59, 30, tzinfo=dt.UTC)
    assert r.ts_max - r.ts_min == dt.timedelta(seconds=11)
    unk = normalise(*parse_iso("2026-09-04 01:00:00")[:2], ZoneSpec())
    assert unk.ts_utc is None and unk.tz_original == "unknown"
    assert unk.ts_max - unk.ts_min >= dt.timedelta(hours=26)
    # DST fold: both candidate instants kept in the bounds
    ldn = ZoneSpec("Europe/London", "manifest")
    r = normalise(*parse_iso("2026-10-25 01:30:00")[:2], ldn)
    assert "dst_ambiguous" in r.flags and r.ts_max - r.ts_min >= dt.timedelta(hours=1)
    v, p, abbr = parse_iso("2026-09-03 01:15:00.123 SAST")
    assert normalise(v, p, ZoneSpec(), record_abbrev=abbr).tz_original == "+02:00"
    v, p, abbr = parse_iso("2026-09-03 01:15:00 XYZT")
    r = normalise(v, p, ZoneSpec(), record_abbrev=abbr)
    assert r.ts_utc is None and "tz_abbreviation_unrecognised" in r.flags
    with pytest.raises(ConfigError):
        ZoneSpec("Mars/Olympus", "manifest")


def test_url_paths_are_reduced():
    assert safe_url_path("/portal/results/8001015009087/pdf?token=abc") == ("/portal/results/{n}/pdf", True)
    assert safe_url_path("/u/jane@example.com/x")[0] == "/u/{email}/x"
    assert safe_url_path("https://h.example/a;jsessionid=XYZ/b")[0] == "/a/b"


def test_pg_csvlog_and_jsonlog():
    row = ['2026-09-03 01:15:00.123 SAST', 'alice', 'lis', '4242', '10.0.0.9:51000', '64f1.1092', '3', 'SELECT',
           '2026-09-03 01:14:00 SAST', '3/5', '0', 'LOG', '00000',
           'AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.patient_index,"select * from patient_index where x=\'1\'",<not logged>',
           '', '', '', '', '', '', '', '', 'psql', 'client backend']
    buf = io.StringIO()
    import csv

    csv.writer(buf).writerow(row)
    recs = run(postgres, ctx("pgaudit", "csvlog"), buf.getvalue())
    assert recs[0]["observation_type"] == "select" and recs[0]["objects"] == ["lis.public.patient_index"]
    assert recs[0]["session_id"] == "64f1.1092" and recs[0]["remote_ip"] == "10.0.0.9"
    j = {"timestamp": "2026-09-03 01:15:00.123 UTC", "user": "bob", "dbname": "lis", "pid": 1, "remote_host": "10.0.0.8",
         "session_id": "a.b", "error_severity": "LOG", "message": "statement: COPY public.specimens TO stdout",
         "application_name": "pg_dump"}
    recs = run(postgres, ctx("pg_log", "jsonlog"), json.dumps(j) + "\nnot json\n")
    assert recs[0]["observation_type"] == "dump_export" and recs[0]["objects"] == ["lis.public.specimens"]
    c = ctx("pg_log", "stderr", {"log_line_prefix": "%t [%p]: user=%u,db=%d,app=%a,client=%h "})
    line = "2026-09-03 01:15:00 UTC [77]: user=carol,db=lis,app=psql,client=10.1.1.1 LOG:  statement: SELECT * FROM public.x\n"
    recs = run(postgres, c, line + "\tcontinued line\n")
    assert recs[0]["account"] == "carol" and recs[0]["remote_ip"] == "10.1.1.1" and recs[0]["objects"] == ["lis.public.x"]
    recs = run(postgres, ctx("pg_log", "stderr", {"log_line_prefix": "%m [%p] "}),
               '2026-09-03 01:15:00.000 UTC [9] LOG:  parameter "pgaudit.log" changed to "none"\n')
    assert recs[0]["observation_type"] == "auditing_disabled"


def test_apache_nginx_formats():
    line = '203.0.113.9 - jdoe [10/Sep/2026:13:55:36 +0200] "POST /admin/upload.php?x=1 HTTP/1.1" 200 2326 "-" "UA"\n'
    r = run(web, ctx("apache", "combined"), line)[0]
    assert r["url_path"] == "/admin/upload.php" and "query_stripped" in r["flags"] and r["method"] == "POST"
    assert r["_ts"][0].utcoffset() == dt.timedelta(hours=2)
    c = ctx("nginx", "custom", {"log_format": '$remote_addr [$time_iso8601] "$request" $status $bytes_sent $request_id'})
    r = run(web, c, '198.51.100.2 [2026-09-10T11:55:36+00:00] "GET /a HTTP/1.1" 404 10 abc123\n')[0]
    assert r["request_id"] == "abc123" and r["http_status"] == 404 and r["outcome"] == "failure"
    c = ctx("apache", "custom", {"log_format": '%h %u %t "%r" %>s %b %{X-Request-ID}i'})
    r = run(web, c, '10.0.0.1 - [10/Sep/2026:13:55:36 +0000] "GET /x HTTP/1.1" 200 5 rid-9\n')[0]
    assert r["request_id"] == "rid-9"
    bad = ctx("apache", "combined")
    assert run(web, bad, "garbage line\n") == [] and bad.failures == 1


def test_windows_xml_csv_and_dtd_refusal():
    ev = ("<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID>"
          "<TimeCreated SystemTime='2026-09-03T23:10:00.0000000Z'/><EventRecordID>5</EventRecordID>"
          "<Computer>SRV.lab.example</Computer></System><EventData><Data Name='TargetUserName'>u1</Data>"
          "<Data Name='TargetDomainName'>LAB</Data><Data Name='TargetLogonId'>0x1A2B</Data>"
          "<Data Name='LogonType'>10</Data><Data Name='IpAddress'>::ffff:10.8.0.5</Data>"
          "<Data Name='CommandLine'>secret-cmd</Data></EventData></Event></Events>")
    r = run(windows, ctx("win_security", "xml"), ev)[0]
    assert r["account"] == "LAB\\u1" and r["logon_id"] == "0x1a2b" and r["remote_ip"] == "10.8.0.5"
    assert "secret-cmd" not in json.dumps({k: v for k, v in r.items() if not k.startswith("_")})
    c = ctx("win_security", "xml")
    assert run(windows, c, '<!DOCTYPE x [<!ENTITY a "b">]><Events/>') == [] and c.failures == 1
    csv_text = ("TimeCreated,EventID,Computer,RecordId,SubjectUserName,SubjectDomainName,SubjectLogonId,ObjectType,"
                "ObjectName,AccessMask,ProcessName\n2026-09-03T23:31:00Z,4663,SRV,9,svc,LAB,0x3e7,File,"
                "D:\\out\\Jane Doe results.csv,0x2,C:\\x\\bcp.exe\n")
    r = run(windows, ctx("win_security", "csv"), csv_text)[0]
    assert r["observation_type"] == "file_write" and r["object_name"].startswith("file:csv:")
    assert "Jane" not in r["object_name"] and r["application"] == "bcp.exe"


def test_mssql_jsonl_and_failed_select():
    rows = [{"event_time": "2026-09-03 23:12:30.1234567", "action_id": "SL", "succeeded": False, "session_id": 61,
             "server_principal_name": "LAB\\x", "database_name": "LabDB", "schema_name": "dbo", "object_name": "patients",
             "statement": "SELECT * FROM dbo.patients", "client_ip": "10.0.0.1"},
            {"event_time": "2026-09-03 23:12:31", "action_id": "LGIS", "session_id": 62,
             "server_principal_name": "LAB\\y", "connection_id": "6F9619FF-8B86-D011-B42D-00C04FC964FF"}]
    recs = run(mssql, ctx("mssql_audit", "jsonl"), "\n".join(json.dumps(r) for r in rows))
    assert recs[0]["outcome"] == "failure" and recs[0]["objects"] == ["LabDB.dbo.patients"]
    assert recs[1]["session_id"].startswith("conn:") and recs[1]["observation_type"] == "login_success"


def test_entra_csv_with_mfa_and_generic_kv_json():
    text = ("Date (UTC),Request ID,Username,User,IP address,Location,Status,Authentication requirement,"
            "Multifactor authentication result\n2026-09-03 23:05:00,rid1,a@lab.example,A Person,1.2.3.4,"
            "\"Paris, FR\",Success,Multifactor authentication,MFA requirement satisfied by claim in the token\n")
    r = run(entra, ctx("entra_signin", "csv"), text)[0]
    assert r["mfa"] == "true" and r["account"] == "a@lab.example" and "A Person" not in json.dumps({k: v for k, v in r.items() if not k.startswith("_")})
    m = {"timestamp_format": "epoch_ms", "fields": {"ts": "t", "remote_ip": "src", "dest_ip": "dst", "bytes": "out",
                                                    "url": "u"}}
    r = run(generic, ctx("proxy", "kv", mapping=m), 't=1788566400000 src=10.0.0.1 dst=8.8.8.8 out=99 u="https://x.example/p?k=s"\n')[0]
    assert r["domain"] == "x.example" and r["url_path"] == "/p" and "query_stripped" in r["flags"]
    assert r["observation_type"] == "proxy_request"
    m2 = {"fields": {"ts": "when", "account": "who.name", "operation": "what"}, "observation_map": {"x": "other"}}
    r = run(generic, ctx("vpn", "json", mapping=m2), json.dumps([{"when": "2026-09-01T00:00:00Z", "who": {"name": "u"},
                                                                     "what": "Login"}]))[0]
    assert r["account"] == "u" and r["observation_type"] == "vpn_connect"
    with pytest.raises(ConfigError):
        generic.validate_mapping({"fields": {"ts": "a", "password": "p"}})


def test_indicators_require_provenance_and_valid_values():
    doc = {"indicators": [
        {"type": "ip", "value": "203.0.113.5", "provenance": "partner X report 7", "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "domain", "value": "Evil.Example.", "provenance": "partner X"},
        {"type": "sha256", "value": "ab" * 32, "provenance": "partner X"},
        {"type": "ip", "value": "203.0.113.6"},
        {"type": "ip", "value": "not-an-ip", "provenance": "p"},
        {"type": "cidr", "value": "10.0.0.0/8", "provenance": "p", "valid_from": "2026-02-01T00:00:00Z",
         "valid_to": "2026-01-01T00:00:00Z"}]}
    c = ctx("indicators", "json")
    out = indicators.parse(c, io.BytesIO(json.dumps(doc).encode()), "i.json")
    assert [i["value"] for i in out] == ["203.0.113.5", "evil.example", "ab" * 32]
    assert "open_validity" in out[1]["flags"]
    assert sorted(r["reason"] for r in c.rejected) == ["invalid ip value", "no provenance", "valid_to before valid_from"]
