"""A2/A4 catalogue analysis and A2/A5 identity checks on small hand-built exports."""

import json

import yaml

from tripline_scope.core.crypto import Fingerprinter
from tripline_scope.exposure.catalog import analyse_database, catalog_from_doc, load_catalog
from tripline_scope.exposure.coverage import Recorder
from tripline_scope.exposure.identity import Identity, analyse_identity
from tripline_scope.exposure.manifest import load_manifest
from tripline_scope.exposure.model import Keys
from tripline_scope.exposure.state import ScanState


class _Store:
    def fingerprinter(self, purpose):
        return Fingerprinter(b"k" * 32, purpose)


def _state(tmp_path, *, window=True, identity=None, principals=None, engine="mssql"):
    (tmp_path / "cat.json").write_text("{}")
    doc = {"schema": "tripline.exposure-manifest/v1", "owner": "IT", "legal_basis": "test",
           "received_at": "2026-10-01T00:00:00Z", "budget": {},
           "databases": [{"id": "db1", "engine": engine, "name": "LabDB", "patient_data": True, "export": "cat.json"}],
           "principals": principals or []}
    if window:
        doc["observation_window"] = {"start": "2026-04-01T00:00:00Z", "end": "2026-09-30T23:59:59Z"}
    if identity:
        doc["identity"] = {}
        for k, (name, text) in identity.items():
            (tmp_path / name).write_text(text)
            doc["identity"][k] = name
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(doc))
    m = load_manifest(tmp_path / "m.yaml")
    st = ScanState(m, Keys(_Store()), Recorder())
    ident = Identity(st)
    ident.load()
    return st, m.databases[0], ident


def _mssql(**q):
    base = {"server_principals": [], "database_principals": [], "database_role_members": [], "database_permissions": [],
            "server_role_members": []}
    base.update(q)
    return catalog_from_doc({"engine": "mssql", "queries": base})


def _rules(st):
    return sorted((f.rule_id, f.location.get("principal")) for f in st.findings.values())


def test_nested_roles_deny_and_least_privilege(tmp_path):
    st, db, ident = _state(tmp_path, principals=[
        {"name": "report_svc", "type": "service", "expected_access": "read"},
        {"name": "lis_app", "type": "application", "expected_access": "write"},
        {"name": "ro_app", "type": "application", "expected_access": "read"}])
    sp = [{"name": n, "type": "S", "is_disabled": 0, "sid": s} for n, s in (("report_svc", "0x1"), ("lis_app", "0x2"),
                                                                           ("ro_app", "0x3"))]
    dp = [{"name": n, "type": "S", "authentication_type_desc": "INSTANCE", "login_name": n} for n in
          ("report_svc", "lis_app", "ro_app")] + [{"name": r, "type": "R"} for r in ("app_role", "db_owner", "db_datawriter")]
    rm = [{"role_name": "app_role", "member_name": "lis_app"}, {"role_name": "db_owner", "member_name": "app_role"},
          {"role_name": "db_datawriter", "member_name": "report_svc"}]
    perms = [{"grantee": "ro_app", "class_desc": "DATABASE", "permission_name": "SELECT", "state_desc": "GRANT"},
             {"grantee": "ro_app", "class_desc": "DATABASE", "permission_name": "INSERT", "state_desc": "GRANT"},
             {"grantee": "ro_app", "class_desc": "DATABASE", "permission_name": "INSERT", "state_desc": "DENY"}]
    analyse_database(st, db, _mssql(server_principals=sp, database_principals=dp, database_role_members=rm,
                                    database_permissions=perms), ident)
    r = _rules(st)
    assert ("A2.app-admin-rights", "lis_app") in r          # db_owner reached through a nested role
    assert ("A2.unjustified-write", "report_svc") in r      # write beyond declared read
    assert not any(p == "ro_app" for _, p in r)              # DENY removes the INSERT grant: least privilege
    lis = next(f for f in st.findings.values() if f.location.get("principal") == "lis_app")
    assert lis.basis == "observation" and "member of db_owner" in lis.details["derived_via"]


def test_missing_role_membership_is_labelled_uncertain(tmp_path):
    st, db, ident = _state(tmp_path, principals=[{"name": "lis_app", "type": "application", "expected_access": "write"}])
    cat = catalog_from_doc({"engine": "mssql", "queries": {
        "server_principals": [{"name": "lis_app", "type": "S", "is_disabled": 0}],
        "database_principals": [{"name": "lis_app", "type": "S", "authentication_type_desc": "INSTANCE",
                                 "login_name": "lis_app"}],
        "database_permissions": [{"grantee": "lis_app", "class_desc": "DATABASE", "permission_name": "CONTROL",
                                  "state_desc": "GRANT"}]}})
    analyse_database(st, db, cat, ident)
    f = next(iter(st.findings.values()))
    assert f.rule_id == "A2.app-admin-rights" and f.confidence < 0.9
    assert any("role membership was not in the catalogue export" in c for c in f.caveats)
    assert any(u["unit"] == "db:db1:role_membership" for u in st.rec.unavailable)


def test_unsupported_engine_option_and_inaccessible_query(tmp_path):
    st, db, ident = _state(tmp_path, engine="oracle")
    analyse_database(st, db, None, ident)
    assert {x["controls"][0] for x in st.rec.not_assessed} == {"A2", "A4"}
    assert not st.findings
    st, db, ident = _state(tmp_path)
    cat = _mssql(configurations=[{"name": "xp_cmdshell", "value_in_use": "maybe"}])
    cat.errors["server_audits"] = "permission denied"
    analyse_database(st, db, cat, ident)
    na = {x["unit"]: x["reason"] for x in st.rec.not_assessed}
    un = {x["unit"]: x["reason"] for x in st.rec.unavailable}
    assert "unrecognised value" in na["db:db1:xp_cmdshell"]          # never invented
    assert "db:db1:linked_servers" in na                              # query not exported
    assert "permission denied" in un["db:db1:audit"]                  # inaccessible object
    assert not any(f.rule_id.startswith("A4.mssql-xp") for f in st.findings.values())


def test_malformed_catalogue_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    try:
        load_catalog(p, 1 << 20)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed export accepted")
    d = tmp_path / "csvdir"
    d.mkdir()
    (d / "roles.csv").write_text("rolname,rolsuper,rolcanlogin\napp,t,t\n")
    (d / "_meta.json").write_text(json.dumps({"engine": "postgres"}))
    assert load_catalog(d, 1 << 20).rows("roles")[0]["rolsuper"] == "t"


def test_postgres_inheritance_and_copy_program(tmp_path):
    st, db, ident = _state(tmp_path, engine="postgres", principals=[{"name": "etl", "type": "service",
                                                                      "expected_access": "read"}])
    cat = catalog_from_doc({"engine": "postgres", "queries": {
        "roles": [{"rolname": "etl", "rolsuper": "f", "rolinherit": "f", "rolcanlogin": "t"},
                  {"rolname": "writers", "rolsuper": "f", "rolinherit": "t", "rolcanlogin": "f"},
                  {"rolname": "pg_execute_server_program", "rolsuper": "f", "rolcanlogin": "f"}],
        "auth_members": [{"role_name": "writers", "member_name": "etl", "inherit_option": "true"},
                         {"role_name": "pg_execute_server_program", "member_name": "etl", "inherit_option": "false"}],
        "table_privileges": [{"schema_name": "public", "table_name": "patients", "grantee": "writers",
                              "privilege_type": "INSERT", "owner": "postgres"}],
        "columns": [{"schema_name": "public", "table_name": "patients", "column_name": "surname"}]}})
    analyse_database(st, db, cat, ident)
    r = _rules(st)
    assert ("A2.unjustified-write", "etl") in r and ("A4.pg-copy-program", "etl") in r


DIRECTORY = ("sAMAccountName,userPrincipalName,enabled,accountType,userType,company,groups,lastLogon\n"
             "jsmith,jsmith@hosp.example,true,user,Member,Hospital,Lab,2025-12-01\n"
             "vend1,vend1@vendor.example,true,user,Guest,VendorCo,,2026-09-01\n"
             "vend2,vend2@vendor.example,true,user,Guest,VendorCo,,\n")
SIGNINS = ("timestamp,userPrincipalName,appDisplayName,authenticationRequirement,status\n"
           "2026-04-01T08:00:00Z,vend1@vendor.example,LIS,singleFactorAuthentication,success\n"
           "2026-09-30T08:00:00Z,other@hosp.example,LIS,multiFactorAuthentication,success\n")


def _rights(st, *names, level="read"):
    for n in names:
        st.principal_rights.append({"database": "db1", "asset_id": None, "patient": True, "principal": n, "key": n,
                                    "ptype": "supplier" if "vend" in n else "human", "level": level, "via": ["x"],
                                    "basis": "observation", "uncertain": [], "enabled": True, "via_group": None,
                                    "login_type": "U", "has_login": True, "capabilities": [], "unit": "db:db1:principals"})


def test_dormancy_unknown_without_window(tmp_path):
    st, db, ident = _state(tmp_path, window=False, identity={"directory_export": ("d.csv", DIRECTORY),
                                                             "signin_export": ("s.csv", SIGNINS)})
    _rights(st, "jsmith")
    analyse_identity(st, ident)
    assert not any(f.rule_id == "A2.dormant-account" for f in st.findings.values())
    assert any("no observation window" in x["reason"] for x in st.rec.not_assessed)


def test_dormancy_observed_with_window_and_coverage(tmp_path):
    st, db, ident = _state(tmp_path, identity={"directory_export": ("d.csv", DIRECTORY), "signin_export": ("s.csv", SIGNINS)})
    _rights(st, "jsmith")
    analyse_identity(st, ident)
    f = [f for f in st.findings.values() if f.rule_id == "A2.dormant-account"]
    assert f and f[0].basis == "observation"


def test_dormancy_unknown_when_signins_do_not_cover_window(tmp_path):
    short = SIGNINS.splitlines()[0] + "\n2026-09-01T08:00:00Z,other@hosp.example,LIS,mfa,success\n"
    st, db, ident = _state(tmp_path, identity={"directory_export": ("d.csv", DIRECTORY), "signin_export": ("s.csv", short)})
    _rights(st, "jsmith")
    analyse_identity(st, ident)
    assert not any(f.rule_id == "A2.dormant-account" for f in st.findings.values())
    assert any("not the whole observation window" in x["reason"] for x in st.rec.not_assessed)


def test_supplier_mfa_unknown_not_disabled(tmp_path):
    mfa = "userPrincipalName,isMfaRegistered\nsomeone@hosp.example,true\n"
    st, db, ident = _state(tmp_path, identity={"directory_export": ("d.csv", DIRECTORY), "mfa_export": ("m.csv", mfa)})
    _rights(st, "vend1", "vend2")
    analyse_identity(st, ident)
    f = {x.rule_id: x for x in st.findings.values() if x.location["principal"] == "vend1"}
    assert "A5.supplier-mfa-unknown" in f and "A5.supplier-mfa-missing" not in f
    assert f["A5.supplier-mfa-unknown"].details["mfa"] == "unknown" and f["A5.supplier-mfa-unknown"].basis == "unknown"
    assert f["A5.supplier-no-contract"].details["contract"] == "unknown"
    assert f["A5.supplier-mfa-unknown"].details["activity"] == "active"    # directory last-logon inside the window
    v2 = {x.rule_id: x for x in st.findings.values() if x.location["principal"] == "vend2"}
    assert v2["A5.supplier-mfa-unknown"].details["activity"] == "unknown"  # no evidence: unknown, never 'inactive'
    assert "A5.supplier-inactive" not in v2


def test_supplier_single_factor_observed(tmp_path):
    st, db, ident = _state(tmp_path, identity={"directory_export": ("d.csv", DIRECTORY), "signin_export": ("s.csv", SIGNINS)})
    _rights(st, "vend1")
    analyse_identity(st, ident)
    f = {x.rule_id: x for x in st.findings.values()}
    assert f["A5.supplier-mfa-missing"].basis == "observation"


def test_malformed_identity_export_is_unavailable(tmp_path):
    st, db, ident = _state(tmp_path, identity={"directory_export": ("d.json", "[{broken")})
    assert ident.loaded["directory_export"] is False
    assert st.rec.parser_failures and any(u["unit"] == "identity:directory_export" for u in st.rec.unavailable)
