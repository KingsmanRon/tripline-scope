from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.reports import ReportStore


def _release(case_dir, kind):
    return testing.run_cli(["--json", "release", "--case", str(case_dir), "--kind", kind, "--approver", "ines"])


def test_readiness_report_cites_released_components(install, tmp_path):
    case_dir = testing.open_case(tmp_path, "READY-001", mode="readiness")
    rs = ReportStore(Case(case_dir))
    rs.save_draft("datamap", rs.new_body("datamap", summary={"tables": 4, "id_number_columns": 2}))
    assert _release(case_dir, "datamap")[0] == 0
    testing.login("olivia")
    rc, out, err = testing.run_cli(["--json", "readiness", "report", "--case", str(case_dir)])
    assert rc == 0, err
    assert '"exposure"' in out and '"drill"' in out  # listed as missing
    assert _release(case_dir, "readiness")[0] == 0
    body = ReportStore(Case(case_dir)).load("readiness")
    assert body["components"]["datamap"]["status"] == "released"
    assert body["components"]["datamap"]["summary"] == {"id_number_columns": 2, "tables": 4}
    assert body["components"]["exposure"]["status"] == "not available"
    assert "not a breach scope" in body["statement"]
    rc, out, err = testing.run_cli(["verify", "--case", str(case_dir)])
    assert rc == 0, out + err


def test_readiness_report_refused_in_incident_case(case_dir):
    testing.login("olivia")
    rc, out, err = testing.run_cli(["readiness", "report", "--case", str(case_dir)])
    assert rc == 2
