from tripline_scope import testing


def test_whoami_login_logout(install):
    testing.login("olivia")
    rc, out, err = testing.run_cli(["--json", "whoami"])
    assert rc == 0 and '"olivia"' in out
    assert testing.run_cli(["logout"])[0] == 0
    rc, out, err = testing.run_cli(["whoami"])
    assert rc == 3


def test_non_admin_cannot_add_users(install):
    testing.login("olivia")
    rc, out, err = testing.run_cli(["user", "add", "mallory"])
    assert rc == 3


def test_audit_verify_and_export(case_dir, tmp_path):
    rc, out, err = testing.run_cli(["audit", "verify", "--case", str(case_dir)])
    assert rc == 0, out
    rc, out, err = testing.run_cli(["audit", "export", "--case", str(case_dir), "--out", str(tmp_path / "siem.jsonl")])
    assert rc == 0
    import json

    lines = (tmp_path / "siem.jsonl").read_text().splitlines()
    assert lines and all(json.loads(x)["schema"] == "tripline.audit/v1" for x in lines)


def test_doctor(install):
    rc, out, err = testing.run_cli(["doctor"])
    assert rc == 0
