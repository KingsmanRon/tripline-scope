import json

import pytest

from tripline_scope import testing
from tripline_scope.core.audit import AuditLog
from tripline_scope.core.auth import UserStore
from tripline_scope.core.errors import AuthenticationFailed, ConfigError
from tripline_scope.core.home import Home


def test_audit_chain_verifies_and_detects_tamper(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    for i in range(5):
        log.append(command=f"cmd{i}", actor="olivia", role="operator", case_id="C-1", inputs={"x": "ab" * 32})
    assert log.verify().ok
    lines = (tmp_path / "audit.log").read_bytes().split(b"\n")
    # alter a field in entry 3
    e = json.loads(lines[2])
    e["actor"] = "mallory"
    from tripline_scope.core.canonical import canonical_bytes

    lines2 = list(lines)
    lines2[2] = canonical_bytes(e)
    (tmp_path / "t.log").write_bytes(b"\n".join(lines2))
    assert not AuditLog(tmp_path / "t.log").verify().ok
    # delete an entry
    (tmp_path / "d.log").write_bytes(b"\n".join(lines[:2] + lines[3:]))
    assert not AuditLog(tmp_path / "d.log").verify().ok
    # reorder
    (tmp_path / "r.log").write_bytes(b"\n".join([lines[1], lines[0]] + lines[2:]))
    assert not AuditLog(tmp_path / "r.log").verify().ok


def test_audit_params_are_scrubbed(tmp_path):
    import datetime as dt

    from tripline_scope.core.identifiers import make_sa_id

    sid = make_sa_id(dt.date(1990, 1, 2), 4321)
    log = AuditLog(tmp_path / "audit.log")
    log.append(command="x", actor="a", role=None, case_id=None,
               params={"q": f"id={sid} mail a.b@example.com password=hunter2"}, note=f"{sid}")
    raw = (tmp_path / "audit.log").read_text()
    assert sid not in raw and "a.b@example.com" not in raw and "hunter2" not in raw


def test_argon2id_and_lockout(install):
    home = Home()
    store = UserStore(home)
    doc = json.loads(home.users_path.read_bytes())
    assert doc["users"]["olivia"]["password_hash"].startswith("$argon2id$")
    assert store.authenticate("olivia", testing.PASSWORD).username == "olivia"
    for _ in range(5):
        with pytest.raises(AuthenticationFailed):
            store.authenticate("olivia", "wrong-password-123")
    with pytest.raises(AuthenticationFailed):
        store.authenticate("olivia", testing.PASSWORD)  # locked
    with pytest.raises(ConfigError):
        store.add("shorty", "short")


def test_totp_required_once_enrolled_and_not_replayable(install):
    import pyotp

    home = Home()
    store = UserStore(home)
    store.enroll_totp("ines")
    with pytest.raises(AuthenticationFailed):
        store.authenticate("ines", testing.PASSWORD)
    code = pyotp.TOTP(store.totp_secret("ines")).now()
    ident = store.authenticate("ines", testing.PASSWORD, code)
    assert ident.auth_method == "password+totp"
    with pytest.raises(AuthenticationFailed):
        store.authenticate("ines", testing.PASSWORD, code)  # replay


def test_users_file_has_no_plain_totp(install):
    home = Home()
    store = UserStore(home)
    store.enroll_totp("rami")
    secret = store.totp_secret("rami")
    assert secret not in home.users_path.read_text()
