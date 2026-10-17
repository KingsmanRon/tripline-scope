"""Workbench security controls: loopback binding, sign-in, roles, sessions, host/origin/CSRF, headers, file paths."""

import os
import re
import socket
import subprocess
import sys
import time

import httpx
import pytest
from dashkit import API, audit, client, login, page_csrf, signed_in
from fastapi.testclient import TestClient

from tripline_scope import cli as tscope_cli
from tripline_scope import testing
from tripline_scope.core.errors import ConfigError
from tripline_scope.dashboard import app as A

MODULE = "tripline_scope.dashboard.cli"


@pytest.fixture
def with_dashboard_cli(monkeypatch):
    """The integrator adds this module to COMMAND_MODULES; until then the tests register it themselves."""
    mods = list(tscope_cli.COMMAND_MODULES)
    if MODULE not in mods:
        mods.append(MODULE)
    monkeypatch.setattr(tscope_cli, "COMMAND_MODULES", mods)


class FakeServer:
    seen: list = []

    def __init__(self, config):
        FakeServer.seen.append({"host": config.host, "port": config.port})

    def run(self):
        FakeServer.seen[-1]["ran"] = True


# ------------------------------------------------------------------------------------------------ binding
def test_serve_binds_localhost_only(dash, monkeypatch, with_dashboard_cli):
    import uvicorn

    case, store, home = dash
    FakeServer.seen = []
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    A.serve(case, store, home)  # defaults
    assert FakeServer.seen == [{"host": "127.0.0.1", "port": 8766, "ran": True}]
    with pytest.raises(ConfigError):
        A.serve(case, store, home, host="0.0.0.0")
    with pytest.raises(ConfigError):
        A.create_app(case, store, home, host="192.168.1.10")
    # through the CLI: default host, then refused hosts never construct a server
    testing.login("rami")
    FakeServer.seen = []
    rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root), "--port", "8799"])
    assert rc == 0, err
    assert FakeServer.seen == [{"host": "127.0.0.1", "port": 8799, "ran": True}]
    for bad in ("0.0.0.0", "::", "10.0.0.5", "example.org", "127.0.0.1.nip.io"):
        rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root), "--host", bad])
        assert rc != 0 and "loopback" in err, (bad, rc, err)
    assert len(FakeServer.seen) == 1
    starts = audit(case, "dashboard serve")
    assert starts[-1]["outcome"] == "error" and starts[-1]["error_class"] == "ConfigError"
    rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root), "--host", "::1", "--port", "8800"])
    assert rc == 0, err
    assert FakeServer.seen[-1] == {"host": "::1", "port": 8800, "ran": True}
    assert "http://localhost:8800/" in out
    rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root), "--port", "70000"])
    assert rc != 0 and len(FakeServer.seen) == 2
    starts = audit(case, "dashboard serve")
    assert starts[-1]["outcome"] == "error" and starts[-1]["error_class"] == "ConfigError"
    assert any(e["outcome"] == "ok" and e["actor"] == "rami" for e in starts)


def test_serve_requires_a_case_role(dash, monkeypatch, with_dashboard_cli):
    import uvicorn

    case, store, home = dash
    FakeServer.seen = []
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    testing.login("mallory")
    rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root)])
    assert rc != 0 and "role" in err
    assert FakeServer.seen == []
    e = audit(case, "dashboard serve")[-1]
    assert e["actor"] == "mallory" and e["outcome"] == "denied"
    for user in ("olivia", "rami", "ines"):  # every case role may start it
        testing.login(user)
        rc, out, err = testing.run_cli(["dashboard", "serve", "--case", str(case.root), "--host", "localhost"])
        assert rc == 0, (user, err)
    assert [s["host"] for s in FakeServer.seen] == ["localhost"] * 3


def test_live_server_binds_loopback_only(dash):
    """A real process started through the CLI: 127.0.0.1 only, sign-in works, foreign Host refused."""
    case, store, home = dash
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    testing.login("rami")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    code = ("import sys; from tripline_scope import cli; m = 'tripline_scope.dashboard.cli'\n"
            "cli.COMMAND_MODULES.append(m) if m not in cli.COMMAND_MODULES else None\n"
            "sys.exit(cli.main(sys.argv[1:]))")
    proc = subprocess.Popen([sys.executable, "-c", code, "dashboard", "serve", "--case", str(case.root),
                             "--port", str(port)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(150):
            try:
                httpx.get(base + "/", timeout=1)
                break
            except httpx.TransportError:
                assert proc.poll() is None, proc.communicate()[1]
                time.sleep(0.1)
        listening = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True).stdout
        assert listening.strip(), "no listening socket found by ss"
        assert {line.split()[3] for line in listening.splitlines()} == {f"127.0.0.1:{port}"}
        with httpx.Client(base_url=base, timeout=10) as c:
            r = c.get("/")
            tok = r.text.split('name="csrf" value="')[1].split('"')[0]
            r = c.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": tok},
                       headers={"Origin": base})
            assert r.status_code == 303
            page = c.get("/")
            assert page.status_code == 200 and "script-src 'nonce-" in page.headers["content-security-policy"]
            assert c.get("/api/overview").json()["case_id"] == case.case_id
        assert httpx.get(base + "/", headers={"Host": "evil.example"}, timeout=5).status_code == 400
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=10)
    assert f"http://127.0.0.1:{port}/" in out


# ------------------------------------------------------------------------------------------------ sign-in
def test_unauthenticated_gets_login_page_and_401(dash):
    case, store, home = dash
    c = client(case, store, home)
    r = c.get("/")
    assert r.status_code == 200 and 'action="/login"' in r.text and "csrf-token" not in r.text
    for path in API + ["/reports/paths/v1/report.json"]:
        r = c.get(path)
        assert r.status_code == 401, path
        assert r.json() == {"error": "sign in"}
    assert c.post("/logout").status_code == 401


def test_login_rules_and_audit(dash):
    case, store, home = dash
    c = client(case, store, home)
    n0 = len(audit(case, "dashboard login"))
    # form token required and single-use, bound to its cookie
    assert c.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": "x"}).status_code == 403
    tok = c.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    other = TestClient(c.app, base_url="http://127.0.0.1")  # another browser: no matching login cookie
    assert other.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": tok},
                      follow_redirects=False).status_code == 403
    assert c.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": tok},
                  follow_redirects=False).status_code == 403  # the token was consumed by the failed attempt
    # wrong password
    r = login(c, "rami", "wrong-password-123")
    assert r.status_code == 401 and A.SESSION_COOKIE not in r.cookies
    # an installation user without a role on the case
    r = login(c, "mallory")
    assert r.status_code == 403 and "no role" in r.text and A.SESSION_COOKIE not in r.cookies
    assert c.get("/api/overview").status_code == 401
    # each case role may sign in; roles are recorded in the session
    for user, role in (("olivia", "operator"), ("rami", "reviewer"), ("ines", "approver")):
        cc = client(case, store, home)
        r = login(cc, user)
        assert r.status_code == 303 and r.headers["location"] == "/"
        set_cookie = r.headers["set-cookie"].lower()
        assert "httponly" in set_cookie and "samesite=strict" in set_cookie
        ov = cc.get("/api/overview").json()
        assert ov["user"] == user and ov["roles"] == [role]
    entries = audit(case, "dashboard login")[n0:]
    denied = [e for e in entries if e["outcome"] == "denied"]
    assert {e["actor"] for e in denied} == {"rami", "mallory"}
    ok = [(e["actor"], e["role"]) for e in entries if e["outcome"] == "ok"]
    assert ok == [("olivia", "operator"), ("rami", "reviewer"), ("ines", "approver")]
    assert all(e["case_id"] == case.case_id for e in entries)


def test_totp_required_role_is_enforced(dash):
    case, store, home = dash
    home.config["require_totp_roles"] = ["reviewer"]  # in memory only
    c = client(case, store, home)
    assert login(c, "rami").status_code == 401
    assert login(c, "olivia").status_code == 303


def test_foreign_host_and_origin_refused(dash):
    case, store, home = dash
    c = signed_in(case, store, home, port=8766)
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/api/overview", headers={"Host": "127.0.0.1.evil.example"}).status_code == 400
    assert c.get("/api/overview", headers={"Host": "localhost:8766"}).status_code == 200
    csrf = page_csrf(c)
    for origin in ("http://evil.example", "null", "http://127.0.0.1:9999", "https://127.0.0.1:8766"):
        r = c.post("/logout", headers={"Origin": origin, "X-CSRF-Token": csrf})
        assert r.status_code == 403 and r.json()["error"] == "cross-origin request refused", origin
    r = c.post("/logout", headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": csrf})
    assert r.status_code == 403
    tok = c.get("/").text  # still signed in after the refused requests
    assert "csrf-token" in tok
    fresh = client(case, store, home, port=8766)
    t = fresh.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    r = fresh.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": t},
                   headers={"Origin": "http://evil.example"}, follow_redirects=False)
    assert r.status_code == 403
    t = fresh.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    r = fresh.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": t},
                   headers={"Origin": "http://127.0.0.1:8766", "Sec-Fetch-Site": "same-origin"},
                   follow_redirects=False)
    assert r.status_code == 303
    r = c.post("/logout", headers={"Origin": "http://localhost:8766", "X-CSRF-Token": csrf})
    assert r.status_code == 200


def test_logout_requires_csrf(dash):
    case, store, home = dash
    c = signed_in(case, store, home)
    assert c.post("/logout").status_code == 403
    assert c.post("/logout", headers={"X-CSRF-Token": "not-the-token"}).status_code == 403
    assert c.get("/api/overview").status_code == 200  # still signed in
    r = c.post("/logout", headers={"X-CSRF-Token": page_csrf(c)})
    assert r.status_code == 200 and r.json() == {"signed_out": True}
    assert c.get("/api/overview").status_code == 401


def test_session_idle_and_absolute_expiry(dash, monkeypatch):
    case, store, home = dash
    now = [1_000_000.0]
    monkeypatch.setattr(A, "_clock", lambda: now[0])
    c = signed_in(case, store, home)
    now[0] += 29 * 60
    assert c.get("/api/overview").status_code == 200  # activity refreshes the idle timer
    now[0] += 29 * 60
    assert c.get("/api/overview").status_code == 200
    now[0] += 31 * 60
    assert c.get("/api/overview").status_code == 401  # idle > 30 min
    assert c.get("/api/overview").status_code == 401  # and the session is gone
    c2 = signed_in(case, store, home)
    start = now[0]
    while now[0] - start < 2 * 3600 - 20 * 60:
        now[0] += 20 * 60
        assert c2.get("/api/overview").status_code == 200
    now[0] = start + 2 * 3600 + 1
    assert c2.get("/api/overview").status_code == 401  # absolute 2 h even while active
    # login form tokens expire too
    c3 = client(case, store, home)
    tok = c3.get("/").text.split('name="csrf" value="')[1].split('"')[0]
    now[0] += A.LOGIN_TOKEN_SECONDS + 1
    r = c3.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": tok},
                follow_redirects=False)
    assert r.status_code == 403


# ------------------------------------------------------------------------------------------------ headers
EXPECTED = {"x-frame-options": "DENY", "cache-control": "no-store", "pragma": "no-cache",
            "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
            "cross-origin-resource-policy": "same-origin", "cross-origin-opener-policy": "same-origin"}
BASE_CSP = ("default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def _check_headers(r, page=False):
    for k, v in EXPECTED.items():
        assert r.headers.get(k) == v, (r.request.url, k, r.headers.get(k))
    csp = r.headers["content-security-policy"]
    assert csp.startswith(BASE_CSP), csp
    assert ("script-src 'nonce-" in csp) == page
    assert not [k for k in r.headers if k.lower().startswith("access-control-")]


def test_security_headers_on_every_response(dash):
    case, store, home = dash
    c = client(case, store, home)
    _check_headers(c.get("/"))
    _check_headers(c.get("/api/overview"))  # 401
    _check_headers(c.get("/nope"))  # 404
    _check_headers(c.get("/", headers={"Host": "evil.example"}))  # 400 from TrustedHostMiddleware
    _check_headers(c.post("/login", data={"username": "x", "password": "y", "csrf": "z"}))
    c = signed_in(case, store, home)
    page = c.get("/", headers={"Origin": "http://evil.example"})  # Origin on GET is irrelevant
    _check_headers(page, page=True)
    nonce = re.search(r"script-src 'nonce-([^']+)'", page.headers["content-security-policy"]).group(1)
    assert f'<script nonce="{nonce}">' in page.text
    assert page.text.count("<script") == 1
    assert c.get("/").headers["content-security-policy"] != page.headers["content-security-policy"]  # per response
    for path in API:
        _check_headers(c.get(path, headers={"Origin": "http://evil.example"}))
    _check_headers(c.get("/reports/paths/v1/report.json"))
    _check_headers(c.get("/reports/notify/v1/report.json"))
    _check_headers(c.options("/api/overview", headers={"Origin": "http://evil.example",
                                                        "Access-Control-Request-Method": "GET"}))


def test_page_is_self_contained_and_escapes(dash):
    case, store, home = dash
    c = signed_in(case, store, home)
    html = c.get("/").text
    login_html = client(case, store, home).get("/").text
    for doc in (html, login_html):
        assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", doc, re.I)
        assert "@import" not in doc and "url(" not in doc
        assert "<link" not in doc.lower() and "<iframe" not in doc.lower()
    assert "innerHTML" not in html and "outerHTML" not in html and "insertAdjacentHTML" not in html
    assert "eval(" not in html and "new Function" not in html and "document.write" not in html
    for section in ("Overview", "Timeline", "Access paths", "Exposure", "People", "AI Investigator", "Reports"):
        assert section in html
    assert 'aria-label="Workbench sections"' in html and "Skip to content" in html


# ------------------------------------------------------------------------------------------------ report files
def test_report_files_only_released_allowlisted(dash):
    case, store, home = dash
    c = signed_in(case, store, home)
    root = case.root / "reports"
    for kind, n, name in (("paths", 1, "report.json"), ("paths", 1, "report.pdf"), ("scope", 2, "release.json"),
                          ("exposure", 1, "signatures.json"), ("scope", 1, "report.json")):
        r = c.get(f"/reports/{kind}/v{n}/{name}")
        assert r.status_code == 200, (kind, n, name)
        assert r.content == (root / kind / f"v{n:04d}" / name).read_bytes()
        assert "attachment" in r.headers["content-disposition"]
    assert c.get("/reports/paths/v0001/report.json").status_code == 200
    bad = [
        "/reports/paths/v1/../../case.yaml", "/reports/paths/v1/%2e%2e/%2e%2e/case.yaml",
        "/reports/%2e%2e/v1/report.json", "/reports/paths/%2e%2e/report.json", "/reports/paths/v1/..%2frelease.json",
        "/reports/paths/v1/attachments%2ftimeline.jsonl", "/reports/paths/v1/attachments/timeline.jsonl",
        "/reports/notify/v1/report.json", "/reports/work/v1/report.json", "/reports/drafts/v1/report.json",
        "/reports/datamap/v1/report.json", "/reports/unknown/v1/report.json",
        "/reports/paths/vx/report.json", "/reports/paths/1/report.json", "/reports/paths/v-1/report.json",
        "/reports/paths/v1.0/report.json", "/reports/paths/v99/report.json", "/reports/paths/v0/report.json",
        "/reports/exposure/v1/report.pdf",  # not released with a PDF (--no-pdf)
        "/reports/paths/v1/case.yaml", "/reports/paths/v1/audit.log", "/reports/paths/v1/REPORT.JSON",
        "/reports/paths/v1/report.json%00", "/reports/paths/v1/.", "/reports/paths/v1/report.json/",
        "/reports/paths/v1/%2e", "/reports//v1/report.json",
    ]
    for url in bad:
        r = c.get(url)
        assert r.status_code == 404, (url, r.status_code)
        assert b'"schema"' not in r.content and b"case_id" not in r.content
