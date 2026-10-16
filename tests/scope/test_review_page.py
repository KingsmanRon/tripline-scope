import datetime as dt

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient
from test_matching_rules import ROWS, add_manual

from conftest import c, cli, ingest
from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.scope import review_app


@pytest.fixture
def queued(case_dir, synth_dir, tmp_path):
    ingest(case_dir, synth_dir)
    keys = add_manual(case_dir, tmp_path)
    cli(["scope", "match"] + c(case_dir), "olivia")
    case = Case(case_dir)
    return case, open_store(case, Home()), keys


def _login(client, user):
    r = client.get("/")
    tok = r.text.split('name="csrf" value="')[1].split('"')[0]
    return client.post("/login", data={"username": user, "password": testing.PASSWORD, "csrf": tok},
                       follow_redirects=False)


def test_review_page_auth_csrf_fields_and_audit(queued):
    case, store, keys = queued
    app = review_app.create_app(case, store, Home())
    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.get("/api/item/0").status_code == 401
    assert "Sign in" in client.get("/").text
    # form token required
    assert client.post("/login", data={"username": "rami", "password": testing.PASSWORD, "csrf": "x"}).status_code == 403
    r = client.get("/")
    tok = r.text.split('name="csrf" value="')[1].split('"')[0]
    assert client.post("/login", data={"username": "rami", "password": "wrong-password-123", "csrf": tok}).status_code == 401
    assert _login(client, "olivia").status_code == 403  # operator is not a reviewer
    r = _login(client, "rami")
    assert r.status_code == 303 and review_app.SESSION_COOKIE in r.cookies
    page = client.get("/")
    assert "Content-Security-Policy" in page.headers and "j</kbd>" in page.text
    csrf = page.text.split('const csrf = "')[1].split('"')[0]
    n_before = sum(1 for e in case.audit.entries() if e["command"] == "scope review view")
    item = client.get("/api/item/0").json()
    assert item["total"] >= 2
    assert set(item["left"]) == {"source", "first_names", "surname", "maiden_name", "date_of_birth", "sex", "id_number",
                                 "passport", "phone", "email", "postal_code"}
    for side in ("left", "right"):
        for k in ("id_number", "phone", "email", "passport"):
            v = item[side][k]
            assert v == "—" or "•" in v
    views = [e for e in case.audit.entries() if e["command"] == "scope review view"]
    assert len(views) == n_before + 1 and views[-1]["actor"] == "rami"
    assert views[-1]["params"] == {"pair": item["pair_key"]}
    audit_text = case.audit.path.read_text()
    assert "Leopoldine".upper() not in audit_text.upper() and "Wexford".upper() not in audit_text.upper()
    # decisions need the CSRF token
    assert client.post("/api/decide", json={"pair_key": item["pair_key"], "decision": "same"}).status_code == 403
    r = client.post("/api/decide", json={"pair_key": item["pair_key"], "decision": "same"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    log = list(store.read_jsonl("review/decisions.jsonl"))
    assert log[-1]["pair_key"] == item["pair_key"] and log[-1]["reviewer"] == "rami" and not log[-1]["simulated"]
    assert client.post("/api/decide", json={"pair_key": "nope", "decision": "same"},
                       headers={"X-CSRF-Token": csrf}).status_code == 400
    # DNS rebinding: other Host headers are refused
    evil = TestClient(app, base_url="http://evil.example")
    assert evil.get("/").status_code == 400


def test_review_server_binds_localhost_only(queued, monkeypatch):
    case, store, keys = queued
    seen = {}

    class FakeServer:
        def __init__(self, config):
            seen["host"], seen["port"] = config.host, config.port

        def run(self):
            seen["ran"] = True

    import uvicorn

    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    review_app.serve(case, store, Home(), port=8799)
    assert seen == {"host": "127.0.0.1", "port": 8799, "ran": True}


def test_review_page_live_server(queued):
    """`tscope scope review` as a real process: binds 127.0.0.1 only, sign-in works, other Host headers refused."""
    import os
    import socket
    import subprocess
    import sys
    import time

    import httpx

    case, store, keys = queued
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    testing.login("rami")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    proc = subprocess.Popen([sys.executable, "-m", "tripline_scope", "scope", "review"] + c(case.root)
                            + ["--port", str(port)], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                httpx.get(base + "/", timeout=1)
                break
            except httpx.TransportError:
                assert proc.poll() is None, proc.communicate()[1]
                time.sleep(0.1)
        listening = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True).stdout
        if listening.strip():  # local-address column of every listening socket on this port
            assert {line.split()[3] for line in listening.splitlines()} == {f"127.0.0.1:{port}"}
        with httpx.Client(base_url=base, timeout=5) as client:
            assert _login(client, "rami").status_code == 303
            page = client.get("/")
            assert page.status_code == 200 and "Content-Security-Policy" in page.headers
            item = client.get("/api/item/0").json()
            assert item["total"] >= 2
            assert "Leopoldine".upper() not in str(item["left"]["id_number"]).upper()
        assert httpx.get(base + "/", headers={"Host": "evil.example"}, timeout=5).status_code == 400
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=10)
    assert f"http://127.0.0.1:{port}/" in out


def test_simulated_decisions_are_marked_in_the_report(queued, tmp_path):
    case, store, keys = queued
    names = list(ROWS)
    person = {"X": 1, "Y": 1, "Z": 2}
    gt = pa.table({"source_db": ["manualdb"] * 3, "table": ["patients"] * 3,
                   "local_patient_key": [f"M{names.index(n)}" for n in ("X", "Y", "Z")],
                   "person_id": [person[n] for n in ("X", "Y", "Z")]})
    pq.write_table(gt, tmp_path / "gt.parquet")
    rc, out, err = cli(["scope", "decide"] + c(case.root) + ["--simulate-reviewer", str(tmp_path / "gt.parquet")], "rami")
    assert out["simulated"] and out["same"] >= 1 and out["different"] >= 1
    assert all(e["simulated"] for e in store.read_jsonl("review/decisions.jsonl"))
    cli(["scope", "match"] + c(case.root), "olivia")
    rc, rep, err = cli(["scope", "report"] + c(case.root))
    assert rep["simulated_review"] is True
    drafts = sorted((case.root / "reports/scope/drafts").iterdir(), key=lambda p: p.stat().st_mtime)
    assert b"simulated" in (drafts[-1] / "report.pdf").read_bytes()
    assert dt.date  # keep import
