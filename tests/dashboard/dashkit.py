"""Helpers for the dashboard tests (imported by the test modules in this directory)."""

import json

from fastapi.testclient import TestClient

from tripline_scope import testing
from tripline_scope.dashboard import app as A

API = ["/api/overview", "/api/timeline", "/api/paths", "/api/exposure", "/api/people", "/api/investigation",
       "/api/reports"]


def client(case, store, home, port=8766) -> TestClient:
    return TestClient(A.create_app(case, store, home, port=port), base_url="http://127.0.0.1")


def form_token(client) -> str:
    r = client.get("/")
    assert r.status_code == 200
    return r.text.split('name="csrf" value="')[1].split('"')[0]


def login(client, user, password=testing.PASSWORD):
    tok = form_token(client)
    return client.post("/login", data={"username": user, "password": password, "csrf": tok},
                       follow_redirects=False)


def signed_in(case, store, home, user="rami", port=8766) -> TestClient:
    c = client(case, store, home, port=port)
    r = login(c, user)
    assert r.status_code == 303, r.text
    return c


def page_csrf(client) -> str:
    page = client.get("/")
    return page.text.split('<meta name="csrf-token" content="')[1].split('"')[0]


def report(case_dir, kind, version) -> dict:
    return json.loads((case_dir / "reports" / kind / f"v{version:04d}" / "report.json").read_bytes())


def audit(case, command):
    return [e for e in case.audit.entries() if e["command"] == command]
