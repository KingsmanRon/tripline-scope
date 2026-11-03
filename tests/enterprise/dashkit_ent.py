"""Workbench helpers for the enterprise tests (same sign-in flow as tests/dashboard/dashkit.py)."""

from fastapi.testclient import TestClient

from tripline_scope import testing
from tripline_scope.dashboard import app as A


def signed_in(case, store, home, user="rami", port=8766) -> TestClient:
    c = TestClient(A.create_app(case, store, home, port=port), base_url="http://127.0.0.1")
    page = c.get("/")
    tok = page.text.split('name="csrf" value="')[1].split('"')[0]
    r = c.post("/login", data={"username": user, "password": testing.PASSWORD, "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return c
