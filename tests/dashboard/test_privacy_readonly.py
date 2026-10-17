"""No identifiers in any response, read-only, GET-only data endpoints, offline operation and audit entries."""

import hashlib
import json
import socket

import pyarrow.parquet as pq
from dashkit import API, audit, client, login, page_csrf, signed_in

from tripline_scope.core.redact import find_identifier_like

AUDIT_FILES = {"audit.log", "audit.log.lock"}


def _walk(c, signed=True):
    """Exercise every page and endpoint; returns {label: response text}."""
    out = {}
    out["login page"] = client_page = c.get("/").text
    if not signed:
        return {"login page": client_page}
    for path in API:
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
        out[path] = r.text
    offset = 0
    while True:
        r = c.get(f"/api/timeline?limit=500&offset={offset}")
        out[f"timeline@{offset}"] = r.text
        offset += 500
        if offset >= r.json()["total"]:
            break
    for qs in ("class=access_observed", "family=entra_signin", "start=2026-09-03T00:00:00Z&end=2026-09-04T12:00:00Z",
               "asset=AST-LABSQL02"):
        out["timeline?" + qs] = c.get("/api/timeline?" + qs + "&limit=500").text
    out["reports refresh"] = c.get("/api/reports?refresh=1").text
    for url in ("/reports/paths/v1/report.json", "/reports/scope/v2/report.json", "/reports/scope/v1/release.json",
                "/reports/exposure/v1/signatures.json"):
        r = c.get(url)
        assert r.status_code == 200
        out[url] = r.text
    return out


def test_no_patient_identifiers_in_any_response(dash, built):
    case, store, home = dash
    c = signed_in(case, store, home)
    responses = _walk(c)
    responses["page"] = c.get("/").text
    t = pq.read_table(built.synth / "ground_truth_identifiers.parquet")
    values = {v for col in t.column_names for v in t.column(col).to_pylist() if isinstance(v, str) and len(v) >= 6}
    assert len(values) > 1000
    for label, text in responses.items():
        low = text.lower()
        hits = [v for v in values if v.lower() in low]
        assert hits == [], (label, hits[:5])
        assert find_identifier_like(text) == [], (label, find_identifier_like(text))
    # the timeline has been fully walked, including every event
    total = json.loads(responses["/api/timeline"])["total"]
    assert sum(len(json.loads(v)["events"]) for k, v in responses.items() if k.startswith("timeline@")) == total


def _tree_hashes(root):
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name not in AUDIT_FILES:
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_read_only_and_get_only(dash):
    case, store, home = dash
    before = _tree_hashes(case.root)
    audit_before = len(list(case.audit.entries()))
    c = client(case, store, home)
    assert login(c, "rami", "wrong-password-123").status_code == 401
    assert login(c, "rami").status_code == 303
    _walk(c)
    for path in API + ["/reports/paths/v1/report.json", "/"]:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            if path == "/" and method == "POST":
                continue
            r = c.request(method, path, headers={"X-CSRF-Token": page_csrf(c)})
            assert r.status_code == 405, (method, path, r.status_code)
    assert c.get("/api/timeline?limit=-1").status_code == 400
    assert c.get("/reports/notify/v1/report.json").status_code == 404
    assert c.post("/logout", headers={"X-CSRF-Token": page_csrf(c)}).status_code == 200
    c2 = signed_in(case, store, home, user="ines")
    _walk(c2)
    after = _tree_hashes(case.root)
    assert after == before  # nothing under the case directory changed (audit log excepted)
    assert len(list(case.audit.entries())) > audit_before  # ... which did record the session
    assert not (case.root / "notify").exists() or not any((case.root / "notify").iterdir())


def test_offline_no_outbound_connections(dash, monkeypatch):
    case, store, home = dash
    attempts = []
    real_connect, real_connect_ex, real_cc = socket.socket.connect, socket.socket.connect_ex, socket.create_connection

    def loopback(addr):
        host = addr[0] if isinstance(addr, tuple) else str(addr)
        return host in ("127.0.0.1", "::1", "localhost") or isinstance(addr, str | bytes)  # AF_UNIX paths

    def guard(fn):
        def wrapped(self, addr, *a, **kw):
            attempts.append(addr)
            if not loopback(addr):
                raise OSError("network disabled in this test")
            return fn(self, addr, *a, **kw)
        return wrapped

    def guard_cc(addr, *a, **kw):
        attempts.append(addr)
        if not loopback(addr):
            raise OSError("network disabled in this test")
        return real_cc(addr, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", guard(real_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guard(real_connect_ex))
    monkeypatch.setattr(socket, "create_connection", guard_cc)
    c = signed_in(case, store, home)
    responses = _walk(c)
    responses["page"] = c.get("/").text
    assert c.post("/logout", headers={"X-CSRF-Token": page_csrf(c)}).status_code == 200
    assert [a for a in attempts if not loopback(a)] == []
    assert attempts == []  # the workbench itself opens no connection at all
    assert all(text for text in responses.values())


def test_audit_entries_for_login_and_sensitive_views(dash):
    case, store, home = dash
    n_view = len(audit(case, "dashboard view"))
    c = signed_in(case, store, home, user="rami")
    for _ in range(2):
        for path in ("/api/people", "/api/investigation", "/api/timeline", "/api/timeline?offset=100", "/api/paths",
                     "/api/exposure", "/api/overview", "/api/reports"):
            assert c.get(path).status_code == 200
    views = audit(case, "dashboard view")[n_view:]
    sections = [e["params"]["section"] for e in views]
    # people and investigation: every request; timeline, paths, exposure: once per section per session
    assert sorted(sections) == sorted(["people", "people", "investigation", "investigation", "timeline", "paths",
                                       "exposure"])
    assert all(e["actor"] == "rami" and e["role"] == "reviewer" and e["outcome"] == "ok"
               and e["case_id"] == case.case_id for e in views)
    c2 = signed_in(case, store, home, user="olivia")
    assert c2.get("/api/timeline").status_code == 200
    e = audit(case, "dashboard view")[-1]
    assert (e["actor"], e["role"], e["params"]["section"]) == ("olivia", "operator", "timeline")
    logins = [x for x in audit(case, "dashboard login") if x["outcome"] == "ok"][-2:]
    assert [(x["actor"], x["role"]) for x in logins] == [("rami", "reviewer"), ("olivia", "operator")]
    for x in views + logins:  # audit entries carry no values beyond ids and section names
        assert set(x["params"]) <= {"section", "auth"}
