"""Module B makes no network requests: the whole pipeline runs with sockets and name resolution disabled.
(The suite is additionally run under ``unshare -n`` with no network namespace; see docs/ACCESS_PATHS.md.)"""

import socket

from paths_helpers import WINDOW, activate, build_case

from tripline_scope import testing


def test_pipeline_runs_with_network_disabled(demo_dir, tmp_path, monkeypatch):
    attempts = []

    def deny(*a, **k):
        attempts.append(a[:1])
        raise OSError("network disabled for this test")

    class NoSocket(socket.socket):
        def __init__(self, *a, **k):
            deny(*a)

    monkeypatch.setattr(socket, "socket", NoSocket)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "gethostbyname", deny)
    ns = build_case(tmp_path / "inst", demo_dir)
    activate(ns, monkeypatch)
    for argv in (["paths", "analyse", "--case", str(ns.case_dir), "--window", WINDOW],
                 ["paths", "report", "--case", str(ns.case_dir)],
                 ["paths", "scope-candidates", "--case", str(ns.case_dir), "--out", str(tmp_path / "c.json")]):
        rc, out, err = testing.run_cli(argv)
        assert rc == 0, err
    assert attempts == []
