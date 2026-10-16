"""Matching (Splink on DuckDB) opens no network connection and writes no file outside the encrypted case store."""

import os
import sys

from conftest import c, cli
from tripline_scope import testing

_events: list = []
_active = {"on": False}


def _hook(event, args):
    if not _active["on"]:
        return
    if event in ("socket.connect", "socket.bind", "socket.getaddrinfo", "urllib.Request"):
        _events.append((event, None))
    elif event == "open" and len(args) >= 2:
        path, mode = args[0], args[1]
        flags = args[2] if len(args) > 2 else 0
        writing = (isinstance(mode, str) and any(x in mode for x in "wax+")) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        if writing and isinstance(path, str | bytes | os.PathLike):
            _events.append(("write", os.fsdecode(path)))


sys.addaudithook(_hook)


def test_match_no_network_and_only_encrypted_case_files(scoped):
    case_dir, _ = scoped
    testing.login("olivia")
    _events.clear()
    _active["on"] = True
    try:
        cli(["scope", "match"] + c(case_dir))
    finally:
        _active["on"] = False
    assert not [e for e in _events if e[0] != "write"], "network activity during matching"
    root = str(case_dir.resolve())
    bad = []
    for _, p in _events:
        rp = os.path.realpath(p)
        in_case = rp.startswith(root + os.sep)
        ok = (in_case and (rp.endswith(".tse") or rp.endswith(".tse.partial") or rp.endswith("audit.log")
                           or rp.endswith(".lock"))) or rp.endswith("users.lock") or rp == "/dev/null"
        if not ok:
            bad.append(rp)
    assert not bad, bad[:5]
