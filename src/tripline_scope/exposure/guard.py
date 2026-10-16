"""Offline guard: refuses any network activity while an exposure scan runs.

Implemented as a process-wide audit hook on the ``socket.*`` audit events (connect, sendto, sendmsg, bind,
getaddrinfo, gethostbyname). The only exception is an endpoint the manifest explicitly declares for a
metadata-only read-only database login (``live_metadata``); everything else raises ``PermissionError``.
"""

from __future__ import annotations

import sys
import threading
from contextlib import contextmanager

_lock = threading.Lock()
_state = {"depth": 0, "allowed": set(), "blocked": 0}
_installed = False
_EVENTS = {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind", "socket.getaddrinfo",
           "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo"}


def _endpoint(event: str, args) -> tuple[str, int | None] | None:
    try:
        if event in ("socket.connect", "socket.sendto", "socket.bind"):
            addr = args[1]
        elif event == "socket.getaddrinfo":
            return str(args[0]), (int(args[1]) if isinstance(args[1], int) or str(args[1]).isdigit() else None)
        elif event in ("socket.gethostbyname", "socket.gethostbyaddr"):
            return str(args[0]), None
        else:
            return None
        if isinstance(addr, tuple) and len(addr) >= 2:
            return str(addr[0]), int(addr[1])
        return None  # AF_UNIX path or unknown: not an allowed TCP endpoint
    except Exception:  # noqa: BLE001
        return None


def _hook(event: str, args) -> None:
    if not _state["depth"] or event not in _EVENTS:
        return
    ep = _endpoint(event, args)
    if ep is not None:
        host, port = ep
        for ah, ap in _state["allowed"]:
            if host == ah and (port is None or port == ap):
                return
    _state["blocked"] += 1
    raise PermissionError("network access is disabled during exposure scans")


def _install() -> None:
    global _installed
    with _lock:
        if not _installed:
            sys.addaudithook(_hook)
            _installed = True


@contextmanager
def offline(allowed: set[tuple[str, int]] | None = None):
    """Block network activity for the duration; ``allowed`` lists declared (host, port) database endpoints."""
    _install()
    with _lock:
        prev = set(_state["allowed"])
        _state["allowed"] = set(allowed or ())
        _state["depth"] += 1
    try:
        yield
    finally:
        with _lock:
            _state["depth"] -= 1
            _state["allowed"] = prev


def blocked_attempts() -> int:
    return _state["blocked"]
