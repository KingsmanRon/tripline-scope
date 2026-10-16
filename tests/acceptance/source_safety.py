"""Source safety for acceptance tests: prove that no command writes to a source.

Two independent checks:

* **Snapshots** (:func:`snapshot`, :func:`diff`): SHA-256, size, mode, mtime and symlink targets of every
  source file (directories walked without following links), taken before and after each command.
* **Write watcher** (:class:`WriteWatcher`, Linux inotify): records, from *any* process including native
  code that bypasses Python's audit hooks, every write-mode open (``IN_CLOSE_WRITE``), modification,
  attribute change, create, delete or rename on or under the source paths while commands run.

:func:`run_commands` runs a list of commands (argv lists run as subprocesses, optionally through
``scripts/run_offline.sh``; or Python callables), checking both after every command, and returns per-command
results including console output for the leak scan.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import os
import stat
import struct
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_OFFLINE = ROOT / "scripts" / "run_offline.sh"


# ------------------------------------------------------------------------------------------- snapshots
@dataclass(frozen=True)
class Entry:
    kind: str                 # file | dir | symlink | other
    sha256: str | None
    size: int
    mode: int
    mtime_ns: int
    target: str | None = None


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _entry(path: str) -> Entry:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return Entry("symlink", None, 0, st.st_mode, st.st_mtime_ns, os.readlink(path))
    if stat.S_ISREG(st.st_mode):
        return Entry("file", _sha256(path), st.st_size, st.st_mode, st.st_mtime_ns)
    if stat.S_ISDIR(st.st_mode):
        return Entry("dir", None, 0, st.st_mode, st.st_mtime_ns)
    return Entry("other", None, st.st_size, st.st_mode, st.st_mtime_ns)


def snapshot(paths: Iterable[str | Path]) -> dict[str, Entry]:
    """Snapshot each path (a file, or a directory walked without following symlinks)."""
    out: dict[str, Entry] = {}
    for p in paths:
        p = os.path.abspath(os.fspath(p))
        out[p] = _entry(p)
        if os.path.isdir(p) and not os.path.islink(p):
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                for name in dirnames + filenames:
                    q = os.path.join(dirpath, name)
                    out[q] = _entry(q)
    return out


def diff(before: dict[str, Entry], after: dict[str, Entry]) -> list[str]:
    changes = []
    for p in sorted(set(before) | set(after)):
        a, b = before.get(p), after.get(p)
        if a is None:
            changes.append(f"added {p}")
        elif b is None:
            changes.append(f"removed {p}")
        elif a != b:
            fields = [f for f in ("kind", "sha256", "size", "mode", "mtime_ns", "target") if getattr(a, f) != getattr(b, f)]
            # A directory's mtime only changes when entries are added/removed (reported separately).
            changes.append(f"changed {p}: {', '.join(fields)}")
    return changes


# ------------------------------------------------------------------------------------------- inotify
IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE = 0x002, 0x004, 0x008
IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x040, 0x080, 0x100, 0x200
IN_DELETE_SELF, IN_MOVE_SELF, IN_Q_OVERFLOW, IN_IGNORED = 0x400, 0x800, 0x4000, 0x8000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000
WRITE_EVENTS = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE
                | IN_DELETE_SELF | IN_MOVE_SELF)
_NAMES = {IN_MODIFY: "MODIFY", IN_ATTRIB: "ATTRIB", IN_CLOSE_WRITE: "CLOSE_WRITE", IN_MOVED_FROM: "MOVED_FROM",
          IN_MOVED_TO: "MOVED_TO", IN_CREATE: "CREATE", IN_DELETE: "DELETE", IN_DELETE_SELF: "DELETE_SELF",
          IN_MOVE_SELF: "MOVE_SELF", IN_Q_OVERFLOW: "Q_OVERFLOW"}


class WatcherUnavailable(RuntimeError):
    pass


class WriteWatcher:
    """Record write-type filesystem events on source paths (Linux inotify, any process)."""

    def __init__(self, paths: Iterable[str | Path]):
        self.paths = [os.path.abspath(os.fspath(p)) for p in paths]
        self.events: list[tuple[str, str]] = []
        self._fd = -1
        self._wd: dict[int, str] = {}
        libc_name = ctypes.util.find_library("c")
        if not libc_name or not hasattr(os, "uname") or os.uname().sysname != "Linux":
            raise WatcherUnavailable("inotify needs Linux")
        self._libc = ctypes.CDLL(libc_name, use_errno=True)

    def __enter__(self) -> WriteWatcher:
        self._fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self._fd < 0:
            raise WatcherUnavailable(os.strerror(ctypes.get_errno()))
        for p in self.paths:
            self._watch(p)
            if os.path.isdir(p) and not os.path.islink(p):
                for dirpath, dirnames, _ in os.walk(p, followlinks=False):
                    for d in dirnames:
                        q = os.path.join(dirpath, d)
                        if not os.path.islink(q):
                            self._watch(q)
        return self

    def _watch(self, path: str) -> None:
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), WRITE_EVENTS)
        if wd < 0:
            raise WatcherUnavailable(f"inotify_add_watch {path}: {os.strerror(ctypes.get_errno())}")
        self._wd[wd] = path

    def poll(self) -> list[tuple[str, str]]:
        new = []
        while True:
            try:
                buf = os.read(self._fd, 65536)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    break
                raise
            off = 0
            while off < len(buf):
                wd, mask, _cookie, length = struct.unpack_from("iIII", buf, off)
                name = buf[off + 16: off + 16 + length].rstrip(b"\0").decode(errors="replace")
                off += 16 + length
                if mask & IN_IGNORED:
                    continue
                where = os.path.join(self._wd.get(wd, "?"), name) if name else self._wd.get(wd, "?")
                kinds = "|".join(v for k, v in _NAMES.items() if mask & k)
                new.append((where, kinds))
        self.events += new
        return new

    def __exit__(self, *exc) -> None:
        self.poll()
        os.close(self._fd)
        self._fd = -1


# ------------------------------------------------------------------------------------------- runner
@dataclass
class CommandResult:
    label: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    changes: list[str] = field(default_factory=list)       # snapshot differences
    write_events: list[tuple[str, str]] = field(default_factory=list)

    @property
    def source_safe(self) -> bool:
        return not self.changes and not self.write_events


Command = Sequence[str] | Callable[[], tuple[int, str, str]]


def run_commands(commands: Iterable[tuple[str, Command]], sources: Sequence[str | Path], *,
                 env: dict[str, str] | None = None, cwd: str | Path | None = None, offline: bool = False,
                 watch: bool = True, timeout: float = 600) -> list[CommandResult]:
    """Run ``(label, command)`` pairs; snapshot and watch the sources around every command.

    A command is an argv list (subprocess; through ``scripts/run_offline.sh`` when ``offline``) or a callable
    returning ``(returncode, stdout, stderr)``. Raises ``WatcherUnavailable`` when ``watch`` is requested on a
    system without inotify.
    """
    results = []
    watcher = WriteWatcher(sources) if watch else None
    if watcher:
        watcher.__enter__()
    try:
        for label, cmd in commands:
            before = snapshot(sources)
            if callable(cmd):
                rc, out, err = cmd()
            else:
                argv = [str(RUN_OFFLINE), *map(str, cmd)] if offline else [str(c) for c in cmd]
                proc = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
                rc, out, err = proc.returncode, proc.stdout, proc.stderr
            after = snapshot(sources)
            events = watcher.poll() if watcher else []
            results.append(CommandResult(label, rc, out, err, diff(before, after), events))
    finally:
        if watcher:
            watcher.__exit__(None, None, None)
    return results


def assert_source_safe(results: Iterable[CommandResult]) -> None:
    bad = [r for r in results if not r.source_safe]
    if bad:
        lines = []
        for r in bad:
            lines += [f"{r.label}: {c}" for c in r.changes] + [f"{r.label}: {k} {p}" for p, k in r.write_events]
        raise AssertionError("source safety violated:\n  " + "\n  ".join(lines))
