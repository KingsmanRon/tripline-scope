"""Append-only, hash-chained audit log (canonical JSON Lines, SIEM-ingestible as-is).

Each entry records actor, role, command, whitelisted parameters, input and output hashes and the outcome.
Entries never contain patient identifiers, secret values, passwords, connection strings or full queries:
parameter strings are length-capped and scrubbed of identifier-like patterns before they are written.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from tscope_verify.audit import entry_hash, verify_audit_log
from tscope_verify.formats import AUDIT_SCHEMA, GENESIS_HASH
from tscope_verify.result import Result

from .canonical import canonical_bytes
from .redact import scrub_text
from .timeutil import now_iso

_MAX_PARAM = 200


def _clean(value):
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) < 1e15 else str(value)
    if isinstance(value, list | tuple):
        return [_clean(v) for v in value][:50]
    if isinstance(value, dict):
        return {str(k)[:64]: _clean(v) for k, v in list(value.items())[:50]}
    return scrub_text(str(value))[:_MAX_PARAM]


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _last(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS_HASH
        import json

        with open(self.path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            back = min(size, 65536)
            while True:
                fh.seek(size - back)
                tail = fh.read(back)
                lines = [ln for ln in tail.split(b"\n") if ln]
                if len(lines) >= 2 or back == size:
                    break
                back = min(size, back * 2)
        last = json.loads(lines[-1])
        return int(last["seq"]), str(last["hash"])

    def append(
        self,
        *,
        command: str,
        actor: str | None,
        role: str | None,
        case_id: str | None,
        outcome: str = "ok",
        params: dict | None = None,
        inputs: dict | None = None,
        outputs: dict | None = None,
        error_class: str | None = None,
        note: str | None = None,
    ) -> dict:
        with self._locked():
            seq, prev = self._last()
            entry = {
                "schema": AUDIT_SCHEMA,
                "seq": seq + 1,
                "ts": now_iso(),
                "case_id": case_id,
                "actor": actor,
                "role": role,
                "command": command,
                "params": _clean(params or {}),
                "inputs": {str(k): str(v) for k, v in sorted((inputs or {}).items())},
                "outputs": {str(k): str(v) for k, v in sorted((outputs or {}).items())},
                "outcome": outcome,
                "error_class": error_class,
                "note": scrub_text(note)[:500] if note else None,
                "prev": prev,
            }
            entry["hash"] = entry_hash(entry)
            line = canonical_bytes(entry) + b"\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        return entry

    def entries(self) -> Iterator[dict]:
        import json

        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    yield json.loads(raw)

    def head(self) -> tuple[int, str]:
        return self._last()

    def verify(self) -> Result:
        return verify_audit_log(self.path)

    def export_jsonl(self, out: Path | str) -> int:
        """Copy the log as JSON Lines for SIEM ingestion. Returns the number of entries."""
        n = 0
        with open(out, "wb") as dst:
            for entry in self.entries():
                dst.write(canonical_bytes(entry) + b"\n")
                n += 1
        return n

    def actors_with_role(self, role: str, case_id: str | None = None) -> set[str]:
        return {
            e["actor"]
            for e in self.entries()
            if e.get("role") == role and e.get("actor") and (case_id is None or e.get("case_id") == case_id)
            and e.get("outcome") == "ok"
        }
