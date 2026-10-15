"""Verification of the hash-chained audit log (JSON Lines)."""

from __future__ import annotations

import json
from pathlib import Path

from .canonical import canonical_bytes, sha256_hex
from .formats import AUDIT_SCHEMA, GENESIS_HASH
from .result import Result


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(canonical_bytes(body))


def verify_audit_log(path: str | Path) -> Result:
    path = Path(path)
    res = Result(subject=str(path))
    if not res.add("audit log exists", path.is_file()):
        return res
    prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    for lineno, raw in enumerate(path.read_bytes().split(b"\n"), start=1):
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            res.add(f"line {lineno} is JSON", False)
            return res
        if canonical_bytes(entry) != raw:
            res.add(f"line {lineno} is canonical", False)
            return res
        if entry.get("schema") != AUDIT_SCHEMA:
            res.add(f"line {lineno} schema", False)
            return res
        if entry.get("seq") != expected_seq:
            res.add(f"line {lineno} sequence", False, f"seq={entry.get('seq')} expected {expected_seq}")
            return res
        if entry.get("prev") != prev:
            res.add(f"line {lineno} links to previous entry", False)
            return res
        if entry.get("hash") != entry_hash(entry):
            res.add(f"line {lineno} hash matches content", False)
            return res
        prev = entry["hash"]
        expected_seq += 1
        count += 1
    res.add("hash chain intact", True, f"{count} entries")
    res.info.update(entries=count, head=prev)
    return res
