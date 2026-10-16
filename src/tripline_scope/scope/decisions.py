"""Review decisions: an append-only, encrypted log in ``review/decisions.jsonl``.

Each entry: ``pair_key`` (HMAC of the record-key pair under the case key), the two record keys (positional
"<SRC>|<table>|<ordinal>" strings, never identifiers), ``decision`` (same | different | skip), ``reviewer``,
``decided_at``, ``via`` (review_page | file | simulated) and ``simulated`` (true only for synthetic drills and
demos). The latest entry per pair wins; every run replays them. The decision hash recorded in each report covers
(pair_key, decision, simulated) in pair order, so it changes exactly when a decision changes.
"""

from __future__ import annotations

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.timeutil import now_iso

DECISIONS = "review/decisions.jsonl"
QUEUE = "review/queue.json"
VALID = ("same", "different", "skip")


def load_log(store) -> list[dict]:
    if not store.exists(DECISIONS):
        return []
    return list(store.read_jsonl(DECISIONS))


def latest(store) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in load_log(store):
        out[e["pair_key"]] = e
    return {k: v for k, v in out.items() if v.get("decision") in ("same", "different")}


def append(store, entries: list[dict]) -> int:
    if not entries:
        return 0
    log = load_log(store)
    for e in entries:
        if e.get("decision") not in VALID:
            raise ConfigError("decision must be same, different or skip")
    log.extend(entries)
    store.write_jsonl(DECISIONS, log)
    return len(entries)


def entry(item: dict, decision: str, reviewer: str, via: str, simulated: bool = False) -> dict:
    return {"pair_key": item["pair_key"], "key_l": item["key_l"], "key_r": item["key_r"], "decision": decision,
            "reviewer": reviewer, "decided_at": now_iso(), "via": via, "simulated": bool(simulated)}


def digest(decisions: dict[str, dict]) -> str:
    rows = [[k, v["decision"], bool(v.get("simulated"))] for k, v in sorted(decisions.items())]
    return sha256_hex(canonical_bytes(rows))


def summary(decisions: dict[str, dict]) -> dict:
    sim = sum(1 for v in decisions.values() if v.get("simulated"))
    return {"count": len(decisions), "same": sum(1 for v in decisions.values() if v["decision"] == "same"),
            "different": sum(1 for v in decisions.values() if v["decision"] == "different"),
            "simulated": sim, "any_simulated": sim > 0}


def load_queue(store) -> list[dict]:
    if not store.exists(QUEUE):
        return []
    return store.read_json(QUEUE)["items"]
