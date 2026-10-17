"""Where investigator working data lives (all under ``work/investigator/``, encrypted through ``CaseStore``).

``work/investigator/index.json``                     run index (ids, times, provider, status; no content)
``work/investigator/runs/<run_id>/bundle.json``      evidence bundle given to the provider
``work/investigator/runs/<run_id>/prompt.json``      exact prompt sent (bounded)
``work/investigator/runs/<run_id>/response.bin``     exact provider output bytes (may be rejected content)
``work/investigator/runs/<run_id>/result.json``      validated result, ``tripline.investigation/v1``
``work/investigator/runs/<run_id>/reviews.jsonl``    human review decisions (append-only)

Everything is under ``work/`` so case closure destroys it with the case key, legal hold blocks that closure, and
the retention rules of the case apply unchanged.
"""

from __future__ import annotations

import re

from tripline_scope.core.errors import ConfigError, NotReady

BASE = "work/investigator"
INDEX = f"{BASE}/index.json"
_RUN = re.compile(r"^RUN-[0-9a-f]{12}$")


def run_dir(run_id: str) -> str:
    if not _RUN.match(run_id or ""):
        raise ConfigError("invalid run id")
    return f"{BASE}/runs/{run_id}"


def list_runs(store) -> list[dict]:
    """Run index entries, oldest first: run_id, created_at, provider, provider_kind, model_id, status."""
    if not store.exists(INDEX):
        return []
    return list(store.read_json(INDEX).get("runs", []))


def add_run(store, entry: dict) -> None:
    runs = [r for r in list_runs(store) if r["run_id"] != entry["run_id"]] + [entry]
    store.write_json(INDEX, {"schema": "tripline.investigation-index/v1", "runs": runs})


def load_result(store, run_id: str) -> dict:
    rel = f"{run_dir(run_id)}/result.json"
    if not store.exists(rel):
        raise NotReady("no validated result for this run")
    return store.read_json(rel)


def latest_run_id(store, *, status: str | None = "completed") -> str | None:
    runs = [r for r in list_runs(store) if status is None or r.get("status") == status]
    return runs[-1]["run_id"] if runs else None


def latest_result(store) -> dict | None:
    """The most recent completed, validated result (with review decisions applied), or None."""
    rid = latest_run_id(store)
    if rid is None:
        return None
    res = load_result(store, rid)
    res["human_review"]["decisions"] = load_reviews(store, rid)
    return res


def load_reviews(store, run_id: str) -> dict[str, dict]:
    """Latest decision per item id: {item_id: {decision, reviewer, at, note}}."""
    rel = f"{run_dir(run_id)}/reviews.jsonl"
    out: dict[str, dict] = {}
    if store.exists(rel):
        for row in store.read_jsonl(rel):
            out[row["item_id"]] = {k: row[k] for k in ("decision", "reviewer", "at", "note")}
    return out


def append_review(store, run_id: str, row: dict) -> None:
    rel = f"{run_dir(run_id)}/reviews.jsonl"
    rows = list(store.read_jsonl(rel)) if store.exists(rel) else []
    store.write_jsonl(rel, rows + [row])
