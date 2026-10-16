"""Module B → C bridge: scope candidates, scoping decisions and the scenarios they produce.

``tripline.scope-candidates/v1`` (from ``tscope paths scope-candidates``) lists, per (database, table), a
``window_class`` — ``confirmed`` (access observed), ``possible`` or ``not_assessable`` — with time windows,
consequence class, basis, accounts, evidence ids, confidence and limitations, plus coverage gaps and lower/upper
scenarios. Candidates are matched to extracted tables case-insensitively on (database, table); a schema prefix
("dbo.") is ignored when only one side carries it.

Scenarios (all counted from the same matched people; matching itself always runs on every extracted record, so
the full-scope count is always available):

* ``lower`` (observed access): people with records in tables whose access is *confirmed* (or explicitly widened
  by the operator), created no later than the end of a confirmed window (records without a date count);
* ``candidate``: the same over confirmed and possible tables;
* ``upper`` (possible exposure): every table — confirmed, possible, not assessable, and every table Module B did
  not cover — with no time limit. Uncertain or absent logs never remove anyone from the upper scenario, and the
  notification proposal is the upper scenario.

Each ``constrain`` call is a scoping decision recorded in the audit log and in the next scope report.
"""

from __future__ import annotations

import datetime as dt
import json

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError

CANDIDATES = "work/scope/candidates.json"
DECISIONS = "work/scope/scoping_decisions.json"
SCHEMA = "tripline.scope-candidates/v1"
# Order = breadth when a table is listed twice. ``none_observed`` (Module B covered the table and saw no access) is
# never part of the lower or candidate scenario, and like every other class it stays in the upper scenario.
WINDOW_CLASSES = ("confirmed", "possible", "not_assessable", "none_observed")


def parse(raw: bytes) -> dict:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ConfigError("scope candidates file is not valid JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ConfigError(f"scope candidates must have schema {SCHEMA}")
    tables = doc.get("tables")
    if not isinstance(tables, list):
        raise ConfigError("scope candidates need a 'tables' list")
    for t in tables:
        if not isinstance(t, dict) or not t.get("table"):
            raise ConfigError("each candidate table needs 'database' and 'table'")
        if t.get("window_class") not in WINDOW_CLASSES:
            raise ConfigError("window_class must be confirmed, possible, not_assessable or none_observed")
    return doc


def _norm(s) -> str:
    return str(s or "").strip().lower()


def _short(table: str) -> str:
    return _norm(table).split(".")[-1]


def _window_end(w) -> dt.date | None:
    end = None
    if isinstance(w, dict):
        end = w.get("end") or w.get("to") or w.get("until")
    elif isinstance(w, list | tuple) and len(w) == 2:
        end = w[1]
    if not end:
        return None
    try:
        return dt.date.fromisoformat(str(end)[:10])
    except ValueError:
        return None


def map_tables(candidates: dict, tables: list[dict]) -> tuple[dict[tuple[str, str], dict], list[dict]]:
    """Return {(source_id, slug): candidate entry} and the candidate entries that matched no extracted table."""
    out: dict[tuple[str, str], dict] = {}
    unmatched = []
    for c in candidates.get("tables", []):
        db, tb = _norm(c.get("database")), _norm(c.get("table"))
        hits = [t for t in tables if _norm(t.get("database")) == db and _norm(t.get("table")) == tb]
        if not hits:
            hits = [t for t in tables if _norm(t.get("database")) == db and _short(t.get("table") or "") == _short(tb)]
        if not hits:
            unmatched.append({"database": c.get("database"), "table": c.get("table"), "window_class": c.get("window_class")})
            continue
        for t in hits:
            key = (t["source_id"], t["slug"])
            prev = out.get(key)
            # a table listed twice keeps the broader class (confirmed > possible > not_assessable) and all windows
            if prev is None or WINDOW_CLASSES.index(c["window_class"]) < WINDOW_CLASSES.index(prev["window_class"]):
                merged = dict(c)
                merged["windows"] = list((prev or {}).get("windows") or []) + list(c.get("windows") or [])
                out[key] = merged
            else:
                prev["windows"] = list(prev.get("windows") or []) + list(c.get("windows") or [])
    return out, unmatched


def table_rules(candidates: dict | None, tables: list[dict], decisions: list[dict]) -> dict:
    """Per extracted table: class and time cutoff for the lower and candidate scenarios."""
    widen_all = any(d.get("widen_all") for d in decisions)
    widened = {_norm(x) for d in decisions for x in (d.get("widen") or [])}
    ignore_time = any(d.get("ignore_time_windows") for d in decisions)
    mapping, unmatched = map_tables(candidates or {"tables": []}, tables)
    rules = {}
    for t in tables:
        key = (t["source_id"], t["slug"])
        c = mapping.get(key)
        cls = c["window_class"] if c else "not_covered"
        names = {_norm(f"{t.get('database')}.{t.get('table')}"), _norm(t.get("table")), _norm(t.get("slug"))}
        is_widened = widen_all or bool(names & widened)
        cutoff = None
        if c and not ignore_time and not is_widened:
            ends = [_window_end(w) for w in c.get("windows") or []]
            if ends and all(e is not None for e in ends):
                cutoff = max(ends)
        rules[key] = {"class": cls, "widened": is_widened, "cutoff": cutoff,
                      "consequence_class": (c or {}).get("consequence_class")}
    return {"rules": rules, "unmatched": unmatched}


def scenario_sql(rules: dict, scenario: str) -> str:
    """SQL predicate over person_tables (source_id, slug, min_date, n_null_date) for one scenario."""
    if scenario == "upper":
        return "TRUE"
    allowed = ("confirmed",) if scenario == "lower" else ("confirmed", "possible")
    terms = []
    for (sid, slug), r in sorted(rules.items()):
        if not (r["class"] in allowed or r["widened"]):
            continue
        cond = f"(source_id = '{sid}' AND slug = '{slug}'"
        if r["cutoff"] is not None:
            cond += f" AND (min_date IS NULL OR min_date <= DATE '{r['cutoff'].isoformat()}' OR n_null_date > 0)"
        terms.append(cond + ")")
    return "(" + " OR ".join(terms) + ")" if terms else "FALSE"


def load_candidates(store) -> dict | None:
    return store.read_json(CANDIDATES) if store.exists(CANDIDATES) else None


def load_decisions(store) -> list[dict]:
    return store.read_json(DECISIONS)["decisions"] if store.exists(DECISIONS) else []


def record(store, *, candidates_raw: bytes | None, reason: str, actor: str, widen: list[str], widen_all: bool,
           ignore_time_windows: bool, clear: bool = False) -> dict:
    if not reason or not reason.strip():
        raise ConfigError("a scoping decision needs a reason")
    decisions = load_decisions(store)
    entry = {"decision_id": f"SD-{len(decisions) + 1:03d}", "actor": actor, "reason": reason.strip()[:300],
             "widen": sorted(set(widen)), "widen_all": bool(widen_all), "ignore_time_windows": bool(ignore_time_windows)}
    if clear:
        entry["kind"] = "clear_candidates"
        entry["candidates_sha256"] = None
        store.delete(CANDIDATES)
    elif candidates_raw is not None:
        doc = parse(candidates_raw)
        entry["kind"] = "constrain_to_candidates"
        entry["candidates_sha256"] = sha256_hex(candidates_raw)
        entry["candidates_canonical_sha256"] = sha256_hex(canonical_bytes(doc))
        store.write_json(CANDIDATES, doc)
    else:
        if not (widen or widen_all or ignore_time_windows):
            raise ConfigError("nothing to record: pass --candidates, --widen, --widen-all or --ignore-time-windows")
        entry["kind"] = "widen"
        entry["candidates_sha256"] = None
    decisions.append(entry)
    store.write_json(DECISIONS, {"decisions": decisions})
    return entry
