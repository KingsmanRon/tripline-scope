"""Helpers shared by the Module B tests (imported by conftest and the test modules)."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

from tripline_scope import testing

WINDOW = "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"


def _clear():
    for k in list(os.environ):
        if k.startswith("TSCOPE_"):
            del os.environ[k]


def build_case(base: Path, syn: Path, *, analyse: bool = True) -> SimpleNamespace:
    """Installation + case + ingest (+ analyse) for ``syn``; environment cleared afterwards."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("TSCOPE_")}
    _clear()
    try:
        env = testing.setup_installation(base)
        case_dir = testing.open_case(base)
        testing.login("olivia")
        rc, out, err = testing.run_cli(["--json", "paths", "ingest", "--case", str(case_dir),
                                        "--manifest", str(syn / "logs.yaml")])
        assert rc == 0, err
        ingest = json.loads(out)
        analysis = None
        if analyse:
            rc, out, err = testing.run_cli(["--json", "paths", "analyse", "--case", str(case_dir), "--window", WINDOW])
            assert rc == 0, err
            analysis = read_json(case_dir, "work/paths/analysis.json")
        return SimpleNamespace(env=env, case_dir=case_dir, ingest=ingest, analysis=analysis, syn=syn,
                               truth=json.loads((syn / "ground_truth.json").read_text()) if (syn / "ground_truth.json").exists() else {})
    finally:
        _clear()
        os.environ.update(saved)


def read_json(case_dir, rel):
    from tripline_scope.core.case import Case
    from tripline_scope.core.home import Home
    from tripline_scope.core.store import open_store

    return open_store(Case(case_dir), Home()).read_json(rel)


def activate(ns: SimpleNamespace, monkeypatch, user: str = "olivia") -> None:
    for k, v in ns.env.vars().items():
        monkeypatch.setenv(k, v)
    testing.login(user)


def find_units(analysis: dict, sel: dict) -> list[dict]:
    out = []
    for u in analysis["units"]:
        ok = True
        for k, v in sel.items():
            if k == "request_id":
                ok = ok and v in (u.get("request_ids") or [])
            elif k in ("account", "host"):
                ok = ok and (u.get(k) or "").lower() == v.lower()
            else:
                ok = ok and u.get(k) == v
        if ok:
            out.append(u)
    return out


def edges_between(analysis: dict, frm: dict, to: dict) -> list[dict]:
    a = {u["unit_id"] for u in find_units(analysis, frm)}
    b = {u["unit_id"] for u in find_units(analysis, to)}
    return [e for e in analysis["edges"] if e["from"] in a and e["to"] in b]
