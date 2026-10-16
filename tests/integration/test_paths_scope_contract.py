"""Module B's scope-candidates (every window class it can emit) are accepted by Module C and never shrink the
upper scenario."""

import json

from tripline_scope.scope import constrain

TABLES = [
    {"source_id": "SRC-003", "slug": "dbo_patients", "database": "LabDB03", "table": "dbo.patients"},
    {"source_id": "SRC-007", "slug": "dbo_patients", "database": "LabDB07", "table": "dbo.patients"},
    {"source_id": "SRC-009", "slug": "dbo_patients", "database": "LabDB09", "table": "dbo.patients"},
    {"source_id": "SRC-001", "slug": "dbo_patients", "database": "LabDB01", "table": "dbo.patients"},
    {"source_id": "SRC-002", "slug": "dbo_patients", "database": "LabDB02", "table": "dbo.patients"},
]


def _doc():
    w = [{"class": "confirmed", "start": "2026-09-03T00:00:00Z", "end": "2026-09-05T00:00:00Z"}]
    return {"schema": constrain.SCHEMA, "case_id": "X", "tables": [
        {"database": "LabDB03", "table": "dbo.patients", "window_class": "confirmed", "windows": w},
        {"database": "labdb07", "table": "PATIENTS", "window_class": "possible", "windows": w},
        {"database": "LabDB09", "table": "dbo.patients", "window_class": "not_assessable", "windows": []},
        {"database": "LabDB01", "table": "dbo.patients", "window_class": "none_observed", "windows": []},
    ]}


def test_every_module_b_window_class_is_accepted_and_scenarios_nest():
    doc = constrain.parse(json.dumps(_doc()).encode())
    rules = constrain.table_rules(doc, TABLES, [])["rules"]
    assert rules[("SRC-001", "dbo_patients")]["class"] == "none_observed"
    assert rules[("SRC-002", "dbo_patients")]["class"] == "not_covered"
    lower = constrain.scenario_sql(rules, "lower")
    cand = constrain.scenario_sql(rules, "candidate")
    assert "SRC-003" in lower and "SRC-007" not in lower and "SRC-009" not in lower
    assert "SRC-003" in cand and "SRC-007" in cand
    assert "SRC-001" not in cand and "SRC-002" not in cand
    assert constrain.scenario_sql(rules, "upper") == "TRUE"  # absent or quiet logs never exclude anyone
