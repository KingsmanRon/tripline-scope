"""Link rules on hand-made records embedded in a synthetic background (so the model has data to learn from)."""

import datetime as dt
import json

from conftest import c, cli, ingest
from tripline_scope import testing
from tripline_scope.core import custody
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.home import Home
from tripline_scope.core.identifiers import make_sa_id
from tripline_scope.core.store import open_store
from tripline_scope.scope import run as R
from tripline_scope.scope.fixtures import write_rows_as_extract

D = dt.date
ID1 = make_sa_id(D(1971, 3, 4), 4321)
ID2 = make_sa_id(D(1950, 5, 5), 1234)
ID3 = make_sa_id(D(1950, 5, 5), 1235)
PH = "+27820000004"

ROWS = {
    "det1": dict(first_name="Quintavius", last_name="Abernathy", dob=D(1971, 3, 4), sa_id=ID1, phone="+27820000001"),
    "det2": dict(first_name="Quintavius", last_name="Abernathi", dob=D(1971, 3, 4), sa_id=ID1),
    "sw1": dict(first_name="Ignatius", last_name="Vorsterbosch", dob=D(1962, 7, 21), phone="+27820000002", sex="M"),
    "sw2": dict(first_name="Vorsterbosch", last_name="Ignatius", dob=D(1962, 7, 21), phone="+27820000002", sex="M"),
    "md1": dict(first_name="Xanthe", last_name="Orlovsky", dob=D(1985, 11, 30), email="xanthe.o@example.org", sex="F"),
    "md2": dict(first_name="Xanthe", last_name="Pritchard", maiden_name="Orlovsky", dob=D(1985, 11, 30),
                email="xanthe.o@example.org", sex="F"),
    "ty1": dict(first_name="Yolanda", last_name="Vermaakz", dob=D(1993, 2, 17), phone="+27820000003", postal_code="7700"),
    "ty2": dict(first_name="Yolanda", last_name="Vermaaks", dob=D(1993, 2, 17), phone="+27820000003", postal_code="7700"),
    "tw1": dict(first_name="Oksana", last_name="Kovalenko", dob=D(2015, 6, 10), phone=PH, postal_code="1234",
                guardian_name="Iryna Kovalenko", guardian_phone=PH, sex="F"),
    "tw2": dict(first_name="Maryna", last_name="Kovalenko", dob=D(2015, 6, 10), phone=PH, postal_code="1234",
                guardian_name="Iryna Kovalenko", guardian_phone=PH, sex="F"),
    "gd": dict(first_name="Iryna", last_name="Kovalenko", dob=D(1984, 1, 20), phone=PH, postal_code="1234", sex="F"),
    "pc1": dict(first_name="Bohdan", last_name="Kovalenko", dob=D(1975, 9, 9), phone=PH, postal_code="1234", sex="M"),
    "pc2": dict(first_name="Bohdan", last_name="Kovalenko", dob=D(2005, 9, 9), phone=PH, postal_code="1234", sex="M"),
    "unres": dict(last_name="Unknown", phone="+27820000099"),
    "X": dict(first_name="Leopoldine", last_name="Wexford", dob=D(1950, 5, 5), sa_id=ID2, phone="+27820000005"),
    "Y": dict(first_name="Leopoldine", last_name="Wexford", dob=D(1950, 5, 5), phone="+27820000005"),
    "Z": dict(first_name="Leopoldine", last_name="Wexford", dob=D(1950, 5, 5), sa_id=ID3, phone="+27820000005"),
}


def add_manual(case_dir, tmp_path):
    testing.login("olivia")
    case = Case(case_dir)
    f = tmp_path / "manual.csv"
    f.write_text("placeholder\n1\n")
    names = list(ROWS)
    rows = [dict(ROWS[n], local_patient_key=f"M{i}") for i, n in enumerate(names)]
    with command("test manual source", home=Home(), case=case, role="operator") as ctx:
        rec = custody.add_source(case, ctx.store, kind="csv", paths=[f], label="manual records",
                                 evidence_role="system_copy", legal_basis="test", supplied_by="test",
                                 received_at="2026-09-15T00:00:00Z", registered_by=ctx.actor)
        sid = rec["source_id"]
        write_rows_as_extract(ctx.store, sid, [{"database": "manualdb", "table": "patients", "role": "identity",
                                                "rows": rows}])
    return {n: f"{sid}|patients|{i}" for i, n in enumerate(names)}


def person_of(case_dir):
    store = open_store(Case(case_dir), Home())
    rows = store.read_table(R.PERSON_ROWS).to_pylist()
    people = {p["person_key"]: p for p in store.read_table(R.PEOPLE).to_pylist()}
    m = {r["row_key"]: r["person_key"] for r in rows}
    return m, people, store


def test_link_rules_guards_overmerge_and_replay(case_dir, synth_dir, tmp_path):
    ingest(case_dir, synth_dir)
    keys = add_manual(case_dir, tmp_path)
    rc, out, err = cli(["scope", "match"] + c(case_dir), "olivia")
    m, people, store = person_of(case_dir)
    same = lambda a, b: m[keys[a]] == m[keys[b]]  # noqa: E731
    assert same("det1", "det2") and people[m[keys["det1"]]]["confidence"] in ("deterministic", "auto-linked")
    assert same("sw1", "sw2"), "swapped first name and surname"
    assert same("md1", "md2"), "maiden and married surname"
    assert same("ty1", "ty2"), "surname typo"
    assert not same("tw1", "tw2"), "twins sharing a phone must not merge"
    assert not same("tw1", "gd") and not same("tw2", "gd"), "child and guardian must not merge"
    assert not same("pc1", "pc2"), "parent and child with the same name must not merge"
    assert keys["unres"] not in m, "rows without usable identifiers are never forced into people"
    tables = store.read_json(R.TABLES)["tables"]
    manual = [t for t in tables if t["database"] == "manualdb"][0]
    assert manual["identity_rows_without_identifiers"] == 1
    # child with guardian contact is routed to the guardian
    assert people[m[keys["tw1"]]]["segment"] == "minor_guardian_routed"
    # over-merge guard: X-Y and Y-Z would chain two different valid IDs; split and queued for review
    assert len({m[keys["X"]], m[keys["Y"]], m[keys["Z"]]}) == 3
    assert people[m[keys["Y"]]]["confidence"] == "probabilistic-unreviewed"
    queue = store.read_json("review/queue.json")["items"]
    om = [q for q in queue if q["reason"] == "over_merge_guard"]
    pairs = {frozenset((q["key_l"], q["key_r"])): q for q in om}
    xy, yz = frozenset((keys["X"], keys["Y"])), frozenset((keys["Y"], keys["Z"]))
    assert xy in pairs and yz in pairs
    # a reviewer decides from a file; decisions replay on every run
    dec = tmp_path / "decisions.jsonl"
    dec.write_text("\n".join(json.dumps({"pair_key": pairs[p]["pair_key"], "decision": d})
                             for p, d in ((xy, "same"), (yz, "different"))))
    rc, out, err = cli(["scope", "decide"] + c(case_dir) + ["--file", str(dec)], "rami")
    assert out["recorded"] == 2 and out["simulated"] is False
    for _ in range(2):
        cli(["scope", "match"] + c(case_dir), "olivia")
        m, people, store = person_of(case_dir)
        assert m[keys["X"]] == m[keys["Y"]] != m[keys["Z"]]
        assert people[m[keys["X"]]]["confidence"] == "reviewed"
        queue = store.read_json("review/queue.json")["items"]
        assert not [q for q in queue if frozenset((q["key_l"], q["key_r"])) in (xy, yz)]


def test_decide_requires_reviewer_and_known_pairs(scoped, tmp_path):
    case_dir, _ = scoped
    cli(["scope", "match"] + c(case_dir), "olivia")
    f = tmp_path / "d.jsonl"
    f.write_text(json.dumps({"pair_key": "0" * 32, "decision": "same"}))
    rc, out, err = cli(["scope", "decide"] + c(case_dir) + ["--file", str(f)], "olivia", ok=False)
    assert rc == 3  # operator is not a reviewer
    rc, out, err = cli(["scope", "decide"] + c(case_dir) + ["--file", str(f)], "rami", ok=False)
    assert rc == 2  # unknown pair
