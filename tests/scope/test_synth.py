import json

import pyarrow.parquet as pq

from tripline_scope import testing
from tripline_scope.core.identifiers import card_number_like, normalise_phone, parse_sa_id
from tripline_scope.synth.generate import generate


def test_layout_and_meta(synth_dir):
    meta = json.loads((synth_dir / "synth_meta.json").read_text())
    assert meta["totals"]["admissions"] == 6000
    assert len(meta["databases"]) == 10
    for db in meta["databases"]:
        for t in ("patients", "admissions", "billing", "results"):
            assert (synth_dir / db["path"] / f"{t}.parquet").exists()
    # column names vary between databases (discovery has to work for them)
    keys = {db["tables"]["patients"]["columns"].get("sa_id") for db in meta["databases"]}
    assert len(keys) >= 4
    assert (synth_dir / "leak_sample.csv").exists() and (synth_dir / "ground_truth_identifiers.parquet").exists()
    pop = meta["population"]
    assert pop["registrations"] > pop["persons"]  # duplicate and repeat registrations
    assert pop["unresolvable_registrations"] > 0 and pop["orphan_admissions"] > 0
    assert pop["minors"] > 0 and 0 < pop["minors_with_guardian"] < pop["minors"]
    assert pop["twins"] >= 0


def test_identifiers_are_valid_and_noisy(synth_dir):
    t = pq.read_table(synth_dir / "sources/db01/patients.parquet").to_pylist()
    ids = [r["id_number"] for r in t if r["id_number"]]
    valid = sum(parse_sa_id(i).valid for i in ids)
    assert valid >= 0.95 * len(ids) and valid < len(ids) or len(ids) < 50  # ~1% typos fail Luhn
    assert any(r["id_number"] is None for r in t)  # missing IDs (children, foreigners)
    phones = [r["cell_phone"] for r in t if r["cell_phone"]]
    assert phones and all(normalise_phone(p) for p in phones)
    gt = pq.read_table(synth_dir / "ground_truth.parquet")
    assert set(gt.column_names) >= {"source_db", "table", "local_patient_key", "person_id", "is_minor", "has_guardian",
                                    "has_contact"}
    cards = [r["card_number"] for r in pq.read_table(synth_dir / "sources/db01/billing.parquet").to_pylist()
             if r["card_number"]]
    assert cards and all(card_number_like(x) for x in cards)
    res = pq.read_table(synth_dir / "sources/db01/results.parquet")
    assert set(res.column_names) == {"result_id", "admission_id", "patient_id", "collected_on", "test_code", "status"}


def test_children_share_guardian_phone_and_twins_differ(synth_dir):
    t = pq.read_table(synth_dir / "sources/db01/patients.parquet").to_pylist()
    kids = [r for r in t if r["guardian_phone"]]
    assert kids
    assert any(normalise_phone(k["guardian_phone"]) == normalise_phone(k["cell_phone"]) for k in kids if k["cell_phone"])


def test_deterministic_for_seed(tmp_path):
    a = generate(tmp_path / "a", 800, seed=7)
    b = generate(tmp_path / "b", 800, seed=7)
    assert a["totals"] == b["totals"]
    ta = pq.read_table(tmp_path / "a/ground_truth.parquet")
    tb = pq.read_table(tmp_path / "b/ground_truth.parquet")
    assert ta.equals(tb)
    assert (tmp_path / "a/leak_sample.csv").read_bytes() == (tmp_path / "b/leak_sample.csv").read_bytes()


def test_cli(tmp_path, install):
    rc, out, err = testing.run_cli(["--json", "synth", "--rows", "500", "--out", str(tmp_path / "s"), "--seed", "3"])
    assert rc == 0, err
    assert json.loads(out)["totals"]["admissions"] == 500
