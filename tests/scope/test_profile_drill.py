import pyarrow.parquet as pq
import yaml

from conftest import c, cli, ingest
from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.redact import find_identifier_like


def test_profile_saves_no_patient_data_and_applies(scoped, synth_dir, tmp_path):
    case_dir, _ = scoped
    case = Case(case_dir)
    case.config["column_overrides"] = {"SRC-001": {"patients": {"id_number": "sa_id", "surname": "last_name",
                                                                "first_name": "first_name", "date_of_birth": "dob"}}}
    case.config["matching"] = {"bands": {"auto_link": 0.997, "review": 0.85},
                               "name_variants": [["THEMBEKILE", "THEMBI"]]}
    case.save()
    rc, out, err = cli(["profile", "save"] + c(case_dir) + ["--name", "lab-default"], "olivia")
    path = Home().profiles_dir / "lab-default.yaml"
    text = path.read_text()
    assert not find_identifier_like(text)
    ids = pq.read_table(synth_dir / "ground_truth_identifiers.parquet")
    for col in ids.column_names:
        for v in ids.column(col).to_pylist()[:2000]:
            if v and len(v) >= 6:
                assert v not in text
    prof = yaml.safe_load(text)
    assert prof["matching"]["bands"] == {"auto_link": 0.997, "review": 0.85}
    assert prof["column_mappings"]["Synthetic lab database db01"]["patients"]["surname"] == "last_name"
    rc, shown, err = cli(["profile", "show", "--name", "lab-default"])
    assert shown["name"] == "lab-default"
    other = testing.open_case(tmp_path, "CASE-OTHER")
    rc, out, err = cli(["profile", "apply"] + c(other) + ["--name", "lab-default"], "olivia")
    assert Case(other).config["matching"]["bands"]["auto_link"] == 0.997
    rc, out, err = cli(["profile", "list"])
    assert out["profiles"] == ["lab-default"]


def test_drill_end_to_end_small(install, tmp_path, synth_dir):
    ready = testing.open_case(tmp_path, "CASE-READY", mode="readiness")
    case = Case(ready)
    case.config["column_overrides"] = {"SRC-001": {"pat": {"PatNo": "patient_key", "IdNo": "sa_id", "Given": "first_name",
                                                           "Family": "last_name", "Born": "dob", "Cell": "phone"}}}
    case.save()
    rc, out, err = cli(["drill"] + c(ready) + ["--rows", "3000", "--approver", "ines"], "olivia")
    assert out["failed_steps"] == [], out
    steps = out["steps"]
    for s in ("synth", "register and extract", "estimate", "match", "review (simulated)", "report", "notify build",
              "release (approver)", "notify export (approver)"):
        assert s in steps
    assert out["accuracy"]["pairwise_precision"] > 0.99 and out["accuracy"]["person_count_error"] < 0.02
    drafts = list((ready / "reports" / "drill" / "drafts").iterdir())
    assert drafts and (drafts[0] / "report.pdf").exists()
    ingest  # noqa: B018 - shared helper kept imported for parity with other modules
