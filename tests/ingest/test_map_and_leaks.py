"""``tscope map`` readiness data map, release by the approver, and leak checks on every output."""

import json

import ingest_helpers as H
import pyarrow as pa
import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.pdf import pdf_text
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.store import open_store
from tscope_verify.report import verify_chain

SENSITIVE_KEYS = ["IDNumber", "CellNo", "Email", "MedAidNo", "CardNumber", "BankAccountNo", "Surname", "FirstNames",
                  "Notes", "Comment", "Address1", "Ref13", "BatchCode", "Token16"]


@pytest.fixture
def mapped(case_dir, tmp_path):
    testing.login("olivia")
    data = H.make_dataset(150, seed=31)
    paths = [H.write_csv(tmp_path / "exp" / f"{n}.csv", rows) for n, rows in data.items()]
    sid = H.add_source(case_dir, paths, "csv")
    leak = H.write_jsonl(tmp_path / "leak" / "dump.jsonl", data["patients"][:40])
    sid2 = H.add_source(case_dir, leak, "jsonl", role="leak_sample", copy=True)
    return case_dir, data, (sid, sid2)


def test_map_release_and_no_values_anywhere(mapped):
    case_dir, data, (sid, sid2) = mapped
    console = []
    rc, out, err = testing.run_cli(["--json", "map", "--case", str(case_dir)])
    assert rc == 0, err
    console += [out, err]
    res = json.loads(out)
    assert res["sources"] == 2 and res["groups"]["identity_numbers"] == 2 and res["groups"]["payment"] == 1
    assert res["groups"]["clinical"] >= 2
    draft_dir = case_dir / "reports" / "datamap" / "drafts" / res["draft_id"]
    body = json.loads((draft_dir / "report.json").read_text())
    ids = {(s["source_id"], t["table"]): t for s in body["sources"] for t in s["tables"]}
    pat = ids[(sid, "patients")]
    assert pat["row_count"] == 150 and "IDNumber" in pat["groups"]["identity_numbers"]
    assert "CellNo" in pat["groups"]["contact"] and "MedAidNo" in pat["groups"]["medical_aid"]
    assert ids[(sid, "billing")]["groups"]["payment"] == ["BankAccountNo", "CardNumber"]
    assert ids[(sid, "results")]["groups"]["clinical"] == ["ICD10", "Notes", "Result", "TestCode"]
    assert ids[(sid2, "dump")]["row_count"] == 40
    assert body["config_sha256"] and body["method_version"] and body["inputs"][sid]["discovery_sha256"]

    # a second map from the same discovery gives a byte-identical report body
    first = (draft_dir / "report.json").read_bytes()
    rc, out, err = testing.run_cli(["--json", "map", "--case", str(case_dir)])
    assert rc == 0, err
    console += [out, err]
    assert json.loads(out)["draft_id"] == res["draft_id"]
    assert (draft_dir / "report.json").read_bytes() == first

    # approver releases; the chain verifies
    testing.login("ines")
    rc, out, err = testing.run_cli(["--json", "release", "--case", str(case_dir), "--kind", "datamap",
                                    "--approver", "ines"])
    assert rc == 0, err
    console += [out, err]
    vdir = case_dir / "reports" / "datamap" / "v0001"
    assert verify_chain(case_dir / "reports" / "datamap", hospital_keys=Home().trusted_hospital_keys()).ok
    rc, out, err = testing.run_cli(["verify", "--case", str(case_dir)])
    assert rc == 0, out + err

    # no identifier-like content and none of the synthetic values in any output
    values = H.all_values(data, SENSITIVE_KEYS)
    texts = {
        "report.json": (vdir / "report.json").read_text(),
        "report.pdf": pdf_text((vdir / "report.pdf").read_bytes()),
        "datamap.csv": (vdir / "attachments" / "datamap.csv").read_text(),
        "audit.log": (case_dir / "audit.log").read_text(),
        "console": "\n".join(console),
    }
    for name, text in texts.items():
        assert find_identifier_like(text) == [], name
        assert H.scan_text_for(text, values) == [], name
    assert "Readiness data map" in texts["report.pdf"] and "IDNumber" in texts["report.pdf"]


def test_ingest_outputs_never_hold_clinical_card_or_bank_values(mapped):
    case_dir, data, (sid, sid2) = mapped
    console = []
    rc, out, err = testing.run_cli(["ingest", "--case", str(case_dir)])
    assert rc == 0, err
    console += [out, err]
    rc, out, err = testing.run_cli(["ingest", "status", "--case", str(case_dir)])
    assert rc == 0, err
    console += [out, err]
    store = open_store(Case(case_dir), Home())
    forbidden = H.all_values(data, ["CardNumber", "BankAccountNo", "Notes", "Comment", "Result", "AccountNo",
                                    "Ref13", "BatchCode", "Token16", "Scheme"])
    forbidden |= {r["ICD10"] for r in data["results"]} | {r["TestCode"] for r in data["results"]}
    n = 0
    for s in (sid, sid2):
        m = store.read_json(f"work/extract/{s}/manifest.json")
        for e in m["tables"]:
            for part in e["parts"]:
                t = store.read_table(part)
                n += t.num_rows
                for col in t.column_names:
                    if pa.types.is_string(t.schema.field(col).type):
                        vals = {v for v in t.column(col).to_pylist() if v}
                        assert not (vals & forbidden), col
                        for v in vals:
                            assert not any(f in v for f in forbidden if len(f) >= 6), col
    assert n > 150
    # encrypted on disk: no plaintext Parquet magic or values in any working file
    for p in (case_dir / "work").rglob("*"):
        if p.is_file():
            raw = p.read_bytes()
            assert raw.startswith(b"TSENC1") and b"PAR1" not in raw[:64]
    for text in console + [(case_dir / "audit.log").read_text()]:
        assert find_identifier_like(text) == []
        assert H.scan_text_for(text, H.all_values(data, SENSITIVE_KEYS)) == []
