"""File readers: CSV / TSV / XLSX / JSON Lines / JSON arrays, encrypted copies, bounds and malformed rows."""

import json
import zipfile

import ingest_helpers as H
import pytest
import yaml

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.ingest.config import IngestLimits
from tripline_scope.ingest.files import FileReader
from tripline_scope.ingest.model import assign_slugs


@pytest.fixture
def op(case_dir):
    testing.login("olivia")
    return case_dir


def _reader(case_dir, sid, **lim):
    case = Case(case_dir)
    return FileReader(case, open_store(case, Home()), case.source(sid), IngestLimits(**lim))


def _all(reader, table, batch=7):
    rows = []
    for b in reader.iter_batches(table, batch):
        rows.extend(b.to_pylist())
    return rows


def test_tsv_semicolon_csv_and_cp1252(op, tmp_path):
    rows = H.make_dataset(30)["patients"]
    tsv = H.write_csv(tmp_path / "a" / "pats.tsv", rows, delimiter="\t")
    semi = tmp_path / "b" / "pats.csv"
    semi.parent.mkdir()
    semi.write_bytes("Naam;Van;Kommentaar\nZoë;Müller;café\nJan;Botha;\n".encode("cp1252"))
    sid = H.add_source(op, tsv, "tsv")
    sid2 = H.add_source(op, semi, "csv")
    r = _reader(op, sid)
    (t,) = r.tables()
    assert [c.name for c in t.columns][:3] == ["PatientID", "FirstNames", "Surname"]
    data = _all(r, t)
    assert len(data) == 30 and data[0]["c0"] == "P000001"
    assert r.table_stats(t)["malformed_rows"] == 0
    r2 = _reader(op, sid2)
    (t2,) = r2.tables()
    assert [c.name for c in t2.columns] == ["Naam", "Van", "Kommentaar"]
    data2 = _all(r2, t2)
    assert data2[0] == {"c0": "Zoë", "c1": "Müller", "c2": "café"} and data2[1]["c2"] is None


def test_malformed_rows_counted_not_echoed(op, tmp_path):
    f = tmp_path / "m" / "bad.csv"
    f.parent.mkdir()
    f.write_text("id,name,phone\n1,Alpha,0821234567\n2,Beta\n3,Gamma,0831234567,EXTRA_SECRET_8001015009087\n")
    sid = H.add_source(op, f, "csv")
    r = _reader(op, sid)
    (t,) = r.tables()
    rows = _all(r, t)
    assert len(rows) == 3 and rows[1]["c2"] is None
    assert r.table_stats(t)["malformed_rows"] == 2
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(op)])
    assert rc == 0, err
    assert json.loads(out)["sources"][0]["malformed_rows"] == 2
    assert "EXTRA_SECRET" not in out + err and "8001015009087" not in out + err


def test_headerless_leak_sample_gets_positional_names(op, tmp_path):
    rows = H.make_dataset(20)["patients"]
    f = tmp_path / "leak" / "leak.csv"
    f.parent.mkdir()
    f.write_text("\n".join(",".join([r["Surname"], r["IDNumber"] or "", r["CellNo"]]) for r in rows) + "\n")
    sid = H.add_source(op, f, "csv", role="leak_sample", copy=True)
    r = _reader(op, sid)
    (t,) = r.tables()
    assert [c.name for c in t.columns] == ["column_1", "column_2", "column_3"]
    assert len(_all(r, t)) == 20          # the first row is data, not a header
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(op)])
    assert rc == 0, err
    store = open_store(Case(op), Home())
    doc = store.read_json(f"work/discovery/{sid}.json")
    cats = {c["name"]: c["category"] for c in doc["tables"][0]["columns"]}
    assert cats["column_2"] == "sa_id" and cats["column_3"] == "phone"   # value evidence alone


def test_xlsx_sheets_numbers_and_dates(op, tmp_path):
    import datetime as dt

    data = H.make_dataset(25)
    pats = [dict(r, IDNumber=int(r["IDNumber"]) if r["IDNumber"] else None,
                 DateOfBirth=dt.datetime.strptime(r["DateOfBirth"], "%d/%m/%Y")) for r in data["patients"]]
    x = H.write_xlsx(tmp_path / "x" / "lab.xlsx", {"Patients": pats, "Results": data["results"]})
    sid = H.add_source(op, x, "xlsx")
    r = _reader(op, sid)
    tabs = r.tables()
    assign_slugs(tabs)
    assert [t.name for t in tabs] == ["lab.Patients", "lab.Results"]
    pt = tabs[0]
    idcol = next(c for c in pt.columns if c.name == "IDNumber")
    assert idcol.numeric is True
    rows = _all(r, pt)
    assert rows[0]["c4"] == pats[0]["DateOfBirth"].date().isoformat()
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(op)])
    assert rc == 0, err
    store = open_store(Case(op), Home())
    doc = store.read_json(f"work/discovery/{sid}.json")
    pdoc = next(t for t in doc["tables"] if t["slug"] == "lab_patients")
    cols = {c["name"]: c for c in pdoc["columns"]}
    assert cols["IDNumber"]["category"] == "sa_id" and cols["IDNumber"]["match_rate"] == 1.0
    assert cols["DateOfBirth"]["category"] == "dob"


def test_xlsx_zip_bomb_refused(op, tmp_path):
    bomb = tmp_path / "z" / "bomb.xlsx"
    bomb.parent.mkdir()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/worksheets/sheet1.xml", b"0" * (5 * 1024 * 1024))
    sid = H.add_source(op, bomb, "xlsx")
    with pytest.raises(ConfigError, match="compression ratio|expands"):
        _reader(op, sid).tables()


def test_jsonl_and_json_array_encrypted_copies(op, tmp_path):
    data = H.make_dataset(15)
    nested = [{"patient": {"id": r["PatientID"], "id_number": r["IDNumber"]}, "contact": {"cell": r["CellNo"]},
               "tags": ["a", "b"]} for r in data["patients"]]
    jl = tmp_path / "j" / "p.jsonl"
    jl.parent.mkdir()
    jl.write_text("\n".join(json.dumps(x) for x in nested) + "\nnot json\n[1,2]\n")
    ja = tmp_path / "j" / "p.json"
    ja.write_text(json.dumps({"records": nested}))
    sid = H.add_source(op, jl, "jsonl", copy=True)
    sid2 = H.add_source(op, ja, "json", copy=True)
    r = _reader(op, sid)
    (t,) = r.tables()
    assert [c.name for c in t.columns] == ["patient.id", "patient.id_number", "contact.cell", "tags"]
    rows = _all(r, t)
    assert len(rows) == 15 and r.table_stats(t)["malformed_rows"] == 2
    assert rows[0]["c3"] == '["a", "b"]'
    r2 = _reader(op, sid2)
    (t2,) = r2.tables()
    assert len(_all(r2, t2)) == 15
    # no plaintext copy of the sources anywhere in the case directory
    for p in (op / "sources").rglob("*"):
        if p.is_file() and p.suffix == ".tse":
            assert b"P000001" not in p.read_bytes()


def test_bounds_rows_and_bytes(op, tmp_path):
    rows = H.make_dataset(40)["patients"]
    f = H.write_csv(tmp_path / "b" / "p.csv", rows)
    sid = H.add_source(op, f, "csv")
    r = _reader(op, sid, max_rows_per_table=10)
    (t,) = r.tables()
    with pytest.raises(ConfigError, match="more rows than the configured limit"):
        _all(r, t)
    r = _reader(op, sid, max_bytes_per_file=100)
    with pytest.raises(ConfigError, match="larger than the configured limit"):
        r.tables()
    # installation limits apply to the CLI too
    home = Home()
    cfg = yaml.safe_load((home.root / "config.yaml").read_text())
    cfg["ingest"] = {"max_rows_per_table": 10}
    (home.root / "config.yaml").write_text(yaml.safe_dump(cfg))
    rc, out, err = testing.run_cli(["ingest", "--case", str(op)])
    assert rc == 2 and "limit" in err
    cfg["ingest"] = {"bogus_setting": 1}
    (home.root / "config.yaml").write_text(yaml.safe_dump(cfg))
    rc, out, err = testing.run_cli(["ingest", "--case", str(op)])
    assert rc == 2 and "unknown ingest setting" in err


def test_sample_and_batch_options(op, tmp_path):
    data = H.make_dataset(120)
    f = H.write_csv(tmp_path / "s" / "patients.csv", data["patients"])
    sid = H.add_source(op, f, "csv")
    rc, out, err = testing.run_cli(["--json", "discover", "--case", str(op), "--sample-rows", "25",
                                    "--batch-rows", "13"])
    assert rc == 0, err
    res = json.loads(out)["sources"][0]
    assert res["rows"] == 120 and res["categories"]["sa_id"] == 1
    store = open_store(Case(op), Home())
    doc = store.read_json(f"work/discovery/{sid}.json")
    assert doc["sample_rows"] == 25 and doc["tables"][0]["sampled_rows"] == 25
    assert not store.exists(f"work/extract/{sid}/manifest.json")   # discover does not extract
    rc, out, err = testing.run_cli(["--json", "ingest", "--case", str(op), "--source", sid, "--tables", "nope"])
    assert rc == 2
