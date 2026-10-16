"""Native EVTX: a file produced by the test-only writer (from the published layout) is read with ``evtx`` and
must give exactly the same normalised events as the wevtutil XML export of the same events."""

import io
import json

from evtx_writer import write_evtx
from paths_helpers import build_case

from tripline_scope.paths.parsers import windows
from tripline_scope.paths.parsers.base import ParseContext
from tripline_scope.paths.timenorm import parse_iso


def _ctx(fmt):
    return ParseContext(source_id="SRC-T", family="win_security", fmt=fmt, host=None, options={}, mapping=None,
                        sql_fp=str, file_fp=lambda s: "f" * 16)


def _strip(recs):
    return [{k: (v[0].isoformat() if k == "_ts" else v) for k, v in r.items() if k not in ("_raw", "_loc")} for r in recs]


def _events_from_xml(path):
    out = []
    for info in windows._xml_events(_ctx("xml"), io.BytesIO(path.read_bytes()), path.name):
        out.append({"ts": parse_iso(info["TimeCreated"])[0], "EventID": int(info["EventID"]),
                    "computer": info["Computer"], "data": info["data"]})
    return out


def test_evtx_equals_xml_export(acceptance_dir, tmp_path):
    xml = acceptance_dir / "windows" / "labsql02_security.xml"
    events = _events_from_xml(xml)
    assert len(events) > 500
    evtx_path = tmp_path / "labsql02.evtx"
    write_evtx(evtx_path, events)
    from evtx import PyEvtxParser

    assert sum(1 for _ in PyEvtxParser(str(evtx_path), validate_checksums=True).records()) == len(events)
    a = _strip(windows.parse(_ctx("xml"), io.BytesIO(xml.read_bytes()), xml.name))
    c = _ctx("evtx")
    b = _strip(windows.parse(c, io.BytesIO(evtx_path.read_bytes()), evtx_path.name))
    assert c.failures == 0 and a == b


def test_evtx_ingest_and_corruption(acceptance_dir, tmp_path):
    events = _events_from_xml(acceptance_dir / "windows" / "dc01_security.xml")
    d = tmp_path / "logs"
    d.mkdir()
    write_evtx(d / "dc01.evtx", events)
    bad = bytearray((d / "dc01.evtx").read_bytes())
    bad[4096 + 512 + 40:4096 + 512 + 60] = b"\xff" * 20          # damage the first record of the first chunk
    (d / "damaged.evtx").write_bytes(bytes(bad))
    (d / "logs.yaml").write_text(json.dumps({
        "schema": "tripline.logs-manifest/v1",
        "defaults": {"supplied_by": "test", "received_at": "2026-09-15T08:00:00Z", "legal_basis": "test"},
        "sources": [{"id": "dc01-evtx", "family": "win_security", "format": "evtx", "path": "dc01.evtx"},
                    {"id": "damaged", "family": "win_security", "format": "evtx", "path": "damaged.evtx"}]}))
    ns = build_case(tmp_path / "inst", d, analyse=False)
    good = next(s for s in ns.ingest["sources"] if s["source_id"] == "SRC-001")
    assert good["events"] == len(events) and good["parse_failures"] == 0
    dmg = next(s for s in ns.ingest["sources"] if s["source_id"] == "SRC-002")
    assert dmg["parse_failures"] >= 1 and dmg["events"] < len(events)
