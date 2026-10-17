"""Unified synthetic laboratory breach (docs/PLAN.md §14/§15, Workstream C), without SQL Server.

Module A findings come from the real scanner on the generated laboratory estate, Module B from the generated logs,
Module C from the generated records; cross-module joins resolve on shared asset ids and accounts; both scenarios'
classes hold; every case source is attested synthetic output.
"""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from tripline_scope import testing
from tripline_scope.core.canonical import sha256_file
from tripline_scope.core.case import Case
from tripline_scope.core.errors import IntegrityError
from tripline_scope.core.home import Home
from tripline_scope.core.reports import ReportStore
from tripline_scope.core.store import open_store
from tripline_scope.exposure import synthetic as estate_gen
from tripline_scope.investigator.synthetic import case_is_synthetic, registered
from tripline_scope.paths import synthetic as logs_gen
from tscope_verify.report import verify_chain

REPO = Path(__file__).resolve().parents[2]
CORROBORATED = "LabDB03.dbo.patients"  # same as the demo; Module C's leak sample is drawn from LabDB03

# Digests of the hospital estate written by the code before the estate parameter existed (commit 60bcfae), so
# estate="hospital" must stay byte-identical. Normalised only where the original output itself varies between
# runs: the workbook's creation timestamp (sheet values are compared instead) and the absolute output path.
HOSPITAL_DIGEST = {"baseline": "9c2edf0627adffa255017cdf19cc18c1d21dd6b517c4936b943f3ac1bb70877d",
                   "fixed": "bee6cd68dc6b6b128e52e2021f47176473fcffba7d90b07525f6559dd8659cde"}

SUSPECTED_CLASSES = {
    "LabDB01.dbo.results": "access_observed",
    "LabDB03.dbo.patients": "egress_suspected",
    "LabDB03.dbo.admissions": "egress_suspected",
    "LabDB05.dbo.billing": "export_or_staging_observed",
    "LabDB07.dbo.patients": "egress_suspected",
    "LabDB07.dbo.admissions": "egress_suspected",
    "LabDB07.dbo.results": "access_observed",
    **{f"LabDB09.dbo.{t}": "undetermined" for t in ("patients", "admissions", "billing", "results")},
}


def tree_digest(out: Path) -> str:
    import openpyxl

    h = hashlib.sha256()
    for p in sorted(out.rglob("*")):
        rel = p.relative_to(out).as_posix()
        if p.is_symlink():
            h.update(f"L {rel} {os.readlink(p).replace(str(out.resolve()), '<OUT>')}\n".encode())
            continue
        if not p.is_file():
            continue
        data = p.read_bytes()
        if p.suffix == ".xlsx" and p.name != "broken.xlsx":
            wb = openpyxl.load_workbook(io.BytesIO(data))
            data = json.dumps([[ws.title, [list(r) for r in ws.iter_rows(values_only=True)]] for ws in wb]).encode()
        if rel == "ground_truth.json":
            data = data.replace(str(out.resolve()).encode(), b"<OUT>")
        h.update(f"F {rel} {hashlib.sha256(data).hexdigest()}\n".encode())
    return h.hexdigest()


def table_classes(paths_report: dict) -> dict[str, str]:
    return {t["table"]: t["consequence_class"] for t in paths_report["tables"]}


def find(findings, rule, asset, **loc):
    return [f for f in findings if f["rule_id"] == rule and f["asset"]["asset_id"] == asset
            and all(f["location"].get(k) == v for k, v in loc.items())]


def files_of(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())


# ------------------------------------------------------------------------------------------------ Module A estate
@pytest.mark.parametrize("variant", ["baseline", "fixed"])
def test_hospital_estate_is_byte_identical_to_the_original(tmp_path, variant):
    estate_gen.build(tmp_path / "e", variant)
    assert tree_digest(tmp_path / "e") == HOSPITAL_DIGEST[variant]


def test_lab_estate_is_aligned_with_module_b_and_keeps_the_seeded_weaknesses(tmp_path):
    hosp = estate_gen.build(tmp_path / "h")
    lab = estate_gen.build(tmp_path / "l", estate="lab")
    assert lab["secrets"] == hosp["secrets"] and lab["sa_ids"] == hosp["sa_ids"]  # same seeded weaknesses
    assert [(f["rule_id"], f["path"]) for f in lab["file_findings"]] == \
        [(f["rule_id"], f["path"]) for f in hosp["file_findings"]]
    assert len(lab["db_findings"]) == len(hosp["db_findings"])
    import yaml

    from tripline_scope.core.assets import AssetMap

    amap = AssetMap.load(tmp_path / "l" / "assets.yaml")
    b = logs_gen.Generator(tmp_path / "b", "demo").manifest()
    for src in b["sources"]:
        if src.get("asset_id"):
            assert src["asset_id"] in amap.assets, src["asset_id"]
            for name in [src["host"], *src.get("host_ips", [])]:
                assert amap.resolve(name) == src["asset_id"], (name, src["asset_id"])
    for db in logs_gen.DBS:
        assert amap.resolve(db) == ("AST-LABSQL01" if db <= "LabDB05" else "AST-LABSQL02")
    assert amap.resolve("lis") == "AST-LISPG01" and amap.resolve("portal.lab.example") == "AST-WEB01"
    m = yaml.safe_load((tmp_path / "l" / "manifest.yaml").read_text())
    assert m["hospital_domains"] == ["lab.example"]
    assert {d["asset"] for d in m["databases"] if d.get("asset")} == {"AST-LABSQL01", "AST-LISPG01"}
    cat = json.loads((tmp_path / "l" / "catalog" / "labdb_mssql.json").read_text())
    assert cat["server"] == "LABSQL01" and cat["database"] == "LabDB03"
    names = {p["name"] for p in cat["queries"]["server_principals"]}
    assert {"LAB\\svc_backup", "vendor.support"} <= names and not any("HOSP" in n for n in names)
    # nothing of the hospital estate's names survives in the lab estate
    for f in files_of(tmp_path / "l"):
        text = f.read_bytes()
        assert b"hosp.example" not in text and b"HOSP\\" not in text, f
    assert not any(p.is_symlink() for p in (tmp_path / "l").rglob("*"))  # regular files only, all content-attested
    assert set(lab["key_weaknesses"]) == {"xp_cmdshell_enabled", "over_privileged_service_account", "audit_disabled",
                                          "stale_export", "exposed_credential", "supplier_access"}


def test_module_a_findings_come_from_the_scanner_on_the_lab_estate(suspected):
    rep, scan = suspected.exposure, suspected.scan
    assert scan["metrics"]["files_examined"] > 0 and scan["assessed_units"] > 0
    assert set(scan["sources"]) >= {"root:web01", "root:share01", "db:labsql01", "identity:supplier_register"}
    findings = rep["findings"]
    assert all(f["evidence_ids"] and f["source_ids"] for f in findings)
    # the five weakness types on the aligned assets
    assert find(findings, "A4.mssql-xp-cmdshell", "AST-LABSQL01", database="labsql01")
    assert find(findings, "A2.app-admin-rights", "AST-LABSQL01", principal="LAB\\svc_backup")
    assert find(findings, "A4.mssql-audit-disabled", "AST-LABSQL01")
    stale = find(findings, "A3.data-copy", "AST-FS01", root="share01", path="Lab/Exports/patients_2025-01.csv")
    assert stale and stale[0]["details"].get("stale") is True
    assert find(findings, "A1.db-connection-password", "AST-WEB01", root="web01", path="wwwroot/web.config")
    supplier = [f for f in findings if f["control_id"] == "A5" and f["location"].get("principal") == "vendor.support"]
    assert {f["rule_id"] for f in supplier} >= {"A5.supplier-excess-privilege", "A5.supplier-mfa-missing"}
    # every expected finding of the lab ground truth, with its asset
    for exp in suspected.estate_truth["file_findings"] + suspected.estate_truth["db_findings"]:
        hits = [f for f in findings if f["rule_id"] == exp["rule_id"]
                and (exp.get("root") is None or (f["location"].get("root"), f["location"].get("path"))
                     == (exp["root"], exp["path"]))
                and (exp.get("database") is None or f["location"].get("database") == exp["database"])
                and (exp.get("principal") is None or f["location"].get("principal") == exp["principal"])]
        assert hits, exp
        if exp.get("asset_id"):
            assert exp["asset_id"] in {f["asset"]["asset_id"] for f in hits}, exp
    for name, exp in suspected.estate_truth["key_weaknesses"].items():
        loc = {k: exp[k] for k in ("principal", "database", "root", "path") if k in exp}
        assert find(findings, exp["rule_id"], exp["asset_id"], **loc), name


def test_released_reports_verify(suspected, corroborated, as_env):
    for run in (suspected, corroborated):
        as_env(run)
        home = Home()
        for kind in ("exposure", "paths", "scope"):
            res = ReportStore(Case(run.case_dir)).verify(kind, home)
            assert res.ok, (run.scenario, kind, res.render())
            assert verify_chain(run.case_dir / "reports" / kind, hospital_keys=home.trusted_hospital_keys()).ok, \
                (run.scenario, kind)


# ------------------------------------------------------------------------------------------------ Module B
def test_module_b_processes_generated_logs_and_cross_references_module_a(suspected):
    paths, exposure = suspected.paths, suspected.exposure
    assert paths["counts"]["observed_access"]["tables"] > 0
    cont = paths["containment"]
    assert cont["module_a"]["status"] == "cross-referenced" and cont["module_a"]["released"] is True
    assert cont["module_a"]["report_sha256"] == hashlib.sha256(
        (suspected.exposure_dir / "report.json").read_bytes()).hexdigest()
    by_id = {f["finding_id"]: f for f in exposure["findings"]}
    linked = [r for r in cont["recommendations"] if r["module_a_refs"]]
    assert linked, "no Module B recommendation cross-references a Module A finding"
    for r in linked:
        assert r["requires_hospital_authorisation"] is True and r["executed"] is False
        for ref in r["module_a_refs"]:
            assert ref["finding_id"] in by_id  # refs resolve to findings of the released exposure report
    vendor = [r for r in linked if r["target"].get("label") == "LAB\\vendor.support"]
    assert vendor, "the unresolved supplier session is not linked to Module A's supplier findings"
    refs = {x["finding_id"] for x in vendor[0]["module_a_refs"]}
    assert {by_id[i]["rule_id"] for i in refs} >= {"A5.supplier-excess-privilege", "A5.supplier-mfa-missing"}
    assert all(by_id[i]["location"]["principal"] == "vendor.support" for i in refs)


@pytest.mark.xfail(strict=True, reason="paths/containment.py matches Module A findings on a top-level 'asset_id', but "
                   "released exposure findings carry it as 'asset.asset_id', so asset-keyed cross-references (xp_cmdshell, "
                   "VPN-to-database routes) never resolve against a real exposure report. Module B engine fix, outside "
                   "Workstream C; remove this marker when fixed.")
def test_xp_cmdshell_recommendation_cross_references_the_module_a_finding_on_the_same_asset(suspected):
    xp = [f["finding_id"] for f in suspected.exposure["findings"] if f["rule_id"] == "A4.mssql-xp-cmdshell"]
    rec = [r for r in suspected.paths["containment"]["recommendations"]
           if r["target"].get("description") == "xp_cmdshell on labsql01"]
    assert rec and rec[0]["target"]["asset_id"] == "AST-LABSQL01"
    assert set(xp) <= {x["finding_id"] for x in rec[0]["module_a_refs"]}


def test_suspected_classes(suspected):
    classes = table_classes(suspected.paths)
    for table, cls in SUSPECTED_CLASSES.items():
        assert classes.get(table) == cls, (table, classes.get(table))
    assert "exfiltration_evidenced" not in classes.values()
    assert suspected.paths["counts"]["confirmed_exfiltration"]["tables"] == "not determinable"
    assert not (suspected.logs / "evidence" / "leak_sample_index.csv").exists()
    assert suspected.logs_truth["corroborated_table"] is None


def test_corroborated_classes(corroborated):
    classes = table_classes(corroborated.paths)
    assert [t for t, c in classes.items() if c == "exfiltration_evidenced"] == [CORROBORATED]
    for table, cls in SUSPECTED_CLASSES.items():
        if table != CORROBORATED:
            assert classes.get(table) == cls, (table, classes.get(table))
    t = corroborated.logs_truth
    assert t["corroborated_table"] == CORROBORATED
    assert t["expected_table_classes"][CORROBORATED] == "exfiltration_evidenced"
    assert t["expected_table_classes"]["LabDB07.dbo.patients"] == "egress_suspected"
    assert t["fixtures"]["iv_corroborated_external_copy"]["table"] == CORROBORATED
    idx = (corroborated.logs / "evidence" / "leak_sample_index.csv").read_text().splitlines()[1:]
    assert idx and all(r.endswith("," + CORROBORATED) for r in idx)


def test_module_b_generator_default_and_validation(tmp_path):
    t = logs_gen.generate(tmp_path / "a", "acceptance", scale=2000)
    assert t["corroborated_table"] == "LabDB07.dbo.patients"
    assert t["expected_table_classes"]["LabDB07.dbo.patients"] == "exfiltration_evidenced"
    assert t["expected_table_classes"]["LabDB03.dbo.patients"] == "egress_suspected"
    import yaml

    doc = yaml.safe_load((tmp_path / "a" / "logs.yaml").read_text())
    assert doc["corroborations"][0]["tables"] == ["LabDB07.dbo.patients"]
    with pytest.raises(ValueError):
        logs_gen.Generator(tmp_path / "b", "demo", corroborated_table=CORROBORATED)
    with pytest.raises(ValueError):
        logs_gen.Generator(tmp_path / "c", "acceptance", corroborated_table="LabDB03.dbo.nothing")
    with pytest.raises(SystemExit):
        logs_gen.main(["--out", str(tmp_path / "d"), "--scenario", "demo", "--corroborate", CORROBORATED])


# ------------------------------------------------------------------------------------------------ Module C
def test_module_c_tiers_follow_the_scenario(suspected, corroborated):
    s = suspected.scope["scope_tiers"]
    assert s["confirmed_exfiltration"]["count"] == "not determinable"  # never a fabricated count
    assert s["confirmed_exfiltration"]["basis"] == "unknown"
    c = corroborated.scope["scope_tiers"]
    assert isinstance(c["confirmed_exfiltration"]["count"], int) and c["confirmed_exfiltration"]["count"] > 0
    assert c["confirmed_exfiltration"]["exfiltration_evidence_kind"] == "independently_confirmed_external_copy"
    for tiers in (s, c):
        assert isinstance(tiers["observed_access"]["count"], int)  # Module B candidates were applied
        assert tiers["possible_exposure"]["count"] >= tiers["observed_access"]["count"]
        assert tiers["notification_scope"]["proposed_count"] == tiers["possible_exposure"]["count"]
    assert c["possible_exposure"]["count"] >= c["confirmed_exfiltration"]["count"]


def test_leak_sample_is_drawn_from_the_corroborated_table(corroborated):
    meta = json.loads((corroborated.synth / "synth_meta.json").read_text())
    assert meta["leak_sample"]["drawn_from"] == "db03"
    assert CORROBORATED.startswith("LabDB03.")


# ------------------------------------------------------------------------------------------------ attestation
def test_generated_files_are_attested(suspected, as_env):
    as_env(suspected)
    reg = registered(Home())
    for root, generator in ((suspected.synth, "synth"), (suspected.estate, "exposure-estate"),
                            (suspected.logs, "paths-logs")):
        files = files_of(root)
        assert files
        for f in files:
            entry = reg.get(sha256_file(f))
            assert entry is not None, f
        assert generator in {reg[sha256_file(f)]["generator"] for f in files}


def test_case_with_only_attested_sources_is_synthetic(suspected, corroborated, as_env):
    for run in (suspected, corroborated):
        as_env(run)
        testing.login("olivia")
        case, home = Case(run.case_dir), Home()
        ok, problems = case_is_synthetic(case, home, open_store(case, home))
        assert ok, problems
        roles = {s["evidence_role"] for s in case.sources()}
        assert ("leak_sample" in roles) == (run.scenario == "corroborated")


def test_modified_file_is_not_registered_and_tampering_is_detected(suspected, as_env, tmp_path):
    as_env(suspected)
    home = Home()
    reg = registered(home)
    copy = tmp_path / "web.config"
    copy.write_bytes((suspected.estate / "snapshot" / "web01" / "wwwroot" / "web.config").read_bytes())
    assert sha256_file(copy) in reg
    copy.write_bytes(copy.read_bytes() + b"<!-- real data -->\n")
    assert sha256_file(copy) not in reg
    path = Path(home.root) / "synthetic_registry.json"
    original = path.read_bytes()
    try:
        doc = json.loads(original)
        doc["entries"]["0" * 64] = {"generator": "synth", "params_sha256": "0" * 64, "attested_at": "2026-01-01"}
        path.write_text(json.dumps(doc))
        with pytest.raises(IntegrityError):
            registered(home)
    finally:
        path.write_bytes(original)
    assert registered(home) == reg


def test_without_attest_nothing_is_registered(tmp_path, monkeypatch, capsys):
    env = testing.setup_installation(tmp_path / "inst")
    for k, v in env.vars().items():
        monkeypatch.setenv(k, v)
    assert estate_gen.main(["--out", str(tmp_path / "estate"), "--estate", "lab"]) == 0
    assert logs_gen.main(["--out", str(tmp_path / "logs"), "--scale", "2000"]) == 0
    assert "attested_files" not in capsys.readouterr().out
    assert registered(Home()) == {}


def _build_baks_module():
    spec = importlib.util.spec_from_file_location("build_baks", REPO / "demo" / "lab-breach" / "build_baks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_bak_builder_requires_attested_synthetic_inputs(suspected, as_env, tmp_path):
    """build_baks.py --attest refuses inputs that are not registered output of ``tscope synth --attest``
    (the SQL Server build itself is covered by the Docker demo)."""
    as_env(suspected)
    bb = _build_baks_module()
    hashes = bb.attested_input_hashes(suspected.synth, Home())
    assert len(hashes) == 40  # 10 databases x 4 tables
    import shutil

    copy = tmp_path / "synth"
    shutil.copytree(suspected.synth / "sources", copy / "sources")
    bb.attested_input_hashes(copy, Home())
    victim = sorted((copy / "sources").rglob("*.parquet"))[0]
    victim.write_bytes(victim.read_bytes() + b"\0")
    with pytest.raises(SystemExit, match="not attested"):
        bb.attested_input_hashes(copy, Home())
    (copy / "sources" / "db01" / "extra.parquet").write_bytes(b"PAR1")
    with pytest.raises(SystemExit):
        bb.attested_input_hashes(copy, Home())


# ------------------------------------------------------------------------------------------------ full demo
def test_demo_leak_scan_search_is_exact():
    """The demo's prefiltered multi-needle search finds exactly what a plain substring test finds, including a
    needle that spans a chunk boundary."""
    spec = importlib.util.spec_from_file_location("run_demo", REPO / "demo" / "lab-breach" / "run_demo.py")
    rd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rd)
    import random

    rng = random.Random(7)
    needles = {"".join(rng.choice("abcdef0123456789 ") for _ in range(rng.randint(6, 20))): "x" for _ in range(500)}
    needles["8001015009087"] = "x"
    maxlen = max(map(len, needles))
    base = "".join(rng.choice("ghijklmnop{}:,\" ") for _ in range(rd._CHUNK + 50))
    assert rd._first_needle(base, needles, maxlen) is None
    for pos in (0, 1000, rd._CHUNK - 5, len(base) - 13):
        text = base[:pos] + "8001015009087" + base[pos:]
        assert rd._first_needle(text, needles, maxlen) == "8001015009087", pos
    assert rd._first_needle("short", {"shorter": "x"}, 7) is None



def _docker_ready() -> bool:
    import subprocess

    try:
        return subprocess.run(["docker", "ps"], capture_output=True, timeout=20, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.docker
@pytest.mark.slow
@pytest.mark.parametrize("scenario", ["suspected", "corroborated"])
def test_full_demo_with_sql_server(tmp_path, scenario):
    import subprocess
    import sys

    if not _docker_ready():
        pytest.skip("Docker / SQL Server container not available")
    env = {k: v for k, v in os.environ.items() if not k.startswith("TSCOPE_")}
    env["TSCOPE_DEMO_MSSQL_PASSWORD"] = os.environ.get("TSCOPE_DEMO_MSSQL_PASSWORD", "Synth3tic!Demo")
    p = subprocess.run([sys.executable, str(REPO / "demo" / "lab-breach" / "run_demo.py"), "--rows", "20000",
                        "--workdir", str(tmp_path / "w"), "--scenario", scenario], env=env, capture_output=True,
                       text=True, timeout=1800, check=False)
    assert p.returncode == 0 and "DEMO PASSED" in p.stdout, p.stdout[-4000:] + p.stderr[-4000:]
    summary = json.loads((tmp_path / "w" / "demo_summary.json").read_text())
    assert summary["scenario"] == scenario and all(summary["checks"].values())
