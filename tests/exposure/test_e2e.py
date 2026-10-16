"""Module A acceptance: synthetic fixtures end to end (scan, report, release, fixed rescan, diff).

One module-scoped run; each test asserts one acceptance property against it.
"""

import json
import logging
import os
import shutil
import stat

import pytest

from tripline_scope import testing
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.pdf import pdf_text
from tripline_scope.core.store import open_store
from tripline_scope.exposure.synthetic import build
from tscope_verify.report import verify_chain, verify_version


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


def _cli(run, argv, ok=True):
    rc, out, err = testing.run_cli(argv)
    run["console"].append(out + err)
    if ok:
        assert rc == 0, err
    return rc, out, err


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    base = tmp_path_factory.mktemp("expo")
    env = testing.setup_installation(base)
    case_dir = testing.open_case(base, "READY-001", mode="readiness")
    gt = build(base / "synth")
    gt_fixed = build(base / "synth_fixed", "fixed")
    r = {"base": base, "env": env, "case": case_dir, "gt": gt, "gt_fixed": gt_fixed, "console": []}
    cap = _Capture()
    root = logging.getLogger()
    old = root.level
    root.addHandler(cap)
    root.setLevel(logging.DEBUG)
    try:
        testing.login("olivia")
        c = str(case_dir)
        _cli(r, ["exposure", "scan", "--case", c, "--inputs", str(base / "synth" / "manifest.yaml")])
        store = open_store(Case(case_dir), Home())
        r["findings_1"] = store.read_json("work/exposure/findings.json")
        _cli(r, ["--json", "exposure", "report", "--case", c])
        draft_a = json.loads(r["console"][-1].split("\n\n")[0] if False else r["console"][-1])["draft_id"]
        r["draft_a"] = (case_dir / "reports" / "exposure" / "drafts" / draft_a / "report.json").read_bytes()
        _cli(r, ["--json", "exposure", "scan", "--case", c, "--inputs", str(base / "synth" / "manifest.yaml")])
        r["scan_json_out"] = json.loads(r["console"][-1])
        r["findings_2"] = store.read_json("work/exposure/findings.json")
        _cli(r, ["--json", "exposure", "report", "--case", c])
        draft_b = json.loads(r["console"][-1])["draft_id"]
        r["draft_b"] = (case_dir / "reports" / "exposure" / "drafts" / draft_b / "report.json").read_bytes()
        r["operator_release_rc"] = _cli(r, ["release", "--case", c, "--kind", "exposure", "--approver", "olivia"], ok=False)[0]
        _cli(r, ["release", "--case", c, "--kind", "exposure", "--approver", "ines"])
        testing.login("olivia")
        _cli(r, ["exposure", "scan", "--case", c, "--inputs", str(base / "synth_fixed" / "manifest.yaml")])
        _cli(r, ["exposure", "report", "--case", c])
        _cli(r, ["release", "--case", c, "--kind", "exposure", "--approver", "ines"])
        testing.login("rami")
        _cli(r, ["exposure", "diff", "--case", c, "--from", "v1", "--to", "v2", "--out", str(base / "diff.json"),
                 "--csv", str(base / "diff.csv")])
        _cli(r, ["--json", "exposure", "diff", "--case", c, "--from", "v1", "--to", "latest"])
        r["work_decrypted"] = {rel: store.read_bytes(rel) for rel in store.list("work/exposure")}
    finally:
        root.removeHandler(cap)
        root.setLevel(old)
    r["log_lines"] = cap.lines
    rdir = case_dir / "reports" / "exposure"
    r["v1"] = json.loads((rdir / "v0001" / "report.json").read_bytes())
    r["v2"] = json.loads((rdir / "v0002" / "report.json").read_bytes())
    r["diff"] = json.loads((base / "diff.json").read_bytes())
    return r


@pytest.fixture(autouse=True)
def _env(run, monkeypatch):
    for k, v in run["env"].vars().items():
        monkeypatch.setenv(k, v)


def _match(f, exp):
    loc = f["location"]
    if f["rule_id"] != exp["rule_id"]:
        return False
    if "root" in exp and (loc.get("root"), loc.get("path")) != (exp["root"], exp["path"]):
        return False
    if exp.get("member") and loc.get("member") != exp["member"]:
        return False
    if exp.get("database") and loc.get("database") != exp["database"]:
        return False
    if exp.get("principal") and loc.get("principal") != exp["principal"]:
        return False
    return True


def test_expected_findings_locations_and_severity(run):
    findings = run["v1"]["findings"]
    expected = run["gt"]["file_findings"] + run["gt"]["db_findings"]
    missing, wrong = [], []
    for exp in expected:
        hits = [f for f in findings if _match(f, exp)]
        if not hits:
            missing.append(exp)
            continue
        if exp["severity"] not in {f["severity"] for f in hits}:
            wrong.append((exp, sorted({f["severity"] for f in hits})))
        for k, v in (exp.get("details") or {}).items():
            assert any(f["details"].get(k) == v for f in hits), (exp, k)
        if exp.get("basis"):
            assert any(f["basis"] == exp["basis"] for f in hits), exp
    assert not missing, missing
    assert not wrong, wrong
    assert all(f["state"] == "new" for f in findings)


def test_least_privilege_and_negative_cases_produce_no_finding(run):
    findings = run["v1"]["findings"]
    for rule_or_ctl, db, principal in run["gt"]["absent"]:
        bad = [f for f in findings if (f["rule_id"] == rule_or_ctl or f["control_id"] == rule_or_ctl)
               and (db is None or f["location"].get("database") == db)
               and f["location"].get("principal") == principal]
        assert not bad, (rule_or_ctl, db, principal, [b["rule_id"] for b in bad])
    quiet = {"Lab/Exports/accessions_2026.csv", "Lab/Exports/numbers_only.csv", "wwwroot/js/vendor.min.js",
             "wwwroot/docs/example.env", "wwwroot/tests/fixtures/web.config", "tests/test_settings.py",
             "Archive/nested.zip", "Archive/bomb.zip", "Large/huge_export.csv"}
    assert not [f for f in findings if f["location"].get("path") in quiet]
    assert not [f for f in findings if "node_modules" in json.dumps(f["location"])]


def test_coverage_reports_assessed_not_assessed_unavailable_separately(run):
    cov = run["v1"]["coverage"]
    assert set(cov) == {"A1", "A2", "A3", "A4", "A5"}
    for c in cov.values():
        assert {"assessed", "not_assessed", "unavailable", "status"} <= set(c)
    un = " | ".join(f"{x['location']} {x['reason']}" for x in cov["A3"]["unavailable"])
    assert "huge_export.csv" in un and "possible archive bomb" in un and "depth budget" in un
    na = " | ".join(f"{x['unit']} {x['reason']}" for c in cov.values() for x in c["not_assessed"])
    assert "db:risdb" in na and "oracle" in na and "7z" in na and "packfile" in na
    assert any(x["unit"] == "db:pathdb:hba_auth" and "permission denied" in x["reason"] for x in cov["A4"]["unavailable"])
    assert {x["unit"] for x in cov["A4"]["assessed"]} >= {"db:labdb:xp_cmdshell", "db:pathdb:copy_program"}
    pf = {(p["format"], p["error_class"]) for p in run["v1"]["parser_failures"]["counts"]}
    assert pf == {("json", "JSONDecodeError"), ("xlsx", "BadZipFile")}
    kinds = {e["kind"] for e in run["v1"]["exclusions"]["applied"]}
    assert kinds == {"declared-exclusion", "special-file", "symlink-escape-rejected", "symlink-not-followed"}
    assert sum(1 for e in run["v1"]["exclusions"]["applied"] if e["kind"] == "symlink-escape-rejected") == 2
    assert run["v1"]["missing_evidence"]


def test_no_secret_or_id_leaks_anywhere(run):
    gt = run["gt"]
    needles = [v for v in list(gt["secrets"].values()) + list(run["gt_fixed"]["secrets"].values()) if len(v) >= 6]
    needles += gt["sa_ids"] + run["gt_fixed"]["sa_ids"]
    assert len(needles) > 300
    hay = {"console": "\n".join(run["console"]), "logs": "\n".join(run["log_lines"])}
    case_dir = run["case"]
    for p in case_dir.rglob("*"):
        if p.is_file() and not p.is_symlink():
            data = p.read_bytes()
            hay[str(p)] = data.decode("latin-1")
            if p.suffix == ".pdf":
                hay[str(p) + "#text"] = pdf_text(data)
    hay["home-audit"] = Home().audit_path.read_text()
    hay["diff.json"] = (run["base"] / "diff.json").read_text()
    hay["diff.csv"] = (run["base"] / "diff.csv").read_text()
    for rel, data in run["work_decrypted"].items():
        hay["decrypted:" + rel] = data.decode("utf-8")
    assert any("report.pdf#text" in k for k in hay) and any(k.startswith("decrypted:") for k in hay)
    leaks = [(name, n[:4] + "...") for name, text in hay.items() for n in needles if n in text]
    assert not leaks, leaks[:10]


def test_deterministic_ids_and_canonical_report(run):
    a = {f["finding_id"] for f in run["findings_1"]}
    b = {f["finding_id"] for f in run["findings_2"]}
    assert a == b and run["findings_1"] == run["findings_2"]
    assert run["draft_a"] == run["draft_b"]
    from tripline_scope.core.canonical import canonical_bytes

    assert canonical_bytes(json.loads(run["draft_a"])) == run["draft_a"]


def test_finding_contract_fields(run):
    req = {"finding_id", "control_id", "rule_id", "title", "severity", "likelihood", "impact", "severity_rationale",
           "asset", "location", "evidence_ids", "first_seen", "last_seen", "provenance", "basis", "confidence",
           "confidence_reason", "caveats", "ownership", "suggested_fix", "state", "coverage_unit", "rank"}
    for f in run["v1"]["findings"] + run["v2"]["findings"]:
        assert req <= set(f), req - set(f)
        assert f["finding_id"].startswith("AF-") and f["evidence_ids"] and f["evidence_ids"][0].startswith("EV-")
        assert f["basis"] in ("observation", "inference", "unknown") and 0 <= f["confidence"] <= 1
        assert f["suggested_fix"]["action"] and f["severity_rationale"]["impact"] and f["severity_rationale"]["likelihood"]
        assert "asset_id" in f["asset"] and "display" in f["location"]
        if f["location"]["type"] in ("identity",) or f["control_id"] in ("A2", "A5"):
            assert f["location"].get("principal")
        if f["control_id"] == "A1":
            assert f["secret_fingerprint"] and f["redacted_context"]
        assert not any("compromise" in c and "not" not in c for c in f["caveats"])
    body = run["v1"]
    assert body["method_version"] and body["config_sha256"] and body["scan"]["manifest_sha256"]
    assert body["previous_report_sha256"] is None and run["v2"]["previous_report_sha256"]
    assert body["sources"] and all(s["content_sha256"] for s in body["sources"])
    ranks = [f["rank"] for f in body["findings"]]
    assert ranks == list(range(1, len(ranks) + 1))
    order = ["critical", "high", "medium", "low", "info"]
    sev = [order.index(f["severity"]) for f in body["findings"]]
    assert sev == sorted(sev)


def test_release_separation_signing_chain_and_tamper(run, tmp_path):
    assert run["operator_release_rc"] == 3
    kind_dir = run["case"] / "reports" / "exposure"
    keys = Home().trusted_hospital_keys()
    assert verify_chain(kind_dir, hospital_keys=keys).ok
    rc, out, err = testing.run_cli(["verify", "--case", str(run["case"])])
    assert rc == 0, out
    rel = json.loads((kind_dir / "v0001" / "release.json").read_bytes())
    assert rel["approval"]["approver"] == "ines" and "olivia" in rel["operators"]
    assert set(rel["artefacts"]) == {"report.pdf", "attachments/findings.csv", "attachments/coverage.json"}
    t = tmp_path / "tampered"
    shutil.copytree(kind_dir, t)
    for p in t.rglob("*"):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
    p = t / "v0001" / "report.json"
    d = json.loads(p.read_bytes())
    d["findings"][0]["severity"] = "low"
    from tripline_scope.core.canonical import canonical_bytes

    p.write_bytes(canonical_bytes(d))
    assert not verify_chain(t, hospital_keys=keys).ok
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert not verify_version(kind_dir / "v0002", hospital_keys=[Ed25519PrivateKey.generate().public_key()]).ok
    assert stat.S_IMODE((kind_dir / "v0001" / "report.json").stat().st_mode) & 0o222 == 0


def test_fixed_variant_gives_verified_mitigated_delta(run):
    fixed = [e for e in run["gt"]["file_findings"] + run["gt"]["db_findings"] if e.get("fixed_in_variant")]
    d = run["diff"]
    assert d["summary"]["new"] == 0 and d["summary"]["not_reassessed"] == 0
    assert d["summary"]["resolved"] == len(fixed)
    assert all(e["verified"] for e in d["resolved"])
    v1 = {f["finding_id"]: f for f in run["v1"]["findings"]}
    for exp in fixed:
        fid = next(f["finding_id"] for f in run["v1"]["findings"] if _match(f, exp))
        assert fid in {e["finding_id"] for e in d["resolved"]}, exp
        m = next(f for f in run["v2"]["findings"] if f["finding_id"] == fid)
        assert m["state"] == "mitigated" and "verified" in m["verification"]
    persisting = [f for f in run["v2"]["findings"] if f["state"] == "open"]
    assert persisting and all(f["first_seen"] == v1[f["finding_id"]]["first_seen"] for f in persisting)
    lab_app = [e for e in d["severity_changed"] if e["principal"] == "lab_app"]
    assert lab_app and lab_app[0]["severity_from"] == "critical" and lab_app[0]["severity_to"] == "high"


def test_cross_module_fields_for_containment(run):
    """Module B keys containment advice on finding_id, control_id, severity, asset.asset_id, location
    (principal for accounts) and suggested_fix.action."""
    by = {}
    for f in run["v1"]["findings"]:
        by.setdefault(f["rule_id"], []).append(f)
    conn = by["A1.db-connection-password"][0]
    assert conn["asset"]["asset_id"] == "AST-WEB01" and conn["target_asset"]["asset_id"] == "AST-LABDB"
    assert conn["suggested_fix"]["action"] == "rotate-and-vault-credential"
    assert conn["details"]["credential_principal"] == "lab_app"
    admin = [f for f in by["A2.app-admin-rights"] if f["location"]["principal"] == "lab_app"][0]
    assert admin["asset"]["asset_id"] == "AST-LABDB" and conn["finding_id"] in admin["related_findings"]
    sup = by["A5.supplier-mfa-missing"]
    assert {f["location"]["principal"] for f in sup} == {"tech3", "vendor_support"}
    assert {f["location"].get("principal_domain") for f in sup} == {"medisoft.example", None}
    assert run["v1"]["stable_fields"]
