"""Unified synthetic laboratory breach demo: Module A → Module B → Module C on one case (also the sales demo).

Tripline Scope — Synthetic South African Laboratory Breach Investigation. All data is synthetic; this is not a
reconstruction of any real incident.

Flow (``docs/DEMO.md`` tells the story):

0. installation, users and the incident case (first, so every generator can attest its outputs);
   ``tscope synth --attest`` (10 lab databases + a leak sample drawn from LabDB03) and ``.bak`` backups
   (``build_baks.py --attest``);
1. **Module A** (before/around the incident): the synthetic laboratory estate
   (``python -m tripline_scope.exposure.synthetic --estate lab --attest``) → ``exposure scan/report`` → release;
2–3. **Module B**: synthetic incident logs (``--scenario demo`` for *suspected*, ``--scenario acceptance
   --corroborate LabDB03.dbo.patients`` for *corroborated*) → ``paths ingest/analyse`` → ``paths report
   --exposure-report`` (containment cross-referenced to the released exposure report) → scope candidates → release;
4. **Module C**: custody (backups; the leak sample only in *corroborated* mode) → restore/discover/extract →
   constrain → estimate → release preliminary → match → simulated review → report → notification pack → release
   refined → notification export;
5. :func:`investigate_and_present` (integration hook: AI Investigator + dashboard; currently a no-op);
6. verify (``tscope verify``, ``audit verify``, ``tscope_verify chain`` for exposure, paths and scope) → close
   (unless ``--keep-open``) → verify the destruction certificate;
7. leak scan of every log, console capture, report and PDF (synthetic identifiers, seeded estate secrets) and a
   source-checksum check of every input; ``demo_summary.json``.

SQL Server Developer Edition is used only because this is a demo. Run via ``demo/lab-breach/run.sh`` (starts the
database container) or directly:

    python demo/lab-breach/run_demo.py --rows 100000 --workdir demo/lab-breach/out --scenario corroborated
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PASSWORD = "Synthetic-Pass-2026!"  # noqa: S105 - synthetic demo account
SQL_SA_PASSWORD_ENV = "TSCOPE_DEMO_MSSQL_PASSWORD"  # noqa: S105 - env var name
HEADER = ("Tripline Scope — Synthetic South African Laboratory Breach Investigation "
          "(all data synthetic; not a reconstruction of any real incident)")
CASE_ID = "DEMO-LAB-2026"
WINDOW = "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"
CORROBORATED_TABLE = "LabDB03.dbo.patients"  # Module C's leak sample is drawn from LabDB03 (synth.generate.LEAK_DB)
CHAIN_KINDS = ("exposure", "paths", "scope")

console: list[str] = []
timings: dict[str, float] = {}


def env_base(work: Path) -> dict[str, str]:
    e = dict(os.environ)
    e.update({
        "PYTHONPATH": f"{REPO / 'src'}:{REPO / 'verify' / 'src'}",
        "TSCOPE_HOME": str(work / "home"),
        "TSCOPE_SESSION_FILE": str(work / "session.token"),
        "TSCOPE_KEK_PASSPHRASE": "demo-kek-passphrase",
        "TSCOPE_HOSPITAL_KEY_PASSPHRASE": "demo-signing-passphrase",
        "TSCOPE_PASSWORD": PASSWORD,
        "TSCOPE_NEW_USER_PASSWORD": PASSWORD,
        "TSCOPE_APPROVER_PASSWORD": PASSWORD,
    })
    e.pop("TSCOPE_FIXED_NOW", None)  # real clock for the demo
    return e


def run(step: str, args: list[str], env: dict, *, tscope: bool = True, check: bool = True, stdin: str | None = None) -> str:
    cmd = ([sys.executable, "-m", "tripline_scope"] if tscope else []) + args
    t0 = time.perf_counter()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, input=stdin, cwd=REPO, check=False)
    dt = time.perf_counter() - t0
    timings[step] = timings.get(step, 0.0) + dt
    console.append(f"$ {' '.join(args[:3])} ...\n{p.stdout}\n{p.stderr}")
    print(f"[{dt:7.1f}s] {step}: {'ok' if p.returncode == 0 else 'FAILED rc=' + str(p.returncode)}", flush=True)
    if check and p.returncode != 0:
        print(p.stdout[-3000:], p.stderr[-3000:], sep="\n", file=sys.stderr)
        raise SystemExit(f"demo step failed: {step}")
    return p.stdout


def stage(title: str) -> None:
    print(f"\n== {title}", flush=True)


def login(user: str, env: dict) -> None:
    run(f"login {user}", ["login", "--user", user], env)


def regular_files(root: Path) -> list[Path]:
    """Regular files under ``root`` (FIFOs, sockets and symlinks are not opened)."""
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def sha_tree(paths: list[Path]) -> dict[str, str]:
    out = {}
    for p in paths:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        out[str(p)] = h.hexdigest()
    return out


def released_versions(case: Path, kind: str) -> list[Path]:
    d = case / "reports" / kind
    return sorted(p for p in d.glob("v[0-9][0-9][0-9][0-9]") if (p / "release.json").is_file()) if d.is_dir() else []


def latest_released(case: Path, kind: str) -> tuple[Path, dict]:
    versions = released_versions(case, kind)
    if not versions:
        raise SystemExit(f"no released {kind} report")
    return versions[-1], json.loads((versions[-1] / "report.json").read_bytes())


# ------------------------------------------------------------------------------------------------ integration hook
def investigate_and_present(env: dict, case: Path, work: Path, args: argparse.Namespace) -> dict:
    """INTEGRATION HOOK — placeholder, intentionally does nothing yet.

    Called after the refined scope report is released and before verification. The integrator fills it with the
    AI Investigator and dashboard stages of the unified demo contract (docs/PLAN.md §14):
    ``investigator analyse --provider fixture`` → review → ``investigator report`` → ``release --kind
    investigation`` → dashboard smoke test.

    Return a dict merged into ``demo_summary.json`` under ``"investigation"``. If it releases further report kinds,
    list them under ``"report_kinds"`` so the verification stage also runs ``tscope_verify chain`` on them; any
    ``"checks"`` (name → bool) are added to the pass/fail checks.
    """
    return {}


# ------------------------------------------------------------------------------------------------ summary helpers
def module_a_summary(case: Path, estate_truth: dict) -> dict:
    vdir, rep = latest_released(case, "exposure")
    findings = rep.get("findings", [])

    def hit(exp: dict) -> str | None:
        for f in findings:
            loc = f.get("location") or {}
            if f.get("rule_id") != exp["rule_id"] or (f.get("asset") or {}).get("asset_id") != exp["asset_id"]:
                continue
            if any(exp.get(k) is not None and loc.get(k) != exp[k] for k in ("principal", "database", "root", "path")):
                continue
            return f["finding_id"]
        return None

    key = {name: hit(exp) for name, exp in (estate_truth.get("key_weaknesses") or {}).items()}
    return {"report_version": rep.get("version"), "findings": rep["summary"]["findings"],
            "by_severity": rep["summary"]["by_severity"], "by_control": rep["summary"]["by_control"],
            "key_weaknesses": key}


def module_b_summary(case: Path) -> dict:
    vdir, rep = latest_released(case, "paths")
    tables = {t["table"]: t["consequence_class"] or t["status"] for t in rep.get("tables", [])}
    recs = rep["containment"]["recommendations"]
    xrefs = [{"rec_id": r["rec_id"], "category": r["category"],
              "target": r["target"].get("asset_id") or r["target"].get("label") or r["target"].get("description"),
              "module_a_findings": sorted(x["finding_id"] for x in r["module_a_refs"])}
             for r in recs if r.get("module_a_refs")]
    return {"report_version": rep.get("version"),
            "sensitive_tables_by_class": rep["classification"]["sensitive_tables_by_class"],
            "exfiltration_evidenced_tables": sorted(t for t, s in tables.items() if s == "exfiltration_evidenced"),
            "table_classes": {t: tables.get(t) for t in (
                "LabDB01.dbo.results", "LabDB03.dbo.patients", "LabDB03.dbo.admissions", "LabDB05.dbo.billing",
                "LabDB07.dbo.patients", "LabDB09.dbo.patients")},
            "recommendations": len(recs), "cross_referenced_recommendations": len(xrefs), "cross_references": xrefs,
            "module_a_link": rep["containment"]["module_a"].get("status")}


def module_c_summary(case: Path) -> dict:
    versions = released_versions(case, "scope")
    prelim = json.loads((versions[0] / "report.json").read_bytes()) if versions else {}
    vdir, rep = latest_released(case, "scope")
    tiers = rep.get("scope_tiers", {})

    def count(name: str):
        t = tiers.get(name) or {}
        return t.get("count", t.get("proposed_count"))

    return {"preliminary": {"version": prelim.get("version"),
                            "unique_people": (prelim.get("counts") or {}).get("unique_people")},
            "refined_version": rep.get("version"),
            "tiers": {name: count(name) for name in ("observed_access", "possible_exposure", "confirmed_exfiltration",
                                                     "notification_scope")},
            "confirmed_exfiltration_basis": (tiers.get("confirmed_exfiltration") or {}).get("basis")}


CHECK_SYNTHETIC = """
import json, sys
from pathlib import Path
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.investigator.synthetic import case_is_synthetic
case = Case(Path(sys.argv[1])); home = Home()
ok, problems = case_is_synthetic(case, home, open_store(case, home))
print(json.dumps({"all_sources_attested_synthetic": ok, "sources": len(case.sources()), "problems": len(problems)}))
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=["suspected", "corroborated"], default="suspected",
                    help="suspected: outbound flows of unknown content, no corroboration; corroborated: an "
                         f"independently confirmed external copy of {CORROBORATED_TABLE} (leak sample)")
    ap.add_argument("--keep-open", action="store_true", help="do not close the case (explore it afterwards)")
    ap.add_argument("--rows", type=int, default=100_000, help="synthetic admission rows")
    ap.add_argument("--workdir", default=str(HERE / "out"))
    ap.add_argument("--mssql-host", default="127.0.0.1")
    ap.add_argument("--mssql-port", type=int, default=14330)
    ap.add_argument("--mssql-container", default="mssql-test", help="container used for .bak transfer (docker cp)")
    ap.add_argument("--keep", action="store_true", help="keep an existing workdir")
    args = ap.parse_args()
    print(HEADER, flush=True)
    print(f"scenario: {args.scenario}", flush=True)

    work = Path(args.workdir).resolve()
    if work.exists() and not args.keep:
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    env = env_base(work)
    env.setdefault(SQL_SA_PASSWORD_ENV, "Synth3tic!Demo")
    case = work / "case"
    # Restored databases are named after the case (tscope_<case>_<source>) and only closure drops them, so a case
    # left open gets a run-unique id; a later run then never meets its restores on the SQL Server instance.
    case_id = CASE_ID + (time.strftime("-%Y%m%d%H%M%S") if args.keep_open else "")
    corroborated = args.scenario == "corroborated"
    sys.path[:0] = [str(REPO / "src"), str(REPO / "verify" / "src")]

    # 0. installation, users and the case first: the generators attest their outputs under this installation
    stage("Set-up: installation, users, incident case")
    run("init", ["init", "--hospital-name", "Synthetic Lab Group", "--admin", "admin"], env)
    import yaml

    cfg_path = work / "home" / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["restore_targets"] = {"mssql": {
        "host": args.mssql_host, "port": args.mssql_port, "login": "sa", "password_env": SQL_SA_PASSWORD_ENV,
        "backup_transfer": "docker_cp", "container": args.mssql_container,
        "server_backup_dir": "/var/opt/mssql/backup/tscope-demo", "data_dir": "/var/opt/mssql/data",
        "encryption": False, "trust_server_certificate": True,
    }}
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    login("admin", env)
    for u in ("olivia", "rami", "ines"):
        run(f"user add {u}", ["user", "add", u], env)
    run("case init", ["case", "init", str(case), "--case-id", case_id, "--mode", "incident",
                      "--incident-start", "2026-09-01T00:00:00Z", "--incident-end", "2026-09-14T23:59:59Z",
                      "--operator", "olivia", "--reviewer", "rami", "--approver", "ines",
                      "--retain-until", "2033-12-31"], env)

    stage("Synthetic laboratory databases (Module C inputs), attested")
    run("synth", ["synth", "--rows", str(args.rows), "--databases", "10", "--seed", "2026",
                  "--out", str(work / "synth"), "--attest"], env)
    run("build .bak backups", [sys.executable, str(HERE / "build_baks.py"), "--synth", str(work / "synth"),
                               "--out", str(work / "baks"), "--host", args.mssql_host, "--port", str(args.mssql_port),
                               "--container", args.mssql_container, "--password-env", SQL_SA_PASSWORD_ENV, "--attest"],
        env, tscope=False)
    baks = sorted((work / "baks").glob("*.bak"))
    leak = work / "synth" / "leak_sample.csv"
    sources = baks + [leak]
    before = sha_tree(sources)  # every input is hashed before any module reads it

    # Stage 1: Module A on the laboratory estate
    stage("Stage 1 - Module A: exposure scan of the synthetic laboratory estate")
    estate = work / "estate"
    run("synthetic estate (Module A)", [sys.executable, "-m", "tripline_scope.exposure.synthetic", "--out",
                                        str(estate), "--estate", "lab", "--variant", "baseline", "--attest"],
        env, tscope=False)
    sources += regular_files(estate)
    before.update(sha_tree(regular_files(estate)))
    login("olivia", env)
    run("exposure scan", ["exposure", "scan", "--case", str(case), "--inputs", str(estate / "manifest.yaml")], env)
    run("exposure report", ["exposure", "report", "--case", str(case)], env)
    run("release exposure", ["release", "--case", str(case), "--kind", "exposure", "--approver", "ines"], env)
    exposure_dir, _ = latest_released(case, "exposure")

    # Stages 2-3: Module B on the generated incident logs
    stage(f"Stages 2-3 - Module B: access paths from synthetic incident logs ({args.scenario})")
    logs = work / "logs"
    gen = (["--scenario", "acceptance", "--corroborate", CORROBORATED_TABLE] if corroborated else ["--scenario", "demo"])
    run("synthetic incident logs (Module B)", [sys.executable, "-m", "tripline_scope.paths.synthetic", "--out",
                                               str(logs), *gen, "--attest"], env, tscope=False)
    sources += regular_files(logs)
    before.update(sha_tree(regular_files(logs)))
    login("olivia", env)
    run("paths ingest", ["paths", "ingest", "--case", str(case), "--manifest", str(logs / "logs.yaml")], env)
    run("paths analyse", ["paths", "analyse", "--case", str(case), "--window", WINDOW], env)
    run("paths report", ["paths", "report", "--case", str(case), "--exposure-report", str(exposure_dir)], env)
    candidates = work / "scope_candidates.json"
    run("paths scope-candidates", ["paths", "scope-candidates", "--case", str(case), "--out", str(candidates)], env)
    run("release paths", ["release", "--case", str(case), "--kind", "paths", "--approver", "ines"], env)

    # Stage 4: Module C
    stage("Stage 4 - Module C: restore, scope people, notify")
    login("olivia", env)
    common = ["--legal-basis", "POPIA s22 incident investigation (synthetic demo)",
              "--received-at", "2026-09-15T08:00:00Z", "--case", str(case)]
    for b in baks:
        run("source add", ["source", "add", "--kind", "mssql_bak", "--path", str(b), "--label", f"backup {b.stem}",
                           "--evidence-role", "system_copy", "--supplied-by", "Head of IT", *common], env)
    if corroborated:
        run("source add leak", ["source", "add", "--kind", "csv", "--path", str(leak), "--label",
                                "published leak sample", "--evidence-role", "leak_sample", "--supplied-by",
                                "Laboratory attorneys", "--copy", *common], env)
    run("ingest", ["ingest", "--case", str(case)], env)
    run("scope constrain", ["scope", "constrain", "--case", str(case), "--candidates", str(candidates),
                            "--reason", "Access-path analysis candidates; full scope kept as upper bound"], env)
    run("estimate", ["estimate", "--case", str(case)], env)
    run("release preliminary", ["release", "--case", str(case), "--kind", "scope", "--approver", "ines"], env)
    login("olivia", env)
    run("scope match", ["scope", "match", "--case", str(case)], env)
    login("rami", env)
    run("scope review (simulated reviewer)", ["scope", "decide", "--case", str(case), "--simulate-reviewer",
                                               str(work / "synth" / "ground_truth.parquet")], env)
    login("olivia", env)
    run("scope match (replay decisions)", ["scope", "match", "--case", str(case)], env)
    run("scope report", ["scope", "report", "--case", str(case)], env)
    run("notify build", ["scope", "notify", "build", "--case", str(case)], env)
    run("release refined", ["release", "--case", str(case), "--kind", "scope", "--approver", "ines"], env)
    export = work / "notify_export"
    run("notify export", ["scope", "notify", "export", "--case", str(case), "--out", str(export),
                          "--approver", "ines"], env)

    # Integration hook: AI Investigator + dashboard (filled in by the integrator)
    stage("AI Investigator and dashboard (integration hook)")
    t0 = time.perf_counter()
    extra = investigate_and_present(env, case, work, args) or {}
    timings["investigate_and_present"] = time.perf_counter() - t0
    print("  investigate_and_present: " + ("ran" if extra else "not implemented yet (placeholder hook)"), flush=True)

    # Verification
    stage("Verification")
    login("olivia", env)
    run("verify", ["verify", "--case", str(case)], env)
    run("audit verify", ["audit", "verify", "--case", str(case)], env)
    run("audit export", ["audit", "export", "--case", str(case), "--out", str(work / "audit.jsonl")], env)
    synthetic = json.loads(run("synthetic-origin check", [sys.executable, "-c", CHECK_SYNTHETIC, str(case)], env,
                               tscope=False))
    pub = work / "home" / "keys" / "hospital_signing.pub"
    kinds = list(CHAIN_KINDS) + [k for k in extra.get("report_kinds", []) if k not in CHAIN_KINDS]
    for kind in kinds:
        run(f"tscope-verify chain {kind}", [sys.executable, "-m", "tscope_verify", "chain", str(case / "reports" / kind),
                                            "--hospital-key", str(pub)], env, tscope=False)
    estate_truth = json.loads((estate / "ground_truth.json").read_bytes())
    mod_a, mod_b, mod_c = module_a_summary(case, estate_truth), module_b_summary(case), module_c_summary(case)
    after = sha_tree(sources)

    if args.keep_open:
        stage("Case left open (--keep-open)")
        print(f"  case {case_id}: {case}\n  TSCOPE_HOME={work / 'home'}  TSCOPE_SESSION_FILE={work / 'session.token'}\n"
              "  (demo passphrases and passwords are the synthetic constants in run_demo.py)\n"
              f"  its restored databases stay on {args.mssql_container} until the case is closed: "
              f"tscope case close --case {case} --approver ines", flush=True)
    else:
        stage("Closure")
        run("close", ["case", "close", "--case", str(case), "--approver", "ines",
                      "--external-backup", "demo: no keystore backups taken"], env)
        run("tscope-verify certificate", [sys.executable, "-m", "tscope_verify", "certificate",
                                          str(case / "reports" / "closure" / "certificate.json"), "--hospital-key", str(pub)],
            env, tscope=False)
        run("tscope-verify chain scope (after closure)", [sys.executable, "-m", "tscope_verify", "chain",
                                                           str(case / "reports" / "scope"), "--hospital-key", str(pub)],
            env, tscope=False)

    # Leak scan + source safety + scenario checks
    stage("Leak scan, source safety and scenario checks")
    (work / "console.txt").write_text("\n".join(console))
    t0 = time.perf_counter()
    leak_result = leak_scan(work, exempt=[export], estate_truth=estate_truth)
    timings["leak scan"] = time.perf_counter() - t0
    exfil_tables = mod_b["exfiltration_evidenced_tables"]
    confirmed = mod_c["tiers"]["confirmed_exfiltration"]
    checks = {
        "sources_unchanged": before == after,
        "no_leaks": leak_result["hits"] == 0,
        "leak_scan_positive_control": leak_result["positive_control_files_with_hits"] > 0,
        "module_a_key_weaknesses_found_by_scanner": bool(mod_a["key_weaknesses"]) and all(mod_a["key_weaknesses"].values()),
        "module_b_cross_referenced_to_module_a": mod_b["cross_referenced_recommendations"] > 0,
        "all_sources_attested_synthetic": synthetic["all_sources_attested_synthetic"],
    }
    if corroborated:
        checks["only_corroborated_table_exfiltration_evidenced"] = exfil_tables == [CORROBORATED_TABLE]
        checks["module_c_confirmed_exfiltration_counted"] = isinstance(confirmed, int) and confirmed > 0
    else:
        checks["no_table_exfiltration_evidenced"] = exfil_tables == []
        checks["module_c_confirmed_exfiltration_not_determinable"] = confirmed == "not determinable"
    checks.update({f"investigation:{k}": bool(v) for k, v in (extra.get("checks") or {}).items()})
    summary = {
        "scenario": args.scenario,
        "rows": args.rows,
        "case_closed": not args.keep_open,
        "module_a_findings": {"total": mod_a["findings"], **mod_a["by_severity"]},
        "module_a": mod_a,
        "module_b_classes": mod_b["sensitive_tables_by_class"],
        "module_b": mod_b,
        "cross_references": mod_b["cross_referenced_recommendations"],
        "module_c_tiers": mod_c["tiers"],
        "module_c": mod_c,
        "synthetic_origin": synthetic,
        "investigation": {k: v for k, v in extra.items() if k not in ("checks",)} or {"status": "hook not implemented"},
        "timings_s": {k: round(v, 2) for k, v in timings.items()},
        "total_s": round(sum(timings.values()), 1),
        "sources_unchanged": checks["sources_unchanged"],
        "leak_scan": leak_result,
        "checks": checks,
    }
    (work / "demo_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("scenario", "total_s", "module_a_findings", "module_b_classes",
                                              "cross_references", "module_c_tiers", "sources_unchanged", "leak_scan",
                                              "checks")}, indent=2))
    ok = all(checks.values())
    print("DEMO PASSED" if ok else "DEMO FAILED: " + ", ".join(k for k, v in checks.items() if not v))
    return 0 if ok else 1


def leak_scan(work: Path, exempt: list[Path], estate_truth: dict | None = None) -> dict:
    """Scan every non-exempt file of the case, installation, console capture, audit export and summary for the
    synthetic identifiers from ground truth and for the secrets seeded into the Module A estate and Module B logs.
    The generated input directories (synth, baks, estate, logs) contain these values by design and are not
    outputs, so they are not scanned."""
    import pyarrow.parquet as pq

    from tripline_scope.core.pdf import pdf_text
    from tripline_scope.paths.synthetic import SQL_CMDLINE_SECRET

    gt = pq.read_table(work / "synth" / "ground_truth_identifiers.parquet")
    needles: dict[str, str] = {}
    for col in gt.column_names:
        for v in gt.column(col).to_pylist():
            if isinstance(v, str) and len(v) >= 6:
                needles[v] = "synthetic identifier"
    for v in (estate_truth or {}).get("secrets", {}).values():
        if isinstance(v, str) and len(v) >= 8:
            needles[v] = "seeded estate secret"
    for v in (estate_truth or {}).get("sa_ids", []):
        needles[v] = "seeded estate identifier"
    needles[SQL_CMDLINE_SECRET] = "seeded log secret"
    needles = {n: k for n, k in needles.items() if len(n) >= _GRAM}
    roots = [work / "case", work / "home", work / "console.txt", work / "audit.jsonl", work / "demo_summary.json"]
    skip = [p.resolve() for p in exempt]
    inputs = [(work / d).resolve() for d in ("synth", "baks", "estate", "logs")]
    maxlen = max(len(n) for n in needles)
    hits, scanned = [], 0
    for root in roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        for f in files:
            if f.is_symlink() or any(str(f.resolve()).startswith(str(s)) for s in skip + inputs) \
                    or f.name.endswith(".tse"):
                # custody references (symlinks under case/sources/) point at the generated inputs, which hold these
                # values by design; encrypted envelopes are ciphertext; the exempt export holds authorised notices
                continue
            data = f.read_bytes()
            text = pdf_text(data) if data[:4] == b"%PDF" else data.decode("utf-8", "replace")
            scanned += 1
            n = _first_needle(text, needles, maxlen)
            if n is not None:
                hits.append({"file": str(f.relative_to(work)), "kind": needles[n]})
    # positive control: the approver's authorised notification export must contain the identifiers, which shows
    # the scan would have found them anywhere else
    control = sum(1 for s in skip for f in (s.rglob("*") if s.is_dir() else []) if f.is_file()
                  and _first_needle(f.read_bytes().decode("utf-8", "replace"), needles, maxlen) is not None)
    kinds: dict[str, int] = {}
    for k in needles.values():
        kinds[k] = kinds.get(k, 0) + 1
    return {"files_scanned": scanned, "identifiers_checked": len(needles), "needles_by_kind": kinds,
            "hits": len(hits), "where": hits[:20], "positive_control_files_with_hits": control}


_GRAM = 6  # every needle is at least this long
_CHUNK = 1 << 20


def _first_needle(text: str, needles: dict[str, str], maxlen: int) -> str | None:
    """Exact substring search for many needles: a needle is tested with ``in`` only when its first and last
    ``_GRAM``-character substrings occur in the chunk (a necessary condition, so nothing is missed). Chunks overlap
    by the longest needle, so a needle spanning a chunk boundary is still found."""
    for start in range(0, max(len(text), 1), _CHUNK):
        chunk = text[start:start + _CHUNK + maxlen - 1]
        grams = {chunk[i:i + _GRAM] for i in range(len(chunk) - _GRAM + 1)}
        for n in needles:
            if n[:_GRAM] in grams and n[-_GRAM:] in grams and n in chunk:
                return n
    return None


if __name__ == "__main__":
    raise SystemExit(main())
