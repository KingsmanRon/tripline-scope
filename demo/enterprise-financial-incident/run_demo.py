"""Enterprise profile demonstration: suspected unauthorised privileged access to a utility's financial system.

Tripline Scope — Synthetic Utility Financial-System Investigation. All data is synthetic and fictional ("Synthetic
Utility Ltd", ``utility.example``, documentation-range addresses). It is not a reconstruction of any real incident
and makes no claim about any real organisation. Nothing here connects to any network or system.

Stages (printed as they run; one case per scenario):

 1. fictional enterprise with known ground truth (``python -m tripline_scope.enterprise.synthetic``, attested)
 2. excessive privileges and access-control weaknesses in the estate (part of stage 1's estate)
 3. suspicious authentication and privileged-account events (Windows, Entra ID, VPN, SQL Server audit)
 4. financial-application audit events (attempted / completed unauthorised actions, per scenario)
 5. scenario C only: independently corroborated activity (bank settlement statement)
 6. Module A exposure scan (A1–A5 + enterprise E1–E5) and Module B access-path analysis → release
 7. financial transaction-evidence analysis → ``financial`` report → release
 8. deterministic investigation (fixture, NOT AI inference), validation and simulated human review → release
 9. signed reports for every module
10. verification: ``tscope verify``, ``audit verify``, ``tscope_verify chain`` per report kind, source integrity,
    and a leak scan of every output for the seeded secrets and raw references
11. the Investigation Workbench on loopback, signed in over real HTTP, checked against the released reports

Scenarios: ``a`` suspicious access, financial impact not determinable; ``b`` attempted transaction rejected or
stopped; ``c`` corroborated settlement. ``--scenario all`` runs the three and checks they are distinguished.

    python demo/enterprise-financial-incident/run_demo.py --scenario all --workdir demo/enterprise-financial-incident/out
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
PASSWORD = "Synthetic-Pass-2026!"
EXPECTED = {"a": "not_determinable", "b": "attempted_and_stopped", "c": "settlement_corroborated"}
console: list[str] = []
timings: dict[str, float] = {}


def env_base(work: Path) -> dict[str, str]:
    e = dict(os.environ)
    e.update({"PYTHONPATH": f"{REPO / 'src'}:{REPO / 'verify' / 'src'}", "TSCOPE_HOME": str(work / "home"),
              "TSCOPE_SESSION_FILE": str(work / "session.token"), "TSCOPE_KEK_PASSPHRASE": "demo-kek-passphrase",
              "TSCOPE_HOSPITAL_KEY_PASSPHRASE": "demo-signing-passphrase", "TSCOPE_PASSWORD": PASSWORD,
              "TSCOPE_NEW_USER_PASSWORD": PASSWORD, "TSCOPE_APPROVER_PASSWORD": PASSWORD})
    e.pop("TSCOPE_FIXED_NOW", None)
    return e


def run(step: str, args: list[str], env: dict, *, tscope: bool = True, check: bool = True) -> str:
    cmd = ([sys.executable, "-m", "tripline_scope"] if tscope else [sys.executable]) + args
    t0 = time.perf_counter()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=REPO, check=False)
    dt = time.perf_counter() - t0
    timings[step] = timings.get(step, 0.0) + dt
    console.append(f"$ {' '.join(args[:3])} ...\n{p.stdout}\n{p.stderr}")
    print(f"[{dt:6.1f}s] {step}: {'ok' if p.returncode == 0 else 'FAILED rc=' + str(p.returncode)}", flush=True)
    if check and p.returncode != 0:
        print(p.stdout[-3000:], p.stderr[-3000:], sep="\n", file=sys.stderr)
        raise SystemExit(f"demo step failed: {step}")
    return p.stdout


def stage(n: int, title: str) -> None:
    print(f"\n== Stage {n}: {title}", flush=True)


def login(user: str, env: dict) -> None:
    run(f"login {user}", ["login", "--user", user], env)


def sha_tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def leak_scan(work: Path, needles: list[str]) -> dict:
    from tripline_scope.core.pdf import pdf_text

    needles = sorted({n for n in needles if isinstance(n, str) and len(n) >= 6})
    hits, scanned = [], 0
    for root in (work / "inst", work / "console.txt", work / "dashboard.json"):
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        for f in files:
            if f.is_symlink() or f.name.endswith(".tse"):
                continue           # custody references point at the inputs; .tse files are ciphertext
            data = f.read_bytes()
            text = pdf_text(data) if data[:4] == b"%PDF" else data.decode("utf-8", "replace")
            scanned += 1
            for n in needles:
                if n in text:
                    hits.append({"file": str(f.relative_to(work)), "needle_kind": "seeded secret or raw reference"})
                    break
    control = sum(1 for f in (work / "gen").rglob("*") if f.is_file()
                  and any(n in f.read_bytes().decode("utf-8", "replace") for n in needles))
    return {"files_scanned": scanned, "needles": len(needles), "hits": len(hits), "where": hits[:20],
            "positive_control_input_files_with_hits": control}


def dashboard_smoke(env: dict, case: Path, work: Path) -> dict:
    import http.cookiejar
    import re
    import socket
    import urllib.parse
    import urllib.request

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    login("olivia", env)
    proc = subprocess.Popen([sys.executable, "-m", "tripline_scope", "dashboard", "serve", "--case", str(case),
                             "--port", str(port)], env=env, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        for _ in range(100):
            try:
                page = opener.open(base + "/", timeout=2).read().decode()  # noqa: S310 - fixed loopback http URL
                break
            except OSError:
                if proc.poll() is not None:
                    raise SystemExit("dashboard failed to start:\n" + proc.communicate()[1][-2000:]) from None
                time.sleep(0.2)
        tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        form = urllib.parse.urlencode({"username": "rami", "password": PASSWORD, "csrf": tok}).encode()
        opener.open(urllib.request.Request(base + "/login", data=form), timeout=10).read()  # noqa: S310
        home = opener.open(base + "/", timeout=10).read().decode()  # noqa: S310

        def get(path):
            return json.loads(opener.open(base + path, timeout=30).read())  # noqa: S310

        views = {n: get(f"/api/{n}") for n in ("overview", "financial", "exposure", "paths", "people", "investigation",
                                               "reports")}
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    (work / "dashboard.json").write_text(json.dumps(views, sort_keys=True))
    rel = json.loads(max((case / "reports" / "financial").glob("v*/report.json")).read_bytes())
    fin = views["financial"]
    checks = {
        "enterprise_navigation": 'data-section="financial"' in home and 'data-section="people"' not in home,
        "impact_matches_report": fin.get("financial_impact", {}).get("status") == rel["financial_impact"]["status"],
        "counts_match_report": all(fin["counts"][k] == rel["counts"][k] for k in ("transactions", "suspicious_transactions",
                                                                               "settled_corroborated")),
        "people_not_applicable": views["people"].get("status") == "not_applicable",
        "all_chains_verified": all((k.get("verification") or {}).get("ok") for k in views["reports"]["kinds"].values()
                                   if k.get("status") == "released"),
        "no_integrity_alerts": not any(v.get("integrity_alerts") for v in views.values()),
        "fixture_labelled": views["investigation"].get("fixture") is True,
    }
    print(f"[dashboard] {base}/ checks: {checks}", flush=True)
    if not all(checks.values()):
        raise SystemExit(f"dashboard checks failed: {checks}")
    return checks


def run_scenario(sc: str, work: Path, *, dashboard: bool) -> dict:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    env = env_base(work)
    gen, case = work / "gen", work / "inst" / f"ent-demo-{sc}"
    c = ["--case", str(case)]
    print(f"\n#### Scenario {sc.upper()} (expected impact: {EXPECTED[sc]})", flush=True)
    stage(0, "installation, users and the enterprise-profile case")
    run("init", ["init", "--hospital-name", "Synthetic Utility Ltd (fictional)", "--admin", "admin"], env)
    login("admin", env)
    for u in ("olivia", "rami", "ines"):
        run(f"user add {u}", ["user", "add", u], env)
    run("case init", ["case", "init", str(case), "--case-id", f"ENT-DEMO-{sc.upper()}", "--mode", "incident",
                      "--profile", "enterprise", "--incident-start", "2026-09-01T00:00:00Z",
                      "--incident-end", "2026-09-14T23:59:59Z", "--operator", "olivia", "--reviewer", "rami",
                      "--approver", "ines"], env)
    stage(1, "fictional enterprise with ground truth (stages 2–5: weaknesses, authentication, financial events"
             + (", independent settlement" if sc != "a" else "") + ")")
    run("generate (attested)", ["-m", "tripline_scope.enterprise.synthetic", "--out", str(gen), "--scenario", sc,
                                "--attest"], env, tscope=False)
    truth = json.loads((gen / "ground_truth.json").read_text())
    inputs_before = sha_tree(gen)
    stage(6, "Module A exposure scan (A1–A5, E1–E5) and Module B access paths")
    login("olivia", env)
    run("exposure scan", ["exposure", "scan", *c, "--inputs", str(gen / "estate" / "manifest.yaml")], env)
    run("exposure report", ["exposure", "report", *c], env)
    run("release exposure", ["release", *c, "--kind", "exposure", "--approver", "ines"], env)
    login("olivia", env)
    run("paths ingest", ["paths", "ingest", *c, "--manifest", str(gen / "logs" / "logs.yaml")], env)
    run("paths analyse", ["paths", "analyse", *c, "--window", "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"], env)
    run("paths report", ["paths", "report", *c, "--exposure-report", str(case / "reports" / "exposure" / "v0001")], env)
    run("release paths", ["release", *c, "--kind", "paths", "--approver", "ines"], env)
    stage(7, "financial transaction-evidence analysis")
    login("olivia", env)
    fa = json.loads(run("financial analyse", ["--json", "financial", "analyse", *c, "--config",
                                              str(gen / "financial.yaml")], env))
    run("financial report", ["financial", "report", *c], env)
    run("release financial", ["release", *c, "--kind", "financial", "--approver", "ines"], env)
    stage(8, "deterministic investigation (fixture — NOT AI inference), validation and simulated review")
    login("olivia", env)
    inv = json.loads(run("investigator analyse (fixture)", ["--json", "investigator", "analyse", *c, "--provider",
                                                            "fixture"], env))
    login("rami", env)
    for h in inv["hypotheses"]:
        run(f"review {h} (synthetic reviewer)", ["investigator", "review", *c, "--run", inv["run_id"], "--item", h,
                                                 "--decision", "accept", "--note", "checked against the cited evidence (synthetic demo)"], env)
    stage(9, "signed reports")
    login("olivia", env)
    run("investigator report", ["investigator", "report", *c], env)
    run("release investigation", ["release", *c, "--kind", "investigation", "--approver", "ines"], env)
    stage(10, "verification and leak protection")
    login("rami", env)
    run("tscope verify", ["verify", "--case", str(case)], env)
    run("audit verify", ["audit", "verify", "--case", str(case)], env)
    ver = json.loads(run("investigator verify", ["--json", "investigator", "verify", *c], env))
    pub = work / "home" / "keys" / "hospital_signing.pub"
    for kind in ("exposure", "paths", "financial", "investigation"):
        run(f"tscope-verify chain {kind}", ["-m", "tscope_verify", "chain", str(case / "reports" / kind),
                                            "--hospital-key", str(pub)], env, tscope=False)
    dash = None
    if dashboard:
        stage(11, "Investigation Workbench (loopback, real HTTP)")
        dash = dashboard_smoke(env, case, work)
    (work / "console.txt").write_text("\n".join(console))
    leaks = leak_scan(work, truth["secrets_never_in_outputs"])
    rel = json.loads(max((case / "reports" / "financial").glob("v*/report.json")).read_bytes())
    sus = [t for t in rel["transactions"] if t["suspicious"]]
    checks = {
        "impact_as_expected": rel["financial_impact"]["status"] == EXPECTED[sc],
        "suspicious_count_matches_truth": len(sus) == len(truth["suspicious"]),
        "settled_count_matches_truth": sum(1 for t in sus if t["category"] == "settled_corroborated")
        == len(truth["settled_corroborated"]),
        "investigation_reproducible": bool(ver["chain_ok"] and ver["reproducible"]),
        "no_leaks": leaks["hits"] == 0,
        "leak_scan_positive_control": leaks["positive_control_input_files_with_hits"] > 0,
        "inputs_unchanged": sha_tree(gen) == inputs_before,
        "fixture_not_ai": inv["is_model_inference"] is False,
    }
    print(f"[scenario {sc}] impact={rel['financial_impact']['status']} checks={checks}", flush=True)
    return {"scenario": sc, "financial_impact": rel["financial_impact"], "counts": rel["counts"],
            "suspicious_transactions": [{k: t[k] for k in ("transaction_id", "category", "amount_minor", "currency",
                                                            "approval_indicators")} for t in sus],
            "analysis": {k: fa[k] for k in ("financial_impact", "suspicious_sessions", "suspicious_transactions")},
            "investigation": {"validation": inv["validation"], "hypotheses": inv["hypotheses"]},
            "checks": checks, "dashboard_checks": dash, "leak_scan": leaks}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", choices=["a", "b", "c", "all"], default="all")
    ap.add_argument("--workdir", default=str(HERE / "out"))
    ap.add_argument("--no-dashboard", action="store_true")
    args = ap.parse_args()
    sys.path[:0] = [str(REPO / "src"), str(REPO / "verify" / "src")]
    t0 = time.perf_counter()
    scs = ["a", "b", "c"] if args.scenario == "all" else [args.scenario]
    results = [run_scenario(sc, Path(args.workdir) / f"scenario-{sc}", dashboard=not args.no_dashboard) for sc in scs]
    distinct = len({r["financial_impact"]["status"] for r in results}) == len(results)
    summary = {"title": "Synthetic Utility Financial-System Investigation (fictional; synthetic data only)",
               "scenarios": results, "scenarios_distinguished": distinct,
               "seconds": round(time.perf_counter() - t0, 1), "timings": {k: round(v, 2) for k, v in timings.items()}}
    out = Path(args.workdir) / "demo_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True))
    ok = distinct and all(all(r["checks"].values()) for r in results)
    print(f"\n{'DEMO PASSED' if ok else 'DEMO FAILED'} in {summary['seconds']} s — summary: {out}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
