"""One-command synthetic lab-breach demo (also the sales demo).

Steps: synthesise 10 lab databases → build and restore SQL Server .bak backups → add a "published leak sample"
→ (optional) synthetic incident logs through access-path analysis → estimate → release preliminary →
match → review → report → release → notification pack → verify → close → verify certificate. Then a leak
scan of every log, console capture, report and PDF for the synthetic identifiers, and a source-checksum check.

Everything is synthetic. SQL Server Developer Edition is used only because this is a demo.
Run via ``demo/lab-breach/run.sh`` (starts the database containers) or directly:

    python demo/lab-breach/run_demo.py --rows 100000 --workdir demo/lab-breach/out
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
        "TSCOPE_FIXED_NOW": "",  # real clock for the demo
    })
    e.pop("TSCOPE_FIXED_NOW")
    return e


def run(step: str, args: list[str], env: dict, *, tscope: bool = True, check: bool = True, stdin: str | None = None) -> str:
    cmd = ([sys.executable, "-m", "tripline_scope"] if tscope else []) + args
    t0 = time.perf_counter()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, input=stdin, cwd=REPO)
    dt = time.perf_counter() - t0
    timings[step] = timings.get(step, 0.0) + dt
    console.append(f"$ {' '.join(args[:3])} ...\n{p.stdout}\n{p.stderr}")
    print(f"[{dt:7.1f}s] {step}: {'ok' if p.returncode == 0 else 'FAILED rc=' + str(p.returncode)}", flush=True)
    if check and p.returncode != 0:
        print(p.stdout[-3000:], p.stderr[-3000:], sep="\n", file=sys.stderr)
        raise SystemExit(f"demo step failed: {step}")
    return p.stdout


def login(user: str, env: dict) -> None:
    run(f"login {user}", ["login", "--user", user], env)


def sha_tree(paths: list[Path]) -> dict[str, str]:
    out = {}
    for p in paths:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        out[str(p)] = h.hexdigest()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=100_000, help="synthetic admission rows")
    ap.add_argument("--workdir", default=str(HERE / "out"))
    ap.add_argument("--mssql-host", default="127.0.0.1")
    ap.add_argument("--mssql-port", type=int, default=14330)
    ap.add_argument("--mssql-container", default="mssql-test", help="container used for .bak transfer (docker cp)")
    ap.add_argument("--with-logs", action="store_true", default=True, help="include synthetic incident logs (Module B)")
    ap.add_argument("--no-logs", dest="with_logs", action="store_false")
    ap.add_argument("--keep", action="store_true", help="keep an existing workdir")
    args = ap.parse_args()

    work = Path(args.workdir).resolve()
    if work.exists() and not args.keep:
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    env = env_base(work)
    env.setdefault(SQL_SA_PASSWORD_ENV, "Synth3tic!Demo")
    case = work / "case"

    # 1. synthetic data and .bak backups of 10 databases
    run("synth", ["synth", "--rows", str(args.rows), "--databases", "10", "--seed", "2026",
                  "--out", str(work / "synth")], env)
    run("build .bak backups", [sys.executable, str(HERE / "build_baks.py"), "--synth", str(work / "synth"),
                               "--out", str(work / "baks"), "--host", args.mssql_host, "--port", str(args.mssql_port),
                               "--container", args.mssql_container, "--password-env", SQL_SA_PASSWORD_ENV],
        env, tscope=False)
    baks = sorted((work / "baks").glob("*.bak"))
    leak = work / "synth" / "leak_sample.csv"
    sources = baks + [leak]
    before = sha_tree(sources)

    # 2. installation, users, restore target
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
    run("case init", ["case", "init", str(case), "--case-id", "DEMO-LAB-2026", "--mode", "incident",
                      "--incident-start", "2026-09-01T00:00:00Z", "--incident-end", "2026-09-14T23:59:59Z",
                      "--operator", "olivia", "--reviewer", "rami", "--approver", "ines",
                      "--retain-until", "2033-12-31"], env)

    # 3. sources (chain of custody)
    login("olivia", env)
    common = ["--legal-basis", "POPIA s22 incident investigation (synthetic demo)",
              "--received-at", "2026-09-15T08:00:00Z", "--case", str(case)]
    for b in baks:
        run("source add", ["source", "add", "--kind", "mssql_bak", "--path", str(b), "--label", f"backup {b.stem}",
                           "--evidence-role", "system_copy", "--supplied-by", "Head of IT", *common], env)
    run("source add leak", ["source", "add", "--kind", "csv", "--path", str(leak), "--label", "published leak sample",
                            "--evidence-role", "leak_sample", "--supplied-by", "Hospital attorneys", "--copy", *common], env)

    # 4. optional access-path analysis from synthetic incident logs
    candidates = None
    if args.with_logs:
        logs = work / "logs"
        run("synthetic incident logs", [sys.executable, "-m", "tripline_scope.paths.synthetic", "--out", str(logs),
                                        "--scenario", "demo"], env, tscope=False)
        run("paths ingest", ["paths", "ingest", "--case", str(case), "--manifest", str(logs / "logs.yaml")], env)
        run("paths analyse", ["paths", "analyse", "--case", str(case),
                              "--window", "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"], env)
        run("paths report", ["paths", "report", "--case", str(case)], env)
        candidates = work / "scope_candidates.json"
        run("paths scope-candidates", ["paths", "scope-candidates", "--case", str(case), "--out", str(candidates)], env)

    # 5. ingest: restore, discover, extract
    run("ingest", ["ingest", "--case", str(case)], env)
    if candidates:
        run("scope constrain", ["scope", "constrain", "--case", str(case), "--candidates", str(candidates),
                                "--reason", "Access-path analysis candidates; full scope kept as upper bound"], env)

    # 6. preliminary estimate → first Regulator filing
    run("estimate", ["estimate", "--case", str(case)], env)
    run("release preliminary", ["release", "--case", str(case), "--kind", "scope", "--approver", "ines"], env)

    # 7. match, review, report
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

    # 8. verify offline, then close
    run("verify", ["verify", "--case", str(case)], env)
    run("audit verify", ["audit", "verify", "--case", str(case)], env)
    run("audit export", ["audit", "export", "--case", str(case), "--out", str(work / "audit.jsonl")], env)
    after = sha_tree(sources)
    run("close", ["case", "close", "--case", str(case), "--approver", "ines",
                  "--external-backup", "demo: no keystore backups taken"], env)
    pub = work / "home" / "keys" / "hospital_signing.pub"
    run("tscope-verify certificate", [sys.executable, "-m", "tscope_verify", "certificate",
                                      str(case / "reports" / "closure" / "certificate.json"), "--hospital-key", str(pub)],
        env, tscope=False)
    run("tscope-verify chain", [sys.executable, "-m", "tscope_verify", "chain", str(case / "reports" / "scope"),
                                "--hospital-key", str(pub)], env, tscope=False)

    # 9. leak scan + source safety
    (work / "console.txt").write_text("\n".join(console))
    leak_result = leak_scan(work, exempt=[export])
    summary = {
        "rows": args.rows,
        "timings_s": {k: round(v, 2) for k, v in timings.items()},
        "total_s": round(sum(timings.values()), 1),
        "sources_unchanged": before == after,
        "leak_scan": leak_result,
    }
    (work / "demo_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("total_s", "sources_unchanged", "leak_scan")}, indent=2))
    ok = summary["sources_unchanged"] and leak_result["hits"] == 0
    print("DEMO PASSED" if ok else "DEMO FAILED")
    return 0 if ok else 1


def leak_scan(work: Path, exempt: list[Path]) -> dict:
    """Scan every non-exempt file in the workdir (logs, console capture, reports, PDFs, audit) for the
    synthetic identifiers from ground truth."""
    sys.path[:0] = [str(REPO / "src"), str(REPO / "verify" / "src")]
    import pyarrow.parquet as pq

    from tripline_scope.core.pdf import pdf_text

    gt = pq.read_table(work / "synth" / "ground_truth_identifiers.parquet")
    needles = set()
    for col in gt.column_names:
        for v in gt.column(col).to_pylist():
            if isinstance(v, str) and len(v) >= 6:
                needles.add(v)
    roots = [work / "case", work / "home", work / "console.txt", work / "audit.jsonl", work / "demo_summary.json"]
    skip = [p.resolve() for p in exempt]
    hits, scanned = [], 0
    for root in roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
        for f in files:
            if any(str(f.resolve()).startswith(str(s)) for s in skip) or f.name.endswith(".tse"):
                continue  # encrypted envelopes are ciphertext; exempt export dir holds authorised notices
            data = f.read_bytes()
            text = pdf_text(data) if data[:4] == b"%PDF" else data.decode("utf-8", "replace")
            scanned += 1
            for n in needles:
                if n in text:
                    hits.append({"file": str(f.relative_to(work)), "kind": "synthetic identifier"})
                    break
    return {"files_scanned": scanned, "identifiers_checked": len(needles), "hits": len(hits), "where": hits[:20]}


if __name__ == "__main__":
    raise SystemExit(main())
