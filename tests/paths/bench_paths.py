"""Module B scale measurement (not a test; run by hand):

    python tests/paths/bench_paths.py --events 1000000 --work /path/to/scratch

Generates a synthetic incident of about ``--events`` records, then runs ``tscope paths ingest``, ``analyse``,
``report`` and ``scope-candidates`` as separate processes and prints wall time, throughput, peak RSS per phase,
encrypted disk use, file counts and parser failures as JSON. Measured numbers only; no guarantees.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _du(p: Path) -> tuple[int, int]:
    size = files = 0
    for f in p.rglob("*"):
        if f.is_file() and not f.is_symlink():
            size += f.stat().st_size
            files += 1
    return size, files


def _phase(argv, env) -> dict:
    t = time.perf_counter()
    r = subprocess.run([sys.executable, "-m", "tripline_scope", "--json", *argv], env=env, capture_output=True, text=True)
    wall = time.perf_counter() - t
    if r.returncode != 0:
        raise SystemExit(f"{argv[:2]} failed: {r.stderr[-2000:]}")
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024
    return {"seconds": round(wall, 2), "peak_rss_mb_so_far": peak, "out": json.loads(r.stdout)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=1_000_000)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    work = Path(a.work)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "verify" / "src")]
    from tripline_scope import testing
    from tripline_scope.paths import synthetic

    t = time.perf_counter()
    truth = synthetic.generate(work / "logs", "demo", scale=int(a.events * 0.78))
    gen_s = time.perf_counter() - t
    logs_bytes, logs_files = _du(work / "logs")
    for k in list(os.environ):
        if k.startswith("TSCOPE_"):
            del os.environ[k]
    env_ = testing.setup_installation(work / "inst")
    case_dir = testing.open_case(work / "inst")
    testing.login("olivia")
    env = dict(os.environ, PYTHONPATH=f"{ROOT / 'src'}:{ROOT / 'verify' / 'src'}", **env_.vars())
    res = {"synthetic_events": truth["total_events"], "generation_seconds": round(gen_s, 1),
           "input_bytes": logs_bytes, "input_files": logs_files}
    ing = _phase(["paths", "ingest", "--case", str(case_dir), "--manifest", str(work / "logs" / "logs.yaml")], env)
    res["ingest"] = {"seconds": ing["seconds"], "events": ing["out"]["events"],
                     "events_per_second": round(ing["out"]["events"] / ing["seconds"]),
                     "parse_failures": ing["out"]["parse_failures"], "peak_rss_mb": ing["peak_rss_mb_so_far"]}
    an = _phase(["paths", "analyse", "--case", str(case_dir), "--window", "2026-09-01T00:00:00Z/2026-09-14T23:59:59Z"], env)
    res["analyse"] = {"seconds": an["seconds"], "peak_rss_mb_max_so_far": an["peak_rss_mb_so_far"],
                      **{k: an["out"][k] for k in ("paths", "edges", "anomalies", "gaps")}}
    rp = _phase(["paths", "report", "--case", str(case_dir)], env)
    res["report"] = {"seconds": rp["seconds"], "timeline_rows": rp["out"]["timeline_rows"],
                     "peak_rss_mb_max_so_far": rp["peak_rss_mb_so_far"]}
    sc = _phase(["paths", "scope-candidates", "--case", str(case_dir), "--out", str(work / "cand.json")], env)
    res["scope_candidates"] = {"seconds": sc["seconds"]}
    w_bytes, w_files = _du(case_dir / "work" / "paths")
    r_bytes, r_files = _du(case_dir / "reports" / "paths")
    res["case_disk"] = {"work_paths_bytes": w_bytes, "work_paths_files": w_files, "report_draft_bytes": r_bytes,
                        "report_files": r_files}
    res["host"] = {"cpus": os.cpu_count(), "python": sys.version.split()[0]}
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
