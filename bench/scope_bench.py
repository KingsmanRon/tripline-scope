"""Module C accuracy and speed benchmark on synthetic data with ground truth.

    python bench/scope_bench.py --rows 1000000 [--workdir DIR] [--threads N] [--publish] [--keep]

Runs synth → extract (fixture standing in for ingest) → estimate → match → people, then measures against ground
truth: auto-link precision (edges), pairwise precision and recall (clusters), unique-person count error,
review-band share, preliminary-estimate error, minors/contact routes, timings per step and peak RSS. Writes
``bench/results/<rows>.json``; ``--publish`` also writes the packaged ``templates/measured/error_rates.json`` that
every scope report quotes. Run on a quiet machine; the result records the hardware.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "verify" / "src")]

from tripline_scope import METHOD_VERSION, testing  # noqa: E402
from tripline_scope.core.case import Case  # noqa: E402
from tripline_scope.core.context import command  # noqa: E402
from tripline_scope.core.home import Home  # noqa: E402
from tripline_scope.scope import config, data, estimate, evaluate, people  # noqa: E402
from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources, synth_reference_date  # noqa: E402
from tripline_scope.scope.match import Matcher, make_pair_key  # noqa: E402
from tripline_scope.synth.generate import generate  # noqa: E402


def rss_mb() -> int:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


def hardware() -> dict:
    mem = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem = round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    cpu = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"cpus": os.cpu_count(), "memory_gb": mem, "cpu_model": cpu, "platform": platform.platform(),
            "shared_machine_note": "measured on a development machine shared with other workloads"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--seed", type=int, default=20260914)
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--memory-limit", help="DuckDB memory cap, e.g. 56GB (spill stays disabled: an exceeded cap "
                                           "aborts the run with an out-of-memory error instead of writing plaintext)")
    ap.add_argument("--approved-by", help="required above 20M rows: who approved the cost/resources (recorded)")
    args = ap.parse_args(argv)
    if args.rows > 20_000_000 and not args.approved_by:
        ap.error("runs above 20M rows need --approved-by (see docs/BENCHMARK_80M_RUNBOOK.md)")
    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="scope-bench-"))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    T: dict[str, float] = {}
    rss: dict[str, int] = {}

    def mark(name, t0):
        T[name] = round(time.time() - t0, 2)
        rss[name] = rss_mb()
        print(f"{name}: {T[name]} s, peak RSS {rss[name]} MB", flush=True)

    t0 = time.time()
    syn = work / "synth"
    meta = generate(syn, args.rows, seed=args.seed, threads=args.threads)
    mark("synth", t0)
    testing.setup_installation(work / "inst")
    case_dir = testing.open_case(work / "inst")
    testing.login("olivia")
    case, home = Case(case_dir), Home()
    t0 = time.time()
    with command("bench ingest", home=home, case=case, role="operator") as ctx:
        smap = register_synth_sources(case, ctx.store, syn, actor=ctx.actor)
        load_synth_as_extract(case, ctx.store, syn, source_map=smap)
        store = ctx.store
    mark("extract", t0)
    cfg = config.load(case)
    ref = synth_reference_date(syn)
    t0 = time.time()
    d = data.load(case, store, cfg, threads=args.threads, memory_limit=args.memory_limit, reference_date=ref)
    mark("load", t0)
    t0 = time.time()
    est = estimate.estimate(d)
    mark("estimate", t0)
    t0 = time.time()
    m = Matcher(d, cfg, pair_key=make_pair_key(store.fingerprinter("review-pair")), threads=args.threads)
    m.run()
    mark("match", t0)
    t0 = time.time()
    people.build(d.con, cfg, d.reference_date)
    mark("people", t0)
    evaluate.load_ground_truth(d.con, syn / "ground_truth.parquet", smap)
    ev = evaluate.evaluate(d.con, estimate_point=est["point"])
    result = {
        "schema": "tripline.scope-bench/v1",
        "method_version": METHOD_VERSION,
        "date": dt.date.today().isoformat(),
        "rows": {"admissions": meta["totals"]["admissions"], **meta["totals"],
                 "identity_rows": ev["identity_rows"], "match_records": m.stats["records"]},
        "seed": args.seed,
        "config_sha256": config.config_sha256(cfg),
        "accuracy": ev,
        "estimate": {k: est[k] for k in ("point", "lower", "upper")},
        "matcher": {"stats": m.stats, "timings_s": m.timings},
        "timings_s": T,
        "peak_rss_mb": rss,
        "hardware": hardware(),
        "memory_limit": args.memory_limit,
        "approved_by": args.approved_by,
    }
    out = HERE / "results" / f"{args.rows}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    print(json.dumps({k: ev[k] for k in ("auto_link_precision", "pairwise_precision", "pairwise_recall",
                                         "person_count_error", "review_band_share", "estimate_error_vs_final")}, indent=1))
    if args.publish:
        pub = {
            "source": f"bench/results/{args.rows}.json", "date": result["date"], "dataset_rows": args.rows,
            "method_version": METHOD_VERSION,
            "auto_link_precision_pct": round(100 * ev["auto_link_precision"], 3),
            "pairwise_precision_pct": round(100 * ev["pairwise_precision"], 3),
            "pairwise_recall_pct": round(100 * ev["pairwise_recall"], 3),
            "person_count_error_pct": round(100 * ev["person_count_error"], 3),
            "review_band_share_pct": round(100 * ev["review_band_share"], 3),
            "preliminary_estimate_error_pct": round(100 * ev["estimate_error_vs_final"], 3),
            "data": "synthetic lab data with typos, swapped names, maiden names, twins, shared phones, missing IDs",
        }
        p = ROOT / "src" / "tripline_scope" / "templates" / "measured" / "error_rates.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(pub, indent=2, sort_keys=True) + "\n")
    d.con.close()
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
