"""Preliminary-estimate benchmark at scale (e.g. 80M admission rows): synth → extract → load → estimate only.

    python bench/estimate_bench.py --rows 80000000 [--workdir DIR] [--synth DIR] [--threads N]

The full match is not run (it needs more memory than this benchmark targets); the estimate is compared with the
true number of people in the synthetic ground truth instead of the final matched count.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE.parent / "verify" / "src")]

import pyarrow.parquet as pq  # noqa: E402
from scope_bench import hardware, rss_mb  # noqa: E402

from tripline_scope import METHOD_VERSION, testing  # noqa: E402
from tripline_scope.core.case import Case  # noqa: E402
from tripline_scope.core.context import command  # noqa: E402
from tripline_scope.core.home import Home  # noqa: E402
from tripline_scope.scope import config, data, estimate  # noqa: E402
from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources, synth_reference_date  # noqa: E402
from tripline_scope.synth.generate import generate  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--synth", help="reuse an existing synthetic dataset directory")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--memory-limit", help="DuckDB memory limit, e.g. 13GB (default: DuckDB's 80%% of RAM)")
    ap.add_argument("--seed", type=int, default=20260914)
    args = ap.parse_args(argv)
    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="estimate-bench-"))
    T: dict[str, float] = {}
    rss: dict[str, int] = {}

    def mark(name, t0):
        T[name] = round(time.time() - t0, 2)
        rss[name] = rss_mb()
        print(f"{name}: {T[name]} s, peak RSS {rss[name]} MB", flush=True)

    syn = Path(args.synth) if args.synth else work / "synth"
    if not args.synth:
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        t0 = time.time()
        generate(syn, args.rows, seed=args.seed, threads=args.threads)
        mark("synth", t0)
    shutil.rmtree(work / "inst", ignore_errors=True)
    meta = json.loads((syn / "synth_meta.json").read_text())
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
    t0 = time.time()
    d = data.load(case, store, cfg, threads=args.threads, memory_limit=args.memory_limit,
                  reference_date=synth_reference_date(syn))
    mark("load", t0)
    t0 = time.time()
    est = estimate.estimate(d)
    mark("estimate", t0)
    gt = pq.read_table(syn / "ground_truth.parquet", columns=["person_id"])
    true_people = len(set(gt.column("person_id").to_pylist()))
    result = {
        "schema": "tripline.estimate-bench/v1",
        "method_version": METHOD_VERSION,
        "date": dt.date.today().isoformat(),
        "rows": meta["totals"],
        "estimate": {k: est[k] for k in ("point", "lower", "upper")},
        "true_people": true_people,
        "estimate_error_vs_truth": abs(est["point"] - true_people) / true_people,
        "truth_within_bounds": est["lower"] <= true_people <= est["upper"],
        "timings_s": T,
        "estimate_path_s": round(T["load"] + T["estimate"], 2),
        "peak_rss_mb": rss,
        "hardware": hardware(),
        "note": "load + estimate is the preliminary-estimate path after ingest; synth and extract stand in for ingest.",
    }
    out = HERE / "results" / f"estimate_{args.rows}.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    print(json.dumps({k: result[k] for k in ("estimate", "true_people", "estimate_error_vs_truth",
                                             "truth_within_bounds", "estimate_path_s")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
