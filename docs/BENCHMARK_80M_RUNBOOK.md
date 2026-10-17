# Runbook — full 80M-admission person-matching validation (DEFERRED)

Status: **DEFERRED — resource-dependent full 80M person-level matching validation; preliminary estimation already
measured separately** (`bench/results/estimate_80000000.json`: estimate path 265.9 s, peak RSS 4.9 GB, +1.85 % vs
the synthetic truth, on 4 vCPU / 15.7 GB). Nothing in this runbook has been executed. It states what must be true
before the run, how to run it, what to measure and when to stop. It makes no timing prediction.

## 1. Approval before execution

* The run needs a dedicated machine for several hours and possibly a paid cloud or lab host. The operator records,
  before starting: who approved the cost and the resources, the machine (vCPU, RAM, storage, encryption), the
  expected maximum duration they are willing to pay for, and where results go.
* `bench/scope_bench.py` refuses any run above 20M rows without `--approved-by "<name, role, date>"`; the value is
  written into the result file.
* Synthetic data only. No hospital data may be used for this benchmark.

## 2. Hardware and memory prerequisites

* At least the reference size from the README: 16 cores, 64 GB RAM, SSD. The whole-estate match path loads every
  identity row and all dependent rows into one in-memory DuckDB session. On 15.7 GB it ran out of memory at 80M rows
  three times (12.1 GB used); the 10M run peaked at 6.2 GB. Do not assume linear scaling.
* Free disk: the synthetic estate (~4 GB at 80M) + encrypted extracts (~similar) + headroom; measure with `du` before
  and after.
* No swap, or encrypted swap only (`tscope doctor` reports swap).

## 3. Encrypted storage and spill

* Keep the work directory on an encrypted volume (LUKS or equivalent); synthetic data is not sensitive, but the run
  should exercise the production posture.
* Spill is **disabled** by design. Note a gap found while preparing this runbook: the installation setting
  `duckdb.spill_dir` + `spill_dir_encrypted: true` (described in SECURITY.md) is honoured by
  `core.duck.connect_for_home`, but the Module C load path (`scope.data.connect`) does not use it. A run that relies on
  encrypted spill therefore needs that wiring first (a reviewed code change, outside this release). Without it the
  run is a pure in-memory test.

## 4. Commands

```
# 1. preliminary estimate (already measured; re-run only to compare hardware)
python bench/estimate_bench.py --rows 80000000 --workdir /enc/bench80 --threads 16 --memory-limit 56GB

# 2. full matching (deferred) — hard memory cap, approval recorded
systemd-run --scope -p MemoryMax=60G -p MemorySwapMax=0 \
  python bench/scope_bench.py --rows 80000000 --workdir /enc/bench80-match --threads 16 \
    --memory-limit 56GB --approved-by "<name, role, date>" --keep
```

`--memory-limit` caps DuckDB below the cgroup limit so DuckDB fails with an out-of-memory error before the kernel
kills the process. Results go to `bench/results/80000000.json` (accuracy, timings per stage, peak RSS per stage,
hardware, memory limit, approver).

## 5. Measurements to record

Per stage (synth, extract, load, estimate, match, people): wall time and peak RSS (from the result file); machine
facts (`hardware` block); `du -sh` of the work directory; DuckDB memory limit; thread count. Accuracy from
`evaluate`: auto-link precision, pairwise precision and recall, person-count error, review-band share, preliminary
estimate vs final count.

## 6. Accuracy verification

Pass criteria are the existing targets (ACCEPTANCE.md §3): auto-link precision ≥ 99.5 %, person-count error ≤ 1 %,
review band ≤ 0.5 % of people, preliminary estimate within 5 % of the final count, full run < 24 h. Compare with the
10M result (`bench/results/10000000.json`); a regression at 80M is reported as a FAIL with numbers, not tuned away.

## 7. Abort conditions

Stop and record the reason (do not retry blindly) when any of these happens:

* DuckDB raises an out-of-memory error, or the cgroup kills the process (exit 137);
* free disk on the work volume falls below 10 %;
* swap activity appears on a host that should have none;
* a stage exceeds the duration the approver accepted;
* the host is shared with other workloads (results would not be comparable).

Record a failed attempt in ACCEPTANCE.md exactly as the three 80M estimate attempts were recorded.
