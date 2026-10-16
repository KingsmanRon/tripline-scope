# Acceptance record — Tripline Scope v0

Every result below was produced in this repository on synthetic data, on the machine described in §1. "Pass" means
the check was run and passed; "Fail" means it was run and missed the target; "Not run" means it was not done here,
with the reason. No timing in this document is a guarantee.

## 1. Benchmark environment

| Item | Value |
|---|---|
| CPU | Intel Xeon @ 2.10 GHz, **4 vCPU** (spec reference hardware: 16 cores) |
| RAM | **15.7 GB**, no swap (spec reference: 64 GB) |
| Disk | virtual disk, ~22 GB free during runs |
| OS | Ubuntu 24.04 (Linux 6.18), Python 3.12.3, DuckDB 1.5.6, Splink 5.0.0 |
| Containers | Docker 29.8; SQL Server 2022 **Developer** (synthetic data only); PostgreSQL 16 (native, throw-away clusters) |
| Note | shared development VM; earlier measurements ran while other build work used the same CPUs |

## 2. Test suites

| Suite | Command | Result |
|---|---|---|
| Everything (incl. Docker/SQL Server and PostgreSQL integration) | `pytest -q tests` | **390 passed, 3 skipped** (the 3 are opt-in `-m slow` ingest benchmarks). Full run: 385 passed in 9 min 47 s; its 4 failures were packaging tests reading a bundle built before pyOpenSSL was locked, and passed (67/67) after `make bundle`; the opaque-reference test was added afterwards and passes with the 315-test non-Docker run |
| Same, networking disabled (empty namespace, loopback only) | `make test-offline` | **374 passed**, 13 deselected (Docker-dependent and slow) |
| Lint | `ruff check src tests verify bench demo scripts` | pass |
| Locks pinned with hashes | `make check-locks` | pass (runtime 42, dev 80) |
| Licence gate | `make licences` | **PASS**: 42 runtime distributions, 41 allowed, 1 by documented exception (Pillow, MIT-CMU), 0 unknown/denied |
| SBOM | `make sbom` | PASS: CycloneDX 1.6, 43 components, every locked dependency with version, purl, SHA-256, licence |
| Offline bundle | `make bundle && make bundle-verify` | built (496 MB) and signed checksums verified with `tscope-verify` (ephemeral release key — see §5) |
| Offline install | `make install-test` | **PASS** venv mode in a clean `python:3.12-slim` container with `--network none`; **PASS** container mode on an `internal: true` compose network (1.1.1.1 and 8.8.8.8 unreachable) |
| One-command demo, 100k rows | `demo/lab-breach/run.sh` | **PASS** in 130 s (`bench/results/demo_100k.json`) |
| Same demo, air-gapped | `scripts/run_airgapped.sh … run_demo.py` | **PASS** in 135 s; the namespace's only route is the Docker bridge; pypi.org unreachable (`bench/results/demo_100k_airgapped.json`) |

## 3. Definition of done

| Criterion | Target | Measured | Status |
|---|---|---|---|
| Auto-link precision, 10M rows | ≥ 99.5 % | **99.912 %** (pairwise precision 99.932 %, recall 99.754 %) | Pass |
| Unique-person count error, 10M | ≤ 1 % | **0.15 %** (1 410 524 predicted vs 1 408 377 true) | Pass |
| Review band, 10M | ≤ 0.5 % of people | **0.465 %** (6 557 people, 4 445 pairs; 0.07 % at 100k, 0.15 % at 1M). First run missed at 0.89 %; fixed — see §4.1 | Pass |
| Preliminary estimate vs final count | within 5 % | **2.5 %** at 10M (2.7 % at 100k, 2.6 % at 1M); the true count is inside the stated range in every run (lower end calibrated — §4.1) | Pass |
| Estimate time, 80M rows | < 1 h | **4 min 26 s** for the estimate path (sliced load + estimate) on 4 vCPU / 15.7 GB, peak RSS 4.9 GB, no spill; 1.85 % from the true count, which lies inside the stated range (`bench/results/estimate_80000000.json`). Three earlier attempts with the whole-estate load ran out of memory — §4.2 | Pass |
| Full run, 10M rows | < 2 h on 16 cores/64 GB | **≈ 2 min** for extract → load → estimate → match → people on 4 vCPU/15.7 GB, peak RSS 6.2 GB (`bench/results/10000000.json`); SQL Server restore + discovery at 10M **not run** — at the measured 14–32k rows/s it projects to roughly 20–40 min for the ~30M rows of a 10M-admission estate | Pass for matching; ingest projected, not measured |
| Full run, 80M rows | < 24 h | **Not run** (needs > 15.7 GB RAM for matching) | Not run |
| Source safety | checksums identical; no write reaches a source | identical before/after every demo command and every module test; process write guard + inotify watcher tests (`tests/core`, `tests/ingest`, `tests/acceptance`) | Pass |
| Leak safety | no synthetic identifier in logs, console, reports, PDFs (notify pack exempt) | demo leak scan: 0 hits in 59 files for 85 612 identifiers; per-module leak tests (ingest, A, B, C, acceptance) | Pass |
| Offline | full demo with networking disabled; bundle installs on a clean VM with no network | demo passes air-gapped; bundle installs in a clean network-less **container**; **clean VM / Hyper-V not tested** | Pass (container); VM not run |
| Approval gate | release fails without approver sign-in and when operator = approver | `tests/core/test_reports_closure.py`, module release tests | Pass |
| Case closure | no case data readable, key gone, certificate verifies | `tests/core`, demo close step + `tscope-verify certificate` | Pass |
| Integrity | byte-identical report for identical inputs; `tscope verify` fails on any altered field, signature or chain link; audit chain verifies and fails when tampered | core, A, B and C determinism and tamper tests; demo `verify` | Pass |
| Notices | minors routed to guardians; people without contact counted correctly | 20k cross-check: 503 routed vs 502 true, 99 flagged vs 98 true; C flow test > 98 % segment agreement | Pass |
| Exposure scan | 5 control families, signed ranked report, coverage gaps, correct remediation diff, zero leakage | 96 Module A tests incl. PostgreSQL 16 and SQL Server 2022 catalogue runs; 10 verified mitigated deltas | Pass |
| Access paths | all parser families; direct edges recovered; weak edges labelled inference; missing logs explicit | 37 Module B tests; native EVTX demonstrated by fixture | Pass |
| Integration | path→scope constraints and scan→containment with provenance; never silently shrink scope; degraded mode | contract test, demo (constrain with LabDB09 `not_assessable`), degraded-mode test, real-ingest-vs-direct consistency test | Pass |
| Licences + SBOM + RFC 8785 vectors | — | licence gate PASS; SBOM covers all; RFC 8785 Appendix B and §3.2 vectors pass | Pass |
| SQL Server TLS | encrypted session; certificate chain and host name verified | pyOpenSSL (Apache-2.0) now bundled. Against SQL Server 2022 with a test-CA certificate: right CA + matching host → encrypted session; mismatched host → refused (accepted only with `trust_server_certificate`, which skips the host check alone); wrong CA → refused in both modes. Unit tests `tests/ingest/test_mssql_tls.py`; the server-side matrix was run by hand (needs a certificate installed in the container) | Pass |
| Review page as a live process | binds 127.0.0.1 only; sign-in; DNS-rebinding refused | `tscope scope review` started as a subprocess: listening only on 127.0.0.1, reviewer sign-in and item fetch over real HTTP, foreign Host header → 400 (`test_review_page_live_server`) | Pass |
| Documentation | README, METHOD, SECURITY, EXPOSURE, ACCESS_PATHS, INTEGRATION, ACCEPTANCE | all present (plus INGEST, SUPPLY_CHAIN, PLAN) | Pass |

## 4. Details for the misses and the scale runs

### 4.1 Review band at 10M, and the estimate's lower bound

The first 10M run put 0.89 % of people in the review band (target 0.5 %). Diagnosis on the 10M run: borderline
pairs grew faster than the data (17 → 360 → 9 549 per tenfold increase); most were unrelated people sharing a
common surname sound and birthday, and 95 % of the pairs routed to review by the "conflicting date of birth" rule
were different people (mostly siblings in one household). Fix, without loosening any threshold: the model now also
compares middle names and street address, and a non-slip date-of-birth conflict is a non-link (it can only count a
person twice, never merge two people). Result at 10M: review band 0.465 %, auto-link precision 99.874 → 99.912 %,
recall 99.62 → 99.75 %, person-count error 0.24 → 0.15 %.

The same re-run showed that the estimate's structural lower bound was either invalid (distinct ID counts overshoot
when one person carries two valid IDs) or far too loose at scale (transitive merging: 21–38 % below the truth at
10M). The lower end is now the point estimate minus 5 % — calibrated on synthetic data, where the estimate was
2.2–2.7 % above the truth in every run — and is labelled as calibrated in the report and in METHOD.md.

### 4.2 Preliminary estimate at 80M rows

* Synthetic estate: 80M admissions, 40M billing rows, 97.6M results, 19.9M patient (identity) rows in 10
  databases; 11.33M true people. Generation 5 946 s; extract to encrypted Parquet 268–561 s (stand-ins for ingest).
* **Three attempts with the original estimate ran out of memory** (10.6 GB at DuckDB's default cap; 12.1 GB at a
  13 GB cap, twice — the second time after dropping unneeded identity columns). That path loaded every identity
  column and all 218M dependent rows into one in-memory session and sorted it; spilling to disk stays disabled
  because it would write plaintext temporary files (SECURITY.md).
* **Fix: the estimate now works in slices** (METHOD §5). Each source is processed on its own, split by a hash of
  the patient key into slices of at most 3M identity rows (12 slices here). Each usable identity row is reduced
  to five 64-bit values, and the counts run over that table. Dependent rows join their patient only within one
  source and by the same key, so the result is exactly the whole-estate result: tested at three slicings
  (`tests/scope/test_estimate_sliced.py`, which also checks the original string-key SQL) and identical on a
  2M-row estate (point 289 265 both ways).
* **Result at 80M:** estimate path 265.9 s (load 257.5 s, of which most is decrypting and reading 238M rows;
  counting 8.4 s), peak RSS 4.9 GB with a 13 GB DuckDB cap, nothing spilled. Point 11 541 765 vs 11 331 565 true
  (+1.85 %), range 10 964 676–13 039 938 contains the truth. 179 411 identity rows lacked enough identifiers and
  2.6M dependent rows had no matching patient; both are reported, as before.
* The person-level **match** at 80M still loads the estate as a whole and was not run here (needs the 64 GB
  reference machine or an encrypted spill volume).

### 4.3 Module measurements (synthetic, 4 vCPU shared)

| Module | Workload | Result |
|---|---|---|
| Ingest — CSV | 200k rows, 4 tables | discovery 7.8 s (~26k rows/s), extract 1.9–2.2 s (72–85k rows/s) |
| Ingest — SQL Server `.bak` | 17 MB backup, 200k rows | restore 1.6–3.1 s, discovery 10–14 s (14–19k rows/s), extract 5–8 s (20–32k rows/s) |
| Ingest — PostgreSQL custom dump | 200k rows | restore 0.5 s, discovery 7.8 s, extract 2.5 s |
| Module A exposure scan | 20k / 50k mixed files | 4.4 s (~4 500 files/s, 115 MB RSS) / 17.3 s (126 MB); 0 parser failures |
| Module B access paths | 99k / 988k events | ingest 8.2 s / 73 s (~13.5k events/s), analyse 10 s / 364 s (peak 4.1 GB), 0 parser failures |
| Module C | 100k / 1M / 10M admission rows | match 9.3 s / 17 s / 47 s; auto-link precision 99.916 / 99.950 / 99.912 % |
| Cross-check | 20k rows, real `.bak` → ingest → C vs direct extract | identical people, segments, precision and recall after the discovery and row-key fixes this check found |

## 5. Not done, limitations and owner decisions

* **Not demonstrated:** install on a clean physical machine, VM or Hyper-V;
  80M full run; SQL Server restore + discovery at 10M; reviewer TOTP; provider co-signing in the demo.
* **Release key:** the bundle here is signed with an ephemeral key generated outside the repository. A real release
  key must be generated off-repo and published out of band.
* **Licence decisions for the owner:** permissive licences outside the short list in linked native code (Unicode-3.0
  in pydantic-core's ICU4X crates, CC0-1.0 in evtx's encoding tables, FTL/IJG/libpng/libtiff/X11/BSL-1.0/Zlib notices in
  Pillow/pyarrow/splink assets); reportlab's wheel ships an unused GPL sample font and unlicensed Adobe/Monotype fonts
  (the installers delete them; the wheel itself is unmodified); DuckDB's vendored code notices and OpenSSL's notice in
  cryptography need confirming. The product's own licence in `pyproject.toml` is a placeholder.
* **CI on GitHub** runs lint/locks, licences/SBOM, the non-Docker tests and the bundle. Two failures found there
  were fixed: the bundle step's `docker image inspect` template broke on newer Docker, and the paths report's leak
  guard occasionally refused a timeline because a keyed account reference (`ACCT-` + 10 hex) happened to be all
  digits and read as a phone number; Tripline's own opaque references are now recognised (`core/redact.py`).
* **Synthetic data only.** Error rates are measured on synthetic data shaped like hospital data; real data will differ.
  Name detection relies on column-name hints (no name dictionary); only the last full backup set in a `.bak` is
  restored; pgAudit `log_rows` positions and Entra CSV column names follow public documentation, not vendor files.
