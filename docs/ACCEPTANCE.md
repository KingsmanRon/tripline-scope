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
| Everything (incl. Docker/SQL Server and PostgreSQL integration) | `pytest -q tests` | **384 passed, 3 skipped** (the 3 are opt-in `-m slow` ingest benchmarks), 9 min 05 s |
| Same, networking disabled (empty namespace, loopback only) | `make test-offline` | **374 passed**, 13 deselected (Docker-dependent and slow) |
| Lint | `ruff check src tests verify bench demo scripts` | pass |
| Locks pinned with hashes | `make check-locks` | pass (runtime 41, dev 79) |
| Licence gate | `make licences` | **PASS**: 41 runtime distributions, 40 allowed, 1 by documented exception (Pillow, MIT-CMU), 0 unknown/denied |
| SBOM | `make sbom` | PASS: CycloneDX 1.6, 42 components, every locked dependency with version, purl, SHA-256, licence |
| Offline bundle | `make bundle && make bundle-verify` | built (495 MB) and signed checksums verified with `tscope-verify` (ephemeral release key — see §5) |
| Offline install | `make install-test` | **PASS** venv mode in a clean `python:3.12-slim` container with `--network none`; **PASS** container mode on an `internal: true` compose network (1.1.1.1 and 8.8.8.8 unreachable) |
| One-command demo, 100k rows | `demo/lab-breach/run.sh` | **PASS** in 130 s (`bench/results/demo_100k.json`) |
| Same demo, air-gapped | `scripts/run_airgapped.sh … run_demo.py` | **PASS** in 135 s; the namespace's only route is the Docker bridge; pypi.org unreachable (`bench/results/demo_100k_airgapped.json`) |

## 3. Definition of done

| Criterion | Target | Measured | Status |
|---|---|---|---|
| Auto-link precision, 10M rows | ≥ 99.5 % | **99.874 %** (pairwise precision 99.905 %, recall 99.619 %) | Pass |
| Unique-person count error, 10M | ≤ 1 % | **0.24 %** (1 411 801 predicted vs 1 408 377 true) | Pass |
| Review band, 10M | ≤ 0.5 % of people | **0.89 %** (12 533 people, 9 549 pairs; 0.15 % at 100k, 0.34 % at 1M) | **Fail** — see §4.1 |
| Preliminary estimate vs final count | within 5 % | **2.4 %** at 10M (2.6 % at 100k and 1M); true count inside the stated bounds on every seed checked | Pass |
| Estimate time, 80M rows | < 1 h | see §4.2 | see §4.2 |
| Full run, 10M rows | < 2 h on 16 cores/64 GB | **≈ 2 min** for extract → load → estimate → match → people on 4 vCPU/15.7 GB, peak RSS 6.1 GB (`bench/results/10000000.json`); SQL Server restore + discovery at 10M **not run** — at the measured 14–32k rows/s it projects to roughly 20–40 min for the ~30M rows of a 10M-admission estate | Pass for matching; ingest projected, not measured |
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
| Documentation | README, METHOD, SECURITY, EXPOSURE, ACCESS_PATHS, INTEGRATION, ACCEPTANCE | all present (plus INGEST, SUPPLY_CHAIN, PLAN) | Pass |

## 4. Details for the misses and the scale runs

### 4.1 Review band at 10M (0.89 % vs 0.5 %)

Borderline pairs grow faster than the data (17 → 360 → 9 549 pairs per tenfold increase) because large estates hold
more *different* people who share a common surname sound and date of birth. About 70 % of the 10M review pairs are
true matches. Auto-linking them would lower precision, which the spec forbids trading away, so the thresholds were
not loosened. The cost is reviewer effort (≈ 9.5k decisions at 10M), not accuracy. Likely remedies for v1: extra
discriminating comparisons (middle names, address tokens), term-frequency-adjusted DOB, and batch review of
household groups.

### 4.2 Preliminary estimate at 80M rows

_Pending: filled in from `bench/results/estimate_80000000.json` when the run completes._

### 4.3 Module measurements (synthetic, 4 vCPU shared)

| Module | Workload | Result |
|---|---|---|
| Ingest — CSV | 200k rows, 4 tables | discovery 7.8 s (~26k rows/s), extract 1.9–2.2 s (72–85k rows/s) |
| Ingest — SQL Server `.bak` | 17 MB backup, 200k rows | restore 1.6–3.1 s, discovery 10–14 s (14–19k rows/s), extract 5–8 s (20–32k rows/s) |
| Ingest — PostgreSQL custom dump | 200k rows | restore 0.5 s, discovery 7.8 s, extract 2.5 s |
| Module A exposure scan | 20k / 50k mixed files | 4.4 s (~4 500 files/s, 115 MB RSS) / 17.3 s (126 MB); 0 parser failures |
| Module B access paths | 99k / 988k events | ingest 8.2 s / 73 s (~13.5k events/s), analyse 10 s / 364 s (peak 4.1 GB), 0 parser failures |
| Module C | 100k / 1M / 10M admission rows | match 8.5 s / 16 s / 41 s; precision 99.985 / 99.961 / 99.874 % |
| Cross-check | 20k rows, real `.bak` → ingest → C vs direct extract | identical people, segments, precision and recall after the discovery and row-key fixes this check found |

## 5. Not done, limitations and owner decisions

* **Not demonstrated:** install on a clean physical machine, VM or Hyper-V; CI on GitHub (workflow written, not run);
  80M full run; SQL Server restore + discovery at 10M; `scope review` against a live server process (tested through
  the ASGI test client); reviewer TOTP; provider co-signing in the demo; SQL Server TLS (needs pyOpenSSL, not bundled).
* **Release key:** the bundle here is signed with an ephemeral key generated outside the repository. A real release
  key must be generated off-repo and published out of band.
* **Licence decisions for the owner:** permissive licences outside the short list in linked native code (Unicode-3.0
  in pydantic-core's ICU4X crates, CC0-1.0 in evtx's encoding tables, FTL/IJG/libpng/libtiff/X11/BSL-1.0/Zlib notices in
  Pillow/pyarrow/splink assets); reportlab's wheel ships an unused GPL sample font and unlicensed Adobe/Monotype fonts
  (the installers delete them; the wheel itself is unmodified); DuckDB's vendored code notices and OpenSSL's notice in
  cryptography need confirming. The product's own licence in `pyproject.toml` is a placeholder.
* **Synthetic data only.** Error rates are measured on synthetic data shaped like hospital data; real data will differ.
  Name detection relies on column-name hints (no name dictionary); only the last full backup set in a `.bak` is
  restored; pgAudit `log_rows` positions and Entra CSV column names follow public documentation, not vendor files.
