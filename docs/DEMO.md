# Demo: Synthetic South African Laboratory Breach Investigation

**Tripline Scope — Synthetic South African Laboratory Breach Investigation.** Everything in this demo is
synthetic: the laboratory, its systems, accounts, logs, patients and the leak sample are all generated. It is
**not a reconstruction of any real incident.** The scenario takes its general shape from a problem that
South African pathology laboratories have reported publicly: patient databases accessed, exported and published,
then a Regulator filing and patient notification needed fast. No real organisation's data, systems, names,
indicators or reports are used, and none of the numbers below describe a real event.

One command runs all three modules on one case. Each module produces a signed, versioned report, and those
reports refer to each other:

| Stage | Module | Question | Report |
|---|---|---|---|
| 1 | A: exposure scan (readiness) | Which conditions in the laboratory estate could expose patient data? | `exposure` |
| 2–3 | B: access paths (incident) | What do the logs support about who reached which tables, and what may have left? | `paths` |
| 4 | C: breach scoping (incident) | Which people are potentially affected, what was exposed, and who gets notified? | `scope` (preliminary, then refined) |
| 5 | AI Investigator and dashboard | (integration hook, see below) | (`investigation`) |

## 1. Prerequisites

* Linux with Python 3.12 and the project installed (`/opt/tscope-venv` in the development container; set
  `TSCOPE_PYTHON` to use a different interpreter).
* Docker with a SQL Server 2022 **Developer** container for the `.bak` restores. `run.sh` starts the container
  `mssql-test` on `127.0.0.1:14330`, or creates it from `mcr.microsoft.com/mssql/server:2022-latest`.
  The SA password is read from `TSCOPE_DEMO_MSSQL_PASSWORD` (default `Synth3tic!Demo`, a demo value).
  SQL Server Developer Edition is licensed for development, test and demonstration only. A real case restores
  to an instance the hospital provides and licenses.
* No network access is needed beyond the local Docker bridge. The earlier single-module demo was run
  air-gapped (`scripts/run_airgapped.sh`, ACCEPTANCE.md). This unified version has not been re-run air-gapped.
* The work directory took 53 MB at the default 100 000 admission rows, plus the SQL Server container's own
  storage.

## 2. Running it

```bash
demo/lab-breach/run.sh                              # scenario "suspected" (default), 100 000 rows
demo/lab-breach/run.sh --scenario corroborated      # adds an independently confirmed external copy
demo/lab-breach/run.sh --scenario suspected --keep-open --workdir /tmp/lab-demo   # leave the case open
ROWS=20000 demo/lab-breach/run.sh                   # smaller and faster
```

`run.sh` passes any extra arguments to `demo/lab-breach/run_demo.py`. Options:

| Option | Meaning |
|---|---|
| `--scenario suspected` | Outbound flows of unknown content follow the exports. Nothing is corroborated, so no table is `exfiltration_evidenced` and Module C reports confirmed exfiltration as `not determinable`. |
| `--scenario corroborated` | As above, plus an independently confirmed external copy (a leak sample received through counsel) of `LabDB03.dbo.patients`. That table becomes `exfiltration_evidenced`, and Module C counts the people matched to the sample. |
| `--keep-open` | Skip closure, so the case, its reports and the installation can be explored afterwards (`TSCOPE_HOME=<workdir>/home`). The case then gets a run-unique id (`DEMO-LAB-2026-<timestamp>`), because its restored databases stay on the SQL Server container until it is closed with `tscope case close --case <workdir>/case --approver ines`, which the run prints. |
| `--workdir DIR` | Where everything is written (default `demo/lab-breach/out`; replaced on each run unless `--keep`). |
| `--rows N` | Synthetic admission rows (default 100 000). |

The run prints one line per step with its duration, then a JSON summary, then `DEMO PASSED` or
`DEMO FAILED: <checks>`. The full summary is in `<workdir>/demo_summary.json`.

A Docker-free version of the same flow runs in the test suite (`tests/demo/`). It uses smaller data and writes
Module C extracts directly instead of restoring `.bak` files. The full demo is also available as
`pytest -m "docker and slow" tests/demo`.

## 3. The synthetic incident

The synthetic laboratory group runs SQL Server instances **LABSQL01** (LabDB01–05) and **LABSQL02**
(LabDB06–10). Each database holds `patients`, `admissions`, `billing` and `results`. There is also a PostgreSQL
LIS database (**LISPG01**, `lis`), a results portal **WEB01** behind gateway **GW01**, a domain controller
**DC01**, a VPN, a firewall and a proxy. Module A and Module B use the same asset ids for these systems
(`AST-LABSQL01`, `AST-LABSQL02`, `AST-WEB01`, `AST-GW01`, `AST-DC01`, `AST-LISPG01`), and the same accounts in
the `LAB\` / `lab.example` domain.

**Stage 1: readiness weaknesses (Module A).** `python -m tripline_scope.exposure.synthetic --estate lab`
writes a snapshot of the estate: the WEB01 web root, the reverse-proxy configuration, the laboratory file share,
the LIS repository, the SQL Server catalogue export of LABSQL01 (`LabDB03`), the PostgreSQL catalogue of
LISPG01, the Entra/AD exports and the supplier register. The real scanner (`tscope exposure scan`) then finds,
among other things:

* `xp_cmdshell` enabled on LABSQL01 (`A4.mssql-xp-cmdshell`, critical, `AST-LABSQL01`);
* an over-privileged service account, `LAB\svc_backup` with `CONTROL SERVER`, and an application login in
  `sysadmin` (`A2.app-admin-rights`, critical, `AST-LABSQL01`);
* SQL Server auditing switched off, which means incomplete audit coverage (`A4.mssql-audit-disabled`);
* stale patient exports left on the file share (`A3.data-copy`, `Lab/Exports/patients_2025-01.csv`, stale,
  `AST-FS01`);
* a database password in the web configuration snapshot (`A1.db-connection-password`, `wwwroot/web.config`,
  `AST-WEB01`). The value is synthetic and never appears in any report;
* supplier access needing review: `vendor.support` has more access than its contract allows and no MFA
  (`A5.supplier-excess-privilege`, `A5.supplier-mfa-missing`).

None of these findings is fabricated. The estate's `ground_truth.json` lists what the scanner is expected to find.
The tests compare the scanner's output with it; the demo only reads the released report.

**Stages 2–3: the intrusion as the logs show it (Module B).** `python -m tripline_scope.paths.synthetic`
writes 15 log sources: SQL Server audit as CSV and JSON, pgaudit, IIS, Nginx, Windows Security as XML and CSV,
Entra sign-ins as JSON and CSV, VPN, firewall, proxy, a middleware log with an unknown time zone, and partner
indicators. That is 25 747 events in the demo run. The traces show:

* admin and upload requests to the portal from an external address;
* a VPN sign-in from abroad as `t.naidoo`;
* `SELECT *` on LabDB03 and LabDB07 `patients`/`admissions`;
* a self-grant of `sysadmin`;
* `bcp` exports through `xp_cmdshell`;
* auditing switched off on LabDB09;
* a cleared security log;
* two multi-gigabyte outbound flows of unknown content to an address a partner reported.

Around them are an ordinary DBA query (LabDB01 `results`), a local billing export with no egress (LabDB05),
staff behind a shared NAT address, a nightly bulk import and an unexplained supplier session as
`LAB\vendor.support`.

Module B classifies each sensitive table. It never treats access as theft. Exfiltration is
`exfiltration_evidenced` only on independently verifiable evidence:

| Table | suspected | corroborated |
|---|---|---|
| LabDB01.dbo.results | `access_observed` | `access_observed` |
| LabDB05.dbo.billing | `export_or_staging_observed` | `export_or_staging_observed` |
| LabDB03.dbo.patients | `egress_suspected` | **`exfiltration_evidenced`** |
| LabDB03.dbo.admissions, LabDB07.dbo.patients/admissions | `egress_suspected` | `egress_suspected` |
| LabDB09.dbo.* (auditing off) | `undetermined` (`not_assessable`) | `undetermined` |

The paths report is built with `--exposure-report` pointing at the released exposure report. Its containment
recommendations are advisory, need hospital authorisation and are never executed. They name Module A
findings that concern the same account or asset. `paths scope-candidates` hands the per-table access windows to
Module C.

**Stage 4: people and notification (Module C).** `tscope synth` generates the ten laboratory databases
(about 100 000 admissions at the default size), including families, twins, typos, maiden names, foreign
nationals and placeholder rows, and a 300-person leak sample drawn from **LabDB03** patients. The demo builds
real SQL Server backups from them. It then registers them under chain of custody, restores them into SQL Server,
discovers and extracts the personal-information columns, applies Module B's candidates
(`scope constrain`), files a preliminary estimate (release v1), links rows to people, replays a simulated review,
writes the refined report with a notification pack, releases it (v2) and exports the notices.

* In **suspected** mode no leak sample is registered. The scope report then states confirmed exfiltration as
  `not determinable` with basis `unknown`, never a number. Observed access comes from Module B's confirmed
  windows. Possible exposure, and the notification proposal, cover everyone in the implicated sources.
* In **corroborated** mode the leak sample is registered with `evidence_role: leak_sample`. The people matched to
  it form the `confirmed_exfiltration` tier, for the categories in the sample only. This is the same data as
  Module B's `exfiltration_evidenced` table (`LabDB03.dbo.patients`).

**Verification and closure.** `tscope verify`, `tscope audit verify` and the independent verifier
`python -m tscope_verify chain` check the exposure, paths and scope chains. The case is then closed (unless
`--keep-open`) and the destruction certificate is verified. Finally the demo scans the case, the installation,
the console capture, the audit export and the summary. It looks for 85 000+ synthetic identifiers, the estate's
seeded secrets and SA ID numbers, and the secret planted in a log command line. As a positive control, the
approver's authorised notification export must contain identifiers. The demo also checks that no input file
changed.

## 4. Observed outcomes (synthetic)

These were recorded on the development container (4 vCPU, 15.7 GB, shared) at 100 000 admission rows. They are
counts from synthetic data and describe nothing real.

| | suspected | corroborated |
|---|---|---|
| Synthetic data (Module C) | 100 000 admissions, 24 784 patient rows, 14 034 people in 10 databases; leak sample 300 rows from db03 (LabDB03) | same |
| Module A findings (released exposure report v1) | 63: 6 critical, 30 high, 18 medium, 9 low (A1 20, A2 9, A3 9, A4 18, A5 7) | same 63 |
| The six narrated weaknesses found by the scanner on their assets | 6 of 6 | 6 of 6 |
| Module B events / sources | 25 747 events from 15 log sources | same |
| Module B sensitive tables by class (42 tables) | access_observed 17, egress_suspected 4, export_or_staging_observed 1, undetermined 4, no_access_observed 16 | access_observed 17, egress_suspected 3, **exfiltration_evidenced 1** (`LabDB03.dbo.patients`), export_or_staging_observed 1, undetermined 4, no_access_observed 16 |
| Containment recommendations / cross-referenced to Module A | 21 / 1 (`LAB\vendor.support` → the two A5 findings) | 21 / 1 (same) |
| Module C preliminary estimate (scope v1) | 14 363 people (range 13 644 – 16 200) | same |
| Module C refined (scope v2): observed access | 12 814 | 12 814 |
| possible exposure = notification proposal | 13 983 | 13 983 |
| confirmed exfiltration | `not determinable` (basis `unknown`) | **298** (basis `observation`, independently confirmed external copy) |
| Case sources, all attested synthetic | 36 of 36 | 38 of 38 |
| Leak scan | 86 files, 85 955 needles, 0 hits; positive control 1 file | 88 files, 85 955 needles, 0 hits; positive control 1 file |
| Inputs unchanged, report chains verified, case closed, certificate verified | yes | yes |
| Step time (sum) / wall clock of `run.sh` (container already running) | 154.3 s / 154 s | 151.7 s / 154 s |

The timings are from the final run of each scenario. Earlier runs of the same flow took 163–179 s of step time
on the same shared machine. The slowest steps were the SQL Server restore, discovery and extraction (`ingest`,
57–68 s), the `.bak` build (14–18 s) and the two matching passes (11–13 s each). Modules A and B together took about 20 s. The person
counts are equal in the two scenarios: the corroboration changes what is *confirmed*, not who is possibly
exposed.

## 5. How A, B and C connect

* **Shared asset ids.** Module A's asset map (`estate/assets.yaml`) and Module B's `logs.yaml` use the same ids
  and names (`AST-LABSQL01` = LABSQL01 = 10.20.0.15 = LabDB01–05, and so on). Every Module A finding carries
  `asset.asset_id`. Every Module B source and route carries the host's `asset_id`.
* **Shared accounts.** Module A principals (`LAB\svc_backup`, `vendor.support`, …) are compared with Module B
  accounts after normalisation (NetBIOS prefix and the laboratory's own UPN suffix removed). In both scenarios the
  supplier account `LAB\vendor.support`, seen in an SQL session with no upstream evidence, is linked to Module A's
  `A5.supplier-excess-privilege` and `A5.supplier-mfa-missing` findings.
* **Finding ids.** Module B's containment recommendations list `module_a_refs`: finding id, control, severity and
  state from the released exposure report, whose hash and version are recorded. A reference is advisory. It does
  not show that the weakness was used in the incident.
* **Known gap.** Asset-keyed references are not made yet: the recommendation to disable `xp_cmdshell` on
  `AST-LABSQL01` is not linked to Module A's `A4.mssql-xp-cmdshell` finding on the same asset. The cause is in
  `paths/containment.py`, which reads a top-level `asset_id`, while released exposure findings store it as
  `asset.asset_id`. This is a Module B fix. `tests/demo` holds a strict `xfail` test that will pass once it is
  fixed.
* **Scope candidates.** `tscope paths scope-candidates` → `tscope scope constrain`. Module C splits its results
  into the lower scenario (confirmed access windows) and the upper scenario (every implicated table). The
  notification proposal is always the upper scenario.
* **Leak sample ↔ corroboration.** Module C's leak sample is drawn from LabDB03 patients
  (`synth/generate.py`, `LEAK_DB = 3`). In corroborated mode Module B's corroboration (`COR-001`,
  `independently_confirmed_external_copy`) names `LabDB03.dbo.patients`, generated with
  `python -m tripline_scope.paths.synthetic --scenario acceptance --corroborate LabDB03.dbo.patients`. So Module B's
  `exfiltration_evidenced` table and Module C's `confirmed_exfiltration` tier refer to the same data.
* **Synthetic origin.** `tscope init` runs before any data is generated. Every generator runs with `--attest`
  (`synth`, `exposure-estate`, `paths-logs`, `lab-bak`) and records the SHA-256 of each file it wrote in
  `<home>/synthetic_registry.json`, which is authenticated with an HMAC under the hospital KEK. The `.bak`
  builder first checks that every input Parquet file is registered output of `tscope synth`. At the end the
  demo checks that every file of every case source is registered (`case_is_synthetic`). The laboratory estate
  leaves out the hospital estate's symlink traversal fixtures, which are walker guardrail tests and not
  weaknesses, so every case source file is a regular file whose content hash is attested.

## 6. What is synthetic, and what has not been validated

Synthetic: every database row, name, ID number, phone number and address; the estate snapshot, its secrets and
its catalogue and identity exports; every log line, account, address and indicator; the leak sample; the
review decisions (a simulated reviewer that reads the generator's ground truth); the asset map. The SQL Server
backups are real backups of synthetic data.

Not validated on real hospital or laboratory systems:

* the parsers on log exports from production SQL Server, IIS, Nginx, Windows, Entra, VPN, firewall and proxy
  systems, beyond the documented formats and the generated variants;
* catalogue and identity exports collected from a production SQL Server, PostgreSQL or directory;
* restore, discovery and extraction on production-sized hospital schemas;
* matching quality on real South African patient registers. The measured error rates come from synthetic
  data with known ground truth;
* any timing at real-estate scale other than the separate estimate benchmark below.

The demo's numbers show that the pipeline is consistent end to end on generated data. They are not accuracy
claims about real incidents.

## 7. AI Investigator and dashboard

The integrator completes this section: AI Investigator and dashboard steps are added in `investigate_and_present` in `demo/lab-breach/run_demo.py`.

## 8. Separate benchmark: preliminary estimate at 80 million admissions

This benchmark is not part of the quick demo and never runs in CI. It was run once with
`python bench/estimate_bench.py --rows 80000000`; the result is recorded in
`bench/results/estimate_80000000.json` (2026-10-16):

| Measure | Result |
|---|---|
| Synthetic estate | 80M admissions, 40.0M billing, 97.6M results, 19.9M patient rows in 10 databases; 11 331 565 true people |
| Estimate path (sliced load + estimate) | **265.9 s** (load 257.5 s, counting 8.4 s), 12 slices of at most 3M identity rows |
| Peak RSS | **4.9 GB** (4 888 MB) on the estimate path, nothing spilled to disk |
| Point estimate | 11 541 765, **+1.85 %** from the true count; range 10 964 676 – 13 039 938 contains the truth |
| Hardware | 4 vCPU (Intel Xeon @ 2.10 GHz), 15.7 GB RAM, development machine shared with other workloads |

**Full person-level matching at 80M was not performed. It is DEFERRED.** It still loads the estate as a whole
and needs the 64 GB reference machine or an encrypted spill volume (ACCEPTANCE.md §4.2).
