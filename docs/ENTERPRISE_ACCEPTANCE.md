# Enterprise profile — acceptance

**Scope.** Synthetic data only, on a shared 4 vCPU / 15 GB machine, branch
`feature/enterprise-financial-investigation`.

**Not tested.** No customer data, production export or real organisation's environment was used.

**Status codes.**
- **PASS**: demonstrated by the evidence named.
- **NOT RUN**: not executed.
- **NOT IN SCOPE**: excluded by the brief.

## 1. Acceptance gates

| Gate | Requirement | Evidence | Status |
|---|---|---|---|
| A | Original healthcare workflows remain compatible | Every pre-existing test passes unchanged, including both full lab-breach demos with SQL Server (§3). Healthcare `case.yaml`, exposure reports (A1–A5 only), the paths timeline, Module C and the workbench HTML are unchanged. The only healthcare-visible differences are listed in §4. | PASS |
| B | Synthetic enterprise demonstration runs end to end | `demo/enterprise-financial-incident/run.sh --scenario all`: DEMO PASSED, 145.0 s, three scenarios, all checks true (§2) | PASS |
| C | Unsupported fraud and financial-loss claims rejected | `tests/enterprise/test_enterprise_investigator.py`: fraud/blame (6 phrasings), money movement without independent settlement, loss for an attempted payment, unscoped claims, steps/remediation text, and absence claims during gaps are rejected; hedged text is accepted | PASS |
| D | Every released conclusion supported by traceable evidence | Every session, transaction, privilege event and gap carries Module B event ids or source ids. Counts are computed from input records only. Validator item references must exist in the bundle. Investigator items: 25 / 20 / 24 accepted with 0 rejected in A/B/C, all reviewed before release. | PASS |
| E | Dashboard verifies report integrity before displaying trusted results | `/api/financial` reads through the release-1 integrity gate. A tampered `financial` report is refused with "INTEGRITY FAILURE" (`test_signed_report_verifies_and_tampering_is_detected`). In the demo, all chains verify and there are no alerts. | PASS |
| F | Offline and source-safety tests pass | `make test-offline` (empty network namespace): see §3. `test_financial_analysis_runs_offline` records 0 connection attempts. The demo checks that inputs are unchanged and runs without a network or database container. | PASS |
| G | Independently verifiable signed report mechanism continues to work | `tscope_verify chain` passes for `exposure`, `paths`, `financial` and `investigation` in every scenario, and fails after tampering. `investigator verify` re-renders byte-identically. | PASS |
| H | Known limitations documented | [ENTERPRISE_LIMITATIONS.md](ENTERPRISE_LIMITATIONS.md) | PASS |
| I | No production systems, third-party networks or real organisations' assets accessed | Only generated fictional data: `.example` domains, RFC 5737 and private addresses. There is no network code path, the offline suite passes, and nothing names a real organisation. | PASS |

## 2. Scenario results (demo run recorded with this release)

| Scenario | Financial impact | Sessions (suspicious) | Transactions (suspicious) | Evidence for the suspicious transactions | Suspicious totals (per currency) | Investigator items accepted / rejected |
|---|---|---|---|---|---|---|
| A — suspicious access, impact not determinable | `not_determinable` | 86 (1) | 42 (0) | No transaction linked. The declared audit outage overlaps the suspicious session, and no settlement evidence was supplied. | none | 25 / 0 |
| B — attempted transaction rejected/stopped | `attempted_and_stopped` | 87 (1) | 43 (1) | `rejected_or_stopped`; release attempt denied (blocked: 1) | rejected_or_stopped: ZAR 4,850,000.00 | 20 / 0 |
| C — corroborated settlement | `settlement_corroborated` | 86 (1) | 44 (2) | ZAR payment `settled_corroborated` (independent bank record: same reference, amount, currency). USD payment `posted`, with the application's settlement claim not corroborated. | settled_corroborated: ZAR 1,275,400.00; posted: USD 18,500.00 (never added) | 24 / 0 |

**Common to every scenario:**
- The suspicious supplier session is linked as follows: identity `direct`, remote access `direct`, host logon
  `correlated`, privilege `observed`.
- Its suspicion reasons are `supplier_outside_window`, `privilege_granted_before_session`, `signin_without_mfa` and
  `external_signin`.
- The released exposure report raises E1, E2 (×3), E3 (×2), E4 and E5. It does not flag the approved privileged
  mapping or the inventoried copy, and E4 is "partially assessed" where coverage is unknown.
- The leak scan covered 41–42 output files per scenario against 113–197 seeded secrets and raw references, with
  0 hits and a positive control on the inputs.
- Inputs were unchanged after the run.
- The workbench matches the reports.

**Per-stage time** (mean of three runs, small synthetic estate):

| Stage | Time |
|---|---|
| exposure scan | 1.5 s |
| paths ingest | 1.8 s |
| paths analyse | 1.9 s |
| financial analyse | 1.4 s |
| financial report | 1.5 s |
| investigator analyse | 1.6 s |

These figures are not a throughput claim.

## 3. Tests executed

| Run | Command | Result |
|---|---|---|
| Enterprise tests | `pytest tests/enterprise` | 73 passed: transactions 18, adapter 20, pipeline 14, investigator 16, workbench 5 |
| Complete suite, Docker up (SQL Server, PostgreSQL, both lab-breach demos) | `pytest -q -rs tests` | **614 passed, 1 failed, 3 skipped** (opt-in `-m slow` benchmarks), 23 min 34 s. The failure was a function-level `from conftest import clone` in a new enterprise test that resolved another directory's conftest under full collection. It was fixed by a module-level import, and the affected tests then passed under full-tree collection (35 passed, 583 deselected). |
| Same, networking disabled | `make test-offline` | **603 passed**, 15 deselected (Docker/slow), 14 min 39 s (530 pre-existing + 73 enterprise) |
| Healthcare investigator regression after the bundle, validator and fixture changes | `pytest tests/investigator` | 69 passed |
| Healthcare exposure regression after E1–E5 | `pytest tests/exposure` | 95 passed, 1 skipped (SQL Server container down at that time; passed in the complete run) |
| Lint | `ruff check src tests demo` | clean |
| Real browser | headless Chromium, enterprise case, all sections | no console errors, no external requests |

**Test coverage against the brief:**

| # | Requirement | Covered by |
|---|---|---|
| 1 | Enterprise exposure controls | `test_enterprise_exposure_controls`, `test_enterprise_controls_are_not_assessed_without_their_inputs` |
| 2–3 | Parser validation; invalid and malformed input | `test_finapp_adapter.py` (10 malformed cases, unreadable lines, mapping validation) |
| 4 | Duplicates | adapter flag; exact vs conflicting (`test_transactions.py`); demo exact-duplicate count |
| 5 | Timestamp inconsistencies | out-of-sequence and unresolved-time tests |
| 6 | Missing and contradictory evidence | missing creation record, action after rejection, amount/currency conflicts, settlement without release, scenario A gaps |
| 7 | Cross-system correlation | `test_cross_system_correlation_labels` |
| 8–9 | Fraud claims; settlement claims | investigator rule tests |
| 10 | Currency and amounts | minor units, exponents, per-currency totals, never mixed |
| 11 | Roles | reviewer cannot analyse, operator cannot approve, non-enterprise case refused, views need a role and are audited |
| 12–13 | Signatures; tampering | `tscope_verify chain`, tamper test, workbench refusal |
| 14 | No leakage | released outputs scanned for seeded secrets and raw references; workbench response scan |
| 15 | Offline | socket-denied analysis; offline suite |
| 16 | Three scenarios | parametrised against ground truth |
| 17 | Healthcare regression | the complete suite |

## 4. Healthcare-visible differences (all additive)

- Workbench `/api/overview` adds `"profile": "healthcare"`.
- The `case init` audit entry records the profile parameter.
- Investigator bundle items carry two new null fields, `categories` and `financial_category`. The validator is now
  `investigator-validator/1.2.0`, whose financial rules only reject claims of fraud, blame, money movement or loss
  that are not independently settled.
- Module B accepts two more families and has six additive event columns, all null for healthcare sources. A case
  ingested before this release must be re-ingested before an enterprise analysis; healthcare analyses are
  unaffected.

## 5. Not run

| Item | Status |
|---|---|
| Customer production exports, any real ERP / identity / bank format | NOT RUN (synthetic only) |
| Enterprise-scale volumes | NOT RUN |
| Real local AI model on enterprise bundles | NOT RUN (fixture only) |
| Offline bundle rebuild and install test for this branch | NOT RUN |
| Clean VM / Hyper-V install | NOT RUN |
| Energy profile and OT evidence | NOT IN SCOPE (documented future capability) |
| Full 80M person-level matching | NOT IN SCOPE (unchanged; DEFERRED since release 1) |
