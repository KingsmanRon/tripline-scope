# Enterprise profile — acceptance

**Scope.** Synthetic data only, on a shared 4 vCPU / 15 GB machine, branch
`feature/enterprise-financial-investigation`. The results below were recorded at commit `9aa07b7`, which includes the
fixes for the PR review findings (§3a). Later commits on the branch change this document only.

**Not tested.** No customer data, production export or real organisation's environment was used. This is a
synthetic enterprise investigation capability. It is not qualified for production use or for deployment to any real
organisation's environment.

**Status codes.**
- **PASS**: demonstrated by the evidence named.
- **NOT RUN**: not executed.
- **NOT IN SCOPE**: excluded by the brief.

## 1. Acceptance gates

| Gate | Requirement | Evidence | Status |
|---|---|---|---|
| A | Original healthcare workflows remain compatible | The complete suite passes with Docker up (SQL Server, PostgreSQL, both healthcare lab-breach demos): 630 passed, 0 failed (§3). Healthcare `case.yaml`, exposure reports (A1–A5 only), the paths timeline, Module C and the workbench HTML are unchanged. The only healthcare-visible differences are additive and listed in §4. | PASS |
| B | Synthetic enterprise demonstration runs end to end | `demo/enterprise-financial-incident/run.sh --scenario all`: DEMO PASSED, 136.2 s, three scenarios, all checks true (§2) | PASS |
| C | Unsupported fraud and financial-loss claims rejected | `tests/enterprise/test_enterprise_investigator.py`: fraud/blame (6 phrasings), money movement without independent settlement, loss for an attempted payment, unscoped claims, steps/remediation text, and absence claims during gaps are rejected; hedged text is accepted | PASS |
| D | Every released conclusion supported by traceable evidence | Every session, transaction, privilege event and gap carries Module B event ids or source ids. A `direct` link is made only after the joined records validate; otherwise the link is `unresolved` and the conflicting records are listed (§3a). The financial analysis runs only over the event set the released paths report was signed over, and the binding is recorded in the report. Counts are computed from input records only. Investigator items: 25 / 20 / 24 accepted with 0 rejected in A/B/C, all reviewed before release. | PASS |
| E | Dashboard verifies report integrity before displaying trusted results | `/api/financial` reads through the release-1 integrity gate. A tampered `financial` report is refused with "INTEGRITY FAILURE" (`test_signed_report_verifies_and_tampering_is_detected`). In the demo, all chains verify and there are no alerts. | PASS |
| F | Offline and source-safety tests pass | `make test-offline` (empty network namespace): 618 passed (§3). `test_financial_analysis_runs_offline` records 0 connection attempts. The demo checks that inputs are unchanged and runs without a network or database container. The offline install proof passes in both modes (§3). | PASS |
| G | Independently verifiable signed report mechanism continues to work | `tscope_verify chain` passes for `exposure`, `paths`, `financial` and `investigation` in every scenario, and fails after tampering. `investigator verify` re-renders byte-identically. `make bundle-verify` verifies the signed bundle checksums with the stand-alone verifier. | PASS |
| H | Known limitations documented | [ENTERPRISE_LIMITATIONS.md](ENTERPRISE_LIMITATIONS.md) | PASS |
| I | No production systems, third-party networks or real organisations' assets accessed | Only generated fictional data: `.example` domains, RFC 5737 and private addresses. There is no network code path, the offline suite passes, and nothing names a real organisation. | PASS |

## 2. Scenario results (demo run at `9aa07b7`)

| Scenario | Financial impact | Sessions (suspicious) | Transactions (suspicious) | Evidence for the suspicious transactions | Suspicious totals (per currency) | Investigator items accepted / rejected |
|---|---|---|---|---|---|---|
| A — suspicious access, impact not determinable | `not_determinable` | 86 (1) | 42 (0) | No transaction linked. The declared audit outage overlaps the suspicious session, and no settlement evidence was supplied. | none | 25 / 0 |
| B — attempted transaction rejected/stopped | `attempted_and_stopped` | 87 (1) | 43 (1) | `rejected_or_stopped`; release attempt denied (blocked: 1) | rejected_or_stopped: ZAR 4,850,000.00 | 20 / 0 |
| C — corroborated settlement | `settlement_corroborated` | 86 (1) | 44 (2) | ZAR payment `settled_corroborated` (independent bank record: same reference, amount, currency). USD payment `posted`, with the application's settlement claim not corroborated. | settled_corroborated: ZAR 1,275,400.00; posted: USD 18,500.00 (never added) | 24 / 0 |

**Other counts** (released `financial` report):

| Count | A | B | C |
|---|---|---|---|
| Linked to sessions with privilege evidence | 0 | 1 | 2 |
| Verified ledger postings | 42 | 42 | 44 |
| Settled (independent record) | 0 | 42 | 43 |
| Settled with no recorded ledger posting | 0 | 0 | 0 |

**Common to every scenario:**
- The suspicious supplier session is linked as follows:
  - identity `direct` (validated: same account, successful, plausible time);
  - remote access `direct` (validated);
  - host logon `correlated`;
  - privilege `correlated` (privilege events are observed by their source; the link to the session is by account and
    time).
- Its suspicion reasons are `supplier_outside_window`, `privilege_granted_before_session`, `signin_without_mfa` and
  `external_signin`.
- The released exposure report raises E1, E2 (×3), E3 (×2), E4 and E5. It does not flag the approved privileged
  mapping or the inventoried copy, and E4 is "partially assessed" where coverage is unknown.
- The leak scan covered 41–42 output files per scenario against 113–197 seeded secrets and raw references, with
  0 hits and a positive control on the inputs (6–7 input files hit).
- Inputs were unchanged after the run.
- The workbench matches the reports.

**Per-stage time** (mean of the three scenario runs, small synthetic estate):

| Stage | Time |
|---|---|
| exposure scan | 1.4 s |
| paths ingest | 2.0 s |
| paths analyse | 1.8 s |
| financial analyse | 1.3 s |
| financial report | 1.2 s |
| investigator analyse | 1.5 s |

These figures are not a throughput claim.

## 3. Tests executed (at commit `9aa07b7`)

| Run | Command | Result |
|---|---|---|
| Complete suite, Docker up (SQL Server 2022 and PostgreSQL 16 containers, both healthcare lab-breach demos) | `pytest -q -rs tests` | **630 passed, 0 failed, 3 skipped**, 24 min 19 s. The 3 skips are the opt-in benchmarks in `tests/ingest/test_benchmark.py`, marked `slow` and run only with `-m slow`. They are performance measurements, not correctness checks. All 10 non-slow Docker tests ran and passed (lab-breach demos ×2, SQL Server ingest ×3, live ingest, database exposure, ingest/scope consistency, offline install ×2), as did all 10 PostgreSQL tests. |
| Re-run of the test files that read `docs/` on the clean committed tree (documentation was edited while the complete suite ran; code was not) | `pytest -q tests/demo`, `tests/packaging`, `tests/paths/test_offline.py`, `tests/exposure/test_e2e.py tests/exposure/test_secrets.py` | 20, 67, 1 and 57 passed |
| Same, networking disabled | `make test-offline` | **618 passed**, 15 deselected (`docker` or `slow` markers: 11 Docker tests and 4 other slow tests), 14 min 22 s |
| Enterprise tests | `pytest tests/enterprise` | **88 passed**: transactions 20, adapter 20, pipeline 14, investigator 16, workbench 5, review regressions 13 |
| Offline bundle | `make bundle` | built in 2 min 12 s, 496 MB, `git_commit` 9aa07b7, `git_dirty: false`. It was signed with an **ephemeral** release key because `RELEASE_KEY` was not set, as in CI for non-tag builds; a tagged release needs the organisation's release key. |
| Bundle signature | `make bundle-verify` | PASS: release signature valid, all 78 listed files match |
| Offline install proof | `make install-test` | **venv mode** offline install PASS (smoke test passed). **Container mode** on an internal network PASS: the app reached PostgreSQL 16, and 1.1.1.1:443 and 8.8.8.8:53 were unreachable from the app container. |
| Lint | `ruff check src tests demo verify scripts` | clean |
| GitHub CI on the PR | `test`, `lint-locks`, `licences-sbom` | success (`bundle` runs only on main and tags) |

### 3a. Review findings and their regression tests

| Finding | Fix | Regression tests |
|---|---|---|
| P0: direct identity links were not validated | Every record carrying the shared identifier is checked: same account, not failed, plausible time, and agreement on MFA/address (VPN: addresses). Another account on the identifier, or ambiguity, makes the link `unresolved` with the conflicts listed, and nothing is attributed from those records. | `test_review_regressions.py`: same correlation id with a different account; failed sign-in; failed-then-successful retry; implausible and unresolvable times; multiple matching records (consistent vs inconsistent); VPN outcome handling; an end-to-end case with a reused correlation id |
| P0: the financial analysis was not bound to the released paths event set | Ingest records each source's `events_file_sha256`, and the paths report signs it. `financial analyse` compares sources, files, custody, coverage and event-file hashes with the latest released paths report and fails closed. The binding is recorded in `inputs.paths_binding`. | Re-ingest after the paths release is refused, then accepted after paths is re-run and re-released; a new source is handled the same way; each bound field is checked; the binding equals the signed paths report |
| P1: "posted" overstated ledger postings | `ledger_posting_verified` per transaction. The counts are `ledger_posting_verified`, `settled_corroborated` and `settled_corroborated_without_ledger_posting`; there is no combined "posted" count. | `test_release_and_bank_settlement_without_ledger_posting_is_not_a_posting` |
| P1: a privileged actor was treated as a privileged session | Transactions are linked only through their own sessions' privilege evidence (`sessions_with_privilege_evidence`, label `correlated`). The count is renamed `linked_to_sessions_with_privilege_evidence`. | `test_privileged_actor_in_another_session_does_not_link_this_transaction` |

**Test coverage against the brief:**

| # | Requirement | Covered by |
|---|---|---|
| 1 | Enterprise exposure controls | `test_enterprise_exposure_controls`, `test_enterprise_controls_are_not_assessed_without_their_inputs` |
| 2–3 | Parser validation; invalid and malformed input | `test_finapp_adapter.py` (10 malformed cases, unreadable lines, mapping validation) |
| 4 | Duplicates | adapter flag; exact vs conflicting (`test_transactions.py`); demo exact-duplicate count |
| 5 | Timestamp inconsistencies | out-of-sequence and unresolved-time tests; implausible identity-join times |
| 6 | Missing and contradictory evidence | missing creation record, action after rejection, amount/currency conflicts, settlement without release, scenario A gaps, contradictory identity joins |
| 7 | Cross-system correlation | `test_cross_system_correlation_labels`, identity-join regression tests |
| 8–9 | Fraud claims; settlement claims | investigator rule tests; release-and-settlement without posting |
| 10 | Currency and amounts | minor units, exponents, per-currency totals, never mixed |
| 11 | Roles | reviewer cannot analyse, operator cannot approve, non-enterprise case refused, views need a role and are audited |
| 12–13 | Signatures; tampering | `tscope_verify chain`, tamper test, workbench refusal, paths-binding refusal |
| 14 | No leakage | released outputs scanned for seeded secrets and raw references; workbench response scan |
| 15 | Offline | socket-denied analysis; offline suite; offline install proof |
| 16 | Three scenarios | parametrised against ground truth |
| 17 | Healthcare regression | the complete suite, including both lab-breach demos |

## 4. Healthcare-visible differences (all additive)

- Workbench `/api/overview` adds `"profile": "healthcare"`.
- The `case init` audit entry records the profile parameter.
- Investigator bundle items carry two new null fields, `categories` and `financial_category`. The validator is now
  `investigator-validator/1.2.0`, whose financial rules only reject claims of fraud, blame, money movement or loss
  that are not independently settled.
- Module B accepts two more families and has six additive event columns, all null for healthcare sources.
- Module B coverage records, and each source in the paths report's `inputs.sources`, carry `events_file_sha256`: the
  hash of the stored encrypted event file. A case ingested before this release must be re-ingested before an
  enterprise analysis; healthcare analyses are unaffected.

## 5. Not run

| Item | Status |
|---|---|
| Customer production exports, any real ERP / identity / bank format | NOT RUN (synthetic only) |
| Enterprise-scale volumes | NOT RUN |
| Real local AI model on enterprise bundles | NOT RUN (fixture only) |
| Bundle signed with the organisation's release key (tagged release) | NOT RUN (ephemeral key; see §3) |
| Clean VM / Hyper-V install | NOT RUN (the install proof uses a clean `--network none` container and a venv on this machine) |
| Energy profile and OT evidence | NOT IN SCOPE (documented future capability) |
| Full 80M person-level matching | NOT IN SCOPE (unchanged; DEFERRED since release 1) |
