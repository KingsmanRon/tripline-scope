# Integration: how the three modules work together

Tripline Scope has three engines that share one evidence model, one case, one custody record, one audit log and
one signed report chain per report kind:

| Module | Mode | Question it answers | Report kind |
|---|---|---|---|
| A — exposure scan | readiness | Which conditions could expose patient data before an incident? | `exposure` |
| B — access paths | incident | What do the available logs support about who accessed what, and what may have left? | `paths` |
| C — breach scoping | incident | Who are the potentially affected people, what may have been exposed, and how do we notify them? | `scope` |

Every engine can run on its own. None of them needs another to produce a defensible result; each records what it
could not assess.

## 1. Contracts

### 1.1 Exposure → containment (A → B)

Module B's containment advice is cross-referenced to a released Module A `exposure` report given with
`tscope paths report --exposure-report <exposure v000N/report.json or its version directory>`. Every
recommendation carries `requires_hospital_authorisation: true` and `executed: false`; nothing is ever executed.

* Join keys: `finding_id` (`AF-…`, keyed to the readiness case), `asset.asset_id` / `target_asset.asset_id` (from
  the hospital's approved asset map, `core.assets`), and `location.principal` (+ `principal_domain`) for account
  findings; each exposure report repeats the list under `stable_fields`. **Never a secret value**: a "rotate this
  credential" recommendation names the finding id and asset, not the credential.
* A match is advisory ("this account was reported as over-privileged in exposure report v3, finding EXP-…").
  It is not evidence that the finding was used in the incident.
* If no exposure report is supplied, recommendations are still produced from Module B's own evidence and the
  report states that no exposure cross-reference was available.

### 1.2 Paths → scope (B → C)

`tscope paths scope-candidates --case C --out candidates.json` writes `tripline.scope-candidates/v1`:

* per table (`database`, `table`): `window_class` (`confirmed` | `possible` | `not_assessable` |
  `none_observed` — logs covered the table and showed no access), `windows[]` (each with class, start, end, basis,
  consequence class, account references, sessions, evidence ids, `rows_logged`, `volume_unknown`, time
  uncertainty), `status`, `consequence_class`, `basis`, `covering_sources`, `confidence` with its reason,
  `limitations`;
* `coverage_gaps` (missing logs, auditing-off periods, unknown time zones);
* `scenarios.lower` (confirmed windows only) and `scenarios.upper` (every sensitive table over the whole window,
  including `not_assessable` and `none_observed`; with no Module B input it is simply all tables);
* `coverage_status` (`assessed` | `partial` | `not_assessable`), `exclusion_policy`, `operator_may_widen: true`.

Account references: hospital directory accounts are named only when their domain is listed in
`paths.directory_domains`; every other e-mail-shaped account is pseudonymised (`ACCT-…`). Staff and supplier
accounts are not patient data, but they are kept out of reports unless the hospital chooses otherwise.

`tscope scope constrain --case C --candidates candidates.json --reason "…"` records a scoping decision (who,
when, why, input hashes) in the audit log and in the next scope report (`--widen TABLE`, `--widen-all` and
`--ignore-time-windows` record a widening; `--clear` withdraws candidates). Matching always runs on every
extracted record; candidates only split the results into scenarios, so the full-scope count is always available.
Module C then reports:

* **candidate scope** (lower scenario): people with records in tables with confirmed access windows;
* **full scope** (upper scenario): everyone with records in the implicated sources, including every table whose
  logs are missing or inconclusive.

The **notification proposal is the upper scenario by default.** Missing, partial or inconclusive logs never
remove anyone from the proposal. The operator may widen scope at any time; narrowing below the upper scenario is
a recorded decision of the Information Officer (approver) with a reason, and both numbers stay in the report.

### 1.3 Evidence classes carried end to end

The same classification is used in the event store, the paths report, the scope report, the PDF, the notice
templates and the Regulator summary:

| Scope tier (people) | Evidence threshold | Typical source |
|---|---|---|
| `observed_access` | records in tables with `access_observed` (or stronger) events inside a confirmed window | Module B |
| `possible_exposure` | records in any implicated source, whatever the logs say | Module C over the restored systems |
| `confirmed_exfiltration` | records matched to an `exfiltration_evidenced` source — e.g. a leak sample received through the hospital's lawyers (independently confirmed external copy) — and only for the categories that copy contains | Module C + custody `evidence_role: leak_sample` |
| `notification_scope` | the Information Officer's decision, with counsel | release record |

When a tier cannot be supported it is written as `not determinable`, with the reason. Database access is never
reported as exfiltration; traffic volume is never reported as identified patient records.

### 1.4 Scope → notices (C → notify)

Only people inside the approver's notification scope reach `notify/`. The pack stays encrypted until a scope
report version is released, and only the approver can export it (fresh sign-in). The export records which
released report version it belongs to.

## 2. Legal hold and retention

* `tscope case hold on --reason …` (approver) blocks closure; `hold off` lifts it. Both are audited.
* `case.yaml retention.retain_reports_until` records how long signed reports, custody manifests, findings and the
  audit log are kept. Closure keeps exactly these; working data, restores, notification pack and the case key are
  destroyed and listed in the signed destruction certificate.
* Readiness cases are long-lived: they retain configuration, finding metadata, data maps, drill reports and signed
  reports. Working files (scan intermediates, drill data) are purged by closing the drill sub-case or by
  `tscope case close`; findings stay in the signed reports.

## 3. Worked degraded-evidence scenarios

**No logs at all (Module B absent).** Module C runs normally. The scope report sets `observed_access` to
`not determinable — no access logs were provided`, `possible_exposure` to everyone in the implicated sources,
`degraded_evidence` to a plain statement, and the notification proposal to the full population. Nothing is
narrowed.

**Logs cover only part of the incident window.** Module B marks the uncovered periods and tables as
`not_assessable`. Module C's lower scenario counts people in confirmed tables; the upper scenario (and the
proposal) still includes the not-assessable tables.

**Auditing switched off on one database.** Module B reports an auditing-off gap with its start/end where
observable. That database's tables are `not_assessable` and stay in the upper scenario; the containment list
includes "restore auditing" cross-referenced to the matching Module A finding when one exists.

**SELECT logged, no export.** Consequence `access_observed`. People in those tables count towards
`observed_access`; nothing counts towards `confirmed_exfiltration`.

**Export file created, no egress evidence.** Consequence `export_or_staging_observed` — a copy was prepared inside
the hospital. Still not exfiltration.

**Large outbound flow after staging, payload unknown.** Consequence `egress_suspected`. The report says which
records may have been involved (scenario bounds) and that the payload is unknown.

**Leak sample received.** The leak-sample source has `evidence_role: leak_sample`. People matched to it form
`confirmed_exfiltration`, for the categories present in the sample only; every other person in scope remains
`possible_exposure`.

**No exposure scan (Module A absent).** Containment advice is derived from Module B evidence only, and says so.

## 4. Version lineage

Every change to inputs — a new source, new logs, new review decisions, a scoping decision, a parser-rule or
configuration change — produces a new draft whose `previous_report_sha256` links to the last released version
of that kind. Scope reports carry `config_sha256`, `review_decisions_sha256`, `scoping_decisions` and source
hashes; `diff.json` lists people added and removed per category (counts only).
