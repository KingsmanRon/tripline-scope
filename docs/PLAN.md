# Tripline Scope v0 — build plan and interface contracts

This file fixes the interfaces between the shared core and the three engines so they can be built in
parallel. It is the contract; module docs (`METHOD.md`, `EXPOSURE.md`, `ACCESS_PATHS.md`, `INTEGRATION.md`)
explain behaviour.

## 1. Layout

```
src/tripline_scope/
  core/        shared: case, custody, crypto, store, duck, audit, auth, context, reports, closure,
               evidence, identifiers, redact, assets, pdf, hostcheck   (built first; owned by core)
  cli/         tscope entry point; each module exposes register(subparsers)
  ingest/      shared ingestion: SQL Server .bak / PostgreSQL dump restore, CSV/TSV/XLSX/JSONL readers,
               read-only live connections, extraction to encrypted Parquet          → `tscope ingest`
  discovery/   shared column classification (sample, then full scan)               → used by ingest, map, exposure
  readiness/   data map (`tscope map`) and the readiness report
  exposure/    Module A — offline exposure scan                                    → `tscope exposure ...`
  paths/       Module B — access-path analysis from exported logs                  → `tscope paths ...`
  scope/       Module C — rows→people, exposure per person, scope report, notices  → `tscope estimate`, `tscope scope ...`,
               `tscope profile`, `tscope drill`
  synth/       synthetic lab data + ground truth                                   → `tscope synth`
verify/src/tscope_verify/   stand-alone offline verifier (cryptography + rfc8785 only) → `tscope-verify`
```

Rules for every module: never write to a source; never print, log, sign or report patient identifiers, secret
values, passwords, connection strings or full queries; encrypt every working file through `CaseStore`; open
DuckDB only through `core.duck.connect*`; run every case command inside `core.context.command(...)` so it is
authorised and audited; express every claim with `core.evidence` (basis + consequence class kept separate).

## 2. Key hierarchy and storage

| Key | Held where | Protects |
|---|---|---|
| Hospital KEK (AES-256) | `kek.json` outside every case (removable media or service-account-only path), scrypt-wrapped by a passphrase | wraps case DEKs; TOTP secrets |
| Case DEK (AES-256, one per case) | hospital keystore `<keystore>/cases/<CASE>.dek.json`, AES-GCM-wrapped by the KEK, AAD = case id | every envelope in the case |
| Per-file key | HKDF-SHA256(DEK, "tripline-file"‖file_id) | one envelope |
| Fingerprint key | HKDF-SHA256(DEK, "tripline-fingerprint:"‖purpose) | keyed HMAC fingerprints (secrets, record keys, review pairs) |
| Hospital signing key (Ed25519) | passphrase-encrypted PKCS#8, hospital-held | `release.json` of every released report; destruction certificates |
| Provider signing key (Ed25519, optional) | provider-held | co-signature over `report.json` at draft time |
| Release signing key (Ed25519) | vendor build machine | `SHA256SUMS` of the offline bundle |

Envelope `TSENC1`: chunked AES-256-GCM (1 MiB chunks, nonce = prefix‖index‖final-flag, AAD = header hash‖index);
detects tampering, truncation, reordering and file substitution (logical name bound in the header). DuckDB runs
in memory with spill disabled, extensions off and external access off (only allow-listed source files are
readable); DuckDB/Parquet native encryption is not used (needs a runtime-downloaded extension in 1.5.x).
Closure overwrites + unlinks the wrapped DEK, deletes managed files, runs module closure hooks (drop restores)
and writes a signed destruction certificate.

## 3. Case, custody, audit, roles

* `case.yaml` keys: `case_id, mode (incident|readiness), incident_window, team{operators,reviewers,approvers},
  retention, legal_hold, case_key, sources[], declared_gaps[], column_overrides{SRC:{table:{column:category}}},
  relations[], matching{}` (modules may add their own top-level keys).
* Sources: `tscope source add` (reference to a read-only original, or `--copy` for an encrypted copy) with
  SHA-256, size, `supplied_by`, `received_at`, `legal_basis`, `evidence_role ∈ {system_copy, leak_sample,
  export_found, log, readiness_copy, reference_data}`. A process-wide audit hook blocks any write, rename,
  delete or chmod under a source path; size+mtime are checked before and after every command; full SHA-256 at
  ingest, `source verify --full` and close.
* Roles per case: operator, reviewer, approver; `admin` is a system role for accounts only. Operator ≠ approver
  on the same case, enforced at assignment, on every command and again at release/close (audit log history).
  Release and close require a fresh approver sign-in (Argon2id password, TOTP if enrolled/required).
* Audit: `<case>/audit.log`, canonical JSON lines, `prev`/`hash` chain, verified by `tscope audit verify` and
  `tscope-verify audit`; exported as JSON Lines for the SIEM.

## 4. Reports (all modules)

`ReportStore.new_body(kind, ...)` → module content → `save_draft(kind, body, pdf=, attachments=, provider=)` →
`tscope release --kind KIND --approver IO` → `reports/<kind>/v000N/{report.json, report.pdf, attachments/*,
release.json, signatures.json}` (read-only). Kinds: `scope, exposure, paths, readiness, datamap, drill`.
Report JSON must be deterministic (no wall-clock times unless they are case facts) so identical inputs give a
byte-identical `report.json`. Every report body carries `method_version`, `config_sha256` and the hashes of its
inputs. `save_draft` refuses bodies containing identifier-like values. Release hooks
(`register_release_hook(kind, fn)`) run after signing (Module C uses one to unlock the notification pack).

## 5. Ingest → discovery → extract contract (consumed by Module C, map, drill)

* Restore targets are installation config (`restore_targets.mssql|postgres`: host, port, login, password env
  var, backup path mapping); never in `case.yaml`. Each restore is recorded in `work/restores.json`; a closure
  hook drops them. Live connections are off unless `live: true` for the source; the login is checked for write
  permissions (refuse if any) and every query runs read-only with row limits and timeouts.
* Discovery per table: sample (default 10 000 rows) → classify → full scan confirms. Output
  `work/discovery/<SRC>.json`: per column `{name, category, confidence, match_rate, null_rate, purpose
  (matching|contact|exposure|none), extracted, standard_field, override}` and `row_count`. Overrides in
  `case.yaml` win. Column categories: `sa_id, passport, phone, email, first_name, last_name, full_name,
  maiden_name, dob, sex, address, postal_code, medical_aid_no, medical_aid_scheme, patient_key, patient_ref,
  guardian_name, guardian_phone, guardian_email, guardian_sa_id, language, record_date, icd10, test_code,
  test_result, clinical_free_text, card_number, bank_account, other_identifier, other`.
* Extract `work/extract/<SRC>/<table_slug>/part-NNNNN.parquet` (encrypted) with the **standard schema**:
  `_row_key ("<SRC>|<slug>|<ordinal>"), _source_id, _table, sa_id (normalised, valid only), passport_no,
  first_name, middle_names, last_name, full_name, maiden_name, dob (date), sex, medical_aid_no,
  local_patient_key, patient_ref, phone (E.164), phone_alt, email, address, postal_code, language,
  guardian_name, guardian_phone, guardian_email, guardian_sa_id, record_date (date)` plus boolean presence
  flags `_has_<category>` for exposure categories. Clinical, card and bank columns are **never** extracted:
  only their `_has_*` flags. Manifest `work/extract/<SRC>/manifest.json`: tables with `database`, `table`,
  `slug`, `row_count`, `parts`, `role (identity|dependent|other)`, `fields`, `flags`.
* Exposure categories used in every report: `identity_number, name, date_of_birth, contact_details, address,
  medical_aid, clinical_diagnosis, clinical_tests, clinical_results, clinical_notes, payment_card, bank_account`.

## 6. Module C — matching configuration (defaults; tuned values recorded in METHOD.md)

* Records: identity rows (≥2 of name/DOB/ID/passport); dependent rows link to their source's identity row by
  `patient_ref = local_patient_key` (relation from discovery or `case.yaml relations`); unresolved dependent
  rows and rows with no usable identifiers are counted as **unresolvable**, never forced into people.
* Deterministic link: equal valid SA ID and DOB consistent with the ID's embedded date (or DOB absent).
* Blocking (OR): `sa_id`; `soundex(last_name)+dob`; `soundex(sorted name tokens)+dob` (swapped order);
  `soundex(maiden_name)=soundex(last_name)+dob` (maiden/married); `phone`; `email`.
* Comparisons (Fellegi–Sunter, Splink on DuckDB): SA ID (exact / both-valid-differ / null); first name (exact,
  JW ≥ .92, ≥ .80, swapped-with-surname); surname (exact, any-surname incl. maiden, JW ≥ .92, ≥ .80); DOB
  (exact, one edit/transposition, same year); sex; phone (exact, term-frequency adjusted); email; medical aid
  number; postal code. u by random sampling (fixed seed), m by EM on the DOB and ID blocks.
* Bands on match probability: auto-link ≥ 0.995, review 0.80–0.995, non-link < 0.80 (config). Decisions from the
  review page are keyed by an HMAC of the record-key pair and replayed on every re-run.
* Clustering: connected components over deterministic + auto + accepted review links; over-merge guard sends a
  cluster to review when it holds > 1 distinct valid SA ID, contradictory DOBs or more than 25 records, and
  counts it conservatively (split) until reviewed.
* Confidence per person: `deterministic | auto-linked | reviewed | probabilistic-unreviewed`.
* Scope tiers kept separate: `observed_access`, `possible_exposure`, `confirmed_exfiltration` (people matched to
  an `exfiltration_evidenced` source such as a leak sample), `notification_scope` (the Information Officer's
  decision; default proposal = possible exposure upper bound). Absent or uncertain logs never shrink scope.

## 7. Module B — common event schema

Encrypted Parquet `work/paths/events/<SRC>.parquet`, one row per source record:
`event_id, source_id, source_family, ordinal, ts_original_text, tz_original ("Z"|"+02:00"|"unknown"), ts_utc
(null if unresolvable), clock_offset_s, ts_uncertainty_s, time_precision, host, account, application, session_id,
request_id, logon_id, remote_ip, operation, observation_type, database, object_name, rows (null = volume
unknown), bytes, outcome (success|failure|unknown), mfa (true|false|unknown), url_path (no query string),
http_status, parser ("<family>/<version>"), raw_sha256, consequence_class`. SQL text is never stored (operation
and object names are extracted; statements are fingerprinted with the case key).
Path edges are `direct` (exact session/request/logon id), `correlated` (bounded, configured time window — an
inference) or `unresolved`. Outputs: `work/paths/analysis.json`, draft `paths` report (timeline CSV/JSONL
attachment, bounded), and `scope-candidates` (schema `tripline.scope-candidates/v1`: per table
`window_class confirmed|possible|not_assessable`, windows, consequence class, basis, accounts, evidence ids,
confidence, limitations; coverage gaps; lower/upper scenarios).

## 8. Module A — authorised scan boundaries and findings

`manifest.yaml` (`tripline.exposure-manifest/v1`) declares: owner, legal basis, data-processing budget (files,
bytes, per-file size, archive depth/members/ratio, seconds), `roots[]` (read-only snapshots: web roots, config
folders, shares, exported scripts, repositories), `databases[]` (catalogue export, restored copy or
metadata-only read-only login), identity/sign-in/MFA exports, supplier register, observation window for
dormancy, exclusions, asset map. Anything outside declared roots is never opened; symlinks escaping a root are
rejected; archives are bounded. No network activity, no credential validation, no deletion or revocation.
Finding: `finding_id` (stable keyed fingerprint), `control_id` (A1 secrets, A2 privileges, A3 data copies,
A4 database configuration, A5 supplier access), title, severity with likelihood/impact rationale, asset + bounded
location, evidence ids, first/last seen, provenance, confidence, ownership, suggested fix, state
(`new|open|mitigated|accepted-risk|not-assessed`), redacted context, keyed secret fingerprint. Coverage per
control: `assessed | not assessed | unavailable` with reasons.

## 9. Cross-module joins

* A → B containment: by `finding_id` and `asset_id` from the shared asset map (`core.assets`), never by secret.
* B → C: `scope-candidates` JSON; C records each scoping decision (constrain/widen + reason) in the audit log and
  in the next scope report; candidate and full-scope counts are both reported.
* C → notices: only records of people inside the approver's notification scope reach `notify/`; export only
  after release, by the approver.

## 10. Delivery order

Shared core (done, tested) → parallel tracks: ingest/discovery/map, Module A, Module B, Module C (+synth,
profile, drill), packaging/acceptance → integration (demo, readiness report, cross-module tests, benchmarks,
acceptance record).

---

# Release 1 — AI Investigator, Investigation Workbench, unified synthetic demo

These contracts were fixed before implementation. Workstreams own disjoint files; shared files (`core/reports.py`,
`cli/__init__.py`, the top-level docs) are changed only by the integrating owner.

## 11. Layout additions

```
src/tripline_scope/
  investigator/   Workstream A — read-only, evidence-grounded investigation      → `tscope investigator ...`
    bundle.py       released A/B/C reports → verified, bounded, allowlisted evidence bundle
    schema.py       tripline.investigation-candidate/v1 (model output) and tripline.investigation/v1 (result)
    validate.py     deterministic validator (the only gate between model output and Tripline)
    providers.py    provider interface: fixture | local (loopback HTTP) | hosted adapters (unavailable) | bridge
    prompt.py       bounded prompt built from the bundle (evidence is data, never instructions)
    fixture.py      deterministic rule-based fixture "provider" (labelled; never presented as AI inference)
    run.py          analyse → store (encrypted) → validate → review → report
    report.py       `investigation` report body + PDF from a frozen, reviewed result
    synthetic.py    synthetic-origin registry (HMAC under the hospital KEK) for the manual bridge
    cli.py
  dashboard/      Workstream B — read-only local workbench                          → `tscope dashboard serve`
    app.py          FastAPI app (security model of scope/review_app.py)
    data.py         read models over released reports + investigator results
    page.py         single self-contained HTML/CSS/JS page (no external assets)
    cli.py
demo/lab-breach/  Workstream C — unified synthetic laboratory breach (extends the existing demo)
```

## 12. Investigator contracts

**Inputs.** Only *released* report versions (`ReportStore.load`) of kinds `exposure`, `paths`, `scope`, each
verified with `ReportStore.verify(kind, home)` before use (signature + chain). Drafts, extracts, restores, logs,
the notification pack and case sources are never read. A missing kind is recorded as `not assessed`.

**Evidence bundle** `tripline.investigation-bundle/v1` (encrypted at `work/investigator/runs/<run>/bundle.json`):

| field | content |
|---|---|
| `case_id`, `bundle_sha256` | canonical hash of the bundle without this field |
| `reports[]` | `{kind, version, report_sha256, released: true, verified: true}` |
| `evidence{id: item}` | items keyed by the ids already in the reports: `AF-…` findings (A), `PATH-…` paths, `CLM-…` table claims, `ANOM-…` anomalies, `GAP-…` gaps, `COR-…` corroborations, `REC-…` containment recommendations (B); `FACT-…` quantities (A/B/C) |
| item fields (allowlist) | `id, module, report{kind,version}, type, basis, consequence_class, statement, severity, assets[], sources[], tables[], accounts[] (opaque `ACCT-` refs + approved labels), time_window, confidence, limitations[], exfiltration_evidence_kind` |
| `facts{FACT-id: {value, unit, source:{kind,version,pointer}}}` | every number the model may quote (counts, bounds, estimates, tiers, class counts); `"not determinable"` values kept as strings |
| `assets[]`, `sources[]`, `missing_source_families[]`, `window` | from the reports |

Strings are copied from released reports only, truncated (≤ 300 chars), control characters removed, and
re-scrubbed (`core.redact`). Bundle limits: ≤ 400 evidence items, ≤ 200 facts, ≤ 256 KiB canonical.

**Model output** `tripline.investigation-candidate/v1` (strict: unknown keys are rejected):

```
{schema, case_id, bundle_sha256, summary,
 hypotheses: [{hypothesis_id "H1".."H9", rank "main"|"alternative", statement, basis "hypothesis"|"inference",
               consequence_class (one of the five), supporting_evidence[ids ≥1], contradicting_evidence[ids],
               assets[], sources[], time_window {start,end}|null, confidence "low"|"moderate"|"high",
               confidence_rationale, alternative_explanations[], tests[{evidence_needed, would_resolve}],
               cannot_conclude[≥1], quantities[{fact_id, value}]}],
 missing_evidence: [{description, source_family, related_evidence[ids]}],
 investigation_steps: [{step, priority "immediate"|"next"|"later", evidence_ids[≥1]}],
 remediation: [{action, priority, evidence_ids[≥1], asset_ids[]}],
 unproven_assertions: [str]}
```

Confidence labels are ordinal, not probabilities: `low` = consistent with the evidence but not preferred over the
alternatives; `moderate` = better supported than the alternatives on cited evidence; `high` = supported by
observations with no cited contradicting evidence. Labels are never converted to numbers.

**Validator** (deterministic, `validate.py`) — each item gets `accepted | rejected | unverified` with reason codes;
the run is `completed` only if the envelope is valid and ≥ 1 hypothesis is accepted:

| code | rule |
|---|---|
| `schema` | malformed JSON / wrong types / unknown keys / limits exceeded → whole candidate rejected |
| `case_mismatch`, `bundle_mismatch` | `case_id` / `bundle_sha256` differ from the run → whole candidate rejected |
| `unknown_evidence` | any id not in the bundle (covers cross-case ids) |
| `promotion` | asserted `consequence_class` stronger than the strongest class among the cited supporting evidence |
| `exfiltration_unsupported` | `exfiltration_evidenced` without a cited item that carries an `EXFILTRATION_EVIDENCE_KINDS` kind; or text asserting theft/exfiltration as fact without such evidence |
| `basis_upgrade` | basis other than `hypothesis`/`inference` |
| `missing_logs_as_absence` | text concluding "no compromise/access" while a cited or case gap is open |
| `unsupported_number` | a number in free text that is not an id/date and not declared in `quantities`, or a quantity whose value ≠ the fact |
| `unknown_asset`, `unknown_source` | asset/source ids not in the bundle |
| `prohibited_content` | identifier-like values, credential patterns, URLs, e-mail, clinical codes, shell/SQL command text |
| `unsupported_conclusion` | `inference` without an observation/inference among the supporting evidence |

Rejected text is never stored outside the encrypted run directory, logged or shown; diagnostics carry codes and
counts only. The validated result `tripline.investigation/v1` is stored encrypted and contains: case and run ids,
schema, references (kind, version, sha256), method + config versions, provider provenance
`{provider, kind: fixture|local|manual_bridge, model_id, model_version, is_model_inference, endpoint_class}`,
`analysis_status` (`completed|unavailable|failed|not_assessed`), accepted hypotheses, missing evidence, steps,
remediation, unproven assertions, per-item validation verdicts, `model_output_sha256`, `validator_version`,
`human_review` (`required`, per-item decisions).

**Providers.** `Provider.analyse(prompt: dict, budget) -> ProviderResponse(raw: bytes, provenance)`. Explicit
selection only (`--provider NAME`); no fallback. `fixture` (deterministic, `is_model_inference: false`), `local`
(OpenAI-compatible `/v1/chat/completions` on a literal loopback address configured by the admin in
`config.yaml` → `investigator.local`; proxies and redirects disabled; timeout and byte limits), `openai-daybreak`
and `anthropic` (adapter boundaries that report `unavailable`: not authorised in this release), and the
synthetic-only manual bridge (`bridge-export` / `bridge-import`) which refuses any case whose sources are not
all in the synthetic registry.

**CLI.** `tscope investigator analyse --case C --provider P` (operator) · `show --case C [--run R]` (any case role)
· `review --case C --run R --item H1 --decision accept|reject --note …` (reviewer) · `report --case C --run R`
(operator; draft of kind `investigation`) · `tscope release --kind investigation` (approver, existing gate) ·
`verify --case C` (any role: chain + re-render from the frozen result) · `bridge-export` / `bridge-import`
(operator, synthetic cases only) · `providers` (list availability).

**Investigation report** (`kind: investigation`, schema `tripline.investigation-report/v1`): sections
`deterministic_findings` (computed by Tripline from the module reports), `ai_analysis` (accepted items,
attributed, `advisory: true`, with review status), `human_reviewed_conclusions`, `missing_evidence`,
`validation` (counts by code, no rejected text), `references`, `provenance`. It never contains prompts, raw model
output or rejected content; it stores `model_output_sha256` and `frozen_result_sha256`. Building a report refuses a
run whose referenced versions are no longer the latest released versions (`stale`).

## 13. Dashboard contracts

`tscope dashboard serve --case C [--port 8766] [--host 127.0.0.1|localhost|::1]` (any case role). Sign-in through
`core.auth.identity_provider`; a session requires a role on the case. Cookies HttpOnly + SameSite=Strict;
absolute 2 h / idle 30 min expiry; CSRF token on every POST; `TrustedHostMiddleware` (127.0.0.1/localhost);
`Origin` checked on POST; CSP `default-src 'none'` with a per-response script nonce; `frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `Cache-Control: no-store`, `Cross-Origin-Resource-Policy: same-origin`. Read-only: only
GET data endpoints; the only writes are sessions and audit entries (`dashboard login`, `dashboard view <section>`).

| endpoint (GET, JSON) | source |
|---|---|
| `/api/overview` | case.yaml, report versions, released report metadata, Module B gaps/coverage |
| `/api/timeline?start&end&source&family&account&asset&class&offset&limit≤500` | released `paths` `attachments/timeline.jsonl` + gaps |
| `/api/paths` | released `paths` report: nodes/edges with labels and evidence ids |
| `/api/exposure` | released `exposure` report findings, coverage; Module B cross-references |
| `/api/people` | released `scope` reports (preliminary + refined); tiers; never person-level rows |
| `/api/investigation` | latest validated investigator run (encrypted work) and/or released `investigation` report |
| `/api/reports` | versions, hashes, approvals, `verify_chain` results |
| `/reports/{kind}/v{n}/{report.json|report.pdf}` | released versions of `exposure|paths|scope|investigation|readiness` only |

Missing data is returned as `{"status": "not_assessed"|"not_determinable"|"awaiting_analysis"}`, never 0.

## 14. Unified demo contract

`demo/lab-breach/run.sh [--scenario suspected|corroborated] [--keep-open] [--dashboard]`:
synthetic estate (Module A, assets aligned to Module B: `AST-LABSQL01`, `AST-LABSQL02`, `AST-WEB01`, …) →
`exposure scan/report/release` → Module B logs (`suspected`: no corroboration; `corroborated`: an independently
corroborated external copy of `LabDB03.dbo.patients`, matching Module C's leak sample) → `paths
ingest/analyse/report --exposure-report/release` → ingest/restore (SQL Server Developer, synthetic only) →
estimate → match → review → report → notify → release → `investigator analyse --provider fixture` → review →
`investigator report` → release → dashboard smoke test → `tscope-verify` every chain → leak scan → close.
The 80M preliminary-estimate benchmark is presented separately and never runs in the quick demo or CI.

## 15. Acceptance tests (new)

Investigator: valid evidence → schema-valid result; unknown / cross-case ids, stale or wrong hashes rejected;
SELECT ≠ theft; local export ≠ exfiltration; flow without content stays `egress_suspected`; exfiltration only
with eligible corroboration; missing logs stay explicit; invented counts rejected; prompt injection in a log has
no effect (no command, no network, no disclosure); no non-loopback connection in hospital mode; provider absence
or failure leaves A/B/C untouched; approval gates; tampered investigation report fails `tscope-verify`; identical
re-render from a frozen result. Dashboard: localhost binding, auth, roles, host/CSRF/session controls, no
arbitrary paths, no identifiers, pagination, unavailable ≠ 0, read-only, counts agree with reports, offline.
Demo: A from real scanner, B from generated logs, C from generated records, lineage, both scenarios' classes,
validated references, signatures, dashboard loads, sources unchanged, no leaks, offline.
