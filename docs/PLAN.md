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
