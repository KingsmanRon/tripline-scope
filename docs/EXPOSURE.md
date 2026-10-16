# Module A — Exposure scan (readiness, offline)

`tscope exposure ...` assesses hospital-authorised, **read-only** snapshots and exports for conditions that could
expose patient data before an incident. It is a configuration and data-exposure assessment, **not** a vulnerability
scanner or penetration test: it never probes the network, validates or uses a found credential, exploits anything,
deletes or moves files, revokes access or patches. Findings describe exposure conditions; none implies a compromise.

| Control | What is detected |
|---|---|
| A1 Plaintext secrets | credentials, database URLs/connection strings, API tokens, signing/encryption keys, private keys, provider formats, in configs, scripts, repositories (incl. loose git objects) and bundled JavaScript |
| A2 Excessive privileges | application/service principals with owner/admin rights on patient databases, write rights beyond declared function, shared identities, dormant accounts (only with an observation window), obsolete/orphaned principals |
| A3 Uncontrolled patient-data copies | CSV/TSV/XLSX/JSON/JSONL/SQL-text exports and extracts (incl. inside zip/tar/gz/bz2/xz), database backups and data files recognised by format header |
| A4 Risky database configuration | audit disabled/incomplete, database-originated shell execution, cross-server links, guest/PUBLIC access, exposed service accounts, excess capabilities (SQL Server and PostgreSQL) |
| A5 Supplier access | external/supplier identities reaching patient-data stores, missing/unknown MFA evidence, privileges beyond contract, expired contracts, long inactivity |

## Workflow

```
tscope exposure synth --out DIR [--variant baseline|fixed]      # synthetic inputs (tests, drills, demo)
tscope exposure catalog-sql --engine mssql|postgres [--out F]   # read-only catalogue queries for the DBA
tscope exposure collect-catalog --engine ... --host --port --user --database --out F   # optional, metadata-only login
#   SQL Server TLS: --tls-cafile CA.pem [--trust-server-certificate]   (encrypts; CA chain always verified)
tscope exposure scan   --case CASE --inputs manifest.yaml       # operator; encrypted results in work/exposure/
tscope exposure report --case CASE [--no-pdf]                   # operator; ranked JSON/PDF draft
tscope release --kind exposure --case CASE --approver IO        # Information Officer signs an immutable version
tscope exposure diff --case CASE --from v1 --to v2 [--out F.json] [--csv F.csv]
tscope exposure purge --case CASE                               # drop working files; released reports remain
```

Roles: `scan`, `report`, `purge` need the case **operator**; release needs a different person holding the
**approver** role (fresh sign-in; operator ≠ approver is enforced by core). `diff` needs any signed-in user (with
`--case` it is audited).

## Approved scan roots and the manifest (`tripline.exposure-manifest/v1`)

Everything the scan may read is declared in the manifest; relative paths resolve against the manifest's directory.

```yaml
schema: tripline.exposure-manifest/v1
scan_id: EXPO-2026-Q4
owner: "Hospital IT Security"                 # required
legal_basis: "POPIA s19 security safeguards"  # required
supplied_by: "Hospital IT"
received_at: 2026-10-01T06:00:00Z             # required (custody)
snapshot_taken_at: 2026-10-01T00:00:00Z       # 'as of' for ages, first/last seen (defaults to received_at)
budget:                                       # required; defaults shown
  max_files: 200000
  max_total_bytes: 20GiB
  max_file_bytes: 64MiB          # larger files: header-only format recognition, reported 'unavailable'
  max_seconds: 14400
  archive_max_depth: 2
  archive_max_members: 2000
  archive_max_ratio: 100         # per-member compression ratio (archive bombs)
  archive_max_total_bytes: 256MiB
  max_rows_per_file: 1000000     # rows counted; beyond this a bounded estimate
  max_rows_inspected: 50000      # rows whose values are validated
observation_window: {start: 2026-04-01T00:00:00Z, end: 2026-09-30T23:59:59Z}   # needed for dormancy/inactivity
stale_after_days: 90
hospital_domains: [hosp.example]
exclusions: ["**/node_modules/**"]            # glob on root-relative paths (** spans directories)
roots:                                        # read-only snapshots: web_root | config | share | scripts | repository
  - {id: web01, path: snapshot/web01, kind: web_root, asset: AST-WEB01, owner: "Web team", exclusions: []}
databases:                                    # engine mssql | postgres (others: 'not assessed')
  - {id: labdb, engine: mssql, name: LabDB, server: LABSQL01, asset: AST-LABDB, patient_data: true,
     export: catalog/labdb_mssql.json}        # JSON export or directory of <query>.csv (+ _meta.json)
  - id: pathdb
    engine: postgres
    name: pathdb
    mode: live_metadata                       # optional: metadata-only read-only login to a restored copy
    live: {host: 10.0.0.5, port: 5432, user: tscope_meta, password_env: TSCOPE_PATHDB_PW, timeout_s: 30, max_rows: 200000}
identity:
  directory_export: identity/directory.csv    # AD/Entra export (CSV or JSON / Graph 'value')
  signin_export: identity/signins.csv
  mfa_export: identity/mfa.csv
  supplier_register: identity/suppliers.csv
  signin_coverage: {start: ..., end: ...}     # optional; otherwise min/max of the records
assets: assets.yaml                           # core.assets map (asset_id, kind, names, owner, criticality)
patient_data_assets: [AST-LABDB, AST-PATHDB, AST-LIS]
accepted_risks: accepted_risks.yaml           # hospital-maintained register (see below)
principals:                                   # declared function/expected access (confirms or clears A2 findings)
  - {name: lab_app, database: labdb, type: application, function: "LIS application", expected_access: write}
```

`type` ∈ `application, service, human, dba, supplier, shared, system`; `expected_access` ∈ `none, read, write, admin`.

Each declared input is registered as a case source through `core.custody.add_source` (reference mode: roots as
`directory`/`readiness_copy`; catalogue exports `catalog_export`/`reference_data`; identity files
`directory_export`/`reference_data`; live logins `live_pg`/`live_mssql`, never with the password). A path with
unchanged content that is already registered is reused, so re-scans keep the same source ids. The core write guard
then refuses any write, rename, delete or chmod under these paths. Custody hashes every file of a declared root
(including excluded paths: hashing is integrity, not inspection).

### Confinement guarantees

* Only declared roots are listed; files are opened `O_RDONLY|O_NOFOLLOW` and checked with `fstat` against the
  directory entry. Symbolic links are **never followed**: a link leaving the root is recorded as
  `symlink-escape-rejected`, one inside as `symlink-not-followed`. FIFOs, devices and sockets are never opened.
* Archives are expanded in memory only (never extracted), bounded by depth, member count, per-member size,
  compression ratio and total bytes; member names are normalised.
* An offline guard (audit hook on `socket.*` events) refuses every network attempt during a scan; only an endpoint
  declared as `live_metadata` is allowed. The scan also passes inside a network namespace with no route out
  (`unshare -n`, tested).
* Tests prove, with an audit hook, that no path outside the declared inputs (and no excluded path, by the scanner)
  is opened or listed.

## Database configuration and permission catalogues

`tscope exposure catalog-sql --engine mssql|postgres` prints the shipped queries (`exposure/catalog_sql.py`), all
single catalogue `SELECT`s: no table data, password hashes, user-mapping options or linked-server provider strings.
The DBA runs them on a **restored copy** or with a **metadata-only login** and saves `<query>.csv` per query, or runs
`collect-catalog`, which writes one JSON export.

* **SQL Server** (server scope): `server_info, server_principals, sql_logins, server_role_members,
  server_permissions, databases, configurations, linked_servers, linked_logins, server_audits,
  server_audit_specifications, credentials, services`; (per database) `database_principals,
  database_role_members, database_permissions, database_audit_specifications, tables, columns`.
  Login: `GRANT VIEW ANY DEFINITION, VIEW SERVER STATE` (2022: `VIEW ANY SECURITY DEFINITION`,
  `VIEW SERVER SECURITY STATE`) and a user in each scanned database with no roles.
* **PostgreSQL**: `server_info, roles, auth_members, databases, database_privileges, schema_privileges,
  table_privileges, tables, columns, settings, extensions, languages, foreign_servers, user_mappings, hba_rules`.
  Login: `LOGIN`, `pg_read_all_settings`, `CONNECT`. `pg_hba_file_rules` needs superuser unless granted; without
  it the client-authentication check is `unavailable`.

The collector **refuses** a login that can write data, change schema, own objects, administer the server or reach
server files/programs (`sysadmin`, `CONTROL SERVER`, `db_owner/db_datawriter/db_ddladmin`, any INSERT/UPDATE/DELETE;
PostgreSQL superuser, CREATE, table write privileges, object ownership, `pg_execute_server_program`,
`pg_write_server_files`, `pg_write_all_data`, CREATEROLE/CREATEDB/REPLICATION). Queries run with timeouts and row
limits (PostgreSQL in read-only transactions); truncation is recorded as missing evidence.

**Effective rights** are derived through role membership (nested roles; PostgreSQL inheritance and SET ROLE to
superuser roles), explicit grants with DENY honoured, database ownership, table ownership, server roles and
`CONTROL SERVER`, and Windows-group logins expanded with the directory export's group memberships (`inference`).
Patient tables are those whose column names identify people (names, ID numbers, DOB, contact, patient keys).
When memberships or grants are missing from the export, findings are labelled with caveats and lower confidence and
the gap is listed (`unavailable: db:<id>:role_membership`).

**Checks** (each is one coverage unit `db:<id>:<check>`): SQL Server `principals, xp_cmdshell, clr,
ole_automation, adhoc_distributed_queries, linked_servers, audit, guest_access, public_grants, trustworthy, sa_login,
service_accounts, password_policy, excess_capabilities, cross_db_chaining`; PostgreSQL `principals, copy_program,
excess_capabilities, untrusted_languages, audit_logging, cross_server_links, public_schema_create,
public_table_grants, hba_auth, password_encryption`. A query absent from the export → `not assessed`; a query that
failed (e.g. permission denied) → `unavailable`; an option value this version cannot interpret → `not assessed`
(never guessed); an unsupported engine → every check `not assessed`.

## Supplier and identity imports

CSV (header row) or JSON. Column names are matched case- and punctuation-insensitively; recognised aliases:

| File | Columns |
|---|---|
| directory | `sAMAccountName/account/login`, `userPrincipalName/upn/mail`, `enabled` (or `disabled`, `userAccountControl`), `accountType` (user/service/shared/guest/external/supplier…), `userType` (Member/Guest), `company`, `groups/memberOf` (`;`-separated, CN= parsed), `lastLogon/lastSignInDateTime`, `employmentEnd/accountExpires` |
| sign-ins | `timestamp/createdDateTime`, `userPrincipalName/account`, `appDisplayName/resource`, `authenticationRequirement/mfa` (multi/single factor, true/false), `status/result/errorCode`, `deviceId/clientIp` |
| MFA | `userPrincipalName/account`, `isMfaRegistered/registered`, `mfaState/perUserMfaState`, `methodsRegistered` |
| supplier register | `supplier`, `accounts` (`;`-separated), `contract_ref`, `contract_end`, `permitted_access` (none/read/support/write/admin), `permitted_assets`, `mfa_required` |

Supplier identities are register accounts, directory guests/external types, `#EXT#` UPNs, companies named in the
register, accounts outside `hospital_domains`, or DB principals typed `supplier`. Reach to patient data comes from
effective DB rights (direct = observation; via group = inference), sign-ins to applications mapped to patient-data
assets, or the contract's permitted patient assets.

**Unknown is not disabled.** MFA is `verified`, `not_evidenced` (no registration, single-factor sign-ins observed,
or SQL-authenticated login) or `unknown` (no record/fields empty/no export). Activity is `active`, `inactive` or
`unknown`: `inactive`/dormant requires a declared `observation_window` **and** sign-in evidence covering it for that
account (or a directory last-logon before the window when no sign-in export exists, with a replication-lag caveat).
Contract is `linked`, `expired` or `unknown`. Unknowns are reported as such and listed under missing evidence.

## A1/A3 detection and false positives

* **Secrets.** Provider formats (AWS secret key and key id, Azure storage key and SAS signature, GitHub, Slack,
  Stripe, Google API key, SendGrid, JWT), PEM private keys (encrypted keys separately), credentials in URLs and
  connection strings (server/database/user parsed to link the target asset and principal), ASP.NET machine keys,
  HTTP Basic and bearer headers, command-line password flags (`sqlcmd -P`, `mysql --password`…), PowerShell
  `ConvertTo-SecureString -AsPlainText`, `net use`, PHP `define()`, and a key-name rule (`password=`,
  `"apiKey": "…"`, `<add key="…Password" value="…"/>`, `SetEnv`/`fastcgi_param`).
* **False-positive reduction.** Placeholders (`${VAR}`, `%VAR%`, `{{…}}`, `<…>`, `changeme`, `your_…`), references to
  vaults/env (`process.env`, `os.environ`, Key Vault), unquoted identifiers in code (`password: e.value`),
  non-secret key names (`passwordField`, `tokenUrl`, `PasswordMinLength`), prose, file paths, low-entropy or short
  tokens (key-name rule: tokens ≥ 12 chars and ≥ 3.0 bits/char; passwords ≥ 4 chars, low entropy only lowers
  confidence), documentation example values (`…EXAMPLE`), Stripe test-mode keys, and **test fixtures** (`test(s)/`,
  `fixtures/`, `examples/`, `*.example`, `.env.sample`, `*.test.js`…; disable with `suppress_test_fixtures: false`).
  Suppressed candidates are counted per reason in the report; their values are never recorded.
* **Never the value.** Each secret becomes a keyed, case-local fingerprint (`store.fingerprinter("exposure-secret")`,
  HMAC under the case key, base32) and a redacted context in which every detected value and any other random-looking
  token is replaced and identifier-like text scrubbed. The same fingerprint in several locations raises likelihood
  (shared credential). A credential whose user holds admin/write on a patient DB raises the A1 impact and the
  matching A2/A5 likelihood (cross-linked by finding id).
* **Patient-data copies.** Headers map to categories; values are checked for valid SA ID numbers (13 digits, real
  date, citizenship digit 0/1/2, Luhn) using `core.identifiers`. A column is `confirmed` when ≥ 80 % of values pass
  **and** its header or neighbouring person columns give context; `probable` (inference) when the pass rate is high
  without context; `unconfirmed` when values are 13 digits but mostly fail (accession numbers, barcodes) — never
  treated as IDs. Reports carry count bands (`0, 1-9, 10-99, 100-999, 1k-10k, 10k+`) or bounded estimates, file age,
  staleness and sensitivity (health information with identifiers = special personal information). Opaque formats —
  SQL Server `.bak` (MTF `TAPE`), PostgreSQL `PGDMP`, `.mdf/.ndf/.ldf` page headers, Oracle export — are reported by
  format and name only; 7z/RAR, office/PDF documents and git packfiles are `not assessed`.

## Finding contract and severity

Each finding: `finding_id` (keyed, case-local, stable for the same inputs), `control_id`, `rule_id`, `title`,
`severity` from impact × likelihood (both low/medium/high; high×high = critical) with `severity_rationale`,
`asset` (+ `target_asset` for credentials and backups), bounded `location` (`display`; files: `root, path, member,
line, column, key`; databases: `database, engine, catalog_name, object, principal, principal_domain`; identities:
`principal, principal_domain, supplier`), `coverage_unit`, `evidence_ids`, `first_seen`/`last_seen` (snapshot
time), `provenance`, `basis` (observation/inference/unknown), `confidence` + reason, `caveats`, `ownership`,
`suggested_fix` (`action` code + text), `state`, `details`, `redacted_context`, `secret_fingerprint`,
`related_findings`. Account UPNs are split into `principal` + `principal_domain` so staff addresses are not rendered as
e-mail addresses.

**Stable fields for Module B** (listed in every report under `stable_fields`): `finding_id, control_id, rule_id,
severity, state, asset.asset_id, target_asset.asset_id, location.{type, root, path, member, database, principal,
principal_domain, object}, suggested_fix.action, secret_fingerprint, coverage_unit`. Containment joins use
`finding_id` and `asset_id` from the shared asset map — never secret values. `suggested_fix.action` codes:
`rotate-and-vault-credential, rotate-signing-key, reduce-database-role-grants, remove-or-protect-copy,
restore-auditing, disable-shell-execution, remove-cross-server-link, revoke-public-access, review-service-account,
disable-or-remove-account, assign-individual-accounts, enforce-mfa, review-supplier-access,
link-account-to-contract, enforce-password-policy`.

## Coverage, exclusions and missing evidence

Every report has, per control, separate `assessed`, `not_assessed` and `unavailable` lists (unit, location, reason)
and an overall status (`assessed`, `partially assessed`, `not assessed`, `unavailable`); exclusions (declared
patterns, symlinks rejected/not followed, special files, archive links) with counts; suppressed secret candidates by
reason; parser failures by format and exception **class** (messages can echo content and are never kept); and
missing evidence (absent exports, failed queries, uncovered observation windows, unknown MFA, truncated queries).

## Reports, states and versioning

Report bodies (`ReportStore.new_body("exposure")`) carry `method_version`, `config_sha256` (manifest + asset map +
accepted-risk register + detector configuration), the manifest SHA-256, source manifests and content hashes,
ranked findings, coverage, exclusions, missing evidence, guardrails, limitations and remediation governance;
`previous_report_sha256` comes from the chain. No wall-clock time is included, so identical inputs give a
byte-identical canonical `report.json` (tested). Attachments: `findings.csv`, `coverage.json`; plus `report.pdf`.
Throughput metrics stay in the encrypted scan metadata and the console.

States against the previous **released** version: `new`; `open` (first_seen carried); `accepted-risk` (unexpired
entry in the register: `finding_id, accepted_by, reason, expires, reference`); `mitigated` (absent now **and** the
same coverage unit — root and path, database check, identity input — assessed now: a verified delta);
`not-assessed` (absent but not re-assessed). `exposure diff` lists new / resolved (verified only when the unit was
assessed in both) / persisting / not re-assessed / severity changes; reports of different cases are refused because
ids are case-local.

## Remediation governance

The product never deletes files or revokes access. Rotate exposed credentials first, then vault them and remove
plaintext copies (including repository history and backups). Remove or protect stray copies under the
records-retention schedule after the owner confirms purpose — never while a legal hold or investigation is open.
Reduce database grants to the declared function; restore auditing with central retention; review supplier access
against the contract (MFA enforced and evidenced, scope limited, expired/inactive accounts disabled). Accepted risks
go in the register with owner, reason and expiry.

Readiness retention: `tscope exposure purge` removes working files; released reports keep findings, counts, source
fingerprints and configuration. Case closure (core) destroys the case key, making keyed fingerprints unlinkable.

## Measured performance (synthetic, 4-core shared host; no guarantee)

| Tree | Files | Input | Scan command | Files/s | MB/s | Peak RSS | Parser failures |
|---|---|---|---|---|---|---|---|
| mixed small configs/text/CSV | 20 000 | 8.1 MB | 4.4 s | ~4 500 | 1.9 | 115 MB | 0 |
| mixed small configs/text/CSV (before 50k-row default) | 50 000 | 20.3 MB | 17.3 s | ~2 900 | 1.2 | 126 MB | 0 |
| large CSV exports full of valid IDs | 5 | 16.7 MB | 4.0 s | — | 4.2 | 167 MB | 0 |

Scan time includes custody registration (SHA-256 of the declared trees). Reproduce with
`pytest -m slow -s tests/exposure/test_scale.py` (`EXPOSURE_SCALE_FILES`, `EXPOSURE_BENCH_OUT`).

## Limitations

Exposure conditions only (no access or exfiltration determination). Git packfiles, 7z/RAR, office/PDF documents
and backups are not opened. Principal types inferred from names are labelled inference — declare them. Engines
other than SQL Server and PostgreSQL are not assessed. The catalogue reflects the restored copy or export, which
may differ from production.
