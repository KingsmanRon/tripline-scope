# Ingest, discovery, extraction and the readiness data map

Operator runbook for getting hospital and laboratory data into a case: restoring SQL Server and PostgreSQL
backups, reading vendor exports and leak samples, the optional read-only live connection, column discovery,
extraction to the standard schema, and the readiness data map (`tscope map`).

Everything here follows four rules:

* **Sources are never written.** Backups, dumps and exports are read from read-only references (or decrypted as
  a stream from an encrypted copy). A process-wide guard refuses any write, rename, delete or chmod under a
  registered source, and every `ingest`, `discover` and `map` run hashes every source in full (SHA-256) before
  and after; the hashes are recorded in the audit log and the command fails if anything changed.
* **Least data.** Only columns needed for matching and contact are extracted. Clinical, card and bank columns
  contribute presence flags only; their values are never copied anywhere, not even into encrypted files.
* **Everything at rest is encrypted.** Discovery output, extracts, manifests and the restore registry are
  authenticated envelopes under the case key. DuckDB runs in memory with spilling and external access off.
* **Nothing identifying is printed or logged.** Console output and the audit log hold counts, ids and hashes;
  driver and tool messages (which can quote data) are never echoed.

## 1. Flow

```
tscope source add ...                       # chain of custody (core)
tscope ingest --case C                      # every ingestible source: restore if needed -> discover -> extract
tscope ingest --case C --source SRC-002 --tables dbo.patients dbo.results --sample-rows 20000 --batch-rows 25000
tscope ingest status --case C               # counts only
tscope discover --case C                    # discovery only (no extraction)
tscope map --case C                         # readiness data map -> draft "datamap" report
tscope release --case C --kind datamap --approver <io>
tscope ingest restores --case C             # restored databases recorded for the case
tscope ingest drop --case C --source SRC-001   # drop a restore early (closure drops the rest)
tscope case close ...                       # drops restores, destroys the key, signs a certificate
```

Source kinds handled here: `mssql_bak`, `pg_dump`, `csv`, `tsv`, `xlsx`, `jsonl`, `json`, `live_mssql`,
`live_pg`. With no `--source`, `tscope ingest` processes every registered source of those kinds.

## 2. Restore targets (installation configuration)

Restore targets live in the installation `config.yaml` (never in `case.yaml`). Passwords are **never** stored:
`password_env` names an environment variable; when it is unset the operator is prompted. Config validation
refuses keys such as `password`, `connection_string` or `dsn`.

```yaml
restore_targets:
  mssql:
    host: 10.20.0.5                   # the hospital's licensed restore / test SQL Server
    port: 1433
    login: tscope_restore             # see 2.2
    password_env: TSCOPE_MSSQL_RESTORE_PASSWORD
    backup_transfer: shared_path      # shared_path | docker_cp
    server_backup_dir: /mnt/evidence  # where the SQL Server service sees the backup files
    host_backup_dir: /srv/evidence    # shared_path: where this host sees the same files
    data_dir: /var/opt/mssql/data     # optional; default: the instance default data path
    log_dir: /var/opt/mssql/log       # optional; default: data_dir, else the instance default
    container: mssql-test             # docker_cp only
    encryption: true                  # TLS for the whole session (login and data)
    tls_cafile: /etc/tscope/mssql-ca.pem  # required with encryption: the CA that issued the server certificate
    trust_server_certificate: false   # true skips only the host-name check; the CA chain is always verified
    database_prefix: tscope_          # optional; restored name = <prefix><case>_<source>
    login_timeout_s: 15               # optional
  postgres:
    host: 127.0.0.1
    port: 5432
    login: tscope_restore             # CREATEDB, not superuser (see 3)
    password_env: TSCOPE_PG_RESTORE_PASSWORD
    bin_dir: /usr/lib/postgresql/16/bin   # pg_restore location (optional if on PATH)
    maintenance_db: postgres          # optional
    tls: false                        # optional; tls_cafile: /path/ca.pem
    database_prefix: tscope_
```

Check the configuration with `tscope ingest targets` (validation only) or, as an admin,
`tscope ingest targets --check` (connects and runs `SELECT 1`). Output shows an opaque instance reference, never
the host, login or password.

**Restored database names** are derived from the case id and source id only, e.g.
`tscope_case_2026_014_src_003` (lower case, `-` -> `_`, at most 63 characters). They never contain data. A
database of that name that is not recorded for the case is never replaced: the command stops.

**Restore registry.** Each restore is written to `work/restores.json` (encrypted) *before* any data reaches the
server (`status: restoring`), then marked `restored`. A failed restore is dropped immediately; an interrupted one
is dropped on the next run or at closure. Entries record engine, opaque instance reference, database names
(derived and original), source SHA-256, timestamps and drop verification; never hosts, logins or passwords.

### 2.1 SQL Server licensing

SQL Server **Developer Edition is licensed for development and test only.** Use it only for synthetic demos and
tests (the `docker_cp` transfer exists for those). For real cases, `.bak` files are restored to a SQL Server
instance **the hospital provides and licenses** — typically its existing restore or test server — configured as
`restore_targets.mssql` with `backup_transfer: shared_path`.

### 2.2 SQL Server restore

1. Register the `.bak` **by reference** (`tscope source add --kind mssql_bak --path /srv/evidence/LabDB.bak ...`,
   no `--copy`): the server must read the file in place. Encrypted copies are refused for `.bak` sources.
2. `shared_path`: the file must sit under `host_backup_dir`; the server reads it at the mapped path under
   `server_backup_dir`. Mount the share **read-only** for the SQL Server service account.
   `docker_cp` (demo/test): the file is copied into the container, restored, and the copy deleted at once.
3. `RESTORE HEADERONLY` (last full backup set) and `RESTORE FILELISTONLY`, then
   `RESTORE DATABASE [tscope_<case>_<src>] FROM DISK = ... WITH FILE = n, MOVE ... , RECOVERY` with every file moved
   into `data_dir`/`log_dir` under names derived from the restored database name.
4. The restored copy is set `READ_ONLY`. The original database name from the backup header is kept as
   `original_database` and reported as `database` in discovery and the extract manifest (e.g. `LabDB03`), with
   `table` = `schema.table` (e.g. `dbo.patients`).

Restore login: a dedicated login that is a member of **`dbcreator`** only (needed for `RESTORE DATABASE` and
`DROP DATABASE` of its own restores). It needs no rights in production databases. The instance must be able to
read the backup share; the product never asks for `sysadmin`.

Reading: user tables only, every column except binary types (`varbinary`, `image`, `rowversion`, spatial,
`hierarchyid`), which are recorded by name but never read. Rows are read in bounded batches in a deterministic
order: keyset pagination (`SELECT TOP (n) ... WHERE key > last ORDER BY key`) on integer primary keys, otherwise
`ORDER BY` the primary key or every orderable column with `OFFSET/FETCH`. Every query has a timeout
(`ingest.query_timeout_s`; restores `ingest.restore_timeout_s`).

## 3. PostgreSQL dumps

* Format detection by content: custom (`PGDMP`), tar, plain SQL (optionally gzip-compressed). Directory-format
  dumps: re-dump with `pg_dump -Fc`.
* A fresh database `tscope_<case>_<src>` is created from `template0`, closed to `PUBLIC`
  (`REVOKE ALL ON DATABASE`), and set `default_transaction_read_only = on` after the restore.
* **Custom / tar**: `pg_restore --no-owner --no-privileges --no-tablespaces --no-comments --no-publications
  --no-subscriptions --no-security-labels`, reading the evidence file in place (reference sources) or the
  decrypted stream on stdin (encrypted copies). The original database name is read from the archive's TOC.
* **Plain SQL**: executed in-process (pg8000), **never with `psql`**: `psql` would honour client-side
  meta-commands in the file (`\!` runs a shell, `\o`/`\copy ... to` write files). A lexer splits statements
  (quotes, `E''` strings, dollar quoting, comments, `COPY ... FROM stdin` blocks). `\restrict`/`\unrestrict`
  (pg_dump >= 16.10) and `\connect` lines are skipped; any other meta-command refuses the dump. Ownership,
  `GRANT`/`REVOKE`, `SET ROLE`/`SESSION AUTHORIZATION`, database-level and publication/subscription statements
  are skipped; `COPY` to or from a program or server file refuses the dump.
* Restore login: **`CREATEDB` only, not superuser** (`CREATE ROLE tscope_restore LOGIN CREATEDB PASSWORD ...`).
  A superuser login is refused for plain dumps and produces a warning for custom dumps, because dump content
  (functions, `COPY ... PROGRAM`) would then run with superuser rights on the server.
* Failed restore statements are counted and reported as a number; their messages (which can quote data) are
  never shown or stored.
* Reading: tables and partitioned tables (not partitions) outside system schemas, every column cast to text
  except `bytea` (never read), through a server-side cursor (`DECLARE ... NO SCROLL CURSOR` in a
  `REPEATABLE READ READ ONLY` transaction, `FETCH FORWARD n`), ordered by the primary key or every orderable
  column, with `statement_timeout` and `lock_timeout` set.

## 4. Exports: Oracle, MEDITECH, TrakCare, SAP and leak samples

These systems arrive as exports. Accepted formats: **CSV, TSV, XLSX, JSON Lines, JSON arrays**. Ask the
hospital or vendor for:

* one table per file (one worksheet per table in XLSX); a header row with the source column names;
* UTF-8 (cp1252 is detected and accepted); CSV delimiter `,` `;` `|` or tab (detected from the header);
* ID numbers, phone numbers and medical-aid numbers **as text** (Excel drops leading zeros; numeric ID columns
  are padded back to 13 digits when they are 10–12 digits long, but text is safer);
* dates as `YYYY-MM-DD` (day-first `DD/MM/YYYY`, `YYYYMMDD` and `5 Jan 1980` are also recognised per column);
* no row limit, no filtering and no masking applied by the export tool (record what was exported in the custody
  notes).

Leak samples and e-mailed exports should be registered with `--copy` (encrypted copy; decrypted as a stream at
read time, never to disk). Header-less files are detected (a first row with ID-, phone-, e-mail-, date- or
number-like values) and get positional column names `column_1..N`, so values never become column names.

JSON: nested objects are flattened with dots (`patient.id_number`, up to three levels); lists are kept as JSON
text. A JSON document may be an array of objects or an object holding one such array.

Bounds (installation `ingest:` settings, defaults in brackets): `max_bytes_per_file` [64 GiB],
`max_rows_per_table` [50 000 000], `max_field_bytes` [1 MiB], `xlsx_max_uncompressed_bytes` [2 GiB],
`xlsx_max_ratio` [200], `json_array_max_bytes` [512 MiB]. Exceeding a bound stops the command with an error
rather than silently under-counting. Rows with the wrong number of fields (and unreadable JSON lines) are
counted as malformed and reported as a number; their contents are never echoed.

## 5. Optional read-only live connection

Off by default. Use it only when no backup or export can be obtained. Requirements, all checked on every run:

1. The source is registered as `live_mssql` or `live_pg` (no path).
2. The installation names the connection (never in `case.yaml`):

   ```yaml
   live_connections:
     labsql:
       engine: mssql            # mssql | postgres
       host: 10.20.0.9
       port: 1433
       login: tscope_reader
       password_env: TSCOPE_LIVE_LABSQL_PASSWORD
   ```

3. A **case approver** enables it, naming the database (exactly one per live source) and optionally tables and a
   per-table row cap:
   `tscope ingest live-enable --case C --source SRC-004 --connection labsql --database LabDB --table dbo.patients
   --max-rows 2000000`. This writes `live_access.SRC-004` into `case.yaml` and an audit entry; a hand-edited
   `case.yaml` without the matching audit entry is refused. `tscope ingest live-disable` withdraws it.
4. The login passes the permission checks below; otherwise the run is refused before any data is read.
5. Every run prints `WARNING: LIVE read-only connection to a production database ...` on stderr and records the
   same note in the audit log.

**SQL Server — what the DBA must grant:** a login mapped to a user in the one approved database, member of
`db_datareader` (or `SELECT` on the approved tables only). **Must not grant:** any fixed server role
(`sysadmin`, `serveradmin`, `securityadmin`, `dbcreator`, `bulkadmin`, `diskadmin`, `processadmin`,
`setupadmin`), `db_owner`, `db_datawriter`, `db_ddladmin`, `db_securityadmin`, `db_accessadmin`,
`db_backupoperator`, or any `INSERT`/`UPDATE`/`DELETE`/`ALTER`/`CONTROL`/`EXECUTE`/`TAKE OWNERSHIP`/`IMPERSONATE`
right at server, database, schema or object level. Checks: `IS_SRVROLEMEMBER`, `IS_ROLEMEMBER`, and allow-lists
over `fn_my_permissions` for SERVER, DATABASE, every SCHEMA and every table, plus `EXECUTE`/`ALTER` on procedures
and functions. Session: `ApplicationIntent=ReadOnly`, `SET LOCK_TIMEOUT`, `SET DEADLOCK_PRIORITY LOW`,
`READ COMMITTED`, query timeouts.

**PostgreSQL — must grant:** `CONNECT` on the database, `USAGE` on the schemas, `SELECT` on the approved
tables. **Must not grant:** superuser, `CREATEROLE`, `CREATEDB`, `REPLICATION`, membership of
`pg_write_all_data`, `pg_write_server_files`, `pg_execute_server_program`, `pg_signal_backend`,
`pg_checkpoint`, `pg_create_subscription`, ownership of any table, sequence, schema or the database,
`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`TRIGGER` on any table, `UPDATE` on sequences, `CREATE` on any schema or on
the database. Session: started with `default_transaction_read_only=on`, `statement_timeout`, `lock_timeout`
(verified with `SHOW transaction_read_only`); reads in `READ ONLY` transactions.

Bounds: `ingest.live_max_rows_per_table` [5 000 000] unless the approver set `--max-rows`; a larger table is
refused (not truncated). `ingest.live_statement_timeout_s` [60], `ingest.live_lock_timeout_s` [5]. Only the
approved database, and the approved tables when listed, are queried.

## 6. Discovery

For each selected table: **sample** the first `--sample-rows` rows (default 10 000) in the deterministic read
order, **classify** each column, then **full-scan** every row in batches (in-memory DuckDB with the core
`tscope_*` macros) to confirm the chosen category's match rate and the null rate and to count rows exactly.

Each column gets `category, confidence, basis (hint | values | override | table), reasons, match_rate,
null_rate, sample_match_rate, sample_null_rate, purpose, exposure_category, standard_field, extracted, override`.
`match_rate` = valid values / non-empty values; `null_rate` = empty or null / all rows.

| Category | Evidence | Extracted as |
|---|---|---|
| `sa_id` | 13 digits, real YYMMDD (either century), citizenship digit 0/1/2, Luhn. Name hint + >= 10 % valid, or >= 90 % valid without a hint (confidence 0.85). Numeric columns (and hinted ones) are padded back to 13 digits. | `sa_id` (valid only) |
| `passport` | name hint (`passport`, `travel_doc`, `foreign_id`) + letters-and-digits format; passport-like values in an ID column (only when there is no passport column) | `passport_no` |
| `phone` | hint (`cell`, `mobile`, `tel`, `contact_no`, a bare `contact` decided by values), or >= 90 % SA-formatted numbers without a hint | `phone`; a second phone column -> `phone_alt` (E.164) |
| `email` | >= 80 % well-formed addresses, or hint | `email` (lower case) |
| `first_name`, `last_name`, `full_name`, `maiden_name` | name hints (`Names` beside `Surname` = first names; `middle_name` -> `middle_names`; `other_names` beside forename + family name -> `middle_names`, beside a surname only -> given names) | upper-case ASCII; `full_name` is used only without separate first/last columns and is then split (handles `SURNAME, Given`) |
| `dob`, `record_date` | name hint + date values (format chosen per column: ISO, day-first, compact, `5 Jan 1980`, month-first) | DATE |
| `sex`, `language`, `address`, `postal_code` | hints (`postal`, `zip`, `post_code`; address parts are joined in column order). Sex: `M`/`F`, `Male`/`Female`, or ISO 5218 digits behind a sex hint (1 male, 2 female, 0/9 unknown); never inferred from the ID number here | `sex` as `M`/`F`/`U`; other text normalised |
| `medical_aid_no`, `medical_aid_scheme` | hints (`med_aid_no`, `member_no`, `scheme`, ...) + format | number extracted; scheme flagged only |
| `patient_key`, `patient_ref` | hints (`patient_id`, `folder_no`, `mrn`, `pat_no`, ...) or the identity table's unique key; references are kept only when their values match a patient key of the source | `local_patient_key`, `patient_ref` |
| `guardian_*` | guardian context (`guardian`, `parent`, `mother`, `father`, `nok`, `next_of_kin`, `kin`, `caregiver`, `guarantor`) before or after a phone/contact, name, ID or e-mail word (`nok_contact`, `parent_contact`, `cell_mother`) | `guardian_*` |
| `icd10` | hint + ICD-10 pattern, or >= 90 % ICD-10 codes that repeat (diagnosis text with a hint also counts) | flag `_has_clinical_diagnosis` only |
| `test_code`, `test_result` | hints (`test_code`, `loinc`, `result`, `value` in result/lab tables) | flags only |
| `clinical_free_text` | hints (`notes`, `comments`, `history`, ...), or free text without a hint (confidence 0.5, "possibly clinical") | flag only |
| `card_number` | card prefix + Luhn + 13–19 digits on >= 80 % of values, or a card hint | flag only — **never copied** |
| `bank_account` | bank hints (`bank_acc_no`, `iban`, `branch_code`, `debit_account`); a plain `account_no` is a patient billing account unless >= 80 % of its values look like bank account numbers (then flagged, confidence 0.6) | flag only — **never copied** |
| `other_identifier`, `other` | everything else | not extracted |

Context against false positives: arbitrary 13-digit numbers, Luhn-valid numbers without context and random
16-digit numbers do not become IDs or cards; value-only rules never override a contrary name hint; names ending
in `_id`/`_no`/`_key` are keys, not clinical content. The full scan **demotes** a sample decision whose
confirmed match rate falls below the threshold (e.g. a value-only `sa_id` below 80 %); the reason is recorded.

**One column per standard field.** Columns never fill each other's gaps: the best column for a field (confidence, then a primary-looking name, then column order) takes it, a second phone column takes `phone_alt`, and any further column of the same kind keeps its category but gets `standard_field: null` with the reason `no_free_standard_field_slot_for_<field>` (it still sets exposure flags). Address parts are the one exception: they are joined into one address.

**Tables.** An *identity* table has at least two of name, date of birth, SA ID and passport. Its `patient_key`
is the hinted (or `id`/primary-key) column that is unique and non-null. Other tables' key-like columns become
`patient_ref`, and the relation to the identity table is inferred from name equality and value containment
(sample of reference values against the identity table's key set, held in memory only, capped at
`ingest.key_set_cap`). Tables with a patient reference are *dependent*; the rest are *other*.

**Overrides win.** In `case.yaml`:

```yaml
column_overrides:
  SRC-002:
    dbo.patients:            # table as schema.table, bare name or slug
      Ident: sa_id
      Remarks: clinical_free_text
      CardRef: other         # e.g. a column that only looks like card numbers
relations:
  - source: SRC-002
    table: dbo.episodes
    column: PatNo
    references: {table: dbo.patients, column: PatientNumber}
```

Unknown categories, tables or columns are refused. Output: `work/discovery/<SRC>.json` (encrypted,
`tripline.discovery/v1`, deterministic for identical input).

## 7. Extraction

Tables with at least one matching or contact field are re-read in the same order and written as encrypted
Parquet parts `work/extract/<SRC>/<slug>/part-NNNNN.parquet` (`ingest.part_rows` per part) in the **standard
schema** (PLAN §5): `_row_key` (`<SRC>|<slug>|<ordinal>`, 1-based, stable across runs), `_source_id`, `_table`,
`sa_id, passport_no, first_name, middle_names, last_name, full_name, maiden_name, dob, sex, medical_aid_no,
local_patient_key, patient_ref, phone, phone_alt, email, address, postal_code, language, guardian_name,
guardian_phone, guardian_email, guardian_sa_id, record_date` and `_has_<category>` for `identity_number, name,
date_of_birth, contact_details, address, medical_aid, clinical_diagnosis, clinical_tests, clinical_results,
clinical_notes, payment_card, bank_account`. A flag is true when the row has a non-empty value in a column of
that category (a card flag needs 12–19 digits, so masked numbers do not count).

`work/extract/<SRC>/manifest.json` lists **every** table of the source, extracted or not: `database` (original
database name), `table` (`schema.table`), `slug`, `row_count`, `role`, `extracted`, `parts` (+ ciphertext
hashes), `extracted_rows`, `fields`, `source_columns`, `flags`, `patient_key`, `patient_refs`, `relations`,
`exposure_categories`, `columns_not_extracted`. Extraction checks that each table still has the row count seen
by discovery. Consumers load parts with `tripline_scope.ingest.extract.read_extract(store, SRC, slug)`.

## 8. Readiness data map

`tscope map --case C [--source ...] [--rediscover]` uses existing discovery output (running discovery, and a
restore, where needed) and saves a **draft `datamap` report**: `report.json` (where ID numbers, names, dates of
birth, contact details, medical-aid, payment and clinical columns live, with row counts, categories, confidence
and rates — **no values**), `report.pdf`, and `attachments/datamap.csv` (one row per column). The body carries
`method_version`, `config_sha256` and the custody and discovery hashes of its inputs, and is byte-identical for
identical inputs. An approver releases it with `tscope release --kind datamap --approver <io>`; the hospital
keeps it as its exposure map.

## 9. Closure

`tscope case close` runs the `restored_databases` closure hook first: every restore recorded for the case
(including interrupted ones) is dropped (`DROP DATABASE` after `SINGLE_USER WITH ROLLBACK IMMEDIATE` on SQL
Server; `DROP DATABASE ... WITH (FORCE)` on PostgreSQL), checked absent, and listed in the signed destruction
certificate (`source_id, engine, instance_ref, database, original_database, restored_at, dropped_at,
verified_absent, transfer_copy_removed`). If any database cannot be dropped and verified, closure stops before
anything is destroyed. Keep the original `restore_targets` settings until closure.

## 10. Measured throughput

Synthetic lab data, 200 267 rows in 4 tables (patients 40 000, results ~80 000, billing 40 000, misc 40 000),
160 267 rows extracted; shared 4-core test machine with other workloads running, so figures varied between runs
(ranges shown). Discovery includes the sample read, classification and the confirming full scan; the command
wall time also includes two full SHA-256 passes over the sources. Reproduce with
`BENCH_OUT=/tmp/bench.json pytest -q -m slow tests/ingest/test_benchmark.py -s`.

| Source | Restore | Discovery | Extraction | Command wall time |
|---|---|---|---|---|
| CSV (4 files, 23 MB) | — | 7.8 s (25 800 rows/s) | 1.9–2.2 s (72 000–85 000 rows/s) | 9.8–10.1 s |
| SQL Server `.bak` (17 MB, `docker_cp`) | 1.6–3.1 s | 10.3–14.4 s (13 900–19 400 rows/s) | 5.0–8.2 s (19 600–32 300 rows/s) | 17.0–25.9 s |
| PostgreSQL custom dump | 0.5 s | 7.8 s (25 600 rows/s) | 2.5 s (63 900 rows/s) | 11.0 s |

Building the demo `.bak` (load 200 267 rows + `BACKUP ... WITH COMPRESSION` + copy out) took 11.5 s.

## 11. Demo backups

`demo/lab-breach/build_baks.py` turns a synthetic dataset (`<dir>/sources/dbNN/<table>.parquet`, as written by
`tscope synth`) into one SQL Server database `LabDBNN` per directory (tables in `dbo`, first column the primary
key when unique), backs each up to `LabDBNN.bak` in `--out` and drops the build database:

```
python demo/lab-breach/build_baks.py --synth DIR --out DIR --host 127.0.0.1 --port 14330 \
    --container mssql-test --password-env TSCOPE_DEMO_MSSQL_PASSWORD [--login sa] [--db-prefix ""]
```

Synthetic data and Developer Edition only.

Discovery is regression-tested against the five column-naming styles (A–E) of the synthetic lab estate
(`tests/ingest/test_synth_styles.py`).

## 12. Known limitations

* SQL Server TLS (`encryption: true`) always verifies the certificate chain against `tls_cafile`; there is no
  "accept any certificate" mode. Host names are matched per RFC 6125 (DNS/IP subject alternative names, left-most
  wildcard, common name only when there are no SANs). With `encryption: false` (the TDS default) the login packet is
  still TLS-protected only if the server forces encryption, so keep such connections on an isolated segment.
* Value-only name detection is not attempted (no name dictionaries): name columns need a recognisable name hint
  or an override. Bank accounts need a bank name hint.
* Tables without a primary key are ordered by every orderable column; rows that are identical in all orderable
  columns but differ in an unorderable one (e.g. `xml`) have no guaranteed relative order.
* A header-less export whose first row has only names (no numbers, dates or e-mails) is read as having a header;
  check `tscope discover` output for implausible column names and re-export with headers.
* SQL Server restores use the last full backup set in a `.bak`; differential and log chains are not applied.
* `--tables` applies to one source at a time; unselected tables are listed with row counts only (not assessed).
