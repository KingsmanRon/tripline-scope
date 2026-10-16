# Module B — Access-path analysis (incident, offline)

Module B reads logs that the hospital has exported and handed over, and reconstructs time-bounded, evidence-backed
access routes to sensitive data: `web/identity → network → host/application → database → table/data → egress`.
Each route stops where the evidence stops. Module B does not run live. It does no packet capture, endpoint access,
memory or malware forensics, threat-intelligence lookups or containment. It never establishes the initial
intrusion vector, because that needs endpoint evidence.

```
tscope paths config           --case C --file paths.yaml          # case.yaml `paths:` settings (or via logs.yaml)
tscope paths ingest           --case C --manifest logs.yaml       # custody registration + normalisation
tscope paths analyse          --case C --window START/END         # default window: the case incident window
tscope paths report           --case C [--exposure-report DIR] [--measures FILE] [--timeline-rows N]
tscope release                --case C --kind paths --approver IO # shared core release (signed, versioned)
tscope paths scope-candidates --case C --out FILE                 # bridge to Module C
python -m tripline_scope.paths.synthetic --out DIR --scenario demo|acceptance [--scale N]
```

All commands need the operator role, are audited, and print only counts, ids and hashes.

## 1. Inputs: `logs.yaml` (`tripline.logs-manifest/v1`)

```yaml
schema: tripline.logs-manifest/v1
defaults: {supplied_by: "Hospital IT", received_at: "2026-09-15T08:00:00Z",
           legal_basis: "POPIA s22 investigation instructed by the Information Officer"}
paths:                       # optional: fills case.yaml `paths:` keys the operator has not set (never overrides)
  sensitive_tables: [LabDB01.dbo.patients, "LabDB*.dbo.results", lis.public.patient_index]
sources:
  - id: labsql01-audit       # manifest-local label
    family: mssql_audit      # see section 2
    format: csv
    path: mssql/labsql01_audit.csv      # file or folder, relative to logs.yaml
    host: LABSQL01
    host_ips: [10.20.0.15]   # used to link outbound flows from the host
    asset_id: AST-LABSQL01   # shared asset map id (cross-reference to Module A)
    timezone: Africa/Johannesburg       # IANA name, fixed offset (+02:00), UTC, or unknown
    timezone_override: false            # only for formats that record UTC (see 3)
    clock_offset_s: 0        # documented host clock check: host clock minus true time (+ = fast)
    clock_uncertainty_s: 2   # omit if unknown (then reported, and an assumption is applied in correlation)
    coverage: {start: ..., end: ..., databases: [LabDB01, LabDB02],
               missing: [{start: ..., end: ..., reason: "audit file rolled over"}]}
    options: {}              # family-specific, see 2
    mapping: {}              # required for vpn/firewall/proxy/generic, see 2.7
    copy: false              # true = encrypted copy in the case instead of a read-only reference
    source_id: SRC-004       # optional: reuse an already registered source
corroborations:              # independently verifiable evidence (the only route to exfiltration_evidenced)
  - id: COR-001
    kind: independently_confirmed_external_copy   # or captured_transfer_validated_content | corroborated_forensic_artefact
    tables: [LabDB07.dbo.patients]
    path: evidence/leak_sample_index.csv          # registered as a source (role leak_sample), or evidence_ids: [SRC-009]
    establishes: "An external copy received through counsel contains records matched to LabDB07.dbo.patients."
    does_not_establish: "Route, time or other tables."
```

`paths ingest` registers each source through `core.custody`: kind `log`, evidence role `log`, or `reference_data`
for indicators. A source whose path is already registered is reused. Every file is read read-only (the write guard
is active) and its SHA-256 is recomputed while it is parsed. A mismatch with the custody hash aborts the ingest,
and a size/mtime change is caught before the command starts. Outputs, all encrypted through `CaseStore`:
`work/paths/events/<SRC>.parquet`, `work/paths/coverage/<SRC>.json` (first/last event, failures with locators,
unplaceable records, declared coverage, zone, completeness), `work/paths/sources.json`,
`work/paths/indicators/<SRC>.json` and `work/paths/corroborations.json`. Validation errors never echo field values.

## 2. Parsers (written from public format documentation)

| family | formats | notes |
|---|---|---|
| `mssql_audit` | csv, json, jsonl | rows of `sys.fn_get_audit_file` (2.1). Native `.sqlaudit` files are refused. |
| `pg_log`, `pgaudit` | csvlog, jsonlog, stderr | stderr needs `options.log_line_prefix`; pgAudit lines (2.2) |
| `iis` | w3c | `#Fields:` directive (may change mid-file); times are UTC by definition |
| `apache`, `nginx` | combined, common, custom | custom via `options.log_format` (Apache `%` or Nginx `$var`) |
| `win_security` | evtx, xml, csv | EVTX via `evtx`; XML from `wevtutil`/`Get-WinEvent`; CSV from the script in 2.4 |
| `entra_signin` | json, jsonl, csv | Graph `auditLogs/signIns` export or portal CSV |
| `vpn`, `firewall`, `proxy`, `generic` | csv, json, jsonl, kv | documented field `mapping` (2.7) |
| `indicators` | csv, json, jsonl | partner IP/CIDR/domain/hash with provenance and validity (2.8) |

**Never stored:** SQL text, URL query strings, command lines, passwords and tokens, message text, user display
names, file names. Statements are reduced to an operation, object names and a keyed fingerprint of the
literal-free normalised form (`store.fingerprinter("paths-sql")`). URL paths are stripped of query strings and
matrix parameters, and identifier-like segments are templated (`/results/{n}/pdf`, `{email}`, `{guid}`, `{hex}`,
`{token}`). File paths become `file:<ext>:<keyed fingerprint>`. AD distinguished names become `dn:<fingerprint>`.
Each record's original text, or the canonical JSON for structured records, is hashed into `raw_sha256` and then
discarded.

### 2.1 SQL Server Audit: licensed export procedure

The hospital's DBA runs the export on the hospital's own licensed SQL Server, against copies of the `.sqlaudit`
files. Tripline never parses native audit files.

```sql
SELECT CONVERT(varchar(33), event_time, 126) AS event_time, sequence_number, action_id, succeeded, session_id,
       connection_id, server_principal_name, session_server_principal_name, target_server_principal_name,
       target_database_principal_name, server_instance_name, database_name, schema_name, object_name, statement,
       client_ip, host_name, application_name, session_context, response_rows, affected_rows
FROM sys.fn_get_audit_file(N'D:\AuditCopy\*.sqlaudit', DEFAULT, DEFAULT)
WHERE event_time >= '2026-08-25' AND event_time < '2026-09-15';     -- event_time is UTC
```

Leave out columns that your version does not have. Older versions lack `client_ip`, `application_name`,
`host_name`, `connection_id`, `session_context`, `response_rows` and `affected_rows`; Module B then reports them
as unknown. Save the result with PowerShell, which quotes fields properly:
`Invoke-Sqlcmd -ServerInstance LABSQL01 -InputFile export.sql -MaxCharLength 65535 | Export-Csv -NoTypeInformation
-Encoding UTF8 labsql01_audit.csv`. Alternatively, add `FOR JSON PATH, INCLUDE_NULL_VALUES` and save the output
with `bcp ... queryout audit.json -c -T`.

The export holds statement text, which can include patient data. Hand it over on read-only media and register it
by reference.

How the export is read:

* **Action ids:** `SL`=select, `IN/UP/DL/MG`=modify, `EX`=execute, `LGIS/LGIF/LGO`=login/failure/logout,
  `BA/BAL`=backup (export), `G/GWG/APRL/ADSR`=rights granted, `AUSC`=audit state changed (the statement decides
  on/off).
* **Statements refine the action:** `BACKUP`, `bcp ... out|queryout` through `xp_cmdshell`, `sqlcmd -o`,
  `SELECT ... INTO` a permanent table and `INSERT INTO OPENROWSET(...)` count as export/staging.
  `ALTER SERVER|DATABASE AUDIT [SPECIFICATION] ... STATE = OFF` and `DROP ... AUDIT` count as auditing disabled,
  scoped to the database for database audit specifications and otherwise to the instance.
* **Rows:** taken from `response_rows` (or `affected_rows` for DML) only when they are present. Otherwise the volume
  is unknown.
* **Sessions:** the session id is `conn:<connection_id>` when available, otherwise `spid:<session_id>`. A spid is
  split into separate sessions at each login, at logout, and after 30 minutes of silence.
* **Request id:** taken from `session_context` by `options.request_id_regex` (default `request_id=<id>`).

### 2.2 PostgreSQL

* Set `log_line_prefix` in `options` exactly as it is in `postgresql.conf`. The supported escapes are `%a %u %d %r
  %h %b %p %P %t %m %n %i %e %c %l %s %v %x %Q %q %%`, with padding such as `%-10u`.
* Zone abbreviations: built in are `UTC`, `GMT` and `SAST`. Others need `options.tz_abbreviations:
  {CAT: "+02:00"}`. An unknown abbreviation is never guessed.
* If the prefix has no `%c`, sessions are tracked by pid between `connection received` and `disconnection` lines,
  in log order (flag `session_from_pid_tracking`).
* Recognised messages: connection received/authorized (including replication), disconnection, password
  failures, `statement:`, `execute <name>:`, `duration: ... statement:`, `parameter "pgaudit.log"|"log_statement"
  changed to "none"` (auditing disabled), and pgAudit lines.
* pgAudit lines (`AUDIT: <type>,<stmt>,<sub>,<CLASS>,<COMMAND>,<OBJECT_TYPE>,<OBJECT_NAME>,[<ROWS>,]<STATEMENT>,
  <PARAMETER>`): set `options.pgaudit_log_rows: true` when `pgaudit.log_rows` is on, and check the field order
  against your pgAudit version. `READ` becomes select, `WRITE` modify, `ROLE` rights granted. `COPY ... TO` and
  `pg_dump`/`pg_basebackup` sessions count as export.

### 2.3 Web servers

* **IIS W3C:** `cs-uri-query` is dropped unread. The request id comes from `options.request_id_field` or any
  `X-Request-ID`-like field. `options.client_ip_field` can name an XFF field, but XFF is supplied by the client,
  so treat it as client-controlled.
* **Apache/Nginx:** the time carries its own offset. User agents and referrers are never stored.

### 2.4 Windows Security

* **EVTX:** read with `evtx` (MIT). Chunk and record CRC32 checksums are validated by default, and damaged chunks
  are counted as parse failures. Set `options.validate_checksums: false` to recover records from dirty chunks; this
  is noted in the coverage record. Native EVTX support is demonstrated by a fixture: a test-only writer, built from
  the published layout, produces files that `evtx` reads with checksum validation, and the parser yields the same
  normalised events as the XML export of those events.
* **XML:** `wevtutil qe Security /q:"*[System[TimeCreated[@SystemTime>='2026-08-25T00:00:00Z']]]" /f:xml /e:Events
  > dc01_security.xml`. XML that declares a DTD or entities is refused.
* **CSV** (documented export; run as an administrator on the host, or on the WEF collector):

```powershell
$cols = 'TimeCreated','EventID','Computer','RecordId','SubjectUserName','SubjectDomainName','SubjectLogonId',
        'TargetUserName','TargetDomainName','TargetLogonId','LogonType','IpAddress','WorkstationName',
        'AuthenticationPackageName','ProcessName','NewProcessName','ObjectType','ObjectName','AccessMask',
        'MemberName','TargetServerName','ShareName','AuditPolicyChanges','Status'
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime='2026-08-25'; EndTime='2026-09-15'} | ForEach-Object {
  $x = [xml]$_.ToXml(); $r = [ordered]@{}; foreach ($c in $cols) { $r[$c] = '' }
  $r.TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); $r.EventID = $_.Id
  $r.Computer = $_.MachineName; $r.RecordId = $_.RecordId
  foreach ($d in $x.Event.EventData.Data) { if ($cols -contains $d.Name) { $r[$d.Name] = $d.'#text' } }
  [pscustomobject]$r } | Export-Csv -NoTypeInformation -Encoding UTF8 labsql01_security.csv
```

The script never exports `CommandLine`. If another export includes it, the parser ignores it.

Mapped event ids:

| events | meaning |
|---|---|
| 4624, 4625 | logon success/failure |
| 4634, 4647 | logoff |
| 4648 | explicit credentials |
| 4672 | special privileges |
| 4688 | process start (executable name only) |
| 4663 | object access; writes to staging extensions become `file_staged` |
| 5140, 5145 | share access |
| 4720/4722/4724/4725/4726/4738 | account changes |
| 4728/4732/4756 | member added to a group (rights granted) |
| 4729/4733/4757 | member removed from a group |
| 4719 | audit policy changed; removals count as auditing disabled |
| 1100 | event logging stopped |
| 1102 | security log cleared |
| 4768/4769/4771/4776 | domain authentication (the AD logon events) |

Logon ids are normalised as lowercase hex. Within one host, events with the same logon id form one logon session.
System ids (`0x3e7`, `0x3e4`, `0x3e5`) are never grouped.

### 2.5 Entra ID sign-ins

* **JSON:** Graph `auditLogs/signIns`: `{"value":[...]}`, a list, or JSON Lines.
* **CSV:** the portal download. A `Date (UTC)` header makes naive times UTC.
* **Fields:** request id, correlation id, session id (when exported), UPN, application, IP, location, status/error
  code. Display names are never read.
* **MFA:** `true` only when the export shows MFA was satisfied (`mfaDetail`, a succeeded secondary step, a result
  like "MFA requirement satisfied", or a successful multi-factor requirement). `false` only for an explicit
  single-factor requirement. Anything else is `unknown`.

### 2.6 AD/VPN/firewall/proxy

AD logon events arrive through `win_security` from the domain controllers. VPN, firewall and proxy logs use a
documented mapping. The shipped example below is a VPN CSV in local time:

```yaml
- id: vpn
  family: vpn
  format: csv
  path: network/vpn_sessions.csv
  timezone: Africa/Johannesburg
  mapping:
    timestamp_format: "%Y-%m-%d %H:%M:%S"
    fields: {ts: time, operation: event, account: user, session_id: session, remote_ip: public_ip,
             assigned_ip: tunnel_ip, request_id: auth_ref, bytes: bytes_in, bytes_received: bytes_out}
    operation_map: {session-start: vpn_connect, session-end: vpn_disconnect}
```

The firewall example (epoch seconds, a documented clock offset of +95 s) maps `ts: epoch`, `remote_ip: src_ip`,
`dest_ip: dst_ip`, `dest_port`, `bytes: bytes_sent` and `outcome: action`. For flows and proxies, `bytes` means
bytes leaving the hospital side.

### 2.7 Generic mappings

| key | meaning |
|---|---|
| `fields` | event column ← source field. Dotted paths are allowed for JSON, and only these fields are read. |
| `timestamp_format` | `iso8601` \| `epoch_s` \| `epoch_ms` \| `clf` \| a strptime pattern |
| `csv` | `{delimiter, header, columns}` |
| `operation_map` / `observation_map` / `outcome_map` | value translations |
| `constants` | fixed values |
| `url` | split into domain and path; the query is dropped |

A target outside the event schema is refused (for example `password`).

### 2.8 Indicators

Columns: `type` (ip, cidr, domain, sha256, sha1, md5), `value`, `provenance` (required), `valid_from`, `valid_to`
(ISO with zone; a missing bound is recorded as `open_validity`), and optional `reference`, `confidence`,
`description`.

Indicators with no provenance, an invalid value or an inverted validity range are rejected and counted. Matches are
only reported inside the validity range, or as `time_unresolved`. Every match says: *"indicator match … not
attribution"*. No outbound lookups are made.

## 3. Common event schema and time normalisation

The PLAN §7 columns are `event_id` (`<SRC>:<ordinal>`), `source_id`, `source_family`, `ordinal`,
`ts_original_text`, `tz_original`, `ts_utc`, `clock_offset_s`, `ts_uncertainty_s`, `time_precision`, `host`,
`account`, `application`, `session_id`, `request_id`, `logon_id`, `remote_ip`, `operation`, `observation_type`,
`database`, `object_name`, `rows`, `bytes`, `outcome`, `mfa`, `url_path`, `http_status`, `parser`, `raw_sha256` and
`consequence_class`.

Additive columns: `record_locator` (`file:line` / `file#record`), `tz_basis`, `ts_utc_min`/`ts_utc_max`
(supported bounds), `objects` (all `db.schema.table` named), `event_code`, `client_host`, `correlation_id`,
`dest_ip`, `dest_port`, `assigned_ip`, `domain`, `method`, `bytes_received`, `target_account`, `location`,
`statement_fp`, `file_hash` and `flags`.

A record's zone comes from the first source that applies:

1. **record:** an offset, `Z` or a recognised abbreviation in the text;
2. **manifest:** the operator-declared zone;
3. **format:** the format documents UTC (SQL Server `event_time`, IIS W3C). Here a declared non-UTC zone is ignored,
   with a note, unless `timezone_override: true`;
4. **unknown:** `ts_utc = null` and `tz_original = "unknown"`. The bounds cover every offset (UTC−12…UTC+14), so the
   record is "possibly in window", and the source is reported as a `time_zone_unknown` gap.

The documented clock offset is subtracted, and the clock uncertainty widens `ts_utc_min`/`ts_utc_max` together
with the precision (millisecond/second/minute/day). Ambiguous local times at DST changes keep both instants (flag
`dst_ambiguous`). If a source's uncertainty is undocumented it stays `null`, and correlation applies
`correlation.unknown_clock_uncertainty_s` (default 120 s), stating that it did so. Original record order is kept
in `ordinal`.

## 4. Correlation, confidence and paths

**Units.** A unit is one of:

* a database session, split on login, logout or 30 minutes of silence; rows with no session id stay single units
  (`no_session_id`);
* a Windows logon session (same host and logon id);
* a VPN session (same session id; lease from connect to disconnect);
* a single sign-in, an interesting web request (admin/upload patterns, a script resource first seen in the window,
  a request id shared with a database session or another web log, or an indicator address), an outbound flow
  linked after staging, or a staged file.

**Direct edges** (confidence 0.95, basis observation) join exactly one shared identifier:

| from → to | shared identifier |
|---|---|
| sign-in → VPN | Entra request or correlation id carried by the VPN (`auth_ref`) |
| gateway → backend web | forwarded request id |
| web request → database session | request id recorded in the session context |
| VPN → flow | VPN session id, when a flow log carries it |

**Correlated edges** (basis inference, capped at 0.8, always below direct) apply only inside configured windows.
Each records its window, the observed gap and its reason.

| join | default window | base confidence |
|---|---|---|
| sign-in → VPN, same account (only when the VPN has no direct sign-in link) | `signin_to_vpn_s` 300 s | 0.6 (+0.1 same unshared address) |
| VPN lease → database/Windows/web session from the assigned address | lease ± `vpn_lease_tolerance_s` 60 s + clock uncertainty | 0.75; −0.1 if the disconnect was not logged (lease assumed ≤ 24 h) |
| external web request → VPN from the same public address | `web_to_vpn_s` 3600 s | 0.45 |
| Windows network logon on the database host from the client address → database session | `host_logon_to_db_s` 900 s | 0.6 |
| export command → file with a staging extension on the same host | `staging_link_s` 600 s | 0.6 |
| export/staging → outbound flow ≥ `egress_min_bytes` (1 MB) from the host or client, or to an indicator | `data_to_egress_s` 21600 s | 0.5 (+0.1 indicator) |

Modifiers to correlated confidence:

* **Shared address** (×0.5, flag `shared_ip`): declared in `shared_ips`, or seen with ≥ 2 distinct accounts in the
  window. A shared address never merges different users into one actor.
* **Ambiguous** (flag `ambiguous:k`): divided by k, or √k for egress.
* **Undocumented clock uncertainty:** −0.05.
* **Account names differ:** ×0.5.
* Account names are compared with the NetBIOS prefix removed, and with the UPN suffix removed only for the
  configured `directory_domains`.

**Paths.** A path is a database route: server, account, client address/host and application. It contains its
sessions, the upstream units reachable over edges, any linked staging and the egress flows.

* Stages: `web_identity`, `network`, `host_application`, `database`, `staging` and `egress`. Each is labelled
  `direct`, `correlated`, `observed` or `unresolved`, with a reason that says whether a log was missing or a log
  was present but had no match.
* `confidence` is the confidence in the logged access itself. `chain_confidence` is that of the weakest resolved
  stage, with a justification.
* Each path also reports its earliest and latest supported times (clock bounds included).
* Paths are ranked by consequence, egress, staging, sensitive tables, non-service account and anomaly severity.

## 5. Evidence of access versus evidence of theft

| class | assigned when |
|---|---|
| `access_observed` | SELECT, DML, EXECUTE or bulk import that touched objects and succeeded. Failed attempts and statements without objects are `not_applicable`. |
| `export_or_staging_observed` | BACKUP, bcp/sqlcmd export, `COPY … TO`, `pg_dump`, `SELECT … INTO` a permanent table, export to file, or a file with a staging extension written (4663). |
| `egress_suspected` | a correlated outbound flow, proxy upload or indicator match after export/staging of that table. Nothing more, whatever the byte count. |
| `exfiltration_evidenced` | only for tables named by a qualifying corroboration that cites a registered evidence source. The claim states what it establishes and what it does not. Logs alone never produce this class, and paths are never promoted. |
| `undetermined` | auditing disabled, cleared logs, or uncovered periods. |

Context events such as sign-ins, logons, flows and privilege changes carry `consequence_class = not_applicable`:
they make no claim about data.

Per table, the class is the strongest supported one. Table windows are:

* `confirmed`: clusters of logged access;
* `possible`: the time is unresolved, so the window spans the bounds;
* `not_assessable`: no covering audit source, a declared gap, auditing disabled, or a silence.

A table whose database was covered and which had no logged access is `none_observed`, with status
`no_access_observed`. It stays in the upper scenario.

## 6. Anomaly detectors

Each detector reports its status, assumptions, baseline and false-positive caveats. Findings are leads, not
conclusions.

* **first_seen_sensitive_access:** no access to that table by that account in the baseline. Only applied to
  sources with at least `baseline.min_days` of coverage.
* **bulk_read:** rows returned per SELECT above `max(min_rows, factor × p95)` of the table's baseline. Only where
  rows are logged; otherwise counted as volume unknown.
* **off_hours:** outside `hospital_hours`. Service accounts are exempt.
* **dump_export:** any export or staging. `known_jobs` are marked and given low severity.
* **privilege_grant:** rights granted, role/group membership added, accounts created or changed.
* **auditing_disabled:** audit switched off, logging stopped, or a security log cleared.
* **new_source_location:** sign-in country, VPN public /16 or database client/application not seen for the account
  in the baseline.
* **web_admin_before_db:** admin/upload requests or a never-before-seen script resource, with any database access
  they reach over edges.

The baseline defaults to the covered period before the analysis window, or `baseline.start`/`end`.

## 7. Gaps

Reported gaps (all `undetermined`):

* no log sources at all, or no source of a family (database audit, VPN, egress, sign-in, Windows, web);
* coverage undeclared, or not covering the window;
* declared missing periods;
* records with an unknown zone;
* parse failures;
* possible missing periods: a source silent for more than `max(silence_gap_s, 10 × typical interval)`. This is only
  checked for sources with ≥ 50 events a day, and is an inference;
* auditing disabled, from the off event to the matching on event (or open-ended), scoped to a database, host or
  session;
* security log cleared, with unknown extent.

Gaps are never filled. They make tables `not_assessable` and are listed as missing evidence for the regulator.

## 8. Report, containment and the bridge to Module C

**Report.** The `paths` report body holds:

* method version, `config_sha256` and `analysis_sha256`;
* sources with file hashes and custody manifest hashes, corroborations, indicators accepted/rejected, and
  coverage;
* the classification summary, per-table outcomes and windows;
* ranked paths (top `max_paths_detailed`, default 50) with stages, tables and egress;
* edge summary, anomalies with detector metadata, indicator matches, shared addresses and gaps;
* containment and regulator fields;
* timeline metadata, forensic hand-off and limitations.

The three counts are kept separate:

* `observed_access`: tables, plus rows as logged (not records);
* `possible_exposure`: every sensitive table;
* `confirmed_exfiltration`: tables only with a qualifying corroboration, else `not determinable`.

Records and people are `not determinable` here. Person counts come from Module C.

The PDF is rendered from the same body, so JSON, PDF and regulator fields always state the same classification.
The attachments are `timeline.csv` and `timeline.jsonl`. They are bounded by `timeline_max_rows` (default 50,000)
or `--timeline-rows`; incident evidence is kept first, then the rest chronologically. They contain account
references and labels, never SQL text, query strings or messages. Output guards refuse identifier-like values in
the body, the PDF and the attachments.

**Account display.** Every account has a case-keyed `ACCT-…` reference. `DOMAIN\user` and plain logins are named.
UPNs in `directory_domains` are shown as `user (domain account)`. Every other e-mail-shaped account, for example a
patient-portal login, is pseudonymised.

**Containment** is advisory and ranked by urgency, then confidence, then evidence. Categories are accounts to
review/disable, credentials to rotate, addresses to investigate/block (shared addresses carry a warning) and access
paths to close (VPN→database routes, `xp_cmdshell`, web admin/upload exposure, audit-configuration protection).
Each recommendation cites its evidence, path and anomaly ids, sets `requires_hospital_authorisation: true` and
`executed: false`, and is cross-referenced to Module A (`--exposure-report`) by `finding_id`/`asset_id` and
`location.principal`. Nothing is executed.

**Regulator fields:**

* observed access by table;
* known actors: logged accounts, explicitly *not proof of the person*;
* unknown actors: unauthenticated web activity, routes without upstream evidence;
* affected systems with asset ids;
* measures taken (operator text from `--measures` or `paths.measures_taken`, else "not supplied by the hospital");
* missing evidence;
* a note that the Information Officer and counsel decide notification, and that the absence of proven exfiltration
  does not remove obligations.

**scope-candidates** (`tripline.scope-candidates/v1`, written to `--out` and to the encrypted
`work/paths/scope_candidates.json`):

```json
{"schema": "tripline.scope-candidates/v1", "case_id": "...", "method_version": "paths/0.1.0",
 "generated_from": {"analysis_sha256": "...", "config_sha256": "...", "window": {"start": "...", "end": "..."},
                    "sources": ["SRC-001", "..."]},
 "coverage_status": "assessed|partial|not_assessable", "coverage_statement": "...",
 "exclusion_policy": "Uncertain or absent logs never exclude potentially exposed people ...", "operator_may_widen": true,
 "tables": [{"table": "LabDB03.dbo.patients", "database": "LabDB03", "sensitive": true, "declared": true,
             "window_class": "confirmed|possible|not_assessable|none_observed", "window_classes": ["..."],
             "status": "assessed|no_access_observed|not_assessable", "consequence_class": "egress_suspected",
             "basis": "observation",
             "windows": [{"class": "confirmed", "start": "...", "end": "...", "basis": "observation",
                          "consequence_class": "...", "accounts": [{"account_ref": "ACCT-...", "label": "LAB\\x"}],
                          "sessions": ["U:SRC-001:123"], "session_count": 1, "evidence_ids": ["SRC-001:124"],
                          "paths": ["PATH-..."], "rows_logged": 15022, "volume_unknown": false,
                          "time_uncertainty_s": 2.0},
                         {"class": "not_assessable", "start": "...", "end": "...", "basis": "observation",
                          "consequence_class": "undetermined", "reason": "auditing disabled"}],
             "accounts": [], "paths": [], "corroborations": [], "covering_sources": ["SRC-001"],
             "evidence_ids": [], "confidence": 0.9, "confidence_reason": "...", "limitations": ["..."]}],
 "coverage_gaps": [{"gap_id": "...", "kind": "auditing_disabled", "scope": "database", "source_id": "SRC-002",
                    "host": "labsql02", "database": "LabDB09", "start": "...", "end": "...", "basis": "observation",
                    "description": "..."}],
 "scenarios": {"lower": {"description": "...", "tables": [{"table": "...", "windows": [{"start": "...", "end": "..."}]}]},
               "upper": {"description": "...", "tables": [{"table": "...", "windows": [{"start": "...", "end": "..."}],
                                                           "window_class": "..."}]}},
 "counts": {"tables_confirmed": 22, "tables_possible": 0, "tables_not_assessable": 4, "tables_none_observed": 16},
 "statement": "..."}
```

With no Module B inputs (no analysis), the document is `coverage_status: not_assessable`. Every declared sensitive
table is `not_assessable`, the upper scenario has `all_tables: true` and the lower scenario is empty. Module C
records and signs every decision to constrain or widen.

## 9. Configuration (`case.yaml` → `paths:`)

`sensitive_tables` (patterns allowed), `directory_domains`, `internal_networks` (RFC 1918 etc. by default),
`shared_ips`, `correlation.*` (section 4), `hospital_hours` (`timezone`, `weekdays`, `saturday`, `sunday` as
`HH:MM-HH:MM`), `service_accounts`, `known_jobs`, `baseline`, `bulk_read`, `web_admin_patterns`,
`web_script_extensions`, `staging_extensions`, `egress_min_bytes`, `silence_gap_s`, `timeline_max_rows`,
`max_paths_detailed` and `measures_taken`.

The merged configuration is hashed into every output. `paths report` refuses to run if the configuration has
changed since `paths analyse`. Changing `staging_extensions` needs a re-ingest.

## 10. Forensic hand-off

Every event id is `<source id>:<ordinal>`. `record_locator` gives the original file and line or record number, and
`raw_sha256` the hash of the original record. Investigators can therefore find the exact record in the hospital's
own copy of the log with its own tools.

Module B does not cover:

* endpoint, memory, malware or disk forensics;
* the content of network transfers (there is no packet capture);
* the initial intrusion vector;
* whether the person behind an account is the account holder.

Hand these to the hospital's forensic provider, together with the timeline attachment and the containment list.

## 11. Synthetic incident, tests and measurements

`tripline_scope.paths.synthetic` writes every log family and `ground_truth.json` on the lab estate. The estate is
LABSQL01 (LabDB01–05) and LABSQL02 (LabDB06–10), each database with `dbo.patients`, `dbo.admissions`,
`dbo.billing` and `dbo.results`, plus the PostgreSQL `lis` database, IIS behind Nginx, DC01, VPN, firewall, proxy,
a log with an unknown zone, and partner indicators.

**Scenarios.**

* `demo`: LabDB03 and LabDB07 `patients`/`admissions` are read and exported, then outbound flows of unknown content
  follow (`egress_suspected`). LabDB07 `results` is read only. LabDB09 database auditing is switched off
  (`not_assessable`). There is no corroboration, so nothing is `exfiltration_evidenced`.
* `acceptance`: `demo` plus a corroborated external copy of LabDB07 `patients`.

`logs.yaml` declares `paths.sensitive_tables` for all 40 LabDB tables and the two `lis` tables.

**The five access-versus-theft fixtures:**

| fixture | table | expected class |
|---|---|---|
| (i) ordinary SELECT | LabDB01 results | `access_observed` |
| (ii) local bcp export, no egress | LabDB05 billing | `export_or_staging_observed` |
| (iii) export, then outbound flow of unknown payload | LabDB03 patients/admissions | `egress_suspected` |
| (iv) corroborated external copy | LabDB07 patients | `exfiltration_evidenced` |
| (v) auditing disabled | LabDB09 | `undetermined` / `not_assessable` |

**Hard cases:**

* mixed zones: UTC, +02:00, SAST, local VPN time, epoch, and an unknown zone;
* a +95 s firewall clock offset;
* NAT addresses shared by many users;
* SQL rows without session ids;
* MFA unknown;
* a database session with no upstream evidence;
* nightly harmless bulk imports;
* a declared firewall gap.

Tests (`tests/paths`, 37 tests) check against `ground_truth.json`:

* every expected direct edge is recovered;
* every expected temporal link is present but labelled correlated, with confidence below direct;
* expected-absent links are absent;
* gaps are reported;
* table and window classes match;
* JSON, PDF and regulator outputs agree;
* outputs contain no identifiers, statements or query strings;
* containment is advisory;
* scope-candidates are conservative, including with no inputs;
* EVTX equals the XML export;
* tampering is detected during ingest;
* the pipeline runs with networking disabled. The suite also passes inside `unshare -n` (no network namespace).

**Scale.** `python tests/paths/bench_paths.py --events N --work DIR` prints measured ingest throughput, per-phase
peak RSS, encrypted disk use, file counts and parser failures. The table below gives measured values; they are not
guarantees.

| run (4 vCPU shared, Python 3.12) | events | ingest | ev/s | ingest peak RSS | analyse | report | work disk |
|---|---|---|---|---|---|---|---|
| 100k | 99,343 | 8.2 s | ≈12,000 | 164 MB | 10.0 s | 12.9 s | 26 MB / 33 files |
| 1M | 988,010 (219 MB of logs, 37 files) | 73 s | ≈13,500 | 993 MB | 364 s (peak RSS 4.1 GB) | 46 s | 496 MB / 33 files |

Both runs had 0 parser failures; scope-candidates took 28 s at 1M. The 1M analysis is dominated by the
≈750,000 edges of routine application traffic (portal request ids, service logons), all of which are kept in
`analysis.json`. Summarising routine routes' edges is the next optimisation if hospitals bring larger volumes.

## 12. Licensing (EVTX parser)

`evtx` 0.13.1 (PyPI wheel, Rust extension) is licensed MIT; its wheel metadata classifier says MIT. The wheel's
bundled CycloneDX SBOM (`evtx-0.13.1.dist-info/sboms/evtx_py.cyclonedx.json`) declares `MIT OR Apache-2.0` for
`evtx_py` and lists 212 crates.

| licence expression | crates |
|---|---|
| `MIT OR Apache-2.0` | 126 |
| `MIT` | 28 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 15 |
| `Apache-2.0 OR MIT` | 12 |
| `Unlicense OR MIT` | 9 (memchr, byteorder, jiff…); MIT can be elected |
| `CC0-1.0` | 7: the `encoding-index-*` tables; 1 is excluded from the build |
| `Apache-2.0` | 4 |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 (r-efi); MIT can be elected |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 |
| `Zlib` | 1 (foldhash; excluded scope) |
| `BSD-2-Clause` | 1 (numpy bindings) |
| `Apache-2.0 WITH LLVM-exception` | 1 (target-lexicon; excluded scope) |
| `Zlib OR Apache-2.0 OR MIT` | 1 (tinyvec) |
| `MIT OR Apache-2.0 OR Zlib` | 1 (tinyvec_macros) |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 (unicode-ident) |
| `(MIT OR Apache-2.0) AND Unicode-DFS-2016` | 1 (unicode_names2) |

Items outside the MIT/BSD/Apache-2.0/ISC/PSF allow-list need a packaging decision:

* CC0-1.0, public-domain data tables (`encoding-index-*`);
* Unicode-3.0 / Unicode-DFS-2016, data licences that are conjunctive with MIT/Apache;
* Zlib (excluded crates only).

All three are permissive. The packaging track's manifest check should record them.
