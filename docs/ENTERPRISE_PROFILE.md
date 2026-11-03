# Enterprise profile

The enterprise profile extends Tripline Scope from hospital breach scoping to investigations of privileged access to
enterprise financial systems. It is aimed at large utilities, state-owned enterprises, financial institutions and the
digital-forensics firms that work for them. It reuses Tripline's core unchanged:
- case, custody and encryption (AES-256-GCM);
- roles and approval gates;
- signed, hash-chained reports (Ed25519) and offline verification;
- audit, closure and legal hold.

> **Synthetic proof only.** Everything in this release has been demonstrated on fictional, synthetic data (see
> [ENTERPRISE_FINANCIAL_INCIDENT.md](ENTERPRISE_FINANCIAL_INCIDENT.md)). It has **not** been validated against any
> customer's production systems, exports or volumes. See [ENTERPRISE_LIMITATIONS.md](ENTERPRISE_LIMITATIONS.md).

## 1. Architecture

```
TRIPLINE CORE  (case · custody · CaseStore encryption · roles · audit · ReportStore + tscope-verify · closure)
    |
    +-- Healthcare profile (default; unchanged)
    |     Module A exposure (A1–A5) · Module B access paths · Module C patient scoping · POPIA notification support
    |
    +-- Enterprise profile (this release)
    |     Module A exposure: A1–A5 plus E1–E5 for financial systems
    |     Module B access paths: same engine, plus fin_app_audit / bank_settlement families
    |     Financial investigation (enterprise/): privileged-access correlation + transaction evidence → "financial" report
    |     Investigator: same safeguards, plus financial claim rules
    |     Workbench: "Financial activity" section instead of People
    |
    +-- Energy profile (future; not implemented)
          corporate IT security · approved OT evidence analysis (read-only exports) · utility configuration assessment
```

**The profile switch.** The profile is a case attribute: `tscope case init --profile enterprise`, which writes
`profile: enterprise` into `case.yaml`. Without it a case is `healthcare`, and `case.yaml`, the reports and the
workbench are exactly as before this release.

Nothing in the enterprise profile is a second engine:
- it adds no new cryptographic code;
- it creates no new application;
- it uses no network.

Internal names are neutral: `enterprise`, `financial`, `fin_app_audit`, `bank_settlement`, `transactions`. Nothing in
the code names, or is configured for, any real organisation.

### Data flow

```
estate exports (read-only) ──► tscope exposure scan (A1–A5, E1–E5) ──► release "exposure"
log & audit exports ────────► tscope paths ingest/analyse/report ─────► release "paths"
   win_security · entra_signin · vpn · mssql_audit · fin_app_audit · bank_settlement
                                     │ (normalised, encrypted events; custody hashes)
financial.yaml ─────────────► tscope financial analyse ──► tscope financial report ──► release "financial"
                                     │ reads: Module B encrypted events + released, verified "paths" (and "exposure")
released exposure/paths/financial ─► tscope investigator analyse (fixture or local) ─► review ─► release "investigation"
released reports ──────────► tscope dashboard serve (loopback, read-only, integrity gate)
every released report ─────► tscope-verify chain (offline, stand-alone)
```

## 2. Components

| Component | Where | What it does |
|---|---|---|
| Case profile | `core/case.py` (`PROFILES`), `tscope case init --profile` | selects the enterprise report set, investigator kinds and workbench sections |
| E1–E5 | `exposure/enterprise.py` | financial-system controls; evaluated only when the exposure manifest declares `enterprise:` |
| Financial audit adapter | `paths/parsers/finapp.py` | validating parser for `fin_app_audit` and `bank_settlement` exports (§3 of the incident doc) |
| Additive event columns | `paths/schema.py` | `txn_ref, approval_ref, evidence_ref, amount_minor, currency, counterparty_ref` (encrypted work data; never in the paths timeline) |
| Financial investigation | `enterprise/financial.py` | sessions, links, privilege events, suspicion reasons, gaps, impact |
| Transaction evidence | `enterprise/transactions.py` | per-transaction state machine and evidence categories; counts and per-currency totals |
| `financial` report | `enterprise/report.py`, `tscope financial report` | signed and released like every report; verified by `tscope-verify` |
| Investigator | `investigator/bundle.py`, `validate.py`, `fixture.py` | enterprise bundle (`FSN- TXN- PEV- FGP- FREC-`, `FACT-F-*`); financial claim rules |
| Workbench | `dashboard/data.py`, `page.py`, `app.py` | `/api/financial`, profile-aware navigation, integrity gate |
| Synthetic utility | `enterprise/synthetic.py`, `demo/enterprise-financial-incident/` | three fictional scenarios with ground truth |

## 3. Supported evidence sources

| Family | Format | Used for |
|---|---|---|
| `win_security` | EVTX/XML/CSV export | logons (4624), special privileges (4672), group membership added (4728/4732/4756), process start (4688) |
| `entra_signin` | Graph JSON or portal CSV | sign-ins, MFA evidence, correlation and request ids |
| `vpn` | CSV/JSON/kv with a documented mapping | remote-access sessions, `auth_ref` → sign-in request id |
| `mssql_audit` | `fn_get_audit_file` CSV/JSON | database sessions and table access (Module B paths) |
| `fin_app_audit` | CSV/JSON/JSONL, documented field set | financial-application actions, sessions, transactions, application role changes |
| `bank_settlement` | CSV/JSON/JSONL, documented field set | independent settlement records (bank statement) |
| Module A inputs | CSV/JSON | entitlements, approved role mappings, operational requirements, data inventory, audit coverage, supplier access windows |

Every input is registered with custody (SHA-256, size, supplier, legal basis), and is read, never written:
- the write guard blocks writes to source paths;
- source fingerprints are checked before and after each command;
- network calls are blocked during scans.

## 4. Required permissions

- **Tripline roles.** An **operator** runs the scans and analyses. A **reviewer** reviews investigator items. An
  **approver** releases reports, and cannot be the operator of the same case. An **admin** manages accounts only.
- **Customer side.** Read-only *exports* are needed: security event logs, identity-provider sign-in exports, VPN
  logs, SQL Server audit files, a financial-application audit export, a bank-statement export, and the entitlement
  and register files listed above.
- **No live access.** Tripline needs no credentials for any production system and makes no connection to one. The
  existing optional `live_metadata` database mode is not used by the enterprise profile.

## 5. Evidence classification rules

Separate claims are kept separate:

1. Credential or privilege **exposure** (Module A) is potential exposure. It is not account compromise.
2. **Account activity** shows that the account acted, not who operated it.
3. **Suspicious activity** is not fraud.
4. A payment **request or approval** is not money movement.
5. **Settlement.** A transaction is `settled_corroborated` only when **an independent settlement record**
   (`bank_settlement`, from a different custody source than the application) carries the same transaction reference,
   the identical amount in minor units, the same currency and a `settled` outcome. The application's own
   "settlement confirmed" status never suffices; it is reported as `settlement_claimed_without_independent_evidence`.
6. Missing, interrupted or unsupplied logs make outcomes **undetermined**; they never show that nothing happened.

### Links in the access chain

Each financial-application session (`FSN-`) carries labels for identity, remote access, host logon and privilege:

| Label | Meaning |
|---|---|
| `observed` | Recorded by the system concerned: the session itself, a privilege event. |
| `direct` | Both records carry the same identifier. The application's `idp_correlation_id` equals a sign-in correlation id, or the VPN `auth_ref` equals the sign-in request id. |
| `correlated` | Same account inside a configured window (`financial.yaml` `correlation`). This is an inference, and it is never upgraded to `direct`. |
| `unresolved` / `none_observed` | No qualifying record; the reason is given. |

**Suspicion reasons** are documented and deterministic. Each one names its evidence.

| Reason | Condition |
|---|---|
| `supplier_outside_window` | A declared supplier account is active outside its declared access window. |
| `privilege_granted_before_session` | A grant to a privileged group or application role was made before or during the session, to an account that is not an approved privileged account. |
| `signin_without_mfa` | The linked sign-in has no MFA evidence. |
| `external_signin` | The linked sign-in came from an address outside RFC 1918 / RFC 4193 space. |
| `module_b_anomaly` | Module B flagged the account in the released paths report. |

A transaction is **suspicious** when either of these holds:
- it was acted on in a suspicious session;
- it carries an approval indicator: release without a completed approval, the same actor initiating and approving,
  a payee change after approval, or a settlement claim without independent evidence.

### Transaction states

Transaction states and evidence categories are defined in `enterprise/transactions.py`. A recorded action becomes a
**verified transition** only if all of these hold:
- its outcome is `success`;
- the transaction already holds the state the action requires;
- its timestamp does not precede that state.

Everything else is kept as an attempt, a missing transition or a contradiction, with the reason. Contradictions make
the transaction `undetermined`. Contradictions are:
- conflicting duplicate records;
- differing amounts or currencies;
- an action recorded after a rejection;
- a settlement record for an unreleased transaction;
- records out of sequence.

### Quantities

The released report holds only counts and sums of input records:
- transactions;
- suspicious transactions;
- transactions linked to privileged sessions;
- rejected or stopped transactions;
- blocked release attempts;
- posted transactions;
- independently settled transactions;
- unresolved transactions;
- monetary totals per evidence category **per currency**.

Currencies are never added together, and no exchange rate is applied. No loss figure is computed.

## 6. Security boundaries (unchanged and verified)

- **Offline.** There is no telemetry and no outbound connection. The workbench binds to loopback only. The demo
  and tests run with networking blocked (§ ENTERPRISE_ACCEPTANCE gate F).
- **Read-only.** Sources are never written. No identity directory, database or payment system is modified. No
  remediation is executed; containment items are advisory and marked `executed: false, requires_authorisation: true`.
- **Opaque identifiers.** Released outputs use only opaque, case-keyed identifiers:

  | Prefix | Identifies |
  |---|---|
  | `ACCT-` | accounts |
  | `FSN-` | financial-application sessions |
  | `TXN-` | transactions |
  | `PEV-` | privilege events |
  | `FGP-` | evidence gaps |
  | `FREC-` | containment considerations |
  | `CPTY-` | counterparties |

  Raw transaction references stay in the encrypted work store (`work/financial/refs.json`) for authorised
  investigators. Payee and bank account numbers are fingerprinted at parse time, and credentials are never read.
  The workbench shows account refs only, without labels.
- **No hosted AI.** The investigator runs with the deterministic fixture (labelled *not AI inference*) or an
  operator-run local model on loopback. Hosted providers remain unavailable. No incident evidence is sent anywhere.
- **No OT.** There is no OT, PLC, SCADA or grid communication, and the profile has no code path for one.

## 7. Human approval requirements

**Who does what.** Operators run analyses, reviewers accept or reject each AI-proposed item, and approvers release.
A released investigation report contains:
- only the hypotheses, steps, remediation and missing-evidence items a reviewer explicitly accepted;
- unreviewed items, segregated as *not reviewed*.

**What the software never decides.** Fraud, a person's responsibility, legal reporting and financial loss are
decisions for the organisation's responsible officers, auditors and authorities. The validator rejects AI text that
claims any of them as fact (see [AI_INVESTIGATOR.md](AI_INVESTIGATOR.md)).

## 8. Commands

```
tscope case init CASE_DIR --case-id ENT-001 --mode incident --profile enterprise \
    --incident-start … --incident-end … --operator … --reviewer … --approver …
tscope exposure scan --case CASE_DIR --inputs estate/manifest.yaml   # manifest with an enterprise: block
tscope paths ingest --case CASE_DIR --manifest logs/logs.yaml          # includes fin_app_audit / bank_settlement
tscope paths analyse --case CASE_DIR --window START/END ; tscope paths report --case CASE_DIR
tscope financial analyse --case CASE_DIR --config financial.yaml ; tscope financial report --case CASE_DIR
tscope release --case CASE_DIR --kind exposure|paths|financial|investigation --approver NAME
tscope-verify chain CASE_DIR/reports/financial --hospital-key KEY.pub
tscope dashboard serve --case CASE_DIR
```

`financial.yaml` (`tripline.financial-config/v1`) declares:
- `directory_domains`;
- `supplier_accounts` (account, supplier, `window_start`, `window_end`);
- `privileged_groups`;
- `approved_privileged_accounts`;
- `directory_members` (account → directory distinguished name, so group-membership events can be attributed);
- `correlation` windows in seconds (`signin_to_app_s`, `logon_to_app_s`, `vpn_to_app_s`,
  `privilege_before_session_s`).

Unknown keys are rejected, and the config hash is recorded in the audit log and the report.

The exposure manifest's `enterprise:` block declares `financial_assets` (asset ids in the asset map) and any of
these inputs:
- `entitlements`
- `role_mappings`
- `operational_requirements`
- `data_inventory`
- `audit_coverage`
- `supplier_access`

Optional settings are `copy_patterns` and `privileged_operations`.

## 9. Proposed future integrations (not implemented)

**Energy profile:**
- corporate IT security assessment;
- analysis of *approved, exported* OT evidence (historian or engineering-workstation logs supplied read-only);
- utility configuration baselines.

The Energy profile would never communicate with OT devices.

**Other source adapters.** Each would need customer-specific validation:
- SAP Security Audit Log / change documents;
- Oracle E-Business Suite audit;
- Microsoft Dynamics audit;
- SWIFT / ISO 20022 statement (`camt.053`) settlement files;
- Microsoft Purview / Defender exports;
- CyberArk / PAM session logs.

**Other capabilities:**
- Multi-currency reporting with an explicit, cited conversion source (never implicit).
- Larger-volume benchmarks on customer-scale exports. Only small synthetic volumes have been measured; see the
  limitations document.
