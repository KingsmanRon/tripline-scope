# Enterprise demonstration: suspected unauthorised privileged access to a utility's financial system

**Fictional, synthetic data only.**
- **What it is.** "Synthetic Utility Ltd" (`utility.example`) is a made-up enterprise. The scenario belongs to a
  publicly reported *category* of enterprise financial-system compromise.
- **What it is not.** It does not reproduce, model or claim to reconstruct any real organisation's systems or
  incident, and it names no real people, accounts, hosts or banks.
- **Identifiers.** Internal addresses are private ranges, external addresses come from the RFC 5737 documentation
  ranges, and domains end in `.example`.
- **No network.** Nothing in the demonstration connects to any network.

## 1. Run it (one command, offline)

```
demo/enterprise-financial-incident/run.sh --scenario all            # or --scenario a|b|c
#   [--workdir DIR] [--no-dashboard]; TSCOPE_PYTHON selects the interpreter
```

**Requirements.** The project venv (Python 3.12). No database container and no internet access are needed.

**Outputs.**
- one installation and one enterprise-profile case per scenario under `--workdir` (default
  `demo/enterprise-financial-incident/out`);
- `demo_summary.json` with every check.

**Exit code.** The command exits non-zero if any check fails.

## 2. The scenario

**Assets** (all fictional):

| Asset | Hosts / names | Role |
|---|---|---|
| `AST-FIN-APP01` | FIN-APP-01 | financial application |
| `AST-FIN-DB01` | FIN-DB-01, database FINDB | financial database |
| `AST-IDP01` | IDP-01 | identity provider |
| `AST-VPN01` | VPN-01 | remote access |
| `AST-DC01` | DC01 | directory |
| `AST-WS-FIN07` | WS-FIN07 | finance workstation |
| `AST-AUDIT01` | AUDIT-01 | log source |
| — | `UTIL\vendor01` | VENDOR-01, an external service provider identity |

**Stages** (all three scenarios):

1. **Ground truth.** A fictional enterprise with known ground truth (`ground_truth.json`): routine payment activity
   by finance clerks and approvers over three weeks.
2. **Weaknesses.**
   - The supplier account holds an admin entitlement with no approved role mapping (E1).
   - It exceeds its declared read-only requirement (E2), as does the finance batch service account.
   - A payment export and a database backup sit outside the approved inventory (E3); an inventoried copy is not
     flagged.
   - Vendor-master changes are not audited (E4).
   - The supplier access window ended on 31 August, but the account is still enabled (E5).
   - A plaintext credential for the batch service account sits in a deployment script (A1).
3. **Suspicious access.**
   - Remote-access software starts on the finance workstation (4688).
   - The supplier identity signs in from a documentation-range address without MFA, then opens a VPN session linked
     by request id.
   - It logs on to the application server.
   - It is added to `FIN-Payments-Admins` (4728) and uses special privileges (4672).
   - It reads `FINDB.dbo.vendor_bank_details` (SQL audit).
4. **Financial-application session.** The application records the identity-provider correlation id, so the
   identity link is direct. In the session the account assigns itself an application role. What follows depends
   on the scenario (below).
5. **Malformed and duplicate records** in the audit export test the adapter.

| Scenario | Financial events | Settlement evidence | Expected result |
|---|---|---|---|
| **A** | views of the vendor master and payment batches only; the audit export has a declared outage overlapping the session | none supplied | `not_determinable`: suspicious access evidenced; gaps prevent a determination |
| **B** | payee changed; payment of ZAR 4,850,000.00 created and submitted; a release attempt is *denied*; an approver *rejects* it next morning | bank statement: no settlement of it | `attempted_and_stopped`; the attempted amount is reported under `rejected_or_stopped`, never as loss |
| **C** | payee changed; ZAR 1,275,400.00 created, **approved by the same account**, released, posted, and **settled per an independent bank record** (exact reference, amount and currency); a second payment of USD 18,500.00 is released and posted, and the application marks it settled, but **the bank statement has no record** | bank statement | `settlement_corroborated`: ZAR payment `settled_corroborated`; USD payment `posted` with `settlement_claimed_without_independent_evidence`; currencies never added together |

**What each run does.**
- **Analysis.** Each scenario runs Module A exposure, Module B access paths, the financial investigation, and the
  deterministic investigator (the fixture, **not AI inference**). Review is simulated by synthetic reviewer accounts.
- **Release.** Every report is released through the approver gate.
- **Verification.** Each run then performs:
  - `tscope verify`, `audit verify` and `tscope_verify chain` for every report kind;
  - an investigator re-render check;
  - a check that the inputs are unchanged;
  - a leak scan of every output (reports, PDFs, audit log, console, workbench responses) for the seeded password,
    bank account numbers, bank references, payee references and raw transaction references, with a positive control
    on the inputs;
  - a workbench session over real loopback HTTP, checked against the released reports.

## 3. Financial-application audit adapter (input schema)

Sources are declared in `logs.yaml` like any Module B source (`family`, `format`, `path`, `host`, `asset_id`,
`coverage`, optional `mapping`). Formats are CSV with a header row, JSON (a list, or `{"value": [...]}`) or JSON Lines.

**`fin_app_audit`** (\* = required):

| Field | Meaning | Stored as |
|---|---|---|
| `event_id`\* | the source system's own event id (plain identifier) | `event_code` |
| `timestamp`\* | event time (`iso8601` by default; `mapping.timestamp_format` for others) | `ts_utc` (with zone/offset handling) |
| `source_system`\* | application name | `application` |
| `actor_reference`\* | the account that acted | `account` (released only as `ACCT-`) |
| `action`\* | one of the actions below (after `mapping.action_map`) | `operation` |
| `outcome`\* | `success`, `failure`, `denied`/`blocked` (→ failure + flag), `unknown` | `outcome` |
| `evidence_source_id`\* | the export the record came from | `evidence_ref` |
| `session_reference` | application session id | `session_id` |
| `target_reference` | object acted on (e.g. `payment`, `vendor:V-1003`) | `object_name` (scrubbed) |
| `transaction_reference` | payment/transaction reference | `txn_ref` (released only as `TXN-`) |
| `approval_reference` | approval/workflow reference | `approval_ref` |
| `amount`, `currency` | non-negative decimal and ISO 4217 code | `amount_minor` (integer minor units), `currency` |
| `payee_reference` | payee/beneficiary reference (often an account number) | keyed fingerprint `counterparty_ref` (`CPTY-`) only |
| `idp_correlation_id` | identity-provider correlation id carried by the session | `correlation_id` (used for `direct` identity links) |
| `client_host`, `target_account` | client host; account acted upon (role assignments) | `client_host`, `target_account` |

**Actions:**

| Group | Actions |
|---|---|
| Payment lifecycle | `payment_created`, `payee_modified`, `approval_submitted`, `approval_rejected`, `approval_completed`, `payment_released`, `payment_stopped`, `ledger_posted`, `transaction_reversed` |
| Settlement claimed by the application | `settlement_confirmed` (never treated as settlement) |
| Application role changes | `role_assigned`, `role_removed` |
| Everything else | `other` (kept, flagged `unmapped_action` when it came from an unknown word) |

**`bank_settlement`**:
- Required: `event_id, timestamp, transaction_reference, amount, currency, outcome (settled|returned|pending|rejected),
  evidence_source_id`.
- Optional: `source_system, bank_reference, payee_reference`.

**Mapping options:**
- `mapping.fields` renames source columns onto these fields, and only mapped or documented fields are read. A
  password, token or account-number column that is not mapped is never touched.
- `mapping.action_map` and `mapping.outcome_map` translate the system's own words.
- Unknown mapping fields or action targets are configuration errors.

**Validation.** A record that fails is not stored; it is counted with its locator and reason. Failures include:
- a missing required field or an unreadable line;
- a bad timestamp;
- a non-identifier event id or reference;
- an unknown currency, an amount without a currency, a negative amount, or too many decimal places for the currency;
- an undocumented settlement outcome.

**Duplicates.** A source `event_id` seen twice in a source is kept and flagged `duplicate_source_event_id`. The
transaction analysis then:
- drops exact duplicates (and counts them);
- keeps conflicting duplicates, which establish no transition and make the transaction `undetermined`.

## 4. Results of the demonstration run

The results recorded with this release are in [ENTERPRISE_ACCEPTANCE.md](ENTERPRISE_ACCEPTANCE.md) §2. Example
(scenario C, from the released `financial` report):

```
financial_impact: settlement_corroborated
counts: transactions 44 · suspicious 2 · linked to privileged sessions 2 · settled (independent) 43 · unresolved 0
suspicious totals: settled_corroborated ZAR 1,275,400.00 · posted USD 18,500.00   (never added together)
suspicious session FSN-…: identity direct · remote access direct · host logon correlated · privilege observed
   reasons: supplier_outside_window, privilege_granted_before_session, signin_without_mfa, external_signin
TXN-… settled_corroborated ZAR 1,275,400.00 — same_actor_initiated_and_approved
TXN-… posted USD 18,500.00 — same_actor_initiated_and_approved, settlement_claimed_without_independent_evidence
```

These are synthetic results. They show that the method distinguishes the three situations; they say nothing about
detection rates on real data.
