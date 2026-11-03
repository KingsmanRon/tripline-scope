# Enterprise profile — limitations and outstanding risks

Read this before any customer use. The enterprise profile is a **synthetic proof of capability**. It is **not** a
validated product for a customer's production environment.

## 1. Validation status

| Area | Status |
|---|---|
| Synthetic utility demonstration (three scenarios) | Demonstrated end to end, offline (ENTERPRISE_ACCEPTANCE.md) |
| Customer production exports (any vendor's ERP, identity provider, VPN, bank) | **Not validated.** No real data has been processed. |
| Specific ERP products (SAP, Oracle EBS, Dynamics, others) | **Not supported natively.** Exports must first be normalised to the documented `fin_app_audit` field set (ENTERPRISE_FINANCIAL_INCIDENT.md §3). The mapping covers renaming fields and actions only; it does not transform data. |
| Bank statement formats (ISO 20022 `camt.053`, MT940, proprietary) | **Not parsed natively.** They need normalisation to the `bank_settlement` field set. |
| Volumes | Measured only on the small synthetic estate: about 230 application events, about 45 transactions and about 130 SQL audit rows per scenario, in seconds. **No claim is made about enterprise-scale throughput.** |
| Multi-tenant or multi-entity ledgers, intercompany flows, batch payment files with many beneficiaries | Not modelled. One transaction reference corresponds to one payment. |
| Clean VM / Hyper-V install of this release | Not run (same as release 1). |
| Real local AI model on enterprise bundles | Not run. The deterministic fixture only; transport tested in release 1. |

## 2. Method limitations

- **Normalised actions only.** Transaction states come from the application's audit trail as exported and mapped.
  - A missing, filtered or incorrectly mapped export produces `undetermined` or missing-transition results. It never
    produces invented states.
  - An action outside the mapped vocabulary is kept as `other` and does not change a state.
- **Settlement needs an independent source.** Without a `bank_settlement` export, no transaction can be classified
  `settled_corroborated`.
  - The report then states that settlement is not determinable.
  - Matching is exact (reference, minor-unit amount, currency). A bank that truncates or reformats references will
    produce `undetermined` (contradiction) results until it is mapped.
- **Correlation windows are configuration.**
  - `correlated` links depend on the declared windows and on clock accuracy. Module B's clock-offset and uncertainty
    settings apply.
  - Shared or reused accounts can produce wrong correlations. They remain labelled `correlated`, never `direct`.
- **Account identity.** Accounts are matched by normalised name (domain prefix and own-domain UPN suffix removed).
  - Renamed accounts, accounts with different names in different systems, and service accounts that act for many
    people are not resolved automatically.
  - A directory group grant is attributed to an account only through the declared `directory_members` mapping.
    Otherwise it is listed as unresolved.
  - Shared-identifier (`direct`) joins are validated, and a correlation id that appears on another account's sign-in
    makes the link `unresolved`. A source that legitimately reuses correlation ids across accounts therefore yields
    fewer `direct` links, never wrong ones.
- **Provenance binding is strict.** Any re-ingest after the paths release, even of identical files, changes the
  encrypted event files. The financial analysis then refuses until paths is re-analysed and re-released. Cases whose
  paths report predates this check must be re-ingested and re-released.
- **Suspicion reasons are deliberately few and documented** (ENTERPRISE_PROFILE.md §5).
  - They are not a detection engine; absence of a reason is not evidence of legitimacy.
  - Approval indicators (segregation of duties and similar) use the application's recorded actors only.
- **E1–E5 rely on declared registers.** Role mappings, requirements, inventory, audit coverage and supplier windows
  come from the organisation.
  - A missing register makes the control *not assessed*, never passed.
  - E3 considers only copies Module A's existing A3 detector recognises. Financial relevance is inferred from the
    target asset or a configurable file-name pattern.
  - E4 reports declared coverage; it does not inspect the system.
- **No loss or fraud determination.** Tripline does not decide either. The investigator validator rejects text that
  asserts fraud, guilt, money movement without independent settlement, or loss.

## 3. Outstanding risks

| Risk | Mitigation in this release | What a customer pilot must add |
|---|---|---|
| Real exports differ from the documented schema | Strict validation: failing records are counted with locators and reasons, never repaired | A per-customer mapping, reviewed with the system owner, and a sample-based reconciliation against the source system |
| Clock skew between systems produces wrong correlations | Labels stay `correlated`; out-of-sequence records are contradictions | Measured clock offsets per source in `logs.yaml` |
| Over-reliance on `settled_corroborated` | Requires exact independent matching | Bank confirmation through the organisation's own channel before any external statement |
| Sensitive business references in outputs | Opaque keyed ids; leak scan in the demo and tests | Customer-specific needles added to the leak scan |
| Investigator text overreaching | Deterministic rules for fraud, blame, money movement, loss and absence; human review before release | Review training for reviewers; legal review of anything released externally |
| Volume | Bounded synthetic runs only | A benchmark on representative customer volumes before committing to timelines |

## 4. Known untested environments

- Windows-only hosts without a Linux VM.
- Air-gapped installs of this release (the release-1 offline bundle process is unchanged, but it has not been rebuilt
  and re-verified for this branch).
- Exports larger than the synthetic estate.
- Non-UTF-8 exports.
- Exports with time zones other than UTC or Africa/Johannesburg.
- The Energy profile (not implemented).

## 5. Safety statement

This release:
- performs no active scanning, exploitation, credential capture or validation, or login attempt;
- executes no live payment and makes no change to identity directories or source databases;
- has no OT, PLC, SCADA or grid communication;
- sends no telemetry and transmits no evidence to hosted AI.

The demonstration uses only fictional entities (`utility.example`, documentation-range addresses). It does not
reproduce or claim to reconstruct any real organisation's incident.
