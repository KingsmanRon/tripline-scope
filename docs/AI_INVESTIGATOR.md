# Tripline AI Investigator

The Investigator proposes investigative reasoning over a case's released, signed Module A, B and C reports. It is
advisory and read-only: it never changes source evidence, evidence classifications, person counts, case scope,
notification decisions or released reports, and it cannot act on any system. Every model output passes a
deterministic validator before anything is stored as a result, shown or reported.

## 1. Architecture

```
released exposure / paths / scope reports ──verify (signature + chain)──▶ evidence bundle (allowlisted, bounded)
        │                                                                     │
        │                                                     prompt (fixed instructions + bundle as data)
        │                                                                     │
        │                                         provider: fixture | local (loopback) | [hosted: unavailable]
        │                                                                     │
        └──────────────▶ deterministic validator ◀─────────── raw output (stored encrypted, never shown)
                                   │
                    validated result (encrypted, work/investigator/)
                                   │
                    human review (case reviewer, per item, audited)
                                   │
          investigation report draft (operator) ──▶ tscope release --kind investigation (approver, hospital key)
```

| Code | Role |
|---|---|
| `investigator/bundle.py` | released reports → `tripline.investigation-bundle/v1` |
| `investigator/prompt.py` | fixed instructions; the bundle is passed as untrusted data |
| `investigator/schema.py` | strict structure of `tripline.investigation-candidate/v1` |
| `investigator/validate.py` | content rules (§4) → `tripline.investigation/v1` |
| `investigator/providers.py` | provider interface (§5) |
| `investigator/fixture.py` | deterministic rule-based output for CI and demos (not AI) |
| `investigator/run.py`, `storage.py` | runs, encrypted storage, review, manual bridge |
| `investigator/report.py` | `investigation` report body and PDF from a frozen, reviewed result |
| `investigator/synthetic.py` | attested synthetic-origin registry (manual bridge only) |

## 2. Commands

| Command | Role | What it does |
|---|---|---|
| `tscope investigator providers` | any | lists providers and why each is or is not available |
| `tscope investigator analyse --case C --provider P` | operator | one run with exactly the named provider (no fallback) |
| `tscope investigator show --case C [--run R]` | any case role | validated result; rejected items as ids and codes only |
| `tscope investigator review --case C --run R --item H1 --decision accept\|reject --note …` | reviewer | per-item human review |
| `tscope investigator report --case C [--run R]` | operator | draft `investigation` report (refuses unreviewed hypotheses and stale runs) |
| `tscope release --case C --kind investigation --approver IO` | approver | existing release gate: sign-in, separation of duties, hospital Ed25519 key |
| `tscope investigator verify --case C` | any case role | chain verification + byte-identical re-render from the frozen input |
| `tscope investigator bridge-export` / `bridge-import` | operator | synthetic cases only (§6) |

Exit codes: 0 ok, 2 configuration, 3 permission, 4 integrity (tampered/stale), 7 not ready, 8 provider unavailable
or analysis failed.

## 3. Evidence contract

Only released versions are read, and each kind's chain is verified first; a chain that fails stops the run. Drafts,
extracts, restores, logs, case sources and the notification pack are never read (tested: the bundle builder opens
no encrypted case file). Items keep the report ids: `AF-` findings and `XA-` unassessed coverage units (A); `PATH-`
paths, `CLM-` table claims, `ANOM-` anomalies, `GAP-` gaps, `COR-` corroborations, `IM-` indicator matches, `REC-`
containment recommendations (B); `SCOPE-<tier>` (C). Every number a provider may quote is a `FACT-` entry pointing
at the exact report field. Fields are allowlisted (`id, module, report, type, basis, consequence_class, statement,
severity, assets, sources, tables, accounts, time_window, confidence, limitations, exfiltration_evidence_kind,
related`); text is control-character-free, re-scrubbed and truncated to 300 characters; accounts appear as the
opaque `ACCT-` references and approved labels Module B already publishes. Limits: 400 items, 200 facts, 256 KiB;
Module A detail is dropped first. A module that has no released report is recorded as `not assessed`.

## 4. Hypotheses, observations and validation

Tripline's evidence model is unchanged: `basis` (observation, inference, hypothesis, unknown) and
`consequence_class` (`access_observed` < `export_or_staging_observed` < `egress_suspected` <
`exfiltration_evidenced`; `undetermined`). Model output may only be `hypothesis` or `inference`; it is never an
observation. Deterministic findings in the report are computed by Tripline from the module reports, not by the model.

The validator assigns each item `accepted`, `unverified` (names a table, account, asset or address that none of its
cited evidence mentions — shown labelled, never reported) or `rejected`:

| Code | Rule |
|---|---|
| `schema` | malformed JSON, duplicate or unknown keys, wrong types, size limits, not exactly one main hypothesis |
| `case_mismatch`, `bundle_mismatch` | output for another case or bundle; also a bundle whose content no longer matches its hash |
| `unknown_evidence`, `unknown_asset`, `unknown_source` | ids not in this bundle (covers cross-case references) |
| `promotion` | asserted class stronger than the strongest class among the cited supporting evidence |
| `exfiltration_unsupported` | `exfiltration_evidenced` (or text asserting theft as fact) without a cited item carrying an eligible `exfiltration_evidence_kind` (`core.evidence.EXFILTRATION_EVIDENCE_KINDS`) |
| `missing_logs_as_absence` | text concluding that nothing happened while gaps exist |
| `unsupported_number` | a number in text not declared in `quantities`, or a quantity whose value differs from the fact |
| `prohibited_content` | ID numbers, card/phone numbers, e-mail, credentials, URLs, unknown IP addresses or domains, clinical codes, shell/SQL command text, code markup |
| `unsupported_conclusion` | an inference without positive supporting evidence (a gap shows only that evidence is missing) |
| `confidence_label` | `high` confidence while citing contradicting evidence |
| `execution_claim` | remediation text claiming an action was taken |

A run is `completed` when at least one hypothesis is accepted; if the main hypothesis is rejected the result says so
and shows only alternatives. Rejected text is kept only inside the encrypted run directory (`response.bin`) and is
never logged, shown, reported or put into error messages; diagnostics are item ids and codes.

**Confidence labels** are ordinal, not probabilities: `low` = consistent with the cited evidence but not preferred
over the alternatives; `moderate` = better supported than the alternatives by the cited evidence; `high` = supported
by cited observations with no cited contradicting evidence. They are never converted to numbers.

## 5. Providers and permissions

| Provider | Status in this release | Network |
|---|---|---|
| `fixture` | implemented; deterministic rule-based output; labelled "not AI inference" everywhere (`is_model_inference: false`) | none |
| `local` | implemented; any OpenAI-compatible `/v1/chat/completions` server the hospital runs | literal loopback only |
| `openai-daybreak` | adapter boundary only; always `unavailable` (not authorised) | none |
| `anthropic` | adapter boundary only; always `unavailable` (not authorised) | none |
| manual bridge | implemented; synthetic cases only (§6) | none (human copy/paste) |

Selection is explicit (`--provider`); there is no fallback. Provider configuration is the administrator's
(`config.yaml` → `investigator.local`). Provenance recorded in every result and report: provider, kind, model id,
model version (from configuration), the model name the server reported, whether it is model inference, endpoint class.

**Local model setup.** Run a vetted inference server on the same host (for example llama.cpp `llama-server` or vLLM)
with weights the hospital has reviewed and licensed, bound to 127.0.0.1. Then:

```yaml
investigator:
  local:
    endpoint: http://127.0.0.1:8080/v1/chat/completions
    model_id: the-served-model-name
    model_version: weights file SHA-256 or release tag
    timeout_s: 120
    max_output_tokens: 4096
```

Tripline connects with `http.client` straight to the loopback literal: no DNS (`127.0.0.1.nip.io` is refused), no
proxies (environment proxy variables are ignored), no redirects, `https`/credentials in URLs refused, request ≤ 1 MiB,
response ≤ 1 MiB, timeout 5–600 s, `temperature: 0`. Tripline never downloads weights, dependencies or extensions,
and the bundle does not include a model runtime or weights.

*Verified:* the transport, limits and failure modes against a stand-in OpenAI-compatible server on 127.0.0.1 that
returns the fixture output (`tests/investigator/test_local_provider.py`). *Not verified:* any real local model — none
was available in the build environment, so the quality, schema adherence and speed of real models are **not tested**.
Expect small models to fail validation often; failures are recorded and can be retried.

**Hosted providers (OpenAI Daybreak, Anthropic).** No API names, model ids or endpoints are assumed and no hosted
integration is active. Individual Daybreak access does not imply API entitlement, permission to embed or distribute
model access, or permission to send patient data or forensic evidence externally. A future integration needs written
approval, a contract that permits the data flow, synthetic-only restriction until approved otherwise, and a code
change to the adapter; hospital cases never communicate with external model services.

## 6. Synthetic-only manual bridge

For evaluating structured, redacted synthetic evidence in a separately authorised chat session (for example an
individual ChatGPT Daybreak session) without pretending that such access is an API:

1. `tscope investigator bridge-export --case C --out prompt.json` — refuses unless **every file of every case source**
   is in the attested synthetic registry. A `synthetic=true` flag is never accepted. The file (mode 0600) holds the
   notice, run id, bundle hash and the two prompt messages.
2. A person pastes the messages into the authorised session and saves the single JSON reply.
3. `tscope investigator bridge-import --case C --run R --response reply.json --model-label "…"` — re-checks the
   registry, validates against the stored bundle, and records the model as *user-declared, unverified*.

The registry (`<home>/synthetic_registry.json`, HMAC under a key derived from the hospital KEK) is written only by the
generators' `--attest` option immediately after they write their outputs. It proves files were produced by those
generators on this installation. Limits: an administrator holding the KEK who deliberately calls the attestation
function on other files defeats it; `.bak` files are attested by the builder that produced them from attested data,
not by reproducing their bytes.

## 7. Prompt-injection and abuse defences

Imported logs, metadata, descriptions and model responses are untrusted. Defences: allowlisted bundle fields,
bounded and cleaned text, evidence passed only as a labelled data document after fixed instructions, no tools at all
(no SQL, shell, file, network, scanning or containment capability exists in the provider interface), strict output
schema, the content rules in §4, and remediation always recorded as `requires_hospital_authorisation: true`,
`executed: false`. Tested (`tests/investigator/test_injection.py`): instructions planted in a SQL audit record travel
through Module B into its released report; a provider that obeys them produces output that is rejected in full; no
process is started and no connection is attempted; nothing injected reaches the result; Module B's classes are
unchanged; the fixture run on the same case stays clean.

## 8. Data classification and storage

| Data | Where | Protection |
|---|---|---|
| bundle, prompt, raw provider output, result, reviews, frozen input | `<case>/work/investigator/` | AES-256-GCM envelopes under the case key; destroyed at closure; closure blocked by legal hold |
| run index | `work/investigator/index.json` | encrypted |
| released investigation report | `<case>/reports/investigation/v000N/` | signed, immutable, verified by `tscope-verify` |
| bridge export | operator-chosen file | synthetic cases only, 0600 |

No plaintext temporary files or response caches are written. Released reports contain validated, reviewed
conclusions, references and hashes — never prompts, raw model output or rejected content.

## 9. Human review and approval

Each accepted hypothesis must be reviewed (`accept` or `reject`, with a short note checked for identifiers) by a user
holding the case reviewer role before a report can be drafted. The report separates: deterministic findings, AI
analysis (advisory, attributed to the provider and model, with review status), human-reviewed conclusions, missing
evidence (deterministic gaps and families not supplied, plus accepted AI suggestions), validation counts and
rejection codes, references and provenance. Release uses the existing approver sign-in, operator/approver separation
and hospital key. A report draft is refused if any referenced module report is no longer the latest released version
(`stale`). `investigator verify` re-renders the released body from the frozen input and compares bytes; separate model
runs are not claimed to be reproducible.

## 10. Failure modes and audit

| Situation | Behaviour |
|---|---|
| provider unavailable (not configured, not authorised) | run recorded `unavailable`, exit 8, no connection, modules untouched |
| provider error, timeout, redirect, oversize, non-JSON | run recorded `failed` with a safe reason, exit 8; retry creates a new run |
| output rejected | run `failed`, codes per item; rejected text never leaves the encrypted run directory |
| released report tampered | analysis refused (exit 4) |
| module re-released after analysis | report draft refused as stale (exit 4) |
| case closed | working data destroyed; released investigation reports remain verifiable |

Every command writes one hash-chained audit entry (actor, role, outcome, input/output hashes, run id); review
decisions are audited with item id and decision only.
