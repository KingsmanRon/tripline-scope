# Security design — for the hospital's security team

Tripline Scope runs entirely on hospital infrastructure. It makes no outbound connections: no telemetry,
licence checks or update checks. The only network connections it opens are to database instances you
configure (a restore server, or an optional read-only live login) on your own network, and the review page,
which listens on `127.0.0.1` only.

## 1. Data flows

```
 hospital media / shares (read-only)        hospital restore server (you license it)
 ┌──────────────────────────────┐           ┌───────────────────────────────┐
 │ .bak, pg dumps, CSV/XLSX/JSONL│──RESTORE─▶│ tscope_<case>_<src> databases │
 │ log exports, config snapshots │           └───────────────┬───────────────┘
 └──────────────┬───────────────┘                           │ bounded SELECTs
                │ read-only (hash-verified)                 ▼
                ▼                              ┌──────────────────────────────┐
        ┌───────────────┐  needed columns only │ tscope process (in memory)    │
        │ custody hash  │─────────────────────▶│ DuckDB :memory:, no spill,    │
        └───────────────┘                      │ no extensions, no file access │
                                               └──────────────┬───────────────┘
                     AES-256-GCM envelopes (case key)         │
        ┌─────────────────────────────────────────────────────▼──────────────┐
        │ <case>/work  review  notify  (encrypted)   reports (signed, counts) │
        └─────────────────────────────────────────────────────────────────────┘
```

* **Sources are never written.** Originals stay on the media you supply, ideally mounted read-only. Each is
  registered with SHA-256, size, `supplied_by`, `received_at` and legal basis. A process-wide guard refuses
  any write, rename, delete, chmod or truncate under a source path; size and modification time are checked
  before and after every command, and full SHA-256 at ingest, on `tscope source verify --full` and at close.
* **Least data.** Discovery classifies every column by sampling and a full scan, but only columns needed for
  matching, contact and exposure are extracted. Clinical, card and bank columns are recorded by name and
  category; per-row *presence flags* are kept, never the values.
* **Restored databases** are created on the restore instance you configure, with names derived from the case
  and source ids. Their data files are protected by that server's storage (place them on an encrypted
  volume); closure drops them through the engine and checks they are gone.
* **Live connections** are off by default. When explicitly enabled the login is checked for write rights and
  refused if it has any; sessions are forced read-only with statement and lock timeouts and row limits.

## 2. Keys

| Key | Where it lives | Notes |
|---|---|---|
| Hospital KEK (AES-256) | `kek.json` **outside every case directory** (removable media or a service-account-only path), wrapped with scrypt + AES-256-GCM under a passphrase | wraps case keys and TOTP secrets; HSM/PKCS#11 is a later seam |
| Case key (AES-256, one per case) | `<keystore>/cases/<CASE>.dek.json`, AES-GCM-wrapped by the KEK, AAD binds the case id | never stored unwrapped on disk; destroyed at closure |
| Per-file key | derived: HKDF-SHA256(case key, file id) | no nonce reuse across files |
| Fingerprint key | derived: HKDF-SHA256(case key, purpose) | keyed HMAC fingerprints of secrets and record pairs; useless once the case key is destroyed |
| Hospital signing key (Ed25519) | passphrase-encrypted PKCS#8 held by the hospital | signs every released report and the destruction certificate; the hospital is the responsible party |
| Provider key (Ed25519, optional) | held by the provider who ran the scoping | co-signs report content |
| Account passwords | `users.json` (mode 0600) as Argon2id hashes (64 MiB, t=3) | lock-out after repeated failures; TOTP optional or required per role |

## 3. What is stored where

| Location | Content | Protection |
|---|---|---|
| `<case>/case.yaml` | case id, incident window, team, source custody records, declared gaps, overrides | plaintext; no patient data, no secrets |
| `<case>/sources/` | read-only references (symlinks) or encrypted copies, custody manifests | originals untouched; copies are envelopes |
| `<case>/work/`, `review/` | extracted columns, discovery results, matches, review decisions, normalised events, scan results | AES-256-GCM envelopes under the case key |
| `<case>/notify/` | the notification pack (minimum identifiers + contact for authorised notices) | encrypted; exported only by the approver after release |
| `<case>/reports/` | released versions: canonical JSON, PDF, attachments, `release.json`, `signatures.json` | counts and categories only (saving a report refuses identifier-like values); signed; read-only |
| `<case>/audit.log` | who did what, when, with input/output hashes | hash-chained JSON Lines; no values; SIEM-exportable |
| installation home | config, users, sessions, profiles, certificates, keystore (unless relocated) | mode 0700; no patient data |

**Encryption at rest.** Every working file is an authenticated envelope (`TSENC1`): 1 MiB chunks of AES-256-GCM,
nonce = random prefix ‖ chunk index ‖ final flag, AAD = header hash ‖ index. This detects modification,
truncation, chunk reordering and substitution of one file for another (the logical path is bound into the
header). Parquet is written and read *through* the envelope stream, so plaintext Parquet never reaches disk.
DuckDB runs in memory with spilling disabled (no plaintext temp files), extension auto-install off (no
downloads), and external access off (it can read only the specific source files it is given and can write
nothing). DuckDB's and Parquet's own encryption features are deliberately **not** used: in the pinned DuckDB
1.5.x secure encrypted writes require downloading the `httpfs` extension at runtime, and the built-in fallback
is documented by DuckDB as insecure.

**Verified properties (tests in `tests/core`).** Round-trip at chunk boundaries; single-bit tampering,
truncation at a chunk boundary, wrong key and file substitution are all rejected; no plaintext marker or
Parquet magic appears in encrypted files; DuckDB cannot read a non-allow-listed file, write, `INSTALL`,
`ATTACH`, fetch a URL or re-enable any of these after configuration is locked.

**Limitations you must manage.**
* Swap: data in RAM can be paged out. Disable swap or use encrypted swap; `tscope doctor` warns while swap is
  active and not attested.
* Restore server storage, OS crash dumps and hypervisor snapshots are outside the product's control.
* Memory limits: with spilling disabled, very large match runs need enough RAM (see README hardware). The
  preliminary estimate works in slices instead (METHOD §5): about 40 bytes per identity row plus one slice. An
  administrator may enable spilling only to a directory on an encrypted volume (`duckdb.spill_dir` +
  `spill_dir_encrypted: true`).
* Passphrases supplied through environment variables are for drills and demos only.

## 4. Roles, approval and audit

Operator, reviewer and approver (Information Officer) are separate per case; the same person cannot be operator
and approver on one case — enforced when the team is set, on every command (from the audit history) and again
at release and close. Release and close require a fresh approver sign-in and the hospital signing key; nothing
leaves the case unsigned. Reviewers see only the fields needed to decide each pair and every view is logged.
The audit log is hash-chained; `tscope audit verify` and the stand-alone `tscope-verify audit` detect any
edited, deleted or reordered entry. Audit parameters are length-capped and scrubbed of identifier-like values.

## 5. Closure and destruction

`tscope case close` (approver; refused while a legal hold is active):

1. module hooks drop restored databases and confirm they are gone;
2. every managed file under `work/`, `review/`, `notify/` and every encrypted source copy is deleted;
3. the wrapped case key is overwritten with random bytes, fsynced and unlinked from the keystore — from this
   point every remaining copy of any envelope (backup, snapshot, unreclaimed SSD block) is unreadable;
4. a destruction certificate is written (canonical JSON, signed by the hospital key) listing what was destroyed
   and when, the audit-log head, signed reports retained, custody manifests, **original media retained by the
   hospital**, and any external backups you declare (for example keystore backups made before closure, which
   still hold the wrapped key until they expire).

The certificate states its limits: it certifies key destruction and logical deletion; it does not claim
physical erasure of SSD blocks, filesystem or array snapshots, or hypervisor snapshots. Verify it offline with
`tscope-verify certificate <case>/reports/closure/certificate.json --hospital-key hospital.pub`.

## 6. Verifying independently

Every signature is plain Ed25519 over the exact bytes of an RFC 8785 canonical JSON file, so anyone can check a
report without Tripline Scope, for example with OpenSSL:

```
python3 -c "import json,base64,sys; s=[x for x in json.load(open('signatures.json'))['signatures'] if x['role']=='hospital'][0]; sys.stdout.buffer.write(base64.b64decode(s['signature']))" > hospital.sig
openssl pkeyutl -verify -pubin -inkey hospital.pub -rawin -in release.json -sigfile hospital.sig
sha256sum report.json        # must equal release.json "report_sha256"
```
