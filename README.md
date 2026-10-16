# Tripline Scope: operator runbook (draft)

Tripline Scope helps a South African hospital or pathology laboratory answer the POPIA section 22 questions
after a suspected breach. Whose personal information was exposed, which records, through which access
paths, and with what confidence? It also answers the same questions in a readiness exercise before any
incident. It runs entirely inside the hospital's network, air-gapped if you choose, on a server you control.
It works on read-only copies of your systems, keeps every working file encrypted under a per-case key, and
produces signed, versioned reports in open formats (JSON, CSV, Parquet, PDF). Anyone can check those
reports offline with the stand-alone `tscope-verify` tool. A trained hospital team runs cases without the
vendor.

> **Draft.** Commands marked *(module)* belong to the scoping modules and are listed with their names
> from the build plan. Check exact flags with `tscope <command> --help` on your installed version. Each
> section ends with what has been demonstrated and what has not.

## 1. Ground rules

* **Patient data stays with you.** There is no telemetry, licence check or update check, ever. The product
  opens no outbound connections. Air-gapped operation is supported.
* **Sources are never written to.** Register originals from read-only media where possible. Every command
  checks source fingerprints before and after it runs, and a write guard blocks writes to source paths.
* **Separation of duties.** The person who operates a case cannot approve its reports or close it.
* **SQL Server licensing.** The bundled SQL Server *Developer Edition* image is licensed for development,
  test and demonstration only. Use it only for the synthetic demo and tests. For real cases, restore `.bak`
  files to a SQL Server instance **the hospital provides and licenses**, typically its existing restore or
  test server, and configure it as the restore target.

## 2. Hardware and platform

| Case size | Minimum |
|---|---|
| up to 20 million rows | 8 cores, 32 GB RAM, 1 TB SSD |
| up to 80 million rows | 16 cores, 64 GB RAM (SSD sized to the restored copies plus about 2× for working data) |

* **Venv mode:** Linux x86_64 with glibc 2.28 or later (RHEL/Rocky 8+, Debian 10+, Ubuntu 20.04+), Python
  3.12 with the `venv` module, and OpenSSL 3 for signature checking.
* **Container mode:** Docker Engine with the compose plugin.
* **Windows-only sites** run a Linux VM under Hyper-V (Generation 2, the sizes above, a fixed-size VHDX on
  an encrypted volume, no virtual network adapter or an internal-only switch) and install inside the VM.
* Disable swap or use encrypted swap. Put the case directories, the installation home and the PostgreSQL
  volume on encrypted storage (LUKS, or BitLocker for the Hyper-V host). `tscope doctor` reports swap and
  key-file permission problems.

## 3. Offline install

You receive `tripline-scope-<version>/` on removable media, plus **the release key id, given to you
separately** (in the handover letter or read back by phone).

1. **Verify before running anything.** `install.sh` does all of this itself; to check by hand:
   ```
   cd tripline-scope-<version>
   openssl pkey -pubin -in release.pub -outform DER | tail -c 32 | sha256sum | cut -c1-32  # must equal the id you were given
   sha256sum -c SHA256SUMS
   tscope-verify checksums SHA256SUMS --sig SHA256SUMS.sig --key release.pub             # on a machine that already has it
   ```
   `docs/SUPPLY_CHAIN.md` §6 shows the same signature check with OpenSSL alone.
2. **Install** as root:
   ```
   ./install.sh --release-key-id <ID> --mode venv --prefix /opt/tripline-scope --bin-dir /usr/local/bin
   ./install.sh --release-key-id <ID> --mode container --prefix /opt/tripline-scope   # Docker sites
   ```
   The installer checks every file and the signature, then installs with
   `pip --no-index --require-hashes` (venv) or `docker load` (container). It never uses the network.
3. **Installation qualification** (synthetic data in a throw-away directory, no network needed):
   `/opt/tripline-scope/share/smoke-test.sh /opt/tripline-scope --require-offline`, or in container mode
   `docker compose run --rm --entrypoint bash tscope /opt/tripline/share/smoke-test.sh`.
4. **Service account and home.** Create a dedicated account (e.g. `tripline`) and a home it alone can read:
   `install -d -m 700 -o tripline /var/lib/tripline`. Load the environment with
   `set -a; . /opt/tripline-scope/tripline.env; set +a`; it sets `TSCOPE_HOME=/var/lib/tripline` and
   disables OpenTelemetry.
5. **Initialise** once, as the service account:
   ```
   tscope init --hospital-name "Example Hospital" --admin it-admin --kek /media/tripline-kek/kek.json
   ```
   * **Hospital KEK.** It wraps every case key. Keep it on removable media, or on a path only the service
     account can read, and never inside a case. It is protected by a passphrase you are prompted for.
     Without the KEK and its passphrase, case data cannot be decrypted.
   * **Hospital signing key** (Ed25519, passphrase-protected). It signs released reports and destruction
     certificates. Give its public key, `<home>/keys/hospital_signing.pub`, to anyone who must verify your
     reports, and back the key up offline.
   * Run `tscope doctor` afterwards and fix any warnings.
6. **Users, roles and TOTP** (as the admin; `tscope login --user it-admin` first):
   ```
   tscope user add olivia                 # prompts for the password (or --password-stdin)
   tscope user totp-enroll ines           # prints an otpauth:// URI once: enrol it in an authenticator app
   tscope user list
   ```
   To require TOTP for approvers, set `require_totp_roles: [approver]` in `<home>/config.yaml`. Users sign
   in with `tscope login --user NAME [--totp CODE]`; sessions expire after `session_hours`, and repeated
   failures lock the account.

**Container mode.** Edit `/opt/tripline-scope/compose/.env` and set `TSCOPE_PG_PASSWORD`. For air-gapped
operation set `TSCOPE_NETWORK_INTERNAL=true`. Then:

```
cd /opt/tripline-scope/compose
docker compose up -d postgres                                     # PostgreSQL 16 for local restores
docker compose run --rm tscope init --hospital-name "..." --admin it-admin --kek /kek/kek.json
docker compose run --rm tscope <command> ...
```

Sources are mounted read-only at `/sources`, cases at `/cases`, the KEK directory at `/kek`, and the
installation home is the `tscope-home` volume.

*Demonstrated:* on a clean `python:3.12-slim` container with no network, the bundle verified, installed
(venv mode) and passed the smoke test. Container mode loaded the images, and on an internal-only compose
network PostgreSQL 16 and the read-only, non-root app container passed the smoke test; the app reached
PostgreSQL and nothing off the host.
*Not demonstrated:* a clean physical machine or VM, and Hyper-V.

## 4. Roles and separation of duties

| Role | Scope | Does |
|---|---|---|
| `admin` | installation | creates and disables accounts, enrols TOTP, opens cases, assigns teams. Has no case access by itself. |
| operator | per case | registers sources, runs ingest, analysis and matching, drafts reports |
| reviewer | per case | decides review pairs and checks drafts |
| approver (usually the Information Officer) | per case | releases reports, decides the notification scope, sets and lifts legal hold, closes the case |

An operator can never be an approver on the same case. This is enforced when the team is assigned, on every
command, and again at release and close, using the case's audit history. Release and close need a fresh
approver sign-in (password, plus TOTP if enrolled or required); a session token is not enough. Every
command is recorded in the case's hash-chained audit log, and `tscope audit export --out FILE` writes JSON
Lines for your SIEM.

## 5. Case lifecycle

Open a case (admin, or one of the case's approvers):

```
tscope case init /cases/CASE-2026-014 --case-id CASE-2026-014 --mode incident \
    --incident-start 2026-09-01T00:00:00Z --incident-end 2026-09-14T23:59:59Z \
    --operator olivia --reviewer rami --approver ines
```

Register every source with its chain of custody (operator). Originals are registered by reference; use
`--copy` for material received by e-mail, which is then stored as an encrypted copy:

```
tscope source add --case /cases/CASE-2026-014 --kind mssql_bak --path /sources/lis-2026-09-15.bak \
    --label "LIS backup 15 Sep" --evidence-role system_copy --legal-basis "POPIA s22 investigation" \
    --supplied-by "IT operations" --received-at 2026-09-15T08:00:00Z
tscope source verify --case /cases/CASE-2026-014 --full      # re-hash every source (also run at ingest and close)
tscope case gap --case /cases/CASE-2026-014 --description "firewall logs before 3 Sep rotated"
```

**Incident case:**

1. `case init`
2. `source add`
3. `tscope ingest` *(module)*: restore `.bak` files to the hospital's licensed SQL Server, or PostgreSQL
   dumps to the local PostgreSQL 16; classify columns; extract to encrypted Parquet.
4. `tscope paths ingest` / `tscope paths analyse` *(module)*, if logs were supplied: access paths and scope
   candidates.
5. `tscope estimate` *(module)*: preliminary counts, then
   `tscope release --kind scope --approver ines` to release the preliminary report.
6. `tscope scope match` / `tscope scope review` *(module)*: link records into people; reviewers decide the
   uncertain pairs.
7. `tscope scope report` *(module)*, then `tscope release --kind scope --approver ines`.
8. `tscope notify export` *(module)*: the approver exports the notification pack, only after release.
9. `tscope case close`.

**Readiness case:**

1. `case init --mode readiness`
2. `tscope map` *(module)*
3. `tscope profile` *(module)*
4. `tscope exposure scan` *(module)*
5. `tscope exposure report` *(module)*
6. `tscope drill` *(module)*
7. `tscope release --kind exposure|readiness|datamap|drill`

`tscope reports --case DIR` lists drafts and released versions. `tscope verify --case DIR` checks every
released chain, the audit log and any destruction certificate with the installation's pinned keys.

## 6. Re-runs and versioning

Re-running a step never edits a released report. A refinement produces a new draft. Releasing it creates
`reports/<kind>/v000N/`, whose `previous_report_sha256` links to the version before it; released versions
are read-only. Identical inputs give a byte-identical `report.json`. Every report records the method
version, the configuration hash and the hashes of its inputs, so a difference between versions can be
traced to a changed input or setting. Review decisions are keyed to record pairs and replayed on re-runs.
Declared gaps and absent logs never shrink the scope.

## 7. Release and close

* **Release:** `tscope release --case DIR --kind KIND --approver ines`. The approver signs in again, the
  hospital key signs `release.json`, and the chain is re-verified.
* **Legal hold:** `tscope case hold on --case DIR --reason "..."` (approver) blocks closure;
  `tscope case hold off` lifts it.
* **Close:** `tscope case close --case DIR --approver ines [--external-backup "nightly keystore backup, 30 days"]`.
  Closing does the following:
  * re-checks the sources;
  * destroys the wrapped case key and the working data, and drops restored databases;
  * keeps the signed reports and the audit log;
  * writes a signed destruction certificate to `reports/closure/` and `<home>/certificates/`. Declare any
    backup that may still hold case data, so the certificate says so.

## 8. Verifying offline

`tscope-verify` needs only `cryptography` and `rfc8785` and can be installed on its own, for example by an
auditor, from the bundle's `wheels/`:

```
tscope-verify chain  CASE/reports/scope --hospital-key hospital_signing.pub
tscope-verify report CASE/reports/scope/v0002 --hospital-key hospital_signing.pub
tscope-verify audit  CASE/audit.log
tscope-verify certificate CASE/reports/closure/certificate.json --hospital-key hospital_signing.pub
tscope-verify checksums SHA256SUMS --sig SHA256SUMS.sig --key release.pub
```

Exit status 0 means every check passed. Every signature is a plain Ed25519 signature over the exact file
bytes, so OpenSSL can reproduce the checks.

## 9. Where data lives

| What | Where | Protection |
|---|---|---|
| Installation home: config, users, sessions, keystore, hospital signing key | `TSCOPE_HOME` (`/var/lib/tripline`; container: `tscope-home` volume) | 0700, service account; KEK-wrapped case keys; passphrase-protected signing key |
| Hospital KEK | the `--kek` path given at `init` (removable media) | scrypt-wrapped by its passphrase |
| Case directory: working data, encrypted source copies, drafts, signed reports, audit log | where you open it, e.g. `/cases/<CASE>` | per-file AES-256-GCM under the case key; reports signed and read-only |
| Restored databases | the hospital's SQL Server, or the PostgreSQL volume `pgdata` | on encrypted storage; dropped at close |
| Original sources | where the hospital keeps them; registered by reference | never written; fingerprinted |
| Logs | console output and Docker `local` logs on this host | patient identifiers are never printed; SQL text is never logged |

## 10. Upgrades and removal

Verify and install the new bundle into a new prefix, run the smoke test, then switch the `bin` links. Cases
and the home are unaffected. Load new images with `docker load` in container mode. To remove the product:
close every case, then delete the prefix, images and volumes. Keep signed reports and certificates for as
long as your retention policy requires.
