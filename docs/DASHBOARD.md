# Investigation Workbench (`tscope dashboard`)

A read-only, local web view of one case: what each module released, the Module B timeline and access paths,
the Module A exposure findings, the Module C people counts, the AI Investigator's latest validated output, and
the signed report files. It listens on a loopback address only and changes nothing in the case: the only
things it writes are in-memory sign-in sessions and entries in the case audit log.

Contract: `docs/PLAN.md` §13. Code: `src/tripline_scope/dashboard/` (`app.py` web app and security,
`data.py` read models, `page.py` the single HTML page, `cli.py` the command). Tests: `tests/dashboard/`.

## 1. Installation (offline)

Nothing extra to install. The workbench is part of the `tripline_scope` package and uses only FastAPI and
uvicorn, which are already runtime dependencies in `pyproject.toml` and therefore already in the offline
bundle's wheels. The page is one self-contained HTML document: no CDN, web fonts, external scripts,
stylesheets or images, so a browser on the same machine with no network shows it completely.

## 2. Sign-in, roles and permissions

* **Starting the server** (`tscope dashboard serve`) needs a signed-in `tscope` user (`tscope login`) who
  holds at least one role on the case: operator, reviewer or approver. Anyone else is refused
  (`PermissionDenied`) and the attempt is audited as `dashboard serve` with outcome `denied`.
* **Using the page.** Every person signs in on the page with their own Tripline account, through the
  installation's identity provider (the same Argon2id accounts and lock-out as `tscope login`; an
  authenticator code when enrolled). A session is created only for a user with at least one role on the case;
  an installation user without a case role is refused. If `require_totp_roles` in `<home>/config.yaml` lists
  one of the user's case roles, a sign-in without an authenticator code is refused.
* **Sections per role.** The roles are recorded in the session and checked for every section. In this
  release every case role (operator, reviewer, approver) may open all seven sections; People and AI
  Investigator are audited on every request. No section, role or URL exposes the notification pack
  (`notify/`), drafts, `work/`, case sources, or person-level rows.

## 3. Usage

```
tscope login --user rami
tscope dashboard serve --case /cases/LAB-2026-001            # default 127.0.0.1:8766
tscope dashboard serve --case /cases/LAB-2026-001 --port 8800 --host localhost
```

Then open **http://127.0.0.1:8766/** in a browser on the same machine and sign in. Stop the server with
Ctrl+C. `--host` accepts only `127.0.0.1` (default), `localhost` and `::1`; anything else (for example
`0.0.0.0`, `::` or a LAN address) is refused with a configuration error before anything listens. With
`--host ::1` the command prints `http://localhost:<port>/` as the address to open.

## 4. Sections and the reports they read

Only **released** report versions are read (`reports/<kind>/vNNNN/`), except the AI Investigator section,
which also reads the investigator's latest validated run from the encrypted case store.

| Section | Reads | Shows |
|---|---|---|
| A · Overview (`/api/overview`) | `case.yaml`, case state, the released versions and `release.json` of `exposure`, `paths`, `scope`, `investigation`, `readiness`; the released `paths` report | case id, mode, incident window, open/closed, legal hold; per report kind: released versions, latest hash, report status, approver and time, whether an unreleased draft exists (its content is never shown); evidence state (sources registered, latest source received/registered time, latest release approval); Module B coverage (log families present, missing family groups, gaps by kind, sources not complete, what logs cannot cover). No overall score is computed. |
| B · Timeline (`/api/timeline`) | released `paths` report `attachments/timeline.jsonl` and its `gaps` | filterable, paged event table (filters: time range, source, log family, account ref, asset, consequence class; 100 rows by default, at most 500 per page); a lane chart of the current page; the logging gaps overlapping the chosen window. Hosts are mapped to asset ids from the paths report's inputs and affected-systems list. Events keep the report's own order (key events first). |
| C · Access paths (`/api/paths`) | released `paths` report `paths[]`, `classification`, `anomalies` | per path a left-to-right chain identity → network/VPN → host/application → database host → table(s) → staging → egress, each link labelled with the stage label from the report, its confidence and reason; consequence class per path and per table; paths and sensitive tables by class. Selecting a box or link shows its values and the path's evidence ids. |
| D · Exposure (`/api/exposure`) | released `exposure` report; `containment.recommendations[].module_a_refs` of the released `paths` report | findings (rank, severity, control, rule, title, asset, state, suggested fix, confidence, basis), summary counts, coverage per control (assessed units, not assessed, unavailable); Module B recommendation ids that cite a finding, labelled "cross-referenced by Module B containment advice; not evidence of causation". |
| E · People (`/api/people`) | released `scope` reports: the latest `preliminary` and the latest `refined` version | preliminary estimate (point and bounds) with its measured error; refined counts and bounds, the four scope tiers (observed access, possible exposure, confirmed exfiltration, notification scope with who decided), people per category, notification routes, unresolvable rows (total and per source), matching bands/rules/review queue, measured error rates. Counts only. |
| F · AI Investigator (`/api/investigation`) | the latest released `investigation` report, and the latest completed run via `investigator.storage.latest_result` | always under the banner "Advisory — AI-generated hypotheses, not findings"; run, provenance and validator counts; each hypothesis with statement, basis, consequence class, supporting and contradicting evidence (each id resolved to its module and type, and flagged if it is not in the released report), confidence label and rationale, alternatives, tests, what cannot be concluded, quantities, review status; missing evidence, next steps, remediation, unproven assertions. Output of the deterministic fixture provider (`is_model_inference: false`) is labelled "Deterministic fixture output — not AI inference". With neither a run nor a report: "Not performed — no authorised AI analysis has been run for this case". |
| G · Reports (`/api/reports`) | every released version of the five kinds | report hash, previous hash, approver/time/authentication, provider co-signature, artefact hashes, links to the files, and signature + hash + chain verification (`ReportStore.verify`, the same checks as `tscope-verify`). Verification is computed once per server start and on demand with "Re-verify" (`?refresh=1`); a failure shows the failing checks. |

Files can be downloaded only as `/reports/{kind}/v{n}/{name}` with `kind` one of `exposure`, `paths`, `scope`,
`investigation`, `readiness`, `n` an existing released version, and `name` one of `report.json`, `report.pdf`,
`release.json`, `signatures.json`. The path is built from these allow-listed parts; everything else
(traversal attempts, encoded dots or slashes, other kinds such as `notify`, drafts, attachments, other
file names) answers 404.

**Missing data is never shown as 0.** Every value that a report does not contain, marks as "not
determinable", or that does not exist yet comes back as a status and is shown as text: *Not determinable*,
*Not assessed*, *Awaiting analysis* (nothing released yet) or *Not performed*. A real zero from a report
(for example an observed-access count of 0 people) is shown as 0.

## 5. Reading the evidence labels

**Links in an access path** (Module B's own labels, never upgraded by the workbench; an unknown label would be
shown as unresolved):

| Line | Label | Meaning |
|---|---|---|
| solid black | **Direct** | the two records share an exact identifier (session, request or logon id) |
| solid black | **Observed** | recorded in the log of that system itself (the database's own audit of the access) |
| dashed amber | **Correlated** | linked by a bounded time window or attribute similarity: an inference, not proof |
| dotted grey | **Unresolved** | the evidence stops here; nothing links this step |

A correlated or unresolved link is never drawn or labelled as direct. Values in a box after an unresolved link
may still come from the database log (for example the client address it recorded); the link to the step
before is what is missing.

**Evidence basis badges** (text and shape as well as colour): **● Observed** (directly logged or detected),
**◐ Inferred** (correlated from partial evidence), **◇ Hypothesis** (an unverified explanation; every AI
Investigator hypothesis), **? Unknown** (gaps prevent a statement), **▷ Proposal** (the notification-scope
proposal; the Information Officer decides).

**Consequence classes** are those of the evidence model: access observed < export/staging observed < egress
suspected < exfiltration evidenced, or undetermined. Context events in the timeline (sign-ins, logons, web
requests, flows) are labelled "Context event". Confidence numbers in Modules A and B are shown as the report
states them; the AI Investigator's confidence is an ordinal label (low, moderate, high) and is never shown as a
number. A logging gap means activity in that period cannot be determined; it is never evidence that nothing
happened.

## 6. Security boundaries

* **Loopback only.** The server binds to the literal address given (`127.0.0.1` by default). A Host header
  other than `127.0.0.1` or `localhost` (and `[::1]` when bound to `::1`) is answered 400 (DNS rebinding).
* **Sessions.** Random 256-bit tokens in an HttpOnly, SameSite=Strict cookie, held in server memory only;
  2 hours absolute and 30 minutes idle expiry. The sign-in form carries a one-time token bound to a cookie
  (10 minutes). Sign-out is a POST that needs the session's CSRF token in `X-CSRF-Token`.
* **Cross-origin requests.** A POST whose `Origin` header is present and is not `http://127.0.0.1:<port>` or
  `http://localhost:<port>`, or whose `Sec-Fetch-Site` header is present and is not `same-origin`/`none`, is
  refused (403). Because the response header is `Referrer-Policy: no-referrer`, browsers would send
  `Origin: null` on same-origin POSTs; the sign-in page therefore sets an in-document `same-origin` referrer
  policy and the page's own POST uses `referrerPolicy: "same-origin"`, so the real origin is sent and nothing
  is sent to any other origin (the CSP allows no other origin anyway). No CORS headers are ever sent.
* **Headers on every response** (including 400/401/404): `Content-Security-Policy: default-src 'none';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self';
  frame-ancestors 'none'; base-uri 'none'` (the page adds `script-src 'nonce-…'` with a new nonce per
  response), `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Pragma: no-cache`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy:
  same-origin`, `Cross-Origin-Opener-Policy: same-origin`.
* **Escaping.** The page script builds every element with `createElement`/`textContent`; it never uses
  `innerHTML` or evaluates strings, so no report value is ever parsed as markup.
* **Read-only.** Data endpoints are GET only (any other method answers 405). Responses are built from
  released reports and the investigator's validated result; as defence in depth every string in a JSON
  response passes the same identifier scrubbing as log output (`core.redact.scrub_text`; hashes and
  Tripline's opaque ids are kept).
* **Audit** (case `audit.log`, hash-chained like every other entry):
  * `dashboard serve` — every start attempt (ok, denied, or error such as a refused `--host`);
  * `dashboard login` — every sign-in, `ok` with the user's case roles, or `denied` (wrong credentials,
    no case role, authenticator code required);
  * `dashboard view` with `params.section` — `people` and `investigation` on **every** request;
    `timeline`, `paths` and `exposure` **once per section per session** (paging through the timeline does not
    add an entry per page). Overview and Reports views are not audited.

## 7. What the tests demonstrate

`tests/dashboard/` builds one realistic synthetic case without SQL Server (Module A estate scan, Module B
incident logs, Module C synthetic databases loaded as extracts; released `exposure` v1, `paths` v1, `scope`
v1 preliminary and v2 refined) and checks:

* binding: the default server configuration is `127.0.0.1:8766`; `--host` values `0.0.0.0`, `::`, `10.0.0.5`,
  `example.org`, `127.0.0.1.nip.io` are refused and never construct a server; `localhost` and `::1` are
  accepted; a real process started through the CLI listens on `127.0.0.1:<port>` only (`ss -ltn`), serves the
  page after sign-in and answers 400 to a foreign Host;
* sign-in: unauthenticated API calls get 401 and `/` the sign-in form; the form token is required, single-use
  and cookie-bound; a wrong password gets 401; a user without a case role cannot sign in; all three case
  roles can; a role listed in `require_totp_roles` cannot sign in without a code;
* sessions: idle expiry after 30 minutes, absolute expiry after 2 hours even while active, form-token expiry;
  sign-out needs the CSRF token;
* foreign Host → 400; POST with a foreign or `null` Origin or a cross-site `Sec-Fetch-Site` → 403;
* every listed header on page, API, 401, 404, 400 and OPTIONS responses, a fresh nonce matching the only
  `<script>` tag, and no CORS headers; the page references no external resource and contains no
  `innerHTML`/`eval`;
* report files: allowed files return the exact bytes on disk; 27 traversal, encoding, kind, version and
  file-name variants (including `notify`, `..`, `%2e%2e`, `%2f`, attachments) return 404;
* no identifiers: every API response, every timeline page, filtered timelines, served report files and both
  HTML pages contain none of the generator's ground-truth identifiers (strings of 6+ characters) and no
  `find_identifier_like` match;
* read-only: SHA-256 of every file under the case directory (except `audit.log`) is identical before and after
  signing in as two users and exercising every endpoint; POST/PUT/PATCH/DELETE on every data endpoint → 405;
* offline: a full walk with `socket.connect`, `connect_ex` and `create_connection` intercepted records no
  connection attempt at all;
* values agree with the released `report.json` files: report versions, hashes and approvals; evidence state;
  Module B gap counts, families and `paths_by_class`; the preliminary point/lower/upper; refined unique people,
  bounds, people per category, notification routes, all four tier counts, unresolvable rows (total and per
  source), matching bands and rules, error rates; exposure summary, findings by severity and control,
  coverage, Module B cross-references; every path's class, tables and link labels (correlated/unresolved
  never direct);
* timeline: totals, offset paging over the whole file with no duplicates, the 500-row cap, filters (class,
  account, family, source, time window with interval overlap, asset id and host name), gap overlap, and 22
  malformed parameter cases → 400 (an empty filter value means "any");
* a case with nothing released: every section reports `awaiting_analysis` / `not_assessed` /
  `not_performed`, and no value in any response is a bare 0 standing in for missing data;
* AI Investigator: `not_performed` without a run; with a stored fixture result the response is advisory,
  `is_model_inference: false`, labelled "Deterministic fixture output — not AI inference", shows the review
  decision, and resolves AF/PATH/CLM/ANOM/GAP/COR/REC ids against the released reports (an id that is not in
  the report is flagged as not found); both views are audited;
* audit: login entries with the user's roles; `people`/`investigation` per request and
  `timeline`/`paths`/`exposure` once per session; `dashboard serve` ok, denied and refused-host entries.

In addition, during development the page was loaded in headless Chromium at 1366×768 against such a case
(sign-in, all seven sections, a path node selected, a timeline filter applied): no console errors, no CSP
violations and no request to any other origin. That browser check is not part of the automated suite.

## 8. Operational limitations

* **Single process, in-memory state.** Sessions and the verification cache live in the server process;
  restarting it signs everyone out. At most 64 sessions are kept (the oldest is dropped).
* **Loopback only, by design.** There is no option to listen on a network interface; remote viewing is not
  supported. In container mode the container's loopback is not reachable from the host; this mode has not
  been tested for the workbench — run it from the venv install.
* **Released data only.** Drafts, extracts and sources are never shown; a module that has not released a
  report shows *Awaiting analysis*. The one exception is the AI Investigator's latest validated (completed) run,
  read from the encrypted case store and always shown as advisory.
* **Large timelines are paged** (at most 500 rows per request). Each request streams the attachment once to
  count matches and keep only the requested page; the timeline itself is capped by Module B's export limit
  (`timeline.row_cap` in the paths report).
* **IPv6 loopback.** `--host ::1` is accepted and passed to the server; serving over IPv6 was not exercised by
  the tests. Open `http://localhost:<port>/`.
* **Synthetic or real.** The header shows the case mode; the workbench does not infer whether the data is
  synthetic.
