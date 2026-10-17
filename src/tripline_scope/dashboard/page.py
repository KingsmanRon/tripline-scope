"""The workbench page: one self-contained HTML document (inline CSS, inline JS run by CSP nonce).

No external scripts, styles, fonts or images. The script builds the DOM with ``createElement``/``textContent``
only (no ``innerHTML``), so no report string is ever parsed as markup.
"""

from __future__ import annotations

import html


def _e(s) -> str:
    return html.escape(str(s or ""), quote=True)


def login_html(token: str, case_id: str, error: str | None = None) -> str:
    err = f'<p class="err" role="alert">{_e(error)}</p>' if error else ""
    return (LOGIN_HTML.replace("{{csrf}}", _e(token)).replace("{{case}}", _e(case_id))
            .replace("{{error}}", err))


def page_html(*, nonce: str, csrf: str, case_id: str, mode: str, user: str, roles: list[str]) -> str:
    return (PAGE_HTML.replace("{{nonce}}", _e(nonce)).replace("{{csrf}}", _e(csrf)).replace("{{case}}", _e(case_id))
            .replace("{{mode}}", _e(mode)).replace("{{user}}", _e(user)).replace("{{roles}}", _e(", ".join(roles))))


_CSS_BASE = """
:root{--ink:#14202e;--muted:#4a5868;--line:#cfd8e3;--bg:#f3f6f9;--panel:#fff;--brand:#0b3a5b;--accent:#0f766e;
--focus:#b45309;--warn-bg:#fff7e6;--warn:#7a4b00;--bad:#9b1c1c;--ok:#166534}
*{box-sizing:border-box}html,body{margin:0;padding:0}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg)}
a{color:#0b5394}a:focus,button:focus,input:focus,select:focus,[tabindex]:focus{outline:3px solid var(--focus);outline-offset:2px}
h2[tabindex]:focus,main:focus{outline:none}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
"""

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="same-origin">
<title>Investigation Workbench — sign in</title>
<style>""" + _CSS_BASE + """
main{max-width:30em;margin:6vh auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:1.6em 2em}
h1{font-size:1.35em;margin:.2em 0 .4em;color:var(--brand)}label{display:block;margin:.8em 0 .2em;font-weight:600}
input{font:inherit;width:100%;padding:.45em;border:1px solid #8b99a8;border-radius:4px}
button{margin-top:1.2em;font:inherit;font-weight:600;padding:.5em 1.4em;border:0;border-radius:4px;background:var(--brand);color:#fff;cursor:pointer}
.err{background:#fdecec;color:var(--bad);border:1px solid #f3b4b4;padding:.5em .7em;border-radius:4px}
.note{color:var(--muted);font-size:.92em}</style></head><body>
<main><h1>Tripline Scope — Investigation Workbench</h1>
<p>Case <strong>{{case}}</strong>. Sign in with your Tripline account. You need a role on this case
(operator, reviewer or approver).</p>{{error}}
<form method="post" action="/login"><input type="hidden" name="csrf" value="{{csrf}}">
<label for="u">User name</label><input id="u" name="username" autocomplete="username" autofocus required maxlength="64">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required maxlength="256">
<label for="t">Authenticator code (if enrolled)</label><input id="t" name="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="12">
<button type="submit">Sign in</button></form>
<p class="note">Read-only view of released reports on this computer only. Sign-ins and views of sensitive
sections are written to the case audit log.</p></main></body></html>"""

PAGE_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{csrf}}">
<title>Investigation Workbench — {{case}}</title>
<style>""" + _CSS_BASE + """
.skip{position:absolute;left:-999px;top:0;background:#fff;padding:.4em .8em;z-index:10}.skip:focus{left:.5em}
header.top{display:flex;align-items:center;gap:1.2em;flex-wrap:wrap;background:var(--brand);color:#fff;padding:.55em 1.2em}
header.top h1{font-size:1.05em;margin:0;font-weight:650;letter-spacing:.01em}
header.top .meta{display:flex;gap:.9em;flex-wrap:wrap;font-size:.92em;opacity:.95}
header.top .pill{border:1px solid rgba(255,255,255,.5);border-radius:999px;padding:.05em .7em}
header.top .spacer{flex:1}
header.top button{font:inherit;background:#fff;color:var(--brand);border:0;border-radius:4px;padding:.3em .9em;cursor:pointer;font-weight:600}
.layout{display:grid;grid-template-columns:210px minmax(0,1fr);min-height:calc(100vh - 44px)}
nav.side{background:#e6edf3;border-right:1px solid var(--line);padding:.8em .5em}
nav.side ol{list-style:none;margin:0;padding:0}
nav.side a{display:flex;gap:.6em;align-items:center;padding:.5em .7em;border-radius:6px;color:var(--ink);text-decoration:none;font-weight:550}
nav.side a .letter{display:inline-flex;width:1.6em;height:1.6em;align-items:center;justify-content:center;border-radius:4px;background:#fff;border:1px solid var(--line);font-size:.85em;color:var(--muted)}
nav.side a[aria-current=page]{background:var(--brand);color:#fff}nav.side a[aria-current=page] .letter{color:var(--brand)}
nav.side a:hover{background:#d5e0ea}nav.side a[aria-current=page]:hover{background:var(--brand)}
nav.side .foot{margin-top:1.4em;font-size:.82em;color:var(--muted);padding:0 .7em}
main{padding:1em 1.4em 3em;min-width:0}
main h2{font-size:1.3em;margin:.2em 0 .2em;color:var(--brand)}main h3{font-size:1.05em;margin:1.3em 0 .4em}
.lede{color:var(--muted);margin:.1em 0 1em;max-width:70em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.9em}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.8em 1em;min-width:0}
.card h3{margin:.1em 0 .5em;font-size:1em}
dl.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.25em .9em;margin:0}
dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;background:var(--panel);font-size:.93em}
caption{text-align:left;font-weight:600;padding:.4em 0;color:var(--ink)}
th,td{border-bottom:1px solid var(--line);padding:.35em .55em;text-align:left;vertical-align:top}
th{background:#eef2f6;font-weight:600;position:sticky;top:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;max-height:65vh}
.badge{display:inline-flex;align-items:center;gap:.3em;border:1px solid;border-radius:4px;padding:0 .45em;font-size:.82em;font-weight:600;white-space:nowrap;line-height:1.6}
.b-obs{color:#14532d;border-color:#14532d;background:#ecfdf3}
.b-inf{color:#7c2d12;border-color:#7c2d12;background:#fff4ec;border-style:dashed}
.b-hyp{color:#4c1d95;border-color:#4c1d95;background:#f5f0ff;border-style:dotted;border-width:2px}
.b-unk{color:#374151;border-color:#6b7280;background:#f3f4f6;border-style:dotted}
.b-prop{color:#1e3a8a;border-color:#1e3a8a;background:#eef4ff}
.c-access_observed{color:#1e3a8a;border-color:#1e3a8a;background:#eef4ff}
.c-export_or_staging_observed{color:#7c2d12;border-color:#9a3412;background:#fff4ec}
.c-egress_suspected{color:#7f1d1d;border-color:#b91c1c;background:#fef2f2}
.c-exfiltration_evidenced{color:#fff;border-color:#7f1d1d;background:#7f1d1d}
.c-undetermined{color:#374151;border-color:#6b7280;background:#f3f4f6;border-style:dotted}
.c-not_applicable,.c-no_access_observed{color:#374151;border-color:#9ca3af;background:#fff}
.s-critical{color:#fff;background:#7f1d1d;border-color:#7f1d1d}.s-high{color:#7f1d1d;background:#fef2f2;border-color:#b91c1c}
.s-medium{color:#7c2d12;background:#fff4ec;border-color:#9a3412}.s-low{color:#1e3a8a;background:#eef4ff;border-color:#1e3a8a}
.s-info{color:#374151;background:#f3f4f6;border-color:#6b7280}
.e-direct,.e-observed{color:#111827;border-color:#111827;background:#fff}
.e-correlated{color:#92400e;border-color:#b45309;background:#fffbeb;border-style:dashed}
.e-unresolved{color:#4b5563;border-color:#9ca3af;background:#f9fafb;border-style:dotted}
.missing{display:inline-flex;gap:.25em;align-items:center;color:var(--warn);background:var(--warn-bg);border:1px dashed #d4a017;border-radius:4px;padding:0 .45em;font-size:.9em;font-style:italic}
.banner{border-radius:8px;padding:.7em 1em;margin:.6em 0;border:2px solid}
.banner.advisory{background:#f5f0ff;border-color:#4c1d95;color:#2e1065}
.banner.fixture{background:#fff7e6;border-color:#b45309;color:#5b3200}
.banner.info{background:#eef4ff;border-color:#1e3a8a;color:#172554}
.banner strong{display:block;font-size:1.02em}
.chips{display:flex;flex-wrap:wrap;gap:.3em;margin:.2em 0}
.chip{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#eef2f6;border:1px solid var(--line);border-radius:4px;padding:0 .4em;color:var(--ink);text-decoration:none}
a.chip:hover{background:#dbe5ee}.chip.nf{border-style:dashed;color:var(--bad)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
form.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.5em .8em;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.7em .9em;margin-bottom:.8em}
form.filters label{display:flex;flex-direction:column;font-size:.86em;color:var(--muted);gap:.15em}
input,select{font:inherit;padding:.3em .4em;border:1px solid #8b99a8;border-radius:4px;background:#fff;color:var(--ink);min-width:0}
button.btn{font:inherit;font-weight:600;padding:.35em 1em;border-radius:4px;border:1px solid var(--brand);background:var(--brand);color:#fff;cursor:pointer}
button.btn.sec{background:#fff;color:var(--brand)}button.btn:disabled{opacity:.45;cursor:not-allowed}
.actions{display:flex;gap:.5em;align-items:end;flex-wrap:wrap}
.pager{display:flex;gap:.6em;align-items:center;margin:.6em 0;flex-wrap:wrap}
.pathcard{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.8em 1em;margin:.9em 0}
.pathcard header{display:flex;gap:.6em;flex-wrap:wrap;align-items:center}
.pathcard header h3{margin:0;font-size:1em}
svg.chain{width:100%;height:auto;max-height:190px;display:block;margin:.6em 0}
svg .node rect{fill:#fff;stroke:#334155;stroke-width:1.4}svg .node.k-unknown rect{stroke:#9ca3af;stroke-dasharray:3 3;fill:#f9fafb}
svg .node:focus rect,svg .node.sel rect{stroke:var(--focus);stroke-width:3}
svg .node,svg .edgehit{cursor:pointer}svg .node:focus,svg .edgehit:focus{outline:none}
svg .edgehit:focus+line,svg .edgehit:focus{stroke:var(--focus)}
svg text{font:11px system-ui,sans-serif;fill:#14202e}svg text.k{fill:#4a5868;font-size:9.5px;text-transform:uppercase;letter-spacing:.04em}
.details{background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:.6em .8em;margin-top:.4em}
.legend{display:flex;flex-wrap:wrap;gap:1.2em;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.5em .9em}
.legend span{display:inline-flex;gap:.4em;align-items:center}
.lanes{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:.6em 0;padding:.3em}
.hyp{background:var(--panel);border:1px solid var(--line);border-left:5px solid #4c1d95;border-radius:8px;padding:.8em 1em;margin:.8em 0}
.hyp header{display:flex;flex-wrap:wrap;gap:.5em;align-items:center}.hyp h4{margin:0;font-size:1em}
.statement{font-size:1.02em;margin:.5em 0}
ul.plain{margin:.3em 0;padding-left:1.2em}
.err{background:#fdecec;color:var(--bad);border:1px solid #f3b4b4;padding:.5em .7em;border-radius:4px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
pre.render{white-space:pre-wrap;background:#fff;border:1px solid var(--line);padding:.5em;font-size:.85em;max-height:20em;overflow:auto}
@media (max-width:860px){.layout{grid-template-columns:1fr}nav.side ol{display:flex;flex-wrap:wrap;gap:.2em}nav.side .foot{display:none}}
@media print{nav.side,header.top button,form.filters{display:none}.layout{display:block}}
</style></head>
<body data-case="{{case}}" data-mode="{{mode}}">
<a class="skip" href="#main">Skip to content</a>
<header class="top" role="banner">
 <h1>Tripline Scope · Investigation Workbench</h1>
 <div class="meta" aria-label="Case">
  <span>Case <strong>{{case}}</strong></span>
  <span class="pill" title="Case mode from case.yaml">Mode: {{mode}}</span>
  <span class="pill">Read-only · released reports</span>
 </div>
 <span class="spacer"></span>
 <span class="meta"><span>Signed in: <strong>{{user}}</strong> ({{roles}})</span></span>
 <button type="button" id="signout">Sign out</button>
</header>
<div class="layout">
<nav class="side" aria-label="Workbench sections"><ol>
 <li><a href="#overview" data-section="overview"><span class="letter" aria-hidden="true">A</span>Overview</a></li>
 <li><a href="#timeline" data-section="timeline"><span class="letter" aria-hidden="true">B</span>Timeline</a></li>
 <li><a href="#paths" data-section="paths"><span class="letter" aria-hidden="true">C</span>Access paths</a></li>
 <li><a href="#exposure" data-section="exposure"><span class="letter" aria-hidden="true">D</span>Exposure</a></li>
 <li><a href="#people" data-section="people"><span class="letter" aria-hidden="true">E</span>People</a></li>
 <li><a href="#investigation" data-section="investigation"><span class="letter" aria-hidden="true">F</span>AI Investigator</a></li>
 <li><a href="#reports" data-section="reports"><span class="letter" aria-hidden="true">G</span>Reports</a></li>
</ol><p class="foot">Views of People and AI Investigator are written to the case audit log.</p></nav>
<main id="main" tabindex="-1" aria-live="polite"></main>
</div>
<script nonce="{{nonce}}">
"use strict";
(function(){
const CSRF = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
const main = document.getElementById("main");
const SVGNS = "http://www.w3.org/2000/svg";

/* ---------- DOM helpers: text is always inserted with textContent / text nodes ---------- */
function h(tag, attrs){
  const e = document.createElement(tag);
  setAttrs(e, attrs);
  for (let i = 2; i < arguments.length; i++) add(e, arguments[i]);
  return e;
}
function s(tag, attrs){
  const e = document.createElementNS(SVGNS, tag);
  setAttrs(e, attrs);
  for (let i = 2; i < arguments.length; i++) add(e, arguments[i]);
  return e;
}
function setAttrs(e, attrs){
  if (!attrs) return;
  for (const k of Object.keys(attrs)){
    const v = attrs[k];
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.setAttribute("class", v);
    else if (k === "text") e.textContent = String(v);
    else if (k.slice(0,2) === "on") e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, String(v));
  }
}
function add(e, kid){
  if (kid === null || kid === undefined || kid === false) return;
  if (Array.isArray(kid)) { kid.forEach(k => add(e, k)); return; }
  e.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
}
function clear(e){ while (e.firstChild) e.removeChild(e.firstChild); }

/* ---------- values, statuses and badges ---------- */
const STATUS = {not_determinable:"Not determinable", not_assessed:"Not assessed", awaiting_analysis:"Awaiting analysis",
  not_performed:"Not performed", not_released:"Not released"};
function isStatus(v){ return v && typeof v === "object" && !Array.isArray(v) && typeof v.status === "string" && STATUS[v.status]; }
function missing(text, reason){
  return h("span", {class:"missing", title: reason || null}, h("span", {"aria-hidden":"true"}, "\\u25cb"), text,
    reason ? h("span", {class:"sr-only"}, " (" + reason + ")") : null);
}
function fmtNum(n){ return Number.isInteger(n) ? n.toLocaleString("en-ZA") : String(n); }
function val(v, emptyText){
  if (v === null || v === undefined || v === "") return missing(emptyText || "Not determinable");
  if (isStatus(v)) return missing(STATUS[v.status], v.reason);
  if (typeof v === "number") return fmtNum(v);
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.length ? v.map(x => typeof x === "object" ? JSON.stringify(x) : String(x)).join(", ") : "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
function when(t){ return (typeof t === "string" && t) ? t.replace("T", " ").replace(/Z$/, " UTC") : val(t); }
const BASIS = {observation:["Observed","b-obs","\\u25cf"], inference:["Inferred","b-inf","\\u25d0"],
  hypothesis:["Hypothesis","b-hyp","\\u25c7"], unknown:["Unknown","b-unk","?"], proposal:["Proposal","b-prop","\\u25b7"]};
function basisBadge(b){
  const d = BASIS[b] || BASIS.unknown;
  return h("span", {class:"badge " + d[1], title:"Evidence basis: " + (b || "unknown")}, h("span", {"aria-hidden":"true"}, d[2]), d[0]);
}
const CLASSES = {access_observed:"Access observed", export_or_staging_observed:"Export / staging observed",
  egress_suspected:"Egress suspected", exfiltration_evidenced:"Exfiltration evidenced", undetermined:"Undetermined",
  not_applicable:"Context event", no_access_observed:"No access observed"};
function classBadge(c){
  if (!c) return missing("Not determinable");
  const known = Object.prototype.hasOwnProperty.call(CLASSES, c);
  return h("span", {class:"badge " + (known ? "c-" + c : "c-undetermined"), title:"Consequence class: " + c}, known ? CLASSES[c] : String(c));
}
const EDGES = {direct:["Direct","e-direct"], observed:["Observed","e-observed"], correlated:["Correlated","e-correlated"],
  unresolved:["Unresolved","e-unresolved"]};
function edgeBadge(l){ const d = EDGES[l] || EDGES.unresolved; return h("span", {class:"badge " + d[1]}, d[0]); }
function sevBadge(sv){ return h("span", {class:"badge s-" + (["critical","high","medium","low","info"].indexOf(sv) >= 0 ? sv : "info")}, sv || "unrated"); }
function kv(pairs){
  const dl = h("dl", {class:"kv"});
  pairs.forEach(p => { if (p) { add(dl, h("dt", null, p[0])); add(dl, h("dd", null, p[1] instanceof Node ? p[1] : val(p[1]))); } });
  return dl;
}
function table(caption, cols, rows, opts){
  const t = h("table", null, caption ? h("caption", null, caption) : null);
  const tr = h("tr");
  cols.forEach(c => add(tr, h("th", {scope:"col", class: c.num ? "num" : null}, c.label)));
  add(t, h("thead", null, tr));
  const tb = h("tbody");
  if (!rows.length) add(tb, h("tr", null, h("td", {colspan: cols.length}, (opts && opts.empty) || missing("None recorded"))));
  rows.forEach(r => {
    const row = h("tr");
    cols.forEach(c => { const v = c.get(r); add(row, h("td", {class: c.num ? "num" : null}, v instanceof Node ? v : val(v, c.empty))); });
    add(tb, row);
  });
  add(t, tb);
  return h("div", {class:"tablewrap"}, t);
}
function chips(ids, links){
  if (!ids || !ids.length) return h("span", {class:"muted"}, "—");
  return h("span", {class:"chips"}, ids.map(id => {
    const l = links && links[id];
    if (l && l.section) {
      return h("a", {class:"chip" + (l.found === false ? " nf" : ""), href:"#" + l.section,
        title: (l.module || "?") + " \\u00b7 " + l.type + (l.found === false ? " \\u00b7 not found in the released report" : "")},
        id, l.found === false ? " (not found)" : "");
    }
    return h("code", {class:"chip", title: l ? (l.type + (l.module ? " \\u00b7 " + l.module : "")) : null}, id);
  }));
}
function heading(title, lede){
  const h2 = h("h2", {tabindex:"-1"}, title);
  return [h2, lede ? h("p", {class:"lede"}, lede) : null];
}
function errorBox(msg){ return h("p", {class:"err", role:"alert"}, msg); }

/* ---------- network ---------- */
async function api(path){
  const r = await fetch(path, {credentials:"same-origin", headers:{"Accept":"application/json"}});
  if (r.status === 401) { location.reload(); throw new Error("signed out"); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body && body.error) ? body.error : "HTTP " + r.status);
  return body;
}
document.getElementById("signout").addEventListener("click", async () => {
  await fetch("/logout", {method:"POST", credentials:"same-origin", referrerPolicy:"same-origin", headers:{"X-CSRF-Token": CSRF}});
  location.reload();
});

/* ---------- A. Overview ---------- */
async function renderOverview(root){
  const d = await api("/api/overview");
  add(root, heading("A · Overview", "Case status and what has been released. No overall score is computed."));
  const hold = d.legal_hold || {};
  const ev = d.evidence_state || {};
  add(root, h("div", {class:"grid"},
    h("section", {class:"card", "aria-label":"Case"}, h("h3", null, "Case"), kv([
      ["Case id", d.case_id], ["Mode", d.mode], d.title ? ["Title", d.title] : null,
      ["Incident window", isStatus(d.incident_window) ? val(d.incident_window) : when(d.incident_window.start) + " \\u2192 " + when(d.incident_window.end)],
      ["Case status", d.case_status === "closed" ? "Closed" : "Open"],
      ["Legal hold", hold.active ? "Active" + (hold.set_at ? " since " + when(hold.set_at) : "") : "Not active"],
      ["Synthetic / real", missing("Not shown", "the workbench does not infer whether data is synthetic; see the case mode")]])),
    h("section", {class:"card", "aria-label":"Evidence state"}, h("h3", null, "Evidence state"), kv([
      ["Sources registered", ev.sources_registered],
      ["Latest source received", isStatus(ev.latest_source_received_at) ? ev.latest_source_received_at : when(ev.latest_source_received_at)],
      ["Latest source registered", isStatus(ev.latest_source_registered_at) ? ev.latest_source_registered_at : when(ev.latest_source_registered_at)],
      ["Latest release approved", isStatus(ev.latest_release_approved_at) ? ev.latest_release_approved_at : when(ev.latest_release_approved_at)],
      ["Declared gaps (case)", ev.declared_gaps]])),
    moduleBCard(d.module_b)));
  const kinds = Object.keys(d.reports || {});
  add(root, h("h3", null, "Released reports and approvals"));
  add(root, table(null, [
    {label:"Report", get: k => k},
    {label:"Status", get: k => d.reports[k].status === "released" ? "Released" : d.reports[k]},
    {label:"Versions", get: k => (d.reports[k].released_versions || []).map(n => "v" + n).join(", ") || "—"},
    {label:"Report status", get: k => d.reports[k].report_status || "—"},
    {label:"Approved by", get: k => d.reports[k].approved_by || "—"},
    {label:"Approved at", get: k => d.reports[k].approved_at ? when(d.reports[k].approved_at) : "—"},
    {label:"Unreleased draft", get: k => d.reports[k].draft_present ? "Yes (not shown)" : "No"}], kinds));
  add(root, h("p", {class:"lede"}, d.score_note));
}
function moduleBCard(b){
  const card = h("section", {class:"card", "aria-label":"Module B coverage"}, h("h3", null, "Log coverage (Module B)"));
  if (isStatus(b)) { add(card, val(b)); return card; }
  add(card, kv([
    ["Analysis window", b.window ? when(b.window.start) + " \\u2192 " + when(b.window.end) : missing("Not determinable")],
    ["Log sources", b.sources],
    ["Families present", (b.families_present || []).join(", ") || "—"],
    ["Missing source families", b.missing_source_families.length ? b.missing_source_families.map(m => m.group).join("; ") : "None (all groups have a source)"],
    ["Gaps recorded", b.gaps.total + (b.gaps.total ? " (" + Object.keys(b.gaps.by_kind).map(k => k + ": " + b.gaps.by_kind[k]).join(", ") + ")" : "")],
    ["Sources not complete", b.sources_not_complete.length ? b.sources_not_complete.map(x => x.source_id + " (" + x.completeness + ")").join(", ") : "None reported"],
    ["Not covered by logs", (b.forensic_not_covered || []).join("; ") || "—"]]));
  return card;
}

/* ---------- B. Timeline ---------- */
const TL = {params:{limit:"100", offset:"0"}, facets:null};
async function renderTimeline(root){
  add(root, heading("B · Timeline", "Events from the released Module B timeline (already sanitised: no SQL text, query strings or message text). Filter, then page through. The chart shows only the current page."));
  const form = h("form", {class:"filters", "aria-label":"Timeline filters"});
  const f = (name, label, input) => { input.setAttribute("name", name); input.setAttribute("id", "f-" + name); return h("label", {for:"f-" + name}, label, input); };
  const sel = (opts) => { const e = h("select"); add(e, h("option", {value:""}, "Any")); opts.forEach(o => add(e, h("option", {value:o}, CLASSES[o] || o))); return e; };
  const fac = TL.facets || {families:[], classes:[], sources:[], assets:[]};
  add(form, f("start", "From (UTC, ISO-8601)", h("input", {placeholder:"2026-09-01T00:00:00Z", maxlength:"40"})));
  add(form, f("end", "To (UTC, ISO-8601)", h("input", {placeholder:"2026-09-14T23:59:59Z", maxlength:"40"})));
  add(form, f("source", "Source", sel(fac.sources)));
  add(form, f("family", "Log family", sel(fac.families)));
  add(form, f("account", "Account ref (ACCT-…)", h("input", {placeholder:"ACCT-…", maxlength:"45"})));
  add(form, f("asset", "Asset", sel(fac.assets)));
  add(form, f("class", "Consequence class", sel(fac.classes)));
  const lim = sel([]); clear(lim); ["50","100","200","500"].forEach(v => add(lim, h("option", {value:v}, v)));
  add(form, f("limit", "Rows per page", lim));
  add(form, h("div", {class:"actions"}, h("button", {class:"btn", type:"submit"}, "Apply filters"),
    h("button", {class:"btn sec", type:"reset"}, "Clear")));
  for (const k of Object.keys(TL.params)) { const el = form.elements.namedItem(k); if (el) el.value = TL.params[k]; }
  form.addEventListener("submit", ev => { ev.preventDefault(); const p = {offset:"0"};
    for (const el of form.elements) { if (el.name && el.value) p[el.name] = el.value.trim(); } TL.params = p; route(); });
  form.addEventListener("reset", () => { TL.params = {limit:"100", offset:"0"}; setTimeout(route, 0); });
  add(root, form);
  const qs = new URLSearchParams(TL.params).toString();
  let d;
  try { d = await api("/api/timeline?" + qs); } catch (e) { add(root, errorBox("Could not load the timeline: " + e.message)); return; }
  if (isStatus(d)) { add(root, val(d)); return; }
  if (!TL.facets) { TL.facets = d.facets; clear(root); return renderTimeline(root); }
  const first = d.total ? d.offset + 1 : 0, last = d.offset + d.events.length;
  const pager = h("div", {class:"pager", role:"navigation", "aria-label":"Timeline pages"},
    h("button", {class:"btn sec", type:"button", disabled: d.offset <= 0 ? "disabled" : null,
      onclick: () => { TL.params.offset = String(Math.max(0, d.offset - d.limit)); route(); }}, "\\u2190 Previous"),
    h("span", {"aria-live":"polite"}, "Events " + first + "\\u2013" + last + " of " + fmtNum(d.total)),
    h("button", {class:"btn sec", type:"button", disabled: last >= d.total ? "disabled" : null,
      onclick: () => { TL.params.offset = String(d.offset + d.limit); route(); }}, "Next \\u2192"));
  add(root, pager);
  add(root, laneChart(d.events));
  add(root, table("Events (report order: key events first)", [
    {label:"Time (UTC)", get: e => when(e.ts_utc || e.ts_utc_earliest)},
    {label:"Precision", get: e => e.time_precision + (e.tz_original && e.tz_original !== "Z" ? " · tz " + e.tz_original : "")},
    {label:"Source", get: e => e.source_id + " · " + e.family},
    {label:"Host / asset", get: e => (e.host || "—") + (e.asset_id ? " · " + e.asset_id : "")},
    {label:"Account", get: e => e.account_label ? e.account_label + " (" + e.account_ref + ")" : (e.account_ref || "—")},
    {label:"Operation", get: e => e.operation || e.observation_type},
    {label:"Objects", get: e => e.objects || "—"},
    {label:"Class", get: e => classBadge(e.consequence_class)},
    {label:"Paths / anomalies", get: e => chips((e.path_ids || []).concat(e.anomaly_ids || []))},
    {label:"Event id", get: e => h("code", null, e.event_id)}], d.events, {empty: "No events match these filters."}));
  add(root, h("h3", null, "Logging gaps overlapping this window"));
  add(root, h("p", {class:"lede"}, "A gap means activity during that period cannot be determined from these logs. It is never evidence that nothing happened."));
  add(root, table(null, [
    {label:"Gap", get: g => h("code", null, g.gap_id)}, {label:"Kind", get: g => g.kind},
    {label:"Scope", get: g => [g.scope, g.source_id, g.host, g.database].filter(Boolean).join(" · ")},
    {label:"From", get: g => g.start ? when(g.start) : missing("Not determinable")},
    {label:"To", get: g => g.end ? when(g.end) : missing("Not determinable")},
    {label:"Basis", get: g => basisBadge(g.basis)}, {label:"Description", get: g => g.description}], d.gaps,
    {empty: "No gaps overlap this window."}));
}
function laneChart(events){
  const pts = events.map(e => ({e, t: Date.parse(e.ts_utc || e.ts_utc_earliest)})).filter(p => !isNaN(p.t));
  const wrap = h("figure", {class:"lanes"});
  if (!pts.length) { add(wrap, h("figcaption", null, "No timed events on this page.")); return wrap; }
  const fams = Array.from(new Set(pts.map(p => p.e.family))).sort();
  const t0 = Math.min.apply(null, pts.map(p => p.t)), t1 = Math.max.apply(null, pts.map(p => p.t));
  const W = 1000, L = 120, R = 16, lane = 22, H = fams.length * lane + 34;
  const x = t => L + (t1 === t0 ? (W - L - R) / 2 : (t - t0) / (t1 - t0) * (W - L - R));
  const svgEl = s("svg", {viewBox:"0 0 " + W + " " + H, role:"img", width:"100%", "aria-label":"Events on this page by log family over time"});
  fams.forEach((fm, i) => {
    const y = 14 + i * lane;
    add(svgEl, s("line", {x1:L, x2:W - R, y1:y, y2:y, stroke:"#dbe3ea"}));
    add(svgEl, s("text", {x:4, y:y + 4}, fm));
  });
  pts.forEach(p => {
    const y = 14 + fams.indexOf(p.e.family) * lane;
    const c = p.e.consequence_class;
    const shape = (c === "not_applicable" || c === "no_access_observed")
      ? s("circle", {cx:x(p.t), cy:y, r:3.2, fill:"#fff", stroke:"#475569"})
      : s("rect", {x:x(p.t) - 4, y:y - 4, width:8, height:8, fill: c === "undetermined" ? "#e5e7eb" : "#0b3a5b", stroke:"#0b3a5b"});
    add(shape, s("title", null, (p.e.ts_utc || p.e.ts_utc_earliest) + " \\u00b7 " + p.e.event_id + " \\u00b7 " + (CLASSES[c] || c)));
    add(svgEl, shape);
  });
  add(svgEl, s("text", {x:L, y:H - 6}, new Date(t0).toISOString().replace(".000Z","Z")));
  add(svgEl, s("text", {x:W - R, y:H - 6, "text-anchor":"end"}, new Date(t1).toISOString().replace(".000Z","Z")));
  add(wrap, svgEl);
  add(wrap, h("figcaption", {class:"lede"}, "Squares: events with a data-related class; circles: context events (sign-ins, flows, web requests). Position shows time only, not confidence."));
  return wrap;
}

/* ---------- C. Access paths ---------- */
function lineStyle(label){
  if (label === "correlated") return {stroke:"#b45309", "stroke-width":2.2, "stroke-dasharray":"7 5"};
  if (label === "direct" || label === "observed") return {stroke:"#111827", "stroke-width":2.6};
  return {stroke:"#9ca3af", "stroke-width":2.2, "stroke-dasharray":"2 5", "stroke-linecap":"round"};
}
function legendSample(label, text){
  const sv = s("svg", {width:46, height:12, "aria-hidden":"true"}, s("line", Object.assign({x1:2, x2:44, y1:6, y2:6}, lineStyle(label))));
  return h("span", null, sv, edgeBadge(label), text);
}
const NODE_KIND = {identity:"Identity", network:"Network / VPN", host_application:"Host / application",
  database_host:"Database host", tables:"Table(s)", staging:"Staging", egress:"Egress"};
async function renderPaths(root){
  const d = await api("/api/paths");
  add(root, heading("C · Access paths", "Routes reconstructed by Module B, left to right from identity to egress. Each link carries the label Module B assigned; correlated and unresolved links are never shown as direct."));
  if (isStatus(d)) { add(root, val(d)); return; }
  add(root, h("div", {class:"legend", "aria-label":"Line legend"},
    legendSample("direct", "exact shared identifier"), legendSample("observed", "recorded by that system"),
    legendSample("correlated", "time-window inference"), legendSample("unresolved", "evidence stops here"),
    h("span", null, basisBadge("observation"), basisBadge("inference"), basisBadge("hypothesis"), basisBadge("unknown"))));
  add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "Paths by consequence class"),
      kv(Object.keys(d.paths_by_class).map(k => [CLASSES[k] || k, d.paths_by_class[k]]))),
    h("section", {class:"card"}, h("h3", null, "Sensitive tables by class"),
      kv(Object.keys(d.sensitive_tables_by_class).map(k => [CLASSES[k] || k, d.sensitive_tables_by_class[k]]))),
    h("section", {class:"card"}, h("h3", null, "Links"),
      kv([["Direct links", d.edges_summary.direct], ["Correlated links", d.edges_summary.correlated]]))));
  if (!d.paths.length) add(root, missing("No paths reported"));
  d.paths.forEach(p => add(root, pathCard(p, d.anomalies)));
  add(root, h("h3", null, "Limitations"));
  add(root, h("ul", {class:"plain"}, d.limitations.map(l => h("li", null, l))));
}
function pathCard(p, anomalies){
  const card = h("article", {class:"pathcard", "aria-label":"Path " + p.path_id});
  add(card, h("header", null, h("h3", null, "#" + p.rank + " ", h("code", null, p.path_id)), classBadge(p.consequence_class), basisBadge(p.basis),
    h("span", null, "chain confidence " + val(p.chain_confidence) + " (report value)")));
  add(card, h("p", {class:"statement"}, p.statement || ""));
  const details = h("div", {class:"details", "aria-live":"polite"}, "Select a box or a link (click, or Tab then Enter) to see its evidence.");
  add(card, chainSvg(p, details));
  add(card, details);
  add(card, kv([
    ["Activity", when(p.first_activity) + " \\u2192 " + when(p.last_activity)],
    ["Weakest link", p.chain_confidence_reason],
    ["Tables", h("span", null, p.tables.map(t => h("span", null, h("code", null, t.table), " ", classBadge(t.consequence_class), " ")))],
    ["Anomalies", chips(p.anomaly_ids)], ["Limitations", p.limitations.join("; ") || "—"]]));
  return card;
}
function chainSvg(p, details){
  const n = p.nodes.length, BW = 128, BH = 56, GAP = 50, W = n * BW + (n - 1) * GAP + 20, H = 110;
  const pos = {};
  const svgEl = s("svg", {class:"chain", viewBox:"0 0 " + W + " " + H, role:"group", "aria-label":"Access path " + p.path_id + ", " + n + " steps"});
  p.nodes.forEach((nd, i) => { pos[nd.id] = 10 + i * (BW + GAP); });
  p.edges.forEach(e => {
    if (!(e.from in pos) || !(e.to in pos)) return;
    const x1 = pos[e.from] + BW, x2 = pos[e.to], y = 30 + BH / 2;
    const ln = s("line", Object.assign({x1:x1, x2:x2, y1:y, y2:y}, lineStyle(e.label)));
    const hit = s("rect", {class:"edgehit", x:x1, y:y - 14, width:Math.max(4, x2 - x1), height:28, fill:"transparent", tabindex:"0", role:"button",
      "aria-label":"Link " + e.stage + ": " + e.label});
    const pick = () => showEdge(details, e);
    hit.addEventListener("click", pick);
    hit.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    add(svgEl, ln);
    add(svgEl, s("text", {x:(x1 + x2) / 2, y:y - 8, "text-anchor":"middle", class:"k"}, e.label === "correlated" ? "corr." : (e.label === "unresolved" ? "unres." : e.label)));
    add(svgEl, hit);
  });
  p.nodes.forEach(nd => {
    const x = pos[nd.id];
    const g = s("g", {class:"node k-" + (nd.basis || "unknown"), tabindex:"0", role:"button", "aria-label":(NODE_KIND[nd.kind] || nd.kind) + ": " + nd.label});
    add(g, s("rect", {x:x, y:30, width:BW, height:BH, rx:6}));
    add(g, s("text", {x:x + 8, y:46, class:"k"}, NODE_KIND[nd.kind] || nd.kind));
    const lab = String(nd.label);
    add(g, s("text", {x:x + 8, y:66}, lab.length > 19 ? lab.slice(0, 18) + "\\u2026" : lab));
    add(g, s("title", null, (NODE_KIND[nd.kind] || nd.kind) + ": " + lab));
    const pick = () => { svgEl.querySelectorAll(".node").forEach(x => x.classList.remove("sel")); g.classList.add("sel"); showNode(details, nd); };
    g.addEventListener("click", pick);
    g.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    add(svgEl, g);
  });
  return svgEl;
}
function showNode(details, nd){
  clear(details);
  add(details, h("strong", null, (NODE_KIND[nd.kind] || nd.kind) + " \\u2014 "), nd.label, " ", basisBadge(nd.basis));
  const v = nd.values || {};
  const pairs = [];
  Object.keys(v).forEach(k => {
    if (k === "tables") return;
    if (k === "upstream_accounts") { pairs.push(["Upstream accounts", (v[k] || []).map(a => (a.label || "") + " (" + a.account_ref + ")").join("; ") || "—"]); return; }
    pairs.push([k.replace(/_/g, " "), v[k]]);
  });
  add(details, kv(pairs));
  if (v.tables) {
    add(details, table(null, [{label:"Table", get: t => h("code", null, t.table)}, {label:"Class", get: t => classBadge(t.consequence_class)},
      {label:"Rows logged", num:true, get: t => t.rows_logged}, {label:"Volume", get: t => t.volume || "—"},
      {label:"Evidence", get: t => chips(t.evidence_ids)}], v.tables));
  }
  add(details, h("p", null, "Path evidence (event ids): "), chips(nd.evidence_ids), h("p", null, "Path: ", h("code", null, nd.path_id)));
}
function showEdge(details, e){
  clear(details);
  add(details, h("strong", null, "Link: " + e.stage + " "), edgeBadge(e.label));
  add(details, kv([["Confidence (report value)", e.confidence], ["Reason", e.reason], ["Alternatives considered", e.alternatives],
    ["Units", e.unit_count]]));
  add(details, h("p", null, "Path evidence (event ids): "), chips(e.evidence_ids), h("p", null, "Path: ", h("code", null, e.path_id)));
}

/* ---------- D. Exposure ---------- */
async function renderExposure(root){
  const d = await api("/api/exposure");
  add(root, heading("D · Exposure", "Configuration and data-exposure findings from the released Module A report, with coverage per control."));
  if (isStatus(d)) { add(root, val(d)); return; }
  const sm = d.summary || {};
  add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "Findings by severity"), kv(["critical","high","medium","low","info"].map(k => [sevBadge(k), (sm.by_severity || {})[k]]))),
    h("section", {class:"card"}, h("h3", null, "Findings by control"), kv(Object.keys(sm.by_control || {}).map(k => [k, sm.by_control[k]]))),
    h("section", {class:"card"}, h("h3", null, "Total"), kv([["Findings", sm.findings]]))));
  add(root, h("h3", null, "Coverage per control"));
  add(root, table(null, [{label:"Control", get: c => c[0] + " · " + (c[1].control || "")}, {label:"Status", get: c => c[1].status},
    {label:"Units assessed", num:true, get: c => c[1].assessed_units},
    {label:"Not assessed", get: c => c[1].not_assessed.length ? c[1].not_assessed.map(x => x.unit + ": " + x.reason).join("; ") : "—"},
    {label:"Unavailable", get: c => c[1].unavailable.length ? c[1].unavailable.map(x => x.unit + ": " + x.reason).join("; ") : "—"}],
    Object.keys(d.coverage).map(k => [k, d.coverage[k]])));
  const xr = d.module_b_cross_references || {by_finding:{}};
  add(root, h("h3", null, "Findings"));
  const sevSel = h("select", {id:"sev"}, h("option", {value:""}, "All severities"), ["critical","high","medium","low","info"].map(v => h("option", {value:v}, v)));
  const holder = h("div");
  const draw = () => { clear(holder); const rows = d.findings.filter(f => !sevSel.value || f.severity === sevSel.value);
    add(holder, table(rows.length + " finding(s)", [
      {label:"#", num:true, get: f => f.rank}, {label:"Severity", get: f => sevBadge(f.severity)},
      {label:"Control", get: f => f.control_id}, {label:"Finding", get: f => h("span", null, f.title, h("br"), h("code", {class:"chip"}, f.finding_id))},
      {label:"Asset", get: f => f.asset_id || "—"}, {label:"State", get: f => f.state},
      {label:"Basis", get: f => basisBadge(f.basis)}, {label:"Confidence (report value)", get: f => f.confidence},
      {label:"Suggested fix", get: f => f.suggested_fix || "—"},
      {label:"Module B", get: f => (xr.by_finding[f.finding_id] || []).length ? h("span", {title: xr.label}, chips(xr.by_finding[f.finding_id]), " cross-referenced; not evidence of causation") : "—"}], rows)); };
  sevSel.addEventListener("change", draw);
  add(root, h("p", null, h("label", {for:"sev"}, "Filter: "), sevSel, " ", h("span", {class:"lede"}, "Module B column: " + xr.label + ".")));
  add(root, holder); draw();
}

/* ---------- E. People ---------- */
const TIERS = [["observed_access","Observed access"],["possible_exposure","Possible exposure"],["confirmed_exfiltration","Confirmed exfiltration"],["notification_scope","Notification scope"]];
function tierTable(tiers){
  return table("Scope tiers (each a different evidence threshold)", [
    {label:"Tier", get: t => t[1]}, {label:"People", num:true, get: t => { const x = tiers[t[0]] || {}; return isStatus(x) ? x : ("proposed_count" in x ? x.proposed_count : x.count); }},
    {label:"Bounds", get: t => { const x = tiers[t[0]] || {}; return ("lower" in x) ? val(x.lower) + " \\u2013 " + val(x.upper) : "—"; }},
    {label:"Basis", get: t => basisBadge((tiers[t[0]] || {}).basis)},
    {label:"Explanation", get: t => (tiers[t[0]] || {}).explanation || "—"},
    {label:"Decided by", get: t => t[0] === "notification_scope" ? ((tiers[t[0]] || {}).decided_by || missing("Not decided", "the Information Officer decides")) : "—"}], TIERS);
}
async function renderPeople(root){
  const d = await api("/api/people");
  add(root, heading("E · People", "Counts from the released scope reports. No person-level data is shown here. This view is audited."));
  if (d.status === "awaiting_analysis") { add(root, val(d)); return; }
  const pe = d.preliminary_estimate;
  add(root, h("h3", null, "Preliminary estimate"));
  if (isStatus(pe)) add(root, val(pe)); else add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "People (preliminary, v" + pe.report_version + ")"), kv([
      ["Estimate", pe.people.point], ["Lower bound", pe.people.lower], ["Upper bound", pe.people.upper],
      ["Measured estimate error (%)", pe.measured_error_pct]])),
    h("section", {class:"card"}, h("h3", null, "How it was estimated"), h("p", null, pe.uncertainty || "—"))));
  const r = d.refined;
  add(root, h("h3", null, "Refined count (after matching)"));
  if (isStatus(r)) { add(root, val(r)); return; }
  const c = r.counts;
  add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "Unique people (v" + r.report_version + ")"), kv([["Count", c.unique_people], ["Lower bound", c.bounds.lower], ["Upper bound", c.bounds.upper], ["Bounds", c.bounds.explanation]])),
    h("section", {class:"card"}, h("h3", null, "Notification routes"), kv(Object.keys(c.notification_routes).map(k => [k.replace(/_/g, " "), c.notification_routes[k]]))),
    h("section", {class:"card"}, h("h3", null, "Unresolvable rows"), kv(Object.keys(r.unresolvable_rows.totals).map(k => [k.replace(/_/g, " "), r.unresolvable_rows.totals[k]])))));
  add(root, tierTable(r.scope_tiers));
  add(root, h("h3", null, "People per data category"));
  add(root, table(null, [{label:"Category", get: k => k.replace(/_/g, " ")}, {label:"People", num:true, get: k => c.people_per_category[k]}], Object.keys(c.people_per_category)));
  const m = r.matching;
  add(root, h("h3", null, "Matching"));
  add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "Bands and rules"), kv([["Auto-link band", isStatus(m.bands) ? m.bands : m.bands.auto_link], ["Review band", isStatus(m.bands) ? m.bands : m.bands.review], ["Blocking rules", m.blocking_rules], ["Pending review items", (m.review_queue || {}).items]])),
    h("section", {class:"card"}, h("h3", null, "Measured error rates"), isStatus(r.measured_error_rates) ? val(r.measured_error_rates) :
      kv(Object.keys(r.measured_error_rates).map(k => [k.replace(/_/g, " "), r.measured_error_rates[k]])))));
}

/* ---------- F. AI Investigator ---------- */
async function renderInvestigation(root){
  const d = await api("/api/investigation");
  add(root, heading("F · AI Investigator", null));
  add(root, h("div", {class:"banner advisory", role:"note"}, h("strong", null, "Advisory \\u2014 AI-generated hypotheses, not findings"),
    "Nothing here changes evidence, classifications, counts, scope or notification decisions. Every item was checked by Tripline's deterministic validator and needs human review."));
  if (d.status === "not_performed") { add(root, h("p", null, missing("Not performed", d.reason), " ", d.reason)); return; }
  const run = d.latest_run;
  if (run && !isStatus(run)) {
    if (d.fixture) add(root, h("div", {class:"banner fixture", role:"note"}, h("strong", null, "Deterministic fixture output \\u2014 not AI inference"),
      "Produced by Tripline's rule-based fixture provider (is_model_inference: false) for testing and demonstration."));
    else add(root, h("div", {class:"banner info", role:"note"}, h("strong", null, d.provenance_note)));
    const pv = d.provenance || {};
    add(root, h("div", {class:"grid"},
      h("section", {class:"card"}, h("h3", null, "Run"), kv([["Run id", run.run_id], ["Created", when(run.created_at)], ["Status", run.analysis_status],
        ["Method", run.method_version], ["Validator", run.validator_version],
        ["Inputs", (run.references || []).map(r => r.kind + " v" + r.version).join(", ") || "—"],
        ["Modules not assessed", (run.not_assessed_modules || []).join(", ") || "None"]])),
      h("section", {class:"card"}, h("h3", null, "Provenance"), kv([["Provider", pv.provider], ["Provider kind", pv.provider_kind], ["Model", pv.model_id],
        ["Model version", pv.model_version], ["Model inference", pv.is_model_inference === false ? "No (deterministic)" : val(pv.is_model_inference)], ["Endpoint class", pv.endpoint_class]])),
      h("section", {class:"card"}, h("h3", null, "Validation"), kv([["Verdict", (run.validation || {}).verdict],
        ["Accepted", ((run.validation || {}).counts || {}).accepted], ["Rejected", ((run.validation || {}).counts || {}).rejected],
        ["Unverified", ((run.validation || {}).counts || {}).unverified],
        ["Rejections (codes only)", ((run.validation || {}).rejections || []).map(x => x.item + ": " + (x.codes || []).join("/")).join("; ") || "—"]]))));
    if (run.summary) add(root, h("p", {class:"statement"}, run.summary));
    const links = d.evidence_links || {};
    const decisions = ((run.human_review || {}).decisions) || {};
    add(root, h("h3", null, "Hypotheses"));
    (run.hypotheses || []).forEach(hy => add(root, hypCard(hy, links, decisions[hy.hypothesis_id])));
    if (!(run.hypotheses || []).length) add(root, missing("No accepted hypotheses"));
    add(root, h("h3", null, "Missing evidence"));
    add(root, table(null, [{label:"What is missing", get: m => m.description}, {label:"Source family", get: m => m.source_family || "—"},
      {label:"Related evidence", get: m => chips(m.related_evidence, links)}], run.missing_evidence || []));
    add(root, h("h3", null, "Next investigation steps"));
    add(root, table(null, [{label:"Priority", get: x => x.priority}, {label:"Step", get: x => x.step}, {label:"Evidence", get: x => chips(x.evidence_ids, links)}], run.investigation_steps || []));
    add(root, h("h3", null, "Remediation (advisory)"));
    add(root, table(null, [{label:"Priority", get: x => x.priority}, {label:"Action", get: x => x.action}, {label:"Assets", get: x => (x.asset_ids || []).join(", ") || "—"},
      {label:"Evidence", get: x => chips(x.evidence_ids, links)}], run.remediation || []));
    add(root, h("h3", null, "Unproven assertions"));
    add(root, (run.unproven_assertions || []).length ? h("ul", {class:"plain"}, run.unproven_assertions.map(u => h("li", null, u))) : h("p", null, "None recorded."));
  } else {
    add(root, h("p", null, "Latest validated run: ", val(run)));
  }
  add(root, h("h3", null, "Released investigation report"));
  const rr = d.released_report;
  add(root, isStatus(rr) ? val(rr) : kv([["Version", "v" + rr.report_version], ["Approved by", rr.approved_by], ["Approved at", when(rr.approved_at)],
    ["Report hash", h("code", null, rr.report_sha256)]]));
}
function hypCard(hy, links, decision){
  const card = h("article", {class:"hyp", "aria-label":"Hypothesis " + hy.hypothesis_id});
  add(card, h("header", null, h("h4", null, hy.hypothesis_id + " \\u00b7 " + (hy.rank === "main" ? "Main hypothesis" : "Alternative")),
    basisBadge(hy.basis), classBadge(hy.consequence_class),
    h("span", {class:"badge b-unk", title:"Ordinal label, not a probability"}, "Confidence: " + (hy.confidence || "not stated")),
    decision ? h("span", {class:"badge b-obs"}, "Reviewed: " + decision.decision + " by " + decision.reviewer) : h("span", {class:"badge b-unk"}, "Awaiting human review")));
  add(card, h("p", {class:"statement"}, hy.statement));
  add(card, kv([
    ["Why this confidence", hy.confidence_rationale || "—"],
    ["Supporting evidence", chips(hy.supporting_evidence, links)],
    ["Contradicting evidence", chips(hy.contradicting_evidence, links)],
    ["Assets / sources", ((hy.assets || []).concat(hy.sources || [])).join(", ") || "—"],
    ["Time window", hy.time_window ? when(hy.time_window.start) + " \\u2192 " + when(hy.time_window.end) : missing("Not determinable")],
    ["Quantities quoted", (hy.quantities || []).map(q => q.fact_id + " = " + q.value).join("; ") || "—"],
    ["Alternative explanations", (hy.alternative_explanations || []).join("; ") || "—"],
    ["Tests that would resolve it", (hy.tests || []).map(t => t.evidence_needed + " \\u2192 " + t.would_resolve).join("; ") || "—"],
    ["Cannot conclude", (hy.cannot_conclude || []).join("; ") || "—"],
    ["Validator", ((hy.validation || {}).verdict || "—") + (((hy.validation || {}).codes || []).length ? " (" + hy.validation.codes.join(", ") + ")" : "")],
    decision ? ["Review note", (decision.note || "—") + " · " + when(decision.at)] : null]));
  return card;
}

/* ---------- G. Reports ---------- */
async function renderReports(root, refresh){
  const d = await api("/api/reports" + (refresh ? "?refresh=1" : ""));
  add(root, heading("G · Reports", "Released versions with their hashes, approvals and signature/chain verification. Files open only for released versions."));
  add(root, h("p", null, h("button", {class:"btn sec", type:"button", onclick: () => { clear(main); renderReports(main, true).catch(e => add(main, errorBox(e.message))); }}, "Re-verify signatures and chains")));
  Object.keys(d.kinds).forEach(kind => {
    const k = d.kinds[kind];
    add(root, h("h3", null, kind));
    if (k.status !== "released") { add(root, val(k)); return; }
    const v = k.verification || {};
    add(root, h("p", null, isStatus(v) ? val(v) : (v.ok ? h("span", {class:"ok"}, "\\u2713 Verified: signatures, hashes and chain (" + v.checks + " checks)")
      : h("span", {class:"bad"}, "\\u2717 Verification FAILED: " + (v.failed || []).join("; ")))));
    if (v.render) add(root, h("pre", {class:"render"}, v.render));
    add(root, table(null, [{label:"Version", get: x => "v" + x.version}, {label:"Report SHA-256", get: x => h("code", {title:x.report_sha256}, String(x.report_sha256).slice(0, 16) + "\\u2026")},
      {label:"Approved by", get: x => x.approval.approver}, {label:"Approved at", get: x => when(x.approval.approved_at)},
      {label:"Provider co-signed", get: x => x.provider_cosigned ? "Yes" : "No"}, {label:"Artefacts", num:true, get: x => Object.keys(x.artefacts).length},
      {label:"Files", get: x => h("span", {class:"chips"}, Object.keys(x.files).map(n => h("a", {class:"chip", href:x.files[n], download:""}, n)))}], k.versions));
  });
}

/* ---------- routing ---------- */
const ROUTES = {overview:renderOverview, timeline:renderTimeline, paths:renderPaths, exposure:renderExposure,
  people:renderPeople, investigation:renderInvestigation, reports:renderReports};
async function route(){
  let sec = (location.hash || "#overview").slice(1);
  if (!ROUTES[sec]) sec = "overview";
  document.querySelectorAll("nav.side a").forEach(a => { if (a.dataset.section === sec) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  clear(main);
  const root = h("div");
  try { await ROUTES[sec](root); } catch (e) { add(root, errorBox("Could not load this section: " + e.message)); }
  clear(main); add(main, root);
  const h2 = main.querySelector("h2"); if (h2) h2.focus();
}
window.addEventListener("hashchange", route);
route();
})();
</script></body></html>"""
