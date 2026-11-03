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


_PEOPLE_NAV = ' <li><a href="#people" data-section="people"><span class="letter" aria-hidden="true">E</span>People</a></li>'
_FIN_NAV = (' <li><a href="#financial" data-section="financial"><span class="letter" aria-hidden="true">E</span>'
            'Financial activity</a></li>')
_FOOT = "Views of People and AI Investigator are written to the case audit log."


def page_html(*, nonce: str, csrf: str, case_id: str, mode: str, user: str, roles: list[str],
              profile: str = "healthcare") -> str:
    html = PAGE_HTML
    if profile == "enterprise":
        # the enterprise profile has no patient scoping (Module C): the People section becomes Financial activity
        html = html.replace(_PEOPLE_NAV, _FIN_NAV).replace(
            _FOOT, "Views of Financial activity and AI Investigator are written to the case audit log.")
    return (html.replace("{{nonce}}", _e(nonce)).replace("{{csrf}}", _e(csrf)).replace("{{case}}", _e(case_id))
            .replace("{{mode}}", _e(mode)).replace("{{user}}", _e(user)).replace("{{roles}}", _e(", ".join(roles))))


_CSS_BASE = """
:root{
/* six colour roles, one accent (the navy brand); secondary ink is tinted, never flat grey; no pure black */
--canvas:#eef2f6;--surface:#fff;--surface-2:#f6f8fb;--ink:#142231;--ink-soft:#46586b;--accent:#0b3a5b;--accent-ink:#fff;
--accent-soft:#e3ecf4;--line:#d3dce6;--line-strong:#a9b8c8;
--muted:var(--ink-soft);--panel:var(--surface);--bg:var(--canvas);--brand:var(--accent);--focus:var(--accent);
--warn-bg:#fff7e6;--warn:#7a4b00;--bad:#9b1c1c;--ok:#166534;
/* 4px spacing scale */
--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:20px;--s6:24px;--s7:32px;--s8:40px;--s9:48px;--s10:64px;
--gutter:clamp(16px,2.4vw,32px);--measure:68ch;
/* one radius scale; three elevations tinted to the ink hue; a 1px edge light on raised surfaces */
--r-sm:4px;--r:8px;--e1:0 1px 2px rgba(20,34,49,.06),0 1px 1px rgba(20,34,49,.04);
--e2:0 2px 6px rgba(20,34,49,.08),0 1px 2px rgba(20,34,49,.06);--e3:0 10px 28px rgba(20,34,49,.14),0 2px 6px rgba(20,34,49,.08);
--edge:inset 0 1px 0 rgba(255,255,255,.9);
--ease-out:cubic-bezier(.23,1,.32,1);--t-fast:140ms;
--font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}html,body{margin:0;padding:0}
html{-webkit-text-size-adjust:100%;scrollbar-color:var(--line-strong) var(--canvas);accent-color:var(--accent)}
body{font:14px/1.5 var(--font);color:var(--ink);background:var(--canvas);caret-color:var(--accent);
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
::selection{background:#bfd4e6;color:var(--ink)}
a{color:#0b4f80;text-decoration-thickness:1px;text-underline-offset:.18em}
a:hover{color:var(--accent);text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:var(--r-sm)}
:focus:not(:focus-visible){outline:none}
h2[tabindex]:focus,main:focus{outline:none}
.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap}
.muted{color:var(--ink-soft)}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition-duration:1ms!important;animation:none!important}}
"""

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="data:,">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="same-origin">
<title>Investigation Workbench · sign in</title>
<style>""" + _CSS_BASE + """
body{min-height:100vh;display:grid;place-items:start center;padding:12vh var(--gutter) var(--s9)}
main{width:100%;max-width:26rem;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);
padding:var(--s7) var(--s7) var(--s6);box-shadow:var(--e2),var(--edge)}
.brand{margin:0 0 var(--s1);font-size:.8rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft)}
h1{font-size:1.45rem;line-height:1.15;letter-spacing:-.015em;margin:0 0 var(--s3);color:var(--accent);text-wrap:balance}
main>p{margin:0 0 var(--s4);text-wrap:pretty}
label{display:block;margin:var(--s4) 0 var(--s1);font-weight:600}
input{font:inherit;width:100%;padding:10px 12px;border:1px solid var(--line-strong);border-radius:var(--r-sm);background:var(--surface);color:var(--ink);
transition:border-color var(--t-fast) var(--ease-out),box-shadow var(--t-fast) var(--ease-out)}
input:focus-visible{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,58,91,.22)}
button{margin-top:var(--s6);width:100%;font:inherit;font-weight:650;padding:11px var(--s5);border:0;border-radius:var(--r-sm);
background:var(--accent);color:var(--accent-ink);cursor:pointer;box-shadow:var(--e1);transition:background-color var(--t-fast) var(--ease-out),transform 100ms var(--ease-out)}
@media (hover:hover) and (pointer:fine){button:hover{background:#082d47}}
button:active{transform:scale(.98)}
.err{background:#fdecec;color:var(--bad);border:1px solid #f3b4b4;padding:var(--s2) var(--s3);border-radius:var(--r-sm);margin:0 0 var(--s3)}
.note{color:var(--ink-soft);font-size:.9em;margin:var(--s5) 0 0;padding-top:var(--s4);border-top:1px solid var(--line);text-wrap:pretty}</style></head><body>
<main><p class="brand">Tripline Scope</p><h1>Investigation Workbench</h1>
<p>Case <strong>{{case}}</strong>. Sign in with your Tripline account. You need a role on this case
(operator, reviewer or approver).</p>{{error}}
<form method="post" action="/login"><input type="hidden" name="csrf" value="{{csrf}}">
<label for="u">User name</label><input id="u" name="username" autocomplete="username" autofocus required maxlength="64">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required maxlength="256">
<label for="t">Authenticator code (if enrolled)</label><input id="t" name="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="12">
<button type="submit">Sign in</button></form>
<p class="note">Read-only view of released reports on this computer only. Sign-ins and views of sensitive
sections are written to the case audit log.</p></main></body></html>"""

PAGE_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="data:,">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{csrf}}">
<title>{{case}} · Investigation Workbench</title>
<style>""" + _CSS_BASE + """
.skip{position:absolute;left:-999px;top:var(--s2);background:var(--surface);color:var(--accent);padding:var(--s2) var(--s3);border-radius:var(--r-sm);z-index:20;box-shadow:var(--e2)}
.skip:focus{left:var(--s2)}
/* header: one band, sticky so case and signed-in user stay visible on long sections */
header.top{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:var(--s3) var(--s5);flex-wrap:wrap;
background:var(--accent);color:var(--accent-ink);padding:var(--s2) var(--gutter);min-height:52px;box-shadow:0 1px 0 rgba(0,0,0,.12)}
header.top :focus-visible{outline-color:#fff}
header.top h1{font-size:.98rem;margin:0;font-weight:650;letter-spacing:-.005em;white-space:nowrap}
header.top h1 .sub{font-weight:450;color:#c9d9e8}
header.top .meta{display:flex;gap:var(--s2) var(--s3);flex-wrap:wrap;align-items:center;font-size:.88rem;color:#dbe7f2}
header.top .meta strong{color:#fff;font-weight:600}
header.top .pill{border:1px solid rgba(255,255,255,.38);border-radius:999px;padding:1px 10px;line-height:1.6;white-space:nowrap}
header.top .spacer{flex:1}
header.top button{font:inherit;font-size:.88rem;font-weight:600;background:transparent;color:#fff;border:1px solid rgba(255,255,255,.55);
border-radius:var(--r-sm);padding:5px 14px;cursor:pointer;white-space:nowrap;transition:background-color var(--t-fast) var(--ease-out),transform 100ms var(--ease-out)}
@media (hover:hover) and (pointer:fine){header.top button:hover{background:rgba(255,255,255,.14)}}
header.top button:active{transform:scale(.97)}
.layout{display:grid;grid-template-columns:224px minmax(0,1fr);min-height:calc(100vh - 52px)}.layout>*{min-width:0}
/* section navigation: the letters A-G are the section ids the reports and docs refer to */
nav.side{background:var(--surface-2);border-right:1px solid var(--line);padding:var(--s4) var(--s3)}
nav.side ol{list-style:none;margin:0;padding:0;position:sticky;top:68px;display:grid;gap:2px}
nav.side a{display:flex;gap:var(--s3);align-items:center;padding:7px var(--s3);border-radius:var(--r-sm);color:var(--ink);text-decoration:none;font-weight:550;
transition:background-color var(--t-fast) var(--ease-out),color var(--t-fast) var(--ease-out)}
nav.side a .letter{display:inline-flex;flex:none;width:22px;height:22px;align-items:center;justify-content:center;border-radius:var(--r-sm);
background:var(--surface);border:1px solid var(--line);font-size:.75rem;font-weight:650;color:var(--ink-soft);font-variant-numeric:tabular-nums}
@media (hover:hover) and (pointer:fine){nav.side a:hover{background:var(--accent-soft)}}
nav.side a[aria-current=page]{background:var(--accent);color:var(--accent-ink);box-shadow:var(--e1)}
nav.side a[aria-current=page] .letter{color:var(--accent);border-color:transparent}
nav.side .foot{margin:var(--s6) 0 0;padding:var(--s4) var(--s3) 0;border-top:1px solid var(--line);font-size:.8rem;line-height:1.5;color:var(--ink-soft);position:sticky;top:420px}
main{padding:var(--s6) var(--gutter) var(--s10);min-width:0;max-width:1480px}
.col{min-width:0}#integrity{padding:var(--s4) var(--gutter) 0}#integrity:empty{display:none}
/* type ramp: tracking tightens as size grows; more space above a heading than below it */
main h2{font-size:1.6rem;line-height:1.15;letter-spacing:-.018em;font-weight:680;margin:0 0 var(--s2);color:var(--accent);text-wrap:balance}
main h3{font-size:1.02rem;line-height:1.3;letter-spacing:-.005em;font-weight:650;margin:var(--s8) 0 var(--s3);text-wrap:balance}
main h4{line-height:1.3}
.lede{color:var(--ink-soft);margin:0 0 var(--s6);max-width:var(--measure);text-wrap:pretty}
p{text-wrap:pretty}
/* cards: content-height, never stretched into empty white blocks */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--s4);align-items:start;margin:var(--s4) 0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:var(--s4) var(--s5);min-width:0;box-shadow:var(--e1),var(--edge)}
.card h3{margin:0 0 var(--s3);font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-soft);font-weight:650}
dl.kv{display:grid;grid-template-columns:minmax(8em,max-content) minmax(0,1fr);gap:6px var(--s4);margin:0}
dl.kv dt{color:var(--ink-soft)}dl.kv dd{margin:0;overflow-wrap:anywhere}
/* tables: tabular numerals, sticky header, opaque ids never break mid-identifier */
table{border-collapse:separate;border-spacing:0;width:100%;background:var(--surface);font-size:.92rem}
caption{text-align:left;font-weight:650;padding:0 0 var(--s2);color:var(--ink)}
th,td{border-bottom:1px solid var(--line);padding:var(--s2) var(--s3);text-align:left;vertical-align:top}
th{background:var(--surface-2);font-weight:650;font-size:.82rem;color:var(--ink-soft);position:sticky;top:0;z-index:1;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
@media (hover:hover) and (pointer:fine){tbody tr:hover td{background:#f8fafc}}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
code.id{font:12.5px/1.5 var(--mono);white-space:nowrap;color:var(--ink)}td>code:only-child{white-space:nowrap}
.tablewrap{position:relative;overflow:auto;border:1px solid var(--line);border-radius:var(--r);max-height:65vh;margin:0 0 var(--s4);background:var(--surface);box-shadow:var(--e1)}
/* evidence badges: colour plus border style, so the label never depends on colour alone */
.badge{display:inline-flex;align-items:center;gap:4px;border:1px solid;border-radius:var(--r-sm);padding:0 7px;font-size:.78rem;font-weight:600;white-space:nowrap;line-height:1.7;vertical-align:baseline}
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
.missing{display:inline-flex;gap:4px;align-items:center;color:var(--warn);background:var(--warn-bg);border:1px dashed #d4a017;border-radius:var(--r-sm);padding:0 7px;font-size:.88em;font-style:italic;white-space:nowrap}
/* banners: the verdict-bearing element of a section, so it carries the heaviest type on the page after h2 */
.banner{border-radius:var(--r);padding:var(--s4) var(--s5);margin:0 0 var(--s4);border:1px solid;box-shadow:var(--e1)}
.banner strong{display:block;font-size:1.06rem;line-height:1.35;letter-spacing:-.005em;margin-bottom:var(--s1);text-wrap:balance}
.banner.advisory{background:#f6f2ff;border-color:#b9a6e6;color:#2e1065}
.banner.fixture{background:#fff7e6;border-color:#e2b86b;color:#5b3200}
.banner.info{background:#edf3fb;border-color:#9fb6d6;color:#14284b}
.banner.integrity{background:#fdecec;border-color:#d98c8c;color:#5f1111}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin:2px 0}
.chip{font:12px/1.55 var(--mono);background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);padding:0 6px;color:var(--ink);text-decoration:none;white-space:nowrap;
transition:background-color var(--t-fast) var(--ease-out),border-color var(--t-fast) var(--ease-out)}
@media (hover:hover) and (pointer:fine){a.chip:hover{background:var(--accent-soft);border-color:var(--line-strong);color:var(--ink)}}
.chip.nf{border-style:dashed;color:var(--bad)}
code,.mono{font-family:var(--mono);font-size:.9em}
/* forms and buttons: every control has hover, focus-visible, active and disabled */
form.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:var(--s3) var(--s4);background:var(--surface);border:1px solid var(--line);
border-radius:var(--r);padding:var(--s4) var(--s5);margin:0 0 var(--s4);box-shadow:var(--e1)}
form.filters label{display:flex;flex-direction:column;font-size:.82rem;font-weight:600;color:var(--ink-soft);gap:var(--s1)}
input,select{font:inherit;font-size:.92rem;padding:6px 8px;border:1px solid var(--line-strong);border-radius:var(--r-sm);background:var(--surface);color:var(--ink);min-width:0;
transition:border-color var(--t-fast) var(--ease-out),box-shadow var(--t-fast) var(--ease-out)}
input:focus-visible,select:focus-visible{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,58,91,.22)}
button.btn{font:inherit;font-size:.92rem;font-weight:600;padding:7px var(--s4);border-radius:var(--r-sm);border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);
cursor:pointer;white-space:nowrap;transition:background-color var(--t-fast) var(--ease-out),transform 100ms var(--ease-out)}
button.btn.sec{background:var(--surface);color:var(--accent)}
@media (hover:hover) and (pointer:fine){button.btn:hover:not(:disabled){background:#082d47}button.btn.sec:hover:not(:disabled){background:var(--accent-soft)}}
button.btn:active:not(:disabled){transform:scale(.97)}
button.btn:disabled{opacity:.5;cursor:not-allowed}
.actions{display:flex;gap:var(--s2);align-items:end;flex-wrap:wrap}
.pager{display:flex;gap:var(--s3);align-items:center;margin:var(--s3) 0;flex-wrap:wrap;color:var(--ink-soft);font-variant-numeric:tabular-nums}
.pathcard{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:var(--s4) var(--s5);margin:0 0 var(--s4);box-shadow:var(--e1),var(--edge)}
.pathcard header{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:center}
.pathcard header h3{margin:0;font-size:1rem}
svg.chain{width:100%;height:auto;max-height:190px;display:block;margin:var(--s3) 0}
svg .node rect{fill:#fff;stroke:#334155;stroke-width:1.4;transition:stroke var(--t-fast) var(--ease-out)}svg .node.k-unknown rect{stroke:#9ca3af;stroke-dasharray:3 3;fill:#f9fafb}
@media (hover:hover) and (pointer:fine){svg .node:hover rect{stroke:var(--accent);stroke-width:2}}
svg .node:focus rect,svg .node.sel rect{stroke:var(--accent);stroke-width:3}
svg .node,svg .edgehit{cursor:pointer}svg .node:focus,svg .edgehit:focus{outline:none}
svg .edgehit:focus+line,svg .edgehit:focus{stroke:var(--accent)}
svg text{font:11px var(--font);fill:#142231}svg text.k{fill:#46586b;font-size:9.5px;text-transform:uppercase;letter-spacing:.04em}
.details{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);padding:var(--s3) var(--s4);margin:var(--s2) 0 var(--s3)}
.legend{display:flex;flex-wrap:wrap;gap:var(--s3) var(--s5);align-items:center;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:var(--s3) var(--s5);margin:0 0 var(--s4);box-shadow:var(--e1)}
.legend span{display:inline-flex;flex-wrap:wrap;gap:var(--s2);align-items:center}
.lanes{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);margin:var(--s3) 0;padding:var(--s1);box-shadow:var(--e1)}
/* hypotheses: framed by the dotted Hypothesis badge and a tinted top band, not a thick coloured side rule */
.hyp{background:var(--surface);border:1px solid #cdbff0;border-radius:var(--r);padding:var(--s4) var(--s5);margin:0 0 var(--s4);box-shadow:var(--e1),inset 0 3px 0 #e4dafb}
.hyp header{display:flex;flex-wrap:wrap;gap:var(--s2);align-items:center}.hyp h4{margin:0;font-size:1.02rem;letter-spacing:-.005em}
.statement{font-size:1rem;line-height:1.55;margin:var(--s3) 0 var(--s4);max-width:var(--measure)}
ul.plain{margin:var(--s1) 0;padding-left:1.2em}ul.plain li+li{margin-top:var(--s1)}
.err{background:#fdecec;color:var(--bad);border:1px solid #f3b4b4;padding:var(--s2) var(--s3);border-radius:var(--r-sm)}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
pre.render{white-space:pre-wrap;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-sm);padding:var(--s3);font-size:.85em;max-height:20em;overflow:auto}
/* phone: the header compresses and section navigation becomes one horizontal strip instead of three wrapped rows */
@media (max-width:860px){
 header.top{position:static;gap:var(--s2) var(--s3);padding:var(--s3) var(--gutter)}
 header.top h1 .sub{display:none}
 header.top .meta.who{order:3;width:100%}
 .layout{grid-template-columns:minmax(0,1fr)}
 nav.side{position:sticky;top:0;z-index:9;padding:var(--s2) 0;border-right:0;border-bottom:1px solid var(--line);background:rgba(246,248,251,.97)}
 nav.side ol{position:static;display:flex;gap:var(--s1);overflow-x:auto;padding:0 var(--gutter);scrollbar-width:none;scroll-snap-type:x proximity}
 nav.side ol::-webkit-scrollbar{display:none}
 nav.side li{flex:none;scroll-snap-align:start}
 nav.side a{padding:6px 10px;white-space:nowrap}
 nav.side .foot{display:none}
 main{padding:var(--s5) var(--gutter) var(--s9)}
 main h2{font-size:1.35rem}
 .grid{grid-template-columns:1fr}
 dl.kv{grid-template-columns:minmax(7em,40%) minmax(0,1fr)}
 .card,.pathcard,.hyp,.banner{padding:var(--s3) var(--s4)}
}
@media print{nav.side,header.top button,form.filters{display:none}header.top{position:static}.layout{display:block}
 .card,.pathcard,.hyp,.banner,.tablewrap,.legend{box-shadow:none}.tablewrap{max-height:none;overflow:visible}}
</style></head>
<body data-case="{{case}}" data-mode="{{mode}}">
<a class="skip" href="#main">Skip to content</a>
<header class="top" role="banner">
 <h1>Tripline Scope <span class="sub">· Investigation Workbench</span></h1>
 <div class="meta" aria-label="Case">
  <span>Case <strong>{{case}}</strong></span>
  <span class="pill" title="Case mode from case.yaml">Mode: {{mode}}</span>
  <span class="pill">Read-only · released reports</span>
 </div>
 <span class="spacer"></span>
 <span class="meta who"><span>Signed in: <strong>{{user}}</strong> ({{roles}})</span></span>
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
<div class="col"><div id="integrity"></div>
<main id="main" tabindex="-1" aria-live="polite"></main></div>
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
  not_performed:"Not performed", not_released:"Not released", not_applicable:"Not applicable", integrity_failure:"INTEGRITY FAILURE \u2014 not shown"};
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
const OPAQUE_ID = /^[A-Z]{2,6}-[A-Za-z0-9]{6,32}$/;
function table(caption, cols, rows, opts){
  const t = h("table", null, caption ? h("caption", null, caption) : null);
  const tr = h("tr");
  cols.forEach(c => add(tr, h("th", {scope:"col", class: c.num ? "num" : null}, c.label)));
  add(t, h("thead", null, tr));
  const tb = h("tbody");
  if (!rows.length) add(tb, h("tr", null, h("td", {colspan: cols.length}, (opts && opts.empty) || missing("None recorded"))));
  rows.forEach(r => {
    const row = h("tr");
    cols.forEach(c => { const v = c.get(r);
      // an opaque case-keyed id (ACCT-, FSN-, TXN-, AF-, ...) is one token: render it whole, never broken mid-identifier
      const cell = (typeof v === "string" && OPAQUE_ID.test(v)) ? h("code", {class:"id"}, v) : (v instanceof Node ? v : val(v, c.empty));
      add(row, h("td", {class: c.num ? "num" : null}, cell)); });
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
function integrityBox(d){
  return h("div", {class:"banner integrity", role:"alert"}, h("strong", null, "\u26a0 " + (d.warning || "INTEGRITY FAILURE")),
    d.reason ? h("span", null, "Detail: " + d.reason) : null);
}
function showAlerts(alerts){
  const box = document.getElementById("integrity");
  clear(box);
  (alerts || []).forEach(a => add(box, integrityBox(a)));
}

/* ---------- network ---------- */
async function api(path){
  const r = await fetch(path, {credentials:"same-origin", headers:{"Accept":"application/json"}});
  if (r.status === 401) { location.reload(); throw new Error("signed out"); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body && body.error) ? body.error : "HTTP " + r.status);
  showAlerts(body.integrity_alerts);
  if (body.status === "integrity_failure") { const e = new Error(body.warning); e.integrity = body; throw e; }
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
      ["Profile", d.profile === "enterprise" ? "Enterprise (financial-system investigation)" : "Healthcare"],
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
  try { d = await api("/api/timeline?" + qs); } catch (e) { add(root, e.integrity ? integrityBox(e.integrity) : errorBox("Could not load the timeline: " + e.message)); return; }
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
    add(svgEl, s("text", {x:(x1 + x2) / 2, y:y - 8, "text-anchor":"middle", class:"k"}, ({correlated:"corr.", unresolved:"unres.", observed:"obs."})[e.label] || e.label));
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
    const review = {label:"Review", get: x => { const r = decisions[x.item_id];
      return r ? h("span", {class:"badge b-obs"}, r.decision + " by " + r.reviewer) : h("span", {class:"badge b-unk"}, "Not reviewed \u2014 not approved"); }};
    add(root, h("h3", null, "Missing evidence"));
    add(root, table(null, [{label:"What is missing", get: m => m.description}, {label:"Source family", get: m => m.source_family || "—"},
      {label:"Related evidence", get: m => chips(m.related_evidence, links)}, review], run.missing_evidence || []));
    add(root, h("h3", null, "Next investigation steps"));
    add(root, table(null, [{label:"Priority", get: x => x.priority}, {label:"Step", get: x => x.step}, {label:"Evidence", get: x => chips(x.evidence_ids, links)}, review], run.investigation_steps || []));
    add(root, h("h3", null, "Remediation (advisory)"));
    add(root, table(null, [{label:"Priority", get: x => x.priority}, {label:"Action", get: x => x.action}, {label:"Assets", get: x => (x.asset_ids || []).join(", ") || "—"},
      {label:"Evidence", get: x => chips(x.evidence_ids, links)}, review], run.remediation || []));
    add(root, h("h3", null, "Unproven assertions"));
    add(root, (run.unproven_assertions || []).length ? h("ul", {class:"plain"}, run.unproven_assertions.map(u =>
      typeof u === "string" ? h("li", null, u) : h("li", null, u.text || "", u.item_id ? " " : null, u.item_id ? h("code", {class:"chip"}, u.item_id) : null))) : h("p", null, "None recorded."));
  } else if (run && run.status === "integrity_failure") {
    add(root, integrityBox(run));
  } else {
    add(root, h("p", null, "Latest validated run: ", val(run)));
  }
  add(root, h("h3", null, "Released investigation report"));
  const rr = d.released_report;
  add(root, rr && rr.status === "integrity_failure" ? integrityBox(rr) : isStatus(rr) ? val(rr) : kv([["Version", "v" + rr.report_version], ["Approved by", rr.approved_by], ["Approved at", when(rr.approved_at)],
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

/* ---------- E (enterprise). Financial activity ---------- */
const IMPACT = {settlement_corroborated:"Settlement corroborated by an independent record",
  released_or_posted_not_settled:"Released or posted; settlement not corroborated",
  initiated_not_released:"Initiated; release not shown", attempted_and_stopped:"Attempted and stopped",
  not_determinable:"Not determinable", no_suspicious_transaction_in_available_evidence:"No suspicious transaction in the supplied evidence",
  no_suspicious_session_identified:"No suspicious session identified"};
const FCAT = {settled_corroborated:"Settled (independent record)", reversed:"Reversed", posted:"Posted (settlement not corroborated)",
  released_not_posted:"Released, not posted", approved_not_released:"Approved, not released", pending_approval:"Pending approval",
  initiated:"Initiated", rejected_or_stopped:"Rejected or stopped", undetermined:"Undetermined (contradictory or incomplete)"};
function linkBadge(l){ return (l && l.label === "none_observed") ? missing("None observed", l.reason) : h("span", {title: l ? l.reason : ""}, edgeBadge(l ? l.label : "unresolved")); }
async function renderFinancial(root){
  const d = await api("/api/financial");
  add(root, heading("E · Financial activity", "From the released financial report (enterprise profile). Evidence categories, not findings of fraud or blame. A payment counts as settled only when an independent settlement record carries the same reference, amount and currency. This view is audited."));
  if (isStatus(d)) { add(root, val(d)); return; }
  const imp = d.financial_impact || {};
  add(root, h("div", {class:"banner info", role:"note"}, h("strong", null, "Financial impact: " + (IMPACT[imp.status] || imp.status || "—")), imp.statement || ""));
  const c = d.counts || {};
  add(root, h("div", {class:"grid"},
    h("section", {class:"card"}, h("h3", null, "Evidence-backed counts"), kv([["Application sessions", c.sessions], ["Suspicious sessions", c.suspicious_sessions],
      ["Transactions", c.transactions], ["Suspicious transactions", c.suspicious_transactions], ["Linked to sessions with privilege evidence (account and time)", c.linked_to_sessions_with_privilege_evidence],
      ["Rejected or stopped", c.rejected_or_stopped], ["Release attempts blocked", c.release_attempts_blocked], ["Verified ledger postings", c.ledger_posting_verified],
      ["Settlement corroborated (independent record)", c.settled_corroborated], ["  of which no ledger posting recorded", c.settled_corroborated_without_ledger_posting], ["Unresolved", c.unresolved]])),
    h("section", {class:"card"}, h("h3", null, "Suspicious amounts by category"), (d.suspicious_amounts || []).length
      ? kv(d.suspicious_amounts.map(x => [FCAT[x.category] || x.category, x.display])) : h("p", null, "None recorded."),
      h("p", {class:"lede"}, "Per currency; never converted or added across currencies."))));
  add(root, h("h3", null, "Identity and privileged access"));
  add(root, table(null, [{label:"Session", get: s => h("code", null, s.session_id)}, {label:"Account", get: s => h("code", null, s.account_ref)},
    {label:"Type", get: s => s.account_type}, {label:"Identity", get: s => linkBadge(s.links.identity)},
    {label:"Remote access", get: s => linkBadge(s.links.remote_access)}, {label:"Host logon", get: s => linkBadge(s.links.host_logon)},
    {label:"Privilege", get: s => linkBadge(s.links.privilege)}, {label:"Suspicion reasons", get: s => (s.suspicious_reasons || []).map(r => r.replace(/_/g, " ")).join("; ") || "—"},
    {label:"Transactions", get: s => chips(s.transactions, null)}], (d.sessions || []).filter(s => s.suspicious_reasons.length || s.transactions.length).slice(0, 60)));
  add(root, h("p", {class:"lede"}, d.sessions_total + " application session(s) in total; sessions without suspicion reasons or transactions are not listed."));
  add(root, table("Privilege events (observed)", [{label:"Event", get: p => h("code", null, p.pev_id)}, {label:"Kind", get: p => p.kind.replace(/_/g, " ")},
    {label:"Account", get: p => p.account_ref || missing("Unresolved", "the record names a member Tripline could not map to an account")},
    {label:"Host", get: p => p.host || "—"}, {label:"Time", get: p => when(p.ts)}], d.privilege_events || []));
  add(root, h("h3", null, "Transactions"));
  add(root, table(null, [{label:"Transaction", get: t => h("code", null, t.transaction_id)},
    {label:"Evidence category", get: t => FCAT[t.category] || t.category}, {label:"Amount", get: t => t.amount},
    {label:"Suspicious", get: t => t.suspicious ? h("span", {class:"badge s-high"}, "Suspicious") : "—"},
    {label:"Approval indicators", get: t => (t.approval_indicators || []).map(r => r.replace(/_/g, " ")).join("; ") || "—"},
    {label:"Independent settlement", get: t => t.independent_settlement ? "Yes" : "No"},
    {label:"Contradictions / missing", num:true, get: t => t.contradictions + " / " + t.missing}], (d.transactions || []).slice(0, 100)));
  add(root, h("h3", null, "Evidence gaps"));
  add(root, table(null, [{label:"Gap", get: g => h("code", null, g.gap_id)}, {label:"Kind", get: g => g.kind.replace(/_/g, " ")},
    {label:"Description", get: g => g.description}, {label:"Period", get: g => g.start ? when(g.start) + " \u2192 " + when(g.end) : "—"}], d.gaps || []));
  const ex = d.exposure || {};
  add(root, h("h3", null, "Credential and privilege exposure (Module A)"));
  add(root, h("p", {class:"lede"}, ex.note || ""));
  add(root, table(null, [{label:"Finding", get: f => h("code", null, f.finding_id)}, {label:"Rule", get: f => f.rule_id}, {label:"Severity", get: f => sevBadge(f.severity)},
    {label:"Account", get: f => f.account_ref || "—"}, {label:"Seen in financial activity", get: f => f.account_in_financial_activity ? "Yes" : "No"}], ex.findings || []));
  const cont = d.containment || {};
  add(root, h("h3", null, "Containment considerations (advisory, not executed)"));
  add(root, h("p", {class:"lede"}, cont.notice || ""));
  add(root, table(null, [{label:"Item", get: r => h("code", null, r.rec_id)}, {label:"Priority", get: r => r.priority}, {label:"Action", get: r => r.action}],
    cont.recommendations || []));
}

/* ---------- G. Reports ---------- */
async function renderReports(root, refresh){
  const d = await api("/api/reports" + (refresh ? "?refresh=1" : ""));
  add(root, heading("G · Reports", "Released versions with their hashes, approvals and signature/chain verification. Files open only for released versions."));
  add(root, h("p", null, h("button", {class:"btn sec", type:"button", onclick: () => { clear(main); renderReports(main, true).catch(e => add(main, errorBox(e.message))); }}, "Re-verify signatures and chains")));
  Object.keys(d.kinds).forEach(kind => {
    const k = d.kinds[kind];
    add(root, h("h3", null, kind));
    if (k.status === "integrity_failure") {
      add(root, integrityBox(k));
      if (k.verification && k.verification.render) add(root, h("pre", {class:"render"}, k.verification.render));
      return;
    }
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
  people:renderPeople, investigation:renderInvestigation, reports:renderReports, financial:renderFinancial};
async function route(){
  let sec = (location.hash || "#overview").slice(1);
  if (!ROUTES[sec]) sec = "overview";
  document.querySelectorAll("nav.side a").forEach(a => {
    if (a.dataset.section === sec) {
      a.setAttribute("aria-current", "page");
      // on a phone the section list is one horizontal strip: keep the current section in view (no page scroll)
      const strip = a.closest("ol");
      if (strip && strip.scrollWidth > strip.clientWidth) a.scrollIntoView({block:"nearest", inline:"center"});
    } else a.removeAttribute("aria-current");
  });
  clear(main);
  const root = h("div");
  try { await ROUTES[sec](root); } catch (e) {
    if (!root.querySelector("h2")) {
      const a = document.querySelector('nav.side a[data-section="' + sec + '"]');
      add(root, heading(a ? a.querySelector(".letter").textContent + " \u00b7 " + a.lastChild.textContent : sec, null));
    }
    add(root, e.integrity ? integrityBox(e.integrity) : errorBox("Could not load this section: " + e.message));
  }
  clear(main); add(main, root);
  const h2 = main.querySelector("h2"); if (h2) h2.focus();
}
window.addEventListener("hashchange", route);
route();
})();
</script></body></html>"""
