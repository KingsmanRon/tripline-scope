"""Review page: uncertain pairs, one at a time, keyboard-first, on 127.0.0.1 only.

* Reviewers sign in on the page (Argon2id via the installation identity provider; TOTP when enrolled) and must hold
  the reviewer role on the case. Sessions are random tokens in an HttpOnly, SameSite=Strict cookie; every state
  change needs the session's CSRF token. Host headers other than 127.0.0.1/localhost are refused (DNS rebinding).
* Each pair shows only the fields needed to decide: names, maiden name, date of birth, sex, the source table, and
  for ID number, passport, phone and e-mail a masked value with a same/different/missing indicator. No clinical
  content, addresses or contact details in full.
* Every pair viewed is written to the case audit log (pair key HMAC and reviewer, no values); every decision is
  appended to the encrypted decision log and audited.
* Keys: j / k next / previous, 1 same person, 0 different people, s skip, ? help.
"""

from __future__ import annotations

import html
import secrets
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from tripline_scope.core.auth import identity_provider
from tripline_scope.core.errors import TriplineError
from tripline_scope.core.redact import mask

from . import config as C
from . import data as D
from . import decisions as DEC

SESSION_COOKIE = "tscope_review"
LOGIN_COOKIE = "tscope_login"
SESSION_SECONDS = 4 * 3600
BIND_HOST = "127.0.0.1"


class ReviewState:
    def __init__(self, case, store, home, fields: dict[str, dict] | None = None):
        self.case, self.store, self.home = case, store, home
        self.items = DEC.load_queue(store)
        self.index = {q["pair_key"]: i for i, q in enumerate(self.items)}
        self.sessions: dict[str, dict] = {}
        self.login_tokens: dict[str, float] = {}
        self.fields = fields if fields is not None else self._load_fields()

    def _load_fields(self) -> dict[str, dict]:
        keys = {q["key_l"] for q in self.items} | {q["key_r"] for q in self.items}
        if not keys:
            return {}
        import pyarrow as pa

        data = D.load(self.case, self.store, C.load(self.case), include_dependent=False)
        con = data.con
        try:
            con.register("_k", pa.table({"row_key": sorted(keys)}))
            rows = con.execute("""
                SELECT i.row_key, i.first_disp, i.middle, i.last_disp, i.maiden, i.dob, i.sex, i.sa_id, i.passport,
                       i.phone, i.email, i.postal, t.database, t."table"
                FROM ident i JOIN _k USING (row_key) JOIN src_tables t ON t.t_idx = i.t_idx""").fetchall()
        finally:
            con.close()
        cols = ["row_key", "first", "middle", "last", "maiden", "dob", "sex", "sa_id", "passport", "phone", "email",
                "postal", "database", "table"]
        return {r[0]: dict(zip(cols, r, strict=True)) for r in rows}

    # ------------------------------------------------------------------ views
    def pair_view(self, i: int) -> dict:
        q = self.items[i]
        a, b = self.fields.get(q["key_l"], {}), self.fields.get(q["key_r"], {})

        def ind(f):
            x, y = a.get(f), b.get(f)
            if x is None or y is None:
                return "missing"
            return "same" if x == y else "different"

        def side(r):
            return {"source": f"{r.get('database') or ''} / {r.get('table') or ''}",
                    "first_names": " ".join(x for x in (r.get("first"), r.get("middle")) if x) or "—",
                    "surname": r.get("last") or "—", "maiden_name": r.get("maiden") or "—",
                    "date_of_birth": r["dob"].isoformat() if r.get("dob") else "—", "sex": r.get("sex") or "—",
                    "id_number": mask(r.get("sa_id"), 3) if r.get("sa_id") else "—",
                    "passport": mask(r.get("passport"), 2) if r.get("passport") else "—",
                    "phone": mask(r.get("phone"), 3) if r.get("phone") else "—",
                    "email": mask(r.get("email"), 4) if r.get("email") else "—",
                    "postal_code": r.get("postal") or "—"}

        decided = DEC.latest(self.store).get(q["pair_key"])
        return {"index": i, "total": len(self.items), "pair_key": q["pair_key"], "reason": q["reason"],
                "guard": q.get("guard"), "match_probability": q["match_probability"], "left": side(a), "right": side(b),
                "indicators": {f: ind(f) for f in ("sa_id", "passport", "phone", "email", "dob", "postal")},
                "decision": decided["decision"] if decided else None}


def create_app(case, store, home, *, state: ReviewState | None = None, port: int = 8765):
    st = state or ReviewState(case, store, home)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[BIND_HOST, "localhost"])
    app.state.review = st

    def audit(command, actor, outcome="ok", **params):
        case.audit.append(command=command, actor=actor, role="reviewer", case_id=case.case_id, outcome=outcome,
                          params=params)

    def session(request: Request):
        tok = request.cookies.get(SESSION_COOKIE)
        s = st.sessions.get(tok or "")
        if not s or s["expires"] < time.time():
            return None
        return s

    def headers(nonce: str | None = None) -> dict:
        csp = "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'"
        if nonce:
            csp += f"; script-src 'nonce-{nonce}'"
        return {"Content-Security-Policy": csp, "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}

    @app.get("/")
    def index(request: Request):
        s = session(request)
        if s is None:
            tok = secrets.token_urlsafe(24)
            st.login_tokens[tok] = time.time() + 600
            resp = HTMLResponse(LOGIN_HTML.replace("{{csrf}}", tok).replace("{{case}}", html.escape(case.case_id)),
                                headers=headers())
            resp.set_cookie(LOGIN_COOKIE, tok, httponly=True, samesite="strict", max_age=600)
            return resp
        nonce = secrets.token_urlsafe(16)
        page = (REVIEW_HTML.replace("{{csrf}}", s["csrf"]).replace("{{nonce}}", nonce)
                .replace("{{case}}", html.escape(case.case_id)).replace("{{user}}", html.escape(s["user"])))
        return HTMLResponse(page, headers=headers(nonce))

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form(...),
              totp: str = Form("")):
        cookie = request.cookies.get(LOGIN_COOKIE)
        exp = st.login_tokens.pop(csrf, 0)
        if not cookie or not secrets.compare_digest(cookie, csrf) or exp < time.time():
            return JSONResponse({"error": "invalid form token"}, status_code=403, headers=headers())
        try:
            ident = identity_provider(home).authenticate(username, password, totp or None)
        except TriplineError:
            audit("scope review login", username[:32], outcome="denied")
            return JSONResponse({"error": "sign-in failed"}, status_code=401, headers=headers())
        if "reviewer" not in case.roles_of(ident.username):
            audit("scope review login", ident.username, outcome="denied")
            return JSONResponse({"error": "not a reviewer on this case"}, status_code=403, headers=headers())
        tok = secrets.token_urlsafe(32)
        st.sessions[tok] = {"user": ident.username, "csrf": secrets.token_urlsafe(32),
                            "expires": time.time() + SESSION_SECONDS}
        audit("scope review login", ident.username, auth=ident.auth_method)
        resp = RedirectResponse("/", status_code=303, headers=headers())
        resp.set_cookie(SESSION_COOKIE, tok, httponly=True, samesite="strict", max_age=SESSION_SECONDS)
        resp.delete_cookie(LOGIN_COOKIE)
        return resp

    @app.post("/logout")
    def logout(request: Request):
        s = session(request)
        if s is not None and secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            st.sessions.pop(request.cookies.get(SESSION_COOKIE), None)
        resp = RedirectResponse("/", status_code=303, headers=headers())
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @app.get("/api/item/{i}")
    def item(i: int, request: Request):
        s = session(request)
        if s is None:
            return JSONResponse({"error": "sign in"}, status_code=401, headers=headers())
        if not st.items:
            return JSONResponse({"index": 0, "total": 0}, headers=headers())
        if not 0 <= i < len(st.items):
            return JSONResponse({"error": "no such item"}, status_code=404, headers=headers())
        view = st.pair_view(i)
        audit("scope review view", s["user"], pair=view["pair_key"])
        return JSONResponse(view, headers=headers())

    @app.post("/api/decide")
    async def decide(request: Request):
        s = session(request)
        if s is None:
            return JSONResponse({"error": "sign in"}, status_code=401, headers=headers())
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            audit("scope review decide", s["user"], outcome="denied", reason="csrf")
            return JSONResponse({"error": "invalid CSRF token"}, status_code=403, headers=headers())
        body = await request.json()
        pk, decision = str(body.get("pair_key", "")), body.get("decision")
        if pk not in st.index or decision not in DEC.VALID:
            return JSONResponse({"error": "unknown pair or decision"}, status_code=400, headers=headers())
        DEC.append(store, [DEC.entry(st.items[st.index[pk]], decision, s["user"], "review_page")])
        audit("scope review decide", s["user"], pair=pk, decision=decision)
        return JSONResponse({"recorded": True}, headers=headers())

    return app


def serve(case, store, home, *, port: int = 8765) -> None:
    import uvicorn

    app = create_app(case, store, home, port=port)
    print(f"review page: http://{BIND_HOST}:{port}/  (Ctrl+C to stop)")
    uvicorn.Server(uvicorn.Config(app, host=BIND_HOST, port=int(port), log_level="warning", access_log=False,
                                  server_header=False)).run()


LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Review sign-in</title>
<style>body{font:15px system-ui,sans-serif;margin:3em auto;max-width:28em}label{display:block;margin:.6em 0}
input{font-size:1em;width:100%;padding:.3em}</style></head><body>
<h1>Review uncertain matches</h1><p>Case {{case}}. Reviewers sign in with their Tripline account.</p>
<form method="post" action="/login"><input type="hidden" name="csrf" value="{{csrf}}">
<label>User name <input name="username" autocomplete="username" autofocus required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<label>Authenticator code (if enrolled) <input name="totp" inputmode="numeric" autocomplete="one-time-code"></label>
<button type="submit">Sign in</button></form></body></html>"""

REVIEW_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Review — {{case}}</title>
<style>body{font:15px system-ui,sans-serif;margin:1.5em}table{border-collapse:collapse;margin:1em 0}
td,th{border:1px solid #9aa5b1;padding:.35em .7em;text-align:left}th{background:#e8ecf1}
.same{color:#05631b}.different{color:#a3141a}.missing{color:#666}#help{display:none;background:#fffbe6;padding:.5em}
kbd{border:1px solid #999;border-radius:3px;padding:0 .3em}</style></head><body>
<header>Case {{case}} · reviewer {{user}} · <span id="pos"></span> · <span id="status"></span></header>
<main id="pair" aria-live="polite"></main>
<p><kbd>1</kbd> same person · <kbd>0</kbd> different people · <kbd>s</kbd> skip · <kbd>j</kbd>/<kbd>k</kbd> next/previous ·
<kbd>?</kbd> help</p>
<div id="help" role="dialog">Compare the two records. Decide <b>same person</b> (1) only when you are confident;
<b>different people</b> (0) when they are not; <b>skip</b> (s) to leave it for someone else. Every pair you open is
written to the audit log. Values are masked where the comparison indicator is enough.</div>
<script nonce="{{nonce}}">
const csrf = "{{csrf}}"; let i = 0, total = 0, cur = null;
const F = [["source","Source"],["first_names","First names"],["surname","Surname"],["maiden_name","Maiden name"],
 ["date_of_birth","Date of birth"],["sex","Sex"],["id_number","ID number"],["passport","Passport"],["phone","Phone"],
 ["email","E-mail"],["postal_code","Postal code"]];
const IND = {id_number:"sa_id", passport:"passport", phone:"phone", email:"email", date_of_birth:"dob", postal_code:"postal"};
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function load(n){const r = await fetch("/api/item/"+n,{credentials:"same-origin"}); if(!r.ok){return;}
 cur = await r.json(); total = cur.total; i = cur.index||0;
 if(!total){document.getElementById("pair").innerHTML="<p>No pairs waiting for review.</p>";return;}
 let h = "<table><tr><th></th><th>Record A</th><th>Record B</th><th></th></tr>";
 for(const [k,l] of F){const ind = IND[k] ? cur.indicators[IND[k]] : "";
  h += "<tr><th>"+l+"</th><td>"+esc(cur.left[k])+"</td><td>"+esc(cur.right[k])+"</td><td class='"+ind+"'>"+ind+"</td></tr>";}
 h += "</table><p>Match probability "+cur.match_probability+" · reason "+esc(cur.reason)+(cur.guard?" · guard "+esc(cur.guard):"")+
  (cur.decision?" · decided: <b>"+esc(cur.decision)+"</b>":"")+"</p>";
 document.getElementById("pair").innerHTML = h; document.getElementById("pos").textContent = (i+1)+" / "+total;}
async function decide(d){if(!cur||!total)return; const r = await fetch("/api/decide",{method:"POST",credentials:"same-origin",
 headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify({pair_key:cur.pair_key,decision:d})});
 document.getElementById("status").textContent = r.ok ? "recorded: "+d : "not recorded"; if(r.ok && i+1<total) load(i+1);}
document.addEventListener("keydown",e=>{if(e.target.tagName==="INPUT")return;
 if(e.key==="j"&&i+1<total)load(i+1); else if(e.key==="k"&&i>0)load(i-1); else if(e.key==="1")decide("same");
 else if(e.key==="0")decide("different"); else if(e.key==="s")decide("skip");
 else if(e.key==="?"){const h=document.getElementById("help");h.style.display=h.style.display==="block"?"none":"block";}});
load(0);
</script></body></html>"""
