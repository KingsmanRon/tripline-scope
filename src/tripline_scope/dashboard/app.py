"""Investigation Workbench: a read-only local web app over a case's released reports, on loopback only.

Security model (that of ``scope/review_app.py``, tightened):

* Sign-in on the page through the installation identity provider (Argon2id, TOTP when enrolled or required for a
  role). A session needs at least one role on the case (operator, reviewer or approver); the roles are stored in
  the session and checked per section.
* Sessions are random tokens in an HttpOnly, SameSite=Strict cookie with a 2 h absolute and 30 min idle expiry,
  kept in memory only. The login form carries a one-time token bound to a cookie; every other POST needs the
  session's CSRF token in ``X-CSRF-Token``. A POST whose ``Origin`` is present and not this server, or whose
  ``Sec-Fetch-Site`` is present and not ``same-origin``/``none``, is refused. (The response header is
  ``Referrer-Policy: no-referrer``; with that policy browsers send ``Origin: null`` on same-origin POSTs, so the
  sign-in page sets an in-document ``same-origin`` referrer policy and the page's POSTs use
  ``referrerPolicy: "same-origin"``: the real origin is sent, and nothing is ever sent to another origin.)
* ``TrustedHostMiddleware`` refuses Host headers other than 127.0.0.1/localhost (DNS rebinding). Every response
  carries a strict CSP (``default-src 'none'``; the page's script runs only by per-response nonce), anti-framing,
  no-store, no-referrer, nosniff and same-origin CORP/COOP headers. No CORS headers are ever sent.
* Read-only: data endpoints are GET only and read released reports (plus the investigator's latest validated
  run). The only writes are in-memory sessions and case audit entries (``dashboard login``, ``dashboard view``).
  Sign-ins (ok/denied) are always audited; views of ``people`` and ``investigation`` on every request; views of
  ``timeline``, ``paths`` and ``exposure`` once per section per session (not per page of a paginated call).
* Nothing exposes the notification pack (``notify/``), drafts, ``work/`` or person-level rows.
"""

from __future__ import annotations

import secrets
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from tripline_scope.core.auth import identity_provider
from tripline_scope.core.errors import ConfigError, TriplineError

from . import data as D
from . import page as P

SESSION_COOKIE = "tscope_dashboard"
LOGIN_COOKIE = "tscope_dashboard_login"
SESSION_ABSOLUTE_SECONDS = 2 * 3600
SESSION_IDLE_SECONDS = 30 * 60
LOGIN_TOKEN_SECONDS = 600
MAX_SESSIONS = 64
MAX_LOGIN_TOKENS = 256
DEFAULT_PORT = 8766
DEFAULT_HOST = "127.0.0.1"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
CASE_ROLES = ("operator", "reviewer", "approver")

# Which case roles may open which section. Every section is open to all three case roles; people and
# investigation are audited on every request.
SECTION_ROLES = {s: set(CASE_ROLES) for s in
                 ("overview", "timeline", "paths", "exposure", "people", "investigation", "reports")}
AUDIT_EVERY_VIEW = {"people", "investigation"}
AUDIT_ONCE_PER_SESSION = {"timeline", "paths", "exposure"}

BASE_CSP = ("default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _clock() -> float:
    """Wall clock for session expiry (tests replace it)."""
    return time.time()


def check_host(host: str | None) -> str:
    """Only literal loopback names are accepted for binding."""
    h = (host or DEFAULT_HOST).strip()
    if h not in LOOPBACK_HOSTS:
        raise ConfigError("the dashboard binds to loopback only: --host must be 127.0.0.1, localhost or ::1")
    return h


def check_port(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise ConfigError("--port must be an integer") from None
    if not 1 <= p <= 65535:
        raise ConfigError("--port must be between 1 and 65535")
    return p


class DashboardState:
    def __init__(self, case, store, home, port: int):
        self.case, self.store, self.home, self.port = case, store, home, port
        self.sessions: dict[str, dict] = {}
        self.login_tokens: dict[str, float] = {}
        self.verified: dict[str, dict] = {}

    def prune(self, now: float) -> None:
        for tok, s in list(self.sessions.items()):
            if self.expired(s, now):
                self.sessions.pop(tok, None)
        for tok, exp in list(self.login_tokens.items()):
            if exp < now:
                self.login_tokens.pop(tok, None)

    @staticmethod
    def expired(s: dict, now: float) -> bool:
        return now - s["created"] > SESSION_ABSOLUTE_SECONDS or now - s["last"] > SESSION_IDLE_SECONDS


def create_app(case, store, home, *, port: int = DEFAULT_PORT, host: str = DEFAULT_HOST) -> FastAPI:
    host = check_host(host)
    st = DashboardState(case, store, home, port)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    allowed_hosts = ["127.0.0.1", "localhost"] + (["[::1]"] if host == "::1" else [])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    if host == "::1":
        allowed_origins.add(f"http://[::1]:{port}")
    app.state.dashboard = st

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            fetch_site = request.headers.get("sec-fetch-site")
            if (origin is not None and origin not in allowed_origins) or (
                    fetch_site is not None and fetch_site not in ("same-origin", "none")):
                return _secure(JSONResponse({"error": "cross-origin request refused"}, status_code=403))
        resp = await call_next(request)
        return _secure(resp)

    def audit(command: str, actor, roles, outcome: str = "ok", **params) -> None:
        case.audit.append(command=command, actor=actor, role=",".join(sorted(roles)) if roles else None,
                          case_id=case.case_id, outcome=outcome, params=params)

    def session(request: Request) -> dict | None:
        tok = request.cookies.get(SESSION_COOKIE) or ""
        s = st.sessions.get(tok)
        if s is None:
            return None
        now = _clock()
        if st.expired(s, now):
            st.sessions.pop(tok, None)
            return None
        s["last"] = now
        return s

    def denied(status: int, msg: str) -> JSONResponse:
        return JSONResponse({"error": msg}, status_code=status)

    def view(request: Request, section: str):
        """Session + role check for a section; returns (session, error response)."""
        s = session(request)
        if s is None:
            return None, denied(401, "sign in")
        if not set(s["roles"]) & SECTION_ROLES[section]:
            audit("dashboard view", s["user"], s["roles"], outcome="denied", section=section)
            return None, denied(403, "your case role does not include this section")
        if section in AUDIT_EVERY_VIEW or (section in AUDIT_ONCE_PER_SESSION and section not in s["viewed"]):
            audit("dashboard view", s["user"], s["roles"], section=section)
            s["viewed"].add(section)
        return s, None

    def ok(payload) -> JSONResponse:
        return JSONResponse(D.scrub(payload))

    def login_page(status: int = 200, error: str | None = None) -> HTMLResponse:
        now = _clock()
        st.prune(now)
        if len(st.login_tokens) >= MAX_LOGIN_TOKENS:
            st.login_tokens.pop(next(iter(st.login_tokens)))
        tok = secrets.token_urlsafe(24)
        st.login_tokens[tok] = now + LOGIN_TOKEN_SECONDS
        resp = HTMLResponse(P.login_html(tok, case.case_id, error), status_code=status)
        resp.set_cookie(LOGIN_COOKIE, tok, httponly=True, samesite="strict", max_age=LOGIN_TOKEN_SECONDS)
        return resp

    # ------------------------------------------------------------------ page and sign-in
    @app.get("/")
    def index(request: Request):
        s = session(request)
        if s is None:
            return login_page()
        nonce = secrets.token_urlsafe(16)
        html = P.page_html(nonce=nonce, csrf=s["csrf"], case_id=case.case_id, mode=case.mode, user=s["user"],
                           roles=s["roles"])
        return HTMLResponse(html, headers={"Content-Security-Policy": f"{BASE_CSP}; script-src 'nonce-{nonce}'"})

    @app.post("/login")
    def login(request: Request, username: str = Form(..., max_length=64), password: str = Form(..., max_length=256),
              csrf: str = Form(..., max_length=128), totp: str = Form("", max_length=12)):
        cookie = request.cookies.get(LOGIN_COOKIE)
        exp = st.login_tokens.pop(csrf, 0)
        if not cookie or not secrets.compare_digest(cookie, csrf) or exp < _clock():
            return login_page(403, "The sign-in form expired. Please try again.")
        try:
            ident = identity_provider(home).authenticate(username, password, totp or None)
        except TriplineError:
            audit("dashboard login", username[:32], None, outcome="denied", reason="authentication")
            return login_page(401, "Sign-in failed.")
        roles = sorted(case.roles_of(ident.username) & set(CASE_ROLES))
        if not roles:
            audit("dashboard login", ident.username, None, outcome="denied", reason="no case role")
            return login_page(403, "You hold no role on this case.")
        required = set(home.config.get("require_totp_roles") or [])
        if required & set(roles) and ident.auth_method != "password+totp":
            audit("dashboard login", ident.username, roles, outcome="denied", reason="totp required")
            return login_page(401, "This installation requires an authenticator code for your role.")
        now = _clock()
        st.prune(now)
        if len(st.sessions) >= MAX_SESSIONS:  # drop the oldest session
            oldest = min(st.sessions, key=lambda t: st.sessions[t]["created"])
            st.sessions.pop(oldest, None)
        tok = secrets.token_urlsafe(32)
        st.sessions[tok] = {"user": ident.username, "roles": roles, "csrf": secrets.token_urlsafe(32),
                            "created": now, "last": now, "viewed": set()}
        audit("dashboard login", ident.username, roles, auth=ident.auth_method)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(SESSION_COOKIE, tok, httponly=True, samesite="strict", max_age=SESSION_ABSOLUTE_SECONDS)
        resp.delete_cookie(LOGIN_COOKIE)
        return resp

    @app.post("/logout")
    def logout(request: Request):
        s = session(request)
        if s is None:
            return denied(401, "sign in")
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            return denied(403, "invalid CSRF token")
        st.sessions.pop(request.cookies.get(SESSION_COOKIE) or "", None)
        resp = JSONResponse({"signed_out": True})
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    # ------------------------------------------------------------------ data (GET only)
    @app.get("/api/overview")
    def api_overview(request: Request):
        s, err = view(request, "overview")
        if err:
            return err
        return ok({**D.overview(case), "user": s["user"], "roles": s["roles"]})

    @app.get("/api/timeline")
    def api_timeline(request: Request):
        s, err = view(request, "timeline")
        if err:
            return err
        params: dict[str, list[str]] = {}
        for k, v in request.query_params.multi_items():
            params.setdefault(k, []).append(v)
        try:
            q = D.parse_timeline_query(params)
        except D.BadRequest as exc:
            return denied(400, str(exc))
        return ok(D.timeline(case, q))

    @app.get("/api/paths")
    def api_paths(request: Request):
        s, err = view(request, "paths")
        return err or ok(D.paths(case))

    @app.get("/api/exposure")
    def api_exposure(request: Request):
        s, err = view(request, "exposure")
        return err or ok(D.exposure(case))

    @app.get("/api/people")
    def api_people(request: Request):
        s, err = view(request, "people")
        return err or ok(D.people(case))

    @app.get("/api/investigation")
    def api_investigation(request: Request):
        s, err = view(request, "investigation")
        return err or ok(D.investigation(case, store))

    @app.get("/api/reports")
    def api_reports(request: Request):
        s, err = view(request, "reports")
        if err:
            return err
        refresh = request.query_params.get("refresh", "0")
        if refresh not in ("0", "1") or set(request.query_params) - {"refresh"}:
            return denied(400, "refresh must be 0 or 1")
        for kind in D.REPORT_KINDS:
            if refresh == "1" or kind not in st.verified:
                st.verified[kind] = D.verification(case, home, kind)
        return ok(D.reports(case, st.verified))

    @app.get("/reports/{kind}/{version}/{name}")
    def report_download(kind: str, version: str, name: str, request: Request):
        s = session(request)
        if s is None:
            return denied(401, "sign in")
        found = D.report_file(case, kind, version, name)
        if found is None:
            return denied(404, "not found")
        path, ctype = found
        headers = {"Content-Disposition": f'attachment; filename="{kind}-{version}-{name}"'}
        return Response(path.read_bytes(), media_type=ctype, headers=headers)

    return app


def _secure(resp: Response) -> Response:
    if "content-security-policy" not in resp.headers:
        resp.headers["Content-Security-Policy"] = BASE_CSP
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    for k in [k for k in resp.headers if k.lower().startswith("access-control-")]:
        del resp.headers[k]
    return resp


def serve(case, store, home, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    import uvicorn

    host, port = check_host(host), check_port(port)
    app = create_app(case, store, home, port=port, host=host)
    shown = "127.0.0.1" if host == "127.0.0.1" else "localhost"
    print(f"investigation workbench: http://{shown}:{port}/  (Ctrl+C to stop)", flush=True)
    uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False,
                                  server_header=False, proxy_headers=False)).run()
