"""The FastAPI application factory.

REST under /api/v1, problem+json errors, and the response hardening headers
from the docs/05 checklist. Run it with:

    uvicorn noctornal_api.http.app:app --reload

Environment: DATABASE_URL, NOCTORNAL_TOTP_KEK, and (for evidence) the
MINIO_* variables. Nothing has a default secret. With
NOCTORNAL_ENV=production `create_app` refuses to build on a missing or
development one -- see `noctornal_api.config`.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from noctornal_api import __version__
from noctornal_api.config import enforce_environment
from noctornal_api.http.errors import install_error_handlers, problem_response
from noctornal_api.http.limits import build_limiter, install_rate_limit_middleware
from noctornal_api.samples import download_cors_headers, origin_split
from noctornal_api.http.routers import (
    ach,
    admin,
    analytics,
    assumptions,
    audit,
    approvals,
    auth,
    cases,
    collection,
    comms,
    compartments,
    curation,
    deception,
    evidence,
    governance,
    graph,
    graphview,
    ingest,
    live,
    merges,
    notifications,
    proposals,
    read,
    reports,
    samples,
    search,
    setup,
)

API_PREFIX = "/api/v1"

# Sent on every response (docs/05 "Transport and headers"). HSTS is
# deliberately left to the TLS terminator.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

# The UI needs to load its own stylesheet, script and canvas images, so the
# API's "default-src 'none'" cannot apply to it. Everything is same-origin
# and there is deliberately NO 'unsafe-inline': the UI ships separate .css
# and .js files precisely so inline script stays forbidden (docs/05).
_UI_CSP_DIRECTIVES = (
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
)
#: The policy with no sample origin configured. Kept as one string because
#: the UI-invariant tests assert the served header against it byte for
#: byte, and because it is what every deployment without a sample origin
#: gets: nothing below adds a source the split has not been configured for.
_UI_CSP = "; ".join(_UI_CSP_DIRECTIVES)


def ui_csp() -> str:
    """The console's CSP, with the sample origin in `connect-src` when one
    is configured.

    Invariant 10 puts sample bytes on a second origin, and until 2026-09-09
    this policy was `connect-src 'self'` unconditionally -- so the Lab
    pane could fetch the application origin and nothing else, and the
    only configuration under which its download button worked was the
    sample origin being the application origin, which is the one the
    invariant forbids. The CSP and the download check were two halves
    that were internally consistent and wrong together. The source added
    here is `samples.origin_split().sample`, the same normalised value the
    download compares against and the same one the policy endpoint hands
    the console, so the three cannot name different origins.
    """
    sample = origin_split().sample
    if not sample:
        return _UI_CSP
    return "; ".join(
        f"connect-src 'self' {sample}" if d == "connect-src 'self'" else d
        for d in _UI_CSP_DIRECTIVES)


#: `POST /api/v1/samples/{id}/download`, the one path a cross-origin
#: request is ever answered on. Matched by shape rather than by routing so
#: the preflight can be answered before FastAPI would 405 an OPTIONS on a
#: POST-only route.
_DOWNLOAD_PATH = re.compile(
    rf"^{re.escape(API_PREFIX)}/samples/[0-9a-fA-F-]{{36}}/download$")

#: Six hundred seconds: the preflight is one config comparison, and a
#: browser that re-asks every download costs nothing worth caching longer.
_PREFLIGHT_MAX_AGE = "600"


def _allowed_on_sample_origin(request: Request) -> bool:
    """What a process configured as the sample origin will serve.

    The sample origin exists so that no page with an analyst's session
    runs on it. This process is the same codebase as the application, so
    left to itself it would serve the console, every case route and the
    login form at the sample hostname -- and an analyst who signed in there
    would put a session exactly where the split says none may be. Serving
    only the download (and its preflight), the load balancer's health
    check and the readiness register makes the split a property of the
    process rather than of a proxy allow-list nobody tests. Until
    2026-09-09 docs/16 C9 asked a human to confirm this by hand.
    """
    path = request.url.path
    if path == "/healthz":
        return True
    if _DOWNLOAD_PATH.match(path):
        return request.method in ("POST", "OPTIONS")
    return path == f"{API_PREFIX}/admin/readiness" and request.method == "GET"


def _preflight(request: Request) -> Response | None:
    """The answer to the console's CORS preflight, or None when this is not
    one this process answers. `download_cors_headers` decides whether the
    Origin is the configured application origin; this only adds what a
    preflight needs on top of what every download answer carries."""
    if request.method != "OPTIONS" or not _DOWNLOAD_PATH.match(request.url.path):
        return None
    cors = download_cors_headers(request.headers.get("origin"))
    if not cors:
        return None
    return Response(status_code=204, headers={
        **cors,
        "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Headers": "authorization",
        "Access-Control-Max-Age": _PREFLIGHT_MAX_AGE,
    })


STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    # First statement in the factory, before the FastAPI object exists,
    # before the limiter is built and before anything has read a KEK, a
    # DSN or a bucket credential: a production deployment configured with
    # a development secret or a missing one is told the whole list here,
    # rather than discovering it one failed analyst action at a time
    # (config.py). Does nothing unless NOCTORNAL_ENV=production, so this
    # line is invisible to a laptop, to CI and to every test in the suite.
    #
    # The router imports at the top of this module have already run by the
    # time anything calls this, so "earliest possible" means earliest
    # inside the factory. That is the right side of the line that matters:
    # nothing has bound a port or touched a secret yet.
    enforce_environment()

    # The schema publishes the full route inventory and every request/response
    # shape of a law-enforcement case system, so it is OFF unless explicitly
    # enabled. (The strict CSP below also blocks Swagger's CDN bundle, so the
    # page was never usable in-browser anyway.)
    docs_enabled = os.environ.get("NOCTORNAL_ENABLE_DOCS", "").lower() in {"1", "true"}
    app = FastAPI(
        title="NocTORnal API",
        version=__version__,
        description="HUMINT / social network analysis platform for cybercrime "
                    "investigation. Every graph write carries an assertion; every "
                    "case-scoped request passes the five-part access gate.",
        docs_url=f"{API_PREFIX}/docs" if docs_enabled else None,
        redoc_url=f"{API_PREFIX}/redoc" if docs_enabled else None,
        openapi_url=f"{API_PREFIX}/openapi.json" if docs_enabled else None,
    )

    install_error_handlers(app)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        """Uniform problem+json, built from loc + msg ONLY.

        Pydantic's error entries include an `input` key holding the offending
        value — on /auth/login with a missing field that is the submitted
        password and live TOTP code, which would then sit in every proxy,
        WAF and APM access log (docs/05 treats logs as lower-trust than the
        database). `ctx`/`url` are dropped too: `url` discloses the exact
        pydantic version.
        """
        parts = [
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg', '')}"
            for e in exc.errors()
        ]
        return problem_response(422, "Validation failed", "; ".join(parts))

    # The limiter belongs to THIS app, not to the module: two apps in one
    # test process must not share meters, or one test's burst fails the
    # next test's first request.
    app.state.limiter = build_limiter()

    # Registered BEFORE _headers, which makes _headers the outer wrapper.
    # Order matters for a reason that is easy to get backwards: the last
    # middleware registered runs first, so registering the limiter last
    # would let a 429 return without ever passing through the security
    # headers. A refusal is exactly the response an attacker sees most of,
    # and it should not be the one served without nosniff and a CSP.
    install_rate_limit_middleware(app)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        split = origin_split()
        if split.serves_here and not _allowed_on_sample_origin(request):
            # This process is the sample origin. It serves sample bytes and
            # nothing else -- see `_allowed_on_sample_origin`. Answered
            # here, outermost, because the refusal is one configuration
            # read and needs neither the limiter's Redis round trip nor a
            # route.
            response = problem_response(
                404, "Not found",
                f"this process is the sample origin and serves sample "
                f"downloads only (invariant 10); the application is at "
                f"{split.app}")
        else:
            response = _preflight(request) or await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if request.url.path.startswith("/ui"):
            # Overwrite, not setdefault: the UI must not inherit the API's
            # default-src 'none'.
            response.headers["Content-Security-Policy"] = ui_csp()
            response.headers["Cache-Control"] = "no-cache"
        if _DOWNLOAD_PATH.match(request.url.path):
            # On every answer the download path gives -- the bytes, a 401,
            # a 404, the limiter's 429 -- so the console can read the
            # refusal as well as the archive. Empty unless this process is
            # the sample origin and the Origin is the application's.
            for key, value in download_cors_headers(
                    request.headers.get("origin")).items():
                response.headers[key] = value
        return response

    @app.get("/healthz", tags=["meta"], include_in_schema=False)
    def healthz() -> dict:
        # No version: an unauthenticated caller does not need the build.
        return {"status": "ok"}

    for router in (auth.router,
                   # The first-run door (open only while iam.app_user is
                   # empty) and the analyst-admin surface behind
                   # user.manage.
                   setup.router, admin.router,
                   # The compartment vocabulary (0057): the closed set
                   # both case creation and user read-ins are checked
                   # against. Free text until 2026-09-02, and a typo in
                   # it was silent no-access.
                   compartments.router,
                   cases.router, graph.router,
                   # Oversight, not case access: `audit.read` is held by
                   # SECURITY_OFFICER alone, and the chain had no verifier
                   # at all until 2026-07-26.
                   audit.router,
                   evidence.router, search.router, read.router,
                   graphview.router, analytics.router,
                   proposals.router, merges.router,
                   approvals.router, approvals.policy_router,
                   notifications.router, samples.router,
                   # The assumptions register (docs/08 Phase 6, 0056):
                   # what the report's findings rest on, listed where
                   # they can be challenged. Nothing until 2026-09-02.
                   ach.router, assumptions.router, reports.router,
                   comms.router, comms.global_router,
                   governance.router, governance.break_glass_router,
                   # `case_router` is the read path: the collector wrote
                   # collect.document and collect.watch_hit from the start
                   # and nothing read them until 2026-08-10.
                   collection.router, collection.case_router, ingest.router,
                   # Tags and node sets: schema and service since
                   # 0009, no router until 2026-07-26.
                   curation.router,
                   # Phishing / vishing / BEC evidence (docs/19).
                   deception.router,
                   # The change-hint socket. Carries no case content by
                   # design — see `live.py`; the client refetches through
                   # the gated REST endpoints.
                   live.router):
        app.include_router(router, prefix=API_PREFIX)

    # The analyst UI: plain HTML/CSS/JS, no build step, same origin as the
    # API so no CORS surface is opened. Mounted last so it cannot shadow an
    # API route. html=True serves index.html for /ui/.
    if STATIC_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def _root() -> RedirectResponse:
            return RedirectResponse("/ui/")

    return app


app = create_app()
