"""The FastAPI application factory: REST under /api/v1, problem+json errors, docs/05 headers.

Run with `uvicorn noctornal_api.http.app:app --reload`. Needs DATABASE_URL, NOCTORNAL_TOTP_KEK
and, for evidence, the MINIO_* variables; nothing has a default secret, and with
NOCTORNAL_ENV=production `create_app` refuses a missing or development one (`config.py`).
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
    collection_authority,  # the two-person collection authority
    collection_telegram,
    comms,
    compartments,
    curation,
    deception,
    dual_control,
    egress,
    evidence,
    governance,
    graph,
    graphview,
    ingest,
    lab_yara,
    integrations,
    live,
    lookups,
    merges,
    notifications,
    proposals,
    providers,
    read,
    reports,
    roles,
    samples,
    search,
    setup,
)
# The persona act queue.
from noctornal_api.http.routers import collection_acts
# Similarity reads and Administration, Embeddings.
from noctornal_api.http.routers import embeddings as embeddings_router
from noctornal_api.http.routers import similarity

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
    """The console's CSP, with the sample origin in `connect-src` when one is configured.

    Invariant 10 puts sample bytes on a second origin, so the Lab pane must be able to fetch it.
    The source is `samples.origin_split().sample`, the same normalised value the download
    compares against and the policy endpoint hands the console, so the three cannot name
    different origins.
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

#: `POST /api/v1/cases/{case_id}/evidence/{evidence_id}/download`, where an exhibit of attacker
#: markup is produced on a ticket. docs/19 section 1.1 sends those bytes out through the sample
#: origin and nowhere else, so this is the second path that origin answers, matched by shape.
_EXHIBIT_DOWNLOAD_PATH = re.compile(
    rf"^{re.escape(API_PREFIX)}/cases/[0-9a-fA-F-]{{36}}"
    rf"/evidence/[0-9a-fA-F-]{{36}}/download$")


def _is_download_path(path: str) -> bool:
    """Either of the two paths that put hostile bytes on a disk, the only
    ones a cross-origin request is ever answered on."""
    return bool(_DOWNLOAD_PATH.match(path) or _EXHIBIT_DOWNLOAD_PATH.match(path))


#: Six hundred seconds: the preflight is one config comparison, and a
#: browser that re-asks every download costs nothing worth caching longer.
_PREFLIGHT_MAX_AGE = "600"


def _allowed_on_sample_origin(request: Request) -> bool:
    """What a process configured as the sample origin will serve.

    The sample origin exists so that no page with an analyst's session runs on it, but this
    process is the same codebase as the application. Serving only the two downloads (a sample,
    and an exhibit of attacker markup, docs/19 section 1.1) and their preflight, the health
    check and the readiness register makes the split a property of the process rather than of
    a proxy allow-list nobody tests. Neither download reads a session; each takes a one-shot
    ticket minted on the application.
    """
    path = request.url.path
    if path == "/healthz":
        return True
    if _is_download_path(path):
        return request.method in ("POST", "OPTIONS")
    return path == f"{API_PREFIX}/admin/readiness" and request.method == "GET"


def _preflight(request: Request) -> Response | None:
    """The answer to the console's CORS preflight, or None when this is not
    one this process answers. `download_cors_headers` decides whether the
    Origin is the configured application origin; this only adds what a
    preflight needs on top of what every download answer carries."""
    if request.method != "OPTIONS" or not _is_download_path(request.url.path):
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
    # First, before anything reads a KEK, a DSN or a bucket credential or binds a port: a
    # production deployment with a missing or development secret is told the whole list here
    # (config.py). Does nothing unless NOCTORNAL_ENV=production.
    enforce_environment()
    # A production process with outbound uses and no egress proxy refuses to start (docs/00
    # decision 68). Only the database knows the uses, so this opens one connection, and only in
    # production with no proxy configured.
    from noctornal_api.egress_routes import enforce_production_egress
    enforce_production_egress()

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
        """Uniform problem+json, built from loc and msg only.

        Pydantic's error entries carry an `input` key holding the offending value, which on
        /auth/login is the submitted password and live TOTP code, bound for every proxy, WAF and
        APM log (docs/05 treats logs as lower-trust than the database). `ctx` and `url` are
        dropped too: `url` discloses the exact pydantic version.
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

    # The closed first-run door, registered first so it is the innermost wrapper, inside the
    # body ceiling too: a closed door answers as an unknown path does before the body is read,
    # or a 413 or a 422 would tell the two apart. Its path is read from the router, so the two
    # cannot drift.
    from noctornal_api.http.setup_token import install_closed_setup_door
    install_closed_setup_door(app, API_PREFIX + next(
        r.path for r in setup.router.routes
        if getattr(r, "endpoint", None) is setup.first_admin))

    # The body ceiling, registered next so it is the innermost wrapper but one: the limiter
    # still counts the request and the 413 still leaves through the security headers.
    from noctornal_api.http.body_ceiling import install_body_ceiling
    install_body_ceiling(app)

    # Registered before _headers, which makes _headers the outer wrapper: the last middleware
    # registered runs first, and a 429 must not leave without nosniff and a CSP.
    install_rate_limit_middleware(app)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        split = origin_split()
        if split.serves_here and not _allowed_on_sample_origin(request):
            # This process is the sample origin and serves only what `_allowed_on_sample_origin`
            # allows. Refused here, outermost: it is one configuration read and needs neither
            # the limiter's Redis round trip nor a route.
            response = problem_response(
                404, "Not found",
                f"this process is the sample origin and serves sample "
                f"downloads and exhibit productions only; the application "
                f"is at {split.app}")
        else:
            response = _preflight(request) or await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if request.url.path.startswith("/ui"):
            # Overwrite, not setdefault: the UI must not inherit the API's
            # default-src 'none'.
            response.headers["Content-Security-Policy"] = ui_csp()
            response.headers["Cache-Control"] = "no-cache"
        if _is_download_path(request.url.path):
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
                   # The compartment vocabulary (0057): the closed set both case creation and
                   # user read-ins are checked against, so a typo cannot become silent no-access.
                   compartments.router,
                   # Which roles hold which permission, so a refusal can name a role, not a code.
                   roles.router,
                   cases.router, graph.router,
                   # Oversight, not case access: `audit.read` is held by SECURITY_OFFICER alone.
                   audit.router,
                   evidence.router, search.router, read.router,
                   graphview.router, analytics.router,
                   proposals.router, merges.router,
                   approvals.router, approvals.policy_router,
                   # Deployment-wide approvals and the two-person policy.
                   approvals.global_router, dual_control.router,
                   # lab_yara.router before samples.router, so no /samples/yara path is read
                   # as a sample id.
                   notifications.router, lab_yara.router, samples.router,
                   # Outbound integrations, lookup providers and lookups.
                   integrations.router, integrations.case_router,
                   providers.router, lookups.router,
                   # The assumptions register (docs/08, 0056): what the report's findings rest
                   # on, listed where they can be challenged.
                   ach.router, assumptions.router, reports.router,
                   comms.router, comms.global_router,
                   governance.router, governance.break_glass_router,
                   # `case_router` is the read path for what the collector writes
                   # (collect.document, collect.watch_hit).
                   collection.router, collection.case_router, ingest.router,
                   # The two-person collection authority (docs/00
                   # decision 69).
                   collection_authority.router,
                   # Telegram chats and personas.
                   collection_telegram.router,
                   # The caller's persona acts.
                   collection_acts.router,
                   # Tags and node sets.
                   curation.router,
                   # Phishing / vishing / BEC evidence (docs/19).
                   deception.router,
                   # The change-hint socket. Carries no case content by
                   # design — see `live.py`; the client refetches through
                   # the gated REST endpoints.
                   live.router,
                   # Where anything may leave: egress profiles, integration routes and the
                   # egress proxy's connection log.
                   egress.router,
                   # Similar wording and meaning, and their administration.
                   similarity.router, embeddings_router.router):
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
