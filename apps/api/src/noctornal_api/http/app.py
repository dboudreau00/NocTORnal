"""The FastAPI application factory.

REST under /api/v1, problem+json errors, and the response hardening headers
from the docs/05 checklist. Run it with:

    uvicorn noctornal_api.http.app:app --reload

Environment: DATABASE_URL, NOCTORNAL_TOTP_KEK, and (for evidence) the
MINIO_* variables. Nothing has a default secret.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from noctornal_api import __version__
from noctornal_api.http.errors import install_error_handlers, problem_response
from noctornal_api.http.routers import (
    analytics,
    auth,
    cases,
    evidence,
    graph,
    graphview,
    read,
    search,
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
_UI_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
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

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if request.url.path.startswith("/ui"):
            # Overwrite, not setdefault: the UI must not inherit the API's
            # default-src 'none'.
            response.headers["Content-Security-Policy"] = _UI_CSP
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/healthz", tags=["meta"], include_in_schema=False)
    def healthz() -> dict:
        # No version: an unauthenticated caller does not need the build.
        return {"status": "ok"}

    for router in (auth.router, cases.router, graph.router,
                   evidence.router, search.router, read.router,
                   graphview.router, analytics.router):
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
