"""The FastAPI application factory.

REST under /api/v1, problem+json errors, and the response hardening headers
from the docs/05 checklist. Run it with:

    uvicorn noctornal_api.http.app:app --reload

Environment: DATABASE_URL, NOCTORNAL_TOTP_KEK, and (for evidence) the
MINIO_* variables. Nothing has a default secret.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError

from noctornal_api import __version__
from noctornal_api.http.errors import install_error_handlers, problem_response
from noctornal_api.http.routers import auth, cases, evidence, graph, search

API_PREFIX = "/api/v1"

# Sent on every response (docs/05 "Transport and headers"). CSP is set here
# for API responses; the app shell's per-request nonce CSP belongs to the
# front end. HSTS is deliberately left to the TLS terminator.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


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
        return response

    @app.get("/healthz", tags=["meta"], include_in_schema=False)
    def healthz() -> dict:
        # No version: an unauthenticated caller does not need the build.
        return {"status": "ok"}

    for router in (auth.router, cases.router, graph.router,
                   evidence.router, search.router):
        app.include_router(router, prefix=API_PREFIX)

    return app


app = create_app()
