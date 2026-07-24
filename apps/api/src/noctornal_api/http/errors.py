"""problem+json error model (RFC 9457 / docs/02).

Every error the API emits is a application/problem+json body so clients get
a machine-readable, uniform shape. Domain exceptions from the service layer
map to problems here in ONE place, so a service that raises never leaks a
stack trace or a raw SQL error to the client.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class Problem(Exception):
    def __init__(self, status: int, title: str, detail: str | None = None,
                 type_: str = "about:blank"):
        self.status = status
        self.title = title
        self.detail = detail
        self.type = type_
        super().__init__(detail or title)


def problem_response(status: int, title: str, detail: str | None = None,
                     type_: str = "about:blank") -> JSONResponse:
    body = {"type": type_, "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(status_code=status, content=body,
                        media_type="application/problem+json")


def install_error_handlers(app) -> None:
    from noctornal_api.cases import CaseError
    from noctornal_api.curation import CurationError
    from noctornal_api.evidence import EvidenceError, IntegrityError
    from noctornal_api.graph import GraphWriteError
    from noctornal_api.security.access import AccessResolutionError
    from noctornal_api.selectors import SelectorError

    @app.exception_handler(Problem)
    async def _problem(_: Request, exc: Problem):
        return problem_response(exc.status, exc.title, exc.detail, exc.type)

    # Service-layer validation errors → 400/409/422. These never carry a
    # stack trace to the client; the message is analyst-facing text.
    @app.exception_handler(CaseError)
    @app.exception_handler(CurationError)
    @app.exception_handler(SelectorError)
    @app.exception_handler(GraphWriteError)
    async def _bad_request(_: Request, exc: Exception):
        return problem_response(400, "Invalid request", str(exc))

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: Exception):
        # A tamper alarm on the evidence read path.
        return problem_response(409, "Integrity check failed", str(exc))

    @app.exception_handler(EvidenceError)
    async def _evidence(_: Request, exc: Exception):
        return problem_response(400, "Evidence error", str(exc))

    @app.exception_handler(AccessResolutionError)
    async def _access_resolution(_: Request, exc: Exception):
        # Fail closed: an unresolvable context is a denial, not a 500.
        return problem_response(403, "Forbidden", "access could not be resolved")
