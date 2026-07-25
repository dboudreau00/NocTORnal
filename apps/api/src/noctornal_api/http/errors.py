"""problem+json error model (RFC 9457 / docs/02).

Every error the API emits is application/problem+json so clients get a
machine-readable, uniform shape. Domain exceptions map to problems here, in
ONE place.

Two rules adversarial review forced into this file:

1. **Never stringify a database exception into a client-visible message.**
   psycopg's str() is the raw PQ error, which carries DETAIL/CONTEXT lines:
   constraint names, offending column values, and PL/pgSQL function names
   and line numbers. Those describe the schema and echo case data. Service
   errors that wrap a DB error are replaced with a fixed, analyst-facing
   catalogue entry chosen by SQLSTATE/constraint, and the raw text is logged
   server-side against a correlation id.
2. **Never echo submitted input.** Pydantic's error list includes an
   `input` key holding the offending value — on the login endpoint that is
   the submitted password and live TOTP code, which would land in every
   proxy and APM access log. Only `loc` and `msg` are returned.
"""
from __future__ import annotations

import logging
import uuid

import psycopg
from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger("noctornal.api")


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


# SQLSTATE / constraint → analyst-facing text. Anything unmatched becomes a
# generic message; the raw error is logged, never returned.
_SQLSTATE_MESSAGES = {
    "23503": "a referenced record does not exist",
    "23505": "that record already exists",
    "23514": "the request violates a data rule",
    "22001": "a value is too long",
    "22P02": "a value is malformed",
}
_CONSTRAINT_MESSAGES = {
    "node_node_type_fkey": "unknown node type",
    "edge_edge_type_fkey": "unknown edge type",
    "selector_selector_type_fkey": "unknown selector type",
    "case_code_key": "that case code is already in use",
    "case_retention_sane": "retention date must be after creation",
    "assertion_inference_needs_rationale":
        "an inference-based assertion requires a rationale",
}


def _safe_detail(exc: Exception) -> str:
    """A client-safe message for a service error, with a correlation id when
    the underlying cause was a database error."""
    cause = exc.__cause__ if isinstance(exc.__cause__, psycopg.Error) else None
    if cause is None and isinstance(exc, psycopg.Error):
        cause = exc
    if cause is None:
        # Raised by our own code with an authored message — safe to return.
        return str(exc)
    cid = uuid.uuid4().hex[:12]
    log.warning("db error %s: %s", cid, cause, exc_info=cause)
    constraint = getattr(getattr(cause, "diag", None), "constraint_name", None)
    if constraint and constraint in _CONSTRAINT_MESSAGES:
        return f"{_CONSTRAINT_MESSAGES[constraint]} (ref {cid})"
    sqlstate = getattr(cause, "sqlstate", None)
    if sqlstate in _SQLSTATE_MESSAGES:
        return f"{_SQLSTATE_MESSAGES[sqlstate]} (ref {cid})"
    # A plpgsql RAISE (e.g. the ontology/TLP/invariant triggers) carries an
    # authored first line; take only that, never DETAIL/CONTEXT.
    if sqlstate == "P0001" or sqlstate == "23514":
        first = str(cause).splitlines()[0].strip()
        return f"{first} (ref {cid})"
    return f"the request could not be completed (ref {cid})"


def install_error_handlers(app) -> None:
    from noctornal_api.cases import CaseError
    from noctornal_api.curation import CurationError
    from noctornal_api.evidence import EvidenceError, IntegrityError
    from noctornal_api.graph import GraphWriteError
    from noctornal_api.security.access import AccessResolutionError
    from noctornal_api.selectors import SelectorError, SelectorOwnerConflict

    @app.exception_handler(Problem)
    async def _problem(_: Request, exc: Problem):
        return problem_response(exc.status, exc.title, exc.detail, exc.type)

    @app.exception_handler(SelectorOwnerConflict)
    async def _conflict(_: Request, exc: Exception):
        # A strong selector already attributed elsewhere — a merge lead.
        return problem_response(409, "Conflict", str(exc))

    @app.exception_handler(CaseError)
    @app.exception_handler(CurationError)
    @app.exception_handler(SelectorError)
    @app.exception_handler(GraphWriteError)
    async def _bad_request(_: Request, exc: Exception):
        return problem_response(400, "Invalid request", _safe_detail(exc))

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: Exception):
        # A tamper alarm on the evidence read path.
        return problem_response(409, "Integrity check failed", str(exc))

    @app.exception_handler(EvidenceError)
    async def _evidence(_: Request, exc: Exception):
        return problem_response(400, "Evidence error", _safe_detail(exc))

    @app.exception_handler(AccessResolutionError)
    async def _access_resolution(_: Request, exc: Exception):
        # Fail closed: an unresolvable context is a denial, not a 500.
        return problem_response(403, "Forbidden", "access could not be resolved")

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        """Catch-all so an unexpected failure is still problem+json with no
        internals — a bare 500 would also bypass the security headers."""
        cid = uuid.uuid4().hex[:12]
        log.exception("unhandled error %s", cid)
        return problem_response(500, "Internal error",
                                f"unexpected failure (ref {cid})")
