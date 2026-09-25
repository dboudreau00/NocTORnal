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
                 type_: str = "about:blank", headers: dict[str, str] | None = None):
        self.status = status
        self.title = title
        self.detail = detail
        self.type = type_
        # Some refusals are only actionable with a header: a 429 without
        # Retry-After tells a client it is limited but not for how long, so
        # a well-behaved client and a hammering one behave identically.
        self.headers = headers or {}
        super().__init__(detail or title)


def problem_response(status: int, title: str, detail: str | None = None,
                     type_: str = "about:blank",
                     headers: dict[str, str] | None = None) -> JSONResponse:
    body = {"type": type_, "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(status_code=status, content=body,
                        media_type="application/problem+json",
                        headers=headers or None)


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
    # The two-person policy ledger (F9, 2026-09-24).
    "dual_control_change_two_people":
        "a change is proposed and countersigned by two different people",
    "dual_control_policy_change_approval_request_id_key":
        "that approval has already been applied",
}


# Row-level security (S1, 2026-09-25). What a refused write is told.
# The gate should have refused first, so every one of these is a finding:
# it is audited as RLS_REFUSED.
RLS_REFUSED_DETAIL = ("The database refused this change because it would write a "
                      "row you could not read back.")
#: The server's text for a WITH CHECK refusal, in the C locale the runtime
#: role pins (db/init/10-app-role.sh). A permission error on a missing GRANT
#: shares SQLSTATE 42501 and must stay a 500: it is a deployment defect.
_RLS_PREFIX = "new row violates row-level security policy"
SYSTEM_UNAVAILABLE_DETAIL = (
    "This operation needs the system database connection, and this deployment "
    "has not configured a usable one (NOCTORNAL_WORKER_DATABASE_URL). The "
    "readiness register says what to set.")


def is_rls_refusal(exc: BaseException) -> bool:
    """True for a row-level security WITH CHECK refusal on a policied table,
    and for nothing else that carries SQLSTATE 42501."""
    if getattr(exc, "sqlstate", None) != "42501":
        return False
    text = str(exc)
    if not text.startswith(_RLS_PREFIX):
        return False
    from noctornal_api.rls_registry import POLICY
    names = {t.split(".", 1)[1] for t in POLICY}
    return any(f'table "{name}"' in text for name in names)


def _db_cause(exc: Exception, depth: int = 8) -> psycopg.Error | None:
    """The psycopg error underneath `exc`, however deeply it is wrapped.

    WALKS THE CHAIN. This used to look exactly one level down
    (`exc.__cause__`), which was enough for a service that wraps psycopg
    directly and wrong the moment one service wraps another.

    `proposals.py:327` does exactly that:

        except GraphWriteError as exc:
            raise ProposalError(f"could not apply proposal: {exc}") from exc

    so accepting a proposal produced ProposalError -> GraphWriteError ->
    psycopg. The one-level check found a GraphWriteError, concluded there
    was no database cause, and returned `str(exc)` — which by then had the
    raw PQ text interpolated into it twice over. Reproduced against the
    live database: one level sanitised correctly, two levels returned
    `... violates foreign key constraint "node_case_id_fkey" DETAIL: Key
    (case_id)=(…)`.

    Bounded and cycle-guarded: an exception chain is not guaranteed
    acyclic, and this runs on the error path where a hang is least
    affordable.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and depth > 0 and id(cur) not in seen:
        if isinstance(cur, psycopg.Error):
            return cur
        seen.add(id(cur))
        cur = cur.__cause__
        depth -= 1
    return None


def safe_detail(exc: Exception) -> str:
    """A client-safe message for a service error, with a correlation id when
    the underlying cause was a database error.

    PUBLIC, and every router that turns a service error into a `Problem`
    must use it instead of `str(exc)`.

    Rule 1 at the top of this file was enforced only for exceptions that
    reached the registered handlers below. A router that CAUGHT a service
    error and re-raised `Problem(400, ..., str(exc))` bypassed all of it —
    and 74 sites across 13 routers did exactly that. Six services
    (`cases`, `graph`, `proposals`, `retention`, `samples`,
    `contact_blocks`) wrap psycopg errors as `XError(str(exc)) from exc`,
    so the raw PQ text — constraint names, the offending column VALUES,
    PL/pgSQL function names and line numbers — was already inside the
    message the router then handed to the client.

    Authored messages pass through untouched: when `__cause__` is not a
    psycopg error this returns `str(exc)` exactly as before. Only the
    DB-wrapped ones are replaced, and their raw text is logged against the
    correlation id that goes back to the caller.
    """
    cause = _db_cause(exc)
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
    if is_rls_refusal(cause):  # S1: row-level security
        return f"{RLS_REFUSED_DETAIL} (ref {cid})"
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
        return problem_response(exc.status, exc.title, exc.detail, exc.type,
                                exc.headers)

    @app.exception_handler(SelectorOwnerConflict)
    async def _conflict(_: Request, exc: Exception):
        # A strong selector already attributed elsewhere — a merge lead.
        return problem_response(409, "Conflict", str(exc))

    @app.exception_handler(CaseError)
    @app.exception_handler(CurationError)
    @app.exception_handler(SelectorError)
    @app.exception_handler(GraphWriteError)
    async def _bad_request(_: Request, exc: Exception):
        return problem_response(400, "Invalid request", safe_detail(exc))

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: Exception):
        # A tamper alarm on the evidence read path.
        return problem_response(409, "Integrity check failed", str(exc))

    @app.exception_handler(EvidenceError)
    async def _evidence(_: Request, exc: Exception):
        return problem_response(400, "Evidence error", safe_detail(exc))

    @app.exception_handler(AccessResolutionError)
    async def _access_resolution(_: Request, exc: Exception):
        # Fail closed: an unresolvable context is a denial, not a 500.
        return problem_response(403, "Forbidden", "access could not be resolved")

    # Row-level security (S1, 2026-09-25).
    from noctornal_api.db import SystemContextUnavailable

    @app.exception_handler(psycopg.errors.InsufficientPrivilege)
    async def _insufficient_privilege(request: Request, exc: Exception):
        """A WITH CHECK refusal is a 403 and an RLS_REFUSED row, written on a
        connection of its own because the request's transaction is aborted.
        Any other 42501 (a missing GRANT) is the 500 it always was."""
        cid = uuid.uuid4().hex[:12]
        if not is_rls_refusal(exc):
            log.exception("unhandled error %s", cid)
            return problem_response(500, "Internal error",
                                    f"unexpected failure (ref {cid})")
        log.warning("row-level security refused a write %s: %s", cid, exc)
        _audit_rls_refused(request, exc, cid)
        return problem_response(403, "Forbidden", f"{RLS_REFUSED_DETAIL} (ref {cid})")

    @app.exception_handler(SystemContextUnavailable)
    async def _no_system_connection(_: Request, exc: Exception):
        log.error("system connection unavailable: %s", exc)
        return problem_response(503, "Service unavailable", SYSTEM_UNAVAILABLE_DETAIL)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        """Catch-all so an unexpected failure is still problem+json with no
        internals — and still carries the security headers.

        ## CR17 (2026-07-26): the headers half of that promise was false

        Starlette routes the `Exception` handler to the OUTERMOST
        `ServerErrorMiddleware`, which sits *above* the `_headers`
        middleware in `app.py`. So an exception with no registered handler
        — a raw `psycopg.Error`, a `TypeError` — propagates up through
        `_headers` and `_blanket` (neither of which catches), is turned
        into a 500 out there, and that response never travels back DOWN
        through the header middleware.

        The result shipped with no CSP, no `nosniff`, no `Referrer-Policy`,
        no `Cache-Control`. The docstring above claimed otherwise and was
        only ever true of the body.

        Stamped explicitly here rather than by restructuring the middleware
        into a pure-ASGI `send()` wrapper: this is the one response class
        that escapes, the fix is local to it, and the alternative touches
        every response in the product to fix the rarest one. `setdefault`
        semantics are preserved by constructing the headers first and
        letting `problem_response` win on any key it sets.
        """
        cid = uuid.uuid4().hex[:12]
        log.exception("unhandled error %s", cid)
        response = problem_response(500, "Internal error",
                                    f"unexpected failure (ref {cid})")
        from noctornal_api.http.app import _SECURITY_HEADERS
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response


def _audit_rls_refused(request: Request, exc: BaseException, cid: str) -> None:
    """The RLS_REFUSED row (S1). Out of band, on a fresh request-role
    connection; never raises, because the answer is already decided."""
    from psycopg.types.json import Json

    from noctornal_api.db import connect_request
    actor = getattr(request.state, "noctornal_user_id", None)
    try:
        with connect_request() as side:
            side.execute(
                """INSERT INTO audit.event
                       (actor_id, actor_kind, action, object_type, object_id,
                        case_id, outcome, detail)
                   VALUES (%s, %s, 'RLS_REFUSED', 'auth', NULL, NULL, 'DENIED', %s)""",
                (actor, "USER" if actor else "SYSTEM",
                 Json({"ref": cid, "path": request.url.path,
                       "method": request.method,
                       "message": str(exc).splitlines()[0][:200]})))
    except psycopg.Error:
        log.exception("could not audit the row-level security refusal %s", cid)
