"""problem+json error model (RFC 9457, docs/02): every error the API emits, mapped in one place.

Two rules. Never put a database exception's text in a client-visible message: psycopg's str()
carries constraint names, column values and PL/pgSQL function names, so a wrapped DB error is
replaced by a fixed catalogue entry chosen by SQLSTATE or constraint, and the raw text is
logged against a correlation id. Never echo submitted input: Pydantic's `input` key holds the
offending value (on login, the password and live TOTP code), so only `loc` and `msg` return.
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
    # The two-person policy ledger.
    "dual_control_change_two_people":
        "a change is proposed and countersigned by two different people",
    "dual_control_policy_change_approval_request_id_key":
        "that approval has already been applied",
}


# Row-level security: what a refused write is told. The gate should have refused first, so each
# one is audited as RLS_REFUSED.
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


#: What a request is told when a statement overran the request connection's limit
#: (`db.request_statement_timeout`). 504, not 503: the console retries a 503 by itself, and a
#: statement that overran once will overrun again. The cause is logged against the reference.
STATEMENT_TIMEOUT_DETAIL = (
    "The database did not finish within the time this deployment allows one "
    "statement, so the request was stopped. Ask for less at once (a smaller "
    "page or a tighter filter) or try again when the system is quieter.")


def is_statement_timeout(exc: BaseException) -> bool:
    """True when the database cancelled a statement of this request, whether
    `exc` is the cancellation or a service error that wraps it."""
    return isinstance(_db_cause(exc), psycopg.errors.QueryCanceled)


def statement_timeout_problem(exc: BaseException,
                              request: Request | None = None) -> Problem:
    """The 504 for `exc`, with a reference the log carries the cause under."""
    cid = uuid.uuid4().hex[:12]
    where = f" on {request.method} {request.url.path}" if request is not None else ""
    log.warning("statement timeout %s%s: %s", cid, where, _db_cause(exc))
    return Problem(504, "Gateway timeout", f"{STATEMENT_TIMEOUT_DETAIL} (ref {cid})")


def _db_cause(exc: Exception, depth: int = 8) -> psycopg.Error | None:
    """The psycopg error underneath `exc`, however deeply it is wrapped.

    Walks the whole chain, because services wrap each other (a ProposalError wrapping a
    GraphWriteError wrapping psycopg), and stopping one level down would return raw PQ text.
    Bounded and cycle-guarded: a chain is not guaranteed acyclic, and this runs on the error
    path, where a hang is least affordable.
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
    """A client-safe message for a service error, with a correlation id when the underlying cause
    was a database error.

    Every router that turns a service error into a `Problem` must use this instead of
    `str(exc)`: several services wrap psycopg errors as `XError(str(exc)) from exc`, so the raw
    PQ text is already inside the message. Authored messages pass through untouched; a
    DB-wrapped one is replaced, and its raw text is logged against the correlation id that goes
    back to the caller.
    """
    cause = _db_cause(exc)
    if cause is None:
        # Raised by our own code with an authored message — safe to return.
        return str(exc)
    if isinstance(cause, psycopg.errors.QueryCanceled):
        # Not a 400 about the request: the database ran out of the time one
        # statement is allowed. Raised, because every caller is on its way to
        # a `Problem` and this is the one that is true.
        raise statement_timeout_problem(exc) from exc
    cid = uuid.uuid4().hex[:12]
    log.warning("db error %s: %s", cid, cause, exc_info=cause)
    constraint = getattr(getattr(cause, "diag", None), "constraint_name", None)
    if constraint and constraint in _CONSTRAINT_MESSAGES:
        return f"{_CONSTRAINT_MESSAGES[constraint]} (ref {cid})"
    sqlstate = getattr(cause, "sqlstate", None)
    if sqlstate in _SQLSTATE_MESSAGES:
        return f"{_SQLSTATE_MESSAGES[sqlstate]} (ref {cid})"
    if is_rls_refusal(cause):
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
    from noctornal_api.evidence import (
        EvidenceError, ExhibitUnavailable, IntegrityError, StoreUnavailable)
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

    @app.exception_handler(psycopg.errors.QueryCanceled)
    async def _statement_timeout(request: Request, exc: Exception):
        """A statement overran the request connection's limit, or was cancelled by an operator:
        a clean 504 with a reference, never a 500 and a logged traceback."""
        problem = statement_timeout_problem(exc, request)
        return problem_response(problem.status, problem.title, problem.detail)

    @app.exception_handler(CaseError)
    @app.exception_handler(CurationError)
    @app.exception_handler(SelectorError)
    @app.exception_handler(GraphWriteError)
    async def _bad_request(request: Request, exc: Exception):
        if is_statement_timeout(exc):
            return await _statement_timeout(request, exc)
        return problem_response(400, "Invalid request", safe_detail(exc))

    @app.exception_handler(IntegrityError)
    async def _integrity(_: Request, exc: Exception):
        # A tamper alarm on the evidence read path.
        return problem_response(409, "Integrity check failed", str(exc))

    @app.exception_handler(ExhibitUnavailable)
    async def _exhibit_unavailable(_: Request, exc: Exception):
        # Retention destroyed the bytes, or is destroying them now: a plain answer, never a
        # tamper alarm. The sentence is fixed text, not the exception's cause.
        return problem_response(409, "Exhibit unavailable", str(exc))

    @app.exception_handler(StoreUnavailable)
    async def _store_unavailable(_: Request, exc: Exception):
        # The object store did not answer: the caller did nothing wrong and may try again, which
        # a 400 would not tell them and a 500 would report as the server's own defect.
        return problem_response(503, "Service unavailable", str(exc),
                                headers={"Retry-After": "5"})

    @app.exception_handler(EvidenceError)
    async def _evidence(request: Request, exc: Exception):
        if is_statement_timeout(exc):
            return await _statement_timeout(request, exc)
        return problem_response(400, "Evidence error", safe_detail(exc))

    @app.exception_handler(AccessResolutionError)
    async def _access_resolution(_: Request, exc: Exception):
        # Fail closed: an unresolvable context is a denial, not a 500.
        return problem_response(403, "Forbidden", "access could not be resolved")

    # Row-level security.
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

    @app.exception_handler(psycopg.errors.DataError)
    async def _unstorable_value(_: Request, exc: Exception):
        """A value the database cannot hold (text with a NUL, a number out of range, a timestamp
        past year 10000): the caller's input, so a 422. `body_ceiling.py` refuses the commonest
        case before a route parses it; this catches the rest (a query string, a path part). The
        raw text goes to the log against the reference, never to the caller."""
        cid = uuid.uuid4().hex[:12]
        log.warning("unstorable value %s: %s", cid, exc)
        return problem_response(
            422, "Validation failed",
            f"a value in the request cannot be stored, for example text "
            f"containing a NUL character or a number out of range (ref {cid})")

    @app.exception_handler(UnicodeEncodeError)
    async def _unencodable_text(request: Request, exc: UnicodeEncodeError):
        """Text no UTF-8 encoder will take: a lone surrogate the caller sent, which the driver
        refuses before a statement leaves the process, so a 422. `body_ceiling.py` refuses the
        commonest case before a route parses it; this catches the rest (a JSON body in another
        encoding, which the byte scan cannot read). Any other encoding failure is the server's
        own and stays a 500."""
        if "surrogates not allowed" not in exc.reason:
            return await _unhandled(request, exc)
        cid = uuid.uuid4().hex[:12]
        log.warning("unencodable text %s: %s", cid, exc)
        return problem_response(
            422, "Validation failed",
            f"a text value in the request holds an unpaired surrogate "
            f"character, which is not text and cannot be stored (ref {cid})")

    @app.exception_handler(SystemContextUnavailable)
    async def _no_system_connection(_: Request, exc: Exception):
        log.error("system connection unavailable: %s", exc)
        return problem_response(503, "Service unavailable", SYSTEM_UNAVAILABLE_DETAIL)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        """Catch-all so an unexpected failure is still problem+json with no internals, and still
        carries the security headers.

        Starlette routes the `Exception` handler to the outermost `ServerErrorMiddleware`, above
        the `_headers` middleware in `app.py`, so this response never passes back through it and
        the headers are stamped here. That is local to the one response class that escapes,
        where a pure-ASGI `send()` wrapper would touch every response. The headers are built
        first and `problem_response` wins on any key it sets, as `setdefault` would.
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
    """The RLS_REFUSED row. Out of band, on a fresh request-role connection; never raises,
    because the answer is already decided."""
    from psycopg.types.json import Json

    from noctornal_api.db import connect_request
    actor = getattr(request.state, "noctornal_user_id", None)
    # The request's own binding, so the database can verify the actor this row names (0150).
    proof = getattr(request.state, "noctornal_rls_proof", None)
    try:
        with connect_request() as side:
            if proof:
                side.execute("SELECT actor, exempt FROM iam.rls_bind(%s)", (proof,))
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
