"""Request dependencies: a per-request DB connection, the authenticated session and user, and
the five-part access gate as a reusable dependency.

The gate is the single choke point every case-scoped endpoint passes through: it resolves the
AccessContext and calls the one evaluate(), so authorization is never re-decided per endpoint
(docs/05). An element is protected by both its own labels and its case's (the stricter
classification, the union of compartments), which authorize_object applies for every caller.
Authorization is decided before existence is revealed, so a caller who fails the gate gets the
same 403 whether or not the row exists. A CLOSED, ARCHIVED or PURGED case is read-only for
content, enforced here once, after the access decision, so the 409 that names the state tells
nobody anything the gate would not (`CONTENT_WRITE_PERMISSIONS`).
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterator
from uuid import UUID

import psycopg
from fastapi import Depends, Header, Path, Request
from psycopg.types.json import Json

from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.db import (
    SystemContextMisconfigured,
    SystemContextUnavailable,
    SystemPurpose,
    bind_session,
    connect_request,
    system_connection,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import client_ip
from noctornal_api.security.access import (
    CHECK_ASSIGNMENT,
    CHECK_STEP_UP,
    Tlp,
    evaluate,
    tlp_from_name,
)
from noctornal_api.security.sessions import (
    STEP_UP_FRESHNESS,
    SessionService,
    binding_mismatch,
    strict_binding_enabled,
)
from noctornal_api.stores import PgAccessResolver, PgSessionStore
from noctornal_api.wording import agree

log = logging.getLogger("noctornal.api")

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SESSION_COOKIE = "__Host-session"
CSRF_COOKIE = "__Host-csrf"
CSRF_HEADER = "x-csrf-token"

#: The attributes both cookies are set with and deleted with, declared once: a browser matches a
#: deletion against the stored cookie's Secure, Path and SameSite, and a `__Host-` cookie
#: deleted without Secure is refused, leaving the revoked token in place until the browser
#: closes. `__Host-` also requires Secure, `Path=/` and no Domain.
COOKIE_ATTRS: dict = {"path": "/", "secure": True, "samesite": "strict"}


def get_conn() -> Iterator[psycopg.Connection]:
    # The request role in production, bound to the request's user by `current_user`; autocommit.
    conn = connect_request()
    try:
        yield conn
    finally:
        conn.close()


def system_conn(purpose: SystemPurpose):
    """A dependency yielding a connection that sees every row, for a route whose work must be
    complete whatever its caller may read (`db.SystemPurpose`). The route's gate still runs on
    the request connection first. In development and the suite this is the request connection;
    in production it is the system role, closed after the response."""
    def _dep(conn: psycopg.Connection = Depends(get_conn),
             ) -> Iterator[psycopg.Connection]:
        with system_connection(purpose, reuse=conn) as sconn:
            yield sconn
    return _dep


@dataclass(frozen=True)
class CurrentUser:
    user_id: UUID
    session_id: UUID
    session_mfa_at: datetime | None


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


#: The 401 for a request that presents no session credential at all, in one place:
#: `session_token` raises it and `http/body_ceiling.py` answers an unauthenticated upload with
#: it before reading a byte, and the two must agree.
NO_SESSION_DETAIL = "no session token"


def presents_session_credential(request: Request) -> bool:
    """Whether `session_token` would find a token on this request: a
    non-empty Bearer value, else the session cookie. Nothing is validated;
    this is only the question of whether anything was presented."""
    return bool(_bearer(request.headers.get("authorization"))
                or request.cookies.get(SESSION_COOKIE))


def session_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    """Extract the opaque token (Authorization: Bearer, else the session cookie).

    Declared before the connection dependency, so a tokenless request 401s without opening a
    DB connection: an unauthenticated flood costs no connections. A cookie-derived credential
    on an unsafe method must carry a header matching the readable CSRF cookie (docs/05,
    double-submit and SameSite); without it a same-site page could POST multipart, which needs
    no preflight, and plant an exhibit in WORM storage under the victim's custody. A Bearer
    token is immune, since script cannot set that header cross-origin.
    """
    bearer = _bearer(authorization)
    if bearer:
        return bearer
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise Problem(401, "Unauthenticated", NO_SESSION_DETAIL)
    if request.method in _UNSAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER)
        expected = request.cookies.get(CSRF_COOKIE)
        # Constant-time, the way `security/totp.py` compares a code: `!=`
        # on two strings returns at the first differing character. Over
        # bytes, because `hmac.compare_digest` raises TypeError on a
        # non-ASCII str and the header is text the caller chose.
        if not sent or not expected or not hmac.compare_digest(
                sent.encode(), expected.encode()):
            raise Problem(403, "Forbidden", "missing or invalid CSRF token")
    return cookie


def current_user(
    request: Request,
    raw: str = Depends(session_token),
    conn: psycopg.Connection = Depends(get_conn),
) -> CurrentUser:
    """Resolve the session token to a live session.

    The failure reason is never returned: telling 'revoked' from 'not_found' would confirm to a
    token holder that the string was a real session. Under `NOCTORNAL_SESSION_STRICT_BINDING`
    (0058) a session presented from another address or client than it was minted with gets the
    same generic 401, plus an audit row naming which binding failed; it is refused, not revoked,
    or a token holder could log the victim out on demand. The idle window slides only after the
    check, so a refused replay does not keep the session alive. The websocket in
    `routers/live.py` applies the same check in the same order (`refuse_unbound_session`), and
    `test_session_binding_pg.py` holds both call sites to it.
    """
    service = SessionService(PgSessionStore(conn))
    result = service.validate(raw, touch=False)
    if not result.ok:
        # No row for a token that matches nothing; otherwise one per real session per window,
        # with the source.
        from noctornal_api.http.session_rejections import record_rejected_session
        record_rejected_session(conn, request, result)
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    s = result.session
    if refuse_unbound_session(
            conn, s, ip=client_ip(request),
            user_agent=request.headers.get("user-agent"), path="http"):
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    # Bind the connection to this session's user for row-level security before sliding the
    # idle window: the request role may update only the session its connection is bound to
    # (0112). On an exempt connection (the owner, in development and the suite) nothing is
    # compared and nothing changes.
    refuse_unbindable_session(conn, s, raw)
    touched = service.touch(s)
    if touched is None:
        # Revoked, expired or idle between the read above and the slide: the same generic 401,
        # and no second audit row, since the revocation was its own event.
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    s = touched
    # Who a row-level security refusal is audited against, when one escapes to the error
    # handler (http/errors.py).
    request.state.noctornal_user_id = s.user_id
    # The same, so a side connection that writes that row can be bound to the session and keep
    # its actor (0150).
    from noctornal_api.security.tokens import rls_proof
    request.state.noctornal_rls_proof = rls_proof(raw)
    return CurrentUser(s.user_id, s.id, s.mfa_satisfied_at)


def refuse_unbindable_session(conn, session, raw: str) -> None:
    """Bind `conn` to `session`, refusing with the generic 401 when that fails.

    A connection subject to row security that does not come out bound to the session's own user
    is refused like any bad session: a session minted before 0110 carries no binding, and a
    mismatch means the proof and the row disagree, which is never the presenter's to know.
    Shared with the websocket handshake in `routers/live.py`."""
    binding = bind_session(conn, raw)
    if binding.exempt or binding.actor == session.user_id:
        return
    audit_auth_event_as_system(
        conn, "RLS_BINDING_FAILED", session.user_id, None,
        {"session_id": str(session.id),
         "reason": "unbound" if binding.actor is None else "mismatch"})
    raise Problem(401, "Unauthenticated", "invalid or expired session")


def refuse_unbound_session(conn, session, *, ip: str | None,
                           user_agent: str | None, path: str) -> bool:
    """True when strict binding says this presentation must be refused.

    Shared by both session-validation call sites (`current_user` here and the websocket
    handshake in `routers/live.py`), so a stolen token cannot be refused on REST and accepted on
    the live stream. The caller must have validated with `touch=False` and slide the idle window
    only after this returns False, or a refused replay would keep the victim's session alive.
    `unbound` in the audit detail tells a replay from a session minted with no binding at all (a
    pre-0058 row, or one from `scripts/bootstrap.py session`); `path` names the surface.
    """
    if not strict_binding_enabled():
        return False
    mismatched = binding_mismatch(session, ip=ip, user_agent=user_agent)
    if not mismatched:
        return False
    audit_auth_event_as_system(
        conn, "SESSION_BINDING_REFUSED", session.user_id, None,
        {"session_id": str(session.id), "mismatched": mismatched,
         "path": path,
         "unbound": session.ip is None and session.user_agent is None})
    return True


def audit_auth_event(conn, action: str, actor_id, case_id, detail: dict,
                     *, ip_hash: bytes | None = None) -> None:
    """Append to the hash-chained audit log; authentication and authorization outcomes are
    auditable events (docs/05).

    Public because `routers/live.py` writes the same SESSION_BINDING_REFUSED row from the
    websocket handshake, and two spellings of one action make an audit query come back short.
    `ip_hash` attributes a refused session presentation to its source. Every row this writes is
    a refusal (AUTHZ_DENIED, AUTH_SESSION_REJECTED, RLS_BINDING_FAILED, SESSION_BINDING_REFUSED,
    CASE_SHARE_REFUSED) and is stored with outcome DENIED. Older rows of these actions carry
    SUCCESS and stay so, since the log is append-only (invariant 6, docs/17): find them by
    `action`.
    """
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                outcome, detail, ip_hash)
           VALUES (%s, %s, %s, 'auth', NULL, %s, 'DENIED', %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, case_id, Json(detail),
         ip_hash),
    )


def audit_auth_event_as_system(conn, action: str, actor_id, case_id,
                               detail: dict) -> None:
    """`audit_auth_event` for a row that names a user this connection is not bound to: a refused
    session (the binding comes after the checks) or one just revoked (a sign-out).

    The database attributes a request-role row only to the user the connection is bound to
    (0150) and demotes any other claim to `unverified_actor_id` in the detail. These outcomes
    the server has established itself, so the system role writes them and the row keeps its
    actor. A process with no system role (the sample origin) writes on `conn`, and the row is
    demoted rather than lost."""
    try:
        with system_connection(SystemPurpose.AUTH, reuse=conn) as sconn:
            audit_auth_event(sconn, action, actor_id, case_id, detail)
    except SystemContextUnavailable as exc:
        note_system_fallback(exc, action)
        audit_auth_event(conn, action, actor_id, case_id, detail)


def note_system_fallback(exc: SystemContextUnavailable, action: str) -> None:
    """Say so when an authentication row falls back to a write the database cannot attribute.

    "No system role in this process" is a deployment shape (the sample origin) and stays quiet.
    A system connection that is configured and wrong (not exempt from row security, or in
    production the owner or a superuser) is logged at ERROR with the reason, naming the setting
    and never its value, so an operator finds it before an investigation needs the actor. The
    row is still written, with its claim in `detail.unverified_actor_id`."""
    if isinstance(exc, SystemContextMisconfigured):
        log.error("%s written without a verified actor: the system "
                  "database connection is misconfigured: %s", action, exc)


def effective_labels(
    conn: psycopg.Connection,
    case_id: UUID,
    element_classification: str | None = None,
    element_compartments: frozenset[str] = frozenset(),
) -> tuple[str, frozenset[str]]:
    """The labels an access decision must use: the stricter classification of case and element,
    and the union of their compartments. Raises 404 only for a case that does not exist
    (callers gate before revealing element existence).

    Read through `iam.case_facts`, because the gate must decide and audit on the case's labels
    whether or not row-level security lets the caller read the case row: an assigned analyst
    asking for a case above their clearance gets the gate's 403 and its AUTHZ_DENIED row, never
    a silent 404."""
    row = conn.execute(
        "SELECT classification, compartments FROM iam.case_facts(%s)",
        (case_id,),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    case_cls, case_comp = row[0], frozenset(row[1] or [])
    if element_classification is None:
        return case_cls, case_comp
    strictest = max(tlp_from_name(case_cls), tlp_from_name(element_classification))
    return strictest.name, case_comp | element_compartments


#: The verbs that author case content and are never used to read it. A gate call naming one is
#: a content write, refused with a 409 on a case in `CONTENT_READ_ONLY_STATES` whatever route
#: made it. Keyed on the verb, not the route, because the gate is the one place every
#: case-scoped write passes, so a new route is covered without anyone remembering to cover it.
#:
#: Deliberately absent: `report.generate` and `case.update`, which also gate reads or
#: governance (their content-writing routes, ACH and the assumptions register, pass
#: `require(..., content_write=True)`); watch-hit triage under `collection.read`, which stays
#: open because the collector keeps raising hits on a closed case; and `comms.minimise`, which
#: is performed at closure (docs/16 L4). `ingest.replay` and `sample.submit` reach
#: `authorize_object` only when they write into a case; no case role carries `ingest.manage`,
#: which stays here for one that ever does. `test_closed_case_read_only.py` holds the route
#: table to this set.
CONTENT_WRITE_PERMISSIONS: frozenset[str] = frozenset({
    "graph.node.create", "graph.node.update", "graph.node.delete",
    "graph.edge.create", "graph.edge.update", "graph.edge.delete",
    "assertion.create", "assertion.retract",
    "graph.merge", "graph.unmerge",
    "evidence.upload",
    "proposal.review",
    "comms.bind", "comms.stoplist.manage",
    "curation.manage",
    "sample.submit",
    "ingest.manage", "ingest.replay",
    # Comms: asking for and approving a key lookup.
    "comms.key.lookup", "comms.key.lookup.approve",
    # Sending a case selector to a provider. Not lookup.authorise: withdrawing a request stays
    # possible on a closed case, and the routes that send under it say content_write=True.
    "lookup.request",
})

#: The problem title of the refusal, and the console's way of recognising
#: it (app.js `CASE_READ_ONLY_TITLE`, held equal by the test).
CASE_READ_ONLY_TITLE = "Case is read-only"

_GOVERNANCE_STILL_WORKS = (
    "Governance still works: status, legal holds, retention, sharing and "
    "break-glass.")

#: What the 409 says, by state. Each names the state, what is refused,
#: and the way out when there is one: only a CLOSED case can be reopened.
_READ_ONLY_DETAIL = {
    "CLOSED": (
        "This case is CLOSED, so its content is read-only: nothing can be "
        "added to, changed in or removed from its graph, evidence, "
        "captures, proposals, comms, analysis, tags or samples. "
        + _GOVERNANCE_STILL_WORKS
        + " Reopen it (status ACTIVE) if the work is genuinely resuming."),
    "ARCHIVED": (
        "This case is ARCHIVED, so its content is read-only: nothing can be "
        "added to, changed in or removed from its graph, evidence, "
        "captures, proposals, comms, analysis, tags or samples. "
        + _GOVERNANCE_STILL_WORKS
        + " An archived case is a record and cannot be reopened."),
    "PURGED": (
        "This case is PURGED: it is marked for destruction and its content "
        "is read-only."),
}


def refuse_if_case_read_only(conn: psycopg.Connection, user: CurrentUser,
                             case_id: UUID, permission_key: str) -> None:
    """409 when `case_id` is in a state whose content is read-only.

    Called by `authorize_object` after the access decision allowed, never before: a caller the
    gate refuses gets the gate's 404 or 403 and learns nothing about the case's state. The
    refusal is audited, because an attempt to change a closed case is what a disclosure review
    asks about. Not atomic with the write that follows: a case closed in between lets that one
    write through (closing the gap needs a trigger on every content table). The status is read
    through `iam.case_facts`, so a case row hidden by row-level security still refuses.
    """
    row = conn.execute("SELECT status FROM iam.case_facts(%s)",
                       (case_id,)).fetchone()
    if row is None or row[0] not in CONTENT_READ_ONLY_STATES:
        return
    status = row[0]
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, outcome, detail)
           VALUES (%s, 'USER', 'CASE_READ_ONLY_REFUSED', 'case', %s, %s,
                   'DENIED', %s)""",
        (user.user_id, case_id, case_id,
         Json({"permission": permission_key, "status": status})))
    raise Problem(409, CASE_READ_ONLY_TITLE, _READ_ONLY_DETAIL[status])


def authorize_object(
    conn: psycopg.Connection,
    user: CurrentUser,
    *,
    case_id: UUID,
    permission_key: str,
    # `count_use` is passed through to `PgAccessResolver.resolve`; `after_case_gate=True` marks a
    # second gate, reached only after this gate passed at the case's own labels, which counts a
    # break-glass use only when the case's gate did not (`counted_at_case_gate`), so one access
    # is one use on the officer's card. The defaults count: a forgotten flag over-counts, visibly.
    count_use: bool = True,
    after_case_gate: bool = False,
    classification: str | None = None,
    compartments: frozenset[str] = frozenset(),
    content_write: bool = False,
) -> None:
    """The five-part gate against a specific element (or the case itself
    when classification is None). ONE complete decision — the verb check is
    included — and the effective labels are computed here so an element can
    never be less protected than its case.

    Then, for a content write, the case's lifecycle: a verb in
    `CONTENT_WRITE_PERMISSIONS`, or `content_write=True` from a route whose
    verb also gates reads, is refused on a read-only case (rule 3 above)."""
    eff_cls, eff_comp = effective_labels(conn, case_id, classification, compartments)
    if after_case_gate and count_use:
        count_use = not counted_at_case_gate(conn, user, case_id)
    ctx = PgAccessResolver(conn).resolve(
        user_id=user.user_id, case_id=case_id, permission_key=permission_key,
        object_classification=eff_cls, object_compartments=eff_comp,
        mfa_satisfied_at=user.session_mfa_at, count_use=count_use,
    )
    decision = evaluate(ctx)
    if not decision.allowed:
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, case_id,
                         {"permission": permission_key,
                          "failed_checks": list(decision.failed_checks)})
        # A caller with NO relationship to the case must not learn whether it
        # exists: return the same 404 a nonexistent case gives. Once they are
        # assigned, 403 reveals nothing they do not already know (they can see
        # their own assignments), and is far more useful to a legitimate user.
        if CHECK_ASSIGNMENT in decision.failed_checks:
            raise Problem(404, "Not found", "case does not exist")
        # A stale sign-in that is the only thing missing is told so, in the global gate's words,
        # which the console answers by asking for the sign-in rather than reporting a missing
        # permission the caller holds. Only an assigned caller gets here, so it reveals nothing.
        if tuple(decision.failed_checks) == (CHECK_STEP_UP,):
            raise Problem(403, "Forbidden", "re-authentication required")
        raise Problem(403, "Forbidden",
                      f"missing permission {permission_key} on this case")
    if content_write or permission_key in CONTENT_WRITE_PERMISSIONS:
        refuse_if_case_read_only(conn, user, case_id, permission_key)


def require_global(permission_key: str):
    """Gate an endpoint that is NOT case-scoped (e.g. case.create — there is
    no case yet). Checks the verb via a global role, that the account is
    still active, and step-up freshness when the permission demands it —
    most globally-scoped permissions in the seed (user.manage, role.manage,
    break_glass.invoke) are step-up, so omitting it here would silently
    ship those without a re-challenge."""
    def _dep(
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        row = conn.execute(
            """SELECT p.requires_step_up
                 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.permission p ON p.key = rp.permission_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND rp.permission_key = %s
                  AND u.is_active
                LIMIT 1""",
            (user.user_id, permission_key),
        ).fetchone()
        if row is None:
            audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                             {"permission": permission_key, "scope": "global"})
            raise Problem(403, "Forbidden",
                          f"missing global permission {permission_key}")
        if row[0]:  # requires_step_up
            fresh = (
                user.session_mfa_at is not None
                and (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
                < STEP_UP_FRESHNESS
            )
            if not fresh:
                audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                                 {"permission": permission_key,
                                  "scope": "global",
                                  "failed_checks": ["step_up_freshness"]})
                raise Problem(403, "Forbidden", "re-authentication required")
        return user
    return _dep


def require(permission_key: str, *, content_write: bool = False):
    """Dependency factory: gate a case-scoped endpoint behind `permission`.
    The case id comes from the path (/cases/{case_id}/...). Denials are
    403; which of the five checks failed is audited, never disclosed.

    `content_write=True` marks a route that writes case content under a
    verb that also gates reads or governance (`case.update` on the
    assumptions register, `report.generate` on ACH), so a read-only case
    refuses it as it refuses every verb in `CONTENT_WRITE_PERMISSIONS`."""
    def _dep(
        case_id: UUID = Path(...),
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        authorize_object(conn, user, case_id=case_id, permission_key=permission_key,
                         content_write=content_write)
        return user
    return _dep


def require_step_up(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> None:
    """Demand a recently re-authenticated session, independently of any permission.

    For operations whose danger the permission row does not capture: docs/01 requires it for
    merges, because a merge rewrites who did what across a whole case. Separate from `require()`
    so an endpoint states its permission and its assurance requirement, neither implying the
    other.
    """
    fresh = (
        user.session_mfa_at is not None
        and (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
        < STEP_UP_FRESHNESS
    )
    if not fresh:
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                         {"failed_checks": ["step_up_freshness"],
                          "scope": "step_up"})
        raise Problem(403, "Forbidden",
                      "re-authenticate with your second factor before "
                      "performing this operation")


def check_writable_labels(
    conn: psycopg.Connection,
    user: CurrentUser,
    *,
    classification: str,
    compartments: frozenset[str] = frozenset(),
) -> None:
    """Refuse to author an element the caller could not read back.

    The DB trigger enforces the case floor (a child may not be less classified than its case);
    this enforces the ceiling, so an analyst cannot create content above their own clearance and
    lose sight of it. Compartments are likewise limited to ones the caller is read into.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    if tlp_from_name(classification) > clearance:
        raise Problem(403, "Forbidden",
                      f"cannot create {classification} content above your "
                      f"{clearance.name} clearance")
    missing = compartments - held
    if missing:
        raise Problem(403, "Forbidden",
                      f"not read into "
                      f"{agree(len(missing), 'compartment', 'compartments')} "
                      f"{', '.join(sorted(missing))}")


def user_ceiling(conn: psycopg.Connection, user_id: UUID,
                 case_id: UUID | None = None) -> tuple[Tlp, frozenset[str]]:
    """The caller's own clearance and compartments, used to filter search results so an
    over-classified element is invisible rather than discoverable and then refused.

    `case_id` is for a read whose rows all belong to that one case, and only such a read may
    pass it: a live break-glass grant scoped to that case then raises the ceiling too. Leave it
    out everywhere else."""
    row = conn.execute(
        "SELECT tlp_clearance, compartments FROM iam.app_user WHERE id = %s",
        (user_id,),
    ).fetchone()
    if row is None:
        raise Problem(401, "Unauthenticated", "unknown user")
    clearance, held = tlp_from_name(row[0]), frozenset(row[1] or [])

    # Without `case_id` (the Lab, collection, ingest, reports, label checks on writes) only a
    # global grant raises the ceiling: a case-scoped one would widen the caller's view of every
    # other case for the life of the grant. With `case_id`, a grant scoped to that case raises it
    # too. Highest live level first, as in PgAccessResolver.resolve(), so a later-ending lower
    # grant cannot hide a higher one; `case_id = NULL` is never true, so with no case only a
    # global grant matches.
    g = conn.execute(
        """SELECT granted_classification FROM iam.break_glass
            WHERE user_id = %s AND (case_id IS NULL OR case_id = %s)
              AND revoked_at IS NULL AND expires_at > now()
              AND granted_classification IS NOT NULL
            ORDER BY granted_classification DESC, expires_at DESC LIMIT 1""",
        (user_id, case_id),
    ).fetchone()
    if g is not None:
        from noctornal_api.security.access import AccessResolutionError
        try:
            granted = tlp_from_name(g[0])
        except AccessResolutionError:
            granted = None
        if granted is not None and granted > clearance:
            clearance = granted
    return clearance, held


def counted_at_case_gate(conn: psycopg.Connection, user: CurrentUser,
                         case_id: UUID) -> bool:
    """Whether the gate this request already passed at the case's own labels recorded a
    break-glass use: true when the case is classified above the caller's own clearance.

    A second gate (an exhibit's, a node's, a capture screenshot's, an operation's own verb) is
    asked with `authorize_object(..., after_case_gate=True)` and counts only when this answers
    False, so one access is one use on the officer's card (docs/05); on a case within clearance
    the second gate still counts an item whose own labels needed the grant. A request the second
    gate refuses keeps the case gate's count: the grant let it past, so it could tell an item
    that exists from one that does not. Compared in the database because `core.tlp` is an
    ordered enum; a case that has gone answers False, which counts rather than hides."""
    # The case's labels through `iam.case_facts`: a case the caller reaches only through a grant
    # is exactly one row security would hide from a plain read.
    row = conn.execute(
        'SELECT c.classification > u.tlp_clearance '
        '  FROM iam.case_facts(%s) c, iam.app_user u '
        ' WHERE u.id = %s',
        (case_id, user.user_id)).fetchone()
    return bool(row and row[0])


# The element pre-reads that feed the gate. A router that must know an element's case and labels
# before calling `authorize_object` reads them here, through `iam.element_facts`, so the gate
# still answers a hidden element with its 403 and its AUTHZ_DENIED row rather than the router
# answering a silent 404. The fact function covers the kinds under row-level security.
ELEMENT_KINDS = frozenset({"node", "edge", "evidence", "assertion",
                           # The kinds 0117 added whose pre-reads a router makes.
                           "document", "sample", "conversation"})


def element_labels(conn: psycopg.Connection, kind: str, element_id: UUID,
                   ) -> tuple[UUID, str, frozenset[str]] | None:
    """(case_id, classification, compartments) of one element, or None when
    it does not exist. Labels only: read content after the gate."""
    if kind not in ELEMENT_KINDS:
        raise ValueError(f"element_labels: unknown kind {kind!r}")
    row = conn.execute(
        "SELECT case_id, classification, compartments "
        "  FROM iam.element_facts(%s, %s)", (kind, element_id)).fetchone()
    if row is None:
        return None
    return row[0], row[1], frozenset(row[2] or [])


# Global gates for the deployment-wide approvals, beside `require_global` rather than folded into
# it. The SQL and the two refusals are the same, word for word, so the console reads them alike.

def _fresh(user: CurrentUser) -> bool:
    return (user.session_mfa_at is not None
            and (datetime.now(user.session_mfa_at.tzinfo)
                 - user.session_mfa_at) < STEP_UP_FRESHNESS)


def holds_global(conn: psycopg.Connection, user_id: UUID,
                 permission_key: str) -> bool:
    """Whether a global role of an active account carries `permission_key`, asked as a question:
    no AUTHZ_DENIED row (a listing that draws a control or leaves it out has not been denied
    anything), and no step-up, which the act itself asks for. `require_global`'s check without
    its refusals, for routes that tell the console whether to offer a verb (the collection
    router's `_holds` is the same query)."""
    return conn.execute(
        """SELECT EXISTS (
               SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND u.is_active
                  AND rp.permission_key = %s)""",
        (user_id, permission_key)).fetchone()[0]


def authorize_global(conn: psycopg.Connection, user: CurrentUser,
                     permission_key: str, *, force_step_up: bool = False) -> None:
    """`require_global`'s check, callable inside a handler whose permission depends on the row it
    reads (the global decide route: the signer's permission of the request's operation).

    `force_step_up` demands a fresh second factor even when the permission row does not, and
    refuses a stale one in the global gate's words, "re-authentication required", which the
    console's `withStepUp` recognises and answers by asking for the sign-in."""
    row = conn.execute(
        """SELECT p.requires_step_up
             FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.permission p ON p.key = rp.permission_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND rp.permission_key = %s
              AND u.is_active
            LIMIT 1""",
        (user.user_id, permission_key),
    ).fetchone()
    if row is None:
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                         {"permission": permission_key, "scope": "global"})
        raise Problem(403, "Forbidden",
                      f"missing global permission {permission_key}")
    if (row[0] or force_step_up) and not _fresh(user):
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                         {"permission": permission_key, "scope": "global",
                          "failed_checks": ["step_up_freshness"]})
        raise Problem(403, "Forbidden", "re-authentication required")


def require_global_any(*permission_keys: str):
    """Gate a route that either side of a two-person act may open: the
    caller holds at least one of `permission_keys` through a global role on
    an active account. Step-up is skipped only when some permission the
    caller holds does not demand it; otherwise a stale sign-in is refused
    in the global gate's words."""
    keys = sorted(set(permission_keys))

    def _dep(
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        rows = conn.execute(
            """SELECT DISTINCT p.key, p.requires_step_up
                 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.permission p ON p.key = rp.permission_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND rp.permission_key = ANY(%s)
                  AND u.is_active""",
            (user.user_id, keys)).fetchall()
        if not rows:
            audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                             {"permission": keys, "scope": "global"})
            raise Problem(403, "Forbidden",
                          f"missing global permission {' or '.join(keys)}")
        if all(r[1] for r in rows) and not _fresh(user):
            audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                             {"permission": keys, "scope": "global",
                              "failed_checks": ["step_up_freshness"]})
            raise Problem(403, "Forbidden", "re-authentication required")
        return user
    return _dep
