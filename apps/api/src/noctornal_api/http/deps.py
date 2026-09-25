"""Request dependencies: a per-request DB connection, the authenticated
session/user, and the five-part access gate as a reusable dependency.

The gate dependency is the single choke point every case-scoped endpoint
passes through — it resolves the AccessContext from the DB and calls the
one evaluate() function (session 4), so authorization is never re-decided
per endpoint (docs/05).

Two rules that adversarial review forced into this file:

1. An element is protected by BOTH its own labels and its case's. The
   effective classification is the STRICTER of the two and the effective
   compartments are the UNION, so an uncompartmented exhibit inside a
   compartmented case is still need-to-know locked. Callers cannot forget
   this because authorize_object does it for them.
2. Authorization is decided BEFORE existence is revealed. A caller who
   fails the gate gets the same 403 whether or not the row exists, so
   status codes are not an existence oracle.

A third arrived with gap-closed-case-writes (2026-09-23):

3. A CLOSED, ARCHIVED or PURGED case is read-only for CONTENT, and the
   gate is where that is enforced, once, AFTER the access decision so the
   409 that names the state tells nobody anything the gate would not.
   See `CONTENT_WRITE_PERMISSIONS` for how a content write is recognised.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterator
from uuid import UUID

import psycopg
from fastapi import Depends, Header, Path, Request
from psycopg.types.json import Json

from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.db import (
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

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SESSION_COOKIE = "__Host-session"
CSRF_COOKIE = "__Host-csrf"
CSRF_HEADER = "x-csrf-token"

#: The attributes BOTH cookies are set with and deleted with. One
#: declaration next to the names, because a browser matches a deletion
#: against the stored cookie's Secure/Path/SameSite and the two halves had
#: drifted: `routers/auth.py` set the pair with `secure=True,
#: samesite="strict"` and cleared them with `delete_cookie(name, path="/")`,
#: whose defaults emit no Secure attribute and `SameSite=lax`. A `__Host-`
#: cookie without Secure is refused outright, so until 2026-09-09 logout
#: returned 204 and the browser kept presenting the revoked token on every
#: request until the BROWSER closed: the pair is set with no Max-Age, which
#: makes it a session cookie, and a session cookie outlives the tab.
#: `secure=True` is also what the `__Host-` prefix requires, with `Path=/`
#: and no Domain.
COOKIE_ATTRS: dict = {"path": "/", "secure": True, "samesite": "strict"}


def get_conn() -> Iterator[psycopg.Connection]:
    # The request role in production (S1, 2026-09-25), bound to the
    # request's user by `current_user`. Autocommit, as before.
    conn = connect_request()
    try:
        yield conn
    finally:
        conn.close()


def system_conn(purpose: SystemPurpose):
    """A dependency yielding a connection that sees every row, for a
    route whose work must be complete whatever its caller may read (S1,
    2026-09-25; `db.SystemPurpose`). The route's gate still runs on the
    request connection first. In development and the suite this IS the
    request connection, so behaviour and transactions are unchanged; in
    production it is the system role, closed after the response."""
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


def session_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    """Extract the opaque token (Authorization: Bearer, else the session
    cookie). Declared BEFORE the connection dependency so a tokenless
    request 401s without ever opening a DB connection — an unauthenticated
    flood costs no connections, and a DB outage still returns 401.

    CSRF (docs/05: double-submit + SameSite): a COOKIE-derived credential
    on an unsafe method must be accompanied by a header matching the
    readable CSRF cookie. Without this, a same-site attacker page could
    POST multipart (a CORS-safelisted content type, so no preflight) and
    plant an exhibit into WORM storage under the victim's custody. A
    Bearer token is immune — script cannot set that header cross-origin.
    """
    bearer = _bearer(authorization)
    if bearer:
        return bearer
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise Problem(401, "Unauthenticated", "no session token")
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
    """Resolve the session token to a live session. The failure reason is
    deliberately NOT returned: distinguishing 'revoked' from 'not_found'
    would confirm to a token holder that the string was a real session.

    Under `NOCTORNAL_SESSION_STRICT_BINDING` (0058) a live session
    presented from a different address or client than it was minted with
    is refused too, with the SAME generic 401 -- the holder of a replayed
    token must not learn that the string was a real session that merely
    failed a binding check -- and an audit row that names WHICH binding
    failed, because that is what the security officer needs. Refused, not
    revoked: an attacker holding the token could otherwise log the victim
    out on demand. The idle window slides only after the check, so a
    refused replay does not keep the session alive.

    This is ONE of the two places a session token is validated. The other
    is the websocket in `routers/live.py`, which applies the same check in
    the same order through `refuse_unbound_session`. Until 2026-09-02 it
    did not, and the gap was not cosmetic: a token refused on every HTTP
    request was still accepted on the live case-event stream, and every
    reconnect slid the idle window, so the replay kept the victim's
    session alive indefinitely. Both call sites now share the check, and
    `test_session_binding_pg.py` asserts it over both.
    """
    service = SessionService(PgSessionStore(conn))
    result = service.validate(raw, touch=False)
    if not result.ok:
        audit_auth_event(conn, "AUTH_SESSION_REJECTED", None, None,
                         {"reason": result.reason})
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    s = result.session
    if refuse_unbound_session(
            conn, s, ip=client_ip(request),
            user_agent=request.headers.get("user-agent"), path="http"):
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    # Bind the connection to this session's user for row-level
    # security (S1, 2026-09-25) BEFORE sliding the idle window: the request
    # role may update only the session its connection is bound to (0112).
    # On an exempt connection (the owner, in development and the suite)
    # nothing is compared and nothing changes.
    refuse_unbindable_session(conn, s, raw)
    s = service.touch(s)
    # Who a row-level security refusal is audited against, when one
    # escapes to the error handler (http/errors.py, S1).
    request.state.noctornal_user_id = s.user_id
    return CurrentUser(s.user_id, s.id, s.mfa_satisfied_at)


def refuse_unbindable_session(conn, session, raw: str) -> None:
    """Bind `conn` to `session` (S1). A connection that is subject to
    row security and does not come out bound to the session's own user is
    refused with the same generic 401 as any bad session: a session minted
    before 0110 carries no binding, and a mismatch means the proof and the
    row disagree, which is never the presenter's to know. Shared with the
    websocket handshake in `routers/live.py`."""
    binding = bind_session(conn, raw)
    if binding.exempt or binding.actor == session.user_id:
        return
    audit_auth_event(conn, "RLS_BINDING_FAILED", session.user_id, None,
                     {"session_id": str(session.id),
                      "reason": "unbound" if binding.actor is None else "mismatch"})
    raise Problem(401, "Unauthenticated", "invalid or expired session")


def refuse_unbound_session(conn, session, *, ip: str | None,
                           user_agent: str | None, path: str) -> bool:
    """True when strict binding says this presentation must be refused.

    Shared by BOTH session-validation call sites -- `current_user` here and
    the websocket handshake in `routers/live.py`. It is a function rather
    than two copies because the two halves of this control were wrong
    together until 2026-09-02: the HTTP half refused a moved token and the
    websocket half did not consult the binding at all, so the same stolen
    credential was rejected on every REST call and accepted on the live
    stream, which re-runs the five-part gate and therefore showed the
    attacker exactly what the victim could read.

    The caller must have validated with `touch=False` and must slide the
    idle window only after this returns False. A refused replay that
    touched the row would keep the victim's session alive for as long as
    the attacker kept reconnecting.

    `unbound` in the audit detail separates two different facts that both
    produce a mismatch: a session minted somewhere else (a replay) from a
    session minted with no binding at all -- a pre-0058 row, or one issued
    by `scripts/bootstrap.py session`, which mints from a shell that is
    not the browser that will present it. The security officer reading the
    log needs to tell "someone moved this token" from "this session could
    never have been bound"; `path` tells them which surface it arrived on.
    """
    if not strict_binding_enabled():
        return False
    mismatched = binding_mismatch(session, ip=ip, user_agent=user_agent)
    if not mismatched:
        return False
    audit_auth_event(conn, "SESSION_BINDING_REFUSED", session.user_id, None,
                     {"session_id": str(session.id), "mismatched": mismatched,
                      "path": path,
                      "unbound": session.ip is None and session.user_agent is None})
    return True


def audit_auth_event(conn, action: str, actor_id, case_id, detail: dict) -> None:
    """Append to the hash-chained audit log. Authentication and
    authorization outcomes are auditable events (docs/05).

    Public (it was `_audit` until 2026-09-02) because `routers/live.py`
    writes the same SESSION_BINDING_REFUSED row from the websocket
    handshake, and two spellings of one audit action is how an audit
    query comes back short.
    """
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, %s, %s, 'auth', NULL, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, case_id, Json(detail)),
    )


def effective_labels(
    conn: psycopg.Connection,
    case_id: UUID,
    element_classification: str | None = None,
    element_compartments: frozenset[str] = frozenset(),
) -> tuple[str, frozenset[str]]:
    """The labels an access decision must use: the STRICTER classification
    of case and element, and the UNION of their compartments. Raises 404
    only for a case that does not exist (callers gate before revealing
    element existence).

    Read through `iam.case_facts` (S1, 2026-09-25), because the gate
    must decide, and audit, on the case's labels whether or not row-level
    security lets the caller read the case row: an assigned analyst asking
    for a case above their clearance gets the gate's 403 and its
    AUTHZ_DENIED row, never a silent 404."""
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


#: The verbs that AUTHOR case content and are never used to read it. A gate
#: call naming one of these is a content write, so on a case in
#: `CONTENT_READ_ONLY_STATES` it is refused with a 409 whatever route made
#: it (gap-closed-case-writes, 2026-09-23).
#:
#: Keyed on the verb, not the route, because the gate is the one place
#: every case-scoped write already passes and the verb is the one thing
#: it is always told. A new route that gates on one of these is covered
#: without anyone remembering to cover it. Two verbs are deliberately NOT
#: here although some of their routes write content, because they also
#: gate reads or governance: `report.generate` (it reads the ACH matrix
#: and builds reports) and `case.update` (it edits the governance record
#: and the approval policy). Their content-writing routes, ACH and the
#: assumptions register, say so with `require(..., content_write=True)`.
#: Watch-hit triage under `collection.read` stays open on purpose: the
#: collector keeps raising hits on a closed case's watches, and a queue
#: nobody may clear nags forever. `test_closed_case_read_only.py`
#: holds the route table to this: every unsafe case route is either a
#: content write under this guard or named there as governance, and no
#: read route gates on a verb in this set.
#:
#: `ingest.manage` and `ingest.replay` reach `authorize_object` only when
#: they parse or replay records INTO a case; `sample.submit` only when a
#: sample is attached to one. `comms.minimise` is absent on purpose:
#: minimisation is performed at closure (docs/16 L4).
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
    # Comms F10c (2026-09-24): asking for and approving a key lookup.
    "comms.key.lookup", "comms.key.lookup.approve",
    # Sending a case selector to a provider (F15.3, 2026-09-24). Not
    # lookup.authorise: withdrawing a request stays possible on a closed
    # case, and the routes that send under it say content_write=True.
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

    Called by `authorize_object` AFTER the access decision allowed, never
    before: a caller the gate refuses must get the gate's 404 or 403 and
    learn nothing about the case's state. Everyone who reaches this may
    read the case, whose status is on its own record.

    The refusal is audited. An attempt to change a closed case is exactly
    what a disclosure review asks about, and a refusal nobody recorded is
    indistinguishable from nobody having tried.

    Not atomic with the write that follows: a case closed between this
    read and that write lets the one write through. Closing that needs a
    trigger on every content table, which is a migration and was left for
    one.

    The status is a lock fact, read through `iam.case_facts` (S1), so
    a case row hidden by row-level security still refuses a content write
    rather than letting it through as "not read-only".
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
    # `count_use` is passed through to `PgAccessResolver.resolve`, and
    # `after_case_gate=True` marks a SECOND gate, one a request reaches
    # only after passing this gate at the case's own labels. A second gate
    # counts a break-glass use only when the case's gate did not
    # (`counted_at_case_gate`), so an exhibit opened, a capture screenshot
    # served or an entity changed on a case above the caller's clearance
    # is one use on the officer's card, not two
    # (sec-breakglass-double-count, 2026-09-23). The defaults count, for
    # the reason `resolve` gives: a forgotten flag over-counts, visibly.
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
        # A stale sign-in that is the ONLY thing missing is told so, in the
        # global gate's words, which the console recognises and answers by
        # asking for the sign-in. "missing permission X" told a Lead
        # investigator fifteen minutes into a session that they lacked a
        # step-up permission they hold (ROADMAP "a stale sign-in reads as
        # missing permission", 2026-09-24; report export had its own fix).
        # Only an assigned caller gets here, so it reveals nothing.
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
    """Demand a RECENTLY re-authenticated session, independently of any
    permission.

    The five-part gate already enforces step-up for permissions flagged
    `requires_step_up` in the seed. This is for operations whose danger is
    not captured by their permission row -- docs/01 requires it explicitly
    for merges, because a merge rewrites who did what across a whole case
    and a session someone walked away from must not be enough to perform
    one.

    Deliberately separate from `require()` so the two can be composed: an
    endpoint states its permission AND its assurance requirement, and
    neither is implied by the other.
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

    The DB trigger enforces the case FLOOR (a child may not be less
    classified than its case); nothing enforced the CEILING, so an analyst
    could create a RED node in an AMBER case and immediately lose sight of
    it — invisible in their own search results, unreviewable by the peers it
    was written for. Compartments are likewise constrained to ones the
    caller is read into.
    """
    clearance, held = user_ceiling(conn, user.user_id)
    if tlp_from_name(classification) > clearance:
        raise Problem(403, "Forbidden",
                      f"cannot create {classification} content above your "
                      f"{clearance.name} clearance")
    missing = compartments - held
    if missing:
        # Agreed with the keys it names, not a bracketed plural (README
        # screenshot set review, 2026-09-23).
        raise Problem(403, "Forbidden",
                      f"not read into "
                      f"{agree(len(missing), 'compartment', 'compartments')} "
                      f"{', '.join(sorted(missing))}")


def user_ceiling(conn: psycopg.Connection, user_id: UUID,
                 case_id: UUID | None = None) -> tuple[Tlp, frozenset[str]]:
    """The caller's own clearance and compartments — used to filter search
    results so an over-classified element is invisible rather than
    discoverable-then-403.

    `case_id` is for a READ whose rows all belong to that one case, and
    only such a read may pass it: a live break-glass grant scoped to that
    case then raises the ceiling too. Leave it out everywhere else."""
    row = conn.execute(
        "SELECT tlp_clearance, compartments FROM iam.app_user WHERE id = %s",
        (user_id,),
    ).fetchone()
    if row is None:
        raise Problem(401, "Unauthenticated", "unknown user")
    clearance, held = tlp_from_name(row[0]), frozenset(row[1] or [])

    # Without `case_id` this ceiling has no case in hand: it is what the
    # Lab, collection, ingest, reports and label checks on writes use, and
    # a case-scoped grant must not apply there, because raising it would
    # widen the caller's view of every OTHER case for the life of the
    # grant. Only a global grant (case_id NULL) raises it then.
    #
    # With `case_id`, a grant scoped to THAT case raises it as well. Until
    # 2026-09-23 no caller could say which case it was reading, so a
    # case-scoped grant opened an exhibit by id and nothing else: the
    # graph, the entity and exhibit lists and case search still hid
    # everything above the analyst's own clearance, while the console,
    # whose default scope is the open case, announced emergency access as
    # live (ux15 breakglass-grant-raises-nothing, verifier follow-up). The
    # case-scoped reads now pass their case; this is the change the
    # comment here used to say should be made on purpose.
    #
    # Highest live level first, as in PgAccessResolver.resolve(): ordered by
    # expiry alone, a later-ending lower grant hid a higher one (2026-09-23).
    # `case_id = NULL` is never true, so with no case only a global grant
    # matches, exactly as before.
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
    """Whether the gate this request has ALREADY passed at the case's own
    labels recorded a break-glass use: true when the case is classified
    above the caller's own clearance.

    A request reaching a second gate (an exhibit's, a node's, a capture
    screenshot's, an operation's own verb) has passed the case's gate
    first. On a case above the caller's clearance that first gate was
    passable only through a live grant, so `PgAccessResolver.resolve`
    counted it there, and the second gate, whose labels are at least the
    case's, counted it again: one exhibit opened read as two accesses on
    the officer's card (sec-breakglass-double-count, 2026-09-23; docs/05).
    So a second gate is asked with `authorize_object(...,
    after_case_gate=True)`, which counts only when this answers False. On
    a case within the caller's clearance the first gate counted nothing,
    and the second still counts an item whose OWN labels needed the
    grant, which is the use the officer's card describes.

    One request the second gate then REFUSES (an item above the grant, a
    compartment the caller is not read into) still carries the case
    gate's count on a case above clearance. That is a request the grant
    let past the case's gate, and so one that could tell an item that
    exists from one that does not, which without the grant it could not.

    Compared in the database, as `routers/deception._gate_the_item` did
    before this existed, because `core.tlp` is an ordered enum and the
    two columns are of that type. A case that has gone answers False,
    which counts rather than hides."""
    # The case's labels through `iam.case_facts` (S1, 2026-09-25): a
    # case the caller reaches only through a grant is exactly one row
    # security would have hidden from a plain read.
    row = conn.execute(
        'SELECT c.classification > u.tlp_clearance '
        '  FROM iam.case_facts(%s) c, iam.app_user u '
        ' WHERE u.id = %s',
        (case_id, user.user_id)).fetchone()
    return bool(row and row[0])


# The element pre-reads that feed the gate (S1, 2026-09-25). A router
# that must know an element's case and labels before calling
# `authorize_object` reads them here, through `iam.element_facts`, so the
# gate still answers a hidden element with its 403 and its AUTHZ_DENIED row
# rather than the router answering a silent 404. The fact function covers
# the kinds under row-level security: node, edge, evidence, assertion.
ELEMENT_KINDS = frozenset({"node", "edge", "evidence", "assertion",
                           # S1, 2026-09-25: the kinds 0117 added whose
                           # pre-reads a router makes.
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


# Global gates for the deployment-wide approvals (F9, 2026-09-24), beside
# `require_global` rather than folded into it. The SQL and the two refusals
# are the same, word for word, so the console reads them the same way.

def _fresh(user: CurrentUser) -> bool:
    return (user.session_mfa_at is not None
            and (datetime.now(user.session_mfa_at.tzinfo)
                 - user.session_mfa_at) < STEP_UP_FRESHNESS)


def authorize_global(conn: psycopg.Connection, user: CurrentUser,
                     permission_key: str, *, force_step_up: bool = False) -> None:
    """`require_global`'s check, callable inside a handler whose permission
    depends on the row it reads (the global decide route: the signer's
    permission of the request's operation).

    `force_step_up` demands a fresh second factor even when the permission
    row does not, and refuses a stale one in the global gate's words,
    "re-authentication required", which the console's `withStepUp`
    recognises and answers by asking for the sign-in. The case routes'
    `require_step_up` words it differently, and a countersigner told
    something the console does not recognise was told nothing useful
    (2026-09-24)."""
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
