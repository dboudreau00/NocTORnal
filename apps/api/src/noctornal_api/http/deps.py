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
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterator
from uuid import UUID

import psycopg
from fastapi import Depends, Header, Path, Request
from psycopg.types.json import Json

from noctornal_api.db import connect
from noctornal_api.http.errors import Problem
from noctornal_api.security.access import (
    CHECK_ASSIGNMENT,
    Tlp,
    evaluate,
    tlp_from_name,
)
from noctornal_api.security.sessions import STEP_UP_FRESHNESS, SessionService
from noctornal_api.stores import PgAccessResolver, PgSessionStore

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SESSION_COOKIE = "__Host-session"
CSRF_COOKIE = "__Host-csrf"
CSRF_HEADER = "x-csrf-token"


def get_conn() -> Iterator[psycopg.Connection]:
    conn = connect()  # autocommit
    try:
        yield conn
    finally:
        conn.close()


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
        if not sent or not expected or sent != expected:
            raise Problem(403, "Forbidden", "missing or invalid CSRF token")
    return cookie


def current_user(
    raw: str = Depends(session_token),
    conn: psycopg.Connection = Depends(get_conn),
) -> CurrentUser:
    """Resolve the session token to a live session. The failure reason is
    deliberately NOT returned: distinguishing 'revoked' from 'not_found'
    would confirm to a token holder that the string was a real session."""
    result = SessionService(PgSessionStore(conn)).validate(raw)
    if not result.ok:
        _audit(conn, "AUTH_SESSION_REJECTED", None, None,
               {"reason": result.reason})
        raise Problem(401, "Unauthenticated", "invalid or expired session")
    s = result.session
    return CurrentUser(s.user_id, s.id, s.mfa_satisfied_at)


def _audit(conn, action: str, actor_id, case_id, detail: dict) -> None:
    """Append to the hash-chained audit log. Authentication and
    authorization outcomes are auditable events (docs/05)."""
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
    element existence)."""
    row = conn.execute(
        'SELECT classification, compartments FROM core."case" WHERE id = %s',
        (case_id,),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    case_cls, case_comp = row[0], frozenset(row[1] or [])
    if element_classification is None:
        return case_cls, case_comp
    strictest = max(tlp_from_name(case_cls), tlp_from_name(element_classification))
    return strictest.name, case_comp | element_compartments


def authorize_object(
    conn: psycopg.Connection,
    user: CurrentUser,
    *,
    case_id: UUID,
    permission_key: str,
    classification: str | None = None,
    compartments: frozenset[str] = frozenset(),
) -> None:
    """The five-part gate against a specific element (or the case itself
    when classification is None). ONE complete decision — the verb check is
    included — and the effective labels are computed here so an element can
    never be less protected than its case."""
    eff_cls, eff_comp = effective_labels(conn, case_id, classification, compartments)
    ctx = PgAccessResolver(conn).resolve(
        user_id=user.user_id, case_id=case_id, permission_key=permission_key,
        object_classification=eff_cls, object_compartments=eff_comp,
        mfa_satisfied_at=user.session_mfa_at,
    )
    decision = evaluate(ctx)
    if not decision.allowed:
        _audit(conn, "AUTHZ_DENIED", user.user_id, case_id,
               {"permission": permission_key,
                "failed_checks": list(decision.failed_checks)})
        # A caller with NO relationship to the case must not learn whether it
        # exists: return the same 404 a nonexistent case gives. Once they are
        # assigned, 403 reveals nothing they do not already know (they can see
        # their own assignments), and is far more useful to a legitimate user.
        if CHECK_ASSIGNMENT in decision.failed_checks:
            raise Problem(404, "Not found", "case does not exist")
        raise Problem(403, "Forbidden",
                      f"missing permission {permission_key} on this case")


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
            _audit(conn, "AUTHZ_DENIED", user.user_id, None,
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
                _audit(conn, "AUTHZ_DENIED", user.user_id, None,
                       {"permission": permission_key, "scope": "global",
                        "failed_checks": ["step_up_freshness"]})
                raise Problem(403, "Forbidden", "re-authentication required")
        return user
    return _dep


def require(permission_key: str):
    """Dependency factory: gate a case-scoped endpoint behind `permission`.
    The case id comes from the path (/cases/{case_id}/...). Denials are
    403; which of the five checks failed is audited, never disclosed."""
    def _dep(
        case_id: UUID = Path(...),
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        authorize_object(conn, user, case_id=case_id, permission_key=permission_key)
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
        _audit(conn, "AUTHZ_DENIED", user.user_id, None,
               {"failed_checks": ["step_up_freshness"], "scope": "step_up"})
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
        raise Problem(403, "Forbidden",
                      f"not read into compartment(s) {sorted(missing)}")


def user_ceiling(conn: psycopg.Connection, user_id: UUID) -> tuple[Tlp, frozenset[str]]:
    """The caller's own clearance and compartments — used to filter search
    results so an over-classified element is invisible rather than
    discoverable-then-403."""
    row = conn.execute(
        "SELECT tlp_clearance, compartments FROM iam.app_user WHERE id = %s",
        (user_id,),
    ).fetchone()
    if row is None:
        raise Problem(401, "Unauthenticated", "unknown user")
    return tlp_from_name(row[0]), frozenset(row[1] or [])
