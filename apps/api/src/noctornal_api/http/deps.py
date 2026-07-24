"""Request dependencies: a per-request DB connection, the authenticated
session/user, and the five-part access gate as a reusable dependency.

The gate dependency is the single choke point every case-scoped endpoint
passes through — it resolves the AccessContext from the DB and calls the
one evaluate() function (session 4), so authorization is never re-decided
per endpoint (docs/05).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator
from uuid import UUID

import psycopg
from fastapi import Depends, Header, Path, Request

from noctornal_api.db import connect
from noctornal_api.http.errors import Problem
from noctornal_api.security.access import evaluate
from noctornal_api.security.sessions import SessionService
from noctornal_api.stores import PgAccessResolver, PgSessionStore


def get_conn() -> Iterator[psycopg.Connection]:
    conn = connect()  # autocommit
    try:
        yield conn
    finally:
        conn.close()


@dataclass(frozen=True)
class CurrentUser:
    user_id: UUID
    session_mfa_at: object  # datetime | None; opaque to callers


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def current_user(
    request: Request,
    conn: psycopg.Connection = Depends(get_conn),
    authorization: str | None = Header(default=None),
) -> CurrentUser:
    """Resolve the opaque session token (Authorization: Bearer, else the
    __Host-session cookie) to a live session. 401 on anything invalid."""
    raw = _bearer(authorization) or request.cookies.get("__Host-session")
    if not raw:
        raise Problem(401, "Unauthenticated", "no session token")
    result = SessionService(PgSessionStore(conn)).validate(raw)
    if not result.ok:
        raise Problem(401, "Unauthenticated", result.reason)
    return CurrentUser(result.session.user_id, result.session.mfa_satisfied_at)


def require_global(permission_key: str):
    """Gate an endpoint that is NOT case-scoped (e.g. case.create — there is
    no case yet) behind a GLOBAL role that grants the permission."""
    def _dep(
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        has = conn.execute(
            """SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                WHERE ur.user_id = %s AND rp.permission_key = %s LIMIT 1""",
            (user.user_id, permission_key),
        ).fetchone()
        if has is None:
            raise Problem(403, "Forbidden",
                          f"missing global permission {permission_key}")
        return user
    return _dep


def require(permission_key: str):
    """Dependency factory: gate a case-scoped endpoint behind `permission`.
    The case id comes from the path (/cases/{case_id}/...). Denials are
    403; the specific failed checks are not disclosed to the client."""
    def _dep(
        case_id: UUID = Path(...),
        user: CurrentUser = Depends(current_user),
        conn: psycopg.Connection = Depends(get_conn),
    ) -> CurrentUser:
        # The object's classification/compartments default to the case's own
        # (case-level authorization); element-level checks pass the specific
        # row's classification when finer control is needed.
        row = conn.execute(
            'SELECT classification, compartments FROM core."case" WHERE id = %s',
            (case_id,),
        ).fetchone()
        if row is None:
            raise Problem(404, "Not found", "case does not exist")
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id, permission_key=permission_key,
            object_classification=row[0], object_compartments=frozenset(row[1] or []),
            mfa_satisfied_at=user.session_mfa_at,
        )
        if not evaluate(ctx).allowed:
            raise Problem(403, "Forbidden",
                          f"missing permission {permission_key} on this case")
        return user
    return _dep
