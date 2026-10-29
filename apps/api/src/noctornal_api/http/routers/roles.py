"""Which roles hold which permission, for any signed-in account.

The console explains a refusal by the roles that carry the permission ("this needs the Analyst or
Reviewer role on this case"), with display names from the server (migration 0062,
`test_role_names_ui`) rather than a copy that would drift. Any signed-in account may read it,
unlike `/admin/roles`: it is deployment configuration, not case content, and names no account and
no assignment. The service account is left out, because no person is told to become one.
"""
from __future__ import annotations

import psycopg
from fastapi import APIRouter, Depends

from noctornal_api.http.deps import CurrentUser, current_user, get_conn

router = APIRouter(prefix="/roles", tags=["roles"])

#: A machine identity: never offered to a person as the way in.
_NOT_FOR_PEOPLE = ("SERVICE",)


@router.get("/holders", response_model=dict)
def holders(
    _: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """`{"roles": [{key, display_name}], "holders": {permission: [role
    key, ...]}}`. Every permission is listed, one no role holds with an
    empty list (sample.detonate, until a deployment grants it), so the
    console can say that rather than print the code."""
    roles = conn.execute(
        """SELECT key, display_name FROM iam.role
            WHERE key <> ALL(%s) ORDER BY key""",
        (list(_NOT_FOR_PEOPLE),)).fetchall()
    held: dict[str, list[str]] = {
        r[0]: [] for r in conn.execute(
            "SELECT key FROM iam.permission ORDER BY key").fetchall()}
    for permission, role in conn.execute(
            """SELECT rp.permission_key, rp.role_key
                 FROM iam.role_permission rp
                WHERE rp.role_key <> ALL(%s)
                ORDER BY rp.permission_key, rp.role_key""",
            (list(_NOT_FOR_PEOPLE),)).fetchall():
        held.setdefault(permission, []).append(role)
    return {"roles": [{"key": k, "display_name": n or k} for k, n in roles],
            "holders": held}
