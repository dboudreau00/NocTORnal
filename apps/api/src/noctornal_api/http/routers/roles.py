"""Which roles hold which permission, for any signed-in account.

Added 2026-09-23 for ux19-copy developer-speak-in-copy. A refusal in the
console named a permission code ("Approvals need case.read on this case",
"missing permission evidence.read on this case") and never the role that
carries it or the person who can give one, so the one thing the analyst
could act on was missing. The console now says "this needs the Analyst,
Contributor, ... or Reviewer role on this case; ask this case's Lead
investigator", and it needs the grant table to say it.

The names come from here, not from a copy in the console: role display
names are the server's (migration 0062, and `test_role_names_ui` holds the
console to that), and a second copy of the grant table would drift the
first time a deployment changed a grant.

Why any signed-in account may read it, when `/admin/roles` needs
user.manage: that route is the administration surface (descriptions, what
may be granted), and this is only the table every refusal is explained
by. It is how the deployment is configured, not case content and not a
need-to-know lock of the kind the compartment registry is (see
`routers/compartments.py`): knowing that REVIEWER holds proposal.review
tells nobody which cases exist or what is in them. It names no account and
no assignment. The service account is left out, because no person is ever
told to become one.
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
