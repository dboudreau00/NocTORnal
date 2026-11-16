"""The Security officer is told when a case's conversations are above everyone assigned to it
(decision 231, 2026-11-15).

## Why

Minimising a conversation acts only on one the minimiser can read (decision 177), and only the Lead
investigator's role carries `comms.minimise`. Where nobody assigned to a case is cleared for one of
its conversations, nobody on the team can minimise it, and nothing said so. The owner's ruling:
conversations should be traceable within the environment via role.

## What

One permission, `comms.minimise.oversee`: read the Oversight list of cases with conversations
nobody assigned can minimise, and receive the notice raised when such a case is closed. Granted to
SECURITY_OFFICER, the overseer who holds no case content and already reviews emergency access. Not
step-up: it is a read and a notice, and it confers nothing on any case. Who acts is unchanged: a
Lead investigator cleared for the conversation, assigned to the case through `case.grant`.

## Downgrade

Takes the grant back, then the permission. No row of any other table names it.
"""
from __future__ import annotations

from alembic import op

revision = "0196"
down_revision = "0195"
branch_labels = None
depends_on = None

PERMISSION = "comms.minimise.oversee"

#: (role, permission), in 0035's style.
_ROLE_GRANTS = [("SECURITY_OFFICER", PERMISSION)]


def run(sql: str, params=None) -> None:
    op.get_bind().connection.driver_connection.execute(sql, params)


def upgrade() -> None:
    run("""INSERT INTO iam.permission (key, description, requires_step_up)
           VALUES (%s, %s, false)
           ON CONFLICT (key) DO NOTHING""",
        (PERMISSION,
         "See the cases whose conversations nobody assigned can minimise, and be "
         "told when one is closed"))
    for role, permission in _ROLE_GRANTS:
        run("""INSERT INTO iam.role_permission (role_key, permission_key)
               VALUES (%s, %s) ON CONFLICT DO NOTHING""", (role, permission))


def downgrade() -> None:
    run("DELETE FROM iam.role_permission WHERE permission_key = %s", (PERMISSION,))
    run("DELETE FROM iam.permission WHERE key = %s", (PERMISSION,))
