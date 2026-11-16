"""Row-level security on case membership (rls-6, 2026-11-15).

## Why

0109 made the IAM plane read-only to the request role instead of filtering it, and 0143 and 0177 took
back an account's credentials, a session's token, binding and address, and a break-glass
justification. Who holds which role on which case stayed whole:
any request-role connection, bound to a session or to nobody, read every assignment, so a statement
injected into a request learned who works which case across the deployment. A row policy could not
stand while two kinds of reader would have come back empty: the gate on a connection bound to nobody
(the live socket's per-delivery checks and the sample origin's ticket redemption, both bound first
now), and the Lab's read of a case's leads on a case its analyst is not on (`iam.case_leads`, 0191).
`test_case_assignment_readers.py` holds every other reader to a term of this policy.

## What

`iam.case_assignment` is under row-level security with one SELECT policy, `rls_read`. A request reads:

- its own assignments, whatever the case's labels (`user_id = iam.rls_actor()`): the gate's resolver,
  the case list, the break-glass invoke on a case above the caller's clearance;
- every assignment on a case in `iam.rls_cases()`, its labels within the caller's reach and a live
  assignment of the caller's own on it, a break-glass grant counted: the team the roster
  (`GET /cases/{id}/users`) shows every member, LIAISON included, so the policy widens nothing.

A connection bound to nobody reads no assignment, and a member whose clearance no longer reaches a case
reads only their own row on it, as the gate refuses them the case. No INSERT, UPDATE or DELETE policy:
the request role holds no write on the table (0109), and every assignment is written on a system
connection (CASE_MEMBERSHIP). Not forced, as no table is: the owner and the system role read every row,
and so do the definers that read the table (`iam.rls_cases`, `iam.case_code`, `iam.case_leads`,
`notify.enqueue`). No index: the primary key and `case_assignment_user_id_expires_at_idx` serve both
terms, whose helpers run once per statement.

## Downgrade

Drops the policy and disables row security on the table. No row is written.
"""
from alembic import op

revision = "0192"
down_revision = "0191"
branch_labels = None
depends_on = None

#: Frozen text. A later revision that changes the policy restates it.
POLICY = ("case_assignment.user_id = (SELECT iam.rls_actor()) OR "
          "case_assignment.case_id = ANY ((SELECT iam.rls_cases())::uuid[])")

UPGRADE_SQL = f"""
ALTER TABLE iam.case_assignment ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_read ON iam.case_assignment FOR SELECT USING ({POLICY});
"""

DOWNGRADE_SQL = """
DROP POLICY rls_read ON iam.case_assignment;
ALTER TABLE iam.case_assignment DISABLE ROW LEVEL SECURITY;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
