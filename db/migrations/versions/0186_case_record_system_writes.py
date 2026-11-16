"""The request role updates no column of a case
(a case's retention date and governance text, 2026-11-15).

## Why

0178 left `noctornal_app` UPDATE of ten columns of `core."case"`, because
the case routes wrote them as that role: the governance record (`title`,
`summary`, `authority_ref`, `review_due`, `retention_until`,
`classification`), the lifecycle (`status`, `closed_at`) and the two policy
switches (`dual_control_merge`, `withheld_disclosure`). One statement
injected into a request could therefore move a case's retention date,
rewrite its governance text, close or reopen it, or change what a reader is
told about withheld material, on a case its policy let it update, without
the route's gate, its refusals or its audit row.

## What

The request role loses UPDATE of the ten columns and keeps SELECT. It now
updates no column of the table at all. The three routes that wrote them
write on a system connection after their own gate, refusals and step-up,
for the caller they authenticated (`SystemPurpose.CASE_RECORD`), as a
case's hold (RETENTION) and its compartments (COMPARTMENTS) already were:

- `PATCH /cases/{id}`: the governance record and its `CASE_UPDATED` row;
- `POST /cases/{id}/status`: the lifecycle and its `CASE_STATUS_CHANGED`
  row;
- `PUT /cases/{id}/policy`: the two switches, their `CASE_POLICY_CHANGED`
  rows and, when the merge switch goes off, the spend of its
  `case.policy.relax` approval, in the one transaction 0076's guard needs.

A row lock needs UPDATE on a column, so the request role can no longer take
`SELECT ... FOR UPDATE` or `FOR SHARE` on a case; no request path does
(the hold, the purge and a sample's rejection lock the case row on a
system connection). The table's `rls_change` policy is left in place, dead
for the request role, so the downgrade stays a grant.

`RUNTIME_COLUMN_UPDATES` declares the table for
`test_app_role_privileges_pg.py`, overriding 0178's entry.
`PRIVILEGES_SQL` is repeatable and `scripts/runtime_roles.py ensure`
replays it after 0178's grant, which hands the ten columns back.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0178 is. The downgrade gives the ten column
grants back.
"""
from alembic import op

revision = "0186"
down_revision = "0185"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: The columns 0178 left the request role, which this revision takes back.
CASE_COLUMNS: tuple[str, ...] = (
    "title", "summary", "authority_ref", "review_due", "retention_until",
    "classification", "status", "closed_at", "dual_control_merge",
    "withheld_disclosure")

#: No column of a case is the request role's to update.
#: `test_app_role_privileges_pg.py` reads it after 0178's entry.
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {"core.case": ()}


def _block(verb: str, preposition: str) -> str:
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    {verb} UPDATE ({', '.join(CASE_COLUMNS)}) ON core."case" {preposition} {APP_ROLE};
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
PRIVILEGES_SQL = _block("REVOKE", "FROM")

DOWNGRADE_SQL = _block("GRANT", "TO")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(PRIVILEGES_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
