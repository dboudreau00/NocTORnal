"""The IAM plane is read-only to the request role (S1, 2026-09-25).

## Why

Row-level security binds each request's connection to its user and
decides what that user may read from the IAM plane: the session that
proves the binding, the account's clearance, compartments and active
flag, its roles, its case assignments and its break-glass grants. Until
this revision `noctornal_app` could WRITE every one of those tables:
one injected `UPDATE iam.session SET ...` or `INSERT INTO
iam.case_assignment ...` would rebind the connection as anyone, or widen
its own reach, and the policies would then faithfully show the attacker
whatever that forged input allowed. A policy is only as strong as the rows
it reads.

So the request role keeps SELECT on the IAM plane (the gate, the
resolver and the policies read it on every request) and loses INSERT,
UPDATE and DELETE on every `iam` table and on `lab.download_ticket`,
whose redeemed rows bind the sample origin's connection to a ticket's
holder. Every IAM write the application makes now runs on
`db.system_connection(purpose)` after the application's own gate
(login, sign-in bookkeeping, second factors, administration, case
membership, break-glass, compartments, the dual-control policy ledger,
ticket mint).

## The two column grants that remain, and why each is safe

- `iam.session (last_seen_at, mfa_satisfied_at, revoked_at,
  revoke_reason)`: every request slides its own idle window, a step-up
  stamps its own session, a logout revokes its own session. 0112's guard
  confines the request role to the ONE session its connection is bound
  to, and refuses an un-revoke.
- `lab.download_ticket (redeemed_at)`: the sample origin spends a ticket
  before any user is bound, so the spend is a request-role write. 0112's
  guard lets the request role set it from NULL only. A spent ticket binds
  its holder for five minutes (iam.rls_actor), but only to a connection
  that presents the RAW ticket, which the table does not hold.

## Future IAM tables are born read-only

0060's default privileges hand the runtime role DML on every table the
owner creates later. For schema `iam` this revision takes INSERT, UPDATE
and DELETE back out of that default, so a new IAM table is read-only to
the request role unless its own migration decides otherwise.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0060 is. The downgrade grants back what 0060 and
0075 left the role holding on these tables (0075's UPDATE and DELETE on
the dual-control ledger stay revoked) and restores the iam default.
"""
from alembic import op

revision = "0109"
down_revision = "0108"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: Every table in these schemas is read-only to the request role.
RUNTIME_READ_ONLY_SCHEMAS = ("iam",)
#: And these tables outside them.
RUNTIME_READ_ONLY_TABLES = ("lab.download_ticket",)
#: The column-level UPDATEs the request role keeps, each confined by
#: 0112's guard trigger. `test_app_role_privileges_pg.py` reads all three
#: constants.
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {
    "iam.session": ("last_seen_at", "mfa_satisfied_at", "revoked_at",
                    "revoke_reason"),
    "lab.download_ticket": ("redeemed_at",),
}

#: What 0075 keeps revoked on the ledger it created; the downgrade must not
#: hand it back.
_STILL_REVOKED_ON_DOWNGRADE = {"iam.dual_control_policy_change": "UPDATE, DELETE"}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _column_grants(verb: str, preposition: str) -> str:
    lines = []
    for table, columns in RUNTIME_COLUMN_UPDATES.items():
        cols = ", ".join(columns)
        lines.append(
            f"    EXECUTE format('{verb} UPDATE ({cols}) ON {table} {preposition} %I', app);")
    return "\n".join(lines)


UPGRADE_SQL = f"""
DO $noc$
DECLARE
  app  text := '{APP_ROLE}';
  ownr text := current_user;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam FROM %I', app);
    EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON lab.download_ticket FROM %I', app);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA iam'
                   || ' REVOKE INSERT, UPDATE, DELETE ON TABLES FROM %I', ownr, app);
{_column_grants('GRANT', 'TO')}
  END IF;
END
$noc$;
"""

DOWNGRADE_SQL = f"""
DO $noc$
DECLARE
  app  text := '{APP_ROLE}';
  ownr text := current_user;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{_column_grants('REVOKE', 'FROM')}
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam TO %I', app);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON lab.download_ticket TO %I', app);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA iam'
                   || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', ownr, app);
""" + "".join(
    f"    EXECUTE format('REVOKE {privs} ON {table} FROM %I', app);\n"
    for table, privs in _STILL_REVOKED_ON_DOWNGRADE.items()) + """  END IF;
END
$noc$;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
