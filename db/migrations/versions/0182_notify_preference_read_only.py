"""A person's delivery settings are read-only to the request role
(unpolicied configuration tables, Beta 1.1, 2026-10-08).

## Why

`notify.preference` is per-person configuration with no case and no label
(`rls_registry.EXEMPT`), and 0060 handed `noctornal_app` INSERT, UPDATE and
DELETE on it. The settings route writes only the caller's own row, and
only an address in a domain an operator declared
(`NotificationService.set_preference`, F19), audited both ways; the
database checks no more than that an address is one plain address (0148).
So one statement injected into any request could point another person's
mail at a mailbox of its choosing, or switch their channels off, past the
domain list and without the audit row: every notice's subject and summary
for that person, case codes included, would go there.

## What

The request role loses INSERT, UPDATE and DELETE on `notify.preference`
and keeps SELECT (the inbox's settings pane and the routing reads). The
settings route writes on a system connection,
`SystemPurpose.NOTIFY_PREFERENCE`, for the caller it has authenticated and
nobody else, with the domain check and the audit it always applied.

`RUNTIME_READ_ONLY_TABLES` declares it for `test_app_role_privileges_pg.py`
and `test_worker_role_privileges_pg.py`. `PRIVILEGES_SQL` is repeatable and
`scripts/runtime_roles.py ensure` replays it after 0108's blanket grant.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0179 is. The downgrade gives the three writes back.
"""
from alembic import op

revision = "0182"
down_revision = "0181"
branch_labels = None
depends_on = None

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = ("notify.preference",)


def _block(verb: str, preposition: str) -> str:
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
    {verb} INSERT, UPDATE, DELETE ON notify.preference {preposition} noctornal_app;
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
