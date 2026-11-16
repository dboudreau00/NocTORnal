"""The collector's heartbeat is read-only to the request role
(the heartbeat and the queues, 2026-11-15).

## Why

0157 left both runtime roles the default privileges on
`collect.collector_heartbeat`, and 0179 left the table out of the
configuration it closed. One statement injected into a request could write
a fresh beat with a ring verdict that opened everything it sampled, and the
readiness row `collector_split` would read green while no collector ran:
persona acts waiting and, in production, no scheduled poll running at all.

## What

The request role loses INSERT, UPDATE and DELETE on the table and keeps
SELECT, which the readiness register reads. No request path writes it: the
collector writes its own beat on its PERSONA_ACTS system connection
(`scripts/collector.py`, `persona_acts.heartbeat_start` and `heartbeat`),
so no code changes.

`RUNTIME_READ_ONLY_TABLES` declares it for `test_app_role_privileges_pg.py`
and `test_worker_role_privileges_pg.py`. `PRIVILEGES_SQL` is repeatable and
`scripts/runtime_roles.py ensure` replays it after 0108's blanket grant.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0182 is. The downgrade gives the three writes back.
"""
from alembic import op

revision = "0187"
down_revision = "0186"
branch_labels = None
depends_on = None

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = ("collect.collector_heartbeat",)


def _block(verb: str, preposition: str) -> str:
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
    {verb} INSERT, UPDATE, DELETE ON collect.collector_heartbeat {preposition} noctornal_app;
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
