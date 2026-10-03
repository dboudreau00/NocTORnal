"""The collector's heartbeat (verify:g38, 2026-10-03).

## Why

The readiness row `collector_split` saw a collector only through the act
queue: it went red once an act had waited more than two minutes. A
collector that was stopped, or never started, read green with an empty
queue. That is the state an upgrade without infra/production/collector.env
leaves (the service refuses by name and restarts in a loop), and in
production the collector also runs every scheduled poll, feeds no persona
reads included, so all collection stopped with nothing red. And since a
persona credential left the TOTP ring's inventory (0156's split), no
readiness probe opened one any more: a persona key changed under its id
showed only as failed acts.

## collect.collector_heartbeat

One row per collector process. `instance` is its host and pid (never a
secret). `started_at`, and `seen_at`, which the collector moves at most
every 30 seconds while it runs. `key_ids`: the persona key ids its ring
holds (ids, never key material). Its ring verdict at start: how many
sampled persona credentials it tried, how many would not open, and the
first sentence why (a key id and what failed, never a plaintext). The
register reads the newest row; the collector deletes rows not seen for a
day when it starts.

## Row security and privileges

Exempt (rls_registry): no case, no label, no person; operational state
the register reads and the collector writes. Both runtime roles keep the
default privileges every ordinary table has (the worker role mirrors the
request role, test_worker_role_privileges_pg). A compromised API could
forge a heartbeat, which only makes one readiness row lie, and such an
API can already do worse.

## Downgrade

Drops the table: a heartbeat is not a record, and nothing else reads it.
"""
from alembic import op

revision = "0157"
down_revision = "0156"
branch_labels = None
depends_on = None

UPGRADE_SQL = """
CREATE TABLE collect.collector_heartbeat (
  instance      text PRIMARY KEY
                  CONSTRAINT collector_heartbeat_instance
                  CHECK (length(instance) BETWEEN 1 AND 120),
  started_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  seen_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
  key_ids       text[] NOT NULL DEFAULT '{}',
  sampled       integer NOT NULL DEFAULT 0 CHECK (sampled >= 0),
  unopenable    integer NOT NULL DEFAULT 0
                  CHECK (unopenable >= 0 AND unopenable <= sampled),
  ring_problem  text CHECK (ring_problem IS NULL OR length(ring_problem) <= 500)
);

COMMENT ON TABLE collect.collector_heartbeat IS
  'One row per collector process: when it was last seen and whether its persona key ring opened what it sampled (verify:g38, 2026-10-03). No secret.';

CREATE INDEX collector_heartbeat_seen ON collect.collector_heartbeat (seen_at DESC);
"""

DOWNGRADE_SQL = """
DROP TABLE collect.collector_heartbeat;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
