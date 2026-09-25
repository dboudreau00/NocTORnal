"""Custody can record a read by the product itself (F11, 2026-09-24).

## What was wrong

`lab.sample_access.actor_id` is NOT NULL, so every custody row names a
person. Static triage (F11) reads a sample's bytes on nobody's request
when it runs on submission or from the cron pass, and prohibited-content
screening (F13) isolates a matched sample the same way. Naming a person on work
nobody asked for is false (the collection poll uses a nil actor only
because it writes no audit), and a synthetic "NocTORnal" account would
hold a role and could sign in. Attributing machine rows to a list
importer would be as false, and a nullable column alone would say
nothing about which rows may be nobody's.

## What this adds

- `actor_kind text NOT NULL DEFAULT 'USER'`, USER or SYSTEM. SYSTEM is
  exactly the rows with no actor (`sample_access_system_names_nobody`),
  and only for SCANNED, VIEWED_META, REJECTED and ANALYSED
  (`sample_access_system_actions`): a download, a share, a detonation
  request or an assignment always names a person, which is the question
  custody exists to answer ("who took a copy of a live binary", 0031).
- A new action SCANNED: the product materialised the plaintext in memory
  for machine analysis, having verified it against the recorded SHA-256;
  nothing was written to disk or served.

A constant DEFAULT is metadata only on PostgreSQL 16 and ALTER TABLE
fires no row trigger, so the append-only triggers are untouched. The
table stays in 0060's LEDGERS and its privileges do not change.

## Downgrade

Refuses while any SYSTEM or SCANNED row exists, naming both counts:
custody is never deleted, and the old NOT NULL and seven-value CHECK
would reject those rows (0063's refusal pattern). Otherwise it drops the
new constraints and the column and restores both.
"""
from __future__ import annotations

from alembic import op

revision = "0078"
down_revision = "0077"
branch_labels = None
depends_on = None

#: The seven actions 0031 allowed, restored by the downgrade.
ACTIONS_0031 = ("VIEWED_META", "DOWNLOADED", "SHARED", "DETONATED",
                "REJECTED", "ASSIGNED", "ANALYSED")
#: The actions from here on.
ACTIONS = ACTIONS_0031 + ("SCANNED",)
#: What the product may do on nobody's request. Screening's
#: isolation is a SYSTEM REJECTED row and its findings SYSTEM ANALYSED, so
#: neither needs this constraint changed.
SYSTEM_ACTIONS = ("SCANNED", "VIEWED_META", "REJECTED", "ANALYSED")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


UPGRADE_SQL = f"""
SET search_path = lab, core, public;

ALTER TABLE sample_access
  ADD COLUMN actor_kind text NOT NULL DEFAULT 'USER',
  ALTER COLUMN actor_id DROP NOT NULL,
  ADD CONSTRAINT sample_access_actor_kind_known
    CHECK (actor_kind IN ('USER', 'SYSTEM')),
  ADD CONSTRAINT sample_access_system_names_nobody
    CHECK ((actor_kind = 'SYSTEM') = (actor_id IS NULL)),
  ADD CONSTRAINT sample_access_system_actions
    CHECK (actor_kind = 'USER' OR action IN ({_in(SYSTEM_ACTIONS)})),
  DROP CONSTRAINT sample_access_action_known,
  ADD CONSTRAINT sample_access_action_known
    CHECK (action IN ({_in(ACTIONS)}));

COMMENT ON COLUMN sample_access.actor_kind IS
  'USER names the person in actor_id; SYSTEM is the product acting on '
  'nobody''s request (actor_id NULL), allowed only for reads in memory '
  '(SCANNED), integrity alarms, screening isolation and machine findings.';
"""

COUNT_SQL = """
SELECT (SELECT count(*) FROM lab.sample_access WHERE actor_kind = 'SYSTEM'),
       (SELECT count(*) FROM lab.sample_access WHERE action = 'SCANNED')"""


def downgrade_refusal(system: int, scanned: int) -> str:
    """Both counts, named, with the nouns agreeing (a migration does not
    import the app, so this does locally what noctornal_api.wording
    does)."""
    def rows(n: int, what: str) -> str:
        return f"{n} custody {'row' if n == 1 else 'rows'} {what}"
    return (
        "refusing to downgrade 0078: "
        + rows(system, "name no person (SYSTEM)") + " and "
        + rows(scanned, "record a read by static triage (SCANNED)")
        + ". Custody is never deleted, and the old NOT NULL and action "
        "check would reject them. Stay at this revision.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    system, scanned = query(COUNT_SQL)[0]
    if system or scanned:
        raise RuntimeError(downgrade_refusal(system, scanned))
    run(f"""
SET search_path = lab, core, public;
ALTER TABLE sample_access
  DROP CONSTRAINT sample_access_system_actions,
  DROP CONSTRAINT sample_access_system_names_nobody,
  DROP CONSTRAINT sample_access_actor_kind_known,
  DROP CONSTRAINT sample_access_action_known,
  ADD CONSTRAINT sample_access_action_known
    CHECK (action IN ({_in(ACTIONS_0031)})),
  DROP COLUMN actor_kind,
  ALTER COLUMN actor_id SET NOT NULL;
""")
