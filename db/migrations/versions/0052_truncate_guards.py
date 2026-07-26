"""Two append-only ledgers were missing their TRUNCATE guard.

CR15 and CR16 (2026-07-26). `audit.event` (0013) and `core.evidence_custody`
(0023) each pair a row-level `BEFORE UPDATE OR DELETE` trigger with a
statement-level `BEFORE TRUNCATE` one, and revoke the privileges besides.
`core.purge_tombstone` (0032) and `lab.sample_access` (0031) installed only
the row trigger — and **a row-level trigger does not fire on TRUNCATE at
all.**

The gap matters because of what these two tables are:

- `core.purge_tombstone` is the record that a destruction happened. It is
  the answer to "you deleted this — prove you were allowed to", and it is
  designed to outlive the thing it describes.
- `lab.sample_access` is the custody log for live malware: who downloaded,
  shared or detonated a hostile binary, and when.

`TRUNCATE core.purge_tombstone;` emptied the first and `TRUNCATE
lab.sample_access;` emptied the second, with no trigger dropped and nothing
in either log to say it happened — while the same statement against
`audit.event` was rejected. `0031`'s docstring claims equivalence to
`audit.event`; this makes that true.

## Privilege-bounded, and still worth closing

TRUNCATE needs table ownership or an explicit grant, so this is not an
analyst-reachable defect. It is reachable by the application role itself
if it owns the tables — which it does in the shipped compose — and by any
operator with a psql session. An append-only guarantee that holds against
the API and not against the DBA is a weaker claim than the one docs/08
makes, and the two tables that were missing it are the two whose whole
purpose is to be evidence about deletion.

The REVOKEs are added too, matching 0013. Belt and braces, because the
trigger can be dropped by the same principal who can TRUNCATE.
"""
from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    # The functions already exist (0031, 0032) and already raise; they were
    # simply never bound to a TRUNCATE event. A statement-level trigger is
    # the only kind TRUNCATE fires.
    run("""
        CREATE TRIGGER purge_tombstone_no_truncate
          BEFORE TRUNCATE ON core.purge_tombstone
          FOR EACH STATEMENT EXECUTE FUNCTION core.block_tombstone_mutation()
    """)
    run("""
        CREATE TRIGGER sample_access_no_truncate
          BEFORE TRUNCATE ON lab.sample_access
          FOR EACH STATEMENT EXECUTE FUNCTION lab.block_access_mutation()
    """)
    run("REVOKE UPDATE, DELETE, TRUNCATE ON core.purge_tombstone FROM PUBLIC")
    run("REVOKE UPDATE, DELETE, TRUNCATE ON lab.sample_access FROM PUBLIC")


def downgrade() -> None:
    run("DROP TRIGGER IF EXISTS purge_tombstone_no_truncate ON core.purge_tombstone")
    run("DROP TRIGGER IF EXISTS sample_access_no_truncate ON lab.sample_access")
