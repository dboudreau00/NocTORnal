"""The two ledger sequences are the chain triggers' alone (F51, 2026-10-03).

## What was wrong (2026-10-03)

0149 draws `audit.event.seq` and `core.evidence_custody.id` inside the chain
lock, in the trigger, as the owner. It left the column defaults
(`nextval(...)`) and both runtime roles' USAGE and SELECT on the two
sequences, so that a row written with the trigger stood down still got a
number. A column default is evaluated as the INSERTING role, so a request
still drew from the sequences itself (a wasted value per append, drawn outside
the lock) and could read them: `SELECT last_value FROM audit.event_seq_seq`
returned the owner's newest `seq` to a bound analyst who may read none of the
log, which is the volume of the whole log, and 0168 exists to stop exactly that
kind of reading.

## What this changes

- Both column defaults are dropped. The trigger assigns the number whatever
  the caller supplied (0149), so nothing else draws, and a default would put a
  second draw back outside the lock for any insert. A row written with the
  trigger stood down (the verifier tests do) names its own number.
  `collect.egress_connection` (0086) has been built this way from its first
  row.
- `noctornal_app` and `noctornal_worker` lose USAGE and SELECT on both
  sequences. Guarded on the role and the sequence existing (a database with no
  runtime roles, or built from `schema.sql`, grants nothing).
  `scripts/runtime_roles.py ensure` replays `REVOKE_SQL` after 0108's grants,
  which hand every sequence to a role created later.

What this does NOT close: `INSERT ... RETURNING seq, prev_hash` on a row the
writer may read (its own case-less row) returns the newest `seq` of the whole
log and the hash of its newest row, which the writer may not read. No
application code asks for a row back
(`test_rls_audit_paths.test_no_append_asks_for_its_row_back`), so this needs SQL
as the request role. And an append waits on the chain lock while another writer
holds it, which tells a caller that someone else is appending and nothing more.

`release/alpha6-upgrade/app-role-grants.sql`, a pinned copy of 0060, grants
USAGE and SELECT on all sequences in `audit` and `core`; run after this
revision it gives the two back, and only `runtime_roles.py ensure` replays the
revoke.

## Downgrade

Gives both roles their privileges back and restores both defaults.
"""
from alembic import op

revision = "0169"
down_revision = "0168"
branch_labels = None
depends_on = None

DROP_DEFAULTS = """
ALTER TABLE audit.event ALTER COLUMN seq DROP DEFAULT;
ALTER TABLE core.evidence_custody ALTER COLUMN id DROP DEFAULT;
"""

RESTORE_DEFAULTS = """
ALTER TABLE audit.event ALTER COLUMN seq SET DEFAULT nextval('audit.event_seq_seq');
ALTER TABLE core.evidence_custody ALTER COLUMN id SET DEFAULT nextval('core.evidence_custody_id_seq');
"""

LEDGER_SEQUENCES = ("audit.event_seq_seq", "core.evidence_custody_id_seq")
RUNTIME_ROLES = ("noctornal_app", "noctornal_worker")


def _sequence_privileges(verb: str, preposition: str) -> str:
    lines = []
    for role in RUNTIME_ROLES:
        for seq in LEDGER_SEQUENCES:
            lines.append(
                f"  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')\n"
                f"     AND to_regclass('{seq}') IS NOT NULL THEN\n"
                f"    EXECUTE '{verb} USAGE, SELECT ON SEQUENCE {seq} {preposition} {role}';\n"
                f"  END IF;")
    return "DO $noc$\nBEGIN\n" + "\n".join(lines) + "\nEND\n$noc$;"


#: Replayed by scripts/runtime_roles.py after 0108's grants, on a cluster
#: whose roles were created later.
REVOKE_SQL = _sequence_privileges("REVOKE", "FROM")
GRANT_SQL = _sequence_privileges("GRANT", "TO")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(DROP_DEFAULTS)
    run(REVOKE_SQL)


def downgrade() -> None:
    run(GRANT_SQL)
    run(RESTORE_DEFAULTS)
