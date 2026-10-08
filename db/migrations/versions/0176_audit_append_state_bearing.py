"""A request appends a state-bearing audit row only where it may act
(the audit log's append policy, Beta 1.1, 2026-10-08).

## Why

0168's INSERT policy on `audit.event` admits every append, because every
writer appends, a writer that may read none of the log included. Some rows
are not only a record: a reader takes them as the current state of
something. The ingest queue reads a record's triage state from the newest
`INGEST_RECORD_TRIAGED` row (`IngestService.triage_state`) and its
classifier's category from the first `INGEST_CATEGORY_CORRECTED`; the ACH
matrix replays `HYPOTHESIS_STANCE`, `HYPOTHESIS_STANCE_CLEARED` and
`HYPOTHESIS_STATUS` rows into its history and a report prints the status
notes; a tie's review history is its `EDGE_REVIEWED` rows. A bound user who
is not on a case could therefore append a triage verdict, a category
correction, an ACH history line or a hypothesis note naming that case, and
the case's team would read it as the case's state. 0150 keeps the planter's
name on the row, which is attribution, not prevention. The same holds for
the rows the database's own readers take as state: the countersigning rule
(0075, 0166) reads six account events on a signer's account, the Lab reads
when screening last ran from `SCREENING_RESCAN` (0167), and the break-glass
queue reads each grant's `BREAK_GLASS_INVOKED` row for the clearance it
raised from. A planted account event blocked a signer for seven days; a
planted screening pass told the Lab screening had run.

## What

For an action in `STATE_BEARING`, the request role's append must name a
case it may read (`case_id = ANY (iam.rls_cases())`, an initplan), or be a
case-less `ingest` row from a holder of `ingest.manage` through a global
role: the policy's own read terms for those rows, so a request appends
state only where it reads state. Every other action is appended as before,
whatever case it names: a refusal (AUTHZ_DENIED, CASE_READ_ONLY_REFUSED and
the rest) honestly names a case its writer may not read, and stays open.

Every legitimate writer already satisfies it. The ACH routes and a tie's
review pass the case's gate first, so the case is one the writer reads; a
triage or a category correction on an attached record passes the record's
case gate, and on a quarantined one requires `ingest.manage`; an attach
passes `ingest.replay` on its target case. The account events, the
screening passes and the break-glass invocation are written on system
connections (IAM_ADMIN, SCREENING, BREAK_GLASS), which row security does
not bind, and never by a request: for the request role, which can name no
case for them, they are refused.

What a request may NAME on a row is still 0150's trigger's to say, before
this policy is checked.

## Downgrade

Restores 0168's `WITH CHECK (true)`.
"""
from alembic import op

revision = "0176"
down_revision = "0175"
branch_labels = None
depends_on = None

#: The actions a reader takes as state, each with what reads it.
#: `test_rls_audit_append_pg.py` holds every action a case or ingest reader
#: in `test_rls_audit_paths._READERS` names to this list.
STATE_BEARING: tuple[str, ...] = (
    # The ACH matrix's history and a report's hypothesis notes.
    "HYPOTHESIS_STANCE", "HYPOTHESIS_STANCE_CLEARED", "HYPOTHESIS_STATUS",
    # A tie's review history.
    "EDGE_REVIEWED",
    # The ingest queue: a record's triage state, its attachment and its
    # category corrections.
    "INGEST_RECORD_TRIAGED", "INGEST_RECORD_ATTACHED", "INGEST_CATEGORY_CORRECTED",
    # The countersigning rule's account events (0075, 0166).
    "PASSWORD_RESET", "TOTP_REENROLLED", "USER_REACTIVATED", "USER_UNLOCKED",
    "ROLE_GRANTED", "USER_CREATED",
    # When screening last ran (0167).
    "SCREENING_RESCAN",
    # The break-glass queue's clearance at invoke.
    "BREAK_GLASS_INVOKED",
)

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_ACTIONS = "ARRAY[" + ", ".join(f"'{a}'" for a in STATE_BEARING) + "]::text[]"

#: Frozen text: a later revision that changes it restates it.
APPEND = (f"event.action <> ALL ({_ACTIONS}) OR "
          f"event.case_id = ANY ({_CASES}) OR "
          "(event.case_id IS NULL AND event.object_type = 'ingest' AND "
          "(SELECT iam.rls_holds_global('ingest.manage')))")

UPGRADE_SQL = f"""
DROP POLICY rls_append ON audit.event;
CREATE POLICY rls_append ON audit.event FOR INSERT WITH CHECK ({APPEND});
"""

#: 0168's.
DOWNGRADE_SQL = """
DROP POLICY rls_append ON audit.event;
CREATE POLICY rls_append ON audit.event FOR INSERT WITH CHECK (true);
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
