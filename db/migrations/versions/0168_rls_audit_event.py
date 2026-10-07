"""Row-level security on the audit log (F51, 2026-10-02).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now reads an `audit.event` row
only where one of four terms holds (the CUSTOM_AUDIT template, decision
151):

- its case is one the user may read (`iam.rls_cases()`): a case's team
  reads the case's ACH history, a tie's review history, the hypothesis
  notes a report prints and the ingest queue's triage state and category
  corrections for the case's records;
- it carries no case and the user wrote it (`actor_id = iam.rls_actor()`);
- the user holds `audit.read` through a global role: the Security
  Officer's search of the whole log (`GET /audit/events`), which returns
  no `detail`;
- it is an `ingest` row with no case and the user holds `ingest.manage`
  through a global role: the operator's quarantine queue, whose triage
  decisions and category corrections carry no case because the record
  has none. An ingest row that names a case is that case's (a reveal of
  victim data, a replay into it) and is read under the case term only.

and APPENDS a row whatever case it names: `WITH CHECK (true)`. The log is
append-only (UPDATE, DELETE and TRUNCATE are refused by trigger and by
privilege) and every writer appends, including a writer that may read none
of it.

What a request may NAME on the row it appends is not the policy's to say. 0150's
BEFORE INSERT trigger `audit_attribution` pins it, and it fires before the
policy is checked: an actor must be the user the connection is bound to, or
the holder of a ticket it spent; another user is refused; a claim from a
connection bound to nobody is kept in `detail` as `unverified_actor_id` with
`actor_id` NULL. The time is the database's too: 0149's chain trigger reads
the clock inside the chain lock for the request role (not `now()`, the start
of a transaction a request can hold open). The first draft of this policy
checked the actor itself, and carried a boundary marker and a ticket-holder
function for it; with 0150 in place those were a second mechanism for the same
question, and one that disagreed with the first about a refused ticket, so
they are gone. No append in the product asks for its row back (`RETURNING`),
which would be refused for a row its writer may not read;
`test_rls_audit_paths.py` holds every writer to that.

An unbound connection's actor, cases and grants are empty or NULL, so it
reads nothing and its claims to a user are demoted by the trigger. The events
that are about a user the connection is not bound to (a session refused
before the connection is bound to it, a binding that failed, a sign-in
outcome, a sign-out whose session has just ended) go on a system connection
(`deps.audit_auth_event_as_system`, `routers.auth.logout`); a refusal written
out of band goes on a side connection bound to the caller's own session
(`approvals.record_out_of_band`, `errors._audit_rls_refused`), so the database
can vouch for the actor it names.

## What had to move first (F51)

- The chain trigger is a definer (0149, which restates it), and the
  countersigning rule reads the whole log as the definer too (0166), so an
  append chains to the true tail and the two-person control still sees an
  administrator's reset of the signer's account.
- The Lab's "screening last ran" reads a fact function (0167).
- The Security Officer's break-glass queue reads each grant's invoke row
  (the clearance it raised from) on the BREAK_GLASS system connection, so
  the queue does not depend on the officer also holding `audit.read`.
- Attaching a quarantined record restates its latest triage state and its
  first category correction on the new case
  (`IngestService._carry_from_quarantine`), so the case's team reads the
  same queue row the operator does. Records attached BEFORE this revision
  have no such copy, so the revision writes theirs before row security is
  enabled (`BACKFILL_SQL`, below).
- The chain and custody verification already walk every row as
  AUDIT_VERIFY, and the legacy-record register as READINESS and SCRIPT.

Every remaining reader is listed by function, with the term or the system
purpose that answers it, in `test_rls_audit_paths.py`, which fails by name
on a new reader nobody classified.

## The backfill (2026-10-03)

A record attached before this revision has its quarantine-era triage rows
and category correction on rows that carry no case, which only the
operator reads from here on, and nothing had copied them onto the case:
after the upgrade the case's team would see NEW instead of DISCARDED or
LINKED, no `category_was`, and the Feeds badge would count the record as
untriaged again. `BACKFILL_SQL` writes the same carried rows
`IngestService._carry_from_quarantine` writes for a new attach (the latest
triage state unless it is NEW, and the first category correction), before
row security is enabled, so the revision's own reads see the whole log:

- the rows are SYSTEM rows (no actor) naming the case, with the original
  detail and `carried` (the original seq, time and actor) plus
  `backfilled: "0168"`, so the record's history shows them as carried and
  as not written by a person;
- idempotent: a record whose latest triage row is already a case row, or
  that already has a case-scoped correction (a carried copy, or a
  correction its team made after the attach), is left alone, so a second
  run writes nothing;
- a record its team has triaged since the attach keeps that triage state
  (it is already the latest row they read). A correction its team made
  after the attach hides the quarantine-era one from `category_was`, which
  reads the FIRST correction it can see: the carry is skipped for such a
  record rather than written where the reader would never look.

What the backfill cannot restore: the time. Every carried row has the time of
the migration (the migration runs as the owner, who keeps the time it
supplies, so it is the column default, the migration's own `now()`), so a
case's queue shows the triage as made by nobody on the day of the upgrade; the
original time is in `detail.carried.at`.

## Who it does not touch

The owner (Alembic, fixtures, pg_dump, the CI chain check; ENABLE, never
FORCE) and `noctornal_worker`, which bypasses row security for every
system purpose. `noctornal_egress` holds no privilege on this table.

## Downgrade

Drops both policies and disables row security on the table. The carried
rows stay: the log is append-only.
"""
from alembic import op

revision = "0168"
down_revision = "0167"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_ACTOR = "(SELECT iam.rls_actor())"

#: Who reads a row (CUSTOM_AUDIT). Frozen text: a later revision that
#: changes it restates it.
READ = (f"event.case_id = ANY ({_CASES}) OR "
        f"(event.case_id IS NULL AND event.actor_id = {_ACTOR}) OR "
        "(SELECT iam.rls_holds_global('audit.read')) OR "
        "(event.case_id IS NULL AND event.object_type = 'ingest' AND "
        "(SELECT iam.rls_holds_global('ingest.manage')))")

#: Who appends a row (frozen text): every writer. What a request may name on
#: the row is pinned by 0150's trigger, which fires before this is checked.
APPEND = "true"

#: Carries the quarantine-era state of records attached before this
#: revision onto their case (see "The backfill" above). Read-only over the
#: log until the INSERT; run before row security is enabled.
BACKFILL_SQL = """
INSERT INTO audit.event
       (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
SELECT NULL, 'SYSTEM', c.action, 'ingest', c.object_id, c.case_id,
       c.detail || jsonb_build_object('carried', jsonb_build_object(
         'seq', c.seq,
         'at', to_char(c.occurred_at AT TIME ZONE 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'),
         'by', c.actor_id::text,
         'backfilled', '0168'))
  FROM (
    SELECT t.action, t.object_id, r.case_id, t.detail, t.seq,
           t.occurred_at, t.actor_id
      FROM ingest.record r
      JOIN LATERAL (SELECT e.action, e.object_id, e.case_id, e.detail, e.seq,
                           e.occurred_at, e.actor_id
                      FROM audit.event e
                     WHERE e.object_id = r.id
                       AND e.action = 'INGEST_RECORD_TRIAGED'
                     ORDER BY e.seq DESC LIMIT 1) t ON true
     WHERE r.case_id IS NOT NULL AND t.case_id IS NULL
       AND coalesce(t.detail ->> 'state', 'NEW') <> 'NEW'
    UNION ALL
    SELECT f.action, f.object_id, r.case_id, f.detail, f.seq,
           f.occurred_at, f.actor_id
      FROM ingest.record r
      JOIN LATERAL (SELECT e.action, e.object_id, e.case_id, e.detail, e.seq,
                           e.occurred_at, e.actor_id
                      FROM audit.event e
                     WHERE e.object_id = r.id
                       AND e.action = 'INGEST_CATEGORY_CORRECTED'
                     ORDER BY e.seq ASC LIMIT 1) f ON true
     WHERE r.case_id IS NOT NULL AND f.case_id IS NULL
       AND NOT EXISTS (SELECT 1 FROM audit.event k
                        WHERE k.object_id = r.id
                          AND k.action = 'INGEST_CATEGORY_CORRECTED'
                          AND k.case_id IS NOT NULL)
  ) c
 ORDER BY c.seq;
"""

UPGRADE_SQL = f"""
ALTER TABLE audit.event ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_read ON audit.event FOR SELECT USING ({READ});
CREATE POLICY rls_append ON audit.event FOR INSERT WITH CHECK ({APPEND});
"""

DOWNGRADE_SQL = """
DROP POLICY rls_append ON audit.event;
DROP POLICY rls_read ON audit.event;
ALTER TABLE audit.event DISABLE ROW LEVEL SECURITY;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    # Before ENABLE: the backfill reads every case-less row, and the
    # owner is exempt either way, but a revision that reads the log under
    # its own policy is one edit away from reading less than it thinks.
    run(BACKFILL_SQL)
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
