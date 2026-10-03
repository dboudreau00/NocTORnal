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

and APPENDS a row whatever case it names, as long as the row names nobody
or the user the connection is bound to: the log is append-only (UPDATE,
DELETE and TRUNCATE are refused by trigger and by privilege) and every
writer appends, including a writer that may read none of it. The INSERT
policy is `WITH CHECK (actor_id IS NULL OR actor_id = iam.rls_actor() OR
(a ticket event AND actor_id = iam.rls_ticket_holder()))`, less the one
action `AUDIT_CHAIN_SERIALISED`, the boundary marker 0153 appends, which
only a migration, the system role or the owner writes
(revised 2026-10-03, evidence-ledger-actor-time-forgeable: it was `true`,
so a connection bound to analyst A could write "LEGAL_HOLD_LIFTED by B"
and the chain would hash it). The time is the database's too: 0153 sets
`occurred_at` in the chain trigger from the clock at the append, read inside
the chain lock (not `now()`, the start of a transaction a request can hold
open; evidence-ledger-actor-time-forgeable, 2026-10-03). No append in the
product asks for its row back (`RETURNING`), which would be refused for a
row its writer may not read; `test_rls_audit_paths.py` holds every writer to
that.

A ticket redemption on the sample origin (which runs no session and holds no
system connection) writes four events about the ticket's holder, spent or
refused (`TICKET_EVENTS`); the connection presents the ticket first
(`db.present_ticket`) and the policy admits a row naming the holder of the
ticket presented (`iam.rls_ticket_holder()`, created here), so the holder's
ticket is what attributes it. No other event takes this term.

An unbound connection's actor, cases and grants are empty or NULL, so it
reads nothing and appends only rows that name nobody. The events that are
about a user the connection is not bound to (a session refused before the
connection is bound to it, a binding that failed, a refusal written out of
band, a sign-in outcome) go on a system connection for the AUDIT_APPEND
purpose, or are written while the binding still holds
(`deps.audit_append_connection`, `routers.auth.logout`).

## What had to move first (F51)

- The chain trigger and the countersigning rule read the whole log as the
  definer (0166), so an append chains to the true tail and the two-person
  control still sees an administrator's reset of the signer's account.
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

## The backfill (verify:g37, 2026-10-03)

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

What the backfill cannot restore: the time. Every carried row has the time
of the migration (the chain trigger sets it, 0153), so a case's queue shows
the triage as made by nobody on the day of the upgrade; the original time
is in `detail.carried.at`.

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
_TICKET_HOLDER = "(SELECT iam.rls_ticket_holder())"

#: The events a ticket redemption writes about its holder, on the sample
#: origin, which runs no session and holds no system connection: the Lab's
#: download ticket and an exhibit's production ticket, spent, or refused
#: before they could be (an expired ticket, one spent already, one for
#: another object, one whose holder has lost the authority). A connection
#: that presents the ticket (`db.present_ticket`) may name the ticket's
#: holder in these four events and no others.
TICKET_EVENTS = ("ARRAY['SAMPLE_DOWNLOAD_TICKET_REDEEMED', "
                 "'SAMPLE_DOWNLOAD_TICKET_REFUSED', "
                 "'EVIDENCE_PRODUCTION_TICKET_REDEEMED', "
                 "'EVIDENCE_PRODUCTION_TICKET_REFUSED']")

#: The user a presented ticket names, whatever its state. 0111's `rls_actor`
#: binds a ticket only once it is spent, inside five minutes, for an active
#: account; a refusal is about a ticket that is none of those. The proof is
#: the same one (`noctornal.rls_ticket`, set by `iam.rls_bind_ticket`, the
#: secret whose sha256 the ticket row holds), so naming the holder needs the
#: holder's ticket in hand. SECURITY DEFINER with the pinned path as 0111's.
TICKET_HOLDER_SQL = """
CREATE FUNCTION iam.rls_ticket_holder() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.user_id
    FROM lab.download_ticket t
   WHERE t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
           nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''),
           'UTF8'))
$$;
"""

#: Who reads a row (CUSTOM_AUDIT). Frozen text: a later revision that
#: changes it restates it.
READ = (f"event.case_id = ANY ({_CASES}) OR "
        f"(event.case_id IS NULL AND event.actor_id = {_ACTOR}) OR "
        "(SELECT iam.rls_holds_global('audit.read')) OR "
        "(event.case_id IS NULL AND event.object_type = 'ingest' AND "
        "(SELECT iam.rls_holds_global('ingest.manage')))")

#: Who appends a row (frozen text): one that names nobody, or the user the
#: connection is bound to. Everything else that names a user is written by a
#: system connection (AUDIT_APPEND) or while the binding holds. The chain's
#: boundary marker (0153) is never a request's to write: the verifier counts
#: a fork newer than the latest marker as tampering.
APPEND = ("event.action <> 'AUDIT_CHAIN_SERIALISED' AND "
          f"(event.actor_id IS NULL OR event.actor_id = {_ACTOR} OR "
          f"(event.action = ANY ({TICKET_EVENTS}) AND "
          f"event.actor_id = {_TICKET_HOLDER}))")

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
{TICKET_HOLDER_SQL}
ALTER TABLE audit.event ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_read ON audit.event FOR SELECT USING ({READ});
CREATE POLICY rls_append ON audit.event FOR INSERT WITH CHECK ({APPEND});
"""

DOWNGRADE_SQL = """
DROP POLICY rls_append ON audit.event;
DROP POLICY rls_read ON audit.event;
ALTER TABLE audit.event DISABLE ROW LEVEL SECURITY;
DROP FUNCTION IF EXISTS iam.rls_ticket_holder();
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
