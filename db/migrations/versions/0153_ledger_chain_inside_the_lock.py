"""The ledgers draw their sequence inside the chain lock (F51, 2026-10-03).

## What was wrong (evidence-audit-chain-forks, 2026-10-03)

`audit.event.seq` and `core.evidence_custody.id` were column defaults
(`nextval`), drawn when the row is constructed, BEFORE the BEFORE INSERT
trigger takes the chain's advisory lock. Two writers handed 33 and 34 could
take the lock in the opposite order: 33 then chained off 34, and the next
writer, which picks the tail as the highest seq, chained off 34 too. Row 33
was a dead end that nothing named as its predecessor, and the pair was a
fork. Measured on 2026-10-03 at revision 0152, four owner connections
appending in parallel forked the chain in 8 rounds of 10 (19 rows sharing a
predecessor), and the review reproduced the same pairs in ordinary test
traffic. The verifier and the CI step called forks harmless ("not known to
be reachable by ordinary traffic"), so a dead-end row could be deleted and
the answer stayed intact.

## What this changes

Each chain trigger now takes the lock FIRST, then draws the sequence, then
reads the tail, so seq order is chain order and the tail it reads is the
last committed row:

- `audit.chain_hash()` (0013, made a definer by 0150) and
  `core.custody_chain_hash()` (0024, a definer since 0113) are restated
  here, whole, as frozen text. `NEW.seq` and `NEW.id` are assigned by the
  trigger whatever the caller supplied, so a caller can neither choose its
  place in the chain nor skip ahead of it. `NEW.occurred_at` is
  `clock_timestamp()` read INSIDE the lock, once it is granted, on both
  ledgers: the database's clock at the append, never the caller's and never
  the start of the caller's transaction (see "The time", below).
- The column defaults are dropped. A default would draw a second, wasted
  value per row and put the draw back outside the lock for any insert that
  runs with the trigger stood down. `collect.egress_connection` (0086) has
  been built this way from its first row.
- The hash input is unchanged character for character, so `_HASH_EXPR` in
  `audit_verify.py` and `custody_verify.py` still matches (the untouched-chain
  tests hold them together), and every row already written still verifies.

## The isolation guard (verify:g37 tail-read-isolation, 2026-10-03)

The tail is read after the lock is taken, in a statement of its own, so it
sees every row committed before the lock was granted. That holds only under
READ COMMITTED, where each statement takes a new snapshot. Under REPEATABLE
READ or SERIALIZABLE the transaction's snapshot predates the wait for the
lock, the tail it reads is stale, and the append chains off an old row: a
fork, which the verifier counts as tampering since this revision (measured
on 2026-10-03: a bound analyst that began REPEATABLE READ forked the chain
and `verify_chain` then reported two FORK breaks that no later write clears).
The first draft of this revision assumed nothing sets a level. The request
role is the untrusted party (0152's premise) and chooses its own: `BEGIN
ISOLATION LEVEL ...`, or `SET default_transaction_isolation` for the session.

So each trigger now REFUSES the append unless the transaction is READ
COMMITTED, before it takes the lock (a refused append never queues behind
it). READ UNCOMMITTED passes: PostgreSQL runs it as READ COMMITTED, a new
snapshot per statement. The refusal is `invalid_transaction_state` (25000)
and not `serialization_failure` (40001), which drivers retry under the same
level and would retry forever. A transaction cannot change its level after
its first statement, so the caller cannot move the check, and no code of
this product sets a level (every connection is `psycopg`'s default,
`isolation_level` appears nowhere, no server or role default is set). What
this leaves: whoever owns the table or is a superuser can stand the trigger
down altogether, which is tampering, and the verifier says so.
`test_the_ledger_triggers_refuse_an_append_outside_read_committed` holds it
at both levels, on both ledgers, for the request role and the owner.

## The time (evidence-ledger-actor-time-forgeable, 2026-10-03)

`now()` is the transaction START in PostgreSQL. Pinning `occurred_at` to it
(this revision's first draft, and custody since 0024) took the choice from the
caller and handed it a different one: a request-role transaction held open
stamped its row with the time it BEGAN, in the past by its own age (8.1 s
measured on 2026-10-03, and unbounded, because nothing in the repository or
the infrastructure sets `idle_in_transaction_session_timeout`). The lock is
taken only at the INSERT, so an idle open transaction blocks nobody and is
easy to hold, and a row could then carry a time earlier than the rows before
it in the chain with nothing noticing, since the verifier orders by seq.
`clock_timestamp()` read after the lock is granted is the time of the append
itself: no caller can stamp a row earlier than the append that wrote it,
and time order is chain order, because the one writer that holds the lock is
the one reading the clock. The one way it can run backwards is the
server's own clock stepping back; the time is NOT clamped to the previous
row's (`GREATEST`), because a row written before this revision may carry any
time its writer chose, in the future included, and a clamp would stamp every
later row with it. The hash input renders `occurred_at` as before, so rows
already written still verify.

What a reader sees differently: a row appended earlier in a transaction is now
LATER than that transaction's `now()` (it used to equal it). The one reader of
the log that compares its times with a `now()` is the seven-day rule,
`iam.countersign_blocked_by` (0075: events at or before `as_of`, which a
decision takes from `now()` at the time it is made). In service every such
event is a request of its own, committed before the decision, so nothing
changes; two tests that wrote the event and the decision in ONE transaction
(`test_dual_control_policy_pg`) now write the event first, in its own.

## The sequences are no longer the request role's

Nothing outside the definer trigger draws from `audit.event_seq_seq` or
`core.evidence_custody_id_seq` any more, so `noctornal_app` and
`noctornal_worker` lose USAGE and SELECT on both. That closes the volume side
channel the verify pass of 2026-10-03 measured: `SELECT last_value FROM
audit.event_seq_seq` returned the owner's max(seq) to a bound analyst who may
read none of the log. What this does NOT close, and what remains:

- `INSERT ... RETURNING seq, prev_hash` on a row the writer may read (its own
  case-less row) returns the newest seq of the whole log and the hash of its
  newest row, which the writer may not read. No application code asks for a
  row back (`test_rls_audit_paths.test_no_append_asks_for_its_row_back`), so
  this needs SQL as the request role. The `seq` column stays readable to it
  because the queue's triage lookup orders by it.
- Timing: an append waits on the chain lock while another writer holds it,
  which tells a caller that someone else is appending, and nothing more.
- A caller's own rows, which it reads under the policy.

`scripts/runtime_roles.py ensure` replays `REVOKE_SQL` below after 0108's
grants, which would otherwise hand the sequences back to a role created
later.

## What does not change

The advisory lock key (`approvals.holds_audit_chain_lock` reads it), the
hash input, the append-only triggers and the order of the chain on rows
written before this revision: a fork already in a database stays where it
is. The verifier's fork boundary (`AUDIT_CHAIN_SERIALISED`, below) is what
tells an old fork from a new one.

## The boundary marker

On a database whose audit log or custody ledger already holds rows this
revision appends one audit row, `AUDIT_CHAIN_SERIALISED` (SYSTEM actor,
object type `audit`), whose detail names the revision and the newest custody
id at that moment. If the revision is applied twice (a downgrade and an
upgrade) the verifier reads the LATEST marker: every row between the two
was written by the older trigger, which forks, and the marker is the point
after which the fixed one wrote every row. The request role cannot append a
row with this action (0152's INSERT policy refuses it), so only a migration,
the system role or the owner moves the boundary. The verifier
counts a fork whose claimant is newer than that row as a break, because a
chain written by this trigger cannot fork: honest traffic does not, and the
isolation guard refuses the one transaction level that could. The older ones
are reported as what they are. A database born at this
revision has no marker and no older rows: its boundary is zero.

## Downgrade

Restores the trigger bodies and defaults this revision replaced (0150's
state for the audit chain, 0113's for the custody chain) and gives the two
roles their sequence privileges back. The marker row stays (the log is
append-only); a verifier of an earlier revision does not read it.
"""
from alembic import op

revision = "0153"
down_revision = "0152"
branch_labels = None
depends_on = None

MARKER_ACTION = "AUDIT_CHAIN_SERIALISED"

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp"


def _isolation_guard(ledger: str) -> str:
    """The refusal both triggers open with. 25000, not 40001: a driver
    retries a serialization failure under the same level, for ever."""
    return f"""  IF pg_catalog.current_setting('transaction_isolation')
       NOT IN ('read committed', 'read uncommitted') THEN
    RAISE EXCEPTION '{ledger} is appended in READ COMMITTED only, this transaction is %',
      pg_catalog.current_setting('transaction_isolation')
      USING ERRCODE = 'invalid_transaction_state',
            HINT = 'Run the append in a READ COMMITTED transaction.';
  END IF;"""

#: The canonical hash input, as 0013 wrote it. Frozen: `audit_verify._HASH_EXPR`
#: is the same text with the row alias, and a test holds the two equal.
AUDIT_CHAIN = f"""
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger
  LANGUAGE plpgsql {_DEFINER}
AS $$
DECLARE prev bytea;
BEGIN
  /* 0. The isolation level (verify:g37 tail-read-isolation, 2026-10-03). The
     tail read below sees the last committed row only where every statement
     takes a new snapshot; a stale one forks the chain. Refused before the
     lock, so a refusal never queues behind it. */
{_isolation_guard('audit.event')}
  /* 1. The lock, first. Everything below is ordered by it. */
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('audit.event.chain', 0));
  /* 2. The sequence and the time, inside it: seq order is chain order, and
     neither is the caller's to choose. The time is the clock at the append
     (evidence-ledger-actor-time-forgeable, 2026-10-03): now() is the start
     of the caller's transaction, which a request can hold open. */
  NEW.seq := pg_catalog.nextval('audit.event_seq_seq');
  NEW.occurred_at := pg_catalog.clock_timestamp();
  /* 3. The tail: the last row committed before the lock was granted, read
     as the owner so a writer that may read none of the log still chains to it. */
  SELECT e.row_hash INTO prev FROM audit.event e ORDER BY e.seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    pg_catalog.convert_to(pg_catalog.concat_ws(pg_catalog.chr(31),
      coalesce(pg_catalog.encode(prev, 'hex'), 'GENESIS'),
      pg_catalog.to_char(NEW.occurred_at AT TIME ZONE 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      coalesce(NEW.actor_id::text, '-'),
      NEW.actor_kind,
      NEW.action,
      coalesce(NEW.object_type, '-'),
      coalesce(NEW.object_id::text, '-'),
      coalesce(NEW.case_id::text, '-'),
      NEW.outcome,
      NEW.detail::text,
      coalesce(pg_catalog.encode(NEW.ip_hash, 'hex'), '-'),
      coalesce(NEW.session_id::text, '-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$;
"""

#: 0024's body, with the lock first and the draw inside it.
CUSTODY_CHAIN = f"""
CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger
  LANGUAGE plpgsql {_DEFINER}
AS $$
DECLARE prev bytea;
BEGIN
  /* Isolation guard, lock, then the draw and the clock inside it, then the
     tail: the reasons are the audit trigger's (above). */
{_isolation_guard('core.evidence_custody')}
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('core.evidence_custody.chain', 0));
  NEW.id := pg_catalog.nextval('core.evidence_custody_id_seq');
  NEW.occurred_at := pg_catalog.clock_timestamp();
  SELECT c.row_hash INTO prev FROM core.evidence_custody c ORDER BY c.id DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    pg_catalog.convert_to(pg_catalog.concat_ws(pg_catalog.chr(31),
      coalesce(pg_catalog.encode(prev, 'hex'), 'GENESIS'),
      NEW.evidence_id::text,
      NEW.action,
      coalesce(NEW.actor_id::text, '-'),
      pg_catalog.to_char(NEW.occurred_at AT TIME ZONE 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      NEW.detail::text,
      coalesce(NEW.hash_verified::text, '-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$;
"""

DROP_DEFAULTS = """
ALTER TABLE audit.event ALTER COLUMN seq DROP DEFAULT;
ALTER TABLE core.evidence_custody ALTER COLUMN id DROP DEFAULT;
"""

#: Both runtime roles, guarded on the role and the sequence existing (a
#: database with no runtime roles, or built from schema.sql, grants nothing).
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


#: Replayed by scripts/runtime_roles.py after 0108's grants on a cluster
#: whose roles were created later.
REVOKE_SQL = _sequence_privileges("REVOKE", "FROM")
GRANT_SQL = _sequence_privileges("GRANT", "TO")

#: The marker the verifier reads as the fork boundary, only where either
#: ledger already has rows. The newest custody id at this moment goes with it.
MARKER_SQL = f"""
INSERT INTO audit.event (actor_kind, action, object_type, detail)
SELECT 'SYSTEM', '{MARKER_ACTION}', 'audit',
       jsonb_build_object(
         'revision', '0153',
         'custody_boundary_id',
         (SELECT coalesce(max(c.id), 0) FROM core.evidence_custody c))
 WHERE EXISTS (SELECT 1 FROM audit.event)
    OR EXISTS (SELECT 1 FROM core.evidence_custody);
"""

#: What this revision replaced, for the downgrade: 0013 and 0024's bodies as
#: 0150 and 0113 left them (definer, pinned path), and the column defaults.
PRIOR_AUDIT_CHAIN = """
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('audit.event.chain', 0));
  SELECT row_hash INTO prev FROM audit.event ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    convert_to(concat_ws(chr(31),
      coalesce(encode(prev,'hex'),'GENESIS'),
      to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      coalesce(NEW.actor_id::text,'-'),
      NEW.actor_kind,
      NEW.action,
      coalesce(NEW.object_type,'-'),
      coalesce(NEW.object_id::text,'-'),
      coalesce(NEW.case_id::text,'-'),
      NEW.outcome,
      NEW.detail::text,
      coalesce(encode(NEW.ip_hash,'hex'),'-'),
      coalesce(NEW.session_id::text,'-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$;
"""

PRIOR_CUSTODY_CHAIN = """
CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE prev bytea;
BEGIN
  NEW.occurred_at := now();
  PERFORM pg_advisory_xact_lock(hashtextextended('core.evidence_custody.chain', 0));
  SELECT row_hash INTO prev FROM core.evidence_custody ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    convert_to(concat_ws(chr(31),
      coalesce(encode(prev,'hex'),'GENESIS'),
      NEW.evidence_id::text,
      NEW.action,
      coalesce(NEW.actor_id::text,'-'),
      to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      NEW.detail::text,
      coalesce(NEW.hash_verified::text,'-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$;
"""

RESTORE_DEFAULTS = """
ALTER TABLE audit.event ALTER COLUMN seq SET DEFAULT nextval('audit.event_seq_seq');
ALTER TABLE core.evidence_custody ALTER COLUMN id SET DEFAULT nextval('core.evidence_custody_id_seq');
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(AUDIT_CHAIN)
    run(CUSTODY_CHAIN)
    run(DROP_DEFAULTS)
    run(REVOKE_SQL)
    run(MARKER_SQL)


def downgrade() -> None:
    run(GRANT_SQL)
    run(RESTORE_DEFAULTS)
    run(PRIOR_CUSTODY_CHAIN)
    run(PRIOR_AUDIT_CHAIN)
