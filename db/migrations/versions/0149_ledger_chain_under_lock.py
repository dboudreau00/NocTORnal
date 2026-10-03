"""The audit and custody chains take their sequence inside the chain lock
(evidence-audit-chain-forks, 2026-10-03).

## What was wrong

`audit.event.seq` and `core.evidence_custody.id` are serial columns. A
column default is evaluated BEFORE a BEFORE INSERT trigger runs, so both
ledgers drew their number before `audit.chain_hash()` and
`core.custody_chain_hash()` took the advisory lock that serialises the
chain. Two writers handed 33 and 34 could reach the lock in the opposite
order: 34 chained off the old tail, 33 then chained off 34, and the next
writer, which picks its predecessor as the HIGHEST number, chained off 34
too. Row 33 is a dead end that nothing names as a predecessor. The two rows
that claim 34 are a fork.

The verifier lists forks and leaves them out of `intact`, on the stated
ground that ordinary traffic cannot make one. It can: the review found 10
rows on an ordinary test run, 5 pairs, in each the lower number chained off
the higher. And a dead end is a row whose removal orphans nothing, so with
table-owner rights it can be deleted while `/audit/verify` and
`/audit/custody/verify` still answer intact.

## The fix

Each function now takes the lock first, THEN assigns the number
(`NEW.seq := nextval(...)`, `NEW.id := nextval(...)`) and reads the tail,
exactly as `collect.egress_connection_chain` has done since 0086. Number
order is chain order: a number is drawn only by the writer that holds the
lock, so the next number is always above every number already written, and
"the highest number" is the true tail. The column default stays in this
revision (a row written with the trigger stood down, which the verifier tests
do, still gets a number); the trigger overrides it, so a caller can no longer
choose a number either, and each append burns one extra value, which is
harmless. 0169 takes the default away, with the runtime roles' privilege on the
two sequences.

The hash expressions are copied character for character, so every row
already written verifies as before and the verifiers' duplicated
`_HASH_EXPR` stays valid.

Both are SECURITY DEFINER with `search_path = pg_catalog, pg_temp`
(`custody_chain_hash` already was since 0113 and keeps its path). The tail
read must see the real tail whoever writes: a role that row-level security
filters would read a filtered tail and fork the chain. 0168 puts `audit.event`
under row-level security and relies on this: an append by a request that may
read none of the log still chains to the true tail.

## The isolation guard

The tail is read after the lock is taken, in a statement of its own, so it
sees every row committed before the lock was granted. That holds only under
READ COMMITTED, where each statement takes a new snapshot. Under REPEATABLE
READ or SERIALIZABLE the snapshot predates the wait for the lock, the tail it
reads is stale, and the append chains off an old row: a fork, which the
verifier counts as a break. The request role is the untrusted party and
chooses its own level (`BEGIN ISOLATION LEVEL ...`, or `SET
default_transaction_isolation` for the session; measured on 2026-10-03: a bound
analyst that began REPEATABLE READ forked the chain). So each function refuses
the append unless the transaction is READ COMMITTED, BEFORE it takes the lock,
so a refusal never queues behind it. READ UNCOMMITTED passes: PostgreSQL runs it
as READ COMMITTED, a new snapshot per statement. The refusal is
`invalid_transaction_state` (25000) and not `serialization_failure` (40001),
which a driver retries under the same level for ever. A transaction cannot
change its level after its first statement, so the caller cannot move the
check, and no code in the product sets a level. Whoever owns the table can
stand the trigger down altogether, which is tampering, and the verifier says
so.

## The time

`now()` is the START of the caller's transaction. Pinning `occurred_at` to it
(custody since 0024) took the choice from the caller and handed it a different
one: a request-role transaction held open stamped its row with the time it
began, in the past by its own age (8.1 s measured on 2026-10-03, and unbounded,
because nothing in the repository or the infrastructure sets
`idle_in_transaction_session_timeout`). The lock is taken only at the INSERT,
so an idle open transaction blocks nobody and is easy to hold, and a row could
carry a time earlier than the rows before it in the chain with nothing
noticing, since the verifier orders by number. Both functions now read
`clock_timestamp()` AFTER the lock is granted: the time of the append itself,
so no caller can stamp a row earlier than the append that wrote it, and time
order is chain order, because the one writer that holds the lock is the one
reading the clock.

The custody function does it for every writer, as it always pinned the time.
The audit function does it for the callers 0150 pins (the request role): that
trigger runs BEFORE this one and, for such a caller, sets `occurred_at` to
`infinity`, a mark that no stored row carries, which this function replaces
with the clock once it holds the lock. The mark, and not a second look at who
the caller is, because asking costs a catalog read and none belongs inside the
serialised section. The owner and the system role keep the time they supply,
as before: they are trusted writers, and the owner can drop the trigger
anyway. The time is not clamped with GREATEST: a row written before this
revision may carry any time its writer chose, a future one included, and a
clamp would copy it into every later row. The one way time runs backwards is
the server's own clock stepping back; the verifier orders by number and does
not read time as evidence.

What a reader sees differently: a request-role audit row, and any custody row,
appended earlier in a transaction is now LATER than that transaction's `now()`
(it used to equal it). The one reader of the log that compares its times with a
`now()` is the seven-day rule, `iam.countersign_blocked_by` (0075: events at or
before `as_of`, which a decision takes from `now()`). In service each such event
is a request of its own, committed before the decision.

## The boundary

History keeps the forks the old order made, and an append-only ledger cannot
be cleaned. `audit.chain_ordered_after()` and
`core.custody_chain_ordered_after()` answer the largest number that existed
when this revision ran, taken under the chain lock. A number above it was
drawn by the fixed writer, so a fork whose claimants are ALL above it cannot
come from ordinary traffic and the verifiers count it as a break. A fork with
a claimant at or below it is legacy and stays a separate, quieter finding.
The boundary is a constant in the function body: the request role cannot
alter it, and the owner who can is the owner the external anchor exists for
(`/audit/verify` tail_row_hash, 2026-10-03).

Two operating facts follow from the boundary being a number read once
(g49v-boundary-operating-notes, 2026-10-03). Run this revision with the API
stopped, as `scripts/launch.*` and `release/install.sh` do: a writer that is
mid-insert under the OLD function text drew its number before the lock, so it
can land above the boundary this revision records and a fork it makes then
reads as a fresh one (a break that is not tampering, never a missed one).
And a downgrade followed by an upgrade records a NEW, higher boundary: forks
written while the revision was absent become legacy, which is the downgrade's
stated effect.

## Downgrade

Restores both functions to their text at 0131, with their SQL comments left
out (the code is identical), and drops the boundary functions.
A fork written while this revision was absent is then legacy again.
"""
from alembic import op

revision = "0149"
down_revision = "0148"
branch_labels = None
depends_on = None

#: Frozen text. A later revision that changes either function restates it.
AUDIT_CHAIN_SQL = """
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE prev bytea;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation')
       NOT IN ('read committed', 'read uncommitted') THEN
    RAISE EXCEPTION 'audit.event is chained under READ COMMITTED only, and this transaction is %: a snapshot taken before the last append cannot see the tail',
      pg_catalog.current_setting('transaction_isolation')
      USING ERRCODE = 'invalid_transaction_state',
            HINT = 'Run the append in a READ COMMITTED transaction.';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit.event.chain', 0));
  NEW.seq := nextval('audit.event_seq_seq');
  IF NEW.occurred_at = 'infinity'::pg_catalog.timestamptz THEN
    NEW.occurred_at := pg_catalog.clock_timestamp();
  END IF;
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
END $fn$;
"""

CUSTODY_CHAIN_SQL = """
CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
AS $fn$
DECLARE prev bytea;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation')
       NOT IN ('read committed', 'read uncommitted') THEN
    RAISE EXCEPTION 'core.evidence_custody is chained under READ COMMITTED only, and this transaction is %: a snapshot taken before the last append cannot see the tail',
      pg_catalog.current_setting('transaction_isolation')
      USING ERRCODE = 'invalid_transaction_state',
            HINT = 'Run the append in a READ COMMITTED transaction.';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('core.evidence_custody.chain', 0));
  NEW.id := nextval('core.evidence_custody_id_seq');
  NEW.occurred_at := pg_catalog.clock_timestamp();
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
END $fn$;
"""

#: The boundary constants are written by this block, under the chain locks,
#: so no writer is between drawing a number and chaining while they are read.
BOUNDARY_SQL = """
DO $do$
DECLARE
  a bigint;
  c bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('audit.event.chain', 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('core.evidence_custody.chain', 0));
  SELECT greatest(coalesce((SELECT max(seq) FROM audit.event), 0),
                  CASE WHEN s.is_called THEN s.last_value ELSE 0 END)
    INTO a FROM audit.event_seq_seq s;
  SELECT greatest(coalesce((SELECT max(id) FROM core.evidence_custody), 0),
                  CASE WHEN s.is_called THEN s.last_value ELSE 0 END)
    INTO c FROM core.evidence_custody_id_seq s;
  EXECUTE format('CREATE OR REPLACE FUNCTION audit.chain_ordered_after() '
                 'RETURNS bigint LANGUAGE sql IMMUTABLE AS %L',
                 'SELECT ' || a || '::bigint');
  EXECUTE format('CREATE OR REPLACE FUNCTION core.custody_chain_ordered_after() '
                 'RETURNS bigint LANGUAGE sql IMMUTABLE AS %L',
                 'SELECT ' || c || '::bigint');
END $do$;

COMMENT ON FUNCTION audit.chain_ordered_after() IS
  'The largest audit.event.seq that existed when 0149 ran. A fork whose claimants are all above it cannot come from ordinary traffic.';
COMMENT ON FUNCTION core.custody_chain_ordered_after() IS
  'The largest core.evidence_custody.id that existed when 0149 ran. A fork whose claimants are all above it cannot come from ordinary traffic.';
"""

UPGRADE_SQL = AUDIT_CHAIN_SQL + CUSTODY_CHAIN_SQL + BOUNDARY_SQL

#: Restores 0013's audit.chain_hash and 0024's custody_chain_hash as 0113
#: left it, for a downgrade. The SQL comments are left out; the code is the same.
PRIOR_AUDIT_CHAIN_SQL = """
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger
  LANGUAGE plpgsql SET search_path TO 'public', 'pg_catalog'
AS $fn$
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
END $fn$;
"""

PRIOR_CUSTODY_CHAIN_SQL = """
CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $fn$
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
END $fn$;
"""

DOWNGRADE_SQL = (
    "DROP FUNCTION audit.chain_ordered_after();\n"
    "DROP FUNCTION core.custody_chain_ordered_after();\n"
    + PRIOR_AUDIT_CHAIN_SQL + PRIOR_CUSTODY_CHAIN_SQL)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
