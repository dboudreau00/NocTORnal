"""Audit log: append-only, hash-chained, nobody can delete (invariant 6).

The chain serialises via advisory lock, hashes a UTC-canonical
delimiter-separated rendering of EVERY payload column, and pins its
search_path so a hardened session cannot break audited writes.
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = audit, core, public;

CREATE TABLE event (
  seq          bigserial PRIMARY KEY,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid,
  actor_kind   text NOT NULL DEFAULT 'USER',  -- USER|SERVICE|SYSTEM
  action       text NOT NULL,
  object_type  text,
  object_id    uuid,
  case_id      uuid,
  outcome      text NOT NULL DEFAULT 'SUCCESS',
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_hash      bytea,
  session_id   uuid,
  -- Tamper evidence: each row hashes the previous row's hash.
  prev_hash    bytea,
  row_hash     bytea NOT NULL
);
CREATE INDEX ON event (occurred_at DESC);
CREATE INDEX ON event (actor_id, occurred_at DESC);
CREATE INDEX ON event (object_id);
CREATE INDEX ON event (case_id, occurred_at DESC);

-- The REVOKE below is documentation only (PUBLIC holds no DML by default;
-- the table owner is unaffected). The trigger is the enforcement: no code
-- path, migration or admin tool mutates history without first being seen
-- to drop the trigger. Invariant 6.
REVOKE UPDATE, DELETE, TRUNCATE ON audit.event FROM PUBLIC;

CREATE FUNCTION audit.block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit.event is append-only (invariant 6)';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.block_mutation();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event
  FOR EACH STATEMENT EXECUTE FUNCTION audit.block_mutation();

-- search_path is pinned on the function: digest() lives in public and
-- plpgsql resolves names under the CALLER's path at runtime — a hardened
-- session (search_path = '') would otherwise abort every audited write.
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  -- Serialise chain extension. Without this, two concurrent writers read
  -- the same tail and fork the chain — honest history then replays as
  -- tampering, the worst failure mode a tamper-evidence mechanism has.
  PERFORM pg_advisory_xact_lock(hashtextextended('audit.event.chain', 0));
  SELECT row_hash INTO prev FROM audit.event ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  -- Canonical hash input: UTC-fixed timestamp rendering (timestamptz::text
  -- follows the session TimeZone GUC and would make the chain unverifiable
  -- from any other session), EVERY payload column (an unhashed column is
  -- an editable column), and an explicit field separator (unseparated
  -- concatenation lets boundary shifts collide).
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
END $$ LANGUAGE plpgsql SET search_path = public, pg_catalog;

CREATE TRIGGER audit_chain BEFORE INSERT ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.chain_hash();

-- NOTE: the advisory lock serialises audit writes under contention. At
-- high volume, move chaining to a single-threaded appender or batch-chain
-- every N rows with a periodic checkpoint hash. Correctness first.
""")


def downgrade() -> None:
    run("""
DROP TRIGGER audit_chain ON audit.event;
DROP FUNCTION audit.chain_hash();
DROP TRIGGER event_no_truncate ON audit.event;
DROP TRIGGER event_append_only ON audit.event;
DROP FUNCTION audit.block_mutation();
DROP TABLE audit.event;
""")
