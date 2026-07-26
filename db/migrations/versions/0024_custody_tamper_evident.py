"""Make the custody ledger tamper-EVIDENT, not just append-only.

The 0023 append-only trigger stops UPDATE/DELETE/TRUNCATE, but a custody
row is still forgeable on INSERT: the caller could supply any occurred_at
(back-dating) or any actor_id (a non-existent or framed analyst), and
deletion is undetectable if a table owner disables the trigger. For a
record whose whole purpose is chain-of-custody, that is not enough
(US FRE 902(13)-(14); Canada Evidence Act ss. 31.1-31.8).

This migration:
- FKs actor_id -> iam.app_user(id): a custody entry cannot name a
  non-existent actor.
- Server-pins occurred_at to now() on INSERT: no back-dating.
- Hash-chains the ledger (prev_hash / row_hash), the same construction as
  audit.event (0013): each row commits to the previous, so a deleted or
  reordered row is detectable on replay even if the append-only trigger
  was disabled out of band.
"""
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

ALTER TABLE core.evidence_custody
  ADD CONSTRAINT evidence_custody_actor_fk
      FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

ALTER TABLE core.evidence_custody ADD COLUMN prev_hash bytea;
ALTER TABLE core.evidence_custody ADD COLUMN row_hash  bytea;

-- BEFORE INSERT: pin the timestamp and extend the hash chain. Runs before
-- the row_hash NOT-NULL check below, so a bypass INSERT (trigger disabled)
-- leaves row_hash NULL and is rejected outright.
CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  NEW.occurred_at := now();  -- server-pinned; any caller value is ignored
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
END $$ LANGUAGE plpgsql SET search_path = public, pg_catalog;

CREATE TRIGGER custody_chain BEFORE INSERT ON core.evidence_custody
  FOR EACH ROW EXECUTE FUNCTION core.custody_chain_hash();

ALTER TABLE core.evidence_custody ALTER COLUMN row_hash SET NOT NULL;
""")


def downgrade() -> None:
    run("""
SET search_path = core, public;
DROP TRIGGER IF EXISTS custody_chain ON core.evidence_custody;
DROP FUNCTION IF EXISTS core.custody_chain_hash();
ALTER TABLE core.evidence_custody DROP COLUMN IF EXISTS row_hash;
ALTER TABLE core.evidence_custody DROP COLUMN IF EXISTS prev_hash;
ALTER TABLE core.evidence_custody DROP CONSTRAINT IF EXISTS evidence_custody_actor_fk;
""")
