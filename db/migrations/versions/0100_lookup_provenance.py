"""Provenance from a lookup answer to the proposals and claims it raised
(F15.3, 2026-09-24).

## What this adds

- `collect.proposal.lookup_result_id`: the answer a machine proposal was
  raised from. ProposalStore reads the answer's label into the proposal's
  read label (proposals._SOURCE_FROM), so a RED answer's proposal is hidden
  from an AMBER reader exactly as a RED capture's is.
- `core.assertion.lookup_result_id`: the answer an accepted claim rests on,
  beside the source_id of the provider's anchor source. Only an
  AUTOMATED_INFERENCE claim may carry one (a CHECK).

## Constraints added NOT VALID, and left so

Both columns are new, so every existing row is NULL and satisfies both
constraints. Every revision runs in one transaction (env.py), so a
VALIDATE here would scan core.assertion under the ACCESS EXCLUSIVE lock
the ADD COLUMN already holds, blocking every claim read and write for
the scan, which is the outcome NOT VALID exists to avoid. New rows are
checked either way. 0040 left its constraint NOT VALID for the same
reason. No index on core.assertion.lookup_result_id: results are never
deleted, so the FK needs no referencing-side index, and no read filters
on it. lock_timeout bounds how long this waits for the locks.

## Downgrade

Refuses when any lookup answer belongs to a case under legal hold, BEFORE
dropping anything (each revision commits on
its own, so a refusal left to 0099 would come after this one had already
destroyed the claim-to-answer provenance of a held case). Otherwise drops
both columns: accepted claims keep source_id and their '[lookup/...]'
rationale and lose only the link to the stored answer.
"""
from alembic import op

revision = "0100"
down_revision = "0099"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET LOCAL lock_timeout = '5s';
ALTER TABLE collect.proposal ADD COLUMN lookup_result_id uuid;
ALTER TABLE collect.proposal ADD CONSTRAINT proposal_lookup_result_fk
  FOREIGN KEY (lookup_result_id) REFERENCES ingest.lookup_result(id) NOT VALID;
CREATE INDEX proposal_lookup_result_idx ON collect.proposal (lookup_result_id)
  WHERE lookup_result_id IS NOT NULL;
ALTER TABLE core.assertion ADD COLUMN lookup_result_id uuid;
ALTER TABLE core.assertion ADD CONSTRAINT assertion_lookup_result_fk
  FOREIGN KEY (lookup_result_id) REFERENCES ingest.lookup_result(id) NOT VALID;
ALTER TABLE core.assertion ADD CONSTRAINT assertion_lookup_is_inference
  CHECK (lookup_result_id IS NULL OR basis = 'AUTOMATED_INFERENCE') NOT VALID;
COMMENT ON COLUMN collect.proposal.lookup_result_id IS
  'The lookup answer this proposal was raised from; its label joins the '
  'proposal''s read label.';
COMMENT ON COLUMN core.assertion.lookup_result_id IS
  'The lookup answer an accepted claim rests on (AUTOMATED_INFERENCE only).';
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE n bigint;
BEGIN
  IF to_regclass('ingest.lookup_result') IS NOT NULL THEN
    SELECT count(*) INTO n FROM ingest.lookup_result r
      JOIN core."case" c ON c.id = r.case_id WHERE c.legal_hold;
    IF n > 0 THEN
      RAISE EXCEPTION 'refusing to downgrade 0100: lookup answers belong to a case under legal hold, and legal hold overrides deletion';
    END IF;
  END IF;
END
$pre$;
ALTER TABLE core.assertion
  DROP CONSTRAINT IF EXISTS assertion_lookup_is_inference,
  DROP CONSTRAINT IF EXISTS assertion_lookup_result_fk,
  DROP COLUMN IF EXISTS lookup_result_id;
DROP INDEX IF EXISTS collect.proposal_lookup_result_idx;
ALTER TABLE collect.proposal
  DROP CONSTRAINT IF EXISTS proposal_lookup_result_fk,
  DROP COLUMN IF EXISTS lookup_result_id;
""")
