"""Fixed vocabularies (genuinely fixed -> enums), all in schema core."""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

-- FIRST v2.0 traffic light protocol. Drives every export, email and
-- Jira sync decision. AMBER_STRICT must never leave the boundary.
CREATE TYPE tlp AS ENUM ('CLEAR','GREEN','AMBER','AMBER_STRICT','RED');

-- NATO Admiralty Code — source reliability.
CREATE TYPE source_reliability AS ENUM ('A','B','C','D','E','F');
--   A completely reliable   B usually reliable   C fairly reliable
--   D not usually reliable  E unreliable         F cannot be judged

-- NATO Admiralty Code — information credibility.
CREATE TYPE info_credibility AS ENUM ('1','2','3','4','5','6');
--   1 confirmed  2 probably true  3 possibly true
--   4 doubtful   5 improbable     6 cannot be judged

-- ICD 203 analytic confidence. Distinct from source grading: you can
-- have high confidence from mediocre sources that corroborate, and low
-- confidence from one excellent source.
CREATE TYPE analytic_confidence AS ENUM ('LOW','MODERATE','HIGH');

-- Where the claim came from, epistemically.
CREATE TYPE assertion_basis AS ENUM (
  'DIRECT_OBSERVATION',  -- we saw the post ourselves
  'THIRD_PARTY_REPORT',  -- a vendor/partner/report said so
  'ANALYST_INFERENCE',   -- a human reasoned to it
  'AUTOMATED_INFERENCE', -- a model/heuristic proposed it
  'SELF_CLAIM',          -- the subject said it about themselves
  'LEGAL_PROCESS'        -- subpoena/warrant return, court record
);

CREATE TYPE case_status AS ENUM ('DRAFT','ACTIVE','DORMANT','CLOSED','ARCHIVED','PURGED');
CREATE TYPE review_state AS ENUM ('PROPOSED','ACCEPTED','REJECTED','SUPERSEDED','DISPUTED');
""")


def downgrade() -> None:
    run("""
DROP TYPE core.review_state;
DROP TYPE core.case_status;
DROP TYPE core.assertion_basis;
DROP TYPE core.analytic_confidence;
DROP TYPE core.info_credibility;
DROP TYPE core.source_reliability;
DROP TYPE core.tlp;
""")
