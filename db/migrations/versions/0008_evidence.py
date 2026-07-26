"""Evidence with chain of custody: evidence, evidence_custody, evidence_link.

Prosecution-grade (decision 13, US + Canada): WORM-locked storage keys,
append-only custody ledger, hash captured at ingest.
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE evidence (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  title           text NOT NULL,
  description     text,
  media_type      text NOT NULL,
  byte_size       bigint NOT NULL,
  -- Integrity. sha256 at ingest, never recomputed from a mutated copy.
  sha256          bytea NOT NULL,
  blake3          bytea,
  -- WORM object store key. Object-lock retention set at PUT time.
  storage_key     text NOT NULL,
  storage_bucket  text NOT NULL,
  is_worm_locked  boolean NOT NULL DEFAULT true,
  -- Acquisition context — the questions a defence team will ask.
  acquired_at     timestamptz NOT NULL,
  acquired_by     uuid NOT NULL,
  acquisition_method text NOT NULL,        -- MANUAL_UPLOAD, COLLECTOR, LEGAL
  source_url       text,
  collection_account_id uuid,              -- which persona captured it
  collection_run_id     uuid,
  classification  tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  -- Derived, searchable text. Original bytes are never modified.
  extracted_text  text,
  extract_status  text NOT NULL DEFAULT 'PENDING',
  search_tsv      tsvector,
  created_at      timestamptz NOT NULL DEFAULT now(),
  legal_hold      boolean NOT NULL DEFAULT false,
  retention_until date,
  UNIQUE (case_id, sha256)                 -- dedupe within a case
);

CREATE INDEX ON evidence USING gin (search_tsv);
CREATE INDEX ON evidence (sha256);         -- cross-case artefact pivot
CREATE INDEX ON evidence (case_id, acquired_at DESC);

-- Append-only custody ledger. Every touch, including reads.
CREATE TABLE evidence_custody (
  id           bigserial PRIMARY KEY,
  evidence_id  uuid NOT NULL REFERENCES evidence(id),
  action       text NOT NULL,              -- ACQUIRED, VIEWED, EXPORTED, HASH_VERIFIED
  actor_id     uuid NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  hash_verified boolean
);
CREATE INDEX ON evidence_custody (evidence_id, occurred_at);

-- Evidence attaches to any number of nodes/edges. This is the
-- "upload evidence against the group AND the actor" requirement.
CREATE TABLE evidence_link (
  evidence_id  uuid NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  node_id      uuid REFERENCES node(id),
  edge_id      uuid REFERENCES edge(id),
  relevance    text,
  page_ref     text,                       -- page / timestamp / line anchor
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT evlink_one_target CHECK (num_nonnulls(node_id, edge_id) = 1)
);
CREATE INDEX ON evidence_link (node_id);
CREATE INDEX ON evidence_link (edge_id);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.evidence_link;
DROP TABLE core.evidence_custody;
DROP TABLE core.evidence;
""")
