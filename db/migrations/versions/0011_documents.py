"""The aggregation bucket and its outflow: document, extraction, proposal,
watch_hit.

Machines propose, analysts dispose (invariant 3): extraction results
reach the graph only through proposal.
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = collect, core, public;

-- THE AGGREGATION BUCKET. One row per captured item.
CREATE TABLE document (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id      uuid NOT NULL REFERENCES source(id),
  collection_run_id uuid REFERENCES collection_run(id),
  watch_id       uuid REFERENCES watch(id),
  -- Stable platform identity, so an edited post updates rather than
  -- duplicating, while old versions are retained.
  external_id    text,
  external_url   text,
  thread_ref     text,
  parent_ref     text,
  author_handle  text,
  author_uid     text,                     -- numeric platform id, not the name
  posted_at      timestamptz,
  captured_at    timestamptz NOT NULL DEFAULT now(),
  title          text,
  body_text      text NOT NULL,
  body_html_key  text,                     -- raw HTML in object store
  lang           text,
  content_sha256 bytea NOT NULL,
  -- Edit tracking
  version        int NOT NULL DEFAULT 1,
  supersedes_id  uuid REFERENCES document(id),
  is_deleted_upstream boolean NOT NULL DEFAULT false,
  classification tlp NOT NULL DEFAULT 'AMBER',
  search_tsv     tsvector,
  embedding      vector(768),
  triage_state   text NOT NULL DEFAULT 'NEW',  -- NEW|TRIAGED|LINKED|DISCARDED
  UNIQUE (source_id, external_id, version)
);

CREATE INDEX ON document USING gin (search_tsv);
CREATE INDEX ON document USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON document (source_id, posted_at DESC);
CREATE INDEX ON document (content_sha256);
CREATE INDEX ON document (triage_state) WHERE triage_state = 'NEW';
CREATE INDEX ON document USING gin (author_handle gin_trgm_ops);

-- Selectors/entities pulled out of documents by extractors.
CREATE TABLE extraction (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id   uuid NOT NULL REFERENCES document(id) ON DELETE CASCADE,
  selector_type text NOT NULL REFERENCES selector_type(key),
  raw_value     text NOT NULL,
  norm_value    text NOT NULL,
  char_start    int,
  char_end      int,
  extractor     text NOT NULL,
  extractor_version text,
  score         numeric(4,3),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON extraction (norm_value, selector_type);
CREATE INDEX ON extraction (document_id);

-- Extractions become graph changes ONLY through an approved proposal.
-- Machines propose; analysts dispose.
CREATE TABLE proposal (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       uuid NOT NULL REFERENCES "case"(id),
  kind          text NOT NULL,             -- CREATE_NODE|CREATE_EDGE|MERGE|ATTR
  payload       jsonb NOT NULL,
  origin        text NOT NULL,             -- extractor / rule / model name
  score         numeric(4,3),
  rationale     text NOT NULL,
  document_id   uuid REFERENCES document(id),
  state         review_state NOT NULL DEFAULT 'PROPOSED',
  reviewed_by   uuid,
  reviewed_at   timestamptz,
  review_note   text,
  applied_node_id uuid REFERENCES node(id),
  applied_edge_id uuid REFERENCES edge(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON proposal (case_id, state) WHERE state = 'PROPOSED';

CREATE TABLE watch_hit (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  watch_id     uuid NOT NULL REFERENCES watch(id) ON DELETE CASCADE,
  document_id  uuid NOT NULL REFERENCES document(id) ON DELETE CASCADE,
  matched_on   jsonb NOT NULL,             -- {keywords:[...], selectors:[...]}
  score        numeric(4,3),
  created_at   timestamptz NOT NULL DEFAULT now(),
  -- Notification lifecycle
  notified_at  timestamptz,
  suppressed   boolean NOT NULL DEFAULT false,
  suppress_reason text,
  acknowledged_by uuid,
  acknowledged_at timestamptz,
  UNIQUE (watch_id, document_id)
);
CREATE INDEX ON watch_hit (created_at DESC) WHERE notified_at IS NULL AND NOT suppressed;
""")


def downgrade() -> None:
    run("""
DROP TABLE collect.watch_hit;
DROP TABLE collect.proposal;
DROP TABLE collect.extraction;
DROP TABLE collect.document;
""")
