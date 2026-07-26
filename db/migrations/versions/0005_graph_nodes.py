"""Graph nodes and selectors (core.node, core.selector).

created_by FKs to iam arrive in 0014 (cross-schema pass), exactly as in
the reference DDL.
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE node (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES "case"(id) ON DELETE RESTRICT,
  node_type      text NOT NULL REFERENCES node_type(key),
  -- Human-facing label. Denormalised for graph render speed; the
  -- authoritative value lives in attrs / assertions.
  label          text NOT NULL,
  attrs          jsonb NOT NULL DEFAULT '{}'::jsonb,
  classification tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{}',
  -- World-time existence of the thing itself (group founded/disbanded,
  -- persona created/abandoned).
  valid_from     timestamptz,
  valid_to       timestamptz,
  first_seen     timestamptz,
  last_seen      timestamptz,
  -- System-time. Soft delete only; nodes are never hard-deleted outside
  -- an authorised purge job.
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     uuid NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz,
  deleted_by     uuid,
  -- Entity resolution: when two identities are merged, the loser points
  -- here rather than being destroyed. Merges must be reversible.
  merged_into_id uuid REFERENCES node(id),
  merged_at      timestamptz,
  merged_by      uuid,
  search_tsv     tsvector,
  embedding      vector(768)
);

CREATE INDEX ON node (case_id, node_type) WHERE deleted_at IS NULL AND merged_into_id IS NULL;
CREATE INDEX ON node USING gin (search_tsv);
CREATE INDEX ON node USING gin (label gin_trgm_ops);
CREATE INDEX ON node USING gin (attrs jsonb_path_ops);
CREATE INDEX ON node USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON node (merged_into_id) WHERE merged_into_id IS NOT NULL;

-- Selector values get their own table rather than living in node.attrs.
-- They are the join key for entity resolution and need exact-match
-- indexes and a normalised form.
CREATE TABLE selector (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  selector_type   text NOT NULL REFERENCES selector_type(key),
  raw_value       text NOT NULL,
  -- Normalised per type: lowercase handles, checksum-cased BTC, E.164
  -- phone, punycode domains, stripped Gmail dots, etc.
  norm_value      text NOT NULL,
  node_id         uuid REFERENCES node(id),   -- owning IDENTITY/PERSON/ASSET
  first_seen      timestamptz,
  last_seen       timestamptz,
  observation_cnt int NOT NULL DEFAULT 1,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, selector_type, norm_value)
);

CREATE INDEX ON selector (selector_type, norm_value);   -- cross-case pivot
CREATE INDEX ON selector (node_id);
CREATE INDEX ON selector USING gin (norm_value gin_trgm_ops);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.selector;
DROP TABLE core.node;
""")
