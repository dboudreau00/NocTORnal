"""Graph edges (core.edge) — signed, time-bounded, uniquely active."""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE edge (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES "case"(id),
  edge_type      text NOT NULL REFERENCES edge_type(key),
  src_node_id    uuid NOT NULL REFERENCES node(id),
  dst_node_id    uuid NOT NULL REFERENCES node(id),
  -- Signed graph. -1 edges are what make this a *trust* network rather
  -- than a contact network.
  sign           smallint NOT NULL DEFAULT 1 CHECK (sign IN (-1,0,1)),
  -- Raw strength (message count, tx volume, vouch count). Normalised
  -- weight for analytics is computed, not stored here.
  weight         numeric(14,4) NOT NULL DEFAULT 1.0,
  attrs          jsonb NOT NULL DEFAULT '{}'::jsonb,  -- role, tx_hash, ...
  classification tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{}',
  -- Time-bounded membership. "Was in LockBit until March" is the normal
  -- case, not the exception.
  valid_from     timestamptz,
  valid_to       timestamptz,
  -- Rolled up from supporting assertions by a trigger; cached for render.
  confidence     analytic_confidence NOT NULL DEFAULT 'LOW',
  -- TRUE when no human has ever confirmed this edge. Rendered dashed.
  -- Inferred edges NEVER silently become asserted ones.
  is_inferred    boolean NOT NULL DEFAULT false,
  inference_method text,                    -- 'CO_OCCURRENCE','STYLOMETRY',...
  review         review_state NOT NULL DEFAULT 'PROPOSED',
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     uuid NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz,
  CONSTRAINT edge_no_self_loop CHECK (src_node_id <> dst_node_id),
  CONSTRAINT edge_time_order CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

-- Parallel edges of the same type in the same interval are a modelling
-- error; distinct intervals are legitimate history.
CREATE UNIQUE INDEX edge_uniq_active ON edge (src_node_id, dst_node_id, edge_type, coalesce(valid_from,'-infinity'))
  WHERE deleted_at IS NULL;
CREATE INDEX ON edge (case_id, edge_type) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (src_node_id) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (dst_node_id) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (review) WHERE review = 'PROPOSED';
""")


def downgrade() -> None:
    run("""
DROP TABLE core.edge;
""")
