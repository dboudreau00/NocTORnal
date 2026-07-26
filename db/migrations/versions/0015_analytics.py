"""SNA metric materialisation: projection, metric_run, node_metric,
community_assignment, layout_position.

Metrics are always computed against a named projection, never "the graph"
in the abstract, because filters change every number.
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = analytics, core, public;

-- A named, reproducible view of the graph. Metrics are always computed
-- against a projection, never "the graph" in the abstract, because
-- filters change every number.
CREATE TABLE projection (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       uuid NOT NULL REFERENCES "case"(id),
  name          text NOT NULL,
  -- Which edge types count, whether inferred edges are included, the
  -- time window, minimum confidence. Reproducibility depends on this.
  edge_types    text[] NOT NULL,
  include_inferred boolean NOT NULL DEFAULT false,
  min_confidence analytic_confidence NOT NULL DEFAULT 'LOW',
  as_of_from    timestamptz,
  as_of_to      timestamptz,
  is_directed   boolean NOT NULL DEFAULT true,
  created_by    uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE metric_run (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  projection_id uuid NOT NULL REFERENCES projection(id) ON DELETE CASCADE,
  algorithm     text NOT NULL,             -- betweenness, louvain, kpp_neg...
  params        jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Approximation flag: betweenness on a big graph is sampled, and the
  -- UI must say so rather than implying exactness.
  is_approximate boolean NOT NULL DEFAULT false,
  sample_size   int,
  node_count    int,
  edge_count    int,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  duration_ms   int,
  graph_hash    bytea,                     -- cache key; skip if unchanged
  status        text NOT NULL DEFAULT 'RUNNING'
);

CREATE TABLE node_metric (
  metric_run_id uuid NOT NULL REFERENCES metric_run(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  metric        text NOT NULL,
  value         double precision NOT NULL,
  rank          int,
  percentile    numeric(5,2),
  PRIMARY KEY (metric_run_id, node_id, metric)
);
CREATE INDEX ON node_metric (node_id, metric);

CREATE TABLE community_assignment (
  metric_run_id uuid NOT NULL REFERENCES metric_run(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  community_id  int NOT NULL,
  membership_strength numeric(5,4),
  PRIMARY KEY (metric_run_id, node_id)
);

-- Saved layouts, so an analyst's mental map of the network survives
-- a page reload. Underrated: people navigate these graphs spatially.
CREATE TABLE layout_position (
  projection_id uuid NOT NULL REFERENCES projection(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  x             double precision NOT NULL,
  y             double precision NOT NULL,
  is_pinned     boolean NOT NULL DEFAULT false,
  PRIMARY KEY (projection_id, node_id)
);
""")


def downgrade() -> None:
    run("""
DROP TABLE analytics.layout_position;
DROP TABLE analytics.community_assignment;
DROP TABLE analytics.node_metric;
DROP TABLE analytics.metric_run;
DROP TABLE analytics.projection;
""")
