"""Tagging and analyst working sets: tag, tag_assignment, node_set(_member).

tag_assignment.document_id FK arrives in 0014 (collect.document exists
from 0011).
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE tag (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     uuid REFERENCES "case"(id),   -- NULL = global taxonomy
  namespace   text NOT NULL,                -- 'ttp','role','priority','mitre'
  name        text NOT NULL,
  colour      text,
  description text,
  parent_id   uuid REFERENCES tag(id),      -- hierarchical taxonomies
  external_id text                          -- e.g. MITRE ATT&CK T1566
);

-- Expression-based uniqueness must be an index, not a table constraint.
-- Two indexes because NULL case_id (global taxonomy) needs its own rule.
CREATE UNIQUE INDEX tag_uniq_case   ON tag (case_id, namespace, name) WHERE case_id IS NOT NULL;
CREATE UNIQUE INDEX tag_uniq_global ON tag (namespace, name)          WHERE case_id IS NULL;

CREATE TABLE tag_assignment (
  tag_id      uuid NOT NULL REFERENCES tag(id) ON DELETE CASCADE,
  node_id     uuid REFERENCES node(id),
  edge_id     uuid REFERENCES edge(id),
  evidence_id uuid REFERENCES evidence(id),
  document_id uuid,
  assigned_by uuid NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tag_one_target CHECK (num_nonnulls(node_id, edge_id, evidence_id, document_id) = 1)
);
CREATE INDEX ON tag_assignment (node_id);
CREATE INDEX ON tag_assignment (tag_id);

-- Ad-hoc analyst groupings that are NOT ontological claims. Keeps
-- working sets out of the graph where they would distort metrics.
CREATE TABLE node_set (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    uuid NOT NULL REFERENCES "case"(id),
  name       text NOT NULL,
  purpose    text,
  is_pinned  boolean NOT NULL DEFAULT false,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE node_set_member (
  set_id  uuid NOT NULL REFERENCES node_set(id) ON DELETE CASCADE,
  node_id uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  note    text,
  PRIMARY KEY (set_id, node_id)
);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.node_set_member;
DROP TABLE core.node_set;
DROP TABLE core.tag_assignment;
DROP TABLE core.tag;
""")
