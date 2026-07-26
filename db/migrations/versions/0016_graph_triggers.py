"""Search-vector maintenance, edge-endpoint validation, TLP floor.

Generated columns would be cleaner, but tsvector generation over jsonb is
not immutable, so triggers it is.
"""
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.node_tsv_update() RETURNS trigger AS $$
BEGIN
  -- Recompute only when the indexed text changed; bookkeeping updates
  -- (last_seen, soft delete, merge) must not churn the GIN index.
  -- left() caps the input: to_tsvector rejects >1MB vectors, and a
  -- failed capture is worse than truncated search.
  IF TG_OP = 'INSERT' OR NEW.label IS DISTINCT FROM OLD.label
     OR NEW.attrs IS DISTINCT FROM OLD.attrs THEN
    NEW.search_tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.label,'')), 'A')
     || setweight(to_tsvector('simple', left(coalesce(NEW.attrs::text,''), 500000)), 'C');
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER node_tsv BEFORE INSERT OR UPDATE ON core.node
  FOR EACH ROW EXECUTE FUNCTION core.node_tsv_update();

CREATE OR REPLACE FUNCTION collect.document_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.search_tsv :=
      setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
   || setweight(to_tsvector('simple', coalesce(NEW.author_handle,'')), 'B')
   -- Capped: combo lists / credential dumps exceed the 1MB tsvector limit
   -- and must land with degraded search rather than fail to land at all.
   || setweight(to_tsvector('simple', left(coalesce(NEW.body_text,''), 500000)), 'C');
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER document_tsv BEFORE INSERT OR UPDATE ON collect.document
  FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();

-- Stops the graph turning to soup. An edge whose endpoints violate the
-- ontology is a modelling error, and modelling errors compound.
CREATE OR REPLACE FUNCTION core.validate_edge_endpoints() RETURNS trigger AS $$
DECLARE
  et      RECORD;
  src_ty  text;
  dst_ty  text;
BEGIN
  NEW.updated_at := now();
  -- Endpoints unchanged → nothing to re-validate. Without this, narrowing
  -- an edge_type's allowed endpoints later makes existing nonconforming
  -- edges un-updatable — including the soft delete that removes them.
  IF TG_OP = 'UPDATE' AND NEW.edge_type = OLD.edge_type
     AND NEW.src_node_id = OLD.src_node_id AND NEW.dst_node_id = OLD.dst_node_id
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT * INTO et FROM core.edge_type WHERE key = NEW.edge_type;
  SELECT node_type INTO src_ty FROM core.node WHERE id = NEW.src_node_id;
  SELECT node_type INTO dst_ty FROM core.node WHERE id = NEW.dst_node_id;

  IF NOT (src_ty = ANY(et.src_node_types)) THEN
    RAISE EXCEPTION 'edge %: source node type % not permitted (allowed: %)',
      NEW.edge_type, src_ty, et.src_node_types;
  END IF;
  IF NOT (dst_ty = ANY(et.dst_node_types)) THEN
    RAISE EXCEPTION 'edge %: target node type % not permitted (allowed: %)',
      NEW.edge_type, dst_ty, et.dst_node_types;
  END IF;

  -- Cross-case edges are never legitimate. Cross-case *pivoting* happens
  -- through selector matching and an access request, not by drawing an
  -- edge that would leak one case's structure into another.
  IF (SELECT case_id FROM core.node WHERE id = NEW.src_node_id) <> NEW.case_id
     OR (SELECT case_id FROM core.node WHERE id = NEW.dst_node_id) <> NEW.case_id THEN
    RAISE EXCEPTION 'edge % spans cases', NEW.edge_type;
  END IF;

  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER edge_validate BEFORE INSERT OR UPDATE ON core.edge
  FOR EACH ROW EXECUTE FUNCTION core.validate_edge_endpoints();

-- A child may be more restricted than its case, never less.
CREATE OR REPLACE FUNCTION core.enforce_tlp_floor() RETURNS trigger AS $$
DECLARE case_tlp core.tlp;
BEGIN
  -- Bookkeeping updates that touch neither classification nor case must
  -- not re-run the floor check: if a case's floor is raised later,
  -- pre-existing rows would otherwise be un-updatable — including the
  -- very UPDATE that would remediate their classification. INSERTs and
  -- classification changes are always checked.
  IF TG_OP = 'UPDATE' AND NEW.classification = OLD.classification
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT classification INTO case_tlp FROM core."case" WHERE id = NEW.case_id;
  IF NEW.classification < case_tlp THEN
    RAISE EXCEPTION 'classification % is below the case floor of %',
      NEW.classification, case_tlp;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER node_tlp     BEFORE INSERT OR UPDATE ON core.node     FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
CREATE TRIGGER edge_tlp     BEFORE INSERT OR UPDATE ON core.edge     FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
CREATE TRIGGER evidence_tlp BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
""")


def downgrade() -> None:
    run("""
DROP TRIGGER evidence_tlp ON core.evidence;
DROP TRIGGER edge_tlp ON core.edge;
DROP TRIGGER node_tlp ON core.node;
DROP FUNCTION core.enforce_tlp_floor();
DROP TRIGGER edge_validate ON core.edge;
DROP FUNCTION core.validate_edge_endpoints();
DROP TRIGGER document_tsv ON collect.document;
DROP FUNCTION collect.document_tsv_update();
DROP TRIGGER node_tsv ON core.node;
DROP FUNCTION core.node_tsv_update();
""")
