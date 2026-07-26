"""Populate evidence.search_tsv so full-text search over evidence works.

evidence has a search_tsv column and a GIN index (0008) but no trigger
filled it, so evidence search returned nothing. This adds the maintenance
trigger, mirroring node_tsv / document_tsv: title (A) + description (B) +
extracted_text (C), with the same 500k cap so a huge extracted body can't
exceed the 1MB tsvector limit and fail the write.
"""
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.evidence_tsv_update() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT'
     OR NEW.title IS DISTINCT FROM OLD.title
     OR NEW.description IS DISTINCT FROM OLD.description
     OR NEW.extracted_text IS DISTINCT FROM OLD.extracted_text THEN
    NEW.search_tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
     || setweight(to_tsvector('simple', coalesce(NEW.description,'')), 'B')
     || setweight(to_tsvector('simple', left(coalesce(NEW.extracted_text,''), 500000)), 'C');
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_tsv BEFORE INSERT OR UPDATE ON core.evidence
  FOR EACH ROW EXECUTE FUNCTION core.evidence_tsv_update();
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS evidence_tsv ON core.evidence;
DROP FUNCTION IF EXISTS core.evidence_tsv_update();
""")
