"""Compartments on `collect.document`, so a capture into a compartmented
case can be stored under the case's compartments (L1, 2026-09-24).

## What was wrong

`collect.document` hangs off a source, not a case, and had no
compartments: a document was listed, searched and cited by clearance
alone. Final review c15 (2026-09-24) therefore refused every capture into
a compartmented case, because the stored text would have been readable
outside the compartment at any label. An analyst on a compartmented case
had no way to capture at all.

## What this adds

1. `compartments text[] NOT NULL DEFAULT '{}'`: the need-to-know lock the
   document is read under. A capture copies its case's compartments; every
   person-facing reader checks `d.compartments <@` their own
   (docs/05, and test_document_reads_check_compartments.py holds every
   reader to it). Adding a column with a constant default is metadata
   only on PostgreSQL 16, so this does not rewrite the table.
2. The binding, by the contract 0069 set (docs/05, "Binding a compartment
   column"): the `compartments_registered` trigger, rendered by the local
   copy of 0059's `trigger_sql` below, and `ADDED_BOUND_COLUMNS`. The
   registry functions are not touched: 0069 reads bindings from the
   catalog, so this column is guarded from the moment its trigger exists.
3. `document_compartments_idx`, a GIN index over compartmented rows only.
   The registry's leg and `compartment_lifecycle`'s rename and retire ask
   `cardinality(compartments) > 0 AND compartments @> ARRAY[key]`, and
   they ask it while every bound table is locked; without the index that
   is a scan of the table of forum bodies with every writer waiting.
4. `document_tsv` fires only when indexed text changes: `UPDATE OF title,
   author_handle, body_text, purged_at`. It fired on EVERY update, so a
   triage click, a relabel or a compartment rename rebuilt a tsvector of
   up to 500 KB. And a purge's `search_tsv = NULL` never held: the same
   trigger rebuilt the vector from the title at once. The function now
   leaves a purged row's vector NULL. A later migration that adds a column
   to the vector adds it to this list.

## Downgrade

Refuses while any document carries a compartment: dropping the column
would leave each readable by clearance alone, outside the compartments it
was captured under (0063's precedent for a downgrade that would
declassify). Otherwise it restores the trigger without a column list and
the function's old body, and drops the index, the binding and the column.
"""
from __future__ import annotations

from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None

#: The columns this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("collect", "document", "compartments", "array"),
)

TRIGGER_NAME = "compartments_registered"


def trigger_sql(schema: str, table: str, column: str, kind: str) -> str:
    """The binding on one column: a local copy of 0059's `trigger_sql`
    (migrations do not import each other)."""
    when = (f"cardinality(NEW.{column}) > 0" if kind == "array"
            else f"NEW.{column} IS NOT NULL")
    return (
        f"CREATE TRIGGER {TRIGGER_NAME}\n"
        f'  BEFORE INSERT OR UPDATE OF {column} ON {schema}."{table}"\n'
        f"  FOR EACH ROW WHEN ({when})\n"
        f"  EXECUTE FUNCTION iam.refuse_unregistered_compartment("
        f"'{column}', '{kind}');")


#: The body 0016 installed, restored by the downgrade.
TSV_BODY_0016 = """
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
"""

#: The body from here on: 0016's, with a purged row left unindexed.
TSV_BODY = """
CREATE OR REPLACE FUNCTION collect.document_tsv_update() RETURNS trigger AS $$
BEGIN
  -- A purged document keeps its row and loses its content; its vector
  -- goes too, rather than being rebuilt from what is left (L1, 2026-09-24).
  IF NEW.purged_at IS NOT NULL THEN
    NEW.search_tsv := NULL;
    RETURN NEW;
  END IF;
  NEW.search_tsv :=
      setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
   || setweight(to_tsvector('simple', coalesce(NEW.author_handle,'')), 'B')
   -- Capped: combo lists / credential dumps exceed the 1MB tsvector limit
   -- and must land with degraded search rather than fail to land at all.
   || setweight(to_tsvector('simple', left(coalesce(NEW.body_text,''), 500000)), 'C');
  RETURN NEW;
END $$ LANGUAGE plpgsql;
"""

#: The columns the vector is built from, plus purged_at. Named once so the
#: test holds the trigger to it.
TSV_COLUMNS = ("title", "author_handle", "body_text", "purged_at")

UPGRADE_SQL = f"""
ALTER TABLE collect.document
  ADD COLUMN compartments text[] NOT NULL DEFAULT '{{}}';

COMMENT ON COLUMN collect.document.compartments IS
  'The need-to-know lock a document is read under. A capture copies the '
  'compartments of the case it was captured into; a collected document '
  'carries what its collection path assigns (none, until a source carries '
  'compartments). Every reader checks d.compartments <@ its own. Bound to '
  'iam.compartment by the compartments_registered trigger.';

{trigger_sql("collect", "document", "compartments", "array")}

CREATE INDEX document_compartments_idx ON collect.document
  USING gin (compartments) WHERE cardinality(compartments) > 0;

{TSV_BODY}

DROP TRIGGER document_tsv ON collect.document;
CREATE TRIGGER document_tsv
  BEFORE INSERT OR UPDATE OF {", ".join(TSV_COLUMNS)} ON collect.document
  FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();
"""

COUNT_SQL = ("SELECT count(*) FROM collect.document "
             "WHERE cardinality(compartments) > 0")

def downgrade_refusal(n: int) -> str:
    """The refusal, its noun, verb and pronouns agreeing with the count. An
    operator reads it, and the count rule holds for operator text too (L1,
    2026-09-24: it said '1 document carry'); a migration does
    not import the app, so this does locally what noctornal_api.wording
    does."""
    if n == 1:
        head = ("1 document carries compartments; dropping the column would "
                "make it readable by clearance alone, outside the compartments "
                "it was captured under. Remove it first")
    else:
        head = (f"{n} documents carry compartments; dropping the column would "
                "make each readable by clearance alone, outside the "
                "compartments it was captured under. Remove them first")
    return (head + " (SELECT id FROM collect.document WHERE "
            "cardinality(compartments) > 0), or stay at this revision.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(f"""
DROP TRIGGER document_tsv ON collect.document;
{TSV_BODY_0016}
CREATE TRIGGER document_tsv BEFORE INSERT OR UPDATE ON collect.document
  FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();
DROP INDEX collect.document_compartments_idx;
DROP TRIGGER {TRIGGER_NAME} ON collect."document";
ALTER TABLE collect.document DROP COLUMN compartments;
""")
