"""Collected-document vectors, labelled by trigger (F6.1, embeddings,
2026-09-24).

## What this adds

`collect.document_embedding`, one row per (document, slot): the outcome
of embedding that document in the space holding the slot. EMBEDDED rows
carry the vector; EMPTY (nothing left after normalising), EXCLUDED
(victim data, never embedded anywhere), WITHHELD (the MEANING gate
refused to send it) and FAILED (retried with backoff) rows carry a reason
and no vector, so an item is never pending for ever and never indexed by
accident.

## The labels are the document's, set by the database

`read_classification` is greatest(document, source) and
`read_compartments` the document's compartments, sorted and de-duplicated.
Trigger `document_embedding_labels` sets both on INSERT from the document
and source rows it locks FOR SHARE, whatever the writer supplied, and
refuses a purged or missing document. It fires on UPDATE only when one of
those three columns is named, and then refuses: a row that exists already
carries its document's current labels, because any change to them
deletes the row (below). Firing on every UPDATE took the document lock on
each re-judgement and each admin recheck, in the reverse order of a
relabel, which is a deadlock waiting to happen.
The one UPDATE of the labels it lets through is the compartment
lifecycle's rename, which replaces a key in place and changes nothing
else (docs/05, "Binding a compartment column", rule 5).

## A change deletes the vectors, in the writer's own transaction

`document_vectors_follow` (AFTER UPDATE of classification, compartments,
category, title, body_text or purged_at, when one really changed) and
`source_vectors_follow` (AFTER UPDATE of a source's classification or
kind) delete the affected rows and queue the documents again, unless
purged. So a vector row never carries a label, a key or a text its
document no longer has; a compartment rename (compartment_lifecycle's
array_replace) deletes the rows of every document carrying the old key,
and the pass re-embeds them under the new one; and a relabelled document
is never left in a lower partition, so it cannot displace anything a
reader receives. `document_embedding_queued` queues every new document for
every building or active space.

## Bound, although derived (docs/00 decision 71)

`read_compartments` stores compartment keys, so it is bound by the
contract of 0069 (docs/05, rule 1: a copy deleted whenever its source
changes is still a copy): the `compartments_registered` trigger rendered
from a local copy of 0059's `trigger_sql`, and `ADDED_BOUND_COLUMNS`, with
the same line in compartment_lifecycle.BOUND_COLUMNS. The registry then
counts the vector rows as carriers of a key, a retire is refused while any
carries it (none can outlive the documents that carry it), and a rename
reaches them. Read as a derived column the catalogue need not know, it
would break docs/00 decision 71 and fail
test_compartment_binding_pg.py. The registry trigger sees the value the
writer supplied, before `document_embedding_labels` replaces it with the
document's own keys, which are registered because the document's column is
bound.

## Partitioned indexes

Fifteen partial HNSW indexes, one per (slot, TLP level), each over the
uncompartmented EMBEDDED rows of exactly one label, so a reader's
nearest-neighbour search walks only graphs of rows it may read and rows
above it can neither be returned nor crowd out the rows it may (the
displacement test in test_similarity_labels_pg.py). Compartmented rows
are reached by an exact branch through a GIN index on
`read_compartments`, which fetches only rows sharing a key the reader
holds rather than every compartmented row at the reader's level
(a cost that followed hidden material was a
small volume oracle). HNSW rather than IVFFlat: it builds incrementally
on an empty table inside a migration and needs no training. Built on an
empty table, so the upgrade is instant.

## Downgrade

Drops the triggers, the table and its functions, and the queue's
document entries. Vectors are derived: a re-upgrade re-embeds on the next
pass, which for a MEANING space sends the eligible text to the model
endpoint again, audited as the first time.
"""
from __future__ import annotations

from alembic import op

revision = "0092"
down_revision = "0091"
branch_labels = None
depends_on = None

#: The TLP levels, in core.tlp's order. One partial HNSW index per slot and
#: level; embeddings.py composes the same names.
LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")
SLOTS = (1, 2, 3)

#: The column this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("collect", "document_embedding", "read_compartments", "array"),
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


#: The document columns whose change deletes the vectors. Named once so
#: test_document_embeddings_pg.py holds the trigger to the list.
FOLLOWED_COLUMNS = ("classification", "compartments", "category", "title",
                    "body_text", "purged_at")


def index_name(slot: int, level: str) -> str:
    return f"document_embedding_s{slot}_{level.lower()}_hnsw"


def _hnsw_indexes() -> str:
    return "\n".join(
        f"CREATE INDEX {index_name(slot, level)} ON collect.document_embedding "
        f"USING hnsw (embedding vector_cosine_ops) "
        f"WHERE slot = {slot} AND read_classification = '{level}'::core.tlp "
        f"AND read_compartments = '{{}}'::text[] AND embedding IS NOT NULL;"
        for slot in SLOTS for level in LEVELS)


_WHEN = " OR ".join(f"OLD.{c} IS DISTINCT FROM NEW.{c}" for c in FOLLOWED_COLUMNS)

UPGRADE_SQL = f"""
CREATE TABLE collect.document_embedding (
  document_id uuid NOT NULL REFERENCES collect.document (id) ON DELETE CASCADE,
  slot smallint NOT NULL,
  space_id uuid NOT NULL,
  status text NOT NULL
    CHECK (status IN ('EMBEDDED', 'EMPTY', 'EXCLUDED', 'WITHHELD', 'FAILED')),
  embedding vector(768),
  reason text,
  read_classification core.tlp NOT NULL,
  read_compartments text[] NOT NULL DEFAULT '{{}}',
  sent_classification core.tlp,
  input_chars integer NOT NULL DEFAULT 0 CHECK (input_chars >= 0),
  truncated_chars integer NOT NULL DEFAULT 0 CHECK (truncated_chars >= 0),
  attempts smallint NOT NULL DEFAULT 1 CHECK (attempts >= 1),
  first_failed_at timestamptz,
  next_attempt_at timestamptz,
  embedded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (document_id, slot),
  FOREIGN KEY (space_id, slot) REFERENCES core.embedding_space (id, slot),
  CONSTRAINT document_embedding_vector_iff_embedded
    CHECK ((status = 'EMBEDDED') = (embedding IS NOT NULL)),
  CONSTRAINT document_embedding_reason_unless_embedded
    CHECK ((status = 'EMBEDDED') = (reason IS NULL)),
  CONSTRAINT document_embedding_retry_dated
    CHECK (status NOT IN ('FAILED', 'WITHHELD') OR next_attempt_at IS NOT NULL),
  CONSTRAINT document_embedding_failure_dated
    CHECK ((status = 'FAILED') = (first_failed_at IS NOT NULL)),
  CONSTRAINT document_embedding_sent_only_embedded
    CHECK (sent_classification IS NULL OR status = 'EMBEDDED')
);

COMMENT ON TABLE collect.document_embedding IS
  'One similarity outcome per collected document and slot (F6.1). The labels '
  'are set by trigger from the document and its source; a change to either '
  'deletes the row. A vector is handled as its text: it never leaves the '
  'database through the product.';

CREATE FUNCTION collect.document_embedding_labels() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  d_cls core.tlp;
  d_comp text[];
  d_purged timestamptz;
  s_cls core.tlp;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    -- The compartment lifecycle's rename replaces a key in place and
    -- changes nothing else (docs/05, rule 5); anything else is refused.
    IF NEW.document_id IS DISTINCT FROM OLD.document_id
       OR NEW.read_classification IS DISTINCT FROM OLD.read_classification
       OR cardinality(NEW.read_compartments)
          IS DISTINCT FROM cardinality(OLD.read_compartments) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'a vector row keeps the document and labels it was written with: a '
        'change to its document deletes it instead';
    END IF;
    RETURN NEW;
  END IF;
  SELECT d.classification, d.compartments, d.purged_at, s.classification
    INTO d_cls, d_comp, d_purged, s_cls
    FROM collect.document d JOIN collect.source s ON s.id = d.source_id
   WHERE d.id = NEW.document_id
     FOR SHARE OF d, s;
  IF NOT FOUND OR d_purged IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its document, and this document is missing or purged';
  END IF;
  NEW.read_classification := greatest(d_cls, s_cls);
  NEW.read_compartments := coalesce(
    (SELECT array_agg(DISTINCT x ORDER BY x) FROM unnest(d_comp) AS x),
    '{{}}'::text[]);
  RETURN NEW;
END $$;

CREATE TRIGGER document_embedding_labels
  BEFORE INSERT OR UPDATE OF document_id, read_classification, read_compartments
  ON collect.document_embedding
  FOR EACH ROW EXECUTE FUNCTION collect.document_embedding_labels();

{trigger_sql("collect", "document_embedding", "read_compartments", "array")}

CREATE FUNCTION collect.document_vectors_follow() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM collect.document_embedding WHERE document_id = NEW.id;
  IF NEW.purged_at IS NULL THEN
    PERFORM core.embedding_enqueue('document', NEW.id);
  ELSE
    DELETE FROM core.embedding_pending
     WHERE kind = 'document' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER document_vectors_follow
  AFTER UPDATE OF {", ".join(FOLLOWED_COLUMNS)} ON collect.document
  FOR EACH ROW WHEN ({_WHEN})
  EXECUTE FUNCTION collect.document_vectors_follow();

CREATE FUNCTION collect.source_vectors_follow() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM collect.document_embedding e
   USING collect.document d
   WHERE e.document_id = d.id AND d.source_id = NEW.id;
  INSERT INTO core.embedding_pending (slot, kind, item_id)
  SELECT s.slot, 'document', d.id
    FROM collect.document d CROSS JOIN core.embedding_space s
   WHERE d.source_id = NEW.id AND d.purged_at IS NULL
     AND s.state IN ('BUILDING', 'ACTIVE')
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;

CREATE TRIGGER source_vectors_follow
  AFTER UPDATE OF classification, kind ON collect.source
  FOR EACH ROW WHEN (OLD.classification IS DISTINCT FROM NEW.classification
                     OR OLD.kind IS DISTINCT FROM NEW.kind)
  EXECUTE FUNCTION collect.source_vectors_follow();

CREATE FUNCTION collect.document_embedding_queued() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM core.embedding_enqueue('document', NEW.id);
  RETURN NULL;
END $$;

CREATE TRIGGER document_embedding_queued
  AFTER INSERT ON collect.document
  FOR EACH ROW WHEN (NEW.purged_at IS NULL)
  EXECUTE FUNCTION collect.document_embedding_queued();

{_hnsw_indexes()}

CREATE INDEX document_embedding_space_status
  ON collect.document_embedding (space_id, status);
CREATE INDEX document_embedding_due
  ON collect.document_embedding (slot, next_attempt_at)
  WHERE status IN ('FAILED', 'WITHHELD');
CREATE INDEX document_embedding_compartmented
  ON collect.document_embedding USING gin (read_compartments)
  WHERE read_compartments <> '{{}}'::text[];
"""

DOWNGRADE_SQL = """
DROP TRIGGER document_embedding_queued ON collect.document;
DROP TRIGGER source_vectors_follow ON collect.source;
DROP TRIGGER document_vectors_follow ON collect.document;
DROP TABLE collect.document_embedding;
DROP FUNCTION collect.document_embedding_queued();
DROP FUNCTION collect.source_vectors_follow();
DROP FUNCTION collect.document_vectors_follow();
DROP FUNCTION collect.document_embedding_labels();
DELETE FROM core.embedding_pending WHERE kind = 'document';
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
