"""Exhibit and live-claim vectors, case-scoped (F6.4, embeddings,
2026-09-24).

## What this adds

`core.evidence_embedding` and `core.assertion_embedding`: the outcome of
embedding an exhibit or a claim in the space holding a slot, with the
statuses, reasons and checks of `collect.document_embedding` and without
its label columns. Similarity over case items is an EXACT scan inside
one case, ordered after every label predicate (compartments included) has
been applied to the rows compared, so there is no approximate index here
and no label partition to keep: a case holds thousands of items, not
millions, and an exact scan cannot be displaced by rows it may not read.

`case_id` is set by trigger from the parent and never trusted from the
writer. The exhibit's trigger locks it FOR SHARE and refuses a purged or
missing one. An exhibit's text or labels changing deletes its vectors in
the writer's transaction and queues it again (`evidence_vectors_follow`),
so the pass re-embeds and, for a MEANING space, judges it again. Claims
are immutable (invariant 5): a retraction or a supersession keeps their
vectors as history, similarity search leaves them out, and the queue
drops them.

New exhibits and new live claims are queued for every building or active
space.

## Downgrade

Drops the triggers, both tables, their functions and the queue's entries
for these kinds. Vectors are derived and are embedded again on the next
pass after a re-upgrade (for a MEANING space, sent again, audited).
"""
from __future__ import annotations

from alembic import op

revision = "0093"
down_revision = "0092"
branch_labels = None
depends_on = None

#: The exhibit columns whose change deletes its vectors.
FOLLOWED_COLUMNS = ("title", "description", "extracted_text", "classification",
                    "compartments", "purged_at")

_WHEN = " OR ".join(f"OLD.{c} IS DISTINCT FROM NEW.{c}" for c in FOLLOWED_COLUMNS)


def _table(kind: str, parent: str) -> str:
    return f"""
CREATE TABLE core.{kind}_embedding (
  {kind}_id uuid NOT NULL REFERENCES {parent} (id) ON DELETE CASCADE,
  slot smallint NOT NULL,
  space_id uuid NOT NULL,
  case_id uuid NOT NULL REFERENCES core."case" (id) ON DELETE CASCADE,
  status text NOT NULL
    CHECK (status IN ('EMBEDDED', 'EMPTY', 'EXCLUDED', 'WITHHELD', 'FAILED')),
  embedding vector(768),
  reason text,
  sent_classification core.tlp,
  input_chars integer NOT NULL DEFAULT 0 CHECK (input_chars >= 0),
  truncated_chars integer NOT NULL DEFAULT 0 CHECK (truncated_chars >= 0),
  attempts smallint NOT NULL DEFAULT 1 CHECK (attempts >= 1),
  first_failed_at timestamptz,
  next_attempt_at timestamptz,
  embedded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ({kind}_id, slot),
  FOREIGN KEY (space_id, slot) REFERENCES core.embedding_space (id, slot),
  CONSTRAINT {kind}_embedding_vector_iff_embedded
    CHECK ((status = 'EMBEDDED') = (embedding IS NOT NULL)),
  CONSTRAINT {kind}_embedding_reason_unless_embedded
    CHECK ((status = 'EMBEDDED') = (reason IS NULL)),
  CONSTRAINT {kind}_embedding_retry_dated
    CHECK (status NOT IN ('FAILED', 'WITHHELD') OR next_attempt_at IS NOT NULL),
  CONSTRAINT {kind}_embedding_failure_dated
    CHECK ((status = 'FAILED') = (first_failed_at IS NOT NULL)),
  CONSTRAINT {kind}_embedding_sent_only_embedded
    CHECK (sent_classification IS NULL OR status = 'EMBEDDED')
);
CREATE INDEX {kind}_embedding_case ON core.{kind}_embedding (case_id, slot);
CREATE INDEX {kind}_embedding_space_status ON core.{kind}_embedding (space_id, status);
CREATE INDEX {kind}_embedding_due ON core.{kind}_embedding (slot, next_attempt_at)
  WHERE status IN ('FAILED', 'WITHHELD');
"""


UPGRADE_SQL = f"""
{_table("evidence", "core.evidence")}
{_table("assertion", "core.assertion")}

COMMENT ON TABLE core.evidence_embedding IS
  'One similarity outcome per exhibit and slot (F6.4): the title, '
  'description and extracted text, never the bytes. case_id is set by '
  'trigger from the exhibit.';
COMMENT ON TABLE core.assertion_embedding IS
  'One similarity outcome per claim and slot (F6.4): rationale, reference '
  'and claimed values. Kept after retraction or supersession as history; '
  'search reads live claims only.';

CREATE FUNCTION core.evidence_embedding_case() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  e_case uuid;
  e_purged timestamptz;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row keeps the exhibit and case it was written for';
  END IF;
  SELECT case_id, purged_at INTO e_case, e_purged
    FROM core.evidence WHERE id = NEW.evidence_id FOR SHARE;
  IF NOT FOUND OR e_purged IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its exhibit, and this exhibit is missing or purged';
  END IF;
  NEW.case_id := e_case;
  RETURN NEW;
END $$;

CREATE TRIGGER evidence_embedding_case
  BEFORE INSERT OR UPDATE OF evidence_id, case_id ON core.evidence_embedding
  FOR EACH ROW EXECUTE FUNCTION core.evidence_embedding_case();

CREATE FUNCTION core.assertion_embedding_case() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  a_case uuid;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row keeps the claim and case it was written for';
  END IF;
  SELECT case_id INTO a_case FROM core.assertion WHERE id = NEW.assertion_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its claim, and this claim is missing';
  END IF;
  NEW.case_id := a_case;
  RETURN NEW;
END $$;

CREATE TRIGGER assertion_embedding_case
  BEFORE INSERT OR UPDATE OF assertion_id, case_id ON core.assertion_embedding
  FOR EACH ROW EXECUTE FUNCTION core.assertion_embedding_case();

CREATE FUNCTION core.evidence_vectors_follow() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM core.evidence_embedding WHERE evidence_id = NEW.id;
  IF NEW.purged_at IS NULL THEN
    PERFORM core.embedding_enqueue('evidence', NEW.id);
  ELSE
    DELETE FROM core.embedding_pending
     WHERE kind = 'evidence' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER evidence_vectors_follow
  AFTER UPDATE OF {", ".join(FOLLOWED_COLUMNS)} ON core.evidence
  FOR EACH ROW WHEN ({_WHEN})
  EXECUTE FUNCTION core.evidence_vectors_follow();

CREATE FUNCTION core.evidence_embedding_queued() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM core.embedding_enqueue('evidence', NEW.id);
  RETURN NULL;
END $$;

CREATE TRIGGER evidence_embedding_queued
  AFTER INSERT ON core.evidence
  FOR EACH ROW WHEN (NEW.purged_at IS NULL)
  EXECUTE FUNCTION core.evidence_embedding_queued();

CREATE FUNCTION core.assertion_embedding_queued() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM core.embedding_enqueue('assertion', NEW.id);
  ELSE
    -- Retracted or superseded: history, never searched, so never queued.
    DELETE FROM core.embedding_pending
     WHERE kind = 'assertion' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER assertion_embedding_queued
  AFTER INSERT ON core.assertion
  FOR EACH ROW WHEN (NEW.retracted_at IS NULL AND NEW.superseded_at IS NULL)
  EXECUTE FUNCTION core.assertion_embedding_queued();

CREATE TRIGGER assertion_embedding_dequeued
  AFTER UPDATE OF retracted_at, superseded_at ON core.assertion
  FOR EACH ROW WHEN (NEW.retracted_at IS NOT NULL OR NEW.superseded_at IS NOT NULL)
  EXECUTE FUNCTION core.assertion_embedding_queued();
"""

DOWNGRADE_SQL = """
DROP TRIGGER assertion_embedding_dequeued ON core.assertion;
DROP TRIGGER assertion_embedding_queued ON core.assertion;
DROP TRIGGER evidence_embedding_queued ON core.evidence;
DROP TRIGGER evidence_vectors_follow ON core.evidence;
DROP TABLE core.assertion_embedding;
DROP TABLE core.evidence_embedding;
DROP FUNCTION core.assertion_embedding_queued();
DROP FUNCTION core.evidence_embedding_queued();
DROP FUNCTION core.evidence_vectors_follow();
DROP FUNCTION core.assertion_embedding_case();
DROP FUNCTION core.evidence_embedding_case();
DELETE FROM core.embedding_pending WHERE kind IN ('evidence', 'assertion');
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
