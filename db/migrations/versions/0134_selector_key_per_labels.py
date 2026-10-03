"""One observation of a selector per value, per labels (beta review,
2026-10-03, second round: graph-selector-record-oracle, http_ui-002, rls-2).

## Why

`core.selector` was unique on (case, type, value) and nothing else. Row
security on it is the case term alone (decision 147), so an upsert meets the
case's one row for a value whoever owns it. The first fix stopped the
route from handing back or writing to a row owned by an entity above the
caller, by answering such a value as a first sighting and storing nothing.
That left the oracle one request away: a second POST returned a new id and a
count of one where an unheld value returned the same id and a count of two,
GET /selectors answered null after the POST where an unheld value answered
the row, a second POST /nodes named no earlier holder, and the id the answer
carried was no row at all (a foreign key failure as a merge's basis). A
unique key that spans labels is an oracle row security does not hide, which
is what 0133 settled for ties.

## What changes

The row carries its own `classification` and `compartments`, and the key
gains them. An observation is stored at the labels of the entity it is
attributed to; one nobody has attributed is stored at the floor (CLEAR, no
compartments), which every reader of the case can see and which no sighting
of the value narrows when an entity is later attributed to it (that entity
gets a row of its own, at its own labels). A value held above a caller is therefore simply not
among the rows the caller can see, and what they record is their own row:
repeat posts count, the row reads back, the id is real. What a caller can
learn about a value no longer depends on a row they cannot read.

A trigger keeps an owned row's labels equal to its owner's whoever writes it
(the application, a seed script, a later unit's upsert, a direct update of
the labels), so no writer can leave an owned row at a label below its
owner. The labels of an unowned row are whatever the writer gave it, the
floor by default. Backfill: an owned row takes its owner's labels, an
unowned one the floor.

The policy stays the case term alone: readers apply the labels themselves
(`SelectorStore.find_for_reader`, the owner test of every other reader), and
the upsert's two arms are both rows the caller may read.

## Downgrade

Restores the 0005 key and drops the columns. On a database that holds two
rows for one value at different labels the downgrade fails on the unique
build, which is the honest answer (reversible on an empty database is the
contract, CONVENTIONS.md).
"""
from alembic import op

revision = "0134"
down_revision = "0133"
branch_labels = None
depends_on = None

#: Frozen text.
UPGRADE_SQL = """
ALTER TABLE core.selector
    ADD COLUMN classification core.tlp NOT NULL DEFAULT 'CLEAR',
    ADD COLUMN compartments   text[]   NOT NULL DEFAULT '{}';

UPDATE core.selector s
   SET classification = n.classification, compartments = n.compartments
  FROM core.node n
 WHERE n.id = s.node_id;

ALTER TABLE core.selector
    DROP CONSTRAINT selector_case_id_selector_type_norm_value_key;
ALTER TABLE core.selector
    ADD CONSTRAINT selector_case_id_selector_type_norm_value_labels_key
    UNIQUE (case_id, selector_type, norm_value, classification, compartments);

CREATE FUNCTION core.selector_labels_follow_owner() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  owner_class core.tlp;
  owner_comps text[];
BEGIN
  IF NEW.node_id IS NOT NULL THEN
    SELECT n.classification, n.compartments INTO owner_class, owner_comps
      FROM core.node n WHERE n.id = NEW.node_id;
    IF FOUND THEN
      NEW.classification := owner_class;
      NEW.compartments := owner_comps;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER selector_labels_follow_owner
  BEFORE INSERT OR UPDATE OF node_id, classification, compartments
  ON core.selector
  FOR EACH ROW EXECUTE FUNCTION core.selector_labels_follow_owner();
"""

DOWNGRADE_SQL = """
DROP TRIGGER selector_labels_follow_owner ON core.selector;
DROP FUNCTION core.selector_labels_follow_owner();

ALTER TABLE core.selector
    DROP CONSTRAINT selector_case_id_selector_type_norm_value_labels_key;
ALTER TABLE core.selector
    ADD CONSTRAINT selector_case_id_selector_type_norm_value_key
    UNIQUE (case_id, selector_type, norm_value);

ALTER TABLE core.selector
    DROP COLUMN compartments,
    DROP COLUMN classification;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
