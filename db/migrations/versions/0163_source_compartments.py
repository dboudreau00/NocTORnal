"""Compartments on `collect.source`, so a collection source can be read
under a compartment and every document it collects carries it (docs/17
F43, docs/00 decision 78's open half, 2026-10-02).

## What was wrong

A source carried a classification and nothing else, so a document an
adapter collected (a feed item, a forum post, a Telegram message) could
carry no compartment: `collect.document.compartments` (0070) was filled
only by a capture into a compartmented case. A unit that needed a forum
read under a compartment had to capture it by hand (docs/17 F43).

## What this adds

1. `compartments text[] NOT NULL DEFAULT '{}'` on `collect.source`: the
   need-to-know lock the source and everything it collects are read
   under. Set at creation by a person who holds every key named
   (collection.create_source), never widened afterwards except through
   the registry's rename and retire, like every other bound column. Every
   document the source collects copies it (`_store_document`), and every
   reader of a source checks `s.compartments <@` its own
   (`collection._SOURCE_VISIBLE_HELD`); a reader that does not pass its
   compartments sees no compartmented source at all (`_SOURCE_VISIBLE`
   fails closed), as a missing set fails closed for documents.
2. The binding, by the contract 0069 set (docs/05, "Binding a compartment
   column"): the `compartments_registered` trigger, rendered by the local
   copy of 0059's `trigger_sql`, and `ADDED_BOUND_COLUMNS`. The registry
   functions are not touched.
3. `source_compartments_idx`, a GIN index over compartmented rows only,
   for the registry's leg (0070's reason).

The egress proxy reads this table as `noctornal_egress` (rls_registry.py,
EXEMPT) and already asks whether a source carries compartments
(egress_authz._source_compartmented), so a compartmented source's
connections are recorded as such in the ledger from this revision on.

## Downgrade

Refuses while any source carries a compartment, naming the count:
dropping the column would leave the source, and every document it
collected, readable by clearance alone (0070's precedent). Otherwise drops
the index, the binding and the column.
"""
from __future__ import annotations

from alembic import op

revision = "0163"
down_revision = "0162"
branch_labels = None
depends_on = None

#: The columns this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("collect", "source", "compartments", "array"),
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


UPGRADE_SQL = f"""
ALTER TABLE collect.source
  ADD COLUMN compartments text[] NOT NULL DEFAULT '{{}}';

COMMENT ON COLUMN collect.source.compartments IS
  'The need-to-know lock a source and everything it collects are read '
  'under (F43, 2026-10-02). Set at creation by a person who holds every '
  'key; every collected document copies it. Bound to iam.compartment by '
  'the compartments_registered trigger.';

{trigger_sql("collect", "source", "compartments", "array")}

CREATE INDEX source_compartments_idx ON collect.source
  USING gin (compartments) WHERE cardinality(compartments) > 0;
"""

DOWNGRADE_SQL = f"""
DROP INDEX collect.source_compartments_idx;
DROP TRIGGER {TRIGGER_NAME} ON collect.source;
ALTER TABLE collect.source DROP COLUMN compartments;
"""

COUNT_SQL = ("SELECT count(*) FROM collect.source "
             "WHERE cardinality(compartments) > 0")


def downgrade_refusal(n: int) -> str:
    if n == 1:
        return ("refusing to downgrade 0163: 1 source carries compartments; "
                "dropping the column would make it, and every document it "
                "collected, readable by clearance alone. Remove the compartment "
                "first, or stay at this revision.")
    return (f"refusing to downgrade 0163: {n} sources carry compartments; "
            f"dropping the column would make each, and every document they "
            f"collected, readable by clearance alone. Remove the compartments "
            f"first, or stay at this revision.")


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
    run(DOWNGRADE_SQL)
