"""Binds `core.selector.compartments` to the compartment catalogue (the first
full run of the merged beta, 2026-10-03).

## What was wrong

0134 gave `core.selector` a `compartments text[]` column (the labels the row
is read under, copied from the entity it is attributed to) and did not bind
it the way every other column that stores compartment keys is bound
(docs/05, "Binding a compartment column"; decision 71). Three consequences:

- a direct write of a key nobody registered was accepted, and the row was
  then readable by no one: the silent no-access the registry exists to end;
- `iam.compartment_in_use` did not look at the table, so a key could be
  retired while selector rows still carried it;
- the lifecycle's rename did not know the column, so renaming a key left
  every selector row under the old name, which is by then registered to
  nobody.

test_compartment_binding_pg and test_compartment_contract_pg caught it on
the first full run, as the contract intends.

## What this adds

1. The binding, exactly as 0069 set it: the `compartments_registered`
   trigger, rendered by a local copy of 0059's `trigger_sql`, and
   `ADDED_BOUND_COLUMNS`. The registry functions are not touched
   (rule 4). `compartment_lifecycle.BOUND_COLUMNS` and `NOUNS` carry the
   column in the same change (rule 3), so a rename now moves selector rows
   and a retire is refused while any carries the key.
2. Before the trigger, a repair of the one way existing rows can have
   drifted. 0134's rule is that an attributed row's compartments equal its
   owner's, and its own trigger enforces that on every write; but a rename
   between 0134 and this revision could not reach the column, so an
   attributed row may still name the old key. Such a row is set to its
   owner's compartments, which is what the next write to it would have
   done and the only value the rule allows. Nothing else is rewritten: a
   row that names no owner is not guessed at.
3. Then a check. A row that still carries a key nobody registered (only an
   unattributed row written by hand can) stops the upgrade, naming how many
   and the two things an operator may do. It is not cleared here: clearing
   would make a row readable by everyone who may read the case, and that is
   a decision for a person (0059's precedent).

The owner-labels trigger of 0134 (`selector_labels_follow_owner`) sorts
after the binding and copies only from `core.node.compartments`, which is
bound, so rule 6 is met: the binding checks what the writer supplied, and
what the trigger then copies came from a column whose keys are registered.

## Downgrade

Drops the binding and nothing else: the column belongs to 0134, whose own
downgrade drops it, and removing a guard declassifies no row, so there is
nothing to refuse on. The repair in step 2 is not undone (it only restored
the value 0134's rule requires).
"""
from __future__ import annotations

from alembic import op

revision = "0170"
down_revision = "0169"
branch_labels = None
depends_on = None

#: The columns this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("core", "selector", "compartments", "array"),
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


#: An attributed row takes its owner's compartments again (0134's rule).
#: Run before the trigger exists, so it is a repair and not a write the
#: binding judges. A no-op wherever nothing drifted. A row whose repaired
#: labels another row of the case already holds for the same value is left
#: alone (the unique key would refuse it); it still names the old key, so
#: the check below stops the upgrade and a person decides.
REPAIR_SQL = """
UPDATE core.selector s
   SET compartments = n.compartments
  FROM core.node n
 WHERE n.id = s.node_id
   AND s.compartments IS DISTINCT FROM n.compartments
   AND NOT EXISTS (
       SELECT 1 FROM core.selector t
        WHERE t.case_id = s.case_id AND t.selector_type = s.selector_type
          AND t.norm_value = s.norm_value
          AND t.classification = s.classification
          AND t.compartments = n.compartments AND t.id <> s.id)
"""

#: The keys still carried that nobody registered, with how many rows carry
#: each. An empty result is the go-ahead.
UNREGISTERED_SQL = """
SELECT k.key, count(*)
  FROM core.selector s
  CROSS JOIN LATERAL unnest(s.compartments) AS k(key)
 WHERE NOT EXISTS (SELECT 1 FROM iam.compartment c WHERE c.key = k.key)
 GROUP BY k.key
 ORDER BY k.key NULLS LAST
"""

UPGRADE_SQL = f"""
{trigger_sql("core", "selector", "compartments", "array")}
"""

DOWNGRADE_SQL = f"""
DROP TRIGGER {TRIGGER_NAME} ON core.selector;
"""


def refusal_message(found: list[tuple]) -> str:
    """Why the upgrade stops, for `UNREGISTERED_SQL` rows (key, rows)."""
    total = sum(n for _key, n in found)
    keys = ", ".join(f"'{key}'" for key, _n in found[:5])
    if len(found) > 5:
        keys += f" and {len(found) - 5} more"
    what = ("1 selector row carries" if total == 1
            else f"{total} selector rows carry")
    return (
        f"refusing to upgrade to 0170: {what} a compartment nobody has "
        f"registered ({keys}). Nobody can be read into an unregistered key, so "
        f"every reader of the case is already shut out of "
        f"{'it' if total == 1 else 'them'}. Register the key under "
        f"Administration, Compartments to keep the lock, or, if the lock was "
        f"a mistake and the row names no entity, clear it deliberately with "
        f"UPDATE core.selector SET compartments = '{{}}' WHERE node_id IS "
        f"NULL AND compartments && ARRAY['<the key>']::text[] (that makes "
        f"the row readable to everyone who may read its case). Then run the "
        f"upgrade again.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(REPAIR_SQL)
    found = query(UNREGISTERED_SQL)
    if found:
        raise RuntimeError(refusal_message(found))
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
