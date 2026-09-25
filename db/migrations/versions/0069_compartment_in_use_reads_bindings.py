"""The compartment registry reads its bound columns from the catalog, so a
column bound by any later migration is guarded without restating it.

## What was wrong (docs/00 decision 71, 2026-09-24)

0059 bound eighteen compartment columns to `iam.compartment` in both
directions: a row cannot carry an unregistered key, and the registry
refuses to drop or rename a key while any bound column still carries it.
The second half is `iam.compartment_in_use(key)`, and 0059 rendered its
body as a fixed eighteen-leg UNION from a tuple in the migration. Its
comment said "a future migration that adds one must add it here", which no
later migration can do: 0059 is released. Three later features would each
have restated the function with their own column added, and whichever
restatement ran last would have dropped every other feature's column from
the guard. A key those columns carried could then be retired while rows
were still filed under it: the silent no-access 0059 exists to end.

## The triggers are the registry

A column is bound when its table carries a trigger named
`compartments_registered` (or `compartments_registered_<column>` for a
second bound column on one table) that calls
`iam.refuse_unregistered_compartment('<column>', 'array'|'scalar')`, as
0059's `trigger_sql` renders it. `iam.compartment_bindings()` lists every
such trigger from the catalog and says, per trigger, what is wrong with it
when anything is. It reads the binding structurally, never by parsing
`pg_get_triggerdef`: the function it calls (`tgfoid`), its argument count
and arguments (`tgargs`), the column those name and that column's type,
the timing and events (`tgtype`) and the one column it fires on
(`tgattr`). A trigger that calls the function under another name is
listed too, with its name as the problem, so a binding cannot hide from
the registry by being misnamed (2026-09-24).

`iam.compartment_in_use(key)` then asks each bound column whether it
carries the key, and REFUSES while any binding cannot be read: if the
guard cannot tell whether rows there carry the key, dropping or renaming
it is exactly the unsafe case. That stops every rename, retire and direct
DELETE of a key until the binding is repaired, which is the intent; the
readiness row `compartment_bindings_intact` names the table and the
problem.

Two details are load-bearing:

- `tgattr` is an int2vector, whose lower bound is 0. Cast to int2[] it
  keeps that bound, and array equality compares bounds, so comparing it
  with `ARRAY[attnum]` (lower bound 1) failed for every binding,
  including the eighteen correct ones. The column list is rebuilt with
  `ARRAY(SELECT unnest(...))`, which starts at 1.
- `tgargs` is bytea with NUL between arguments. `encode(..., 'escape')`
  renders each NUL as the four characters `\\000`, and the split
  delimiter is written `E'\\\\000'` inside a raw string, so no NUL byte is
  ever sent (Postgres refuses one in text) and the split does not depend
  on `standard_conforming_strings`.

The array leg is `cardinality(col) > 0 AND col @> ARRAY[key]`, the same
rows as 0059's `key = ANY(col)` for a non-NULL key, so a partial GIN index
whose predicate is `cardinality(col) > 0` can answer it (0070 gives
`collect.document` one). `IN_USE_ARRAY_LEG` is the exact text, so the
index test EXPLAINs what the function runs rather than a hand copy.

The parameter keeps the name `key` and the result keeps its type, labels
and order, so `iam.refuse_compartment_removal()` is untouched. Both
functions pin `search_path`; both are SECURITY INVOKER, and row-level
security decides whether they become DEFINER (docs/00 decision 76).

## The contract every later compartments column follows

docs/05, "Binding a compartment column". In short: the migration that
adds the column installs the trigger above in the same migration and
declares `ADDED_BOUND_COLUMNS`; the same change appends the tuple to
`compartment_lifecycle.BOUND_COLUMNS` and a noun to `NOUNS`; no later
migration creates, replaces or drops these three registry functions.
test_compartment_contract_pg.py enforces it.

## Downgrade

Refuses while any binding outside 0059's eighteen exists, well formed or
not: restoring 0059's fixed list would stop the registry seeing it, so a
key it carries could be dropped while rows are filed under it. Otherwise
it restores 0059's LANGUAGE sql body and comment from the frozen copy
below (held equal to 0059 by test; migrations do not import each other,
0063) and drops `iam.compartment_bindings()`. No data changes either way.
"""
from __future__ import annotations

from alembic import op

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None

#: The trigger name every binding carries (or begins with).
TRIGGER_NAME = "compartments_registered"

#: A frozen copy of 0059's BOUND_COLUMNS: the columns the restored body of
#: the downgrade names. test_compartment_contract_pg.py holds it equal to
#: 0059's tuple, so the copy cannot drift from the migration it restores.
BOUND_0059: tuple[tuple[str, str, str, str], ...] = (
    ("iam", "app_user", "compartments", "array"),
    ("core", "case", "compartments", "array"),
    ("core", "node", "compartments", "array"),
    ("core", "edge", "compartments", "array"),
    ("core", "evidence", "compartments", "array"),
    ("analytics", "metric_run", "visibility_compartments", "array"),
    ("notify", "notification", "compartments", "array"),
    ("lab", "sample", "compartments", "array"),
    ("ingest", "record", "compartments", "array"),
    ("ingest", "dead_letter", "compartments", "array"),
    ("comms", "channel_binding", "compartments", "array"),
    ("comms", "conversation", "compartments", "array"),
    ("comms", "message", "compartments", "array"),
    ("comms", "contact_block", "compartments", "array"),
    ("deception", "capture", "compartments", "array"),
    ("deception", "email_message", "compartments", "array"),
    ("deception", "call_record", "compartments", "array"),
    ("ingest", "api_key", "forced_compartment", "scalar"),
)

#: What the array leg asks of one bound column, as `format()` renders it
#: inside `iam.compartment_in_use`. Module level so the index test can
#: EXPLAIN exactly this text with the key bound.
IN_USE_ARRAY_LEG = (
    "SELECT EXISTS (SELECT 1 FROM %I.%I "
    "WHERE cardinality(%I) > 0 AND %I @> ARRAY[$1]::text[])")
IN_USE_SCALAR_LEG = "SELECT EXISTS (SELECT 1 FROM %I.%I WHERE %I = $1)"


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _qualified(schema: str, table: str) -> str:
    return f'{schema}."{table}"'


def in_use_0059_body() -> str:
    """0059's `_in_use_sql()` over BOUND_0059, copied rather than imported
    (migrations do not import each other). Held equal to 0059's own by
    test_compartment_contract_pg.py."""
    parts = []
    for schema, table, column, kind in BOUND_0059:
        label = _lit(f"{schema}.{table}.{column}")
        where = (f"$1 = ANY({column})" if kind == "array"
                 else f"{column} = $1")
        parts.append(
            f"SELECT {label} AS col WHERE EXISTS "
            f"(SELECT 1 FROM {_qualified(schema, table)} WHERE {where})")
    return "\n        UNION ALL\n        ".join(parts)


# Every SQL constant is a raw string: the tgargs delimiter below must reach
# Postgres as the four characters backslash, 0, 0, 0 inside an E'' literal.
BINDINGS_SQL = r"""
CREATE FUNCTION iam.compartment_bindings()
RETURNS TABLE (schema_name text, table_name text, column_name text,
               kind text, enabled boolean, problem text)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $f$
#variable_conflict use_column
DECLARE
  t    record;
  args text[];
  att  record;
BEGIN
  FOR t IN
    SELECT tg.tgname::text AS tgname, n.nspname::text AS sch,
           c.relname::text AS tbl, tg.tgrelid, tg.tgfoid, tg.tgnargs,
           tg.tgargs, ARRAY(SELECT unnest(tg.tgattr)) AS cols,
           tg.tgtype::int AS tgtype, tg.tgenabled IN ('O', 'A') AS fires
      FROM pg_trigger tg
      JOIN pg_class c ON c.oid = tg.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE NOT tg.tgisinternal
       AND (tg.tgfoid = 'iam.refuse_unregistered_compartment()'::regprocedure
            OR tg.tgname = 'compartments_registered'
            OR starts_with(tg.tgname::text, 'compartments_registered_'))
     ORDER BY 2, 3, 1
  LOOP
    schema_name := t.sch;
    table_name := t.tbl;
    enabled := t.fires;
    column_name := NULL;
    kind := NULL;
    problem := NULL;
    args := string_to_array(encode(t.tgargs, 'escape'), E'\\000');
    IF t.tgfoid <> 'iam.refuse_unregistered_compartment()'::regprocedure THEN
      problem := 'it does not call iam.refuse_unregistered_compartment';
    ELSIF t.tgnargs <> 2 THEN
      problem := 'it passes ' || t.tgnargs
                 || CASE WHEN t.tgnargs = 1 THEN ' argument' ELSE ' arguments' END
                 || ', and a binding passes two: the column and its kind';
    ELSE
      column_name := args[1];
      kind := args[2];
      SELECT a.attnum, a.atttypid INTO att
        FROM pg_attribute a
       WHERE a.attrelid = t.tgrelid AND a.attname = args[1]
         AND NOT a.attisdropped;
      IF NOT FOUND THEN
        problem := 'it names a column the table does not have';
      ELSIF kind NOT IN ('array', 'scalar') THEN
        problem := 'its kind is neither array nor scalar';
      ELSIF (kind = 'array' AND att.atttypid <> 'text[]'::regtype)
         OR (kind = 'scalar' AND att.atttypid <> 'text'::regtype) THEN
        problem := 'the column is not of the type its kind says';
      ELSIF (t.tgtype & 127) <> 23 THEN
        problem := 'it is not BEFORE INSERT OR UPDATE FOR EACH ROW';
      ELSIF t.cols IS DISTINCT FROM ARRAY[att.attnum]::int2[] THEN
        problem := 'it does not fire on UPDATE OF exactly that column';
      ELSIF t.tgname NOT IN ('compartments_registered',
                             'compartments_registered_' || args[1]) THEN
        problem := 'its name does not follow the binding rule';
      END IF;
    END IF;
    RETURN NEXT;
  END LOOP;
END
$f$;

COMMENT ON FUNCTION iam.compartment_bindings() IS
  'Every compartment binding: the triggers named compartments_registered '
  '(or compartments_registered_<column>), and any trigger that calls '
  'iam.refuse_unregistered_compartment, read from the catalog. problem is '
  'NULL for a well-formed binding and says what is wrong otherwise. The '
  'registry of bound columns IS this list.';
"""

IN_USE_SQL = r"""
CREATE OR REPLACE FUNCTION iam.compartment_in_use(key text) RETURNS text[]
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
  b       record;
  hit     boolean;
  holders text[] := '{}';
BEGIN
  FOR b IN SELECT * FROM iam.compartment_bindings() LOOP
    IF b.problem IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'compartment ' || key || ' was not dropped or renamed: the binding '
        || 'on ' || b.schema_name || '.' || b.table_name || ' cannot be read ('
        || b.problem || '), so whether rows there still carry it is unknown. '
        || 'Recreate that trigger as the migration that added it did, then '
        || 'try again';
    END IF;
    IF b.kind = 'scalar' THEN
      EXECUTE format('""" + IN_USE_SCALAR_LEG + r"""',
                     b.schema_name, b.table_name, b.column_name)
        INTO hit USING key;
    ELSE
      EXECUTE format('""" + IN_USE_ARRAY_LEG + r"""',
                     b.schema_name, b.table_name, b.column_name,
                     b.column_name)
        INTO hit USING key;
    END IF;
    IF hit THEN
      holders := holders || (b.schema_name || '.' || b.table_name || '.'
                             || b.column_name);
    END IF;
  END LOOP;
  IF cardinality(holders) = 0 THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT array_agg(h ORDER BY h) FROM unnest(holders) AS h);
END
$f$;

COMMENT ON FUNCTION iam.compartment_in_use(text) IS
  'The bound columns (schema.table.column) that still carry the key, or '
  'NULL. Reads the bindings from the catalog through '
  'iam.compartment_bindings(), so a column bound by any later migration is '
  'covered without restating this function, and refuses while any binding '
  'cannot be read.';
"""

#: 0059's function, restored by the downgrade: the same CREATE text 0059
#: ran (CREATE OR REPLACE here, which also clears the SET search_path the
#: upgrade added), and 0059's comment.
IN_USE_0059_SQL = f"""
CREATE OR REPLACE FUNCTION iam.compartment_in_use(key text) RETURNS text[]
LANGUAGE sql STABLE AS $f$
  SELECT array_agg(col ORDER BY col) FROM (
        {in_use_0059_body()}
  ) s
$f$;

COMMENT ON FUNCTION iam.compartment_in_use(text) IS
  'The bound columns (schema.table.column) that still carry the key, or '
  'NULL. Used by the registry trigger that refuses to drop or rename a '
  'key in use.';
"""

LISTED_SQL = """
SELECT schema_name, table_name, column_name, problem
  FROM iam.compartment_bindings()
"""

def downgrade_refusal(labels: list[str]) -> str:
    """The refusal, its nouns, verbs and pronouns agreeing with the number
    of bindings it names. An operator reads it, and the count rule holds
    for operator text too (2026-09-24); a migration does not import the
    app, so this does locally what noctornal_api.wording does."""
    named = ", ".join(labels)
    if len(labels) == 1:
        return (
            f"A column bound after 0059 still carries the binding: {named}. "
            "Restoring 0059's fixed list would stop the registry seeing it, "
            "so a key it carries could be dropped while rows are filed under "
            "that key. Downgrade the migration that bound it first.")
    return (
        f"Columns bound after 0059 still carry the binding: {named}. "
        "Restoring 0059's fixed list would stop the registry seeing them, so "
        "a key they carry could be dropped while rows are filed under that "
        "key. Downgrade the migrations that bound them first.")


def extra_bindings(rows) -> list[str]:
    """Labels of the bindings outside 0059's eighteen, well formed or not.

    `rows` are (schema, table, column, problem) from
    `iam.compartment_bindings()`. A binding that cannot be read is named by
    its table and its problem, because its column may be unknown; it is
    still a binding the restored fixed list would not see."""
    known = {(s, t, c) for s, t, c, _k in BOUND_0059}
    out = []
    for schema, table, column, problem in rows:
        if problem is None and (schema, table, column) in known:
            continue
        if problem is None:
            out.append(f"{schema}.{table}.{column}")
        else:
            out.append(f"{schema}.{table} (a binding that cannot be read: "
                       f"{problem})")
    return sorted(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(BINDINGS_SQL)
    run(IN_USE_SQL)


def downgrade() -> None:
    extra = extra_bindings(query(LISTED_SQL))
    if extra:
        raise RuntimeError(downgrade_refusal(extra))
    run(IN_USE_0059_SQL)
    run("DROP FUNCTION iam.compartment_bindings();")
