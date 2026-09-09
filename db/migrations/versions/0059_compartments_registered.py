"""Bind every compartment column to the registry: a psql typo, a direct
UPDATE, or an api_key forced_compartment was still silent no-access.

## What 0057 gated, and what it did not

0057 created `iam.compartment` as the closed vocabulary and made two
SERVICE write sites refuse an unregistered key: `cases.py` when a case is
filed, `iam_admin.set_compartments` when a user is read in. That was the
whole of it, and until 2026-09-09 it was described as if it were the
binding. It was not. A compartment array is a raw `text[]` column -- 32
`text[]` declarations across the migrations, of which seventeen are
compartment arrays, plus `ingest.api_key.forced_compartment`, a scalar
that every stealer-log record and dead letter copies into its own array
-- and the database accepted any string into any of them from any
writer. Concretely, on the day this migration was written:

- `UPDATE iam.app_user SET compartments = '{OP-KESTRAL}'` in psql, the
  exact typo 0057's docstring opens with, succeeded;
- `IngestService.issue_key(declared_category='STEALER_LOG',
  forced_compartment='TYPO')` succeeded, and every record that key then
  ingested was filed under a lock nobody held;
- fifteen other tables (`core.node`, `core.evidence`, `lab.sample`,
  `comms.*`, `deception.*`, ...) carry a compartment array that no service
  checked against the registry at all, because their writers copy the
  case's array, which was itself only checked at case creation.

Each of those produces the defect this codebase keeps finding in itself:
a correct decision about the wrong string, with nothing to say why. The
five-part gate compares `c.compartments <@ u.compartments` byte for byte;
it cannot tell a key that was never registered from one the analyst was
never read into.

## The binding is a trigger, and why it is not a CONSTRAINT trigger

`iam.compartments_registered(text[])` is the predicate: true iff every
element is a non-NULL key present in `iam.compartment`. A `BEFORE INSERT
OR UPDATE OF <column> FOR EACH ROW` trigger on each of the eighteen
columns refuses a row that fails it, and the refusal NAMES the keys, the
column, and the registration route (`POST /api/v1/compartments`,
`user.manage`), so an operator at a psql prompt is told what to type
rather than handed a constraint name.

It is a plain trigger rather than a `CONSTRAINT TRIGGER` for a reason
that was checked on the server, not assumed: Postgres 16 rejects `CREATE
CONSTRAINT TRIGGER ... BEFORE` outright (syntax error 42601; constraint
triggers are AFTER ROW by definition), and an AFTER constraint trigger
would let the row be written and refuse at statement end -- or, if
deferred, at COMMIT, where the error is furthest from the typo that
caused it. A BEFORE trigger refuses before anything is written, which is
also what the application's own checks do.

It is not a foreign key, because there is no such thing as a foreign key
from an array element, and a `CHECK` cannot reference another table.

One function serves all eighteen columns: the column name is a trigger
argument, read from `NEW` by `EXECUTE ... USING NEW`, so the seventeen
arrays and the one scalar cannot drift apart in how they are checked. The
`WHEN` clause skips empty and NULL arrays (and a NULL scalar) without
calling the function, because the common row carries no compartment and
the ingest path is hot. A NULL ELEMENT inside an array, by contrast, is
refused: it is not a key, it is never registered, and it can never be
held.

The refusal is raised with the default SQLSTATE `P0001` on purpose.
`http/errors.safe_detail` passes the authored first line of a `P0001`
through to the client; a `23514` (check_violation) is replaced by the
generic "the request violates a data rule". So a refusal that reaches a
service which wraps psycopg errors (`cases.py` does; `ingest.py` and
`iam_admin.py` do so as of this migration) arrives at the operator as a
400 or 409 that names the key, not a 500.

## The registry side is bound too

Binding the arrays to the registry and leaving the registry free to drop
a key would be two halves that are wrong together: `DELETE FROM
iam.compartment WHERE key = 'OP-KESTREL'` would orphan every row filed
under it, and the next legitimate write to any of those rows would be
refused by this migration's own trigger for a key that was, until a
moment ago, real. So `iam.compartment` refuses a DELETE, or an UPDATE of
`key`, while any bound column still carries the key -- naming the
columns that do. There is no product route that deletes a compartment,
and this is why: the operation is a declassification-or-rename that has
to touch every column first.

## Upgrade refuses an unregistered value already in use, as 0057 did

A pre-existing value in any of the eighteen columns that is not in the
registry -- possible, because sixteen of them were never gated -- would
be refused by the trigger on the row's next write and by nothing else:
exactly the silent state this migration exists to end, now with a
migration's signature on it. Registering such values silently was
rejected for the reason 0057 gives: it mints a typo as a real compartment
that somebody can then be read into. So the upgrade REFUSES, before
creating anything, and the refusal is a documented pre-upgrade cleanup
step in 0057's shape: `refusal_message` names every value, every column
that holds it, and prints, per value, the three statements the operator
can choose between -- register it (only if it satisfies the key format,
and only if it IS a real compartment), rename it in every column that
holds it, or remove it (with the warning that removing a lock
declassifies every row that carried it). `UNREGISTERED_SQL`, the
statement builders and `refusal_message` are module-level so the test
can run exactly what the operator is told to run.

## The application-level checks stay

`cases._require_registered` and `iam_admin._unknown_compartments` are
NOT removed. Through `safe_detail` the database refusal does reach the
client with the same status the service check produces -- that is
tested -- but the service check names EVERY unknown key in one authored
sentence, runs before the more expensive stranding query in
`set_compartments`, and does not carry a correlation-id suffix. The
trigger is the guarantee; the service check is the readable error. Both
sides of that pairing are pinned by `test_compartment_binding_pg.py`.

Downgrade drops the nineteen triggers and the five functions. The
columns and their contents are untouched in both directions.
"""
import re

from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None

#: 0057's key format, repeated here only so the cleanup message can say
#: which of the offending values the registry could accept at all.
KEY_FORMAT = r"^[A-Z0-9_-]{2,32}$"

#: The registration route named in every refusal. The binding test reads
#: the FastAPI route table and fails if this path stops existing, so the
#: message cannot outlive the route.
REGISTRATION_ROUTE = "POST /api/v1/compartments"

#: Every column that carries a compartment key: (schema, table, column,
#: kind). Enumerated from the migrations -- 0004, 0005, 0006, 0008, 0012,
#: 0026, 0029, 0031, 0033 (two), 0034 (three), 0035, 0040, 0048, 0049,
#: 0050 -- and checked against the live catalog by the binding test, which
#: fails if a column named `compartments`, `visibility_compartments` or
#: `forced_compartment` exists that this tuple does not name. A future
#: migration that adds one must add it here.
BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
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

#: The trigger installed on every bound table, and the one on the registry.
TRIGGER_NAME = "compartments_registered"
REGISTRY_TRIGGER_NAME = "compartment_in_use"

#: The placeholder the operator has to replace, as in 0057: deliberately
#: not a valid key, so a copy-paste that skipped the thinking fails on the
#: registry's CHECK rather than filing every affected row under it.
REPLACEMENT = "<the-real-key>"


def qualified(schema: str, table: str) -> str:
    """`schema."table"`. The table is always quoted because `core."case"`
    has to be, and one rendering for all eighteen is one fewer thing for
    the operator to second-guess in a printed statement."""
    return f'{schema}."{table}"'


def column_label(schema: str, table: str, column: str) -> str:
    return f"{schema}.{table}.{column}"


def _lit(value: str) -> str:
    """`value` as a Postgres string literal -- 0057's `_lit`, for 0057's
    reason: `repr()` would quote a value containing an apostrophe with
    DOUBLE quotes, which Postgres reads as an identifier, and an
    apostrophe is one of the ways a value fails the key format, so the
    broken case is precisely the case this code prints for."""
    return "'" + value.replace("'", "''") + "'"


def _union_of_values() -> str:
    """Every value in every bound column, labelled with the column."""
    parts = []
    for schema, table, column, kind in BOUND_COLUMNS:
        label = _lit(column_label(schema, table, column))
        if kind == "array":
            parts.append(
                f"SELECT unnest({column}) AS c, {label} AS col "
                f"FROM {qualified(schema, table)}")
        else:
            parts.append(
                f"SELECT {column} AS c, {label} AS col "
                f"FROM {qualified(schema, table)} WHERE {column} IS NOT NULL")
    return "\n      UNION ALL\n      ".join(parts)


#: (value, column) for every value in use that the registry does not hold.
#: A NULL element comes back as a NULL value -- it is in use and can never
#: be registered, so it is listed, and the cleanup for it is printed.
UNREGISTERED_SQL = f"""
SELECT s.c, s.col
  FROM (
      {_union_of_values()}
  ) s
 WHERE s.c IS NULL
    OR NOT EXISTS (SELECT 1 FROM iam.compartment k WHERE k.key = s.c)
 GROUP BY s.c, s.col
 ORDER BY s.c NULLS LAST, s.col
"""


def _in_use_sql() -> str:
    """The body of `iam.compartment_in_use(text)`: the labelled columns
    that still carry `$1`, generated from the same tuple as the triggers
    so the two directions of the binding cannot disagree about which
    columns exist."""
    parts = []
    for schema, table, column, kind in BOUND_COLUMNS:
        label = _lit(column_label(schema, table, column))
        where = (f"$1 = ANY({column})" if kind == "array"
                 else f"{column} = $1")
        parts.append(
            f"SELECT {label} AS col WHERE EXISTS "
            f"(SELECT 1 FROM {qualified(schema, table)} WHERE {where})")
    return "\n        UNION ALL\n        ".join(parts)


FUNCTIONS_SQL = f"""
CREATE FUNCTION iam.compartments_registered(keys text[]) RETURNS boolean
LANGUAGE sql STABLE AS $f$
  SELECT keys IS NULL OR NOT EXISTS (
    SELECT 1 FROM unnest(keys) AS k
     WHERE k IS NULL
        OR NOT EXISTS (SELECT 1 FROM iam.compartment c WHERE c.key = k))
$f$;

COMMENT ON FUNCTION iam.compartments_registered(text[]) IS
  'True iff every element is a non-NULL key in iam.compartment. A NULL '
  'array is vacuously registered; a NULL ELEMENT is not, because it is '
  'not a key and can never be held.';

CREATE FUNCTION iam.unregistered_compartments(keys text[]) RETURNS text[]
LANGUAGE sql STABLE AS $f$
  SELECT array_agg(DISTINCT coalesce(k, 'NULL') ORDER BY coalesce(k, 'NULL'))
    FROM unnest(keys) AS k
   WHERE k IS NULL
      OR NOT EXISTS (SELECT 1 FROM iam.compartment c WHERE c.key = k)
$f$;

CREATE FUNCTION iam.refuse_unregistered_compartment() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  keys text[];
  bad  text[];
BEGIN
  -- TG_ARGV[0] is the column, TG_ARGV[1] is 'array' or 'scalar'. Read
  -- from NEW by name so one function serves every bound column.
  IF TG_ARGV[1] = 'scalar' THEN
    EXECUTE format('SELECT ARRAY[($1).%I]', TG_ARGV[0]) INTO keys USING NEW;
  ELSE
    EXECUTE format('SELECT ($1).%I', TG_ARGV[0]) INTO keys USING NEW;
  END IF;
  bad := iam.unregistered_compartments(keys);
  IF bad IS NOT NULL THEN
    -- One line, no DETAIL: http/errors.safe_detail forwards only the
    -- first line of a P0001 to the client, so everything the operator
    -- needs has to be on it. The default SQLSTATE IS the contract here;
    -- a check_violation would be replaced by a generic sentence.
    RAISE EXCEPTION USING MESSAGE =
      'compartment key(s) ' || array_to_string(bad, ', ')
      || ' in ' || TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME || '.' || TG_ARGV[0]
      || ' are not registered: register each key first ({REGISTRATION_ROUTE},'
      || ' user.manage), because an unregistered key is a typo and a typo'
      || ' in a need-to-know lock is silent no-access';
  END IF;
  RETURN NEW;
END
$f$;

CREATE FUNCTION iam.compartment_in_use(key text) RETURNS text[]
LANGUAGE sql STABLE AS $f$
  SELECT array_agg(col ORDER BY col) FROM (
        {_in_use_sql()}
  ) s
$f$;

COMMENT ON FUNCTION iam.compartment_in_use(text) IS
  'The bound columns (schema.table.column) that still carry the key, or '
  'NULL. Used by the registry trigger that refuses to drop or rename a '
  'key in use.';

CREATE FUNCTION iam.refuse_compartment_removal() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  holders text[];
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.key = OLD.key THEN
    RETURN NEW;
  END IF;
  holders := iam.compartment_in_use(OLD.key);
  IF holders IS NOT NULL THEN
    RAISE EXCEPTION USING MESSAGE =
      'compartment ' || OLD.key || ' is still carried by '
      || array_to_string(holders, ', ')
      || ': a registered key cannot be dropped or renamed while rows are'
      || ' filed under it, because they would become unregistered and'
      || ' unwritable. Rename or remove it in those columns first';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$f$;

CREATE TRIGGER {REGISTRY_TRIGGER_NAME}
  BEFORE DELETE OR UPDATE OF key ON iam.compartment
  FOR EACH ROW EXECUTE FUNCTION iam.refuse_compartment_removal();
"""


def trigger_sql(schema: str, table: str, column: str, kind: str) -> str:
    """The binding on one column. `UPDATE OF <column>` so an update that
    does not touch the column costs nothing; `WHEN` so a row with no
    compartment never calls the function."""
    when = (f"cardinality(NEW.{column}) > 0" if kind == "array"
            else f"NEW.{column} IS NOT NULL")
    return (
        f"CREATE TRIGGER {TRIGGER_NAME}\n"
        f"  BEFORE INSERT OR UPDATE OF {column} ON {qualified(schema, table)}\n"
        f"  FOR EACH ROW WHEN ({when})\n"
        f"  EXECUTE FUNCTION iam.refuse_unregistered_compartment("
        f"'{column}', '{kind}');")


# --- the pre-upgrade cleanup message ---------------------------------------

def register_sql(value: str) -> str:
    """Register ONE value under its own key as label (there is no better
    label on record), as 0057's backfill did. Only offered when the value
    satisfies the key format; `ON CONFLICT DO NOTHING` so a re-run is
    harmless."""
    return (f"INSERT INTO iam.compartment (key, label) VALUES "
            f"({_lit(value)}, {_lit(value)}) ON CONFLICT (key) DO NOTHING;")


def rename_sql(value: str, replacement: str, columns: list[str]) -> str:
    """Rename ONE value in every column that holds it. Executable as-is,
    and kept free of anything but the statements so the test can run
    exactly what the operator is told to run."""
    out = []
    for schema, table, column, kind in BOUND_COLUMNS:
        if column_label(schema, table, column) not in columns:
            continue
        if kind == "array":
            out.append(
                f"UPDATE {qualified(schema, table)} SET {column} = "
                f"array_replace({column}, {_lit(value)}, {_lit(replacement)})\n"
                f" WHERE {_lit(value)} = ANY({column});")
        else:
            out.append(
                f"UPDATE {qualified(schema, table)} SET {column} = "
                f"{_lit(replacement)}\n WHERE {column} = {_lit(value)};")
    return "\n".join(out)


def remove_sql(value: str | None, columns: list[str]) -> str:
    """Drop ONE value from every array column that holds it. Offered
    second, because dropping a lock is a DECLASSIFICATION. A NULL element
    is removed the same way (`array_remove` matches NULL). The scalar
    `forced_compartment` is never removed here: 0033's CHECK requires a
    stealer-log key to carry one, so the remedy there is rename or
    revoke, and the message says so."""
    out = []
    for schema, table, column, kind in BOUND_COLUMNS:
        if column_label(schema, table, column) not in columns:
            continue
        if kind == "array":
            lit = "NULL" if value is None else _lit(value)
            out.append(
                f"UPDATE {qualified(schema, table)} SET {column} = "
                f"array_remove({column}, {lit})\n"
                f" WHERE array_position({column}, {lit}) IS NOT NULL;")
        else:
            out.append(
                f"  -- {column_label(schema, table, column)} cannot be "
                f"removed (a stealer-log key must carry one): rename it "
                f"above, or revoke the key.")
    return "\n".join(out)


def cleanup_sql(value: str | None, columns: list[str]) -> str:
    """All the remedies for ONE value, each introduced by the sentence
    that tells the operator which of them they are choosing."""
    if value is None:
        return (
            f"  -- a NULL element in {', '.join(columns)} is not a key and "
            f"can never be held; drop it:\n"
            f"{remove_sql(None, columns)}")
    lines = []
    if re.match(KEY_FORMAT, value):
        lines.append(
            f"  -- register {_lit(value)} ONLY if it is a real compartment "
            f"people were meant to hold (this mints it; do not register a "
            f"typo):\n{register_sql(value)}")
        lines.append(
            f"  -- or rename {_lit(value)} to the key it was meant to be, in "
            f"EVERY column that holds it:\n"
            f"{rename_sql(value, REPLACEMENT, columns)}")
    else:
        lines.append(
            f"  -- {_lit(value)} does not satisfy the key format {KEY_FORMAT} "
            f"and cannot be registered. Rename it to the key it was meant to "
            f"be, in EVERY column that holds it:\n"
            f"{rename_sql(value, REPLACEMENT, columns)}")
    lines.append(
        f"  -- or, if it was never a real compartment, REMOVE it -- but note "
        f"that removing a lock DECLASSIFIES every row that carried it:\n"
        f"{remove_sql(value, columns)}")
    return "\n".join(lines)


def group_found(found: list[tuple]) -> dict[str | None, list[str]]:
    """`UNREGISTERED_SQL` rows -> {value: [columns holding it]}."""
    grouped: dict[str | None, list[str]] = {}
    for value, column in found:
        grouped.setdefault(value, []).append(column)
    return grouped


def refusal_message(found: list[tuple]) -> str:
    """Why the upgrade stopped, and the statements that let it continue.

    0057's shape: a migration that refuses without saying what to type is
    a wall, and this one is a pre-upgrade cleanup step. Every value is
    named with every column that holds it, rendered ONE way (`_lit`, the
    way the printed statements render it), and the three remedies are
    printed per value.
    """
    grouped = group_found(found)
    names = ", ".join(
        ("NULL" if v is None else _lit(v)) + f" (in {', '.join(cols)})"
        for v, cols in grouped.items())
    statements = "\n".join(cleanup_sql(v, cols) for v, cols in grouped.items())
    return (
        f"compartment value(s) already in use are not registered in "
        f"iam.compartment: {names}. This migration binds every compartment "
        f"column to the registry, and leaving them unregistered would make "
        f"every row filed under them unwritable and every case under them "
        f"a lock nobody holds -- so this upgrade stops here rather than "
        f"creating that state. Choose a remedy for each value, run it, then "
        f"re-run the upgrade:\n\n{statements}\n\n"
        f"Replace '{REPLACEMENT}' with the key the compartment was meant to "
        f"have; it must match {KEY_FORMAT}. Register a key with "
        f"{REGISTRATION_ROUTE} (user.manage) rather than by hand where you "
        f"can, so the registration is audited.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    # Refuse BEFORE creating anything, with the operator's actual problem
    # and the statements that fix it. Nothing exists yet at this point, so
    # a refused upgrade leaves the database exactly as it was.
    found = query(UNREGISTERED_SQL)
    if found:
        raise RuntimeError(refusal_message(found))
    run(FUNCTIONS_SQL)
    for schema, table, column, kind in BOUND_COLUMNS:
        run(trigger_sql(schema, table, column, kind))


def downgrade() -> None:
    for schema, table, _column, _kind in BOUND_COLUMNS:
        run(f"DROP TRIGGER IF EXISTS {TRIGGER_NAME} ON {qualified(schema, table)};")
    run(f"""
DROP TRIGGER IF EXISTS {REGISTRY_TRIGGER_NAME} ON iam.compartment;
DROP FUNCTION iam.refuse_compartment_removal();
DROP FUNCTION iam.compartment_in_use(text);
DROP FUNCTION iam.refuse_unregistered_compartment();
DROP FUNCTION iam.unregistered_compartments(text[]);
DROP FUNCTION iam.compartments_registered(text[]);
""")
