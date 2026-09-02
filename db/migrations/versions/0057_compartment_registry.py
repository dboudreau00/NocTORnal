"""A registry for compartment keys: a typo was silent no-access.

`iam.app_user.compartments` and `core.case.compartments` have been free
text arrays since 0004 and 0012, validated by nothing, compared
byte-for-byte by the five-part gate (`c.compartments <@ u.compartments`).
The user-side array had no product write path at all: a compartment was
granted with `psql`, and `OP-KESTREL` typed as `OP-KESTRAL` on one side
meant the analyst simply stopped seeing the case. No listing, gate or log
said why -- the gate reported a correct decision about two different
strings. `iam_admin.py` has cited this as "the compartment-registry
lesson" in its role allowlist since 2026-07-30 without the registry
existing to apply it to.

## The registry is the vocabulary, and the schema holds the format

`iam.compartment` is the closed set. `cases.py` refuses to file a case
under a key that is not in it, naming the key; `iam_admin.set_compartments`
refuses the same way for a user. The key format (`^[A-Z0-9_-]{2,32}$`) is
a CHECK on the table rather than a rule in the service, because the
service is not the only writer of a Postgres table, and a key is something
typed into a warrant schedule: case and whitespace variants are not "the
same compartment", they are a second one that nobody holds.

## The backfill registers what is already in use

Every distinct value currently in either array is registered, labelled
with its own key (there is no better label on record), with no
`created_by` (nobody registered it; it was found). Idempotent: `ON
CONFLICT DO NOTHING`, so a re-run changes nothing.

## A value that cannot be registered: the decision, and why (2026-09-02)

A pre-existing value that does not satisfy the format cannot be
registered, and this migration REFUSES rather than skipping it. That is a
hard fail on a database that holds one, so it is a decision and not an
oversight, and here is the whole of it.

Skipping would leave every case filed under that value unreachable
through the product from the moment the gate is applied -- the silent
no-access this migration exists to end, now with a migration's signature
on it. Widening the CHECK to `{1,32}` was rejected: it rescues exactly the
one-character case and nothing else (`op-kestrel`, `OP KESTREL`, a
trailing space all still fail), while giving up the rule that a key is
long enough to be a name rather than a keystroke. Registering the
offenders under a quarantine label was rejected for the same reason it
sounds attractive: it needs the CHECK relaxed to admit them, and it ends
by minting the typo as a real compartment that somebody can then be read
into.

So the refusal stands, and it is a documented PRE-UPGRADE CLEANUP STEP
rather than a wall: `refusal_message` names every offending value and
prints the exact `UPDATE` statements for both arrays, including the
warning that removing a lock is a declassification and not a rename.

This is not purely an operator-data problem, and the first version of this
docstring implied it was. The project's own suite manufactured such a
value: `test_notifications_pg.py` wrote the compartment `'A'` into
`iam.app_user.compartments` until it was renamed on 2026-09-02. A run
interrupted between that write and its fixture teardown leaves the value
behind, and the next `alembic upgrade` on that database stops here. The
fixture was corrected in the same change as this paragraph, because the
fixture was what was wrong.

`BACKFILL_SQL`, `UNREGISTRABLE_SQL` and `refusal_message` are module-level
so the test can run the statements itself against a seeded row -- on CI
both arrays are empty and "the backfill registered everything" would be
vacuous, and "the refusal is actionable" would never be exercised at all.

Downgrade drops the table. The arrays themselves are untouched in both
directions.
"""
from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None

KEY_FORMAT = r"^[A-Z0-9_-]{2,32}$"

#: Every distinct compartment value in use, from both arrays.
_IN_USE = """
      (SELECT unnest(compartments) AS c FROM iam.app_user
       UNION
       SELECT unnest(compartments) FROM core."case") s
"""

BACKFILL_SQL = f"""
INSERT INTO iam.compartment (key, label, created_by)
SELECT DISTINCT s.c, s.c, NULL::uuid
  FROM {_IN_USE}
 WHERE s.c IS NOT NULL
    ON CONFLICT (key) DO NOTHING
"""

UNREGISTRABLE_SQL = f"""
SELECT DISTINCT s.c
  FROM {_IN_USE}
 WHERE s.c IS NOT NULL AND s.c !~ '{KEY_FORMAT}'
 ORDER BY 1
"""


#: The placeholder the operator has to replace. Deliberately not a valid
#: key, so a copy-paste that skipped the thinking fails on the CHECK
#: rather than filing every affected case under the word "REPLACE".
REPLACEMENT = "<the-real-key>"


#: The two arrays the five-part gate compares against each other
#: (`c.compartments <@ u.compartments`). Every remedy below touches both:
#: renaming one side and not the other IS the typo this migration exists
#: to stop, and would leave the case invisible to its own owner.
_ARRAYS = ("iam.app_user", 'core."case"')


def _lit(value: str) -> str:
    """`value` as a Postgres string literal.

    NOT `repr()`. Python quotes a string containing an apostrophe with
    DOUBLE quotes -- `repr("OP'X")` is `"OP'X"` -- and in Postgres that is
    a quoted IDENTIFIER, so the statement would fail with "column
    \"OP'X\" does not exist". Every value this module formats is one the
    key format REJECTED, and an apostrophe is one of the ways to be
    rejected, so the broken case is precisely the case this code exists
    for: the migration would refuse the upgrade and hand the operator SQL
    that does not run.

    Doubling the quote is sufficient and safe: `standard_conforming_strings`
    has been on by default since Postgres 9.1, so a backslash is an
    ordinary character, and text cannot contain a NUL.
    """
    return "'" + value.replace("'", "''") + "'"


def rename_sql(bad: str, replacement: str) -> str:
    """Rename ONE unregistrable value, in both arrays. Executable as-is.

    Kept free of comments and of anything but the two statements, so the
    test can run exactly what the operator is told to run rather than a
    paraphrase of it.
    """
    return "\n".join(
        f"UPDATE {table} SET compartments = "
        f"array_replace(compartments, {_lit(bad)}, {_lit(replacement)})\n"
        f" WHERE {_lit(bad)} = ANY(compartments);"
        for table in _ARRAYS)


def remove_sql(bad: str) -> str:
    """Drop ONE unregistrable value from both arrays.

    Offered only as the second option, because dropping a compartment from
    a case is a DECLASSIFICATION: every analyst who was kept out by that
    lock can read the case afterwards. The operator has to mean it.
    """
    return "\n".join(
        f"UPDATE {table} SET compartments = "
        f"array_remove(compartments, {_lit(bad)})\n"
        f" WHERE {_lit(bad)} = ANY(compartments);"
        for table in _ARRAYS)


def cleanup_sql(bad: str) -> str:
    """Both remedies for ONE value, with the sentence that tells the
    operator which of them they are choosing."""
    return (
        f"  -- rename {_lit(bad)} to the key it was meant to be:\n"
        f"{rename_sql(bad, REPLACEMENT)}\n"
        f"  -- or, if it was never a real compartment, REMOVE it -- but note\n"
        f"  -- that removing a lock DECLASSIFIES every case that carried it:\n"
        f"{remove_sql(bad)}")


def refusal_message(bad: list[str]) -> str:
    """Why the upgrade stopped, and the statements that let it continue.

    A migration that refuses without saying what to type is a wall. This
    one is a pre-upgrade cleanup step: the values are named, and the SQL
    that fixes each of them is printed for both arrays. See this module's
    docstring for why the refusal is preferred to skipping, to a wider
    CHECK, and to quarantining.

    Values are shown as `_lit` renders them -- ONE rendering, the one the
    printed statements use -- so the operator never has to work out which
    quoting the prose meant and which the SQL meant.
    """
    values = ", ".join(_lit(b) for b in bad)
    statements = "\n".join(cleanup_sql(b) for b in bad)
    return (
        f"compartment value(s) already in use do not satisfy the key format "
        f"{KEY_FORMAT}: {values}. They cannot be registered, and leaving "
        f"them unregistered would lock every case filed under them out of "
        f"the product -- so this upgrade stops here rather than creating "
        f"that state. Correct them in BOTH arrays, identically, then re-run "
        f"the upgrade:\n\n{statements}\n\n"
        f"Replace '{REPLACEMENT}' with the key the compartment was meant to "
        f"have; it must match {KEY_FORMAT}.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    # Refuse BEFORE creating anything, with the operator's actual problem
    # and the statements that fix it. Nothing has been created at this
    # point, so a refused upgrade leaves the database exactly as it was
    # and the operator can re-run once the values are corrected.
    bad = [r[0] for r in query(UNREGISTRABLE_SQL)]
    if bad:
        raise RuntimeError(refusal_message(bad))
    run(f"""
CREATE TABLE iam.compartment (
  key         text PRIMARY KEY
              CONSTRAINT compartment_key_format CHECK (key ~ '{KEY_FORMAT}'),
  label       text NOT NULL,
  -- SET NULL, not RESTRICT: the registry outlives the administrator who
  -- filled it, and a backfilled entry never had one.
  created_by  uuid REFERENCES iam.app_user(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE iam.compartment IS
  'The closed vocabulary of compartment keys. cases.py and iam_admin.py '
  'refuse any key not in here, naming it, because an unregistered key is '
  'a typo and a typo in a need-to-know lock is silent no-access.';
""")
    run(BACKFILL_SQL)


def downgrade() -> None:
    run("DROP TABLE iam.compartment;")
