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

A pre-existing value that does not satisfy the format cannot be
registered, and this migration REFUSES rather than skipping it: skipping
would leave every case filed under that value unreachable through the
product from the moment the gate is applied, which is the silent
no-access this migration exists to end, now with a migration's signature
on it. The refusal names the values so the operator can correct them in
place before re-running.

`BACKFILL_SQL` and `UNREGISTRABLE_SQL` are module constants so the test
can run the statement itself against a seeded row -- on CI both arrays
are empty and "the backfill registered everything" would be vacuous.

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


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    # Refuse BEFORE creating anything, with the operator's actual problem.
    bad = [r[0] for r in query(UNREGISTRABLE_SQL)]
    if bad:
        raise RuntimeError(
            "compartment value(s) already in use do not satisfy the key "
            f"format {KEY_FORMAT}: {', '.join(repr(b) for b in bad)}. They "
            "cannot be registered, and leaving them unregistered would lock "
            "every case filed under them. Correct the values in "
            "iam.app_user.compartments and core.case.compartments (on both "
            "sides, identically), then re-run the upgrade.")
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
