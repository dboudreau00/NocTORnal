"""The Lab custody ledger's sequence is its trigger's alone
(definer functions answer for any id, Beta 1.1, 2026-10-08).

## Why

`lab.sample_access.id` is a serial: its column default
`nextval('lab.sample_access_id_seq')` is evaluated as the INSERTING role, so
0060 (and 0108 for the system role) granted both runtime roles USAGE and
SELECT on the sequence. `SELECT last_value FROM lab.sample_access_id_seq`
then read the volume of the Lab's custody ledger, every download, share,
detonation, assignment, analysis and scan on every sample whatever its
labels, to any request-role connection, bound or not, and `nextval()` read
it as well. 0169 closed the same reading on the audit and custody chains;
this is the third ledger sequence.

## What this changes

- `lab.sample_access_numbered()`, BEFORE INSERT on every row, draws the
  number as its owner: `NEW.id := nextval(...)`, whatever the caller
  supplied. SECURITY DEFINER with `search_path = pg_catalog, pg_temp`; it
  reads no table. The ledger is not hash-chained, so no lock is taken: the
  number orders rows (`occurred_at DESC, id DESC` in the custody listing)
  and is unique, and drawing it in a trigger keeps both.
- The column default is dropped, so nothing else draws. A row written with
  the trigger stood down names its own number, as 0169 says of the other two.
- `noctornal_app` and `noctornal_worker` lose USAGE and SELECT on the
  sequence. Guarded on the role and the sequence existing (a database with
  no runtime roles, or built from `schema.sql`, grants nothing).
  `scripts/runtime_roles.py ensure` replays `REVOKE_SQL` after 0108's
  grants, which hand every sequence to a role created later.

What this does NOT close, as 0169 says of the audit log: `INSERT ...
RETURNING id` on a custody row the writer may read returns the newest
number. No application code asks for a custody row back
(`SampleService._access`), so it needs SQL as the request role, on a sample
the caller may see, and it writes a custody row doing it.

## Downgrade

Gives both roles their privileges back, restores the default and drops the
trigger and its function.
"""
from alembic import op

revision = "0175"
down_revision = "0174"
branch_labels = None
depends_on = None

SEQUENCE = "lab.sample_access_id_seq"
RUNTIME_ROLES = ("noctornal_app", "noctornal_worker")

#: Frozen text.
TRIGGER_SQL = """
CREATE FUNCTION lab.sample_access_numbered() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  NEW.id := pg_catalog.nextval('lab.sample_access_id_seq'::pg_catalog.regclass);
  RETURN NEW;
END $fn$;

CREATE TRIGGER sample_access_numbered BEFORE INSERT ON lab.sample_access
  FOR EACH ROW EXECUTE FUNCTION lab.sample_access_numbered();

COMMENT ON FUNCTION lab.sample_access_numbered() IS
  'Draws lab.sample_access.id as the owner, so neither runtime role holds the sequence and none can read the ledger''s volume from it (0175).';

ALTER TABLE lab.sample_access ALTER COLUMN id DROP DEFAULT;
"""

DROP_TRIGGER_SQL = """
ALTER TABLE lab.sample_access ALTER COLUMN id SET DEFAULT nextval('lab.sample_access_id_seq');
DROP TRIGGER sample_access_numbered ON lab.sample_access;
DROP FUNCTION lab.sample_access_numbered();
"""


def _sequence_privileges(verb: str, preposition: str) -> str:
    lines = []
    for role in RUNTIME_ROLES:
        lines.append(
            f"  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')\n"
            f"     AND to_regclass('{SEQUENCE}') IS NOT NULL THEN\n"
            f"    EXECUTE '{verb} USAGE, SELECT ON SEQUENCE {SEQUENCE} {preposition} {role}';\n"
            f"  END IF;")
    return "DO $noc$\nBEGIN\n" + "\n".join(lines) + "\nEND\n$noc$;"


#: Replayed by scripts/runtime_roles.py after 0108's grants, on a cluster
#: whose roles were created later.
REVOKE_SQL = _sequence_privileges("REVOKE", "FROM")
GRANT_SQL = _sequence_privileges("GRANT", "TO")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(TRIGGER_SQL)
    run(REVOKE_SQL)


def downgrade() -> None:
    run(GRANT_SQL)
    run(DROP_TRIGGER_SQL)
