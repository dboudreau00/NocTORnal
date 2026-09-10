"""The runtime role's privileges: everything it needs, and not ownership.

## The REVOKEs were always aimed past the process that mattered

0013 revoked UPDATE, DELETE and TRUNCATE on `audit.event` FROM PUBLIC, 0052
did the same for `core.purge_tombstone` and `lab.sample_access`, and 0058
finished the set with `core.evidence_custody`. Every one of those statements
takes privileges away from PUBLIC. **The owner of a table is not PUBLIC**, and
an owner's rights are implicit -- they are not entries in the ACL and there is
nothing there to revoke. So the four REVOKEs constrained every role in the
cluster except the one actually holding the connection, because the shipped
compose has the API connect as the role that owns the schema.

0052's own docstring says so in as many words: "It is reachable by the
application role itself if it owns the tables -- which it does in the shipped
compose". The triggers are the enforcement and they hold against ordinary DML;
what they do not hold against is `ALTER TABLE audit.event DISABLE TRIGGER ALL`,
which needs table ownership and nothing else, and which the API's own
connection could issue at any point between two audited writes. An append-only
ledger whose writer may switch off the append-only guarantee is a ledger with a
documented threat model of "we trust the application", which is not the claim
docs/08 makes and not the claim an evidential record can afford.

This revision is the second half of the fix. The first half is
`db/init/10-app-role.sh`, which creates `noctornal_app` at initdb -- the only
moment anything here runs as a superuser, and therefore the only place CREATE
ROLE can live (db/README.md). That role owns nothing. Ownership is what confers
ALTER TABLE, DROP TABLE and TRUNCATE, so not being the owner is the entire
control; the grants below are what makes a non-owner able to run the product
anyway.

## It is a complete no-op where the role does not exist

CI has no app role. Neither does any developer database, nor the dev compose,
which passes no NOCTORNAL_APP_DB_PASSWORD and therefore gets nothing from the
init script. All of them run `alembic upgrade head`, and CI additionally
round-trips head -> base -> head. A GRANT naming a role that does not exist is
not a no-op -- it is `ERROR: role "noctornal_app" does not exist`, and it would
break every one of those. Hence one `DO` block per direction, guarded on
`pg_roles`, doing nothing at all when the role is absent.

The guard is also the upgrade path: an existing deployment adds the role by
initialising a fresh volume with the password set (initdb scripts never re-run
on an existing cluster), then re-running `alembic upgrade head`, which finds the
role this time and grants it.

## What is granted, and which parts are load-bearing

- **USAGE on the ten schemas.** Without it every qualified name in the product
  is `permission denied for schema core`.

- **SELECT, INSERT, UPDATE, DELETE on all tables**, then UPDATE and DELETE
  taken back on the four append-only ledgers. Revoking TRUNCATE alongside them
  would read as thoroughness and mean nothing: a GRANT of DML never confers
  TRUNCATE, so there is nothing to revoke. TRUNCATE belongs to the owner (and
  to anyone explicitly granted it, which nobody is), and the reason this role
  cannot truncate a ledger is the same reason it cannot drop the ledger's
  trigger -- it does not own it. That is the point of the whole revision.

- **USAGE, SELECT on all sequences.** This is the grant that looks like
  boilerplate and is not. The database has exactly three sequences, and all
  three sit behind append-only ledgers: `audit.event_seq_seq`,
  `core.evidence_custody_id_seq` and `lab.sample_access_id_seq`. A column
  DEFAULT `nextval(...)` is evaluated as the INSERTING role, so without USAGE
  every audited action in the product fails -- and it fails with `permission
  denied for sequence event_seq_seq`, naming the sequence and not the table,
  which sends the reader looking in the wrong place.

- **EXECUTE on all functions**, which is belt and braces and is described that
  way on purpose: EXECUTE on a new function is granted to PUBLIC by default, so
  this changes nothing today. It becomes the thing that keeps the product
  working the day someone revokes PUBLIC's default. Note what it is NOT for:
  the nineteen trigger functions behind this schema's forty-eight triggers.
  EXECUTE on a trigger function is checked when the trigger is CREATED, not
  when it fires, so the triggers would run for this role with no grant at all.

  It does not cover `public`, where the only function the product calls by
  name lives (`public.digest`, pgcrypto). Extension functions belong to the
  extension's installer rather than to `ownr`, so neither this grant nor the
  default privileges below would reach them; the thing keeping `digest()`
  callable is still PUBLIC's default EXECUTE.

- **SELECT on `public.alembic_version`.** `readiness.py`'s `migrations_at_head`
  check reads that table on the API's own connection, unqualified. Alembic
  creates it, so it belongs to the owner and carries no grant; the check would
  have reported `permission denied for table alembic_version` as a failed
  readiness check -- a control reporting the absence of a grant as "this
  deployment is not at head". SELECT only: the runtime role must never be able
  to stamp a revision it did not apply.

- **ALTER DEFAULT PRIVILEGES FOR ROLE <owner>**, so that tables added by later
  migrations are covered without anyone remembering. A default privilege is
  not a property of the schema; it is a rule attached to ONE creating role,
  and it fires only for objects that role goes on to create.

  `FOR ROLE current_user` is therefore explicit rather than necessary --
  omitting the clause means exactly the same thing, because the current role
  is what Postgres assumes. What it is deliberately not is `FOR ROLE
  noctornal`: the identity running Alembic is `noctornal` under
  `NOCTORNAL_MIGRATION_DATABASE_URL` and in CI, but a laptop's DSN names
  whatever its owner called the role, and a rule written for a role that is
  not the one creating the tables is a rule that never fires. It would fail
  silently -- no error at migration time, and `permission denied for table
  <something new>` months later.

  **The warning that goes with it:** a FUTURE append-only ledger will inherit
  UPDATE and DELETE from these defaults the moment it is created, silently,
  because that is what a default privilege is. The migration that creates it
  must revoke them from `noctornal_app` itself, exactly as this one does for
  the four that exist. `test_app_role_privileges_pg.py` holds the current four;
  it cannot know about the fifth.

## Downgrade

Reverses precisely what was granted here, so that `DROP OWNED BY noctornal_app;
DROP ROLE noctornal_app;` has less to complain about. It deliberately does NOT
revoke CONNECT on the database: that grant is the init script's, this migration
never made it, and revoking it would leave a production deployment unable to
open a connection after a downgrade/upgrade round trip that restored everything
else. Dropping the role for real still needs `DROP OWNED BY` first -- that is
the statement that clears database-level and default-ACL dependencies -- and
db/README.md says so where an operator will look for it.
"""
from alembic import op

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None

#: The runtime role. Created by db/init/10-app-role.sh, never here: CREATE
#: ROLE needs a superuser and the migration role must never be one.
APP_ROLE = "noctornal_app"

#: Every schema the migrations create (0001, 0029, 0031, 0033, 0034, 0048).
#: `public` is handled separately below -- the product owns no table in it,
#: but Alembic's version table lives there.
SCHEMAS = ("analytics", "audit", "collect", "comms", "core", "deception",
           "iam", "ingest", "lab", "notify")

#: The append-only ledgers: UPDATE and DELETE come straight back off these.
#: The list is the one the trigger PAIRS define, and the pairs were not all
#: laid down at once: `audit.event` (0013) and `core.evidence_custody` (0023)
#: shipped with both the row trigger and the BEFORE TRUNCATE one, while
#: `lab.sample_access` (0031) and `core.purge_tombstone` (0032) shipped with
#: only the row trigger and did not become truncate-proof until 0052. Reading
#: 0052 as the second half of all four pairs gets that backwards -- it never
#: touched `core.evidence_custody`, whose missing REVOKE was 0058's.
#:
#: `iam.compartment`'s 0059 guard is not a ledger: it refuses a delete only
#: while the key is in use, and the product legitimately removes an unused one.
LEDGERS = ("audit.event", "core.evidence_custody", "core.purge_tombstone",
           "lab.sample_access")

#: Read by readiness.py, unqualified, on the API's own connection.
VERSION_TABLE = "public.alembic_version"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _array(values: tuple[str, ...]) -> str:
    """A SQL `text[]` literal from a tuple of identifiers.

    No escaping: every value here is a module constant matching
    `[a-z_.]+`. If that ever stops being true this needs `quote_literal`,
    because these strings are pasted into SQL text.
    """
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]"


#: One DO block, so the role check happens once and everything inside it is
#: skipped together. `%I` (quote_ident) throughout rather than pasted names:
#: the values are constants, but a GRANT built by concatenation is a habit
#: worth not having in a file about privileges.
UPGRADE_SQL = f"""
DO $noc$
DECLARE
  app  text := '{APP_ROLE}';
  ownr text := current_user;   -- the OWNER: this migration runs as it
  s    text;
  t    text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    FOREACH s IN ARRAY {_array(SCHEMAS)} LOOP
      EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, app);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE'
                     || ' ON ALL TABLES IN SCHEMA %I TO %I', s, app);
      EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I',
                     s, app);
      EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO %I',
                     s, app);
      -- Applies only to objects created LATER, and only by `ownr`. A future
      -- append-only ledger inherits UPDATE and DELETE from the first of these
      -- the moment it is created; its own migration must revoke them.
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
                     ownr, s, app);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT USAGE, SELECT ON SEQUENCES TO %I',
                     ownr, s, app);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT EXECUTE ON FUNCTIONS TO %I',
                     ownr, s, app);
    END LOOP;

    -- After the blanket grant, never before it: ALL TABLES would put them
    -- straight back. TRUNCATE is absent by construction, not by oversight --
    -- see the docstring.
    FOREACH t IN ARRAY {_array(LEDGERS)} LOOP
      EXECUTE format('REVOKE UPDATE, DELETE ON %s FROM %I', t::regclass, app);
    END LOOP;

    -- USAGE on public is granted to PUBLIC on a stock cluster (PG15 revoked
    -- CREATE there, not USAGE), so this is explicit rather than new. It has to
    -- hold: pgcrypto's digest() lives in public and audit_verify.py and
    -- custody_verify.py call it by name.
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', app);
    -- Guarded because a database built by loading db/schema.sql rather than by
    -- running Alembic has no version table, and this must not be the statement
    -- that decides whether that database can be upgraded.
    IF to_regclass('{VERSION_TABLE}') IS NOT NULL THEN
      EXECUTE format('GRANT SELECT ON {VERSION_TABLE} TO %I', app);
    END IF;
  END IF;
END
$noc$;
"""

#: Mirror image. Default privileges first: they are catalog rows of their own
#: (pg_default_acl) and survive a REVOKE on the tables, so a downgrade that
#: dropped only the table grants would leave the role holding rights over
#: every table any later migration created.
DOWNGRADE_SQL = f"""
DO $noc$
DECLARE
  app  text := '{APP_ROLE}';
  ownr text := current_user;
  s    text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    FOREACH s IN ARRAY {_array(SCHEMAS)} LOOP
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON TABLES FROM %I', ownr, s, app);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON SEQUENCES FROM %I', ownr, s, app);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON FUNCTIONS FROM %I', ownr, s, app);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', s, app);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', s, app);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM %I', s, app);
      EXECUTE format('REVOKE ALL ON SCHEMA %I FROM %I', s, app);
    END LOOP;

    IF to_regclass('{VERSION_TABLE}') IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON {VERSION_TABLE} FROM %I', app);
    END IF;
    -- Removes this migration's explicit grant only; PUBLIC keeps its own, as
    -- it did before 0060 ran.
    EXECUTE format('REVOKE USAGE ON SCHEMA public FROM %I', app);
  END IF;
END
$noc$;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
