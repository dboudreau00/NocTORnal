-- Alpha 6 upgrade, optional. Grants the least-privilege runtime role
-- noctornal_app on a database that was migrated past 0060 before the role
-- existed: an Alpha 5.2 database upgraded before anyone created the role,
-- for one.
--
-- Why it is needed: 0060 grants the role only if the role exists when
-- `alembic upgrade head` takes the database past 0060, and Alembic never
-- re-runs a revision it has recorded. A role created afterwards holds no
-- privilege at all, however often `upgrade head` runs again (Alpha 6
-- pre-release check, 2026-09-23).
--
-- What it runs: 0060's UPGRADE_SQL, then 0063's REVOKE DELETE on
-- lab.preservation_authorisation, which 0063 skipped for the same reason.
-- Both are copied from the migrations, and test_alpha6_upgrade_contract.py
-- fails if either changes without this file. Measured the same day on an
-- upgraded Alpha 5.2 database, the role afterwards held exactly the
-- privileges it holds where it existed before the upgrade.
--
-- How: create the role first (a superuser's job, db/README.md), then run
-- this file with psql as the role that owns the schema, the one `alembic
-- upgrade head` runs as. The default privileges below are recorded for the
-- role that runs them, and they must be the owner's to cover the tables
-- later migrations create. Running it again changes nothing.
\set ON_ERROR_STOP on
BEGIN;
DO $noc$
DECLARE
  app  text := 'noctornal_app';
  ownr text := current_user;   -- the OWNER: this migration runs as it
  s    text;
  t    text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    FOREACH s IN ARRAY ARRAY['analytics', 'audit', 'collect', 'comms', 'core', 'deception', 'iam', 'ingest', 'lab', 'notify'] LOOP
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
    FOREACH t IN ARRAY ARRAY['audit.event', 'core.evidence_custody', 'core.purge_tombstone', 'lab.sample_access'] LOOP
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
    IF to_regclass('public.alembic_version') IS NOT NULL THEN
      EXECUTE format('GRANT SELECT ON public.alembic_version TO %I', app);
    END IF;
  END IF;
END
$noc$;
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
    EXECUTE format('REVOKE DELETE ON lab.preservation_authorisation FROM %I',
                   'noctornal_app');
  END IF;
END
$noc$;
COMMIT;
