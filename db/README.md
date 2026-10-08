# db/

- **`migrations/`**, the Alembic chain, the ONE authoritative schema
  (docs/00 decision 17). `alembic upgrade head`; one concern per revision,
  every revision reversible on an empty database (CI round-trips
  head → base → head). The reasoning for each table's shape lives in the
  docstring of the revision that created it.
- **`schema.sql`**, a GENERATED mirror of the schema at head, written by
  `scripts/dump_schema.py` (`pg_dump --schema-only --no-owner
  --no-privileges`, with session settings, version comments and pg_dump's
  per-run `\restrict` tokens removed). Its header names the revision it
  mirrors. CI regenerates it and fails on any difference ("Schema mirror
  matches the migrations"), and `apps/api/tests/test_schema_mirror.py`
  holds the header to the chain's head and the migrations' schemas to the
  file. **Do not edit it by hand.**
- **The vocabulary** (node, edge and selector types) loads from revision
  0017 plus every later revision that extends it.
  `packages/ontology/generated/seed_ontology.sql` is the generated form of the
  current definition (`packages/ontology/README.md`); there is no separate
  seed file here.
- **`init/`**, what initdb runs, in filename order, once, as the superuser
  the Postgres image creates. Nothing schema-shaped can live here: Alembic
  has not run at this point and the database contains no schemas at all.
  - **`00-extensions.sql`**, `CREATE EXTENSION` needs superuser, which the
    migration role must never be.
  - **`10-app-role.sh`**, creates the least-privilege runtime role
    `noctornal_app` (below). A shell script because the password arrives in
    the environment; a no-op, loudly, when `NOCTORNAL_APP_DB_PASSWORD` is
    unset, which is the case for every dev stack. CI never reaches even that:
    it does not mount this directory, it applies `00-extensions.sql` by name.
    The same script creates the system role `noctornal_worker` when
    `NOCTORNAL_WORKER_DB_PASSWORD` is set.
  - **`20-egress-role.sh`**, creates `noctornal_egress`, the egress proxy's own
    role, from `NOCTORNAL_EGRESS_DB_PASSWORD`, on the same terms.
- **`requirements.txt`**, what CI installs before `alembic upgrade head`.

## The roles

A production deployment has four Postgres roles (docs/00 decision 138), and
the split exists for one reason: `audit.event`, `core.evidence_custody`,
`lab.sample_access` and `core.purge_tombstone` are append-only, enforced by
triggers, and **a table's owner may drop or disable any trigger on it**. Every REVOKE in the chain (0013,
0052, 0058) takes privileges away from PUBLIC, and an owner's rights are
implicit rather than ACL entries, so none of them ever constrained the
connection the API holds. While the API connects as the owner, "append-only"
means "append-only unless the API says otherwise".

| | `noctornal` | `noctornal_app` | `noctornal_worker` | `noctornal_egress` |
|---|---|---|---|---|
| Owns the schema | yes | **no** | **no** | **no** |
| Runs Alembic | yes, via `NOCTORNAL_MIGRATION_DATABASE_URL` | never | never | never |
| Used by | development, and the migration job | the API and every runtime process, reading through row-level policies (`DATABASE_URL`) | the named system purposes that must see every row; bypasses row security (`NOCTORNAL_WORKER_DATABASE_URL`) | the egress proxy alone (`NOCTORNAL_EGRESS_DATABASE_URL`) |
| Can `ALTER TABLE ... DISABLE TRIGGER` | yes | **no** | **no** | **no** |
| Can `TRUNCATE` a ledger | yes | **no** | **no** | **no** |

The passwords come from `NOCTORNAL_APP_DB_PASSWORD`,
`NOCTORNAL_WORKER_DB_PASSWORD` and `NOCTORNAL_EGRESS_DB_PASSWORD` at initdb.
Without them a role is never created: a development stack and CI then connect
as the owner, and a production process whose `DATABASE_URL` names the owner or
a superuser refuses to start.

### Why the role is created at initdb and granted by a migration

`CREATE ROLE` needs superuser or CREATEROLE, and the rule at the top of this
file says the migration role must never be either, so the role is *born* in
`init/10-app-role.sh`, the one moment a superuser is running. It cannot be
*granted* there: at that point in initdb the database has no schemas, and a
`GRANT USAGE ON SCHEMA core` would be a well-formed statement that fails and
abandons a half-built cluster. So every privilege lives in migration
**`0060_app_role_grants.py`**, which is wrapped in a `pg_roles` check and does
absolutely nothing where the role does not exist. The worker's grants (0108)
and the egress role's (0086) follow the same rule, and
`scripts/runtime_roles.py ensure` repairs a cluster initialised without them.

**The ordering is load-bearing.** The role must exist *before* `alembic upgrade
head` runs 0060; a role created afterwards is a role 0060 has already declined
to grant, and running `alembic upgrade head` again grants nothing, because
Alembic does not re-run a revision it has recorded. On an existing database,
create the role as a superuser before upgrading it past 0060. For a role that
arrived later, run [`release/alpha6-upgrade/app-role-grants.sql`](../release/alpha6-upgrade/app-role-grants.sql)
with psql as the owner: it is 0060's `UPGRADE_SQL` followed by 0063's `REVOKE
DELETE ON lab.preservation_authorisation`, copied from the migrations (see the
0060 docstring), and running it twice changes nothing. The same ordering
applies to CI: a job that wants `apps/api/tests/test_app_role_privileges_pg.py`
to run rather than skip must `CREATE ROLE` before the migration step and export
`NOCTORNAL_APP_DB_ROLE=noctornal_app`.

### Recovery: "ERROR: must be owner of table ..."

Symptom: the test suite, or a migration, fails with `must be owner of table
audit.event` (or `permission denied for schema core`; the audit and custody
sequences are drawn by their chain triggers as the owner since 0149, and the
Lab custody ledger's by its own trigger since 0175, and the runtime roles hold
no privilege on any of the three since 0169 and 0175).
Cause, almost always:
`DATABASE_URL` is pointed at `noctornal_app`.

Many `*_pg` test files run `ALTER TABLE ... DISABLE TRIGGER` to seed rows behind
an append-only guard, and Alembic itself creates and drops objects. Both need
ownership. **Tests and migrations use the owner DSN; only the runtime app uses
the app role.** This is not a configuration to be fixed by granting more, a
grant that made the failure go away would hand the runtime role the very
ownership the split exists to withhold.

Fix it by pointing the variable back:

```sh
# the owner, for tests, migrations and scripts
export DATABASE_URL='postgresql+psycopg://noctornal:<password>@localhost:5432/noctornal'
```

Confirm which role a session actually holds, and whether it owns anything:

```sql
SELECT current_user, session_user;
SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'audit.event'::regclass;
```

To remove the role entirely, `downgrade` 0060 (which drops the grants and the
default privileges) and then:

```sql
-- clears BOTH the CONNECT grant the init script made and any default-ACL
-- rows still naming the role; run it in every database the role can reach
DROP OWNED BY noctornal_app;
DROP ROLE noctornal_app;
```

`DROP ROLE` alone fails while any privilege anywhere still references the role,
and the error names the database rather than the grant, which is why the
`DROP OWNED BY` goes first.
