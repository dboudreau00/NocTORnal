"""Deployment configuration is read-only to the request role
(unpolicied configuration tables, Beta 1.1, 2026-10-08).

## Why

The configuration tables carry no case and no label, so row security
filters none of them (`rls_registry.EXEMPT`), and 0060 handed
`noctornal_app` INSERT, UPDATE and DELETE on each. One statement injected
into a request could add an egress route or destination, widen a profile,
add or rebind a source, create or restore a persona, record or confirm a
collection authority, lower a lookup provider's exposure or replace its
key, shorten a retention rule, mint or revive an ingest key, point Jira
somewhere else, retire a prohibited-content list or register an embedding
index: none of it behind the administration route's gate, its step-up or
the audit row the route's service writes.

## What

The request role loses the writes it held on each table in
`CONFIG_WRITES` and keeps SELECT. The administration routes now write on a
system connection after their own gate (the request role's), with the step-up
and the audit they always applied, as 0109 did for the accounts plane:

- `SystemPurpose.CONFIGURATION`: the egress administration
  (`routers/egress.py`), a source's creation, activation and binding and a
  persona's creation and status (`routers/collection.py`), a Telegram
  persona's hours and a chat's activation (`routers/collection_telegram.py`),
  the collection authorities (`routers/collection_authority.py`), the
  lookup providers (`routers/providers.py`, the listing too, which lapses an
  expired exposure change as it reads), and an ingest key's issue and
  revocation (`routers/ingest.py`);
- RETENTION, which already counted for it: a retention rule's confirmation;
- SCREENING, which already imports a list: a list's retirement and purge;
- NOTIFY_ADMIN, since F51: Jira's administration (unchanged);
- EMBEDDINGS: an index's registration and lifecycle (unchanged).

A persona act run inline in development runs its work on the PERSONA_ACTS
connection, as the collector runs it in production
(`persona_acts.run_inline`): the acts write personas, chats and sources.

The one write a request still makes is a key's use: the unauthenticated
ingest submit stamps `ingest.api_key.last_used_at` for the key it
authenticated. `ingest.api_key_used(p_key, p_hmac)` does it as the definer,
and only when `p_hmac` is that key's stored HMAC (compared as sha256 of each
side, so the comparison's timing says nothing an attacker can steer: an
HMAC under a pepper the caller does not hold cannot be chosen byte by byte).
It answers whether it matched, and `IngestService.authenticate` reads that
as the secret's check; it asks on every presentation of a known key, with
no HMAC when another refusal applies (revoked, expired, another
environment, an address the allowlist does not admit), so only a usable
key's use is stamped. A statement that does not hold a key's secret cannot
stamp it, so the stale-key list cannot be fooled into hiding a stolen key.

A person's own delivery settings (`notify.preference`) are 0182's. The
queues (`core.embedding_pending`, `lab.yara_compile_job`), the collector's
heartbeat, the poll runs and an ingest batch's envelope are not
configuration and keep their writes.

`RUNTIME_READ_ONLY_TABLES` declares them for
`test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
`PRIVILEGES_SQL` is repeatable and `scripts/runtime_roles.py ensure`
replays it after 0108's blanket grant.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0060 and 0172 are. The downgrade gives back
exactly the writes this revision took, and drops the function.
"""
from alembic import op

revision = "0179"
down_revision = "0178"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: The writes the request role held on each table when this revision was
#: written: what it revokes, and what the downgrade gives back. Some had
#: lost one already to their own revisions (DELETE on the authorities, the
#: providers and the screening lists, UPDATE on the screening hashes).
CONFIG_WRITES: dict[str, tuple[str, ...]] = {
    "collect.egress_profile": ("INSERT", "UPDATE", "DELETE"),
    "collect.egress_integration_route": ("INSERT", "UPDATE", "DELETE"),
    "collect.egress_destination": ("INSERT", "UPDATE", "DELETE"),
    "collect.source": ("INSERT", "UPDATE", "DELETE"),
    "collect.collection_account": ("INSERT", "UPDATE", "DELETE"),
    "collect.collection_authority": ("INSERT", "UPDATE"),
    "collect.collection_authority_target": ("INSERT", "UPDATE"),
    "core.retention_rule": ("INSERT", "UPDATE", "DELETE"),
    "core.embedding_space": ("INSERT", "UPDATE", "DELETE"),
    "ingest.api_key": ("INSERT", "UPDATE", "DELETE"),
    "ingest.provider": ("INSERT", "UPDATE"),
    "ingest.provider_exposure_change": ("INSERT", "UPDATE"),
    "lab.screening_list": ("INSERT", "UPDATE"),
    "lab.screening_hash": ("INSERT", "DELETE"),
    "notify.jira_destination": ("INSERT", "UPDATE", "DELETE"),
}

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = tuple(CONFIG_WRITES)


def _each(verb: str, preposition: str) -> str:
    return "\n".join(
        f"    EXECUTE format('{verb} {', '.join(privileges)} ON {table} "
        f"{preposition} %I', app);"
        for table, privileges in CONFIG_WRITES.items())


def _block(body: str) -> str:
    return f"""
DO $noc$
DECLARE
  app text := '{APP_ROLE}';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{body}
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
PRIVILEGES_SQL = _block(_each("REVOKE", "FROM"))

#: Frozen text.
FUNCTION_SQL = """
CREATE FUNCTION ingest.api_key_used(p_key uuid, p_hmac bytea) RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  WITH used AS (
    UPDATE ingest.api_key k
       SET last_used_at = pg_catalog.now()
     WHERE k.id = p_key
       AND p_hmac IS NOT NULL
       AND pg_catalog.sha256(k.secret_hmac) = pg_catalog.sha256(p_hmac)
    RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM used)
$$;

COMMENT ON FUNCTION ingest.api_key_used(uuid, bytea) IS
  'Stamps an ingest key''s last use, for a caller that presents its secret''s HMAC, and '
  'answers whether it matched (0179): the keys are read-only to the request role.';

REVOKE ALL ON FUNCTION ingest.api_key_used(uuid, bytea) FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION ingest.api_key_used(uuid, bytea) TO %I', r);
    END IF;
  END LOOP;
END
$noc$;
"""

DOWNGRADE_SQL = "DROP FUNCTION ingest.api_key_used(uuid, bytea);\n" + _block(
    _each("GRANT", "TO"))


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL)
    run(PRIVILEGES_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
