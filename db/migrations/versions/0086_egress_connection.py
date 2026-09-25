"""The egress connection ledger and the least-privilege role that writes it
(S2, the egress proxy, 2026-09-24; docs/00 decision 68: "every connection
is logged append-only").

## What this adds

1. **`collect.egress_connection`**, an EVENT ledger the egress proxy writes:
   OPEN (committed before any dial), REFUSED (once the credentials held),
   CLOSE (bytes, duration, a close reason), PREAUTH (refusals before the
   credentials held, counted per peer per minute) and REWRAP (exits
   re-sealed under the active key). egress_ledger.py documents each shape;
   the CHECKs below hold them, a CLOSE carrying no destination (it copies
   its OPEN's label) among them. Every reference is a plain uuid, as
   audit.event.object_id is, so deleting a run, a source, a persona or a
   test profile never meets this table, and route_id keeps the history
   readable after such a delete.

2. **Append-only and hash-chained from the first row.** Row and TRUNCATE
   triggers refuse every change. The chain trigger takes the advisory lock
   and only THEN draws `seq` from `collect.egress_connection_seq` (no
   column default draws it), so seq order is chain order and concurrent
   writers cannot fork it: audit.event draws before the lock, and
   audit_verify.py documents the false breaks that causes. The row hash
   covers every payload column; egress_ledger.ROW_HASH_SQL is the same
   text and a test holds the two equal.

3. **The role `noctornal_egress`**, created at initdb by
   db/init/20-egress-role.sh where NOCTORNAL_EGRESS_DB_PASSWORD is set,
   is granted EGRESS_GRANTS below and nothing else: it reads the egress
   configuration and exactly the collection columns the proxy decides on,
   updates only a profile's sealed exit (rewrap), and inserts ledger rows.
   The list is egress_ledger.EGRESS_GRANTS, copied because a migration
   does not import the app; a test holds the two equal. Each grant is
   guarded on the role and on its object and column existing, so a
   database that predates the collection framework's columns grants what
   exists and the proxy refuses to start naming what is missing.

4. **The application role loses INSERT, UPDATE and DELETE** on the ledger
   (GUARDED_TABLES), so the API cannot forge a proxy row. The schema owner
   can still rewrite anything; the chain is evidence against anything
   less.

## Downgrade

Refuses while the ledger holds any row: a schema rollback does not destroy
the record of what left the building. On an empty table it revokes the
role's grants and drops the triggers, functions, sequence and table.
"""
from alembic import op

revision = "0086"
down_revision = "0085"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"
EGRESS_ROLE = "noctornal_egress"

#: Read by test_app_role_privileges_pg.py: the runtime role reads the
#: ledger and writes nothing to it.
GUARDED_TABLES = {
    "collect.egress_connection": ("SELECT",),
}

#: egress_ledger.EGRESS_GRANTS, verbatim (test_egress_connection_ledger_pg
#: holds the two equal).
EGRESS_GRANTS = (
    ("schema", "collect", "USAGE", None),
    ("table", "collect.egress_profile", "SELECT", None),
    ("table", "collect.egress_profile", "UPDATE", ("exit_sealed", "exit_seal_key_id")),
    ("table", "collect.egress_integration_route", "SELECT", None),
    ("table", "collect.egress_destination", "SELECT", None),
    ("table", "collect.egress_binding", "SELECT", None),
    ("table", "collect.collection_run", "SELECT",
     ("id", "status", "source_id", "collection_account_id", "egress_profile_id",
      "authority_id", "authority_target_id", "started_at")),
    ("table", "collect.source", "SELECT",
     ("id", "kind", "parser_key", "base_url", "classification", "is_active",
      "collection_account_id", "egress_profile_id")),
    ("table", "collect.collection_account", "SELECT",
     ("id", "status", "cooldown_until", "machine_hold_until",
      "machine_lock_code", "egress_profile_id", "source_id")),
    ("table", "collect.collection_authority", "SELECT",
     ("id", "collection_account_id", "recorded_at", "confirmed_at",
      "revoked_at", "valid_from", "valid_until")),
    ("table", "collect.collection_authority_target", "SELECT",
     ("id", "authority_id", "source_id", "added_at", "confirmed_at",
      "revoked_at", "target_base_url")),
    ("table", "collect.egress_connection", "SELECT",
     ("seq", "row_hash", "event", "occurred_at", "context_kind",
      "collection_account_id")),
    ("table", "collect.egress_connection", "INSERT", None),
    ("sequence", "collect.egress_connection_seq", "USAGE", None),
)

#: The chain trigger's row hash; egress_ledger.ROW_HASH_SQL with r = NEW.
ROW_HASH_SQL = """public.digest(convert_to(concat_ws(chr(31),
  coalesce(encode({prev},'hex'),'GENESIS'),
  {r}.seq::text,
  to_char({r}.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  {r}.event,
  coalesce({r}.connection_id::text,'-'),
  coalesce({r}.protocol,'-'),
  coalesce({r}.route_kind,'-'),
  {r}.route_id,
  coalesce({r}.peer_address::text,'-'),
  coalesce({r}.egress_profile_id::text,'-'),
  coalesce({r}.integration_route_id::text,'-'),
  coalesce({r}.collection_run_id::text,'-'),
  coalesce({r}.source_id::text,'-'),
  coalesce({r}.collection_account_id::text,'-'),
  coalesce({r}.authority_id::text,'-'),
  coalesce({r}.context_kind,'-'),
  coalesce({r}.context_id::text,'-'),
  coalesce({r}.dest_host,'-'),
  coalesce(encode({r}.dest_digest,'hex'),'-'),
  coalesce({r}.dest_port::text,'-'),
  coalesce({r}.resolved_address::text,'-'),
  coalesce({r}.exit_kind,'-'),
  {r}.reason,
  coalesce({r}.item_count::text,'-'),
  coalesce({r}.bytes_up::text,'-'),
  coalesce({r}.bytes_down::text,'-'),
  coalesce({r}.duration_ms::text,'-'),
  {r}.classification::text,
  {r}.source_compartmented::text
), 'UTF8'), 'sha256')"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _grant_block() -> str:
    """One guarded GRANT per entry: skipped where the role, the object or
    a column does not exist."""
    lines = []
    for kind, obj, privilege, columns in EGRESS_GRANTS:
        if kind == "schema":
            lines.append(
                f"  EXECUTE format('GRANT {privilege} ON SCHEMA {obj} TO %I', r);")
            continue
        schema, _, table = obj.partition(".")
        target = "SEQUENCE " if kind == "sequence" else ""
        if columns is None:
            lines.append(
                f"  IF to_regclass('{obj}') IS NOT NULL THEN\n"
                f"    EXECUTE format('GRANT {privilege} ON {target}{obj} TO %I', r);\n"
                f"  END IF;")
            continue
        for column in columns:
            lines.append(
                f"  IF EXISTS (SELECT 1 FROM information_schema.columns\n"
                f"              WHERE table_schema = '{schema}' AND table_name = '{table}'\n"
                f"                AND column_name = '{column}') THEN\n"
                f"    EXECUTE format('GRANT {privilege} ({column}) ON {obj} TO %I', r);\n"
                f"  END IF;")
    body = "\n".join(lines)
    return f"""
DO $grants$
DECLARE r text := '{EGRESS_ROLE}';
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    RETURN;
  END IF;
{body}
END
$grants$;
"""


def upgrade() -> None:
    run(f"""
CREATE SEQUENCE collect.egress_connection_seq;

CREATE TABLE collect.egress_connection (
  seq                   bigint PRIMARY KEY,
  occurred_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
  event                 text NOT NULL,
  connection_id         uuid,
  protocol              text,
  route_kind            text,
  route_id              text NOT NULL,
  peer_address          inet,
  egress_profile_id     uuid,
  integration_route_id  uuid,
  collection_run_id     uuid,
  source_id             uuid,
  collection_account_id uuid,
  authority_id          uuid,
  context_kind          text,
  context_id            uuid,
  dest_host             text,
  dest_digest           bytea,
  dest_port             integer,
  resolved_address      inet,
  exit_kind             text,
  reason                text NOT NULL,
  item_count            integer,
  bytes_up              bigint,
  bytes_down            bigint,
  duration_ms           integer,
  classification        core.tlp NOT NULL DEFAULT 'GREEN',
  source_compartmented  boolean NOT NULL DEFAULT false,
  prev_hash             bytea,
  row_hash              bytea NOT NULL,
  CONSTRAINT egress_connection_event_known
    CHECK (event IN ('OPEN', 'REFUSED', 'CLOSE', 'PREAUTH', 'REWRAP')),
  CONSTRAINT egress_connection_protocol_known
    CHECK (protocol IS NULL OR protocol IN ('HTTP_CONNECT', 'SOCKS5')),
  CONSTRAINT egress_connection_route_kind_known
    CHECK (route_kind IS NULL OR route_kind IN ('persona', 'integration')),
  CONSTRAINT egress_connection_context_known
    CHECK (context_kind IS NULL OR context_kind IN
           ('run', 'act', 'stop', 'delivery', 'lookup', 'detonation', 'embed',
            'wkd', 'check')),
  CONSTRAINT egress_connection_exit_known
    CHECK (exit_kind IS NULL OR exit_kind IN ('DIRECT', 'HTTP', 'HTTPS', 'SOCKS5')),
  CONSTRAINT egress_connection_dest_shape
    CHECK ((dest_host IS NULL OR length(dest_host) BETWEEN 1 AND 253)
           AND (dest_port IS NULL OR dest_port BETWEEN 1 AND 65535)),
  CONSTRAINT egress_connection_profile_is_persona
    CHECK (egress_profile_id IS NULL OR route_kind = 'persona'),
  CONSTRAINT egress_connection_route_is_integration
    CHECK (integration_route_id IS NULL OR route_kind = 'integration'),
  CONSTRAINT egress_connection_open_shape
    CHECK (event <> 'OPEN' OR (connection_id IS NOT NULL AND protocol IS NOT NULL
           AND route_kind IS NOT NULL AND dest_host IS NOT NULL
           AND dest_port IS NOT NULL AND exit_kind IS NOT NULL
           AND reason = 'allowed' AND bytes_up IS NULL AND bytes_down IS NULL
           AND duration_ms IS NULL AND item_count IS NULL)),
  CONSTRAINT egress_connection_refused_shape
    CHECK (event <> 'REFUSED' OR (connection_id IS NOT NULL AND protocol IS NOT NULL
           AND route_kind IS NOT NULL AND reason <> 'allowed'
           AND bytes_up IS NULL AND bytes_down IS NULL AND duration_ms IS NULL
           AND item_count IS NULL)),
  CONSTRAINT egress_connection_close_shape
    CHECK (event <> 'CLOSE' OR (connection_id IS NOT NULL AND duration_ms >= 0
           AND bytes_up >= 0 AND bytes_down >= 0 AND dest_host IS NULL
           AND dest_digest IS NULL AND dest_port IS NULL
           AND resolved_address IS NULL AND item_count IS NULL
           AND reason IN ('client_closed', 'upstream_closed', 'idle_timeout',
                          'session_limit', 'proxy_shutdown', 'error',
                          'authority_revoked', 'run_finished', 'route_withdrawn',
                          'persona_withdrawn'))),
  CONSTRAINT egress_connection_preauth_shape
    CHECK (event <> 'PREAUTH' OR (peer_address IS NOT NULL AND item_count > 0
           AND route_id = 'proxy' AND reason = 'preauth_refused'
           AND connection_id IS NULL AND route_kind IS NULL
           AND context_kind IS NULL AND context_id IS NULL
           AND dest_host IS NULL AND dest_digest IS NULL AND dest_port IS NULL)),
  CONSTRAINT egress_connection_rewrap_shape
    CHECK (event <> 'REWRAP' OR (item_count >= 0 AND route_id = 'proxy'
           AND reason = 'exits_rewrapped' AND route_kind IS NULL
           AND dest_host IS NULL AND dest_port IS NULL)),
  CONSTRAINT egress_connection_peer_only_preauth
    CHECK (peer_address IS NULL OR event = 'PREAUTH')
);

CREATE INDEX egress_connection_connection_idx ON collect.egress_connection (connection_id);
CREATE INDEX egress_connection_time_idx ON collect.egress_connection (occurred_at DESC);
CREATE INDEX egress_connection_profile_idx
  ON collect.egress_connection (egress_profile_id, occurred_at DESC);
CREATE INDEX egress_connection_route_idx
  ON collect.egress_connection (integration_route_id, occurred_at DESC);
CREATE INDEX egress_connection_run_idx ON collect.egress_connection (collection_run_id);
CREATE INDEX egress_connection_refused_idx
  ON collect.egress_connection (occurred_at DESC) WHERE event = 'REFUSED';
CREATE INDEX egress_connection_stop_idx
  ON collect.egress_connection (collection_account_id, occurred_at DESC)
  WHERE context_kind = 'stop';
CREATE INDEX egress_connection_preauth_idx
  ON collect.egress_connection (peer_address, occurred_at DESC) WHERE event = 'PREAUTH';

COMMENT ON TABLE collect.egress_connection IS
  'What left this deployment: one row per egress proxy event (OPEN before any dial, REFUSED, CLOSE, PREAUTH, REWRAP). Append-only and hash-chained; written by noctornal_egress.';

CREATE FUNCTION collect.egress_connection_block() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'collect.egress_connection is append-only: it is the record of what left this deployment';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER egress_connection_append_only
  BEFORE UPDATE OR DELETE ON collect.egress_connection
  FOR EACH ROW EXECUTE FUNCTION collect.egress_connection_block();
CREATE TRIGGER egress_connection_no_truncate
  BEFORE TRUNCATE ON collect.egress_connection
  FOR EACH STATEMENT EXECUTE FUNCTION collect.egress_connection_block();

-- The lock FIRST, then the sequence: seq order is chain order, and two
-- writers can never read the same tail.
CREATE FUNCTION collect.egress_connection_chain() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('collect.egress_connection.chain', 0));
  NEW.seq := nextval('collect.egress_connection_seq');
  SELECT row_hash INTO prev FROM collect.egress_connection ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := {ROW_HASH_SQL.format(r="NEW", prev="prev")};
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = public, pg_catalog;

CREATE TRIGGER egress_connection_chain
  BEFORE INSERT ON collect.egress_connection
  FOR EACH ROW EXECUTE FUNCTION collect.egress_connection_chain();
""")

    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON collect.egress_connection FROM %I',
                   '{APP_ROLE}');
    EXECUTE format('REVOKE USAGE, UPDATE ON SEQUENCE collect.egress_connection_seq FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")
    run(_grant_block())


def downgrade() -> None:
    run(f"""
DO $pre$
BEGIN
  IF to_regclass('collect.egress_connection') IS NOT NULL
     AND EXISTS (SELECT 1 FROM collect.egress_connection) THEN
    RAISE EXCEPTION 'refusing to downgrade 0086: collect.egress_connection holds %, the record of what left this deployment',
      (SELECT CASE count(*) WHEN 1 THEN 'one row' ELSE count(*) || ' rows' END
         FROM collect.egress_connection);
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{EGRESS_ROLE}') THEN
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA collect FROM %I', '{EGRESS_ROLE}');
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA collect FROM %I', '{EGRESS_ROLE}');
    EXECUTE format('REVOKE ALL ON SCHEMA collect FROM %I', '{EGRESS_ROLE}');
  END IF;
END $pre$;

DROP TABLE IF EXISTS collect.egress_connection;
DROP FUNCTION IF EXISTS collect.egress_connection_chain();
DROP FUNCTION IF EXISTS collect.egress_connection_block();
DROP SEQUENCE IF EXISTS collect.egress_connection_seq;
""")
