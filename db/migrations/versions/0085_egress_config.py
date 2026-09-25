"""Egress configuration: profile policy and sealed exits, integration routes
and their exact destinations, the binding history, and two permissions
(S2, the egress proxy, 2026-09-24; docs/00 decisions 68 and 77).

## What this adds

1. **Policy and exit columns on `collect.egress_profile`.** An exit kind
   (DIRECT, HTTP, HTTPS or SOCKS5; NULL is no exit yet), the sealed exit
   (`exit_sealed`, opened only by the egress proxy's private key,
   `security/egress_seal.py`), its key id and keyed fingerprint, a TLP
   ceiling (default AMBER, the default collect.source carries, so an
   AMBER_STRICT or RED source needs a deliberate raise), the destination
   policy (ports, any public host, host suffixes, public networks, onion),
   `resolve_at_proxy` (off: names go to a chained exit unresolved, so a
   persona's forums never reach this platform's resolver), the cleartext
   acknowledgement, per-profile limits, the passive default, and
   `reach_changed_at`. `persona_capable` is GENERATED from the rest, so the
   column the persona forms filter on cannot drift.

2. **`reach_changed_at`, written by the database alone.** The trigger
   below sets it to the clock on every update that WIDENS where the
   profile can reach (a new exit or fingerprint, another kind, a higher
   ceiling, a port, suffix or network not in the old set, any public host
   or onion turned on, the profile switched back on) and keeps the old
   value on every other update, whatever the writer sent: a '-infinity'
   written by a buggy or injected update would otherwise have revalidated
   every stale authority. The egress proxy refuses a persona connection
   whose collection authority was recorded or confirmed before it, so
   widening a profile needs a new two-person authority. Retirement is
   terminal here too (a CHECK cannot compare OLD).

3. **Integration routes and their exact destinations.**
   `collect.egress_integration_route` (one live row per name, a name from
   egress.INTEGRATIONS or a family such as lookup-<key>) and
   `collect.egress_destination` (one egress_policy rule per row:
   NAME:PORTS, NAME@CIDR:PORTS or CIDR:PORTS, validated by
   egress_policy.validate_rule in the service; no wildcard and no suffix,
   decision 68's explicit destination allowlist of host:port entries, with a CHECK
   against '*' as a backstop). A route name is unique among LIVE rows only,
   so retiring jira does not kill the integration for ever, and retirement
   of a route or an entry is terminal.

4. **`collect.egress_binding`**, the append-only history of which egress
   profile each persona and each persona-less source was bound to and
   when. The proxy compares authorities with it: an authority recorded
   before a persona (or a persona-less source) was re-pointed at another
   profile no longer passes. It is written ONLY by a recording trigger on
   collect.collection_account and collect.source (SECURITY DEFINER, so the
   application role keeps SELECT only), so whatever code re-points a
   persona, the database records the time; a recording trigger never
   refuses, so no other feature's write can fail on it. The source half
   needs collect.source.egress_profile_id, which the collection framework
   adds: where it is missing the source
   trigger is not created, and SOURCE_BINDING_SQL below is what a later
   run applies.

5. **The retired 0010 column.** `endpoint_ciphertext` was sealed under the
   platform ring and nothing ever wrote it. It is retired by a CHECK
   rather than dropped, so security/sealed.py, the key-loss wording and
   the installers stay true without an edit; exits live in `exit_sealed`
   under the egress seal key.

6. **Permissions.** `egress.manage` (step-up, SYS_ADMIN): create, change
   and retire profiles and routes, and seal exits. `egress.log.read`
   (SYS_ADMIN and SECURITY_OFFICER): read the connection log within one's
   clearance. integration.manage is untouched: it configures what an
   integration sends, egress.manage where anything may go.

Existing profiles are backfilled with reach_changed_at '-infinity', so
authorities confirmed before this migration stay valid, and existing
bindings with bound_at '-infinity' for the same reason.

## Downgrade

Refuses while any profile carries an exit, any integration route or
destination exists, or collect.egress_binding holds a row: operator
configuration and the binding history that voids stale authorities are
not schema artefacts to drop. Otherwise it removes everything above.
"""
from alembic import op

revision = "0085"
down_revision = "0084"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060 spells it.
APP_ROLE = "noctornal_app"

#: Read by test_app_role_privileges_pg.py beside 0060's LEDGERS: the
#: binding history is append-only, and the runtime role keeps SELECT.
GUARDED_TABLES = {
    "collect.egress_binding": ("SELECT",),
}

#: The source half of the binding history, applied where
#: collect.source.egress_profile_id exists (the collection framework's
#: column). Module constant so a later run, or a test standing the
#: collection framework's columns in, applies exactly this text.
SOURCE_BINDING_SQL = """
CREATE TRIGGER source_egress_bound
  AFTER INSERT ON collect.source
  FOR EACH ROW WHEN (NEW.egress_profile_id IS NOT NULL)
  EXECUTE FUNCTION collect.record_egress_binding();
CREATE TRIGGER source_egress_rebound
  AFTER UPDATE OF egress_profile_id ON collect.source
  FOR EACH ROW WHEN (OLD.egress_profile_id IS DISTINCT FROM NEW.egress_profile_id)
  EXECUTE FUNCTION collect.record_egress_binding();
INSERT INTO collect.egress_binding (source_id, egress_profile_id, bound_at)
  SELECT id, egress_profile_id, '-infinity' FROM collect.source
   WHERE egress_profile_id IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM collect.egress_binding b WHERE b.source_id = source.id);
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
DO $pre$
BEGIN
  IF EXISTS (SELECT 1 FROM collect.egress_profile WHERE endpoint_ciphertext IS NOT NULL) THEN
    RAISE EXCEPTION 'refusing 0085: endpoint_ciphertext is set on %, which this revision retires; nothing in this product wrote it, so clear it deliberately first',
      (SELECT CASE count(*) WHEN 1 THEN 'one egress profile'
                  ELSE count(*) || ' egress profiles' END
         FROM collect.egress_profile WHERE endpoint_ciphertext IS NOT NULL);
  END IF;
END $pre$;

ALTER TABLE collect.egress_profile
  ADD COLUMN exit_kind text,
  ADD COLUMN exit_sealed bytea,
  ADD COLUMN exit_seal_key_id text,
  ADD COLUMN exit_fingerprint bytea,
  ADD COLUMN exit_sealed_at timestamptz,
  ADD COLUMN exit_sealed_by uuid REFERENCES iam.app_user(id),
  ADD COLUMN ceiling core.tlp NOT NULL DEFAULT 'AMBER',
  ADD COLUMN allowed_ports integer[] NOT NULL DEFAULT '{443}',
  ADD COLUMN any_public_host boolean NOT NULL DEFAULT false,
  ADD COLUMN allowed_host_suffixes text[] NOT NULL DEFAULT '{}',
  ADD COLUMN allowed_cidrs cidr[] NOT NULL DEFAULT '{}',
  ADD COLUMN allow_onion boolean NOT NULL DEFAULT false,
  ADD COLUMN resolve_at_proxy boolean NOT NULL DEFAULT false,
  ADD COLUMN cleartext_upstream_ack boolean NOT NULL DEFAULT false,
  ADD COLUMN idle_timeout_s integer NOT NULL DEFAULT 120,
  ADD COLUMN max_session_s integer NOT NULL DEFAULT 900,
  ADD COLUMN max_concurrent integer NOT NULL DEFAULT 4,
  ADD COLUMN is_passive_default boolean NOT NULL DEFAULT false,
  -- '-infinity' for the rows that exist now, so authorities confirmed
  -- before this revision stay valid; new rows take the clock below.
  ADD COLUMN reach_changed_at timestamptz NOT NULL DEFAULT '-infinity',
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN created_by uuid REFERENCES iam.app_user(id),
  ADD COLUMN updated_at timestamptz,
  ADD COLUMN updated_by uuid REFERENCES iam.app_user(id),
  ADD COLUMN retired_at timestamptz,
  ADD COLUMN retired_by uuid REFERENCES iam.app_user(id),
  ADD COLUMN retire_reason text;

ALTER TABLE collect.egress_profile
  ALTER COLUMN reach_changed_at SET DEFAULT clock_timestamp();

ALTER TABLE collect.egress_profile
  ADD COLUMN persona_capable boolean GENERATED ALWAYS AS (
    is_active AND retired_at IS NULL AND NOT is_passive_default
    AND coalesce(exit_kind IN ('HTTP', 'HTTPS', 'SOCKS5'), false)) STORED;

ALTER TABLE collect.egress_profile
  ADD CONSTRAINT egress_profile_exit_kind_known
    CHECK (exit_kind IS NULL OR exit_kind IN ('DIRECT', 'HTTP', 'HTTPS', 'SOCKS5')),
  ADD CONSTRAINT egress_profile_exit_shape
    CHECK ((coalesce(exit_kind, '') IN ('HTTP', 'HTTPS', 'SOCKS5'))
           = (exit_sealed IS NOT NULL AND exit_seal_key_id IS NOT NULL
              AND exit_fingerprint IS NOT NULL)),
  ADD CONSTRAINT egress_profile_direct_is_datacentre
    CHECK (exit_kind IS DISTINCT FROM 'DIRECT' OR kind = 'DATACENTRE'),
  ADD CONSTRAINT egress_profile_tor_shape
    CHECK (kind <> 'TOR' OR (coalesce(exit_kind, 'SOCKS5') = 'SOCKS5'
                             AND NOT resolve_at_proxy)),
  ADD CONSTRAINT egress_profile_onion_only_tor
    CHECK (NOT allow_onion OR kind = 'TOR'),
  ADD CONSTRAINT egress_profile_ports
    CHECK (cardinality(allowed_ports) BETWEEN 1 AND 16
           AND array_position(allowed_ports, NULL) IS NULL
           AND 0 < ALL (allowed_ports) AND 65536 > ALL (allowed_ports)),
  ADD CONSTRAINT egress_profile_rule_counts
    CHECK (cardinality(allowed_host_suffixes) <= 64 AND cardinality(allowed_cidrs) <= 64
           AND array_position(allowed_host_suffixes, NULL) IS NULL
           AND array_position(allowed_cidrs, NULL) IS NULL),
  ADD CONSTRAINT egress_profile_limits
    CHECK (idle_timeout_s BETWEEN 5 AND 3600 AND max_session_s BETWEEN 10 AND 86400
           AND max_concurrent BETWEEN 1 AND 64),
  ADD CONSTRAINT egress_profile_retirement_complete
    CHECK (retired_at IS NULL OR (NOT is_active AND NOT is_passive_default
           AND retired_by IS NOT NULL AND length(btrim(coalesce(retire_reason, ''))) >= 5)),
  ADD CONSTRAINT egress_profile_passive_default_active
    CHECK (NOT is_passive_default OR is_active),
  ADD CONSTRAINT egress_profile_endpoint_ciphertext_retired
    CHECK (endpoint_ciphertext IS NULL);

COMMENT ON COLUMN collect.egress_profile.endpoint_ciphertext IS
  'Retired by 0085 and always NULL: superseded by exit_sealed, sealed for the egress proxy under its own key.';
COMMENT ON COLUMN collect.egress_profile.exit_sealed IS
  'The exit endpoint, HPKE-sealed to the egress proxy''s key (security/egress_seal.py): the API seals and cannot open it.';
COMMENT ON COLUMN collect.egress_profile.reach_changed_at IS
  'When this profile last reached further than before. Set by collect.egress_profile_reach() alone.';

CREATE UNIQUE INDEX egress_profile_one_passive_default
  ON collect.egress_profile ((true)) WHERE is_passive_default;

CREATE FUNCTION collect.egress_profile_reach() RETURNS trigger AS $$
BEGIN
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'a retired egress profile stays retired';
  END IF;
  NEW.updated_at := clock_timestamp();
  IF NEW.exit_kind IS DISTINCT FROM OLD.exit_kind
     OR NEW.exit_fingerprint IS DISTINCT FROM OLD.exit_fingerprint
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.ceiling > OLD.ceiling
     OR NOT (NEW.allowed_ports <@ OLD.allowed_ports)
     OR (NEW.any_public_host AND NOT OLD.any_public_host)
     OR NOT (NEW.allowed_host_suffixes <@ OLD.allowed_host_suffixes)
     OR NOT (NEW.allowed_cidrs <@ OLD.allowed_cidrs)
     OR (NEW.allow_onion AND NOT OLD.allow_onion)
     OR (NEW.is_active AND NOT OLD.is_active) THEN
    NEW.reach_changed_at := clock_timestamp();
  ELSE
    NEW.reach_changed_at := OLD.reach_changed_at;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER egress_profile_reach
  BEFORE UPDATE ON collect.egress_profile
  FOR EACH ROW EXECUTE FUNCTION collect.egress_profile_reach();

CREATE TABLE collect.egress_integration_route (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name            text NOT NULL,
  description     text NOT NULL,
  is_active       boolean NOT NULL DEFAULT true,
  idle_timeout_s  integer NOT NULL DEFAULT 60,
  max_session_s   integer NOT NULL DEFAULT 300,
  max_concurrent  integer NOT NULL DEFAULT 8,
  created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_by      uuid REFERENCES iam.app_user(id),
  updated_at      timestamptz,
  updated_by      uuid REFERENCES iam.app_user(id),
  retired_at      timestamptz,
  retired_by      uuid REFERENCES iam.app_user(id),
  retire_reason   text,
  -- egress_policy.INTEGRATION_NAME, the pattern the wire grammar uses.
  CONSTRAINT egress_integration_route_name
    CHECK (name ~ '^[a-z][a-z0-9-]{1,39}$'),
  CONSTRAINT egress_integration_route_described
    CHECK (length(btrim(description)) BETWEEN 5 AND 500),
  CONSTRAINT egress_integration_route_limits
    CHECK (idle_timeout_s BETWEEN 5 AND 3600 AND max_session_s BETWEEN 10 AND 86400
           AND max_concurrent BETWEEN 1 AND 64),
  CONSTRAINT egress_integration_route_retirement_complete
    CHECK (retired_at IS NULL OR (NOT is_active AND retired_by IS NOT NULL
           AND length(btrim(coalesce(retire_reason, ''))) >= 5))
);
CREATE UNIQUE INDEX egress_integration_route_live_name
  ON collect.egress_integration_route (name) WHERE retired_at IS NULL;

CREATE TABLE collect.egress_destination (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id    uuid NOT NULL REFERENCES collect.egress_integration_route(id),
  entry       text NOT NULL,
  note        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_by  uuid REFERENCES iam.app_user(id),
  retired_at  timestamptz,
  retired_by  uuid REFERENCES iam.app_user(id),
  CONSTRAINT egress_destination_no_wildcard
    CHECK (position('*' in entry) = 0 AND length(entry) BETWEEN 3 AND 300),
  CONSTRAINT egress_destination_noted
    CHECK (length(btrim(note)) BETWEEN 5 AND 500),
  CONSTRAINT egress_destination_retirement_complete
    CHECK ((retired_at IS NULL) = (retired_by IS NULL))
);
CREATE UNIQUE INDEX egress_destination_live_entry
  ON collect.egress_destination (route_id, entry) WHERE retired_at IS NULL;

CREATE FUNCTION collect.egress_route_terminal() RETURNS trigger AS $$
BEGIN
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'a retired egress route or destination stays retired';
  END IF;
  IF TG_TABLE_NAME = 'egress_integration_route' THEN
    IF NEW.name IS DISTINCT FROM OLD.name THEN
      RAISE EXCEPTION 'an egress route keeps its name: retire it and create another';
    END IF;
    NEW.updated_at := clock_timestamp();
  ELSIF NEW.entry IS DISTINCT FROM OLD.entry OR NEW.route_id IS DISTINCT FROM OLD.route_id THEN
    RAISE EXCEPTION 'an egress destination keeps its entry: retire it and add another';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER egress_integration_route_terminal
  BEFORE UPDATE ON collect.egress_integration_route
  FOR EACH ROW EXECUTE FUNCTION collect.egress_route_terminal();
CREATE TRIGGER egress_destination_terminal
  BEFORE UPDATE ON collect.egress_destination
  FOR EACH ROW EXECUTE FUNCTION collect.egress_route_terminal();

CREATE TABLE collect.egress_binding (
  seq                   bigserial PRIMARY KEY,
  collection_account_id uuid,
  source_id             uuid,
  egress_profile_id     uuid,
  bound_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT egress_binding_one_subject
    CHECK ((collection_account_id IS NULL) <> (source_id IS NULL))
);
CREATE INDEX egress_binding_persona_idx
  ON collect.egress_binding (collection_account_id, bound_at DESC)
  WHERE collection_account_id IS NOT NULL;
CREATE INDEX egress_binding_source_idx
  ON collect.egress_binding (source_id, bound_at DESC) WHERE source_id IS NOT NULL;
COMMENT ON TABLE collect.egress_binding IS
  'When each persona and each persona-less source was bound to an egress profile. Append-only, written only by collect.record_egress_binding(); the egress proxy refuses authorities that predate the latest row.';

CREATE FUNCTION collect.egress_binding_block() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'collect.egress_binding is append-only: it is the history the egress proxy compares collection authorities with';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER egress_binding_append_only
  BEFORE UPDATE OR DELETE ON collect.egress_binding
  FOR EACH ROW EXECUTE FUNCTION collect.egress_binding_block();
CREATE TRIGGER egress_binding_no_truncate
  BEFORE TRUNCATE ON collect.egress_binding
  FOR EACH STATEMENT EXECUTE FUNCTION collect.egress_binding_block();

-- SECURITY DEFINER with a pinned path: the application role writes the
-- persona and the source and must not be able to write this history
-- itself (it keeps SELECT only, below).
CREATE FUNCTION collect.record_egress_binding() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_TABLE_NAME = 'collection_account' THEN
    INSERT INTO collect.egress_binding (collection_account_id, egress_profile_id)
    VALUES (NEW.id, NEW.egress_profile_id);
  ELSE
    INSERT INTO collect.egress_binding (source_id, egress_profile_id)
    VALUES (NEW.id, NEW.egress_profile_id);
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER collection_account_egress_bound
  AFTER INSERT ON collect.collection_account
  FOR EACH ROW WHEN (NEW.egress_profile_id IS NOT NULL)
  EXECUTE FUNCTION collect.record_egress_binding();
CREATE TRIGGER collection_account_egress_rebound
  AFTER UPDATE OF egress_profile_id ON collect.collection_account
  FOR EACH ROW WHEN (OLD.egress_profile_id IS DISTINCT FROM NEW.egress_profile_id)
  EXECUTE FUNCTION collect.record_egress_binding();

INSERT INTO collect.egress_binding (collection_account_id, egress_profile_id, bound_at)
  SELECT id, egress_profile_id, '-infinity' FROM collect.collection_account
   WHERE egress_profile_id IS NOT NULL;
""")

    # The source half, where the collection framework's column exists.
    conn = op.get_bind().connection.driver_connection
    has_source_binding = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'egress_profile_id')""").fetchone()[0]
    if has_source_binding:
        run(SOURCE_BINDING_SQL)

    # After the CREATE TABLEs, never before: 0060's default privileges
    # handed the runtime role INSERT, UPDATE and DELETE the moment the
    # table was created. A no-op where the role does not exist.
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON collect.egress_binding FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")

    run("""
SET search_path = iam, core, public;

INSERT INTO permission (key, description, requires_step_up) VALUES
  ('egress.manage',
   'Create, change and retire egress profiles and integration routes, and seal exits',
   true),
  ('egress.log.read',
   'Read the egress connection log, within your clearance', false)
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
  ('SYS_ADMIN', 'egress.manage'),
  ('SYS_ADMIN', 'egress.log.read'),
  ('SECURITY_OFFICER', 'egress.log.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    run("""
DO $pre$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'collect' AND table_name = 'egress_profile'
                AND column_name = 'exit_kind') THEN
    IF EXISTS (SELECT 1 FROM collect.egress_profile WHERE exit_kind IS NOT NULL) THEN
      RAISE EXCEPTION 'refusing to downgrade 0085: an exit is set on %, which is operator configuration rather than a schema artefact',
        (SELECT CASE count(*) WHEN 1 THEN 'one egress profile'
                    ELSE count(*) || ' egress profiles' END
           FROM collect.egress_profile WHERE exit_kind IS NOT NULL);
    END IF;
  END IF;
  IF to_regclass('collect.egress_integration_route') IS NOT NULL
     AND EXISTS (SELECT 1 FROM collect.egress_integration_route) THEN
    RAISE EXCEPTION 'refusing to downgrade 0085: collect.egress_integration_route holds %, which is operator configuration rather than a schema artefact',
      (SELECT CASE count(*) WHEN 1 THEN 'one route' ELSE count(*) || ' routes' END
         FROM collect.egress_integration_route);
  END IF;
  IF to_regclass('collect.egress_binding') IS NOT NULL
     AND EXISTS (SELECT 1 FROM collect.egress_binding) THEN
    RAISE EXCEPTION 'refusing to downgrade 0085: collect.egress_binding holds %, the history that voids collection authorities recorded before a re-binding',
      (SELECT CASE count(*) WHEN 1 THEN 'one row' ELSE count(*) || ' rows' END
         FROM collect.egress_binding);
  END IF;
END $pre$;

DELETE FROM iam.role_permission WHERE permission_key IN ('egress.manage', 'egress.log.read');
DELETE FROM iam.permission WHERE key IN ('egress.manage', 'egress.log.read');

DROP TRIGGER IF EXISTS source_egress_bound ON collect.source;
DROP TRIGGER IF EXISTS source_egress_rebound ON collect.source;
DROP TRIGGER IF EXISTS collection_account_egress_bound ON collect.collection_account;
DROP TRIGGER IF EXISTS collection_account_egress_rebound ON collect.collection_account;
DROP FUNCTION IF EXISTS collect.record_egress_binding();
DROP TABLE IF EXISTS collect.egress_binding;
DROP FUNCTION IF EXISTS collect.egress_binding_block();

DROP TABLE IF EXISTS collect.egress_destination;
DROP TABLE IF EXISTS collect.egress_integration_route;
DROP FUNCTION IF EXISTS collect.egress_route_terminal();

DROP TRIGGER IF EXISTS egress_profile_reach ON collect.egress_profile;
DROP FUNCTION IF EXISTS collect.egress_profile_reach();
DROP INDEX IF EXISTS collect.egress_profile_one_passive_default;
COMMENT ON COLUMN collect.egress_profile.endpoint_ciphertext IS NULL;

ALTER TABLE collect.egress_profile
  DROP CONSTRAINT IF EXISTS egress_profile_endpoint_ciphertext_retired,
  DROP CONSTRAINT IF EXISTS egress_profile_passive_default_active,
  DROP CONSTRAINT IF EXISTS egress_profile_retirement_complete,
  DROP CONSTRAINT IF EXISTS egress_profile_limits,
  DROP CONSTRAINT IF EXISTS egress_profile_rule_counts,
  DROP CONSTRAINT IF EXISTS egress_profile_ports,
  DROP CONSTRAINT IF EXISTS egress_profile_onion_only_tor,
  DROP CONSTRAINT IF EXISTS egress_profile_tor_shape,
  DROP CONSTRAINT IF EXISTS egress_profile_direct_is_datacentre,
  DROP CONSTRAINT IF EXISTS egress_profile_exit_shape,
  DROP CONSTRAINT IF EXISTS egress_profile_exit_kind_known,
  DROP COLUMN IF EXISTS persona_capable,
  DROP COLUMN IF EXISTS retire_reason,
  DROP COLUMN IF EXISTS retired_by,
  DROP COLUMN IF EXISTS retired_at,
  DROP COLUMN IF EXISTS updated_by,
  DROP COLUMN IF EXISTS updated_at,
  DROP COLUMN IF EXISTS created_by,
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS reach_changed_at,
  DROP COLUMN IF EXISTS is_passive_default,
  DROP COLUMN IF EXISTS max_concurrent,
  DROP COLUMN IF EXISTS max_session_s,
  DROP COLUMN IF EXISTS idle_timeout_s,
  DROP COLUMN IF EXISTS cleartext_upstream_ack,
  DROP COLUMN IF EXISTS resolve_at_proxy,
  DROP COLUMN IF EXISTS allow_onion,
  DROP COLUMN IF EXISTS allowed_cidrs,
  DROP COLUMN IF EXISTS allowed_host_suffixes,
  DROP COLUMN IF EXISTS any_public_host,
  DROP COLUMN IF EXISTS allowed_ports,
  DROP COLUMN IF EXISTS ceiling,
  DROP COLUMN IF EXISTS exit_sealed_by,
  DROP COLUMN IF EXISTS exit_sealed_at,
  DROP COLUMN IF EXISTS exit_fingerprint,
  DROP COLUMN IF EXISTS exit_seal_key_id,
  DROP COLUMN IF EXISTS exit_sealed,
  DROP COLUMN IF EXISTS exit_kind;
""")
