"""The outbound lookup provider registry (F15.2, 2026-09-24).

## What this adds

- `ingest.provider`: a service this deployment may send selectors to. Its
  key is envelope-sealed (security/sealed.py lists it) and bound to the
  origin it was entered for: changing the base URL's host or port, or the
  egress route, clears it. Each provider is anchored to an inactive
  collect.source of kind VENDOR_API, which claims cite and nothing polls.
- `ingest.provider_exposure_change`: lowering a provider's exposure (from
  PUBLIC to VENDOR, or to NONE) takes a second administrator.
- `ingest.exposure_rank(text)`: NONE 0, VENDOR 1, PUBLIC 2.

## What the database holds, not only the endpoint

- Only NONE may carry an AMBER ceiling; a VENDOR provider takes CLEAR or
  GREEN, a PUBLIC one CLEAR alone. docs/08
  defines GREEN as "community, not public" and AMBER as "organisation and
  clients": a second person's sign-off does not make a GREEN selector
  publishable, because the label restricts the audience, not the
  approver.
- Every provider is created as PUBLIC unless a second administrator
  approves a lower determination: a BEFORE INSERT trigger sets
  needs_exposure_approval for any level below PUBLIC (keying the rule on
  the host's history let one administrator register the same service
  under another origin, lower).
- A lowering, or clearing needs_exposure_approval, is refused unless an
  APPROVED change for this provider to that level, FOR ITS CURRENT ORIGIN,
  was decided in the same transaction. A change records the origin it
  was asked for, so an approval of one host never clears the flag for
  another. A provider raised to PUBLIC drops the flag: PUBLIC waits for
  nobody.
- A new origin below PUBLIC is a new determination (2026-09-25): moving
  the base URL's host or port, or a NONE provider's
  private network, sets needs_exposure_approval and disables the row, so
  one administrator cannot repoint an approved VENDOR provider at a host
  no second administrator looked at.
- private_cidr is the network a NONE instance answers from (docs/20
  section 9, the lookups row): the provider's declared rule carries it,
  and only a NONE provider may have one.
- The private CA is for NONE providers only: use_private_ca is refused
  on VENDOR and PUBLIC.
- A provider is retired, never deleted; an exposure change is decided
  once and never rewritten. Both refuse DELETE and TRUNCATE by trigger,
  and the runtime role loses DELETE (GUARDED_TABLES).

## Downgrade

Refuses while ingest.lookup exists (0099 must go first). Otherwise marks
every anchor source inactive with a note (claims may cite them, so they
are kept), and drops both tables and the functions. That destroys sealed
keys, which are re-enterable, and the exposure determinations, which
audit.event keeps (PROVIDER_CREATED, PROVIDER_EXPOSURE_LOWERED).
"""
from alembic import op

revision = "0098"
down_revision = "0097"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

GUARDED_TABLES = {
    "ingest.provider": ("SELECT", "INSERT", "UPDATE"),
    "ingest.provider_exposure_change": ("SELECT", "INSERT", "UPDATE"),
}

OLD_DESCRIPTION = "Configure SMTP, Jira, webhooks"
NEW_DESCRIPTION = "Configure SMTP, Jira, webhooks and outbound lookup providers"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(r"""
CREATE FUNCTION ingest.exposure_rank(level text) RETURNS integer
  LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE level WHEN 'NONE' THEN 0 WHEN 'VENDOR' THEN 1 WHEN 'PUBLIC' THEN 2 END
$$;

CREATE TABLE ingest.provider (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key text NOT NULL UNIQUE CONSTRAINT provider_key_shape CHECK (key ~ '^[a-z][a-z0-9_]{1,32}$'),
  display_name text NOT NULL
    CONSTRAINT provider_name_present CHECK (length(btrim(display_name)) BETWEEN 3 AND 80),
  adapter text NOT NULL,
  adapter_version text NOT NULL,
  source_id uuid NOT NULL UNIQUE REFERENCES collect.source(id),
  base_url text NOT NULL
    CONSTRAINT provider_base_url_shape
    CHECK (base_url ~ '^https://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$'),
  origin_host text NOT NULL,
  origin_port integer NOT NULL CONSTRAINT provider_port_range CHECK (origin_port BETWEEN 1 AND 65535),
  -- A member of the lookup route family (egress.INTEGRATION_FAMILIES), so
  -- route_for can name it and the integration route table can hold it.
  egress_route text NOT NULL
    CONSTRAINT provider_route_shape CHECK (egress_route ~ '^lookup-[a-z0-9-]{1,33}$'),
  exposure_level text NOT NULL
    CONSTRAINT provider_exposure_known CHECK (exposure_level IN ('NONE', 'VENDOR', 'PUBLIC')),
  exposure_basis text NOT NULL
    CONSTRAINT provider_exposure_justified CHECK (length(btrim(exposure_basis)) > 20),
  exposure_determined_by uuid NOT NULL REFERENCES iam.app_user(id),
  exposure_determined_at timestamptz NOT NULL DEFAULT now(),
  needs_exposure_approval boolean NOT NULL DEFAULT false,
  classification_ceiling core.tlp NOT NULL DEFAULT 'GREEN'
    CONSTRAINT provider_ceiling_below_floor CHECK (classification_ceiling IN ('CLEAR', 'GREEN', 'AMBER')),
  result_floor core.tlp,
  use_private_ca boolean NOT NULL DEFAULT false,
  private_cidr cidr,
  cache_ttl interval NOT NULL DEFAULT '7 days'
    CONSTRAINT provider_cache_ttl_range CHECK (cache_ttl >= interval '0' AND cache_ttl <= interval '90 days'),
  quota_per_minute integer CONSTRAINT provider_quota_minute CHECK (quota_per_minute > 0),
  quota_per_hour integer CONSTRAINT provider_quota_hour CHECK (quota_per_hour > 0),
  quota_per_day integer CONSTRAINT provider_quota_day CHECK (quota_per_day > 0),
  quota_per_month integer CONSTRAINT provider_quota_month CHECK (quota_per_month > 0),
  queue_reserve_pct smallint NOT NULL DEFAULT 20
    CONSTRAINT provider_reserve_range CHECK (queue_reserve_pct BETWEEN 0 AND 90),
  max_response_bytes integer NOT NULL DEFAULT 2097152
    CONSTRAINT provider_response_cap CHECK (max_response_bytes BETWEEN 65536 AND 16777216),
  enabled boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'HEALTHY'
    CONSTRAINT provider_status_known CHECK (status IN ('HEALTHY', 'LOCKED')),
  locked_reason text,
  cooldown_until timestamptz,
  consecutive_429 smallint NOT NULL DEFAULT 0 CONSTRAINT provider_429_count CHECK (consecutive_429 >= 0),
  secret_ciphertext bytea,
  secret_key_id text,
  secret_origin text,
  secret_set_at timestamptz,
  secret_set_by uuid REFERENCES iam.app_user(id),
  rotate_by date,
  last_request_at timestamptz,
  created_by uuid NOT NULL REFERENCES iam.app_user(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  retired_by uuid REFERENCES iam.app_user(id),
  retired_reason text,
  CONSTRAINT provider_secret_complete CHECK (
    (secret_ciphertext IS NULL) = (secret_key_id IS NULL)
    AND (secret_ciphertext IS NULL) = (secret_origin IS NULL)
    AND (secret_ciphertext IS NULL) = (secret_set_at IS NULL)
    AND (secret_ciphertext IS NULL) = (rotate_by IS NULL)),
  CONSTRAINT provider_enabled_needs_secret CHECK (NOT enabled OR secret_ciphertext IS NOT NULL),
  CONSTRAINT provider_enabled_needs_quota CHECK (
    NOT enabled OR num_nonnulls(quota_per_minute, quota_per_hour, quota_per_day,
                                quota_per_month) >= 1),
  CONSTRAINT provider_enabled_needs_approval CHECK (NOT enabled OR NOT needs_exposure_approval),
  CONSTRAINT provider_locked_says_why CHECK ((status = 'LOCKED') = (locked_reason IS NOT NULL)),
  CONSTRAINT provider_retirement_complete CHECK (
    (retired_at IS NULL) = (retired_reason IS NULL)
    AND (retired_at IS NULL) = (retired_by IS NULL)),
  CONSTRAINT provider_retired_is_off CHECK (
    retired_at IS NULL OR (NOT enabled AND secret_ciphertext IS NULL)),
  CONSTRAINT provider_public_ceiling_clear CHECK (
    exposure_level <> 'PUBLIC' OR classification_ceiling = 'CLEAR'),
  CONSTRAINT provider_vendor_ceiling_green CHECK (
    exposure_level <> 'VENDOR' OR classification_ceiling IN ('CLEAR', 'GREEN')),
  CONSTRAINT provider_private_ca_is_none CHECK (NOT use_private_ca OR exposure_level = 'NONE'),
  CONSTRAINT provider_private_cidr_is_none CHECK (private_cidr IS NULL OR exposure_level = 'NONE')
);
CREATE INDEX provider_origin_idx ON ingest.provider (origin_host, origin_port);

CREATE TABLE ingest.provider_exposure_change (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid NOT NULL REFERENCES ingest.provider(id),
  from_level text NOT NULL CHECK (from_level IN ('NONE', 'VENDOR', 'PUBLIC')),
  to_level text NOT NULL CHECK (to_level IN ('NONE', 'VENDOR', 'PUBLIC')),
  -- The origin (https://host:port) and, for NONE, the private network the
  -- change was asked for: an approval binds to them, never to whatever the
  -- provider row names later (2026-09-25).
  origin text NOT NULL CONSTRAINT exposure_change_origin_shape CHECK (origin ~ '^https://.+:[0-9]{1,5}$'),
  private_cidr cidr,
  basis text NOT NULL CONSTRAINT exposure_change_justified CHECK (length(btrim(basis)) > 20),
  requested_by uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  decision text CHECK (decision IN ('APPROVED', 'DECLINED', 'WITHDRAWN', 'EXPIRED')),
  decided_by uuid REFERENCES iam.app_user(id),
  decided_at timestamptz,
  decision_note text,
  CONSTRAINT exposure_change_lowers
    CHECK (ingest.exposure_rank(to_level) < ingest.exposure_rank(from_level)),
  CONSTRAINT exposure_change_expires
    CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '72 hours'),
  CONSTRAINT exposure_change_two_admins CHECK (
    decision IS NULL OR decision NOT IN ('APPROVED', 'DECLINED')
    OR (decided_by IS NOT NULL AND decided_by <> requested_by)),
  CONSTRAINT exposure_change_withdrawn_by_requester
    CHECK (decision IS DISTINCT FROM 'WITHDRAWN' OR decided_by = requested_by),
  CONSTRAINT exposure_change_expiry_has_no_decider
    CHECK (decision IS DISTINCT FROM 'EXPIRED' OR decided_by IS NULL),
  CONSTRAINT exposure_change_decision_complete CHECK ((decision IS NULL) = (decided_at IS NULL)),
  CONSTRAINT exposure_change_approved_in_time
    CHECK (decision IS DISTINCT FROM 'APPROVED' OR decided_at <= expires_at)
);
CREATE UNIQUE INDEX exposure_change_one_open
  ON ingest.provider_exposure_change (provider_id) WHERE decision IS NULL;

-- Every determination below PUBLIC is a second administrator's act.
CREATE FUNCTION ingest.provider_starts_unapproved() RETURNS trigger AS $$
BEGIN
  IF ingest.exposure_rank(NEW.exposure_level) < 2 THEN
    NEW.needs_exposure_approval := true;
  END IF;
  NEW.enabled := false;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER provider_starts_unapproved
  BEFORE INSERT ON ingest.provider
  FOR EACH ROW EXECUTE FUNCTION ingest.provider_starts_unapproved();

CREATE FUNCTION ingest.guard_provider() RETURNS trigger AS $$
DECLARE
  approved boolean;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a lookup provider is retired, never deleted: claims cite its source and its exposure history is the record';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.key IS DISTINCT FROM OLD.key
     OR NEW.adapter IS DISTINCT FROM OLD.adapter
     OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'a lookup provider''s key, adapter, source and creation are fixed: create a new provider instead';
  END IF;
  IF OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retired lookup provider is final';
  END IF;
  -- A second administrator determined the exposure of ONE destination. A
  -- new host or port (read from base_url as well as the origin columns, so
  -- a write that forgets the columns is caught too), or a NONE provider's
  -- new private network, is a new determination below PUBLIC
  -- (2026-09-25).
  approved := EXISTS (
      SELECT 1 FROM ingest.provider_exposure_change ch
       WHERE ch.provider_id = NEW.id AND ch.decision = 'APPROVED'
         AND ch.to_level = NEW.exposure_level AND ch.decided_at = now()
         AND ch.origin = 'https://' || NEW.origin_host || ':' || NEW.origin_port
         AND ch.private_cidr IS NOT DISTINCT FROM NEW.private_cidr);
  IF ingest.exposure_rank(NEW.exposure_level) < 2 AND NOT approved AND (
       NEW.origin_host IS DISTINCT FROM OLD.origin_host
       OR NEW.origin_port IS DISTINCT FROM OLD.origin_port
       OR substring(NEW.base_url from '^https://([^/]+)')
          IS DISTINCT FROM substring(OLD.base_url from '^https://([^/]+)')
       OR (NEW.exposure_level = 'NONE'
           AND NEW.private_cidr IS DISTINCT FROM OLD.private_cidr)) THEN
    NEW.needs_exposure_approval := true;
    NEW.enabled := false;
  END IF;
  -- PUBLIC waits for nobody, so a provider raised to it may drop the flag.
  IF (ingest.exposure_rank(NEW.exposure_level) < ingest.exposure_rank(OLD.exposure_level)
      OR (OLD.needs_exposure_approval AND NOT NEW.needs_exposure_approval
          AND ingest.exposure_rank(NEW.exposure_level) < 2))
     AND NOT approved THEN
    RAISE EXCEPTION 'lowering a lookup provider''s exposure needs a second administrator''s approval of its current origin in the same transaction';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER provider_guarded
  BEFORE UPDATE OR DELETE ON ingest.provider
  FOR EACH ROW EXECUTE FUNCTION ingest.guard_provider();
CREATE TRIGGER provider_no_truncate
  BEFORE TRUNCATE ON ingest.provider
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_provider();

CREATE FUNCTION ingest.guard_exposure_change() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'an exposure change is the record of who lowered a provider''s controls: never deleted';
  END IF;
  IF OLD.decision IS NOT NULL THEN
    RAISE EXCEPTION 'an exposure change is decided once';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
     OR NEW.from_level IS DISTINCT FROM OLD.from_level
     OR NEW.to_level IS DISTINCT FROM OLD.to_level
     OR NEW.origin IS DISTINCT FROM OLD.origin
     OR NEW.private_cidr IS DISTINCT FROM OLD.private_cidr
     OR NEW.basis IS DISTINCT FROM OLD.basis
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'an exposure change request cannot be rewritten, only decided';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER exposure_change_guarded
  BEFORE UPDATE OR DELETE ON ingest.provider_exposure_change
  FOR EACH ROW EXECUTE FUNCTION ingest.guard_exposure_change();
CREATE TRIGGER exposure_change_no_truncate
  BEFORE TRUNCATE ON ingest.provider_exposure_change
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_exposure_change();

COMMENT ON TABLE ingest.provider IS
  'An outbound lookup provider (docs/12 Part 3). Its key is envelope-sealed '
  'and bound to the origin and route it was entered for. Retired, never deleted.';
COMMENT ON TABLE ingest.provider_exposure_change IS
  'Lowering a provider''s exposure, requested by one administrator and '
  'decided by a different one (docs/12 Part 3). Decided once, never deleted.';
""")
    run(f"""
UPDATE iam.permission SET description = '{NEW_DESCRIPTION}'
 WHERE key = 'integration.manage';
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON ingest.provider, ingest.provider_exposure_change FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    run(f"""
DO $pre$
BEGIN
  IF to_regclass('ingest.lookup') IS NOT NULL THEN
    RAISE EXCEPTION 'refusing to downgrade 0098 while ingest.lookup exists: downgrade 0099 first';
  END IF;
END
$pre$;
DO $anchors$
BEGIN
  IF to_regclass('ingest.provider') IS NOT NULL THEN
    UPDATE collect.source s
       SET is_active = false,
           notes = coalesce(s.notes || ' ', '') || 'Provider removed by downgrade.'
     WHERE s.id IN (SELECT source_id FROM ingest.provider);
  END IF;
END
$anchors$;
DROP TABLE IF EXISTS ingest.provider_exposure_change;
DROP TABLE IF EXISTS ingest.provider;
DROP FUNCTION IF EXISTS ingest.guard_exposure_change();
DROP FUNCTION IF EXISTS ingest.guard_provider();
DROP FUNCTION IF EXISTS ingest.provider_starts_unapproved();
DROP FUNCTION IF EXISTS ingest.exposure_rank(text);
UPDATE iam.permission SET description = '{OLD_DESCRIPTION}'
 WHERE key = 'integration.manage';
""")
