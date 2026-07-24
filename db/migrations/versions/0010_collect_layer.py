"""Collection layer: enums, source, collection_account, egress_profile,
watch, collection_run.

collection_account.egress_profile_id FK arrives in 0014 (as in the
reference DDL, which defers it past egress_profile's creation).
Credentials never leave the collector (invariant 7): the DB only ever
holds ciphertext + key id.
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = collect, core, public;

CREATE TYPE source_kind AS ENUM ('RSS','XENFORO','MYBB','PHPBB','TELEGRAM','DISCORD','PASTE','WEB','MANUAL','VENDOR_API');
CREATE TYPE run_status  AS ENUM ('QUEUED','RUNNING','OK','PARTIAL','FAILED','BLOCKED','RATE_LIMITED');

CREATE TABLE source (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind           source_kind NOT NULL,
  name           text NOT NULL,
  base_url       text,
  -- Default grading applied to everything from this source. An analyst
  -- can override per assertion, but the default is what stops every
  -- forum rumour entering the graph as gospel.
  default_reliability source_reliability NOT NULL DEFAULT 'F',
  classification tlp NOT NULL DEFAULT 'AMBER',
  is_active      boolean NOT NULL DEFAULT true,
  -- Per-source politeness. Aggressive polling burns collection accounts.
  poll_interval_s int NOT NULL DEFAULT 900,
  jitter_pct      int NOT NULL DEFAULT 25,
  max_rps         numeric(6,3) NOT NULL DEFAULT 0.2,
  -- Parser health. Silent parser breakage after a forum upgrade is the
  -- single most common failure mode of a platform like this.
  parser_key      text,
  parser_version  text,
  last_ok_at      timestamptz,
  consecutive_failures int NOT NULL DEFAULT 0,
  health          text NOT NULL DEFAULT 'UNKNOWN',
  notes           text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- Sock puppets / collection personas. Credentials are envelope-encrypted
-- app-side; the DB only ever sees ciphertext + key id.
CREATE TABLE collection_account (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id      uuid REFERENCES source(id),
  handle         text NOT NULL,
  persona_notes  text,
  -- Ciphertext blob (AES-256-GCM), key held in KMS/Vault. Never logged,
  -- never returned by the API, decrypted only inside the collector.
  secret_ciphertext bytea,
  secret_key_id  text,
  secret_nonce   bytea,
  secret_rotated_at timestamptz,
  -- OPSEC: an account is bound to exactly one egress identity. Sharing
  -- an IP across personas is how a collection network gets correlated
  -- and burned in one go.
  egress_profile_id uuid,
  fingerprint_profile jsonb NOT NULL DEFAULT '{}'::jsonb,
  status         text NOT NULL DEFAULT 'HEALTHY',  -- HEALTHY|COOLDOWN|LOCKED|BURNED|RETIRED
  cooldown_until timestamptz,
  last_used_at   timestamptz,
  burn_reason    text,
  owner_user_id  uuid,
  approved_by    uuid,                     -- persona use requires sign-off
  approved_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE egress_profile (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  kind          text NOT NULL,             -- RESIDENTIAL|DATACENTRE|TOR|VPN
  endpoint_ciphertext bytea,
  key_id        text,
  region        text,
  is_active     boolean NOT NULL DEFAULT true,
  UNIQUE (name)
);

-- A watch is a standing tasking against a source.
CREATE TABLE watch (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid REFERENCES "case"(id),
  source_id      uuid NOT NULL REFERENCES source(id),
  collection_account_id uuid REFERENCES collection_account(id),
  name           text NOT NULL,
  -- What to watch: a board, a thread, a channel, a user profile, a feed.
  target_kind    text NOT NULL,            -- BOARD|THREAD|USER|CHANNEL|FEED|SEARCH
  target_ref     text NOT NULL,            -- URL or platform id
  -- What to fire on. NULL keywords = capture everything from the target.
  keywords       text[],
  selector_watch text[],                   -- fire on specific selectors
  regexes        text[],
  priority       smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
  is_active      boolean NOT NULL DEFAULT true,
  owner_user_id  uuid NOT NULL,
  -- Alert hygiene. Without these you get alert fatigue in week two and
  -- the platform stops being read.
  suppress_window_s int NOT NULL DEFAULT 3600,
  digest_only    boolean NOT NULL DEFAULT false,
  quiet_hours    int4range,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_hit_at    timestamptz
);

CREATE TABLE collection_run (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id      uuid NOT NULL REFERENCES source(id),
  watch_id       uuid REFERENCES watch(id),
  collection_account_id uuid REFERENCES collection_account(id),
  egress_profile_id uuid REFERENCES egress_profile(id),
  status         run_status NOT NULL DEFAULT 'QUEUED',
  started_at     timestamptz,
  finished_at    timestamptz,
  items_seen     int NOT NULL DEFAULT 0,
  items_new      int NOT NULL DEFAULT 0,
  http_status    int,
  error_class    text,
  error_detail   text,
  -- Conditional GET state, so we are not re-pulling unchanged pages.
  etag           text,
  last_modified  text,
  cursor         jsonb NOT NULL DEFAULT '{}'::jsonb,
  parser_version text
);
CREATE INDEX ON collection_run (source_id, started_at DESC);
CREATE INDEX ON collection_run (status) WHERE status IN ('QUEUED','RUNNING');
""")


def downgrade() -> None:
    run("""
DROP TABLE collect.collection_run;
DROP TABLE collect.watch;
DROP TABLE collect.egress_profile;
DROP TABLE collect.collection_account;
DROP TABLE collect.source;
DROP TYPE collect.run_status;
DROP TYPE collect.source_kind;
""")
