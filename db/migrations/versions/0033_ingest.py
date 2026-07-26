"""Phase 9 -- ingest API, with stealer logs in scope (docs/12).

=====================================================================
STEALER LOGS ARE IN SCOPE BY OPERATOR DIRECTIVE, 2026-07-25.

docs/12 open question 3 asked whether they were, and said: "If yes,
resolve the compartment and minimisation policy before writing any
ingest code." The operator answered yes. The compartment is resolved
HERE, in the schema. **The minimisation policy is a legal determination
and is NOT resolved** -- see docs/16 L2, which is a BLOCKING entry.

docs/12 on why this is the sharp end:

    They are the highest-volume, highest-value and highest-risk thing you
    will ingest, and they are the most likely route by which this platform
    becomes a data protection incident rather than an intelligence asset.

    A single log archive contains credentials, cookies, session tokens,
    crypto wallets, autofill data and documents belonging to ONE VICTIM
    WHO IS NOT YOUR SUBJECT. A feed contains thousands.
=====================================================================

## The stealer-log controls, in the schema rather than in a service

Every one of these is a column or a constraint, because a control that
lives only in application code is a control that the next bulk-import
script goes around.

1. **Its own compartment, tighter than the parent case.**
   `ingest.api_key.forced_compartment` -- a key declared as a stealer-log
   feed cannot produce a record outside it, and the compartment is applied
   at ingest rather than trusted from the payload.
2. **Credential values are stored SEPARATELY from record metadata**, in
   `ingest.victim_credential`, so the analytic path (infection timeline,
   victim organisation, C2 and builder metadata) never has to touch them.
   docs/12: "You can extract almost all of that from the metadata without
   ever exposing the credential contents. Design for that."
3. **Values are encrypted at rest and masked by default.** A reveal is a
   step-up action with its own audit row, and `reveal_count` on the row
   makes "how often has anybody actually looked" answerable.
4. **Free-text search across victim PII is impossible by construction**:
   `victim_credential` has no tsvector, no trigram index, and the value
   column is ciphertext. There is no index to run a LIKE against.
   docs/12: "otherwise the platform is a credential lookup service and
   someone will use it as one."
5. **Retention is independent and shorter**, via the per-category rules
   from migration 0032. `STEALER_LOG` is the shortest default.
6. **An authorisation ledger** (`ingest.pii_authorisation`) for the narrow
   case where a lookup genuinely is needed. Time-boxed, justified, and
   attached to a named human -- and the search path refuses without one.

## Ingest keys are write-only, by CHECK constraint

CONVENTIONS.md invariant 11: "A `case:read` scope on an `ingest.api_key` is a
bug, and there is a check constraint saying so. A leaked ingest key means
junk data, never the case file." That constraint is `api_key_write_only`
below.

HMAC with a pepper, not Argon2 (docs/12): machine keys are high-entropy by
construction, a per-request KDF at ingest volume melts the API, and you
cannot index a slow hash so every request would scan the table.

## Raw persists before parse

`ingest.batch.raw_key` is written before anything is parsed. When the
parser is wrong -- and it will be -- you re-parse from the original rather
than asking a partner to resend three months of feed.

## Nothing is silently dropped

Invariant 12. `ingest.dead_letter` takes the raw fragment, the error and
the parser version, and a repair-and-replay path exists. Silent drops are
how you find out six months later that a feed has been half-failing.
"""
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

# docs/12's taxonomy. UNKNOWN is an honest default and is better than a
# confident wrong label -- a mis-categorised record gets the wrong
# retention clock, which is the failure that matters.
_CATEGORIES = [
    "STEALER_LOG", "CREDENTIAL_DUMP", "DATABASE_LEAK", "RANSOM_LEAK_POST",
    "MARKET_LISTING", "FORUM_POST", "CHAT_EXPORT", "PASTE", "IOC_FEED",
    "VENDOR_REPORT", "MALWARE_SAMPLE", "BLOCKCHAIN_TX", "SANCTIONS_LIST",
    "COURT_RECORD", "TELEMETRY", "UNKNOWN",
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    categories = ", ".join(f"'{c}'" for c in _CATEGORIES)
    run(f"""
CREATE SCHEMA IF NOT EXISTS ingest;
SET search_path = ingest, core, public;

CREATE TABLE api_key (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Public, indexed lookup handle. The prefix is not cosmetic: a fixed
  -- searchable prefix means leaked keys are findable in GitHub, in pastes
  -- and in your own logs, and log redaction can match reliably rather
  -- than heuristically.
  key_id          text UNIQUE NOT NULL,
  -- HMAC-SHA256 with a pepper, NOT Argon2. Machine keys are high-entropy
  -- by construction; a per-request KDF at ingest volume melts the API and
  -- cannot be indexed.
  secret_hmac     bytea NOT NULL,
  pepper_id       text NOT NULL,
  name            text NOT NULL,
  environment     text NOT NULL DEFAULT 'live',

  -- Invariant 11, as a constraint rather than a convention.
  scopes          text[] NOT NULL DEFAULT '{{ingest:write}}',

  source_id       uuid REFERENCES collect.source(id),
  -- What this feed says it sends. Anything else is rejected at the
  -- boundary rather than guessed at.
  declared_category text NOT NULL DEFAULT 'UNKNOWN',
  declared_schema jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  -- Admiralty grading applied to everything from this feed, so a record's
  -- provenance is never better than its source.
  default_reliability text NOT NULL DEFAULT 'F',
  -- Nothing from this key may be marked above this.
  classification_ceiling core.tlp NOT NULL DEFAULT 'AMBER',
  -- STEALER LOG CONTROL 1. A key declared as a stealer-log feed cannot
  -- produce a record outside this compartment, and it is applied at
  -- ingest rather than trusted from the payload.
  forced_compartment text,
  ip_allowlist    inet[] NOT NULL DEFAULT '{{}}',
  max_records_per_hour integer NOT NULL DEFAULT 10000,
  max_bytes_per_request bigint NOT NULL DEFAULT 33554432,

  -- Mandatory. docs/12: "no 'never' option." An orphaned key is how an
  -- ingest path outlives its purpose.
  expires_at      timestamptz NOT NULL,
  -- A named human, not a team.
  owner_user_id   uuid NOT NULL REFERENCES iam.app_user(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  revoked_reason  text,
  -- Rotation overlap: the key this one replaces, which stays live until
  -- its own expiry. A rotation needing a coordinated cutover does not
  -- happen, and the key lives for three years instead.
  replaces_key_id uuid REFERENCES api_key(id),

  -- INVARIANT 11. A leaked ingest key means junk data, never the case file.
  CONSTRAINT api_key_write_only CHECK (
    scopes <@ ARRAY['ingest:write', 'ingest:status']::text[]
    AND NOT ('case:read' = ANY(scopes))
  ),
  CONSTRAINT api_key_expiry_mandatory CHECK (expires_at > created_at),
  CONSTRAINT api_key_environment_known
    CHECK (environment IN ('live', 'test')),
  CONSTRAINT api_key_category_known
    CHECK (declared_category IN ({categories})),
  -- A stealer-log feed without a compartment is the data-protection
  -- incident docs/12 warns about, arriving through the front door.
  CONSTRAINT api_key_stealer_needs_compartment CHECK (
    declared_category <> 'STEALER_LOG' OR forced_compartment IS NOT NULL
  ),
  CONSTRAINT api_key_revocation_complete
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE INDEX api_key_owner_idx ON api_key (owner_user_id);
CREATE INDEX api_key_live_idx ON api_key (expires_at)
  WHERE revoked_at IS NULL;
-- Keys unused for 30 days are either dead integrations or somebody else's.
CREATE INDEX api_key_stale_idx ON api_key (last_used_at NULLS FIRST)
  WHERE revoked_at IS NULL;

CREATE TABLE batch (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key_id      uuid NOT NULL REFERENCES api_key(id),
  -- Deduped for 24h. Retrying clients are the norm, not the exception.
  idempotency_key text,
  received_at     timestamptz NOT NULL DEFAULT now(),
  -- RAW PERSISTS BEFORE PARSE. When the parser is wrong -- and it will be
  -- -- you re-parse from the original rather than asking a partner to
  -- resend three months of feed.
  raw_key         text NOT NULL,
  raw_bytes       bigint NOT NULL,
  raw_sha256      bytea NOT NULL,
  content_type    text,
  detected_format text,
  state           text NOT NULL DEFAULT 'RECEIVED',
  record_count    integer NOT NULL DEFAULT 0,
  dead_count      integer NOT NULL DEFAULT 0,
  parsed_at       timestamptz,
  parser_version  text,
  error           text,

  CONSTRAINT batch_state_known
    CHECK (state IN ('RECEIVED', 'PARSING', 'PARSED', 'FAILED', 'PURGED'))
);
CREATE UNIQUE INDEX batch_idempotency_idx
  ON batch (api_key_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX batch_key_idx ON batch (api_key_id, received_at DESC);
CREATE INDEX batch_unparsed_idx ON batch (received_at)
  WHERE state IN ('RECEIVED', 'PARSING');

CREATE TABLE record (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id        uuid NOT NULL REFERENCES batch(id),
  case_id         uuid REFERENCES core."case"(id),
  category        text NOT NULL DEFAULT 'UNKNOWN',
  -- Declared by the key, refined by structure, refined by content. The
  -- confidence is kept so an analyst's correction is visible AS a
  -- correction -- corrections are training data.
  category_confidence numeric(4,3) NOT NULL DEFAULT 0.5,
  category_source text NOT NULL DEFAULT 'DECLARED',
  payload         jsonb NOT NULL,
  content_sha256  bytea NOT NULL,
  -- Near-duplicate suppression. Feeds re-publish each other constantly,
  -- and without this the queue fills with the same leak post from nine
  -- sources until analysts stop reading it.
  simhash         bigint,
  duplicate_of    uuid REFERENCES record(id),
  -- The triage score. A record containing a watched selector surfaces in
  -- seconds; a generic combo list sinks silently.
  priority        numeric(6,3) NOT NULL DEFAULT 0,
  priority_detail jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{{}}',
  retain_until    timestamptz,
  purged_at       timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT record_category_known CHECK (category IN ({categories})),
  CONSTRAINT record_category_source_known
    CHECK (category_source IN ('DECLARED', 'STRUCTURE', 'CONTENT', 'ANALYST')),
  CONSTRAINT record_confidence_range
    CHECK (category_confidence BETWEEN 0 AND 1),
  -- STEALER LOG CONTROL 1, enforced on the record and not only on the key.
  -- coalesce is load-bearing: array_length('{{}}', 1) is NULL, not 0, and
  -- `NULL >= 1` is NULL rather than false -- so the obvious form of this
  -- check silently passes on exactly the empty array it exists to catch.
  -- Found by the test that tried to set compartments back to '{{}}'.
  CONSTRAINT record_stealer_is_compartmented CHECK (
    category <> 'STEALER_LOG'
    OR coalesce(array_length(compartments, 1), 0) >= 1
  )
);
CREATE INDEX record_batch_idx ON record (batch_id);
CREATE INDEX record_triage_idx ON record (priority DESC, created_at DESC)
  WHERE duplicate_of IS NULL AND purged_at IS NULL;
CREATE INDEX record_simhash_idx ON record (simhash) WHERE simhash IS NOT NULL;
CREATE INDEX record_content_idx ON record (content_sha256);
CREATE INDEX record_retention_idx ON record (retain_until)
  WHERE purged_at IS NULL;

-- STEALER LOG CONTROL 2. Credential values live HERE, apart from the
-- record metadata, so the analytic path -- infection timeline, victim
-- organisation attribution, C2 and builder metadata -- never has to touch
-- them. docs/12: "You can extract almost all of that from the metadata
-- without ever exposing the credential contents. Design for that."
--
-- STEALER LOG CONTROL 4. There is deliberately NO tsvector, NO trigram
-- index and NO plaintext value column on this table. Free-text search
-- across victim PII is not refused by a permission check that somebody
-- could route around -- there is no index to run it against, and the
-- value is ciphertext.
CREATE TABLE victim_credential (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id       uuid NOT NULL REFERENCES record(id) ON DELETE CASCADE,
  -- The victim, as a graph node flagged is_incidental. docs/12 models
  -- them explicitly so that minimisation at closure has something to act
  -- on rather than a jsonb blob to grep.
  victim_node_id  uuid REFERENCES core.node(id),
  kind            text NOT NULL,
  -- The service the credential is FOR. Not the credential. This is the
  -- analytically useful half and it is not sensitive on its own.
  service_domain  text,
  -- A one-way handle for correlation without disclosure: the same
  -- credential appearing in two feeds is a finding, and it can be found
  -- by comparing these without either being readable.
  value_fingerprint bytea NOT NULL,
  -- Encrypted at rest, masked by default. STEALER LOG CONTROL 3.
  value_ciphertext bytea,
  value_key_id    text,
  -- "How often has anybody actually looked" has to be answerable.
  reveal_count    integer NOT NULL DEFAULT 0,
  last_revealed_at timestamptz,
  captured_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT victim_credential_kind_known
    CHECK (kind IN ('PASSWORD', 'COOKIE', 'SESSION_TOKEN', 'AUTOFILL',
                    'WALLET_KEY', 'DOCUMENT_PATH', 'OTHER')),
  CONSTRAINT victim_credential_encrypted_or_absent
    CHECK ((value_ciphertext IS NULL) = (value_key_id IS NULL))
);
CREATE INDEX victim_credential_record_idx ON victim_credential (record_id);
CREATE INDEX victim_credential_service_idx ON victim_credential (service_domain);
-- Correlation without disclosure: the same credential in two feeds.
CREATE INDEX victim_credential_fingerprint_idx
  ON victim_credential (value_fingerprint);

-- STEALER LOG CONTROL 6. The narrow, logged authorisation for the case
-- where a lookup genuinely is needed. Time-boxed and attached to a named
-- human. Without a live row here, the search path refuses.
CREATE TABLE pii_authorisation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  granted_to      uuid NOT NULL REFERENCES iam.app_user(id),
  granted_by      uuid NOT NULL REFERENCES iam.app_user(id),
  -- What may be looked up, and why. A blanket authorisation is not one.
  scope_note      text NOT NULL,
  legal_basis     text NOT NULL,
  granted_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  query_count     integer NOT NULL DEFAULT 0,

  CONSTRAINT pii_authorisation_two_humans CHECK (granted_to <> granted_by),
  CONSTRAINT pii_authorisation_is_time_boxed
    CHECK (expires_at > granted_at AND expires_at <= granted_at + interval '30 days'),
  CONSTRAINT pii_authorisation_justified
    CHECK (length(btrim(scope_note)) > 20 AND length(btrim(legal_basis)) > 0)
);
CREATE INDEX pii_authorisation_live_idx
  ON pii_authorisation (granted_to, expires_at) WHERE revoked_at IS NULL;

-- Invariant 12. Nothing is silently dropped.
CREATE TABLE dead_letter (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id        uuid REFERENCES batch(id),
  api_key_id      uuid REFERENCES api_key(id),
  -- The RAW fragment, so a repair can be replayed against the original.
  raw_fragment    text NOT NULL,
  error_class     text NOT NULL,
  error_detail    text,
  parser_version  text,
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  replayed_at     timestamptz,
  replayed_by     uuid REFERENCES iam.app_user(id),
  resolution      text,

  CONSTRAINT dead_letter_replay_complete
    CHECK ((replayed_at IS NULL) = (replayed_by IS NULL))
);
CREATE INDEX dead_letter_batch_idx ON dead_letter (batch_id);
CREATE INDEX dead_letter_open_idx ON dead_letter (occurred_at DESC)
  WHERE replayed_at IS NULL;
-- The alert docs/12 asks for: a key whose dead-letter rate crosses a
-- threshold is usually the partner changing their schema without telling
-- you.
CREATE INDEX dead_letter_key_idx ON dead_letter (api_key_id, occurred_at DESC);

CREATE TABLE category_rule (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  category        text NOT NULL,
  -- Matched against the payload's SHAPE, never against a filename or a
  -- declared content type -- both are the sender's opinion.
  match_keys      text[] NOT NULL DEFAULT '{{}}',
  match_pattern   text,
  confidence      numeric(4,3) NOT NULL DEFAULT 0.7,
  is_active       boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT category_rule_category_known CHECK (category IN ({categories})),
  CONSTRAINT category_rule_confidence_range
    CHECK (confidence BETWEEN 0 AND 1)
);
CREATE INDEX category_rule_active_idx ON category_rule (category)
  WHERE is_active;
""")

    run("""
SET search_path = iam, core, public;

INSERT INTO permission (key, description, requires_step_up) VALUES
  ('ingest.manage', 'Issue, rotate and revoke ingest keys', true),
  ('ingest.read', 'See ingest batches, records and dead letters', false),
  ('ingest.replay', 'Repair and replay a dead-lettered record', false),
  ('victim_pii.reveal',
   'Reveal a masked victim credential under a logged authorisation', true),
  ('victim_pii.authorise',
   'Grant a time-boxed authorisation to look up victim PII', true)
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
  ('CASE_OWNER', 'ingest.read'),
  ('CASE_OWNER', 'ingest.replay'),
  ('CASE_OWNER', 'victim_pii.authorise'),
  ('ANALYST', 'ingest.read'),
  ('ANALYST', 'ingest.replay'),
  ('REVIEWER', 'ingest.read'),
  ('SYS_ADMIN', 'ingest.manage'),
  ('SECURITY_OFFICER', 'victim_pii.authorise')
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    run("""
DELETE FROM iam.role_permission WHERE permission_key IN
  ('ingest.manage', 'ingest.read', 'ingest.replay',
   'victim_pii.reveal', 'victim_pii.authorise');
DELETE FROM iam.permission WHERE key IN
  ('ingest.manage', 'ingest.read', 'ingest.replay',
   'victim_pii.reveal', 'victim_pii.authorise');

DROP TABLE ingest.category_rule;
DROP TABLE ingest.dead_letter;
DROP TABLE ingest.pii_authorisation;
DROP TABLE ingest.victim_credential;
DROP TABLE ingest.record;
DROP TABLE ingest.batch;
DROP TABLE ingest.api_key;
DROP SCHEMA ingest;
""")
