-- =====================================================================
-- NocTORnal — CONCEPT SCHEMA  (docs 10, 11, 12)
--
-- ⚠ DRAFT. Deliberately less settled than db/schema.sql. Do not migrate
--   this into production without reading the open questions at the end
--   of each of docs/10, 11 and 12 — several columns here encode
--   assumptions that need a human answer first.
--
-- Kept in a separate file so a reader can tell the difference between
-- "this is decided" and "this is a sketch".
-- =====================================================================

CREATE SCHEMA IF NOT EXISTS comms;
CREATE SCHEMA IF NOT EXISTS lab;
CREATE SCHEMA IF NOT EXISTS ingest;

-- =====================================================================
-- COMMS  (docs/10)
-- =====================================================================
SET search_path = comms, core, public;

CREATE TYPE pm_provenance AS ENUM ('PARTY','LEAK','SEIZURE','DISCLOSED');
CREATE TYPE control_state AS ENUM ('CLAIMED','CONFIRMED','DISPUTED','REFUTED');

CREATE TABLE platform (
  key             text PRIMARY KEY,        -- SESSION, TOX, XMPP, WIRE, MATRIX...
  display_name    text NOT NULL,
  -- Which selector type is the DURABLE identifier. This column exists
  -- because the displayed ID and the durable ID differ on half these
  -- platforms, and conflating them is the main source of false
  -- attribution in the domain.
  durable_selector_type text REFERENCES core.selector_type(key),
  display_selector_type text REFERENCES core.selector_type(key),
  is_e2ee         boolean NOT NULL DEFAULT true,
  has_server_history boolean NOT NULL DEFAULT false,
  -- Realistic collection routes. NULL-ish coverage is itself a finding:
  -- an actor on an uncollectable platform reads as UNMONITORED, never
  -- as inactive.
  collection_routes text[] NOT NULL DEFAULT '{}',  -- PARTY|PUBLIC_ROOM|DISCLOSURE|LEGAL
  notes           text,
  is_active       boolean NOT NULL DEFAULT true
);

-- An account is NOT an identity. One persona may run several accounts on
-- one platform; one account may be shared by several people (shop
-- support, group admin). Keep them separate.
CREATE TABLE account (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  platform_key    text NOT NULL REFERENCES platform(key),
  node_id         uuid REFERENCES core.node(id),   -- the COMMS_ACCOUNT node
  -- As observed, verbatim. Never normalise in place.
  raw_identifier  text NOT NULL,
  -- Normalised to the DURABLE form. For Tox this is the 64-hex public
  -- key, NOT the 76-hex Tox ID. For Telegram the numeric ID, not
  -- @username. Getting this right is the whole point of the table.
  durable_identifier text NOT NULL,
  display_name    text,
  -- Multiple display identifiers may map to one durable one over time:
  -- rotated Tox nospam, changed @username, renamed profile.
  known_aliases   text[] NOT NULL DEFAULT '{}',
  control         control_state NOT NULL DEFAULT 'CLAIMED',
  control_evidence text,                   -- signed msg, admin list, observed use
  first_seen      timestamptz,
  last_seen       timestamptz,
  is_service_account boolean NOT NULL DEFAULT false,  -- escrow, support, bot
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, platform_key, durable_identifier)
);
CREATE INDEX ON account (platform_key, durable_identifier);  -- cross-case pivot

-- Device identity derived from crypto material: OMEMO fingerprints,
-- Matrix device keys, client fingerprints. Links personas WITHOUT
-- merging them, which is exactly what you want when two JIDs share a
-- device but you cannot yet say they share an operator.
CREATE TABLE device_fingerprint (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  node_id         uuid REFERENCES core.node(id),   -- the DEVICE node
  scheme          text NOT NULL,           -- OMEMO, MATRIX_DEVICE, CLIENT_FP
  fingerprint     text NOT NULL,
  first_seen      timestamptz,
  last_seen       timestamptz,
  UNIQUE (case_id, scheme, fingerprint)
);
CREATE INDEX ON device_fingerprint (scheme, fingerprint);

CREATE TABLE account_device (
  account_id  uuid NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES device_fingerprint(id) ON DELETE CASCADE,
  first_seen  timestamptz,
  last_seen   timestamptz,
  PRIMARY KEY (account_id, device_id)
);

-- A contact block is a single published advertisement of several
-- identifiers. It is parsed as a UNIT because co-declaration is strong
-- identity evidence — but only for the entries the publisher claims as
-- their own.
CREATE TABLE contact_block (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  document_id     uuid,                    -- collect.document
  evidence_id     uuid REFERENCES core.evidence(id),
  publisher_node_id uuid REFERENCES core.node(id),   -- the declaring IDENTITY
  raw_text        text NOT NULL,
  context         text,                    -- SIGNATURE|SALE_THREAD|PROFILE|SHOP
  -- Set when this exact block has been seen under a different publisher.
  -- Means one operator OR an impersonator. Do NOT auto-resolve.
  duplicate_of_id uuid REFERENCES contact_block(id),
  observed_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE contact_block_entry (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  block_id        uuid NOT NULL REFERENCES contact_block(id) ON DELETE CASCADE,
  selector_type   text NOT NULL REFERENCES core.selector_type(key),
  raw_value       text NOT NULL,
  norm_value      text NOT NULL,
  label           text,                    -- the literal label: "Jabber:", "Escrow:"
  -- THE important column. Contact blocks routinely list the forum's
  -- escrow agent, a guarantor, or a partner shop. Attributing those to
  -- the publisher is the classic false-link error.
  attributed_role text NOT NULL DEFAULT 'SELF',  -- SELF|ESCROW|GUARANTOR|PARTNER|UNKNOWN
  -- Weight fed to identity resolution. SELF entries in a labelled block
  -- score high; unlabelled entries in a messy block score low.
  linkage_weight  numeric(4,3) NOT NULL DEFAULT 0.5,
  position        int
);
CREATE INDEX ON contact_block_entry (norm_value, selector_type);

-- Known third-party service identifiers that must never be attributed to
-- whoever published them. Seed from forum staff lists and grow it.
CREATE TABLE service_selector_stoplist (
  selector_type text NOT NULL REFERENCES core.selector_type(key),
  norm_value    text NOT NULL,
  service_role  text NOT NULL,             -- ESCROW|ADMIN|GUARANTOR|SUPPORT
  source_note   text,
  PRIMARY KEY (selector_type, norm_value)
);

CREATE TABLE conversation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  node_id         uuid REFERENCES core.node(id),   -- the CONVERSATION node
  platform_key    text NOT NULL REFERENCES platform(key),
  external_id     text,                    -- XenForo conversation_id, MUC jid, room id
  title           text,
  kind            text NOT NULL,           -- DM|GROUP|MUC|CHANNEL|FORUM_PM|SHOP_CHAT
  -- Non-negotiable: how we came to hold this. Reliability and legal
  -- standing both depend on it, and "we have the PMs" is not an answer.
  provenance      pm_provenance NOT NULL,
  provenance_note text,
  -- Which of our personas was the party, when provenance = PARTY.
  collection_account_id uuid,
  first_message_at timestamptz,
  last_message_at  timestamptz,
  message_count    int NOT NULL DEFAULT 0,
  is_content_held  boolean NOT NULL DEFAULT false,  -- false = metadata only
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, platform_key, external_id)
);

CREATE TABLE conversation_participant (
  conversation_id uuid NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
  account_id      uuid NOT NULL REFERENCES account(id),
  -- Participation is temporal: people join and leave conversations.
  joined_at       timestamptz,
  left_at         timestamptz,
  role            text,                    -- OWNER|ADMIN|MEMBER|OBSERVER
  message_count   int NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, account_id)
);

-- Optional. Metadata-only collection is far cheaper and covers most of
-- the analytic value — see docs/10 open question 1 before building this.
CREATE TABLE message (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
  account_id      uuid REFERENCES account(id),
  external_id     text,
  sent_at         timestamptz,
  captured_at     timestamptz NOT NULL DEFAULT now(),
  body_text       text,
  body_sha256     bytea,
  has_attachment  boolean NOT NULL DEFAULT false,
  is_edited       boolean NOT NULL DEFAULT false,
  is_deleted_upstream boolean NOT NULL DEFAULT false,
  reply_to_id     uuid REFERENCES message(id),
  lang            text,
  search_tsv      tsvector,
  UNIQUE (conversation_id, external_id)
);
CREATE INDEX ON message USING gin (search_tsv);
CREATE INDEX ON message (conversation_id, sent_at);

-- =====================================================================
-- LAB  (docs/11)
-- =====================================================================
SET search_path = lab, core, public;

CREATE TYPE sample_state AS ENUM
  ('SUBMITTED','QUARANTINED','TRIAGED','ASSIGNED','IN_ANALYSIS','REPORTED','REJECTED');

CREATE TABLE sample (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid REFERENCES core."case"(id),
  node_id         uuid REFERENCES core.node(id),   -- MALWARE / TOOL node
  -- Object key is the sha256. NEVER the original filename: filenames are
  -- attacker-controlled and are themselves a payload vector.
  sha256          bytea NOT NULL,
  sha1            bytea,
  md5             bytea,
  -- Retained for the record, never used as a path component and never
  -- rendered unescaped.
  original_filename text,
  byte_size       bigint NOT NULL,
  -- Encrypted at rest with a per-sample data key. Incidentally solves
  -- the "our own EDR quarantined the evidence" problem, because the
  -- bytes on disk are not recognisable as malware.
  storage_key     text NOT NULL,
  storage_bucket  text NOT NULL,
  data_key_ciphertext bytea NOT NULL,
  data_key_id     text NOT NULL,
  state           sample_state NOT NULL DEFAULT 'SUBMITTED',
  reject_reason   text,
  -- Fuzzy + structural hashes. These are the cluster keys that link a
  -- sample to a BUILDER and therefore to a developer, who is usually a
  -- more interesting node than any affiliate.
  imphash         text,
  rich_header_hash text,
  ssdeep          text,
  tlsh            text,
  file_type       text,
  submitted_by    uuid NOT NULL,
  submitted_at    timestamptz NOT NULL DEFAULT now(),
  source_note     text,                    -- where the analyst got it
  assigned_to     uuid,                    -- the RE
  assigned_at     timestamptz,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  legal_hold      boolean NOT NULL DEFAULT false,
  UNIQUE (sha256)
);
CREATE INDEX ON sample (state) WHERE state IN ('QUARANTINED','TRIAGED','ASSIGNED');
CREATE INDEX ON sample (imphash) WHERE imphash IS NOT NULL;
CREATE INDEX ON sample (ssdeep)  WHERE ssdeep  IS NOT NULL;

CREATE TABLE sample_analysis (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id       uuid NOT NULL REFERENCES sample(id) ON DELETE CASCADE,
  kind            text NOT NULL,           -- STATIC|YARA|MANUAL_RE|SANDBOX|VENDOR
  analyst_id      uuid,
  tool            text,
  tool_version    text,
  -- Machine-readable, because this is where the graph value comes from.
  -- A PDF report is where analysis goes to die.
  findings        jsonb NOT NULL DEFAULT '{}'::jsonb,
  extracted_selectors jsonb NOT NULL DEFAULT '[]'::jsonb,  -- C2, wallets, mutexes
  yara_hits       text[],
  family_assessment text,
  -- Family attribution is an ASSESSMENT, not a fact. It becomes a
  -- core.assertion, not a column stamped on the actor.
  confidence      core.analytic_confidence,
  narrative       text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE detonation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id       uuid NOT NULL REFERENCES sample(id),
  -- Detonation is an OVERT ACT. Operators watch public sandboxes for
  -- their own samples and treat submission as a signal they have been
  -- noticed. Non-private targets need case-owner sign-off.
  target          text NOT NULL,           -- PRIVATE_CAPE|VENDOR_PRIVATE|PUBLIC
  exposure_level  text NOT NULL,           -- NONE|VENDOR|PUBLIC
  authorised_by   uuid,
  authorisation_note text,
  submitted_at    timestamptz,
  external_ref    text,
  status          text NOT NULL DEFAULT 'PENDING',
  report          jsonb,
  CONSTRAINT detonation_public_needs_auth
    CHECK (exposure_level = 'NONE' OR authorised_by IS NOT NULL)
);

-- Custody for samples, same discipline as core.evidence_custody.
-- Downloads especially: who took a copy of a live binary, and when.
CREATE TABLE sample_access (
  id           bigserial PRIMARY KEY,
  sample_id    uuid NOT NULL REFERENCES sample(id),
  actor_id     uuid NOT NULL,
  action       text NOT NULL,              -- VIEWED_META|DOWNLOADED|SHARED|DETONATED
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  archive_format text,                     -- ZIP_INFECTED|SEVENZ_AES
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ON sample_access (sample_id, occurred_at);

-- =====================================================================
-- INGEST  (docs/12)
-- =====================================================================
SET search_path = ingest, core, public;

CREATE TABLE api_key (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Public, indexed lookup handle. The secret half is HMAC'd with a
  -- pepper — NOT Argon2. Machine keys are high-entropy by construction,
  -- and a per-request KDF at ingest volume will melt the API.
  key_id          text UNIQUE NOT NULL,
  secret_hmac     bytea NOT NULL,
  pepper_id       text NOT NULL,
  name            text NOT NULL,
  environment     text NOT NULL DEFAULT 'live',
  -- Write-only, always. A leaked ingest key should mean junk data,
  -- never case access.
  scopes          text[] NOT NULL DEFAULT '{ingest:write}',
  source_id       uuid,                    -- collect.source this key feeds
  declared_schema jsonb,                   -- payload shape; anything else rejected
  default_reliability core.source_reliability NOT NULL DEFAULT 'F',
  classification_ceiling core.tlp NOT NULL DEFAULT 'AMBER',
  ip_allowlist    cidr[],
  require_hmac_signing boolean NOT NULL DEFAULT false,
  rate_limit_rpm  int NOT NULL DEFAULT 60,
  max_payload_bytes bigint NOT NULL DEFAULT 10485760,
  owner_user_id   uuid NOT NULL,           -- a named human, never a team
  created_at      timestamptz NOT NULL DEFAULT now(),
  -- Mandatory. There is deliberately no "never expires" option.
  expires_at      timestamptz NOT NULL,
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  revoke_reason   text,
  -- Rotation overlap: both keys valid during the window, so rotation
  -- does not need a coordinated cutover (which is why it never happens).
  supersedes_key_id uuid REFERENCES api_key(id),
  CONSTRAINT api_key_no_read_scope CHECK (NOT ('case:read' = ANY(scopes)))
);
CREATE INDEX ON api_key (key_id) WHERE revoked_at IS NULL;
CREATE INDEX ON api_key (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE batch (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key_id      uuid NOT NULL REFERENCES api_key(id),
  idempotency_key text,
  received_at     timestamptz NOT NULL DEFAULT now(),
  -- Raw payload persisted BEFORE parsing. When the parser is wrong — and
  -- it will be — you re-parse rather than asking a partner to resend
  -- three months of feed.
  raw_storage_key text NOT NULL,
  raw_sha256      bytea NOT NULL,
  byte_size       bigint NOT NULL,
  detected_format text,
  declared_format text,
  record_count    int,
  parsed_count    int NOT NULL DEFAULT 0,
  dead_letter_count int NOT NULL DEFAULT 0,
  parser_version  text,
  status          text NOT NULL DEFAULT 'RECEIVED',
  UNIQUE (api_key_id, idempotency_key)
);
CREATE INDEX ON batch (api_key_id, received_at DESC);

CREATE TABLE record (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id        uuid NOT NULL REFERENCES batch(id) ON DELETE CASCADE,
  seq_in_batch    int NOT NULL,
  -- Auto-assigned, correctable by analysts. Corrections are training
  -- data, so keep both the machine guess and the human answer.
  category        text NOT NULL DEFAULT 'UNKNOWN',
  category_confidence numeric(4,3),
  category_corrected_to text,
  category_corrected_by uuid,
  document_id     uuid,                    -- promoted into collect.document
  payload         jsonb NOT NULL,
  content_sha256  bytea NOT NULL,
  -- Near-duplicate cluster key. Feeds republish each other constantly;
  -- without this the queue fills with one leak post from nine sources.
  simhash         bigint,
  duplicate_of_id uuid REFERENCES record(id),
  priority_score  numeric(6,3),
  triage_state    text NOT NULL DEFAULT 'NEW',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON record (batch_id, seq_in_batch);
CREATE INDEX ON record (category, priority_score DESC) WHERE triage_state = 'NEW';
CREATE INDEX ON record (simhash) WHERE simhash IS NOT NULL;
CREATE INDEX ON record (content_sha256);

-- Nothing is ever silently dropped. Silent drops are how you discover
-- six months later that a feed has been half-failing.
CREATE TABLE dead_letter (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id        uuid REFERENCES batch(id),
  api_key_id      uuid REFERENCES api_key(id),
  raw_fragment    text,
  error_class     text NOT NULL,
  error_detail    text,
  parser_version  text,
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  replayed_at     timestamptz,
  replayed_by     uuid,
  resolved        boolean NOT NULL DEFAULT false
);
CREATE INDEX ON dead_letter (api_key_id, occurred_at DESC) WHERE NOT resolved;

CREATE TABLE category_rule (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  category     text NOT NULL,
  priority     int NOT NULL DEFAULT 100,
  match_json   jsonb NOT NULL,             -- field presence, regex, format
  is_active    boolean NOT NULL DEFAULT true,
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- Outbound third-party credentials. Same vault discipline as personas.
CREATE TABLE provider_credential (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider        text NOT NULL,           -- virustotal, shodan, urlscan...
  label           text NOT NULL,
  secret_ciphertext bytea NOT NULL,
  key_id          text NOT NULL,
  -- Some lookups tell the PROVIDER, and occasionally the world, what you
  -- are interested in. Same treatment as sandbox detonation: confirm
  -- before using a leaky one.
  exposure_level  text NOT NULL DEFAULT 'VENDOR',  -- NONE|VENDOR|PUBLIC
  quota_period    text,
  quota_limit     int,
  quota_used      int NOT NULL DEFAULT 0,
  quota_reset_at  timestamptz,
  is_active       boolean NOT NULL DEFAULT true,
  rotated_at      timestamptz,
  UNIQUE (provider, label)
);
