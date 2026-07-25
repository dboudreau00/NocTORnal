-- =====================================================================
-- NocTORnal — HUMINT / Social Network Analysis platform for cybercrime
-- Postgres 16+ schema.  Read docs/01-domain-model.md alongside this.
--
-- REFERENCE ONLY since 2026-07-24: the authoritative schema is the
-- Alembic chain in db/migrations/versions/ (applied via
-- `alembic upgrade head`). Any change lands as a new migration AND is
-- mirrored here so this file stays readable end-to-end.
--
-- Design commitments encoded here (do not "simplify" these away):
--   1. Nothing is a fact. Everything is an ASSERTION with a source,
--      a grading, and a time. The graph is a projection of assertions.
--   2. A handle is not a person. IDENTITY (persona) and PERSON
--      (assessed human) are separate node types joined by a
--      confidence-scored, revocable edge.
--   3. Bitemporal. valid_* = when it was true in the world.
--      recorded_/superseded_at = when we believed it. Never UPDATE
--      history; supersede it.
--   4. Edges are signed and time-bounded. Trust networks need negative
--      edges (rip reports, bans) or structural balance analysis is
--      impossible.
--   5. The ontology lives in reference tables, not enums, so new node
--      and edge types ship without a migration.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "vector";      -- pgvector, for semantic search
-- CREATE EXTENSION IF NOT EXISTS "pg_uuidv7"; -- preferred; else uuid v4 below

CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS collect;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS analytics;

SET search_path = core, public;

-- ---------------------------------------------------------------------
-- 0. FIXED VOCABULARIES  (genuinely fixed → enums)
-- ---------------------------------------------------------------------

-- FIRST v2.0 traffic light protocol. Drives every export, email and
-- Jira sync decision. AMBER_STRICT must never leave the boundary.
CREATE TYPE tlp AS ENUM ('CLEAR','GREEN','AMBER','AMBER_STRICT','RED');

-- NATO Admiralty Code — source reliability.
CREATE TYPE source_reliability AS ENUM ('A','B','C','D','E','F');
--   A completely reliable   B usually reliable   C fairly reliable
--   D not usually reliable  E unreliable         F cannot be judged

-- NATO Admiralty Code — information credibility.
CREATE TYPE info_credibility AS ENUM ('1','2','3','4','5','6');
--   1 confirmed  2 probably true  3 possibly true
--   4 doubtful   5 improbable     6 cannot be judged

-- ICD 203 analytic confidence. Distinct from source grading: you can
-- have high confidence from mediocre sources that corroborate, and low
-- confidence from one excellent source.
CREATE TYPE analytic_confidence AS ENUM ('LOW','MODERATE','HIGH');

-- Where the claim came from, epistemically.
CREATE TYPE assertion_basis AS ENUM (
  'DIRECT_OBSERVATION',  -- we saw the post ourselves
  'THIRD_PARTY_REPORT',  -- a vendor/partner/report said so
  'ANALYST_INFERENCE',   -- a human reasoned to it
  'AUTOMATED_INFERENCE', -- a model/heuristic proposed it
  'SELF_CLAIM',          -- the subject said it about themselves
  'LEGAL_PROCESS'        -- subpoena/warrant return, court record
);

CREATE TYPE case_status AS ENUM ('DRAFT','ACTIVE','DORMANT','CLOSED','ARCHIVED','PURGED');
CREATE TYPE review_state AS ENUM ('PROPOSED','ACCEPTED','REJECTED','SUPERSEDED','DISPUTED');

-- ---------------------------------------------------------------------
-- 1. ONTOLOGY  (extensible → reference tables)
-- ---------------------------------------------------------------------

CREATE TABLE node_type (
  key           text PRIMARY KEY,          -- 'IDENTITY','PERSON','GROUP',...
  display_name  text NOT NULL,
  category      text NOT NULL,             -- ACTOR | ARTEFACT | CONTEXT
  icon          text,
  colour_token  text,                      -- resolves against UI palette
  schema_json   jsonb NOT NULL DEFAULT '{}'::jsonb,  -- JSON Schema for attrs
  is_active     boolean NOT NULL DEFAULT true,
  sort_order    int NOT NULL DEFAULT 100
);

CREATE TABLE edge_type (
  key             text PRIMARY KEY,        -- 'MEMBER_OF','VOUCHED_FOR',...
  display_name    text NOT NULL,
  inverse_name    text,                    -- label when traversed backwards
  is_directed     boolean NOT NULL DEFAULT true,
  -- Signed-network semantics. +1 trust/affiliation, -1 distrust/conflict,
  -- 0 neutral/structural. Drives balance-theory analytics.
  default_sign    smallint NOT NULL DEFAULT 1 CHECK (default_sign IN (-1,0,1)),
  -- Which node types this edge may legally connect. Enforced in app +
  -- validated by a trigger; keeps the graph from turning to soup.
  src_node_types  text[] NOT NULL,
  dst_node_types  text[] NOT NULL,
  -- Whether this edge counts toward SNA metrics by default. Some edges
  -- (SAME_AS, ALIAS_OF) are identity plumbing, not social ties, and will
  -- wreck centrality if included.
  is_social_tie   boolean NOT NULL DEFAULT true,
  schema_json     jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_active       boolean NOT NULL DEFAULT true
);

-- Selector kinds are their own vocabulary because normalisation and
-- validation differ wildly per kind (see collect.selector_norm_rule).
CREATE TABLE selector_type (
  key             text PRIMARY KEY,        -- 'TELEGRAM_ID','BTC_ADDR',...
  display_name    text NOT NULL,
  -- Whether this selector is strong enough to merge identities on its own.
  -- PGP fingerprint: yes. Nickname: absolutely not.
  is_strong       boolean NOT NULL DEFAULT false,
  is_pii          boolean NOT NULL DEFAULT false,
  validator_regex text,
  normaliser      text,                    -- name of app-side normaliser fn
  is_active       boolean NOT NULL DEFAULT true
);

-- ---------------------------------------------------------------------
-- 2. CASES / COMPARTMENTS  (the unit of access control)
-- ---------------------------------------------------------------------

CREATE TABLE "case" (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code            text UNIQUE NOT NULL,     -- OP-KESTREL-24
  title           text NOT NULL,
  summary         text,
  status          case_status NOT NULL DEFAULT 'DRAFT',
  classification  tlp NOT NULL DEFAULT 'AMBER',
  -- Compartments are additive need-to-know locks on top of case access.
  compartments    text[] NOT NULL DEFAULT '{}',
  owner_user_id   uuid NOT NULL,
  deputy_user_id  uuid,
  -- Governance. Non-negotiable: a case with no lawful basis and no
  -- review date is a liability, so these are NOT NULL from day one.
  legal_basis     text NOT NULL,
  authority_ref   text,                     -- warrant / tasking / RIPA ref
  retention_until date NOT NULL,
  review_due      date NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  closed_at       timestamptz,
  -- AT TIME ZONE 'UTC' fixes the cast: a bare ::date follows the session
  -- TimeZone GUC and the constraint would mean different things per session.
  CONSTRAINT case_retention_sane CHECK (retention_until > (created_at AT TIME ZONE 'UTC')::date)
);

CREATE INDEX ON "case" (status) WHERE status IN ('ACTIVE','DORMANT');
CREATE INDEX ON "case" (review_due) WHERE status = 'ACTIVE';

-- ---------------------------------------------------------------------
-- 3. GRAPH — NODES
-- ---------------------------------------------------------------------

CREATE TABLE node (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES "case"(id) ON DELETE RESTRICT,
  node_type      text NOT NULL REFERENCES node_type(key),
  -- Human-facing label. Denormalised for graph render speed; the
  -- authoritative value lives in attrs / assertions.
  label          text NOT NULL,
  attrs          jsonb NOT NULL DEFAULT '{}'::jsonb,
  classification tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{}',
  -- World-time existence of the thing itself (group founded/disbanded,
  -- persona created/abandoned).
  valid_from     timestamptz,
  valid_to       timestamptz,
  first_seen     timestamptz,
  last_seen      timestamptz,
  -- System-time. Soft delete only; nodes are never hard-deleted outside
  -- an authorised purge job.
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     uuid NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz,
  deleted_by     uuid,
  -- Entity resolution: when two identities are merged, the loser points
  -- here rather than being destroyed. Merges must be reversible.
  merged_into_id uuid REFERENCES node(id),
  merged_at      timestamptz,
  merged_by      uuid,
  search_tsv     tsvector,
  embedding      vector(768)
);

CREATE INDEX ON node (case_id, node_type) WHERE deleted_at IS NULL AND merged_into_id IS NULL;
CREATE INDEX ON node USING gin (search_tsv);
CREATE INDEX ON node USING gin (label gin_trgm_ops);
CREATE INDEX ON node USING gin (attrs jsonb_path_ops);
CREATE INDEX ON node USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON node (merged_into_id) WHERE merged_into_id IS NOT NULL;

-- Selector values get their own table rather than living in node.attrs.
-- They are the join key for entity resolution and need exact-match
-- indexes and a normalised form.
CREATE TABLE selector (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  selector_type   text NOT NULL REFERENCES selector_type(key),
  raw_value       text NOT NULL,
  -- Normalised per type: lowercase handles, checksum-cased BTC, E.164
  -- phone, punycode domains, stripped Gmail dots, etc.
  norm_value      text NOT NULL,
  node_id         uuid REFERENCES node(id),   -- owning IDENTITY/PERSON/ASSET
  first_seen      timestamptz,
  last_seen       timestamptz,
  observation_cnt int NOT NULL DEFAULT 1,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, selector_type, norm_value)
);

CREATE INDEX ON selector (selector_type, norm_value);   -- cross-case pivot
CREATE INDEX ON selector (node_id);
CREATE INDEX ON selector USING gin (norm_value gin_trgm_ops);

-- ---------------------------------------------------------------------
-- 4. GRAPH — EDGES
-- ---------------------------------------------------------------------

CREATE TABLE edge (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES "case"(id),
  edge_type      text NOT NULL REFERENCES edge_type(key),
  src_node_id    uuid NOT NULL REFERENCES node(id),
  dst_node_id    uuid NOT NULL REFERENCES node(id),
  -- Signed graph. -1 edges are what make this a *trust* network rather
  -- than a contact network.
  sign           smallint NOT NULL DEFAULT 1 CHECK (sign IN (-1,0,1)),
  -- Raw strength (message count, tx volume, vouch count). Normalised
  -- weight for analytics is computed, not stored here.
  weight         numeric(14,4) NOT NULL DEFAULT 1.0,
  attrs          jsonb NOT NULL DEFAULT '{}'::jsonb,  -- role, tx_hash, ...
  classification tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{}',
  -- Time-bounded membership. "Was in LockBit until March" is the normal
  -- case, not the exception.
  valid_from     timestamptz,
  valid_to       timestamptz,
  -- Rolled up from supporting assertions by a trigger; cached for render.
  confidence     analytic_confidence NOT NULL DEFAULT 'LOW',
  -- TRUE when no human has ever confirmed this edge. Rendered dashed.
  -- Inferred edges NEVER silently become asserted ones.
  is_inferred    boolean NOT NULL DEFAULT false,
  inference_method text,                    -- 'CO_OCCURRENCE','STYLOMETRY',...
  review         review_state NOT NULL DEFAULT 'PROPOSED',
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     uuid NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz,
  CONSTRAINT edge_no_self_loop CHECK (src_node_id <> dst_node_id),
  CONSTRAINT edge_time_order CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

-- Parallel edges of the same type in the same interval are a modelling
-- error; distinct intervals are legitimate history.
CREATE UNIQUE INDEX edge_uniq_active ON edge (src_node_id, dst_node_id, edge_type, coalesce(valid_from,'-infinity'))
  WHERE deleted_at IS NULL;
CREATE INDEX ON edge (case_id, edge_type) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (src_node_id) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (dst_node_id) WHERE deleted_at IS NULL;
CREATE INDEX ON edge (review) WHERE review = 'PROPOSED';

-- ---------------------------------------------------------------------
-- 5. ASSERTIONS  — the provenance spine
-- Every node attribute and every edge traces to >=1 assertion.
-- Retract a source and the graph must visibly change.
-- ---------------------------------------------------------------------

CREATE TABLE assertion (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  -- Subject of the claim: exactly one of these.
  node_id         uuid REFERENCES node(id),
  edge_id         uuid REFERENCES edge(id),
  claim_path      text,                     -- e.g. 'attrs.role' when node-scoped
  claim_value     jsonb,
  basis           assertion_basis NOT NULL,
  reliability     source_reliability NOT NULL DEFAULT 'F',
  credibility     info_credibility  NOT NULL DEFAULT '6',
  confidence      analytic_confidence NOT NULL DEFAULT 'LOW',
  -- Provenance chain
  source_id       uuid,                     -- collect.source
  document_id     uuid,                     -- collect.document
  evidence_id     uuid,                     -- core.evidence
  external_ref    text,                     -- vendor report id, court ref
  -- Analyst rationale is mandatory for inference-based claims — this is
  -- what makes the graph defensible later.
  rationale       text,
  -- Bitemporal
  observed_at     timestamptz,              -- when the fact was true
  recorded_at     timestamptz NOT NULL DEFAULT now(),
  superseded_at   timestamptz,
  superseded_by   uuid REFERENCES assertion(id),
  retracted_at    timestamptz,
  retracted_by    uuid,
  retraction_reason text,
  created_by      uuid NOT NULL,
  CONSTRAINT assertion_one_subject CHECK (num_nonnulls(node_id, edge_id) = 1),
  CONSTRAINT assertion_inference_needs_rationale
    CHECK (basis NOT IN ('ANALYST_INFERENCE','AUTOMATED_INFERENCE') OR rationale IS NOT NULL)
);

CREATE INDEX ON assertion (node_id) WHERE retracted_at IS NULL AND superseded_at IS NULL;
CREATE INDEX ON assertion (edge_id) WHERE retracted_at IS NULL AND superseded_at IS NULL;
CREATE INDEX ON assertion (source_id);
CREATE INDEX ON assertion (document_id);

-- Competing hypotheses. ACH is how you stop the graph becoming a
-- monument to the first theory someone had.
CREATE TABLE hypothesis (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      uuid NOT NULL REFERENCES "case"(id),
  statement    text NOT NULL,
  confidence   analytic_confidence NOT NULL DEFAULT 'LOW',
  status       review_state NOT NULL DEFAULT 'PROPOSED',
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hypothesis_evidence (
  hypothesis_id uuid NOT NULL REFERENCES hypothesis(id) ON DELETE CASCADE,
  assertion_id  uuid NOT NULL REFERENCES assertion(id),
  -- Diagnosticity: does this evidence discriminate between hypotheses?
  stance        smallint NOT NULL CHECK (stance IN (-2,-1,0,1,2)),
  note          text,
  PRIMARY KEY (hypothesis_id, assertion_id)
);

-- ---------------------------------------------------------------------
-- 6. EVIDENCE  — chain of custody
-- ---------------------------------------------------------------------

CREATE TABLE evidence (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  title           text NOT NULL,
  description     text,
  media_type      text NOT NULL,
  byte_size       bigint NOT NULL,
  -- Integrity. sha256 at ingest, never recomputed from a mutated copy.
  sha256          bytea NOT NULL,
  blake3          bytea,
  -- WORM object store key. Object-lock retention set at PUT time.
  storage_key     text NOT NULL,
  storage_bucket  text NOT NULL,
  is_worm_locked  boolean NOT NULL DEFAULT true,
  -- Acquisition context — the questions a defence team will ask.
  acquired_at     timestamptz NOT NULL,
  acquired_by     uuid NOT NULL,
  acquisition_method text NOT NULL,        -- MANUAL_UPLOAD, COLLECTOR, LEGAL
  source_url       text,
  collection_account_id uuid,              -- which persona captured it
  collection_run_id     uuid,
  classification  tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  -- Derived, searchable text. Original bytes are never modified.
  extracted_text  text,
  extract_status  text NOT NULL DEFAULT 'PENDING',
  search_tsv      tsvector,
  created_at      timestamptz NOT NULL DEFAULT now(),
  legal_hold      boolean NOT NULL DEFAULT false,
  retention_until date,
  UNIQUE (case_id, sha256)                 -- dedupe within a case
);

CREATE INDEX ON evidence USING gin (search_tsv);
CREATE INDEX ON evidence (sha256);         -- cross-case artefact pivot
CREATE INDEX ON evidence (case_id, acquired_at DESC);

-- Append-only, hash-chained custody ledger. Every touch, including reads.
-- actor_id FK to iam.app_user is added in the deferred-FK section (Alembic
-- 0024). prev_hash/row_hash + the chain trigger make deletion/back-dating
-- detectable (mirror of 0024).
CREATE TABLE evidence_custody (
  id           bigserial PRIMARY KEY,
  evidence_id  uuid NOT NULL REFERENCES evidence(id),
  action       text NOT NULL,              -- ACQUIRED, VIEWED, EXPORTED, HASH_VERIFIED
  actor_id     uuid NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now(),  -- server-pinned by the trigger
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  hash_verified boolean,
  prev_hash    bytea,
  row_hash     bytea NOT NULL
);
CREATE INDEX ON evidence_custody (evidence_id, occurred_at);

CREATE OR REPLACE FUNCTION core.custody_chain_hash() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  NEW.occurred_at := now();  -- server-pinned; any caller value is ignored
  PERFORM pg_advisory_xact_lock(hashtextextended('core.evidence_custody.chain', 0));
  SELECT row_hash INTO prev FROM core.evidence_custody ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    convert_to(concat_ws(chr(31),
      coalesce(encode(prev,'hex'),'GENESIS'),
      NEW.evidence_id::text, NEW.action, coalesce(NEW.actor_id::text,'-'),
      to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      NEW.detail::text, coalesce(NEW.hash_verified::text,'-')
    ), 'UTF8'), 'sha256');
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = public, pg_catalog;

CREATE TRIGGER custody_chain BEFORE INSERT ON core.evidence_custody
  FOR EACH ROW EXECUTE FUNCTION core.custody_chain_hash();

-- Append-only chain of custody (mirror of Alembic 0023). No UPDATE/DELETE:
-- a doctorable custody log fails the evidence at trial (FRE 902(13)-(14);
-- Canada Evidence Act ss. 31.1-31.8).
CREATE FUNCTION core.block_custody_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'evidence_custody is append-only (chain of custody)';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER evidence_custody_append_only
  BEFORE UPDATE OR DELETE ON core.evidence_custody
  FOR EACH ROW EXECUTE FUNCTION core.block_custody_mutation();
CREATE TRIGGER evidence_custody_no_truncate
  BEFORE TRUNCATE ON core.evidence_custody
  FOR EACH STATEMENT EXECUTE FUNCTION core.block_custody_mutation();

-- Evidence attaches to any number of nodes/edges. This is the
-- "upload evidence against the group AND the actor" requirement.
CREATE TABLE evidence_link (
  evidence_id  uuid NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  node_id      uuid REFERENCES node(id),
  edge_id      uuid REFERENCES edge(id),
  relevance    text,
  page_ref     text,                       -- page / timestamp / line anchor
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT evlink_one_target CHECK (num_nonnulls(node_id, edge_id) = 1)
);
CREATE INDEX ON evidence_link (node_id);
CREATE INDEX ON evidence_link (edge_id);

-- ---------------------------------------------------------------------
-- 7. TAGGING
-- ---------------------------------------------------------------------

CREATE TABLE tag (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id     uuid REFERENCES "case"(id),   -- NULL = global taxonomy
  namespace   text NOT NULL,                -- 'ttp','role','priority','mitre'
  name        text NOT NULL,
  colour      text,
  description text,
  parent_id   uuid REFERENCES tag(id),      -- hierarchical taxonomies
  external_id text                          -- e.g. MITRE ATT&CK T1566
);

-- Expression-based uniqueness must be an index, not a table constraint.
-- Two indexes because NULL case_id (global taxonomy) needs its own rule.
CREATE UNIQUE INDEX tag_uniq_case   ON tag (case_id, namespace, name) WHERE case_id IS NOT NULL;
CREATE UNIQUE INDEX tag_uniq_global ON tag (namespace, name)          WHERE case_id IS NULL;

CREATE TABLE tag_assignment (
  tag_id      uuid NOT NULL REFERENCES tag(id) ON DELETE CASCADE,
  node_id     uuid REFERENCES node(id),
  edge_id     uuid REFERENCES edge(id),
  evidence_id uuid REFERENCES evidence(id),
  document_id uuid,
  assigned_by uuid NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tag_one_target CHECK (num_nonnulls(node_id, edge_id, evidence_id, document_id) = 1)
);
CREATE INDEX ON tag_assignment (node_id);
CREATE INDEX ON tag_assignment (tag_id);

-- Ad-hoc analyst groupings that are NOT ontological claims. Keeps
-- working sets out of the graph where they would distort metrics.
CREATE TABLE node_set (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id    uuid NOT NULL REFERENCES "case"(id),
  name       text NOT NULL,
  purpose    text,
  is_pinned  boolean NOT NULL DEFAULT false,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE node_set_member (
  set_id  uuid NOT NULL REFERENCES node_set(id) ON DELETE CASCADE,
  node_id uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  note    text,
  PRIMARY KEY (set_id, node_id)
);

-- =====================================================================
-- COLLECTION
-- =====================================================================
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

-- THE AGGREGATION BUCKET. One row per captured item.
CREATE TABLE document (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id      uuid NOT NULL REFERENCES source(id),
  collection_run_id uuid REFERENCES collection_run(id),
  watch_id       uuid REFERENCES watch(id),
  -- Stable platform identity, so an edited post updates rather than
  -- duplicating, while old versions are retained.
  external_id    text,
  external_url   text,
  thread_ref     text,
  parent_ref     text,
  author_handle  text,
  author_uid     text,                     -- numeric platform id, not the name
  posted_at      timestamptz,
  captured_at    timestamptz NOT NULL DEFAULT now(),
  title          text,
  body_text      text NOT NULL,
  body_html_key  text,                     -- raw HTML in object store
  lang           text,
  content_sha256 bytea NOT NULL,
  -- Edit tracking
  version        int NOT NULL DEFAULT 1,
  supersedes_id  uuid REFERENCES document(id),
  is_deleted_upstream boolean NOT NULL DEFAULT false,
  classification tlp NOT NULL DEFAULT 'AMBER',
  search_tsv     tsvector,
  embedding      vector(768),
  triage_state   text NOT NULL DEFAULT 'NEW',  -- NEW|TRIAGED|LINKED|DISCARDED
  UNIQUE (source_id, external_id, version)
);

CREATE INDEX ON document USING gin (search_tsv);
CREATE INDEX ON document USING hnsw (embedding vector_cosine_ops);
CREATE INDEX ON document (source_id, posted_at DESC);
CREATE INDEX ON document (content_sha256);
CREATE INDEX ON document (triage_state) WHERE triage_state = 'NEW';
CREATE INDEX ON document USING gin (author_handle gin_trgm_ops);

-- Selectors/entities pulled out of documents by extractors.
CREATE TABLE extraction (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id   uuid NOT NULL REFERENCES document(id) ON DELETE CASCADE,
  selector_type text NOT NULL REFERENCES selector_type(key),
  raw_value     text NOT NULL,
  norm_value    text NOT NULL,
  char_start    int,
  char_end      int,
  extractor     text NOT NULL,
  extractor_version text,
  score         numeric(4,3),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON extraction (norm_value, selector_type);
CREATE INDEX ON extraction (document_id);

-- Extractions become graph changes ONLY through an approved proposal.
-- Machines propose; analysts dispose.
CREATE TABLE proposal (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       uuid NOT NULL REFERENCES "case"(id),
  kind          text NOT NULL,             -- CREATE_NODE|CREATE_EDGE|MERGE|ATTR
  payload       jsonb NOT NULL,
  origin        text NOT NULL,             -- extractor / rule / model name
  score         numeric(4,3),
  rationale     text NOT NULL,
  document_id   uuid REFERENCES document(id),
  state         review_state NOT NULL DEFAULT 'PROPOSED',
  reviewed_by   uuid,
  reviewed_at   timestamptz,
  review_note   text,
  applied_node_id uuid REFERENCES node(id),
  applied_edge_id uuid REFERENCES edge(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON proposal (case_id, state) WHERE state = 'PROPOSED';

CREATE TABLE watch_hit (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  watch_id     uuid NOT NULL REFERENCES watch(id) ON DELETE CASCADE,
  document_id  uuid NOT NULL REFERENCES document(id) ON DELETE CASCADE,
  matched_on   jsonb NOT NULL,             -- {keywords:[...], selectors:[...]}
  score        numeric(4,3),
  created_at   timestamptz NOT NULL DEFAULT now(),
  -- Notification lifecycle
  notified_at  timestamptz,
  suppressed   boolean NOT NULL DEFAULT false,
  suppress_reason text,
  acknowledged_by uuid,
  acknowledged_at timestamptz,
  UNIQUE (watch_id, document_id)
);
CREATE INDEX ON watch_hit (created_at DESC) WHERE notified_at IS NULL AND NOT suppressed;

-- =====================================================================
-- IAM
-- =====================================================================
SET search_path = iam, core, public;

CREATE TABLE app_user (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           citext UNIQUE NOT NULL,
  display_name    text NOT NULL,
  password_hash   text,                    -- argon2id
  is_active       boolean NOT NULL DEFAULT true,
  -- Clearance ceiling. A user can never see above this, whatever their
  -- case assignment says.
  tlp_clearance   tlp NOT NULL DEFAULT 'GREEN',
  compartments    text[] NOT NULL DEFAULT '{}',
  -- MFA. TOTP as the floor, WebAuthn preferred.
  totp_secret_ciphertext bytea,
  totp_key_id     text,
  totp_enrolled_at timestamptz,
  mfa_required    boolean NOT NULL DEFAULT true,
  recovery_codes_hash text[],
  failed_logins   int NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  last_login_at   timestamptz,
  password_changed_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  deactivated_at  timestamptz
);

CREATE TABLE webauthn_credential (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  credential_id  bytea UNIQUE NOT NULL,
  public_key     bytea NOT NULL,
  sign_count     bigint NOT NULL DEFAULT 0,
  aaguid         uuid,
  transports     text[],
  nickname       text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz
);

CREATE TABLE role (
  key         text PRIMARY KEY,
  display_name text NOT NULL,
  description text,
  is_system   boolean NOT NULL DEFAULT false
);

CREATE TABLE permission (
  key         text PRIMARY KEY,            -- 'case.read','graph.merge','evidence.export'
  description text NOT NULL,
  -- Ops that demand a fresh MFA challenge regardless of session age.
  requires_step_up boolean NOT NULL DEFAULT false,
  -- Ops that need a second authoriser.
  requires_dual_control boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permission (
  role_key       text NOT NULL REFERENCES role(key) ON DELETE CASCADE,
  permission_key text NOT NULL REFERENCES permission(key) ON DELETE CASCADE,
  PRIMARY KEY (role_key, permission_key)
);

CREATE TABLE user_role (
  user_id  uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_key text NOT NULL REFERENCES role(key),
  PRIMARY KEY (user_id, role_key)
);

-- ABAC layer: role grants the verb, assignment grants the row.
CREATE TABLE case_assignment (
  case_id     uuid NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_key    text NOT NULL REFERENCES role(key),
  granted_by  uuid NOT NULL,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,                 -- time-boxed access by default
  PRIMARY KEY (case_id, user_id)
);
-- now() is STABLE, not IMMUTABLE, so "currently active" cannot live in a
-- partial-index predicate; index both columns and filter at query time.
CREATE INDEX ON case_assignment (user_id, expires_at);

-- Emergency access. Always allowed, always loud.
CREATE TABLE break_glass (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES app_user(id),
  case_id      uuid REFERENCES "case"(id),
  justification text NOT NULL,
  started_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  reviewed_by  uuid,
  reviewed_at  timestamptz,
  review_outcome text
);

CREATE TABLE dual_control_request (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action        text NOT NULL,
  payload       jsonb NOT NULL,
  requested_by  uuid NOT NULL REFERENCES app_user(id),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  approved_by   uuid REFERENCES app_user(id),
  approved_at   timestamptz,
  executed_at   timestamptz,
  state         text NOT NULL DEFAULT 'PENDING',
  CONSTRAINT dual_control_distinct CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE TABLE session (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash    bytea NOT NULL UNIQUE,
  issued_at     timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  last_seen_at  timestamptz,
  ip_hash       bytea,                     -- hashed, not stored raw
  user_agent    text,
  mfa_satisfied_at timestamptz,            -- step-up freshness clock
  revoked_at    timestamptz,
  revoke_reason text
);
CREATE INDEX ON session (user_id) WHERE revoked_at IS NULL;

-- =====================================================================
-- AUDIT  — append-only, hash-chained, nobody can delete
-- =====================================================================
SET search_path = audit, core, public;

CREATE TABLE event (
  seq          bigserial PRIMARY KEY,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  actor_id     uuid,
  actor_kind   text NOT NULL DEFAULT 'USER',  -- USER|SERVICE|SYSTEM
  action       text NOT NULL,
  object_type  text,
  object_id    uuid,
  case_id      uuid,
  outcome      text NOT NULL DEFAULT 'SUCCESS',
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_hash      bytea,
  session_id   uuid,
  -- Tamper evidence: each row hashes the previous row's hash.
  prev_hash    bytea,
  row_hash     bytea NOT NULL
);
CREATE INDEX ON event (occurred_at DESC);
CREATE INDEX ON event (actor_id, occurred_at DESC);
CREATE INDEX ON event (object_id);
CREATE INDEX ON event (case_id, occurred_at DESC);

-- The REVOKE below is documentation only (PUBLIC holds no DML by default;
-- the table owner is unaffected). The trigger is the enforcement: no code
-- path, migration or admin tool mutates history without first being seen
-- to drop the trigger. Invariant 6.
REVOKE UPDATE, DELETE, TRUNCATE ON audit.event FROM PUBLIC;

CREATE FUNCTION audit.block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit.event is append-only (invariant 6)';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.block_mutation();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event
  FOR EACH STATEMENT EXECUTE FUNCTION audit.block_mutation();

-- =====================================================================
-- ANALYTICS  — SNA metric materialisation
-- =====================================================================
SET search_path = analytics, core, public;

-- A named, reproducible view of the graph. Metrics are always computed
-- against a projection, never "the graph" in the abstract, because
-- filters change every number.
CREATE TABLE projection (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id       uuid NOT NULL REFERENCES "case"(id),
  name          text NOT NULL,
  -- Which edge types count, whether inferred edges are included, the
  -- time window, minimum confidence. Reproducibility depends on this.
  edge_types    text[] NOT NULL,
  include_inferred boolean NOT NULL DEFAULT false,
  min_confidence analytic_confidence NOT NULL DEFAULT 'LOW',
  as_of_from    timestamptz,
  as_of_to      timestamptz,
  is_directed   boolean NOT NULL DEFAULT true,
  preset        text,                      -- trust | communication | financial | all
  -- Remaining parameters that change the numbers, notably the trust-decay
  -- half-life: it reweights every edge, so it must be pinned here or the
  -- results are not reproducible.
  params        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by    uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
-- A name identifies a parameter set within a case, so a metric run upserts
-- its projection rather than accumulating a row per request.
CREATE UNIQUE INDEX projection_case_name_uk ON projection (case_id, name);

CREATE TABLE metric_run (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  projection_id uuid NOT NULL REFERENCES projection(id) ON DELETE CASCADE,
  algorithm     text NOT NULL,             -- sna_suite, kpp_neg...
  params        jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Approximation flag: betweenness on a big graph is sampled, and the
  -- UI must say so rather than implying exactness.
  is_approximate boolean NOT NULL DEFAULT false,
  sample_size   int,
  node_count    int,
  edge_count    int,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  duration_ms   int,
  graph_hash    bytea,                     -- cache key; skip if unchanged
  status        text NOT NULL DEFAULT 'RUNNING',
  -- Graph-level results: structural balance, unbalanced triads, cut
  -- vertices, bridges, components, and the key-player removal set with its
  -- fragmentation preview. These are properties of the graph, so they fit
  -- neither node_metric nor community_assignment.
  result        jsonb NOT NULL DEFAULT '{}'::jsonb,
  error         text,
  created_by    uuid,
  -- Cache safety. project() filters by the CALLER's clearance and
  -- compartments, so metrics differ between analysts. graph_hash is taken
  -- over the caller-VISIBLE edge list, so visibility already partitions the
  -- cache; these columns record that scoping explicitly so the lookup can
  -- filter on it too. Serving an AMBER analyst a score computed over RED
  -- nodes would leak the structure of nodes they may not see.
  --
  -- NOT NULL with NO DEFAULT deliberately: '{}' is what an analyst holding
  -- no compartments looks up with, so a default would turn a forgotten
  -- write into a silent fail-OPEN rather than a loud insert failure.
  visibility_clearance    core.tlp NOT NULL,
  visibility_compartments text[] NOT NULL,
  CONSTRAINT metric_run_status_ck
    CHECK (status IN ('RUNNING', 'COMPLETE', 'FAILED')),
  -- A crashed run must not sit at 'RUNNING' forever reading as "still
  -- working" (invariant 12: nothing is silently dropped).
  CONSTRAINT metric_run_failed_explains_itself_ck
    CHECK ((status = 'FAILED') = (error IS NOT NULL))
);
CREATE INDEX metric_run_cache_idx
    ON metric_run (projection_id, algorithm, graph_hash,
                   visibility_clearance, started_at DESC)
 WHERE status = 'COMPLETE';

CREATE TABLE node_metric (
  metric_run_id uuid NOT NULL REFERENCES metric_run(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  metric        text NOT NULL,
  value         double precision NOT NULL,
  rank          int,
  percentile    numeric(5,2),
  PRIMARY KEY (metric_run_id, node_id, metric)
);
CREATE INDEX ON node_metric (node_id, metric);

CREATE TABLE community_assignment (
  metric_run_id uuid NOT NULL REFERENCES metric_run(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  community_id  int NOT NULL,
  membership_strength numeric(5,4),
  PRIMARY KEY (metric_run_id, node_id)
);

-- Saved layouts, so an analyst's mental map of the network survives
-- a page reload. Underrated: people navigate these graphs spatially.
CREATE TABLE layout_position (
  projection_id uuid NOT NULL REFERENCES projection(id) ON DELETE CASCADE,
  node_id       uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
  x             double precision NOT NULL,
  y             double precision NOT NULL,
  is_pinned     boolean NOT NULL DEFAULT false,
  PRIMARY KEY (projection_id, node_id)
);

-- =====================================================================
-- DEFERRED FOREIGN KEYS
-- These cross schema-creation order (core references collect, and vice
-- versa), so they are added last rather than restructuring the file.
-- =====================================================================
SET search_path = core, public;

ALTER TABLE core.assertion
  ADD CONSTRAINT assertion_source_fk   FOREIGN KEY (source_id)   REFERENCES collect.source(id),
  ADD CONSTRAINT assertion_document_fk FOREIGN KEY (document_id) REFERENCES collect.document(id),
  ADD CONSTRAINT assertion_evidence_fk FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

ALTER TABLE core.evidence
  ADD CONSTRAINT evidence_collection_account_fk FOREIGN KEY (collection_account_id)
      REFERENCES collect.collection_account(id),
  ADD CONSTRAINT evidence_collection_run_fk FOREIGN KEY (collection_run_id)
      REFERENCES collect.collection_run(id);

ALTER TABLE core.tag_assignment
  ADD CONSTRAINT tag_assignment_document_fk FOREIGN KEY (document_id)
      REFERENCES collect.document(id) ON DELETE CASCADE;

ALTER TABLE collect.collection_account
  ADD CONSTRAINT collection_account_egress_fk FOREIGN KEY (egress_profile_id)
      REFERENCES collect.egress_profile(id);

-- User FKs. Deliberately NOT ON DELETE CASCADE anywhere: users are
-- deactivated, never deleted, because their name is on the audit trail
-- and on the custody record.
ALTER TABLE core."case"
  ADD CONSTRAINT case_owner_fk  FOREIGN KEY (owner_user_id)  REFERENCES iam.app_user(id),
  ADD CONSTRAINT case_deputy_fk FOREIGN KEY (deputy_user_id) REFERENCES iam.app_user(id);

ALTER TABLE core.node
  ADD CONSTRAINT node_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.edge
  ADD CONSTRAINT edge_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.assertion
  ADD CONSTRAINT assertion_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.evidence
  ADD CONSTRAINT evidence_acquired_by_fk FOREIGN KEY (acquired_by) REFERENCES iam.app_user(id);

ALTER TABLE core.evidence_custody
  ADD CONSTRAINT evidence_custody_actor_fk FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

-- =====================================================================
-- SEARCH VECTOR MAINTENANCE
-- Generated columns would be cleaner, but tsvector generation over
-- jsonb is not immutable, so triggers it is.
-- =====================================================================
CREATE OR REPLACE FUNCTION core.node_tsv_update() RETURNS trigger AS $$
BEGIN
  -- Recompute only when the indexed text changed; bookkeeping updates
  -- (last_seen, soft delete, merge) must not churn the GIN index.
  -- left() caps the input: to_tsvector rejects >1MB vectors, and a
  -- failed capture is worse than truncated search.
  IF TG_OP = 'INSERT' OR NEW.label IS DISTINCT FROM OLD.label
     OR NEW.attrs IS DISTINCT FROM OLD.attrs THEN
    NEW.search_tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.label,'')), 'A')
     || setweight(to_tsvector('simple', left(coalesce(NEW.attrs::text,''), 500000)), 'C');
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER node_tsv BEFORE INSERT OR UPDATE ON core.node
  FOR EACH ROW EXECUTE FUNCTION core.node_tsv_update();

CREATE OR REPLACE FUNCTION collect.document_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.search_tsv :=
      setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
   || setweight(to_tsvector('simple', coalesce(NEW.author_handle,'')), 'B')
   -- Capped: combo lists / credential dumps exceed the 1MB tsvector limit
   -- and must land with degraded search rather than fail to land at all.
   || setweight(to_tsvector('simple', left(coalesce(NEW.body_text,''), 500000)), 'C');
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER document_tsv BEFORE INSERT OR UPDATE ON collect.document
  FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();

-- Evidence full-text (mirror of Alembic 0025): title (A) + description (B)
-- + extracted_text (C, capped like the others).
CREATE OR REPLACE FUNCTION core.evidence_tsv_update() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT'
     OR NEW.title IS DISTINCT FROM OLD.title
     OR NEW.description IS DISTINCT FROM OLD.description
     OR NEW.extracted_text IS DISTINCT FROM OLD.extracted_text THEN
    NEW.search_tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
     || setweight(to_tsvector('simple', coalesce(NEW.description,'')), 'B')
     || setweight(to_tsvector('simple', left(coalesce(NEW.extracted_text,''), 500000)), 'C');
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_tsv BEFORE INSERT OR UPDATE ON core.evidence
  FOR EACH ROW EXECUTE FUNCTION core.evidence_tsv_update();

-- =====================================================================
-- EDGE TYPE VALIDATION
-- Stops the graph turning to soup. An edge whose endpoints violate the
-- ontology is a modelling error, and modelling errors compound.
-- =====================================================================
CREATE OR REPLACE FUNCTION core.validate_edge_endpoints() RETURNS trigger AS $$
DECLARE
  et      RECORD;
  src_ty  text;
  dst_ty  text;
BEGIN
  NEW.updated_at := now();
  -- Endpoints unchanged → nothing to re-validate. Without this, narrowing
  -- an edge_type's allowed endpoints later makes existing nonconforming
  -- edges un-updatable — including the soft delete that removes them.
  IF TG_OP = 'UPDATE' AND NEW.edge_type = OLD.edge_type
     AND NEW.src_node_id = OLD.src_node_id AND NEW.dst_node_id = OLD.dst_node_id
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT * INTO et FROM core.edge_type WHERE key = NEW.edge_type;
  SELECT node_type INTO src_ty FROM core.node WHERE id = NEW.src_node_id;
  SELECT node_type INTO dst_ty FROM core.node WHERE id = NEW.dst_node_id;

  IF NOT (src_ty = ANY(et.src_node_types)) THEN
    RAISE EXCEPTION 'edge %: source node type % not permitted (allowed: %)',
      NEW.edge_type, src_ty, et.src_node_types;
  END IF;
  IF NOT (dst_ty = ANY(et.dst_node_types)) THEN
    RAISE EXCEPTION 'edge %: target node type % not permitted (allowed: %)',
      NEW.edge_type, dst_ty, et.dst_node_types;
  END IF;

  -- SAME_AS is unconfidenced identity-equivalence plumbing; letting it
  -- cross the IDENTITY/PERSON layer hard-codes an attribution as a fact.
  -- The cross-layer join is exclusively ATTRIBUTED_TO (invariant 2).
  IF NEW.edge_type = 'SAME_AS' AND src_ty <> dst_ty THEN
    RAISE EXCEPTION 'SAME_AS may not cross the IDENTITY/PERSON layer (attribution is ATTRIBUTED_TO)';
  END IF;

  -- Cross-case edges are never legitimate. Cross-case *pivoting* happens
  -- through selector matching and an access request, not by drawing an
  -- edge that would leak one case's structure into another.
  IF (SELECT case_id FROM core.node WHERE id = NEW.src_node_id) <> NEW.case_id
     OR (SELECT case_id FROM core.node WHERE id = NEW.dst_node_id) <> NEW.case_id THEN
    RAISE EXCEPTION 'edge % spans cases', NEW.edge_type;
  END IF;

  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER edge_validate BEFORE INSERT OR UPDATE ON core.edge
  FOR EACH ROW EXECUTE FUNCTION core.validate_edge_endpoints();

-- =====================================================================
-- CLASSIFICATION INHERITANCE
-- A child may be more restricted than its case, never less.
-- =====================================================================
CREATE OR REPLACE FUNCTION core.enforce_tlp_floor() RETURNS trigger AS $$
DECLARE case_tlp core.tlp;
BEGIN
  -- Bookkeeping updates that touch neither classification nor case must
  -- not re-run the floor check: if a case's floor is raised later,
  -- pre-existing rows would otherwise be un-updatable — including the
  -- very UPDATE that would remediate their classification. INSERTs and
  -- classification changes are always checked.
  IF TG_OP = 'UPDATE' AND NEW.classification = OLD.classification
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT classification INTO case_tlp FROM core."case" WHERE id = NEW.case_id;
  IF NEW.classification < case_tlp THEN
    RAISE EXCEPTION 'classification % is below the case floor of %',
      NEW.classification, case_tlp;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER node_tlp     BEFORE INSERT OR UPDATE ON core.node     FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
CREATE TRIGGER edge_tlp     BEFORE INSERT OR UPDATE ON core.edge     FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
CREATE TRIGGER evidence_tlp BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

-- =====================================================================
-- INVARIANT 1 — NOTHING IS A FACT (mirror of Alembic 0022)
-- A node or edge must trace to >=1 assertion ROW at ALL times. Symmetric
-- deferred constraint triggers: one rejects committing an element with no
-- assertion; one rejects deleting/repointing the LAST assertion of a
-- still-existing element (closing the SET CONSTRAINTS timing game and the
-- later-transaction delete). Retraction/supersede are row-preserving
-- UPDATEs of retracted_at/superseded_at, so they never fire trigger 2 —
-- LIVE provenance is a projection property, not write-enforced.
-- =====================================================================
CREATE OR REPLACE FUNCTION core.require_node_assertion() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM core.node WHERE id = NEW.id) THEN
    RETURN NULL;                      -- removed within this same transaction
  END IF;
  IF NOT EXISTS (SELECT 1 FROM core.assertion WHERE node_id = NEW.id) THEN
    RAISE EXCEPTION
      'invariant 1: node % committed without a supporting assertion', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.require_edge_assertion() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM core.edge WHERE id = NEW.id) THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM core.assertion WHERE edge_id = NEW.id) THEN
    RAISE EXCEPTION
      'invariant 1: edge % committed without a supporting assertion', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE CONSTRAINT TRIGGER node_requires_assertion
  AFTER INSERT ON core.node
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.require_node_assertion();

CREATE CONSTRAINT TRIGGER edge_requires_assertion
  AFTER INSERT ON core.edge
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.require_edge_assertion();

CREATE OR REPLACE FUNCTION core.assertion_protects_element() RETURNS trigger AS $$
BEGIN
  IF OLD.node_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM core.node WHERE id = OLD.node_id)
     AND NOT EXISTS (SELECT 1 FROM core.assertion WHERE node_id = OLD.node_id) THEN
    RAISE EXCEPTION
      'invariant 1: last assertion for node % may not be removed (retract or supersede instead)',
      OLD.node_id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.edge_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM core.edge WHERE id = OLD.edge_id)
     AND NOT EXISTS (SELECT 1 FROM core.assertion WHERE edge_id = OLD.edge_id) THEN
    RAISE EXCEPTION
      'invariant 1: last assertion for edge % may not be removed (retract or supersede instead)',
      OLD.edge_id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE CONSTRAINT TRIGGER assertion_protects_element
  AFTER DELETE OR UPDATE OF node_id, edge_id ON core.assertion
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.assertion_protects_element();

-- =====================================================================
-- AUDIT HASH CHAIN
-- Each row commits to the previous one. Deletion or edit of history
-- becomes detectable by replaying the chain.
-- =====================================================================
-- search_path is pinned on the function: digest() lives in public and
-- plpgsql resolves names under the CALLER's path at runtime — a hardened
-- session (search_path = '') would otherwise abort every audited write.
CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  -- Serialise chain extension. Without this, two concurrent writers read
  -- the same tail and fork the chain — honest history then replays as
  -- tampering, the worst failure mode a tamper-evidence mechanism has.
  PERFORM pg_advisory_xact_lock(hashtextextended('audit.event.chain', 0));
  SELECT row_hash INTO prev FROM audit.event ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  -- Canonical hash input: UTC-fixed timestamp rendering (timestamptz::text
  -- follows the session TimeZone GUC and would make the chain unverifiable
  -- from any other session), EVERY payload column (an unhashed column is
  -- an editable column), and an explicit field separator (unseparated
  -- concatenation lets boundary shifts collide).
  NEW.row_hash := public.digest(
    convert_to(concat_ws(chr(31),
      coalesce(encode(prev,'hex'),'GENESIS'),
      to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      coalesce(NEW.actor_id::text,'-'),
      NEW.actor_kind,
      NEW.action,
      coalesce(NEW.object_type,'-'),
      coalesce(NEW.object_id::text,'-'),
      coalesce(NEW.case_id::text,'-'),
      NEW.outcome,
      NEW.detail::text,
      coalesce(encode(NEW.ip_hash,'hex'),'-'),
      coalesce(NEW.session_id::text,'-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = public, pg_catalog;

CREATE TRIGGER audit_chain BEFORE INSERT ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.chain_hash();

-- NOTE: the advisory lock serialises audit writes under contention. At
-- high volume, move chaining to a single-threaded appender or batch-chain
-- every N rows with a periodic checkpoint hash. Correctness first.
