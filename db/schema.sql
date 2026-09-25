-- =====================================================================
-- NocTORnal -- db/schema.sql
--
-- GENERATED MIRROR of the schema at Alembic revision 0124.
-- Produced by scripts/dump_schema.py from
--   pg_dump --schema-only --no-owner --no-privileges
-- with session SET lines, version comments and pg_dump's per-run
-- \restrict tokens removed. DO NOT EDIT BY HAND: the authoritative
-- schema is the Alembic chain in db/migrations/versions/, every change
-- lands there as a new revision, and this file is regenerated with
--
--   python scripts/dump_schema.py
--
-- against a database at head. CI regenerates it and fails on any
-- difference (.github/workflows/ci.yml, "Schema mirror matches the
-- migrations"), and apps/api/tests/test_schema_mirror.py holds the
-- revision below to the chain's head. The commentary on WHY each table
-- is shaped as it is lives in the migration that created it; a dump
-- cannot carry it, and until 2026-09-09 the hand-written commentary
-- here described five of the ten schemas.
--
-- Read docs/01-domain-model.md alongside this. The five commitments
-- the migrations encode: nothing is a fact (every element has an
-- assertion -- constraint triggers in 0022); a handle is not a person
-- (IDENTITY and PERSON are separate node types); bitemporal history is
-- superseded, never overwritten; edges are signed and time-bounded;
-- the ontology lives in reference tables, not enums.
--
-- Alembic revision: 0124
-- =====================================================================

--
-- PostgreSQL database dump
--

--
-- Name: analytics; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA analytics;

--
-- Name: audit; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA audit;

--
-- Name: collect; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA collect;

--
-- Name: comms; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA comms;

--
-- Name: core; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA core;

--
-- Name: deception; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA deception;

--
-- Name: iam; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA iam;

--
-- Name: ingest; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA ingest;

--
-- Name: lab; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA lab;

--
-- Name: notify; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA notify;

--
-- Name: btree_gist; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;

--
-- Name: EXTENSION btree_gist; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION btree_gist IS 'support for indexing common datatypes in GiST';

--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

--
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';

--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;

--
-- Name: EXTENSION vector; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';

--
-- Name: run_status; Type: TYPE; Schema: collect; Owner: -
--

CREATE TYPE collect.run_status AS ENUM (
    'QUEUED',
    'RUNNING',
    'OK',
    'PARTIAL',
    'FAILED',
    'BLOCKED',
    'RATE_LIMITED'
);

--
-- Name: source_kind; Type: TYPE; Schema: collect; Owner: -
--

CREATE TYPE collect.source_kind AS ENUM (
    'RSS',
    'XENFORO',
    'MYBB',
    'PHPBB',
    'TELEGRAM',
    'DISCORD',
    'PASTE',
    'WEB',
    'MANUAL',
    'VENDOR_API'
);

--
-- Name: analytic_confidence; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.analytic_confidence AS ENUM (
    'LOW',
    'MODERATE',
    'HIGH'
);

--
-- Name: assertion_basis; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.assertion_basis AS ENUM (
    'DIRECT_OBSERVATION',
    'THIRD_PARTY_REPORT',
    'ANALYST_INFERENCE',
    'AUTOMATED_INFERENCE',
    'SELF_CLAIM',
    'LEGAL_PROCESS'
);

--
-- Name: case_status; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.case_status AS ENUM (
    'DRAFT',
    'ACTIVE',
    'DORMANT',
    'CLOSED',
    'ARCHIVED',
    'PURGED'
);

--
-- Name: info_credibility; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.info_credibility AS ENUM (
    '1',
    '2',
    '3',
    '4',
    '5',
    '6'
);

--
-- Name: review_state; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.review_state AS ENUM (
    'PROPOSED',
    'ACCEPTED',
    'REJECTED',
    'SUPERSEDED',
    'DISPUTED'
);

--
-- Name: source_reliability; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.source_reliability AS ENUM (
    'A',
    'B',
    'C',
    'D',
    'E',
    'F'
);

--
-- Name: tlp; Type: TYPE; Schema: core; Owner: -
--

CREATE TYPE core.tlp AS ENUM (
    'CLEAR',
    'GREEN',
    'AMBER',
    'AMBER_STRICT',
    'RED'
);

--
-- Name: sample_state; Type: TYPE; Schema: lab; Owner: -
--

CREATE TYPE lab.sample_state AS ENUM (
    'SUBMITTED',
    'QUARANTINED',
    'TRIAGED',
    'ASSIGNED',
    'IN_ANALYSIS',
    'REPORTED',
    'REJECTED'
);

--
-- Name: block_mutation(); Type: FUNCTION; Schema: audit; Owner: -
--

CREATE FUNCTION audit.block_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'audit.event is append-only (invariant 6)';
END $$;

--
-- Name: chain_hash(); Type: FUNCTION; Schema: audit; Owner: -
--

CREATE FUNCTION audit.chain_hash() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
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
END $$;

--
-- Name: authority_target_fits(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.authority_target_fits() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  src record;
  auth record;
BEGIN
  SELECT classification, collection_account_id, base_url, egress_profile_id
    INTO src FROM collect.source WHERE id = NEW.source_id;
  SELECT classification, collection_account_id
    INTO auth FROM collect.collection_authority WHERE id = NEW.authority_id;
  IF src.classification > auth.classification THEN
    RAISE EXCEPTION USING MESSAGE =
      'an authority is never labelled below a source it covers: raise its classification first';
  END IF;
  IF src.collection_account_id IS DISTINCT FROM auth.collection_account_id THEN
    RAISE EXCEPTION USING MESSAGE =
      'this source is read through a different binding than the one this authority covers';
  END IF;
  NEW.target_base_url := src.base_url;
  NEW.target_egress_profile_id :=
    CASE WHEN auth.collection_account_id IS NULL
         THEN src.egress_profile_id ELSE NULL END;
  RETURN NEW;
END
$$;

--
-- Name: document_embedding_labels(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.document_embedding_labels() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  d_cls core.tlp;
  d_comp text[];
  d_purged timestamptz;
  s_cls core.tlp;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    -- The compartment lifecycle's rename replaces a key in place and
    -- changes nothing else (docs/05, rule 5); anything else is refused.
    IF NEW.document_id IS DISTINCT FROM OLD.document_id
       OR NEW.read_classification IS DISTINCT FROM OLD.read_classification
       OR cardinality(NEW.read_compartments)
          IS DISTINCT FROM cardinality(OLD.read_compartments) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'a vector row keeps the document and labels it was written with: a '
        'change to its document deletes it instead';
    END IF;
    RETURN NEW;
  END IF;
  SELECT d.classification, d.compartments, d.purged_at, s.classification
    INTO d_cls, d_comp, d_purged, s_cls
    FROM collect.document d JOIN collect.source s ON s.id = d.source_id
   WHERE d.id = NEW.document_id
     FOR SHARE OF d, s;
  IF NOT FOUND OR d_purged IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its document, and this document is missing or purged';
  END IF;
  NEW.read_classification := greatest(d_cls, s_cls);
  NEW.read_compartments := coalesce(
    (SELECT array_agg(DISTINCT x ORDER BY x) FROM unnest(d_comp) AS x),
    '{}'::text[]);
  RETURN NEW;
END $$;

--
-- Name: document_embedding_queued(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.document_embedding_queued() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM core.embedding_enqueue('document', NEW.id);
  RETURN NULL;
END $$;

--
-- Name: document_tsv_update(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.document_tsv_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  -- A purged document keeps its row and loses its content; its vector
  -- goes too, rather than being rebuilt from what is left (L1, 2026-09-24).
  IF NEW.purged_at IS NOT NULL THEN
    NEW.search_tsv := NULL;
    RETURN NEW;
  END IF;
  NEW.search_tsv :=
      setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
   || setweight(to_tsvector('simple', coalesce(NEW.author_handle,'')), 'B')
   -- Capped: combo lists / credential dumps exceed the 1MB tsvector limit
   -- and must land with degraded search rather than fail to land at all.
   || setweight(to_tsvector('simple', left(coalesce(NEW.body_text,''), 500000)), 'C');
  RETURN NEW;
END $$;

--
-- Name: document_vectors_follow(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.document_vectors_follow() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  DELETE FROM collect.document_embedding WHERE document_id = NEW.id;
  IF NEW.purged_at IS NULL THEN
    PERFORM core.embedding_enqueue('document', NEW.id);
  ELSE
    DELETE FROM core.embedding_pending
     WHERE kind = 'document' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

--
-- Name: egress_binding_block(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.egress_binding_block() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'collect.egress_binding is append-only: it is the history the egress proxy compares collection authorities with';
END $$;

--
-- Name: egress_connection_block(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.egress_connection_block() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'collect.egress_connection is append-only: it is the record of what left this deployment';
END $$;

--
-- Name: egress_connection_chain(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.egress_connection_chain() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('collect.egress_connection.chain', 0));
  NEW.seq := nextval('collect.egress_connection_seq');
  SELECT row_hash INTO prev FROM collect.egress_connection ORDER BY seq DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(convert_to(concat_ws(chr(31),
  coalesce(encode(prev,'hex'),'GENESIS'),
  NEW.seq::text,
  to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  NEW.event,
  coalesce(NEW.connection_id::text,'-'),
  coalesce(NEW.protocol,'-'),
  coalesce(NEW.route_kind,'-'),
  NEW.route_id,
  coalesce(NEW.peer_address::text,'-'),
  coalesce(NEW.egress_profile_id::text,'-'),
  coalesce(NEW.integration_route_id::text,'-'),
  coalesce(NEW.collection_run_id::text,'-'),
  coalesce(NEW.source_id::text,'-'),
  coalesce(NEW.collection_account_id::text,'-'),
  coalesce(NEW.authority_id::text,'-'),
  coalesce(NEW.context_kind,'-'),
  coalesce(NEW.context_id::text,'-'),
  coalesce(NEW.dest_host,'-'),
  coalesce(encode(NEW.dest_digest,'hex'),'-'),
  coalesce(NEW.dest_port::text,'-'),
  coalesce(NEW.resolved_address::text,'-'),
  coalesce(NEW.exit_kind,'-'),
  NEW.reason,
  coalesce(NEW.item_count::text,'-'),
  coalesce(NEW.bytes_up::text,'-'),
  coalesce(NEW.bytes_down::text,'-'),
  coalesce(NEW.duration_ms::text,'-'),
  NEW.classification::text,
  NEW.source_compartmented::text
), 'UTF8'), 'sha256');
  RETURN NEW;
END $$;

--
-- Name: egress_profile_reach(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.egress_profile_reach() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: egress_route_terminal(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.egress_route_terminal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: guard_collection_authority(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_collection_authority() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'collect.collection_authority is never deleted: it is the record of who allowed collection (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.collection_account_id IS DISTINCT FROM OLD.collection_account_id
     OR NEW.scope IS DISTINCT FROM OLD.scope
     OR NEW.authority_ref IS DISTINCT FROM OLD.authority_ref
     OR NEW.issued_by IS DISTINCT FROM OLD.issued_by
     OR NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction
     OR NEW.legal_basis IS DISTINCT FROM OLD.legal_basis
     OR NEW.member_authority_ref IS DISTINCT FROM OLD.member_authority_ref
     OR NEW.target_description IS DISTINCT FROM OLD.target_description
     OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
     OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
     OR NEW.recorded_by IS DISTINCT FROM OLD.recorded_by
     OR NEW.recorded_at IS DISTINCT FROM OLD.recorded_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a collection authority cannot be rewritten: revoke it and record another';
  END IF;
  IF NEW.classification < OLD.classification THEN
    RAISE EXCEPTION USING MESSAGE =
      'a collection authority''s classification only rises';
  END IF;
  IF OLD.confirmed_at IS NOT NULL
     AND (NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
          OR NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
          OR NEW.confirm_note IS DISTINCT FROM OLD.confirm_note) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a confirmed collection authority stays confirmed as it was';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked collection authority cannot then be confirmed';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked collection authority stays revoked';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_collection_authority_target(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_collection_authority_target() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'collect.collection_authority_target is never deleted: it is the record of which source an authority covered (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
     OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.added_by IS DISTINCT FROM OLD.added_by
     OR NEW.added_at IS DISTINCT FROM OLD.added_at
     OR NEW.target_base_url IS DISTINCT FROM OLD.target_base_url
     OR NEW.target_egress_profile_id IS DISTINCT FROM OLD.target_egress_profile_id THEN
    RAISE EXCEPTION USING MESSAGE =
      'a source under a collection authority cannot be rewritten: revoke it and add it again';
  END IF;
  IF OLD.confirmed_at IS NOT NULL
     AND (NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
          OR NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a confirmed source under a collection authority stays confirmed as it was';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked source under a collection authority cannot then be confirmed';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked source under a collection authority stays revoked';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_persona_holds(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_persona_holds() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.platform IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'a persona bound to a platform account is never deleted: burn it instead';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.machine_hold_until IS NOT NULL
     AND OLD.machine_hold_until > clock_timestamp()
     AND (NEW.machine_hold_until IS NULL
          OR NEW.machine_hold_until < OLD.machine_hold_until) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a platform''s wait on a persona is never shortened: it ends when the platform said';
  END IF;
  IF OLD.machine_lock_code IS NOT NULL AND NEW.machine_lock_code IS NULL
     AND NOT (NEW.secret_ciphertext IS DISTINCT FROM OLD.secret_ciphertext
              AND coalesce(octet_length(NEW.secret_ciphertext), 0) > 0
              AND coalesce(NEW.secret_rotated_at > OLD.machine_lock_at, false)) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona locked over its credential comes back only with a new credential enrolled after the lock';
  END IF;
  IF OLD.machine_lock_code IS NOT NULL AND NEW.machine_lock_code IS NOT NULL
     AND NEW.machine_lock_at IS DISTINCT FROM OLD.machine_lock_at
     AND NOT coalesce(NEW.machine_lock_at > OLD.machine_lock_at, false) THEN
    RAISE EXCEPTION USING MESSAGE =
      'the time a persona was locked moves only forward, with a later lock';
  END IF;
  IF NEW.secret_rotated_at IS DISTINCT FROM OLD.secret_rotated_at
     AND NEW.secret_ciphertext IS NOT DISTINCT FROM OLD.secret_ciphertext THEN
    RAISE EXCEPTION USING MESSAGE =
      'a credential''s rotation time moves only when a new credential is stored';
  END IF;
  IF (OLD.platform IS NOT NULL AND NEW.platform IS DISTINCT FROM OLD.platform)
     OR (OLD.platform_uid IS NOT NULL
         AND NEW.platform_uid IS DISTINCT FROM OLD.platform_uid) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona is one account on one platform for life';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_run_requests(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_run_requests() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.requests = '[]'::jsonb AND OLD.status = 'RUNNING'
     AND NEW.status <> 'RUNNING' THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING MESSAGE =
    'a poll''s request log is written once, when the run finishes, and never '
    || 'rewritten: it is custody';
END
$$;

--
-- Name: guard_telegram_chat(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_telegram_chat() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram chat source is never deleted: stop reading it';
  END IF;
  IF NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.peer_type IS DISTINCT FROM OLD.peer_type
     OR NEW.peer_id IS DISTINCT FROM OLD.peer_id
     OR NEW.durable_id IS DISTINCT FROM OLD.durable_id
     OR NEW.username_at_resolve IS DISTINCT FROM OLD.username_at_resolve
     OR NEW.title_at_resolve IS DISTINCT FROM OLD.title_at_resolve
     OR NEW.resolved_at IS DISTINCT FROM OLD.resolved_at
     OR NEW.resolved_by IS DISTINCT FROM OLD.resolved_by
     OR (OLD.migrated_to IS NOT NULL
         AND NEW.migrated_to IS DISTINCT FROM OLD.migrated_to) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a chat source''s identity is fixed: add the new chat as a new source, so a confirmed authority target never silently changes chat';
  END IF;
  IF (NEW.access_mode IS DISTINCT FROM OLD.access_mode
      OR NEW.provenance_class IS DISTINCT FROM OLD.provenance_class)
     AND NOT (OLD.access_mode = 'PUBLIC_READ' AND OLD.provenance_class = 'OPEN_GROUP'
              AND NEW.access_mode = 'MEMBER'
              AND NEW.provenance_class = 'PERSONA_PARTY') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a chat read in public can become a member chat, and never back';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_telegram_message(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_telegram_message() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram message''s capture record is never deleted';
  END IF;
  IF (NEW.document_id, NEW.source_id, NEW.chat_durable_id, NEW.message_id,
      NEW.seen_via_uid, NEW.fwd_from_message_id, NEW.reply_to_message_id,
      NEW.topic_id, NEW.grouped_id, NEW.is_service, NEW.service_action,
      NEW.is_self, NEW.media_kind, NEW.noforwards, NEW.edit_date,
      NEW.views_at_capture, NEW.forwards_at_capture, NEW.captured_at)
     IS DISTINCT FROM
     (OLD.document_id, OLD.source_id, OLD.chat_durable_id, OLD.message_id,
      OLD.seen_via_uid, OLD.fwd_from_message_id, OLD.reply_to_message_id,
      OLD.topic_id, OLD.grouped_id, OLD.is_service, OLD.service_action,
      OLD.is_self, OLD.media_kind, OLD.noforwards, OLD.edit_date,
      OLD.views_at_capture, OLD.forwards_at_capture, OLD.captured_at)
     OR (OLD.deleted_seen_at IS NOT NULL
         AND NEW.deleted_seen_at IS DISTINCT FROM OLD.deleted_seen_at) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a Telegram message''s capture record is fixed; only the purge clears its identifiers';
  END IF;
  IF (NEW.sender_uid, NEW.sender_handle_at_capture, NEW.post_author,
      NEW.fwd_from_uid, NEW.fwd_from_name, NEW.via_bot_uid)
     IS DISTINCT FROM
     (OLD.sender_uid, OLD.sender_handle_at_capture, OLD.post_author,
      OLD.fwd_from_uid, OLD.fwd_from_name, OLD.via_bot_uid) THEN
    IF NOT EXISTS (SELECT 1 FROM collect.document d
                    WHERE d.id = NEW.document_id AND d.purged_at IS NOT NULL)
       OR NEW.sender_uid IS NOT NULL OR NEW.sender_handle_at_capture IS NOT NULL
       OR NEW.post_author IS NOT NULL OR NEW.fwd_from_uid IS NOT NULL
       OR NEW.fwd_from_name IS NOT NULL OR NEW.via_bot_uid IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'a Telegram message''s capture record is fixed; only the purge clears its identifiers';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_telegram_persona(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.guard_telegram_persona() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.platform = 'TELEGRAM'
     AND NEW.egress_profile_id IS DISTINCT FROM OLD.egress_profile_id THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a Telegram persona keeps its egress profile for life';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: raise_authority_labels(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.raise_authority_labels() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.classification > OLD.classification THEN
    UPDATE collect.collection_authority a
       SET classification = NEW.classification
     WHERE a.classification < NEW.classification
       AND a.id IN (SELECT t.authority_id
                      FROM collect.collection_authority_target t
                     WHERE t.source_id = NEW.id);
  END IF;
  RETURN NULL;
END
$$;

--
-- Name: record_egress_binding(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.record_egress_binding() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
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

--
-- Name: source_vectors_follow(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.source_vectors_follow() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  DELETE FROM collect.document_embedding e
   USING collect.document d
   WHERE e.document_id = d.id AND d.source_id = NEW.id;
  INSERT INTO core.embedding_pending (slot, kind, item_id)
  SELECT s.slot, 'document', d.id
    FROM collect.document d CROSS JOIN core.embedding_space s
   WHERE d.source_id = NEW.id AND d.purged_at IS NULL
     AND s.state IN ('BUILDING', 'ACTIVE')
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;

--
-- Name: guard_pgp_key(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.guard_pgp_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  entry_case uuid;
  entry_type text;
  entry_value text;
  block_cls core.tlp;
  block_comp text[];
  acq_cls core.tlp;
  acq_comp text[];
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a vendor key record is never deleted: retire it';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.confirmed_at IS NOT NULL OR NEW.confirmed_fingerprint IS NOT NULL
       OR NEW.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'a key is never born confirmed or retired';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.id, NEW.case_id, NEW.acquisition_id, NEW.primary_fingerprint,
      NEW.algorithm, NEW.curve, NEW.key_bits, NEW.key_created_at,
      NEW.key_expires_at, NEW.revoked, NEW.capabilities, NEW.subkeys,
      NEW.user_ids, NEW.material, NEW.material_sha256, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.case_id, OLD.acquisition_id, OLD.primary_fingerprint,
      OLD.algorithm, OLD.curve, OLD.key_bits, OLD.key_created_at,
      OLD.key_expires_at, OLD.revoked, OLD.capabilities, OLD.subkeys,
      OLD.user_ids, OLD.material, OLD.material_sha256, OLD.created_at) THEN
    RAISE EXCEPTION 'what gpg read from a key is fixed';
  END IF;
  IF OLD.retired_at IS NOT NULL
     AND (NEW.retired_at, NEW.retired_by, NEW.retired_reason)
         IS DISTINCT FROM (OLD.retired_at, OLD.retired_by, OLD.retired_reason) THEN
    RAISE EXCEPTION 'a retired key stays retired';
  END IF;
  IF (NEW.confirmed_fingerprint, NEW.confirmed_against,
      NEW.confirmed_contact_block_entry_id, NEW.confirmed_source_ref,
      NEW.confirmation_statement, NEW.confirmed_by, NEW.confirmed_at)
     IS NOT DISTINCT FROM
     (OLD.confirmed_fingerprint, OLD.confirmed_against,
      OLD.confirmed_contact_block_entry_id, OLD.confirmed_source_ref,
      OLD.confirmation_statement, OLD.confirmed_by, OLD.confirmed_at) THEN
    RETURN NEW;
  END IF;
  IF OLD.confirmed_at IS NOT NULL THEN
    RAISE EXCEPTION 'a key''s confirmation is made once and never changed';
  END IF;
  IF OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retired key is not confirmed';
  END IF;
  IF NEW.confirmed_contact_block_entry_id IS NOT NULL THEN
    SELECT b.case_id, e.selector_type, e.durable_value,
           b.classification, b.compartments
      INTO entry_case, entry_type, entry_value, block_cls, block_comp
      FROM comms.contact_block_entry e
      JOIN comms.contact_block b ON b.id = e.block_id
     WHERE e.id = NEW.confirmed_contact_block_entry_id;
    IF entry_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the contact block line belongs to another case';
    END IF;
    IF entry_type IS DISTINCT FROM 'PGP_FPR' THEN
      RAISE EXCEPTION 'the contact block line is not a PGP fingerprint';
    END IF;
    IF comms.pgp_fingerprint_norm(entry_value) <> NEW.primary_fingerprint THEN
      RAISE EXCEPTION 'the contact block line lists a different fingerprint than this key''s';
    END IF;
    SELECT classification, compartments INTO acq_cls, acq_comp
      FROM comms.pgp_key_acquisition WHERE id = NEW.acquisition_id;
    IF block_cls > acq_cls OR NOT (block_comp <@ acq_comp) THEN
      RAISE EXCEPTION 'the contact block line is filed above this key; a confirmation shown with the key cannot rest on material its readers may not see';
    END IF;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_pgp_key_acquisition(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.guard_pgp_key_acquisition() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  cited_cls core.tlp;
  cited_comp text[];
  cited_case uuid;
  lookup_state text;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key acquisition is the record of what was obtained and from where; it is never deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.case_id, NEW.source, NEW.raw_bytes, NEW.raw_sha256,
        NEW.filename, NEW.source_ref, NEW.channel_binding_id,
        NEW.contact_block_id, NEW.evidence_id, NEW.classification,
        NEW.requested_by, NEW.requested_at, NEW.lookup_id)
       IS DISTINCT FROM
       (OLD.id, OLD.case_id, OLD.source, OLD.raw_bytes, OLD.raw_sha256,
        OLD.filename, OLD.source_ref, OLD.channel_binding_id,
        OLD.contact_block_id, OLD.evidence_id, OLD.classification,
        OLD.requested_by, OLD.requested_at, OLD.lookup_id)
       OR cardinality(NEW.compartments) <> cardinality(OLD.compartments) THEN
      RAISE EXCEPTION 'an acquisition''s record and labels are fixed; only a compartment rename may touch them';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT (NEW.compartments @> (SELECT compartments FROM core."case"
                                WHERE id = NEW.case_id)) THEN
    RAISE EXCEPTION 'an acquisition carries at least its case''s compartments';
  END IF;
  IF NEW.source = 'WKD' THEN
    SELECT state, classification INTO lookup_state, cited_cls
      FROM comms.pgp_key_lookup WHERE id = NEW.lookup_id;
    IF lookup_state IS DISTINCT FROM 'SENDING' THEN
      RAISE EXCEPTION 'a key found by a lookup is filed while its lookup is being answered';
    END IF;
    IF NEW.classification <> cited_cls THEN
      RAISE EXCEPTION 'a key found by a lookup is filed at the lookup''s own labels';
    END IF;
  END IF;
  IF NEW.evidence_id IS NOT NULL THEN
    SELECT case_id, classification, compartments
      INTO cited_case, cited_cls, cited_comp
      FROM core.evidence WHERE id = NEW.evidence_id;
    IF cited_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the exhibit belongs to another case';
    END IF;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the exhibit it cites';
    END IF;
  END IF;
  IF NEW.channel_binding_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the channel binding it cites';
    END IF;
  END IF;
  IF NEW.contact_block_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.contact_block WHERE id = NEW.contact_block_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the contact block it cites';
    END IF;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_pgp_key_lookup(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.guard_pgp_key_lookup() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  case_cls core.tlp;
  case_comp text[];
  cited_cls core.tlp;
  cited_comp text[];
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key lookup is the record of a request made outside this deployment, or of one refused before it was; it is never deleted';
  END IF;
  SELECT classification, compartments INTO case_cls, case_comp
    FROM core."case" WHERE id = NEW.case_id;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'REQUESTED' THEN
      RAISE EXCEPTION 'a key lookup is born REQUESTED';
    END IF;
    IF cardinality(case_comp) > 0 THEN
      RAISE EXCEPTION 'a compartmented case''s addresses are never looked up outside this deployment';
    END IF;
    IF NEW.classification < case_cls THEN
      RAISE EXCEPTION 'a key lookup is never filed below its case';
    END IF;
    IF NEW.channel_binding_id IS NOT NULL THEN
      SELECT classification, compartments INTO cited_cls, cited_comp
        FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
      IF cardinality(cited_comp) > 0 OR NEW.classification < cited_cls THEN
        RAISE EXCEPTION 'a key lookup is never filed below, or beside a compartment of, the binding it cites';
      END IF;
    END IF;
    IF NEW.contact_block_id IS NOT NULL THEN
      SELECT classification, compartments INTO cited_cls, cited_comp
        FROM comms.contact_block WHERE id = NEW.contact_block_id;
      IF cardinality(cited_comp) > 0 OR NEW.classification < cited_cls THEN
        RAISE EXCEPTION 'a key lookup is never filed below, or beside a compartment of, the contact block it cites';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  -- UPDATE: what was asked never changes.
  IF (NEW.id, NEW.case_id, NEW.address, NEW.local_part, NEW.domain,
      NEW.wkd_hash, NEW.reason, NEW.channel_binding_id, NEW.contact_block_id,
      NEW.classification, NEW.ceiling, NEW.route_name, NEW.requested_by,
      NEW.requested_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.id, OLD.case_id, OLD.address, OLD.local_part, OLD.domain,
      OLD.wkd_hash, OLD.reason, OLD.channel_binding_id, OLD.contact_block_id,
      OLD.classification, OLD.ceiling, OLD.route_name, OLD.requested_by,
      OLD.requested_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'what a key lookup asked for is fixed when it is asked';
  END IF;
  IF OLD.state = 'REQUESTED' THEN
    IF NEW.state NOT IN ('DECLINED', 'EXPIRED', 'SENDING') THEN
      RAISE EXCEPTION 'a waiting key lookup is declined, lapses, or is approved and sent';
    END IF;
    IF NEW.state = 'SENDING' THEN
      IF now() >= NEW.expires_at THEN
        RAISE EXCEPTION 'the key lookup lapsed before it was approved';
      END IF;
      IF cardinality(case_comp) > 0 OR case_cls > NEW.classification THEN
        RAISE EXCEPTION 'the case''s labels changed since the key lookup was asked for, so it is not sent';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.state = 'SENDING' THEN
    IF NEW.state NOT IN ('FOUND', 'NOT_FOUND', 'FAILED') THEN
      RAISE EXCEPTION 'a key lookup that was sent ends FOUND, NOT_FOUND or FAILED';
    END IF;
    IF (NEW.decided_by, NEW.decided_at, NEW.decision_note, NEW.planned_urls,
        NEW.sent_at)
       IS DISTINCT FROM
       (OLD.decided_by, OLD.decided_at, OLD.decision_note, OLD.planned_urls,
        OLD.sent_at) THEN
      RAISE EXCEPTION 'the decision and the planned URLs of a sent key lookup are fixed';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'a key lookup that has finished is not changed';
END $$;

--
-- Name: guard_pgp_verification(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.guard_pgp_verification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'a verification is the record behind a confirmation; it is never rewritten or deleted';
END $$;

--
-- Name: pgp_fingerprint_norm(text); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.pgp_fingerprint_norm(v text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN regexp_replace(upper(regexp_replace(COALESCE(v, ''::text), '[[:space:]]'::text, ''::text, 'g'::text)), '^0X'::text, ''::text);

--
-- Name: FUNCTION pgp_fingerprint_norm(v text); Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON FUNCTION comms.pgp_fingerprint_norm(v text) IS 'The one normalisation of a published PGP fingerprint: whitespace out, upper case, a leading 0X dropped (F10b). The service and the triggers both read it, so they cannot disagree.';

--
-- Name: pgp_verification_cites_a_confirmed_key(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.pgp_verification_cites_a_confirmed_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  confirmed text;
  retired timestamptz;
BEGIN
  IF NEW.pgp_key_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT confirmed_fingerprint, retired_at INTO confirmed, retired
    FROM comms.pgp_key WHERE id = NEW.pgp_key_id;
  IF confirmed IS NULL THEN
    RAISE EXCEPTION 'a check made with a registry key cites a key whose fingerprint was confirmed';
  END IF;
  IF retired IS NOT NULL THEN
    RAISE EXCEPTION 'a retired key is not used for a check';
  END IF;
  IF NEW.claimed_fingerprint <> confirmed THEN
    RAISE EXCEPTION 'a check made with a registry key claims that key''s confirmed fingerprint';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: pgp_verification_confirms_its_binding(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.pgp_verification_confirms_its_binding() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  bound text;
BEGIN
  IF NEW.outcome <> 'VERIFIED' OR NEW.channel_binding_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT durable_value INTO bound
    FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
  -- A binding with no durable value has nothing a signature could
  -- confirm; upgrading it would assert control of an identifier this
  -- system has declined to index.
  IF bound IS NULL THEN
    RAISE EXCEPTION 'invariant: cannot confirm a binding that has no '
                    'durable value (verification %)', NEW.id;
  END IF;
  IF NEW.confirms_value IS NULL OR lower(NEW.confirms_value) <> lower(bound) THEN
    RAISE EXCEPTION 'invariant: a VERIFIED row must confirm the binding''s '
                    'own identifier -- signature covers %, binding holds %',
                    coalesce(NEW.confirms_value, '(null)'), bound;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: pgp_verification_is_attributed(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.pgp_verification_is_attributed() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  cb_cls core.tlp;
  cb_comp text[];
  cb_identity uuid;
  cb_platform text;
  cb_durable text;
  b_cls core.tlp;
  b_comp text[];
  b_publisher uuid;
  a_cls core.tlp;
  a_comp text[];
BEGIN
  IF NEW.outcome <> 'VERIFIED' OR NEW.channel_binding_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.contact_block_id IS NULL OR NEW.attribution IS NULL THEN
    RAISE EXCEPTION 'a check that confirms a binding cites the contact block that ties the key to the binding''s holder, and says how';
  END IF;
  SELECT classification, compartments, identity_node_id, platform_key,
         durable_value
    INTO cb_cls, cb_comp, cb_identity, cb_platform, cb_durable
    FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
  SELECT classification, compartments, publisher_identity_node_id
    INTO b_cls, b_comp, b_publisher
    FROM comms.contact_block WHERE id = NEW.contact_block_id;
  IF b_cls > cb_cls OR NOT (b_comp <@ cb_comp) THEN
    RAISE EXCEPTION 'the cited contact block is filed above the binding it would confirm';
  END IF;
  IF NEW.pgp_key_id IS NOT NULL THEN
    SELECT a.classification, a.compartments INTO a_cls, a_comp
      FROM comms.pgp_key k
      JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
     WHERE k.id = NEW.pgp_key_id;
    IF a_cls > cb_cls OR NOT (a_comp <@ cb_comp) THEN
      RAISE EXCEPTION 'the key is filed above the binding it would confirm';
    END IF;
  END IF;
  IF NOT EXISTS (
       SELECT 1 FROM comms.contact_block_entry e
        WHERE e.block_id = NEW.contact_block_id
          AND e.role = 'SELF' AND e.selector_type = 'PGP_FPR'
          AND comms.pgp_fingerprint_norm(e.durable_value)
              IN (NEW.claimed_fingerprint,
                  coalesce(NEW.signing_primary_fingerprint,
                           NEW.claimed_fingerprint))) THEN
    RAISE EXCEPTION 'the cited contact block does not list the claimed fingerprint as its publisher''s own';
  END IF;
  IF b_publisher IS NOT NULL AND cb_identity IS NOT NULL
     AND b_publisher <> cb_identity THEN
    RAISE EXCEPTION 'the cited contact block''s publisher and the binding''s identity are different entities';
  END IF;
  IF NEW.attribution = 'SAME_IDENTITY' THEN
    IF b_publisher IS NULL OR cb_identity IS NULL OR b_publisher <> cb_identity THEN
      RAISE EXCEPTION 'SAME_IDENTITY needs the block''s publisher to be the binding''s identity';
    END IF;
  ELSIF NOT EXISTS (
       SELECT 1 FROM comms.contact_block_entry e
        WHERE e.block_id = NEW.contact_block_id AND e.role = 'SELF'
          AND e.platform_key = cb_platform
          AND lower(e.durable_value) = lower(cb_durable)) THEN
    RAISE EXCEPTION 'SAME_BLOCK needs the cited contact block to list the binding''s identifier as its publisher''s own';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: announce_change(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.announce_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
          affected uuid;
        BEGIN
          -- DELETE has no NEW TABLE, and an INSERT has no OLD TABLE, so
          -- each branch reads the one that exists. A statement that
          -- touched nothing announces nothing.
          IF TG_OP = 'DELETE' THEN
            SELECT case_id INTO affected FROM oldrows LIMIT 1;
          ELSE
            SELECT case_id INTO affected FROM newrows LIMIT 1;
          END IF;
          IF affected IS NULL THEN
            RETURN NULL;
          END IF;
          PERFORM pg_notify(
            'noctornal_change',
            json_build_object('case_id', affected,
                              'kind', TG_ARGV[0],
                              'op', TG_OP)::text);
          RETURN NULL;
        END $$;

--
-- Name: assertion_derives_tie_confidence(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.assertion_derives_tie_confidence() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'core', 'public', 'pg_temp'
    AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.edge_id IS NOT NULL THEN
      PERFORM core.sync_tie_confidence(NEW.edge_id);
    END IF;
    RETURN NULL;
  END IF;
  IF OLD.edge_id IS NOT NULL THEN
    PERFORM core.sync_tie_confidence(OLD.edge_id);
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.edge_id IS NOT NULL AND NEW.edge_id IS DISTINCT FROM OLD.edge_id THEN
      PERFORM core.sync_tie_confidence(NEW.edge_id);
    END IF;
  END IF;
  RETURN NULL;
END $$;

--
-- Name: assertion_embedding_case(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.assertion_embedding_case() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  a_case uuid;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row keeps the claim and case it was written for';
  END IF;
  SELECT case_id INTO a_case FROM core.assertion WHERE id = NEW.assertion_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its claim, and this claim is missing';
  END IF;
  NEW.case_id := a_case;
  RETURN NEW;
END $$;

--
-- Name: assertion_embedding_queued(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.assertion_embedding_queued() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM core.embedding_enqueue('assertion', NEW.id);
  ELSE
    -- Retracted or superseded: history, never searched, so never queued.
    DELETE FROM core.embedding_pending
     WHERE kind = 'assertion' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

--
-- Name: assertion_protects_element(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.assertion_protects_element() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'core', 'public', 'pg_temp'
    AS $$
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
END $$;

--
-- Name: block_custody_mutation(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.block_custody_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'evidence_custody is append-only (chain of custody)';
END $$;

--
-- Name: block_tombstone_mutation(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.block_tombstone_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'core.purge_tombstone is append-only: the record of '
                  'destruction survives the data (docs/08)';
END $$;

--
-- Name: custody_chain_hash(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.custody_chain_hash() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE prev bytea;
BEGIN
  NEW.occurred_at := now();  -- server-pinned; any caller value is ignored
  PERFORM pg_advisory_xact_lock(hashtextextended('core.evidence_custody.chain', 0));
  SELECT row_hash INTO prev FROM core.evidence_custody ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := prev;
  NEW.row_hash := public.digest(
    convert_to(concat_ws(chr(31),
      coalesce(encode(prev,'hex'),'GENESIS'),
      NEW.evidence_id::text,
      NEW.action,
      coalesce(NEW.actor_id::text,'-'),
      to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      NEW.detail::text,
      coalesce(NEW.hash_verified::text,'-')
    ), 'UTF8'),
    'sha256');
  RETURN NEW;
END $$;

--
-- Name: edge_confidence_is_derived(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.edge_confidence_is_derived() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'core', 'public', 'pg_temp'
    AS $$
DECLARE
  derived core.analytic_confidence := core.tie_confidence(NEW.id);
BEGIN
  IF NEW.confidence IS DISTINCT FROM derived THEN
    RAISE EXCEPTION
      'edge %: confidence is derived from its live assertions (%), not written directly. Record or retract an assertion instead.',
      NEW.id, derived
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: embedding_enqueue(text, uuid); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.embedding_enqueue(p_kind text, p_item uuid) RETURNS void
    LANGUAGE sql
    AS $$
  INSERT INTO core.embedding_pending (slot, kind, item_id)
  SELECT s.slot, p_kind, p_item FROM core.embedding_space s
   WHERE s.state IN ('BUILDING', 'ACTIVE')
  ON CONFLICT DO NOTHING;
$$;

--
-- Name: embedding_space_transition(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.embedding_space_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF (NEW.id, NEW.role, NEW.slot, NEW.provider, NEW.model, NEW.fingerprint,
      NEW.fingerprint_sha256, NEW.dims_native, NEW.canary::text,
      NEW.unicode_version, NEW.registered_endpoint, NEW.created_at,
      NEW.created_by)
     IS DISTINCT FROM
     (OLD.id, OLD.role, OLD.slot, OLD.provider, OLD.model, OLD.fingerprint,
      OLD.fingerprint_sha256, OLD.dims_native, OLD.canary::text,
      OLD.unicode_version, OLD.registered_endpoint, OLD.created_at,
      OLD.created_by) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'an embedding space never changes what it is: register a new space '
      'for another model or setting';
  END IF;
  IF OLD.state = 'RETIRED' THEN
    IF (to_jsonb(NEW) - 'rows_cleared_at') IS DISTINCT FROM
       (to_jsonb(OLD) - 'rows_cleared_at')
       OR (OLD.rows_cleared_at IS NOT NULL
           AND NEW.rows_cleared_at IS DISTINCT FROM OLD.rows_cleared_at) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'a retired embedding space is final: only the moment its rows were '
        'cleared is recorded, once';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'BUILDING' AND NEW.state IN ('ACTIVE', 'RETIRED'))
    OR (OLD.state = 'ACTIVE' AND NEW.state = 'RETIRED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'an embedding space moves from building to active or retired, or from '
      'active to retired, and never back';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: enforce_tlp_floor(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.enforce_tlp_floor() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
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
END $$;

--
-- Name: evidence_embedding_case(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.evidence_embedding_case() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  e_case uuid;
  e_purged timestamptz;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row keeps the exhibit and case it was written for';
  END IF;
  SELECT case_id, purged_at INTO e_case, e_purged
    FROM core.evidence WHERE id = NEW.evidence_id FOR SHARE;
  IF NOT FOUND OR e_purged IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a vector row follows its exhibit, and this exhibit is missing or purged';
  END IF;
  NEW.case_id := e_case;
  RETURN NEW;
END $$;

--
-- Name: evidence_embedding_queued(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.evidence_embedding_queued() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM core.embedding_enqueue('evidence', NEW.id);
  RETURN NULL;
END $$;

--
-- Name: evidence_tsv_update(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.evidence_tsv_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: evidence_vectors_follow(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.evidence_vectors_follow() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  DELETE FROM core.evidence_embedding WHERE evidence_id = NEW.id;
  IF NEW.purged_at IS NULL THEN
    PERFORM core.embedding_enqueue('evidence', NEW.id);
  ELSE
    DELETE FROM core.embedding_pending
     WHERE kind = 'evidence' AND item_id = NEW.id;
  END IF;
  RETURN NULL;
END $$;

--
-- Name: guard_approval_request(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.guard_approval_request() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  deciding boolean;
  consuming boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state IS DISTINCT FROM 'PENDING'
       OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
       OR NEW.decision_note IS NOT NULL OR NEW.consumed_at IS NOT NULL
       OR NEW.result_ref IS NOT NULL THEN
      RAISE EXCEPTION 'an approval request is created pending and undecided';
    END IF;
    RETURN NEW;
  END IF;

  IF (NEW.operation, NEW.case_id, NEW.payload, NEW.payload_hash,
      NEW.justification, NEW.requested_by)
     IS DISTINCT FROM
     (OLD.operation, OLD.case_id, OLD.payload, OLD.payload_hash,
      OLD.justification, OLD.requested_by) THEN
    RAISE EXCEPTION 'what an approval request asks for is fixed when it is raised: raise a new one';
  END IF;

  IF NEW.requested_at > OLD.requested_at OR NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'an approval request never gains time: raise a new one';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'REJECTED', 'WITHDRAWN'))
    OR (OLD.state = 'APPROVED' AND NEW.state = 'CONSUMED')) THEN
    RAISE EXCEPTION 'an approval request moves from pending to decided or withdrawn, and from approved to consumed, and never back';
  END IF;

  deciding := OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'REJECTED');
  IF (NEW.decided_by, NEW.decided_at, NEW.decision_note)
     IS DISTINCT FROM (OLD.decided_by, OLD.decided_at, OLD.decision_note)
     AND NOT deciding THEN
    RAISE EXCEPTION 'a decision on an approval request is made once';
  END IF;
  IF deciding AND NEW.decided_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'a decision on an approval request is recorded at the time it is made';
  END IF;

  consuming := OLD.state = 'APPROVED' AND NEW.state = 'CONSUMED';
  IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at AND NOT consuming THEN
    RAISE EXCEPTION 'an approval is spent once';
  END IF;
  IF consuming AND NEW.consumed_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'an approval is spent at the time it is used';
  END IF;

  IF NEW.result_ref IS DISTINCT FROM OLD.result_ref
     AND (OLD.result_ref IS NOT NULL OR NEW.state IS DISTINCT FROM 'CONSUMED') THEN
    RAISE EXCEPTION 'what an approval produced is recorded once, after it is spent';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: FUNCTION guard_approval_request(); Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON FUNCTION core.guard_approval_request() IS 'An approval request is inserted pending, what it asks for never changes, it is decided once at now(), spent once at now(), and never gains time (migration approval_request_frozen, F9 2026-09-24).';

--
-- Name: guard_case_merge_switch(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.guard_case_merge_switch() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  IF OLD.dual_control_merge IS NOT DISTINCT FROM NEW.dual_control_merge THEN
    IF NEW.dual_control_merge_epoch IS DISTINCT FROM OLD.dual_control_merge_epoch THEN
      RAISE EXCEPTION 'dual_control_merge_epoch moves only with the merge switch';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.dual_control_merge AND NOT NEW.dual_control_merge
     AND NOT EXISTS (
       SELECT 1 FROM core.approval_request r
        WHERE r.operation = 'case.policy.relax'
          AND r.case_id = NEW.id
          AND r.state = 'CONSUMED'
          AND r.consumed_at = now()
          AND r.payload->>'setting' = 'dual_control_merge'
          AND r.payload->>'to' = 'false'
          AND r.payload->>'epoch' = OLD.dual_control_merge_epoch::text) THEN
    RAISE EXCEPTION '%', 'case ' || NEW.code || ' requires a second signature'
      || ' on merges, and turning that off takes a case.policy.relax approval'
      || ' for the switch as it stands, consumed in the same transaction';
  END IF;
  NEW.dual_control_merge_epoch := OLD.dual_control_merge_epoch + 1;
  RETURN NEW;
END
$$;

--
-- Name: node_tsv_update(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.node_tsv_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: require_edge_assertion(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.require_edge_assertion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'core', 'public', 'pg_temp'
    AS $$
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
END $$;

--
-- Name: require_node_assertion(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.require_node_assertion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'core', 'public', 'pg_temp'
    AS $$
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
END $$;

--
-- Name: sync_tie_confidence(uuid); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.sync_tie_confidence(p_edge uuid) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'core', 'public'
    AS $$
DECLARE
  derived core.analytic_confidence;
BEGIN
  -- 1. Lock the edge. Waits here for any other writer still deriving
  --    this tie, until it commits.
  PERFORM 1 FROM core.edge WHERE id = p_edge FOR NO KEY UPDATE;
  -- 2. Derive, in a statement that starts after the lock is held, so its
  --    snapshot includes whatever that writer committed.
  SELECT core.tie_confidence(p_edge) INTO derived;
  -- 3. Write only a change, so an unchanged tie is not rewritten. Never
  --    skipped for want of a grade: the rule answers LOW for a tie no live
  --    claim grades, where it used to answer NULL and leave a withdrawn
  --    claim's grade standing (final review U11, 2026-09-23).
  UPDATE core.edge
     SET confidence = derived
   WHERE id = p_edge
     AND confidence IS DISTINCT FROM derived;
END $$;

--
-- Name: tie_confidence(uuid); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.tie_confidence(p_edge uuid) RETURNS core.analytic_confidence
    LANGUAGE sql STABLE
    SET search_path TO 'core', 'public'
    AS $$
  SELECT coalesce(max(core.tie_grade(a)), 'LOW')
    FROM core.assertion a
   WHERE a.edge_id = p_edge
     AND a.retracted_at IS NULL
     AND a.superseded_at IS NULL
$$;

--
-- Name: FUNCTION tie_confidence(p_edge uuid); Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON FUNCTION core.tie_confidence(p_edge uuid) IS 'A tie''s confidence: the highest core.tie_grade among its live assertions (not retracted, not superseded), and LOW, the ungraded value, when no live assertion is a claim about the tie. Never NULL. Migration 0064.';

--
-- Name: assertion; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.assertion (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    node_id uuid,
    edge_id uuid,
    claim_path text,
    claim_value jsonb,
    basis core.assertion_basis NOT NULL,
    reliability core.source_reliability DEFAULT 'F'::core.source_reliability NOT NULL,
    credibility core.info_credibility DEFAULT '6'::core.info_credibility NOT NULL,
    confidence core.analytic_confidence DEFAULT 'LOW'::core.analytic_confidence NOT NULL,
    source_id uuid,
    document_id uuid,
    evidence_id uuid,
    external_ref text,
    rationale text,
    observed_at timestamp with time zone,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    superseded_at timestamp with time zone,
    superseded_by uuid,
    retracted_at timestamp with time zone,
    retracted_by uuid,
    retraction_reason text,
    created_by uuid NOT NULL,
    lookup_result_id uuid,
    CONSTRAINT assertion_inference_needs_rationale CHECK (((basis <> ALL (ARRAY['ANALYST_INFERENCE'::core.assertion_basis, 'AUTOMATED_INFERENCE'::core.assertion_basis])) OR (rationale IS NOT NULL))),
    CONSTRAINT assertion_one_subject CHECK ((num_nonnulls(node_id, edge_id) = 1))
);

--
-- Name: COLUMN assertion.lookup_result_id; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON COLUMN core.assertion.lookup_result_id IS 'The lookup answer an accepted claim rests on (AUTOMATED_INFERENCE only).';

--
-- Name: tie_grade(core.assertion); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.tie_grade(a core.assertion) RETURNS core.analytic_confidence
    LANGUAGE sql STABLE
    SET search_path TO 'core', 'public'
    AS $$
  SELECT CASE
           WHEN a.claim_value ->> 'confidence' IN ('LOW', 'MODERATE', 'HIGH')
           THEN (a.claim_value ->> 'confidence')::core.analytic_confidence
           WHEN a.claim_path IS NULL
                AND coalesce(jsonb_typeof(a.claim_value), 'null') = 'null'
           THEN a.confidence
         END
$$;

--
-- Name: FUNCTION tie_grade(a core.assertion); Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON FUNCTION core.tie_grade(a core.assertion) IS 'What one assertion says about its tie''s confidence: its own grade for a claim about the tie itself (no claim_path and no claim_value), the value a correction states in claim_value.confidence, and NULL for a correction to another field (weight, attrs), which does not grade the tie. Liveness is core.tie_confidence''s business, not this function''s. Migration 0064.';

--
-- Name: validate_edge_endpoints(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.validate_edge_endpoints() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
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
END $$;

--
-- Name: apply_dual_control_change(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.apply_dual_control_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.change = 'OPERATION_MODE' THEN
    UPDATE iam.dual_control_operation
       SET mode = NEW.mode_to, changed_at = now(), change_id = NEW.id
     WHERE operation = NEW.operation;
  ELSIF NEW.change = 'SEPARATED_DUTY_ADD' THEN
    -- 0062's separated_duty_not_already_violated still fires, and refuses
    -- by role name, rolling the consume back with it.
    INSERT INTO iam.separated_duty
           (permission_a, permission_b, why, origin, added_at, added_by_change)
    VALUES (NEW.permission_a, NEW.permission_b, NEW.why, 'policy', now(), NEW.id);
  ELSE
    DELETE FROM iam.separated_duty
     WHERE origin = 'policy'
       AND (permission_a, permission_b) IN
           ((NEW.permission_a, NEW.permission_b),
            (NEW.permission_b, NEW.permission_a));
  END IF;
  RETURN NULL;
END
$$;

--
-- Name: case_code(uuid); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.case_code(p_case uuid) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT c.code
    FROM core."case" c
   WHERE c.id = p_case
     AND (iam.rls_caller_exempt()
          OR EXISTS (SELECT 1 FROM iam.case_assignment a
                      WHERE a.case_id = c.id AND a.user_id = iam.rls_actor()
                        AND (a.expires_at IS NULL OR a.expires_at > pg_catalog.now()))
          OR iam.rls_holds_global('break_glass.review')
          OR iam.rls_holds_global('sample.read'))
$$;

--
-- Name: case_facts(uuid); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.case_facts(p_case uuid) RETURNS TABLE(id uuid, code text, status core.case_status, classification core.tlp, compartments text[], owner_user_id uuid, deputy_user_id uuid, legal_hold boolean, withheld_disclosure text, dual_control_merge boolean)
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT c.id, iam.case_code(c.id), c.status, c.classification, c.compartments,
         c.owner_user_id, c.deputy_user_id, c.legal_hold, c.withheld_disclosure,
         c.dual_control_merge
    FROM core."case" c
   WHERE c.id = p_case
$$;

--
-- Name: check_dual_control_change(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.check_dual_control_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  r record;
  p jsonb;
  blocked record;
  cur record;
  latest uuid;
BEGIN
  -- Serialises every policy change, so the reads below cannot race.
  PERFORM pg_advisory_xact_lock(hashtextextended('iam.dual_control_policy', 0));
  -- Pinned, never taken from the caller: the policy tables' guard accepts
  -- a write only when the ledger row naming it has applied_at = now(),
  -- which is what marks the row as inserted by this transaction.
  NEW.applied_at := now();

  SELECT a.operation, a.case_id, a.state, a.consumed_at, a.requested_by,
         a.decided_by, a.decided_at, a.payload
    INTO r FROM core.approval_request a WHERE a.id = NEW.approval_request_id;
  IF NOT FOUND OR r.operation IS DISTINCT FROM 'dual_control.policy'
     OR r.case_id IS NOT NULL THEN
    RAISE EXCEPTION 'a two-person policy change applies only a deployment-wide dual_control.policy approval';
  END IF;
  IF r.state IS DISTINCT FROM 'CONSUMED' OR r.consumed_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'a two-person policy change applies only an approval consumed in the same transaction';
  END IF;
  IF r.requested_by IS DISTINCT FROM NEW.requested_by
     OR r.decided_by IS DISTINCT FROM NEW.countersigned_by THEN
    RAISE EXCEPTION 'a two-person policy change names the two people on its approval';
  END IF;
  p := r.payload;
  IF p->>'change' IS DISTINCT FROM NEW.change
     OR p->>'operation' IS DISTINCT FROM NEW.operation
     OR p->>'from' IS DISTINCT FROM NEW.mode_from
     OR p->>'to' IS DISTINCT FROM NEW.mode_to
     OR p->>'permission_a' IS DISTINCT FROM NEW.permission_a
     OR p->>'permission_b' IS DISTINCT FROM NEW.permission_b
     OR p->>'why' IS DISTINCT FROM NEW.why
     OR p->>'based_on' IS DISTINCT FROM NEW.based_on::text THEN
    RAISE EXCEPTION 'a two-person policy change applies exactly what was countersigned';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM iam.app_user u
        JOIN iam.user_role ur ON ur.user_id = u.id
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE u.id = NEW.requested_by AND u.is_active
         AND rp.permission_key = 'dual_control.manage') THEN
    RAISE EXCEPTION 'the proposer is no longer an active account holding dual_control.manage: propose it again';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM iam.app_user u
        JOIN iam.user_role ur ON ur.user_id = u.id
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE u.id = NEW.countersigned_by AND u.is_active
         AND rp.permission_key = 'dual_control.countersign') THEN
    RAISE EXCEPTION 'the countersigner is no longer an active account holding dual_control.countersign: propose it again';
  END IF;
  -- iam.separated_duty keeps the two halves in different ROLES; this keeps
  -- them in different PEOPLE (2026-09-24).
  IF EXISTS (
      SELECT 1 FROM iam.user_role ur
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE ur.user_id = NEW.countersigned_by
         AND rp.permission_key = 'dual_control.manage') THEN
    RAISE EXCEPTION 'the countersigner can also propose changes to which operations need two people, so they are not a second person: propose it again for a Security officer who is not an administrator';
  END IF;
  SELECT * INTO blocked FROM iam.countersign_blocked_by(
      NEW.countersigned_by, 'dual_control.countersign', r.decided_at,
      NEW.requested_by, 'dual_control.manage');
  IF FOUND THEN
    IF blocked.subject_id = NEW.countersigned_by THEN
      RAISE EXCEPTION '%', 'the countersigner''s account '
        || CASE blocked.action
             WHEN 'PASSWORD_RESET' THEN 'had its password reset'
             WHEN 'TOTP_REENROLLED' THEN 'had its authenticator re-enrolled'
             WHEN 'USER_REACTIVATED' THEN 'was reactivated'
             WHEN 'USER_UNLOCKED' THEN 'was unlocked'
             WHEN 'ROLE_GRANTED' THEN 'was given a role that countersigns'
             ELSE 'was created with a role that countersigns' END
        || ' by someone else in the seven days before they countersigned: propose it again';
    END IF;
    RAISE EXCEPTION '%', 'the countersigner '
      || CASE blocked.action
           WHEN 'PASSWORD_RESET' THEN 'reset the proposer''s password'
           WHEN 'TOTP_REENROLLED' THEN 're-enrolled the proposer''s authenticator'
           WHEN 'USER_REACTIVATED' THEN 'reactivated the proposer''s account'
           WHEN 'USER_UNLOCKED' THEN 'unlocked the proposer''s account'
           WHEN 'ROLE_GRANTED' THEN 'gave the proposer a role that proposes'
           ELSE 'created the proposer''s account' END
      || ' in the seven days before they countersigned: propose it again';
  END IF;

  IF NEW.change = 'OPERATION_MODE' THEN
    SELECT o.mode, o.change_id INTO cur
      FROM iam.dual_control_operation o
     WHERE o.operation = NEW.operation FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'no configurable two-person policy for %', NEW.operation;
    END IF;
    IF cur.mode IS DISTINCT FROM NEW.mode_from
       OR cur.change_id IS DISTINCT FROM NEW.based_on THEN
      RAISE EXCEPTION '% changed after this was countersigned (it is % now): propose it again',
        NEW.operation, cur.mode;
    END IF;
    RETURN NEW;
  END IF;

  SELECT c.id INTO latest FROM iam.dual_control_policy_change c
   WHERE c.change IN ('SEPARATED_DUTY_ADD', 'SEPARATED_DUTY_REMOVE')
     AND c.permission_a = NEW.permission_a AND c.permission_b = NEW.permission_b
   ORDER BY c.seq DESC LIMIT 1;
  IF latest IS DISTINCT FROM NEW.based_on THEN
    RAISE EXCEPTION 'the pair % and % changed after this was countersigned: propose it again',
      NEW.permission_a, NEW.permission_b;
  END IF;
  IF NEW.change = 'SEPARATED_DUTY_ADD' THEN
    IF (SELECT count(*) FROM iam.permission
         WHERE key IN (NEW.permission_a, NEW.permission_b)) <> 2 THEN
      RAISE EXCEPTION 'a separated pair names two permissions that exist';
    END IF;
    IF EXISTS (SELECT 1 FROM iam.separated_duty s
                WHERE (s.permission_a, s.permission_b) IN
                      ((NEW.permission_a, NEW.permission_b),
                       (NEW.permission_b, NEW.permission_a))) THEN
      RAISE EXCEPTION 'the pair % and % is already declared', NEW.permission_a, NEW.permission_b;
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM iam.separated_duty s
                     WHERE s.origin = 'policy'
                       AND (s.permission_a, s.permission_b) IN
                           ((NEW.permission_a, NEW.permission_b),
                            (NEW.permission_b, NEW.permission_a))) THEN
    RAISE EXCEPTION 'the pair % and % was not added by a two-person change, so a two-person change cannot remove it',
      NEW.permission_a, NEW.permission_b;
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: compartment_bindings(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.compartment_bindings() RETURNS TABLE(schema_name text, table_name text, column_name text, kind text, enabled boolean, problem text)
    LANGUAGE plpgsql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
#variable_conflict use_column
DECLARE
  t    record;
  args text[];
  att  record;
BEGIN
  FOR t IN
    SELECT tg.tgname::text AS tgname, n.nspname::text AS sch,
           c.relname::text AS tbl, tg.tgrelid, tg.tgfoid, tg.tgnargs,
           tg.tgargs, ARRAY(SELECT unnest(tg.tgattr)) AS cols,
           tg.tgtype::int AS tgtype, tg.tgenabled IN ('O', 'A') AS fires
      FROM pg_trigger tg
      JOIN pg_class c ON c.oid = tg.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE NOT tg.tgisinternal
       AND (tg.tgfoid = 'iam.refuse_unregistered_compartment()'::regprocedure
            OR tg.tgname = 'compartments_registered'
            OR starts_with(tg.tgname::text, 'compartments_registered_'))
     ORDER BY 2, 3, 1
  LOOP
    schema_name := t.sch;
    table_name := t.tbl;
    enabled := t.fires;
    column_name := NULL;
    kind := NULL;
    problem := NULL;
    args := string_to_array(encode(t.tgargs, 'escape'), E'\\000');
    IF t.tgfoid <> 'iam.refuse_unregistered_compartment()'::regprocedure THEN
      problem := 'it does not call iam.refuse_unregistered_compartment';
    ELSIF t.tgnargs <> 2 THEN
      problem := 'it passes ' || t.tgnargs
                 || CASE WHEN t.tgnargs = 1 THEN ' argument' ELSE ' arguments' END
                 || ', and a binding passes two: the column and its kind';
    ELSE
      column_name := args[1];
      kind := args[2];
      SELECT a.attnum, a.atttypid INTO att
        FROM pg_attribute a
       WHERE a.attrelid = t.tgrelid AND a.attname = args[1]
         AND NOT a.attisdropped;
      IF NOT FOUND THEN
        problem := 'it names a column the table does not have';
      ELSIF kind NOT IN ('array', 'scalar') THEN
        problem := 'its kind is neither array nor scalar';
      ELSIF (kind = 'array' AND att.atttypid <> 'text[]'::regtype)
         OR (kind = 'scalar' AND att.atttypid <> 'text'::regtype) THEN
        problem := 'the column is not of the type its kind says';
      ELSIF (t.tgtype & 127) <> 23 THEN
        problem := 'it is not BEFORE INSERT OR UPDATE FOR EACH ROW';
      ELSIF t.cols IS DISTINCT FROM ARRAY[att.attnum]::int2[] THEN
        problem := 'it does not fire on UPDATE OF exactly that column';
      ELSIF t.tgname NOT IN ('compartments_registered',
                             'compartments_registered_' || args[1]) THEN
        problem := 'its name does not follow the binding rule';
      END IF;
    END IF;
    RETURN NEXT;
  END LOOP;
END
$$;

--
-- Name: FUNCTION compartment_bindings(); Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON FUNCTION iam.compartment_bindings() IS 'Every compartment binding: the triggers named compartments_registered (or compartments_registered_<column>), and any trigger that calls iam.refuse_unregistered_compartment, read from the catalog. problem is NULL for a well-formed binding and says what is wrong otherwise. The registry of bound columns IS this list.';

--
-- Name: compartment_in_use(text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.compartment_in_use(key text) RETURNS text[]
    LANGUAGE plpgsql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE
  b       record;
  hit     boolean;
  holders text[] := '{}';
BEGIN
  FOR b IN SELECT * FROM iam.compartment_bindings() LOOP
    IF b.problem IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'compartment ' || key || ' was not dropped or renamed: the binding '
        || 'on ' || b.schema_name || '.' || b.table_name || ' cannot be read ('
        || b.problem || '), so whether rows there still carry it is unknown. '
        || 'Recreate that trigger as the migration that added it did, then '
        || 'try again';
    END IF;
    IF b.kind = 'scalar' THEN
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I WHERE %I = $1)',
                     b.schema_name, b.table_name, b.column_name)
        INTO hit USING key;
    ELSE
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I WHERE cardinality(%I) > 0 AND %I @> ARRAY[$1]::text[])',
                     b.schema_name, b.table_name, b.column_name,
                     b.column_name)
        INTO hit USING key;
    END IF;
    IF hit THEN
      holders := holders || (b.schema_name || '.' || b.table_name || '.'
                             || b.column_name);
    END IF;
  END LOOP;
  IF cardinality(holders) = 0 THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT array_agg(h ORDER BY h) FROM unnest(holders) AS h);
END
$_$;

--
-- Name: FUNCTION compartment_in_use(key text); Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON FUNCTION iam.compartment_in_use(key text) IS 'The bound columns (schema.table.column) that still carry the key, or NULL. Reads the bindings from the catalog through iam.compartment_bindings(), so a column bound by any later migration is covered without restating this function, and refuses while any binding cannot be read.';

--
-- Name: compartments_registered(text[]); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.compartments_registered(keys text[]) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
  SELECT keys IS NULL OR NOT EXISTS (
    SELECT 1 FROM unnest(keys) AS k
     WHERE k IS NULL
        OR NOT EXISTS (SELECT 1 FROM iam.compartment c WHERE c.key = k))
$$;

--
-- Name: FUNCTION compartments_registered(keys text[]); Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON FUNCTION iam.compartments_registered(keys text[]) IS 'True iff every element is a non-NULL key in iam.compartment. A NULL array is vacuously registered; a NULL ELEMENT is not, because it is not a key and can never be held.';

--
-- Name: countersign_blocked_by(uuid, text, timestamp with time zone, uuid, text, interval); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.countersign_blocked_by(signer uuid, signer_permission text, as_of timestamp with time zone DEFAULT now(), proposer uuid DEFAULT NULL::uuid, proposer_permission text DEFAULT NULL::text, lookback interval DEFAULT NULL::interval) RETURNS TABLE(action text, occurred_at timestamp with time zone, actor_id uuid, subject_id uuid, role_key text)
    LANGUAGE sql STABLE
    AS $$
  SELECT e.action, e.occurred_at, e.actor_id, e.object_id,
         CASE WHEN e.action = 'ROLE_GRANTED' THEN e.detail->>'role' END
    FROM audit.event e
   WHERE e.object_type = 'app_user'
     AND e.object_id IN (signer, proposer)
     AND e.occurred_at > as_of - coalesce(lookback, iam.countersigner_seasoning())
     AND e.occurred_at <= as_of
     AND e.actor_id IS NOT NULL
     AND e.action IN ('PASSWORD_RESET', 'TOTP_REENROLLED', 'USER_REACTIVATED', 'USER_UNLOCKED', 'ROLE_GRANTED', 'USER_CREATED')
     AND ((e.object_id = signer AND e.actor_id <> signer
           AND iam.countersign_event_counts(e.action, e.detail, signer_permission))
       OR (proposer IS NOT NULL AND e.object_id = proposer
           AND e.actor_id = signer
           AND iam.countersign_event_counts(e.action, e.detail, proposer_permission)))
   ORDER BY e.occurred_at DESC, e.seq DESC
   LIMIT 1
$$;

--
-- Name: countersign_event_counts(text, jsonb, text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.countersign_event_counts(ev_action text, ev_detail jsonb, wanted text) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
  SELECT CASE
    WHEN ev_action IN ('PASSWORD_RESET', 'TOTP_REENROLLED', 'USER_REACTIVATED', 'USER_UNLOCKED') THEN true
    WHEN ev_action = 'ROLE_GRANTED' THEN EXISTS (
      SELECT 1 FROM iam.role_permission rp
       WHERE rp.role_key = ev_detail->>'role' AND rp.permission_key = wanted)
    WHEN ev_action = 'USER_CREATED'
         AND jsonb_typeof(ev_detail->'roles') = 'array' THEN EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(ev_detail->'roles') AS r(role_key)
        JOIN iam.role_permission rp ON rp.role_key = r.role_key
       WHERE rp.permission_key = wanted)
    ELSE false
  END
$$;

--
-- Name: countersigner_seasoning(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.countersigner_seasoning() RETURNS interval
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT interval '7 days' $$;

--
-- Name: element_facts(text, uuid); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.element_facts(p_kind text, p_id uuid) RETURNS TABLE(case_id uuid, classification core.tlp, compartments text[])
    LANGUAGE plpgsql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
  IF p_kind = 'node' THEN
    RETURN QUERY SELECT n.case_id, n.classification, n.compartments
                   FROM core.node n WHERE n.id = p_id;
  ELSIF p_kind = 'edge' THEN
    RETURN QUERY SELECT e.case_id, e.classification, e.compartments
                   FROM core.edge e WHERE e.id = p_id;
  ELSIF p_kind = 'evidence' THEN
    RETURN QUERY SELECT v.case_id, v.classification, v.compartments
                   FROM core.evidence v WHERE v.id = p_id;
  ELSIF p_kind = 'assertion' THEN
    RETURN QUERY
      SELECT a.case_id, coalesce(n.classification, e.classification),
             coalesce(n.compartments, e.compartments)
        FROM core.assertion a
        LEFT JOIN core.node n ON n.id = a.node_id
        LEFT JOIN core.edge e ON e.id = a.edge_id
       WHERE a.id = p_id;
  ELSIF p_kind = 'document' THEN
    RETURN QUERY SELECT NULL::uuid, d.classification, d.compartments
                   FROM collect.document d WHERE d.id = p_id;
  ELSIF p_kind = 'sample' THEN
    RETURN QUERY SELECT s.case_id, s.classification, s.compartments
                   FROM lab.sample s WHERE s.id = p_id;
  ELSIF p_kind = 'conversation' THEN
    RETURN QUERY SELECT c.case_id, c.classification, c.compartments
                   FROM comms.conversation c WHERE c.id = p_id;
  ELSIF p_kind = 'proposal_block' THEN
    RETURN QUERY SELECT cb.case_id, cb.classification, cb.compartments
                   FROM comms.contact_block_entry e
                   JOIN comms.contact_block cb ON cb.id = e.block_id
                  WHERE e.proposal_id = p_id
                  LIMIT 1;
  ELSE
    RAISE EXCEPTION 'iam.element_facts: unknown kind %', p_kind
      USING ERRCODE = '22023';
  END IF;
END
$$;

--
-- Name: guard_dual_control_ledger(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.guard_dual_control_ledger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'iam.dual_control_policy_change is append-only: a change is corrected by another change';
END
$$;

--
-- Name: policy_changed_only_by_ledger(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.policy_changed_only_by_ledger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  bound boolean := false;
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' is never truncated: it changes only through a two-person policy change';
  END IF;
  -- Depth 1 is a statement from outside any trigger. The ledger's AFTER
  -- INSERT trigger writes at depth 2.
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' changes only through a two-person policy change'
      || ' (iam.dual_control_policy_change); a migration that must write it'
      || ' disables trigger ' || TG_NAME || ' by name for its own run';
  END IF;
  IF TG_OP = 'DELETE' AND TG_TABLE_NAME = 'separated_duty' THEN
    IF OLD.origin = 'migration' THEN
      RAISE EXCEPTION 'a pair installed with the software or by the database owner is removed only the same way';
    END IF;
  END IF;
  -- Depth alone accepts a write from ANY trigger, and the runtime role can
  -- make one (a trigger on a temporary table of its own; PUBLIC holds
  -- TEMP). So the write must also be exactly what a ledger row inserted in
  -- THIS transaction says: the ledger pins applied_at to now(), the
  -- transaction's start, so a row from any earlier transaction never
  -- matches (F9, 2026-09-24).
  IF TG_TABLE_NAME = 'dual_control_operation' THEN
    IF TG_OP = 'UPDATE' THEN
      bound := NEW.operation = OLD.operation AND EXISTS (
        SELECT 1 FROM iam.dual_control_policy_change c
         WHERE c.id = NEW.change_id
           AND c.applied_at = now()
           AND c.change = 'OPERATION_MODE'
           AND c.operation = NEW.operation
           AND c.mode_from = OLD.mode
           AND c.mode_to = NEW.mode);
    END IF;
  ELSIF TG_OP = 'INSERT' THEN
    bound := NEW.origin = 'policy' AND EXISTS (
      SELECT 1 FROM iam.dual_control_policy_change c
       WHERE c.id = NEW.added_by_change
         AND c.applied_at = now()
         AND c.change = 'SEPARATED_DUTY_ADD'
         AND c.permission_a = NEW.permission_a
         AND c.permission_b = NEW.permission_b
         AND c.why IS NOT DISTINCT FROM NEW.why);
  ELSIF TG_OP = 'DELETE' THEN
    bound := EXISTS (
      SELECT 1 FROM iam.dual_control_policy_change c
       WHERE c.applied_at = now()
         AND c.change = 'SEPARATED_DUTY_REMOVE'
         AND c.permission_a = least(OLD.permission_a, OLD.permission_b)
         AND c.permission_b = greatest(OLD.permission_a, OLD.permission_b));
  END IF;
  IF bound IS NOT TRUE THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' changes only as a two-person policy change applied in the same'
      || ' transaction says, and this ' || lower(TG_OP) || ' matches none';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: refuse_compartment_removal(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.refuse_compartment_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  holders text[];
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.key = OLD.key THEN
    RETURN NEW;
  END IF;
  holders := iam.compartment_in_use(OLD.key);
  IF holders IS NOT NULL THEN
    RAISE EXCEPTION USING MESSAGE =
      'compartment ' || OLD.key || ' is still carried by '
      || array_to_string(holders, ', ')
      || ': a registered key cannot be dropped or renamed while rows are'
      || ' filed under it, because they would become unregistered and'
      || ' unwritable. Rename or remove it in those columns first';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

--
-- Name: refuse_separated_duty_grant(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.refuse_separated_duty_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  other text;
  was_role text;
  was_permission text;
BEGIN
  -- On an UPDATE the row being replaced is still visible to the lookup
  -- below, and it is not a grant the role keeps. Without this, moving
  -- CASE_OWNER's reveal row to authorise in place was refused: the lookup
  -- found the very reveal row being replaced and counted it as the other
  -- half (verifier, 2026-09-22). ROW(...) IS DISTINCT FROM a pair of NULLs
  -- is true, so an INSERT, where these stay NULL, excludes nothing.
  IF TG_OP = 'UPDATE' THEN
    was_role := OLD.role_key;
    was_permission := OLD.permission_key;
  END IF;
  SELECT CASE WHEN s.permission_a = NEW.permission_key
              THEN s.permission_b ELSE s.permission_a END
    INTO other
    FROM iam.separated_duty s
    JOIN iam.role_permission rp
      ON rp.role_key = NEW.role_key
     AND rp.permission_key = CASE WHEN s.permission_a = NEW.permission_key
                                  THEN s.permission_b ELSE s.permission_a END
   WHERE NEW.permission_key IN (s.permission_a, s.permission_b)
     AND (rp.role_key, rp.permission_key)
         IS DISTINCT FROM (was_role, was_permission)
   LIMIT 1;
  IF other IS NOT NULL THEN
    -- One line, no DETAIL, for the reason 0059 gives: safe_detail forwards
    -- only the first line of a P0001.
    RAISE EXCEPTION USING MESSAGE =
      'role ' || NEW.role_key || ' already holds ' || other
      || ', and ' || NEW.permission_key || ' is the other half of the same'
      || ' two-person control (iam.separated_duty): one role holding both'
      || ' makes every holder of it both people';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: refuse_unregistered_compartment(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.refuse_unregistered_compartment() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
  keys text[];
  bad  text[];
BEGIN
  -- TG_ARGV[0] is the column, TG_ARGV[1] is 'array' or 'scalar'. Read
  -- from NEW by name so one function serves every bound column.
  IF TG_ARGV[1] = 'scalar' THEN
    EXECUTE format('SELECT ARRAY[($1).%I]', TG_ARGV[0]) INTO keys USING NEW;
  ELSE
    EXECUTE format('SELECT ($1).%I', TG_ARGV[0]) INTO keys USING NEW;
  END IF;
  bad := iam.unregistered_compartments(keys);
  IF bad IS NOT NULL THEN
    -- One line, no DETAIL: http/errors.safe_detail forwards only the
    -- first line of a P0001 to the client, so everything the operator
    -- needs has to be on it. The default SQLSTATE IS the contract here;
    -- a check_violation would be replaced by a generic sentence.
    RAISE EXCEPTION USING MESSAGE =
      'compartment key(s) ' || array_to_string(bad, ', ')
      || ' in ' || TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME || '.' || TG_ARGV[0]
      || ' are not registered: register each key first (POST /api/v1/compartments,'
      || ' user.manage), because an unregistered key is a typo and a typo'
      || ' in a need-to-know lock is silent no-access';
  END IF;
  RETURN NEW;
END
$_$;

--
-- Name: refuse_violated_separation(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.refuse_violated_separation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  holder text;
BEGIN
  SELECT a.role_key INTO holder
    FROM iam.role_permission a
    JOIN iam.role_permission b ON b.role_key = a.role_key
   WHERE a.permission_key = NEW.permission_a
     AND b.permission_key = NEW.permission_b
   LIMIT 1;
  IF holder IS NOT NULL THEN
    RAISE EXCEPTION USING MESSAGE =
      'role ' || holder || ' already holds both ' || NEW.permission_a
      || ' and ' || NEW.permission_b || ': revoke one of them before'
      || ' declaring the pair separated';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: rls_actor(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_actor() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT coalesce(
    (SELECT s.user_id
       FROM iam.session s
       JOIN iam.app_user u ON u.id = s.user_id
      WHERE s.rls_binding_hash = pg_catalog.sha256(pg_catalog.convert_to(
              nullif(pg_catalog.current_setting('noctornal.rls_proof', true), ''),
              'UTF8'))
        AND s.revoked_at IS NULL
        AND s.expires_at > pg_catalog.now()
        AND u.is_active),
    (SELECT t.user_id
       FROM lab.download_ticket t
       JOIN iam.app_user u ON u.id = t.user_id
      WHERE t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
              nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''),
              'UTF8'))
        AND t.redeemed_at IS NOT NULL
        AND t.redeemed_at > pg_catalog.now() - interval '5 minutes'
        AND u.is_active))
$$;

--
-- Name: rls_bind(text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_bind(p_proof text) RETURNS TABLE(actor uuid, exempt boolean)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
  PERFORM pg_catalog.set_config('noctornal.rls_proof', coalesce(p_proof, ''), false);
  RETURN QUERY SELECT iam.rls_actor(), iam.rls_caller_exempt();
END
$$;

--
-- Name: rls_bind_ticket(text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_bind_ticket(p_ticket text) RETURNS TABLE(actor uuid, exempt boolean)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
  PERFORM pg_catalog.set_config('noctornal.rls_ticket', coalesce(p_ticket, ''), false);
  RETURN QUERY SELECT iam.rls_actor(), iam.rls_caller_exempt();
END
$$;

--
-- Name: rls_caller_exempt(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_caller_exempt() RETURNS boolean
    LANGUAGE sql STABLE PARALLEL RESTRICTED
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT coalesce(bool_or(r.rolsuper OR r.rolbypassrls
                          OR pg_catalog.pg_has_role(r.oid, c.relowner, 'USAGE')), false)
    FROM pg_catalog.pg_roles r, pg_catalog.pg_class c
   WHERE r.rolname = CASE WHEN pg_catalog.current_setting('role') = 'none'
                          THEN session_user::text
                          ELSE pg_catalog.current_setting('role') END
     AND c.oid = 'core.node'::pg_catalog.regclass
$$;

--
-- Name: rls_cases(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_cases() RETURNS uuid[]
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  WITH me AS (
    SELECT u.id, u.tlp_clearance, coalesce(u.compartments, '{}'::text[]) AS held
      FROM iam.app_user u
     WHERE u.id = iam.rls_actor() AND u.is_active
  ), grants AS (
    SELECT g.case_id, g.granted_classification
      FROM iam.break_glass g, me
     WHERE g.user_id = me.id
       AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
       AND g.granted_classification IS NOT NULL
  )
  SELECT coalesce(pg_catalog.array_agg(c.id), '{}'::uuid[])
    FROM me
    JOIN iam.case_assignment a ON a.user_id = me.id
    JOIN core."case" c ON c.id = a.case_id
   WHERE (a.expires_at IS NULL OR a.expires_at > pg_catalog.now())
     AND coalesce(c.compartments, '{}'::text[]) OPERATOR(pg_catalog.<@) me.held
     AND c.classification <= GREATEST(
           me.tlp_clearance,
           (SELECT max(gr.granted_classification) FROM grants gr
             WHERE gr.case_id IS NULL OR gr.case_id = c.id))
$$;

--
-- Name: rls_cases_in_reach(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_cases_in_reach() RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT coalesce(pg_catalog.jsonb_object_agg(c.id::text, true), '{}'::jsonb)
    FROM core."case" c
   WHERE c.classification <= iam.rls_clearance()
     AND coalesce(c.compartments, '{}'::text[])
         OPERATOR(pg_catalog.<@) iam.rls_compartments()
$$;

--
-- Name: rls_ceiling_for(jsonb, uuid); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_ceiling_for(p_ceilings jsonb, p_case uuid) RETURNS core.tlp
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$
  SELECT (p_ceilings ->> p_case::text)::core.tlp
$$;

--
-- Name: rls_ceilings(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_ceilings() RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT coalesce(pg_catalog.jsonb_object_agg(x.case_id::text, x.level), '{}'::jsonb)
    FROM (SELECT g.case_id, max(g.granted_classification) AS level
            FROM iam.break_glass g
           WHERE g.user_id = iam.rls_actor() AND g.case_id IS NOT NULL
             AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
             AND g.granted_classification IS NOT NULL
           GROUP BY g.case_id) x
   WHERE x.level > iam.rls_clearance()
$$;

--
-- Name: rls_clearance(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_clearance() RETURNS core.tlp
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT GREATEST(u.tlp_clearance,
                  (SELECT max(g.granted_classification)
                     FROM iam.break_glass g
                    WHERE g.user_id = u.id AND g.case_id IS NULL
                      AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
                      AND g.granted_classification IS NOT NULL))
    FROM iam.app_user u
   WHERE u.id = iam.rls_actor() AND u.is_active
$$;

--
-- Name: rls_compartments(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_compartments() RETURNS text[]
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT coalesce(u.compartments, '{}'::text[])
    FROM iam.app_user u
   WHERE u.id = iam.rls_actor() AND u.is_active
$$;

--
-- Name: rls_holds_global(text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_holds_global(p_permission text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  SELECT EXISTS (
    SELECT 1
      FROM iam.user_role ur
      JOIN iam.role_permission rp ON rp.role_key = ur.role_key
      JOIN iam.app_user u ON u.id = ur.user_id
     WHERE ur.user_id = iam.rls_actor() AND rp.permission_key = p_permission
       AND u.is_active)
$$;

--
-- Name: rls_record_break_glass_use(uuid); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.rls_record_break_glass_use(p_grant uuid) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  WITH counted AS (
    UPDATE iam.break_glass g
       SET used_at = coalesce(g.used_at, pg_catalog.now()),
           action_count = g.action_count + 1
     WHERE g.id = p_grant
       AND (iam.rls_caller_exempt()
            OR (g.user_id = iam.rls_actor()
                AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()))
    RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM counted)
$$;

--
-- Name: search_document_hits(text, text, text, core.tlp, text[], integer); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.search_document_hits(p_tsq text, p_q text, p_pattern text, p_clearance core.tlp, p_compartments text[], p_limit integer) RETURNS TABLE(id uuid, label text, excerpt text, source_name text, posted_at timestamp with time zone, external_url text, rank double precision, total bigint, classification text, author_handle text, compartments text[])
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL RESTRICTED
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
  WITH me AS (
    SELECT iam.rls_caller_exempt() AS exempt,
           iam.rls_clearance() AS clr,
           iam.rls_compartments() AS held
  )
  SELECT h.id, h.label, h.excerpt, h.source_name, h.posted_at,
         h.external_url, h.rank, pg_catalog.count(*) OVER () AS total,
         h.classification, h.author_handle, h.compartments
    FROM (
      SELECT d.id,
             coalesce(nullif(d.title, ''), pg_catalog.left(d.body_text, 80)) AS label,
             pg_catalog.left(d.body_text, 240) AS excerpt, s.name AS source_name,
             d.posted_at, d.external_url,
             d.classification::text AS classification, d.author_handle,
             d.compartments,
             LEAST(0.99::float8, GREATEST(
               coalesce(pg_catalog.ts_rank(d.search_tsv,
                        pg_catalog.to_tsquery('simple', p_tsq)), 0)::float8,
               coalesce(public.similarity(d.author_handle, p_q), 0)::float8))
               AS rank
        FROM collect.document d
        JOIN collect.source s ON s.id = d.source_id
        CROSS JOIN me
       WHERE d.purged_at IS NULL
         AND d.classification <= p_clearance
         AND s.classification <= p_clearance
         AND d.compartments OPERATOR(pg_catalog.<@) p_compartments
         AND (me.exempt
              OR (me.clr IS NOT NULL
                  AND d.classification <= me.clr
                  AND s.classification <= me.clr
                  AND d.compartments OPERATOR(pg_catalog.<@) me.held))
         AND (d.search_tsv OPERATOR(pg_catalog.@@) pg_catalog.to_tsquery('simple', p_tsq)
              OR d.author_handle OPERATOR(pg_catalog.~~*) p_pattern)
    ) h
   ORDER BY h.rank DESC, h.id
   LIMIT LEAST(greatest(p_limit, 0), 200)
$$;

--
-- Name: separated_duty_violations(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.separated_duty_violations() RETURNS TABLE(role_key text, permission_a text, permission_b text)
    LANGUAGE sql STABLE
    AS $$
  SELECT a.role_key, s.permission_a, s.permission_b
    FROM iam.separated_duty s
    JOIN iam.role_permission a ON a.permission_key = s.permission_a
    JOIN iam.role_permission b ON b.permission_key = s.permission_b
                              AND b.role_key = a.role_key
$$;

--
-- Name: session_guard(); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.session_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF OLD.rls_binding_hash IS NULL
     OR OLD.rls_binding_hash IS DISTINCT FROM pg_catalog.sha256(pg_catalog.convert_to(
          nullif(pg_catalog.current_setting('noctornal.rls_proof', true), ''), 'UTF8')) THEN
    RAISE EXCEPTION 'iam.session: this connection may change only the session it is bound to'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'iam.session: a revoked session stays revoked'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: unregistered_compartments(text[]); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.unregistered_compartments(keys text[]) RETURNS text[]
    LANGUAGE sql STABLE
    AS $$
  SELECT array_agg(DISTINCT coalesce(k, 'NULL') ORDER BY coalesce(k, 'NULL'))
    FROM unnest(keys) AS k
   WHERE k IS NULL
      OR NOT EXISTS (SELECT 1 FROM iam.compartment c WHERE c.key = k)
$$;

--
-- Name: exposure_rank(text); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.exposure_rank(level text) RETURNS integer
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE level WHEN 'NONE' THEN 0 WHEN 'VENDOR' THEN 1 WHEN 'PUBLIC' THEN 2 END
$$;

--
-- Name: guard_exposure_change(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.guard_exposure_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: guard_lookup_batch(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.guard_lookup_batch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a lookup batch is the record of an analyst''s plan: retention empties it, nothing deletes it';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['cancelled_at', 'cancelled_by', 'cancel_reason', 'note', 'purged_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['cancelled_at', 'cancelled_by', 'cancel_reason', 'note', 'purged_at']) THEN
    RAISE EXCEPTION 'a lookup batch''s plan is fixed';
  END IF;
  IF OLD.cancelled_at IS NOT NULL AND (NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at
       OR NEW.cancelled_by IS DISTINCT FROM OLD.cancelled_by) THEN
    RAISE EXCEPTION 'a lookup batch is cancelled once';
  END IF;
  IF (NEW.note IS DISTINCT FROM OLD.note
      OR (OLD.cancel_reason IS NOT NULL AND NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason))
     AND NOT (OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL) THEN
    RAISE EXCEPTION 'a lookup batch''s notes change only when retention empties them';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_lookup_result(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.guard_lookup_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a lookup answer is case material: retention empties it, nothing deletes it';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['filed_evidence_id', 'raw_body', 'summary', 'interpret_error',
                            'purged_at', 'findings_total', 'findings_proposed'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['filed_evidence_id', 'raw_body', 'summary', 'interpret_error',
                            'purged_at', 'findings_total', 'findings_proposed']) THEN
    RAISE EXCEPTION 'a lookup answer is kept as it came back';
  END IF;
  -- The finding counts are written once, after the proposals that cite the
  -- answer exist (F15.3, 2026-09-24).
  IF (NEW.findings_total IS DISTINCT FROM OLD.findings_total
      OR NEW.findings_proposed IS DISTINCT FROM OLD.findings_proposed)
     AND (OLD.findings_total <> 0 OR OLD.findings_proposed <> 0) THEN
    RAISE EXCEPTION 'a lookup answer''s finding counts are recorded once';
  END IF;
  IF OLD.filed_evidence_id IS NOT NULL
     AND NEW.filed_evidence_id IS DISTINCT FROM OLD.filed_evidence_id THEN
    RAISE EXCEPTION 'a lookup answer is filed as an exhibit once';
  END IF;
  IF (NEW.raw_body IS DISTINCT FROM OLD.raw_body OR NEW.summary IS DISTINCT FROM OLD.summary
      OR NEW.interpret_error IS DISTINCT FROM OLD.interpret_error)
     AND NOT (OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL) THEN
    RAISE EXCEPTION 'a lookup answer changes only when retention empties it';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_provider(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.guard_provider() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
END $$;

--
-- Name: lookup_attempt_append_only(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.lookup_attempt_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'a lookup attempt is what the quota counts: append-only';
END $$;

--
-- Name: lookup_is_a_record(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.lookup_is_a_record() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  mutable constant text[] := ARRAY['state', 'not_before', 'attempts', 'sent_at',
    'finished_at', 'http_status', 'outcome', 'error_class', 'error_detail', 'refusal',
    'result_id', 'signed_off_by', 'signed_off_at', 'signoff_note', 'query_value',
    'authorisation_note', 'purged_at'];
  allowed text[];
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a lookup is the record of what left this host: retention empties it, nothing deletes it';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state NOT IN ('AWAITING_SIGNOFF', 'QUEUED', 'CACHED')
       OR NEW.attempts <> 0 OR NEW.sent_at IS NOT NULL
       OR NEW.signed_off_by IS NOT NULL OR NEW.signed_off_at IS NOT NULL
       OR NEW.purged_at IS NOT NULL
       OR (NEW.result_id IS NOT NULL AND NEW.state <> 'CACHED') THEN
      RAISE EXCEPTION 'a lookup starts waiting, queued or answered from the cache: nothing sent and nothing signed';
    END IF;
    RETURN NEW;
  END IF;
  IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
    RAISE EXCEPTION 'what a lookup asked, of whom and by whose authority is fixed';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    allowed := CASE OLD.state
      WHEN 'AWAITING_SIGNOFF' THEN ARRAY['SENDING', 'DECLINED', 'EXPIRED', 'CANCELLED',
                                          'REFUSED', 'CACHED']
      WHEN 'QUEUED' THEN ARRAY['SENDING', 'CACHED', 'REFUSED', 'CANCELLED']
      WHEN 'SENDING' THEN ARRAY['ANSWERED', 'FAILED', 'QUEUED']
      ELSE ARRAY[]::text[] END;
    IF NOT (NEW.state = ANY (allowed)) THEN
      RAISE EXCEPTION 'a lookup cannot move from % to %', OLD.state, NEW.state;
    END IF;
  END IF;
  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'a lookup''s attempts only rise';
  END IF;
  IF OLD.sent_at IS NOT NULL AND NEW.sent_at IS DISTINCT FROM OLD.sent_at THEN
    RAISE EXCEPTION 'when a lookup was first sent never changes';
  END IF;
  IF OLD.signed_off_by IS NOT NULL AND (NEW.signed_off_by IS DISTINCT FROM OLD.signed_off_by
       OR NEW.signed_off_at IS DISTINCT FROM OLD.signed_off_at) THEN
    RAISE EXCEPTION 'a sign-off is recorded once';
  END IF;
  IF OLD.result_id IS NOT NULL AND NEW.result_id IS DISTINCT FROM OLD.result_id THEN
    RAISE EXCEPTION 'a lookup''s answer is recorded once';
  END IF;
  IF (NEW.query_value IS DISTINCT FROM OLD.query_value
      OR NEW.authorisation_note IS DISTINCT FROM OLD.authorisation_note
      OR (NEW.signoff_note IS DISTINCT FROM OLD.signoff_note AND OLD.signed_off_by IS NOT NULL)) THEN
    IF NOT (OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL) THEN
      RAISE EXCEPTION 'a lookup''s value and notes change only when retention empties them';
    END IF;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: lookup_result_dominates(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.lookup_result_dominates() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE r record;
BEGIN
  IF NEW.result_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT case_id, classification INTO r FROM ingest.lookup_result WHERE id = NEW.result_id;
  IF r.case_id IS DISTINCT FROM NEW.case_id OR r.classification < NEW.classification THEN
    RAISE EXCEPTION 'a lookup''s answer is in its own case and never labelled below the question';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: provider_starts_unapproved(); Type: FUNCTION; Schema: ingest; Owner: -
--

CREATE FUNCTION ingest.provider_starts_unapproved() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF ingest.exposure_rank(NEW.exposure_level) < 2 THEN
    NEW.needs_exposure_approval := true;
  END IF;
  NEW.enabled := false;
  RETURN NEW;
END $$;

--
-- Name: block_access_mutation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.block_access_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'lab.sample_access is append-only (docs/11 custody)';
END $$;

--
-- Name: block_screening_mutation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.block_screening_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: a screening record is history',
    TG_TABLE_NAME;
END $$;

--
-- Name: download_ticket_guard(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.download_ticket_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF OLD.redeemed_at IS NOT NULL OR NEW.redeemed_at IS NULL THEN
    RAISE EXCEPTION 'lab.download_ticket: a ticket may only be spent, once'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

--
-- Name: guard_detonation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_detonation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a detonation is the record of an overt act and is never deleted';
  END IF;
  IF OLD.mode = 'RECORD_ONLY' THEN
    RAISE EXCEPTION 'a record-only detonation request is never changed';
  END IF;
  IF (NEW.id, NEW.sample_id, NEW.target, NEW.exposure_level, NEW.authorised_by, NEW.authorisation_note, NEW.requested_by, NEW.requested_at, NEW.mode, NEW.provider, NEW.target_key, NEW.target_host, NEW.target_ceiling, NEW.egress_route, NEW.network_route, NEW.route_class, NEW.machine, NEW.machine_class, NEW.options, NEW.signoff_required, NEW.signoff_expires_at) IS DISTINCT FROM (OLD.id, OLD.sample_id, OLD.target, OLD.exposure_level, OLD.authorised_by, OLD.authorisation_note, OLD.requested_by, OLD.requested_at, OLD.mode, OLD.provider, OLD.target_key, OLD.target_host, OLD.target_ceiling, OLD.egress_route, OLD.network_route, OLD.route_class, OLD.machine, OLD.machine_class, OLD.options, OLD.signoff_required, OLD.signoff_expires_at) THEN
    RAISE EXCEPTION 'what a detonation request asked for never changes';
  END IF;
  IF OLD.status NOT IN ('AWAITING_SIGNOFF', 'QUEUED', 'SUBMITTED') THEN
    RAISE EXCEPTION 'a detonation that is % is finished and never changes', OLD.status;
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'AWAITING_SIGNOFF'
          AND NEW.status IN ('QUEUED', 'DECLINED', 'CANCELLED', 'REFUSED'))
    OR (OLD.status = 'QUEUED'
          AND NEW.status IN ('SUBMITTED', 'REFUSED', 'CANCELLED'))
    OR (OLD.status = 'SUBMITTED' AND NEW.status IN ('REPORTED', 'FAILED'))) THEN
    RAISE EXCEPTION 'a detonation cannot move from % to %', OLD.status, NEW.status;
  END IF;
  IF OLD.signed_off_by IS NOT NULL AND NEW.signed_off_by IS DISTINCT FROM OLD.signed_off_by THEN
    RAISE EXCEPTION 'detonation.signed_off_by is set once';
  END IF;
  IF OLD.signed_off_at IS NOT NULL AND NEW.signed_off_at IS DISTINCT FROM OLD.signed_off_at THEN
    RAISE EXCEPTION 'detonation.signed_off_at is set once';
  END IF;
  IF OLD.signoff_decision IS NOT NULL AND NEW.signoff_decision IS DISTINCT FROM OLD.signoff_decision THEN
    RAISE EXCEPTION 'detonation.signoff_decision is set once';
  END IF;
  IF OLD.signoff_note IS NOT NULL AND NEW.signoff_note IS DISTINCT FROM OLD.signoff_note THEN
    RAISE EXCEPTION 'detonation.signoff_note is set once';
  END IF;
  IF OLD.external_ref IS NOT NULL AND NEW.external_ref IS DISTINCT FROM OLD.external_ref THEN
    RAISE EXCEPTION 'detonation.external_ref is set once';
  END IF;
  IF OLD.classification_sent IS NOT NULL AND NEW.classification_sent IS DISTINCT FROM OLD.classification_sent THEN
    RAISE EXCEPTION 'detonation.classification_sent is set once';
  END IF;
  IF OLD.submitted_sha256 IS NOT NULL AND NEW.submitted_sha256 IS DISTINCT FROM OLD.submitted_sha256 THEN
    RAISE EXCEPTION 'detonation.submitted_sha256 is set once';
  END IF;
  IF OLD.submit_outcome IS NOT NULL AND NEW.submit_outcome IS DISTINCT FROM OLD.submit_outcome THEN
    RAISE EXCEPTION 'detonation.submit_outcome is set once';
  END IF;
  IF OLD.report_sha256 IS NOT NULL AND NEW.report_sha256 IS DISTINCT FROM OLD.report_sha256 THEN
    RAISE EXCEPTION 'detonation.report_sha256 is set once';
  END IF;
  IF OLD.report_bytes IS NOT NULL AND NEW.report_bytes IS DISTINCT FROM OLD.report_bytes THEN
    RAISE EXCEPTION 'detonation.report_bytes is set once';
  END IF;
  IF OLD.analysis_id IS NOT NULL AND NEW.analysis_id IS DISTINCT FROM OLD.analysis_id THEN
    RAISE EXCEPTION 'detonation.analysis_id is set once';
  END IF;
  IF OLD.cancelled_by IS NOT NULL AND NEW.cancelled_by IS DISTINCT FROM OLD.cancelled_by THEN
    RAISE EXCEPTION 'detonation.cancelled_by is set once';
  END IF;
  IF OLD.submitted_at IS NOT NULL AND NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
    RAISE EXCEPTION 'detonation.submitted_at is set once';
  END IF;
  IF OLD.completed_at IS NOT NULL AND NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN
    RAISE EXCEPTION 'detonation.completed_at is set once';
  END IF;
  IF OLD.report IS NOT NULL AND NEW.report IS DISTINCT FROM OLD.report THEN
    RAISE EXCEPTION 'detonation.report is set once';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_preservation_authorisation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_preservation_authorisation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'lab.preservation_authorisation is never deleted: it is the record of who allowed a held sample out (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.sample_id IS DISTINCT FROM OLD.sample_id
     OR NEW.granted_to IS DISTINCT FROM OLD.granted_to
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
     OR NEW.scope_note IS DISTINCT FROM OLD.scope_note
     OR NEW.legal_basis IS DISTINCT FROM OLD.legal_basis
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'a preservation authorisation cannot be rewritten; revoke it and grant another';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
                                     OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
    RAISE EXCEPTION 'a revoked preservation authorisation stays revoked';
  END IF;
  IF NEW.retrieval_count < OLD.retrieval_count THEN
    RAISE EXCEPTION 'the retrieval count on a preservation authorisation only rises';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_screening_hash_delete(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_screening_hash_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM gone g
               JOIN lab.screening_list l ON l.id = g.list_id
              WHERE l.retired_at IS NULL OR NOT l.purge_requested) THEN
    RAISE EXCEPTION 'only the entries of a list retired with its purge '
      'requested may be deleted';
  END IF;
  RETURN NULL;
END $$;

--
-- Name: guard_screening_list(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_screening_list() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'screening lists are never deleted: retire the list instead';
  END IF;
  IF (NEW.id, NEW.seq, NEW.name, NEW.provider, NEW.category,
      NEW.authority_reference, NEW.deployment_authority, NEW.source_sha256,
      NEW.entry_count, NEW.algorithms, NEW.imported_by, NEW.imported_via,
      NEW.imported_at)
     IS DISTINCT FROM
     (OLD.id, OLD.seq, OLD.name, OLD.provider, OLD.category,
      OLD.authority_reference, OLD.deployment_authority, OLD.source_sha256,
      OLD.entry_count, OLD.algorithms, OLD.imported_by, OLD.imported_via,
      OLD.imported_at) THEN
    RAISE EXCEPTION 'a screening list''s import is history and never changes';
  END IF;
  IF OLD.retired_at IS NOT NULL
     AND (NEW.retired_at, NEW.retired_by, NEW.retire_reason)
         IS DISTINCT FROM (OLD.retired_at, OLD.retired_by, OLD.retire_reason) THEN
    RAISE EXCEPTION 'a screening list is retired once';
  END IF;
  IF OLD.purge_requested
     AND (NEW.purge_requested, NEW.purge_requested_by)
         IS DISTINCT FROM (OLD.purge_requested, OLD.purge_requested_by) THEN
    RAISE EXCEPTION 'a purge is asked for once';
  END IF;
  IF OLD.entries_purged_at IS NOT NULL
     AND NEW.entries_purged_at IS DISTINCT FROM OLD.entries_purged_at THEN
    RAISE EXCEPTION 'a purge is recorded once';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_screening_outcome(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_screening_outcome() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.screening_outcome = 'MATCH' AND NEW.screening_outcome <> 'MATCH' THEN
    RAISE EXCEPTION 'a prohibited-content match is permanent: sample % '
      'cannot be un-matched', OLD.id;
  END IF;
  IF OLD.screening_bytes_absent_at IS NOT NULL
     AND NEW.screening_bytes_absent_at IS DISTINCT FROM OLD.screening_bytes_absent_at THEN
    RAISE EXCEPTION 'screening_bytes_absent_at is set once';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_yara_activation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_yara_activation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'an activation is never deleted: it is when a rule set '
      'was live and who cleared it';
  END IF;
  IF OLD.deactivated_at IS NOT NULL
     OR NEW.id <> OLD.id OR NEW.ruleset_id <> OLD.ruleset_id
     OR NEW.version_id <> OLD.version_id
     OR NEW.activated_by <> OLD.activated_by
     OR NEW.activated_at <> OLD.activated_at
     OR NEW.licence_acknowledgement IS DISTINCT FROM OLD.licence_acknowledgement
     OR NEW.deactivated_at IS NULL THEN
    RAISE EXCEPTION 'an activation may only be closed, once';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_yara_insert_only(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_yara_insert_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION '% is insert-only: a build and its rejection are history, '
    'and a newer row supersedes an older one', TG_TABLE_NAME;
END $$;

--
-- Name: guard_yara_ruleset(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_yara_ruleset() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  removed text[];
  added   text[];
  old_reg iam.compartment%ROWTYPE;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a YARA rule set is never deleted: it is the record of '
      'what the lab hunted with and who cleared it; deactivate its version '
      'instead';
  END IF;
  IF NEW.id <> OLD.id OR NEW.key <> OLD.key
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_via <> OLD.created_via
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'a YARA rule set''s key and creator never change';
  END IF;
  IF NEW.classification < OLD.classification THEN
    RAISE EXCEPTION 'a YARA rule set''s classification is never lowered: '
      'findings made under it would be exposed';
  END IF;
  removed := ARRAY(SELECT unnest(OLD.compartments)
                   EXCEPT SELECT unnest(NEW.compartments));
  added := ARRAY(SELECT unnest(NEW.compartments)
                 EXCEPT SELECT unnest(OLD.compartments));
  IF cardinality(removed) > 0 THEN
    SELECT * INTO old_reg FROM iam.compartment WHERE key = removed[1];
    IF cardinality(removed) <> 1 OR cardinality(added) <> 1
       OR old_reg.key IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM iam.compartment c
          WHERE c.key = added[1]
            AND c.created_at = old_reg.created_at
            AND c.created_by IS NOT DISTINCT FROM old_reg.created_by
            -- Registered in this very transaction, as the lifecycle's
            -- rename registers it: keys backfilled together share a
            -- creator and a time, and a swap between two of them is
            -- not a rename.
            AND c.xmin::text::bigint
                = pg_current_xact_id()::text::bigint % 4294967296) THEN
      RAISE EXCEPTION 'a rule set''s compartments are only added to, or '
        'renamed through the compartment registry: removing one would '
        'expose findings made under it';
    END IF;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_yara_ruleset_version(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.guard_yara_ruleset_version() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a YARA rule set version is never deleted: findings '
      'and licence decisions name it';
  END IF;
  IF OLD.adopted_by IS NOT NULL
     OR NEW.id <> OLD.id OR NEW.ruleset_id <> OLD.ruleset_id
     OR NEW.version <> OLD.version OR NEW.source_sha256 <> OLD.source_sha256
     OR NEW.source_gz <> OLD.source_gz OR NEW.source_bytes <> OLD.source_bytes
     OR NEW.files <> OLD.files OR NEW.file_count <> OLD.file_count
     OR NEW.licence <> OLD.licence
     OR NEW.licence_review_required <> OLD.licence_review_required
     OR NEW.provenance <> OLD.provenance
     OR NEW.note IS DISTINCT FROM OLD.note
     OR NEW.uploaded_by IS DISTINCT FROM OLD.uploaded_by
     OR NEW.uploaded_at <> OLD.uploaded_at THEN
    RAISE EXCEPTION 'a YARA rule set version is immutable; only its '
      'adoption is recorded, once';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: refuse_screening_hash_change(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.refuse_screening_hash_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'screening list entries are never % ; retire the list and '
    'purge its entries instead', lower(TG_OP);
END $$;

--
-- Name: yara_activation_rules(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.yara_activation_rules() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v lab.yara_ruleset_version%ROWTYPE;
  sponsor uuid;
BEGIN
  SELECT * INTO v FROM lab.yara_ruleset_version WHERE id = NEW.version_id;
  IF v.id IS NULL OR v.ruleset_id <> NEW.ruleset_id THEN
    RAISE EXCEPTION 'the version does not belong to this rule set';
  END IF;
  IF NEW.deactivated_at IS NOT NULL THEN
    RAISE EXCEPTION 'an activation starts open';
  END IF;
  sponsor := coalesce(v.uploaded_by, v.adopted_by);
  IF sponsor IS NULL THEN
    RAISE EXCEPTION 'an imported version must be adopted by a lab member '
      'before it can be activated';
  END IF;
  IF NEW.activated_by = sponsor THEN
    RAISE EXCEPTION 'the person who uploaded or adopted a version cannot '
      'activate it: somebody else has to';
  END IF;
  IF v.licence_review_required AND NEW.licence_acknowledgement IS NULL THEN
    RAISE EXCEPTION 'this version''s licence needs review: the activator '
      'must write down the clearance';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: yara_label_set(text[]); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.yara_label_set(text[]) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
  SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}')
    FROM unnest($1) AS x
$_$;

--
-- Name: announce_notification(); Type: FUNCTION; Schema: notify; Owner: -
--

CREATE FUNCTION notify.announce_notification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
          who uuid;
        BEGIN
          SELECT recipient_id INTO who FROM newrows LIMIT 1;
          IF who IS NULL THEN
            RETURN NULL;
          END IF;
          -- The RECIPIENT, not the case: a client subscribes to its own
          -- badge regardless of which case the notification belongs to,
          -- and the read filter decides whether it may actually see it.
          PERFORM pg_notify(
            'noctornal_change',
            json_build_object('recipient_id', who,
                              'kind', 'notification',
                              'op', TG_OP)::text);
          RETURN NULL;
        END $$;

--
-- Name: guard_jira_event(); Type: FUNCTION; Schema: notify; Owner: -
--

CREATE FUNCTION notify.guard_jira_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a Jira event row is the record of what was posted to a third-party system: it is never deleted';
  END IF;
  IF NEW.link_id IS DISTINCT FROM OLD.link_id
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.marker IS DISTINCT FROM OLD.marker THEN
    RAISE EXCEPTION 'a Jira event row cannot be moved to another issue or event';
  END IF;
  IF OLD.state = 'POSTED' AND (NEW.state <> 'POSTED'
       OR NEW.posted_at IS DISTINCT FROM OLD.posted_at
       OR NEW.posted_as IS DISTINCT FROM OLD.posted_as
       OR NEW.comment_id IS DISTINCT FROM OLD.comment_id) THEN
    RAISE EXCEPTION 'a posted Jira event stays posted';
  END IF;
  RETURN NEW;
END $$;

--
-- Name: guard_jira_link(); Type: FUNCTION; Schema: notify; Owner: -
--

CREATE FUNCTION notify.guard_jira_link() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a Jira link is the record that case material reached a third-party system: it is closed, never deleted';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.destination_id IS DISTINCT FROM OLD.destination_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.work_key IS DISTINCT FROM OLD.work_key
     OR NEW.ref IS DISTINCT FROM OLD.ref
     OR NEW.base_url IS DISTINCT FROM OLD.base_url
     OR NEW.project_key IS DISTINCT FROM OLD.project_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'a Jira link names one work item on one destination and cannot be rewritten';
  END IF;
  IF OLD.state = 'CLOSED' THEN
    IF NEW.state <> 'CLOSED'
       OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
       OR NEW.closed_reason IS DISTINCT FROM OLD.closed_reason
       OR (OLD.issue_key IS NOT NULL AND NEW.issue_key IS DISTINCT FROM OLD.issue_key)
       OR (OLD.issue_id IS NOT NULL AND NEW.issue_id IS DISTINCT FROM OLD.issue_id) THEN
      RAISE EXCEPTION 'a closed Jira link stays closed; only a missing issue key may still be recorded on it';
    END IF;
  END IF;
  RETURN NEW;
END $$;

--
-- Name: community_assignment; Type: TABLE; Schema: analytics; Owner: -
--

CREATE TABLE analytics.community_assignment (
    metric_run_id uuid NOT NULL,
    node_id uuid NOT NULL,
    community_id integer NOT NULL,
    membership_strength numeric(5,4)
);

--
-- Name: layout_position; Type: TABLE; Schema: analytics; Owner: -
--

CREATE TABLE analytics.layout_position (
    projection_id uuid NOT NULL,
    node_id uuid NOT NULL,
    x double precision NOT NULL,
    y double precision NOT NULL,
    is_pinned boolean DEFAULT false NOT NULL
);

--
-- Name: metric_run; Type: TABLE; Schema: analytics; Owner: -
--

CREATE TABLE analytics.metric_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    projection_id uuid NOT NULL,
    algorithm text NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_approximate boolean DEFAULT false NOT NULL,
    sample_size integer,
    node_count integer,
    edge_count integer,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    duration_ms integer,
    graph_hash bytea,
    status text DEFAULT 'RUNNING'::text NOT NULL,
    result jsonb DEFAULT '{}'::jsonb NOT NULL,
    error text,
    created_by uuid,
    visibility_clearance core.tlp NOT NULL,
    visibility_compartments text[] NOT NULL,
    CONSTRAINT metric_run_failed_explains_itself_ck CHECK (((status = 'FAILED'::text) = (error IS NOT NULL))),
    CONSTRAINT metric_run_status_ck CHECK ((status = ANY (ARRAY['RUNNING'::text, 'COMPLETE'::text, 'FAILED'::text])))
);

--
-- Name: node_metric; Type: TABLE; Schema: analytics; Owner: -
--

CREATE TABLE analytics.node_metric (
    metric_run_id uuid NOT NULL,
    node_id uuid NOT NULL,
    metric text NOT NULL,
    value double precision NOT NULL,
    rank integer,
    percentile numeric(5,2)
);

--
-- Name: projection; Type: TABLE; Schema: analytics; Owner: -
--

CREATE TABLE analytics.projection (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    name text NOT NULL,
    edge_types text[] NOT NULL,
    include_inferred boolean DEFAULT false NOT NULL,
    min_confidence core.analytic_confidence DEFAULT 'LOW'::core.analytic_confidence NOT NULL,
    as_of_from timestamp with time zone,
    as_of_to timestamp with time zone,
    is_directed boolean DEFAULT true NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    preset text,
    params jsonb DEFAULT '{}'::jsonb NOT NULL
);

--
-- Name: event; Type: TABLE; Schema: audit; Owner: -
--

CREATE TABLE audit.event (
    seq bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_id uuid,
    actor_kind text DEFAULT 'USER'::text NOT NULL,
    action text NOT NULL,
    object_type text,
    object_id uuid,
    case_id uuid,
    outcome text DEFAULT 'SUCCESS'::text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_hash bytea,
    session_id uuid,
    prev_hash bytea,
    row_hash bytea NOT NULL
);

--
-- Name: event_seq_seq; Type: SEQUENCE; Schema: audit; Owner: -
--

CREATE SEQUENCE audit.event_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: event_seq_seq; Type: SEQUENCE OWNED BY; Schema: audit; Owner: -
--

ALTER SEQUENCE audit.event_seq_seq OWNED BY audit.event.seq;

--
-- Name: collection_account; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.collection_account (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid,
    handle text NOT NULL,
    persona_notes text,
    secret_ciphertext bytea,
    secret_key_id text,
    secret_nonce bytea,
    secret_rotated_at timestamp with time zone,
    egress_profile_id uuid,
    fingerprint_profile jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'HEALTHY'::text NOT NULL,
    cooldown_until timestamp with time zone,
    last_used_at timestamp with time zone,
    burn_reason text,
    owner_user_id uuid,
    approved_by uuid,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    platform collect.source_kind,
    platform_uid text,
    last_request_at timestamp with time zone,
    status_changed_at timestamp with time zone,
    machine_hold_until timestamp with time zone,
    machine_hold_reason text,
    machine_lock_code text,
    machine_lock_at timestamp with time zone,
    session_enrolled_at timestamp with time zone,
    CONSTRAINT collection_account_enrolled_has_secret CHECK (((session_enrolled_at IS NULL) OR (COALESCE(octet_length(secret_ciphertext), 0) > 0))),
    CONSTRAINT collection_account_enrolled_has_uid CHECK (((session_enrolled_at IS NULL) OR (platform_uid IS NOT NULL))),
    CONSTRAINT collection_account_machine_hold_known CHECK ((((machine_hold_until IS NULL) = (machine_hold_reason IS NULL)) AND ((machine_hold_reason IS NULL) OR (machine_hold_reason = ANY (ARRAY['RATE_LIMITED'::text, 'ABANDONED'::text]))))),
    CONSTRAINT collection_account_machine_lock_known CHECK ((((machine_lock_code IS NULL) = (machine_lock_at IS NULL)) AND ((machine_lock_code IS NULL) OR (machine_lock_code = ANY (ARRAY['CREDENTIAL_REVOKED'::text, 'CREDENTIAL_DUPLICATED'::text, 'ACCOUNT_BANNED'::text, 'WRONG_ACCOUNT'::text, 'PLATFORM_REFUSED'::text]))))),
    CONSTRAINT collection_account_platform_is_persona_kind CHECK (((platform IS NULL) OR (platform = ANY (ARRAY['XENFORO'::collect.source_kind, 'MYBB'::collect.source_kind, 'PHPBB'::collect.source_kind, 'TELEGRAM'::collect.source_kind, 'DISCORD'::collect.source_kind])))),
    CONSTRAINT collection_account_telegram_fingerprint CHECK (((platform IS DISTINCT FROM 'TELEGRAM'::collect.source_kind) OR (session_enrolled_at IS NULL) OR (fingerprint_profile ?& ARRAY['device_model'::text, 'system_version'::text, 'app_version'::text, 'lang_code'::text, 'system_lang_code'::text]))),
    CONSTRAINT collection_account_telegram_has_no_venue CHECK (((platform IS DISTINCT FROM 'TELEGRAM'::collect.source_kind) OR (source_id IS NULL))),
    CONSTRAINT collection_account_telegram_needs_egress CHECK (((platform IS DISTINCT FROM 'TELEGRAM'::collect.source_kind) OR (egress_profile_id IS NOT NULL))),
    CONSTRAINT collection_account_telegram_uid_typed CHECK (((platform IS DISTINCT FROM 'TELEGRAM'::collect.source_kind) OR (session_enrolled_at IS NULL) OR (platform_uid ~ '^u:[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT collection_account_uid_needs_platform CHECK (((platform_uid IS NULL) OR (platform IS NOT NULL))),
    CONSTRAINT collection_account_uid_typed CHECK (((platform_uid IS NULL) OR (platform_uid ~ '^[a-z]{1,8}:[A-Za-z0-9_.-]{1,128}$'::text)))
);

--
-- Name: COLUMN collection_account.platform; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.platform IS 'The source kind this persona reads as (a collect.source_kind). One account on one platform for life.';

--
-- Name: COLUMN collection_account.platform_uid; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.platform_uid IS 'The persona''s own durable account id on its platform, typed (u:700000001).';

--
-- Name: COLUMN collection_account.last_request_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.last_request_at IS 'The per-persona request clock: the gap between two requests as this account is measured from here.';

--
-- Name: COLUMN collection_account.status_changed_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.status_changed_at IS 'When a person last moved the status. The machine columns have their own times.';

--
-- Name: COLUMN collection_account.machine_hold_until; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.machine_hold_until IS 'A wait the platform imposed (RATE_LIMITED) or a session that outlived its budget (ABANDONED). Written only by PersonaVault.signal, never shortened.';

--
-- Name: COLUMN collection_account.machine_lock_code; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.machine_lock_code IS 'The platform refused this persona''s credential. Cleared only by storing a new credential after the lock.';

--
-- Name: COLUMN collection_account.session_enrolled_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_account.session_enrolled_at IS 'When the sealed Telegram session was enrolled; NULL after a logout.';

--
-- Name: collection_authority; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.collection_authority (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    collection_account_id uuid,
    scope text NOT NULL,
    classification core.tlp NOT NULL,
    authority_ref text NOT NULL,
    issued_by text NOT NULL,
    jurisdiction text NOT NULL,
    legal_basis text NOT NULL,
    member_authority_ref text,
    target_description text NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    recorded_by uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    confirmed_by uuid,
    confirmed_at timestamp with time zone,
    confirm_note text,
    revoked_by uuid,
    revoked_at timestamp with time zone,
    revoke_reason text,
    CONSTRAINT collection_authority_confirm_complete CHECK ((((confirmed_by IS NULL) = (confirmed_at IS NULL)) AND ((confirmed_by IS NULL) = (confirm_note IS NULL)))),
    CONSTRAINT collection_authority_member_needs_persona CHECK (((scope = 'PUBLIC_READ'::text) OR (collection_account_id IS NOT NULL))),
    CONSTRAINT collection_authority_member_needs_reference CHECK (((scope <> 'MEMBER_READ'::text) OR (length(btrim(COALESCE(member_authority_ref, ''::text))) > 0))),
    CONSTRAINT collection_authority_referenced CHECK (((length(btrim(authority_ref)) >= 3) AND (length(btrim(issued_by)) > 0) AND (length(btrim(jurisdiction)) > 1) AND (length(btrim(legal_basis)) > 0) AND (length(btrim(target_description)) > 20))),
    CONSTRAINT collection_authority_revocation_complete CHECK ((((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL)))),
    CONSTRAINT collection_authority_scope_known CHECK ((scope = ANY (ARRAY['PUBLIC_READ'::text, 'MEMBER_READ'::text]))),
    CONSTRAINT collection_authority_two_people CHECK (((confirmed_by IS NULL) OR (confirmed_by <> recorded_by))),
    CONSTRAINT collection_authority_window CHECK (((valid_until > valid_from) AND (valid_until <= (valid_from + '366 days'::interval))))
);

--
-- Name: TABLE collection_authority; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.collection_authority IS 'A written authority to collect, which exists outside this system: who declared it (recorded_by) and who confirmed it (confirmed_by, never the same person). Every forum and Telegram read needs one covering its source. Never deleted and never rewritten: revocation is a column, and the classification only rises.';

--
-- Name: collection_authority_target; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.collection_authority_target (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    authority_id uuid NOT NULL,
    source_id uuid NOT NULL,
    added_by uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    target_base_url text,
    target_egress_profile_id uuid,
    confirmed_by uuid,
    confirmed_at timestamp with time zone,
    revoked_by uuid,
    revoked_at timestamp with time zone,
    revoke_reason text,
    CONSTRAINT authority_target_confirm_complete CHECK (((confirmed_by IS NULL) = (confirmed_at IS NULL))),
    CONSTRAINT authority_target_revocation_complete CHECK ((((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL)))),
    CONSTRAINT authority_target_two_people CHECK (((confirmed_by IS NULL) OR (confirmed_by <> added_by)))
);

--
-- Name: TABLE collection_authority_target; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.collection_authority_target IS 'One source under a collection authority, added by one person and confirmed by another. Covers its source only while the source''s address equals target_base_url and, for a persona-less authority, its exit equals target_egress_profile_id. Never deleted.';

--
-- Name: COLUMN collection_authority_target.target_base_url; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_authority_target.target_base_url IS 'The source''s address when the target was added: the address the confirmer was shown. Frozen.';

--
-- Name: COLUMN collection_authority_target.target_egress_profile_id; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_authority_target.target_egress_profile_id IS 'For a persona-less authority, the exit the source was read through when the target was added. Frozen. NULL for a persona''s target.';

--
-- Name: collection_run; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.collection_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    watch_id uuid,
    collection_account_id uuid,
    egress_profile_id uuid,
    status collect.run_status DEFAULT 'QUEUED'::collect.run_status NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    items_seen integer DEFAULT 0 NOT NULL,
    items_new integer DEFAULT 0 NOT NULL,
    http_status integer,
    error_class text,
    error_detail text,
    etag text,
    last_modified text,
    cursor jsonb DEFAULT '{}'::jsonb NOT NULL,
    parser_version text,
    requests jsonb DEFAULT '[]'::jsonb NOT NULL,
    requested_by uuid,
    notes text[] DEFAULT '{}'::text[] NOT NULL,
    items_deleted integer DEFAULT 0 NOT NULL,
    authority_id uuid,
    authority_target_id uuid,
    CONSTRAINT collection_run_cursor_capped CHECK (((jsonb_typeof(cursor) = 'object'::text) AND (octet_length((cursor)::text) <= 16384))),
    CONSTRAINT collection_run_items_deleted_non_negative CHECK ((items_deleted >= 0)),
    CONSTRAINT collection_run_notes_capped CHECK ((cardinality(notes) <= 20)),
    CONSTRAINT collection_run_requests_capped CHECK (((jsonb_typeof(requests) = 'array'::text) AND (jsonb_array_length(requests) <= 100))),
    CONSTRAINT collection_run_target_needs_authority CHECK (((authority_target_id IS NULL) OR (authority_id IS NOT NULL)))
);

--
-- Name: COLUMN collection_run.requests; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_run.requests IS 'The custody log of what a poll asked for: at most 100 entries of time, path, query, status, bytes and digest. Written once as the run leaves RUNNING and never rewritten. Read under the source''s label.';

--
-- Name: COLUMN collection_run.requested_by; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_run.requested_by IS 'Who pressed Poll now. NULL is the system (the cron). A plain uuid, as audit.event.actor_id is.';

--
-- Name: COLUMN collection_run.notes; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_run.notes IS 'What a run wants known that is not a fault: a walk that stopped at its budget, documents with no retention clock, times with no zone.';

--
-- Name: COLUMN collection_run.items_deleted; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_run.items_deleted IS 'Items the site no longer shows, flagged on their latest version. The bodies are kept: deletions are intelligence.';

--
-- Name: COLUMN collection_run.authority_id; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.collection_run.authority_id IS 'The confirmed authority this poll of a forum or Telegram source ran under.';

--
-- Name: document; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.document (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    collection_run_id uuid,
    watch_id uuid,
    external_id text,
    external_url text,
    thread_ref text,
    parent_ref text,
    author_handle text,
    author_uid text,
    posted_at timestamp with time zone,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    title text,
    body_text text NOT NULL,
    body_html_key text,
    lang text,
    content_sha256 bytea NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    supersedes_id uuid,
    is_deleted_upstream boolean DEFAULT false NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    search_tsv tsvector,
    triage_state text DEFAULT 'NEW'::text NOT NULL,
    category text DEFAULT 'UNKNOWN'::text NOT NULL,
    retain_until timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    purged_at timestamp with time zone,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    legal_hold_reason text,
    legal_hold_by uuid,
    CONSTRAINT document_hold_has_reason CHECK (((NOT legal_hold) OR (length(btrim(COALESCE(legal_hold_reason, ''::text))) > 0)))
);

--
-- Name: COLUMN document.compartments; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.document.compartments IS 'The need-to-know lock a document is read under. A capture copies the compartments of the case it was captured into; a collected document carries what its collection path assigns (none, until a source carries compartments). Every reader checks d.compartments <@ its own. Bound to iam.compartment by the compartments_registered trigger.';

--
-- Name: COLUMN document.legal_hold_reason; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.document.legal_hold_reason IS 'Why this document, and every earlier version of it, is frozen against deletion. Set and lifted by a person with retention.manage; the purge also honours holds on every case that cites it.';

--
-- Name: COLUMN document.legal_hold_by; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.document.legal_hold_by IS 'Who last placed or lifted the document-level hold.';

--
-- Name: document_embedding; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.document_embedding (
    document_id uuid NOT NULL,
    slot smallint NOT NULL,
    space_id uuid NOT NULL,
    status text NOT NULL,
    embedding public.vector(768),
    reason text,
    read_classification core.tlp NOT NULL,
    read_compartments text[] DEFAULT '{}'::text[] NOT NULL,
    sent_classification core.tlp,
    input_chars integer DEFAULT 0 NOT NULL,
    truncated_chars integer DEFAULT 0 NOT NULL,
    attempts smallint DEFAULT 1 NOT NULL,
    first_failed_at timestamp with time zone,
    next_attempt_at timestamp with time zone,
    embedded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT document_embedding_attempts_check CHECK ((attempts >= 1)),
    CONSTRAINT document_embedding_failure_dated CHECK (((status = 'FAILED'::text) = (first_failed_at IS NOT NULL))),
    CONSTRAINT document_embedding_input_chars_check CHECK ((input_chars >= 0)),
    CONSTRAINT document_embedding_reason_unless_embedded CHECK (((status = 'EMBEDDED'::text) = (reason IS NULL))),
    CONSTRAINT document_embedding_retry_dated CHECK (((status <> ALL (ARRAY['FAILED'::text, 'WITHHELD'::text])) OR (next_attempt_at IS NOT NULL))),
    CONSTRAINT document_embedding_sent_only_embedded CHECK (((sent_classification IS NULL) OR (status = 'EMBEDDED'::text))),
    CONSTRAINT document_embedding_status_check CHECK ((status = ANY (ARRAY['EMBEDDED'::text, 'EMPTY'::text, 'EXCLUDED'::text, 'WITHHELD'::text, 'FAILED'::text]))),
    CONSTRAINT document_embedding_truncated_chars_check CHECK ((truncated_chars >= 0)),
    CONSTRAINT document_embedding_vector_iff_embedded CHECK (((status = 'EMBEDDED'::text) = (embedding IS NOT NULL)))
);

--
-- Name: TABLE document_embedding; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.document_embedding IS 'One similarity outcome per collected document and slot (F6.1). The labels are set by trigger from the document and its source; a change to either deletes the row. A vector is handled as its text: it never leaves the database through the product.';

--
-- Name: egress_binding; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.egress_binding (
    seq bigint NOT NULL,
    collection_account_id uuid,
    source_id uuid,
    egress_profile_id uuid,
    bound_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT egress_binding_one_subject CHECK (((collection_account_id IS NULL) <> (source_id IS NULL)))
);

--
-- Name: TABLE egress_binding; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.egress_binding IS 'When each persona and each persona-less source was bound to an egress profile. Append-only, written only by collect.record_egress_binding(); the egress proxy refuses authorities that predate the latest row.';

--
-- Name: egress_binding_seq_seq; Type: SEQUENCE; Schema: collect; Owner: -
--

CREATE SEQUENCE collect.egress_binding_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: egress_binding_seq_seq; Type: SEQUENCE OWNED BY; Schema: collect; Owner: -
--

ALTER SEQUENCE collect.egress_binding_seq_seq OWNED BY collect.egress_binding.seq;

--
-- Name: egress_connection; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.egress_connection (
    seq bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    event text NOT NULL,
    connection_id uuid,
    protocol text,
    route_kind text,
    route_id text NOT NULL,
    peer_address inet,
    egress_profile_id uuid,
    integration_route_id uuid,
    collection_run_id uuid,
    source_id uuid,
    collection_account_id uuid,
    authority_id uuid,
    context_kind text,
    context_id uuid,
    dest_host text,
    dest_digest bytea,
    dest_port integer,
    resolved_address inet,
    exit_kind text,
    reason text NOT NULL,
    item_count integer,
    bytes_up bigint,
    bytes_down bigint,
    duration_ms integer,
    classification core.tlp DEFAULT 'GREEN'::core.tlp NOT NULL,
    source_compartmented boolean DEFAULT false NOT NULL,
    prev_hash bytea,
    row_hash bytea NOT NULL,
    CONSTRAINT egress_connection_close_shape CHECK (((event <> 'CLOSE'::text) OR ((connection_id IS NOT NULL) AND (duration_ms >= 0) AND (bytes_up >= 0) AND (bytes_down >= 0) AND (dest_host IS NULL) AND (dest_digest IS NULL) AND (dest_port IS NULL) AND (resolved_address IS NULL) AND (item_count IS NULL) AND (reason = ANY (ARRAY['client_closed'::text, 'upstream_closed'::text, 'idle_timeout'::text, 'session_limit'::text, 'proxy_shutdown'::text, 'error'::text, 'authority_revoked'::text, 'run_finished'::text, 'route_withdrawn'::text, 'persona_withdrawn'::text]))))),
    CONSTRAINT egress_connection_context_known CHECK (((context_kind IS NULL) OR (context_kind = ANY (ARRAY['run'::text, 'act'::text, 'stop'::text, 'delivery'::text, 'lookup'::text, 'detonation'::text, 'embed'::text, 'wkd'::text, 'check'::text])))),
    CONSTRAINT egress_connection_dest_shape CHECK ((((dest_host IS NULL) OR ((length(dest_host) >= 1) AND (length(dest_host) <= 253))) AND ((dest_port IS NULL) OR ((dest_port >= 1) AND (dest_port <= 65535))))),
    CONSTRAINT egress_connection_event_known CHECK ((event = ANY (ARRAY['OPEN'::text, 'REFUSED'::text, 'CLOSE'::text, 'PREAUTH'::text, 'REWRAP'::text]))),
    CONSTRAINT egress_connection_exit_known CHECK (((exit_kind IS NULL) OR (exit_kind = ANY (ARRAY['DIRECT'::text, 'HTTP'::text, 'HTTPS'::text, 'SOCKS5'::text])))),
    CONSTRAINT egress_connection_open_shape CHECK (((event <> 'OPEN'::text) OR ((connection_id IS NOT NULL) AND (protocol IS NOT NULL) AND (route_kind IS NOT NULL) AND (dest_host IS NOT NULL) AND (dest_port IS NOT NULL) AND (exit_kind IS NOT NULL) AND (reason = 'allowed'::text) AND (bytes_up IS NULL) AND (bytes_down IS NULL) AND (duration_ms IS NULL) AND (item_count IS NULL)))),
    CONSTRAINT egress_connection_peer_only_preauth CHECK (((peer_address IS NULL) OR (event = 'PREAUTH'::text))),
    CONSTRAINT egress_connection_preauth_shape CHECK (((event <> 'PREAUTH'::text) OR ((peer_address IS NOT NULL) AND (item_count > 0) AND (route_id = 'proxy'::text) AND (reason = 'preauth_refused'::text) AND (connection_id IS NULL) AND (route_kind IS NULL) AND (context_kind IS NULL) AND (context_id IS NULL) AND (dest_host IS NULL) AND (dest_digest IS NULL) AND (dest_port IS NULL)))),
    CONSTRAINT egress_connection_profile_is_persona CHECK (((egress_profile_id IS NULL) OR (route_kind = 'persona'::text))),
    CONSTRAINT egress_connection_protocol_known CHECK (((protocol IS NULL) OR (protocol = ANY (ARRAY['HTTP_CONNECT'::text, 'SOCKS5'::text])))),
    CONSTRAINT egress_connection_refused_shape CHECK (((event <> 'REFUSED'::text) OR ((connection_id IS NOT NULL) AND (protocol IS NOT NULL) AND (route_kind IS NOT NULL) AND (reason <> 'allowed'::text) AND (bytes_up IS NULL) AND (bytes_down IS NULL) AND (duration_ms IS NULL) AND (item_count IS NULL)))),
    CONSTRAINT egress_connection_rewrap_shape CHECK (((event <> 'REWRAP'::text) OR ((item_count >= 0) AND (route_id = 'proxy'::text) AND (reason = 'exits_rewrapped'::text) AND (route_kind IS NULL) AND (dest_host IS NULL) AND (dest_port IS NULL)))),
    CONSTRAINT egress_connection_route_is_integration CHECK (((integration_route_id IS NULL) OR (route_kind = 'integration'::text))),
    CONSTRAINT egress_connection_route_kind_known CHECK (((route_kind IS NULL) OR (route_kind = ANY (ARRAY['persona'::text, 'integration'::text]))))
);

--
-- Name: TABLE egress_connection; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.egress_connection IS 'What left this deployment: one row per egress proxy event (OPEN before any dial, REFUSED, CLOSE, PREAUTH, REWRAP). Append-only and hash-chained; written by noctornal_egress.';

--
-- Name: egress_connection_seq; Type: SEQUENCE; Schema: collect; Owner: -
--

CREATE SEQUENCE collect.egress_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: egress_destination; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.egress_destination (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    route_id uuid NOT NULL,
    entry text NOT NULL,
    note text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    created_by uuid,
    retired_at timestamp with time zone,
    retired_by uuid,
    CONSTRAINT egress_destination_no_wildcard CHECK (((POSITION(('*'::text) IN (entry)) = 0) AND ((length(entry) >= 3) AND (length(entry) <= 300)))),
    CONSTRAINT egress_destination_noted CHECK (((length(btrim(note)) >= 5) AND (length(btrim(note)) <= 500))),
    CONSTRAINT egress_destination_retirement_complete CHECK (((retired_at IS NULL) = (retired_by IS NULL)))
);

--
-- Name: egress_integration_route; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.egress_integration_route (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    idle_timeout_s integer DEFAULT 60 NOT NULL,
    max_session_s integer DEFAULT 300 NOT NULL,
    max_concurrent integer DEFAULT 8 NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    created_by uuid,
    updated_at timestamp with time zone,
    updated_by uuid,
    retired_at timestamp with time zone,
    retired_by uuid,
    retire_reason text,
    CONSTRAINT egress_integration_route_described CHECK (((length(btrim(description)) >= 5) AND (length(btrim(description)) <= 500))),
    CONSTRAINT egress_integration_route_limits CHECK ((((idle_timeout_s >= 5) AND (idle_timeout_s <= 3600)) AND ((max_session_s >= 10) AND (max_session_s <= 86400)) AND ((max_concurrent >= 1) AND (max_concurrent <= 64)))),
    CONSTRAINT egress_integration_route_name CHECK ((name ~ '^[a-z][a-z0-9-]{1,39}$'::text)),
    CONSTRAINT egress_integration_route_retirement_complete CHECK (((retired_at IS NULL) OR ((NOT is_active) AND (retired_by IS NOT NULL) AND (length(btrim(COALESCE(retire_reason, ''::text))) >= 5))))
);

--
-- Name: egress_profile; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.egress_profile (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    endpoint_ciphertext bytea,
    key_id text,
    region text,
    is_active boolean DEFAULT true NOT NULL,
    exit_kind text,
    exit_sealed bytea,
    exit_seal_key_id text,
    exit_fingerprint bytea,
    exit_sealed_at timestamp with time zone,
    exit_sealed_by uuid,
    ceiling core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    allowed_ports integer[] DEFAULT '{443}'::integer[] NOT NULL,
    any_public_host boolean DEFAULT false NOT NULL,
    allowed_host_suffixes text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_cidrs cidr[] DEFAULT '{}'::cidr[] NOT NULL,
    allow_onion boolean DEFAULT false NOT NULL,
    resolve_at_proxy boolean DEFAULT false NOT NULL,
    cleartext_upstream_ack boolean DEFAULT false NOT NULL,
    idle_timeout_s integer DEFAULT 120 NOT NULL,
    max_session_s integer DEFAULT 900 NOT NULL,
    max_concurrent integer DEFAULT 4 NOT NULL,
    is_passive_default boolean DEFAULT false NOT NULL,
    reach_changed_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_at timestamp with time zone,
    updated_by uuid,
    retired_at timestamp with time zone,
    retired_by uuid,
    retire_reason text,
    persona_capable boolean GENERATED ALWAYS AS ((is_active AND (retired_at IS NULL) AND (NOT is_passive_default) AND COALESCE((exit_kind = ANY (ARRAY['HTTP'::text, 'HTTPS'::text, 'SOCKS5'::text])), false))) STORED,
    CONSTRAINT egress_profile_direct_is_datacentre CHECK (((exit_kind IS DISTINCT FROM 'DIRECT'::text) OR (kind = 'DATACENTRE'::text))),
    CONSTRAINT egress_profile_endpoint_ciphertext_retired CHECK ((endpoint_ciphertext IS NULL)),
    CONSTRAINT egress_profile_exit_kind_known CHECK (((exit_kind IS NULL) OR (exit_kind = ANY (ARRAY['DIRECT'::text, 'HTTP'::text, 'HTTPS'::text, 'SOCKS5'::text])))),
    CONSTRAINT egress_profile_exit_shape CHECK (((COALESCE(exit_kind, ''::text) = ANY (ARRAY['HTTP'::text, 'HTTPS'::text, 'SOCKS5'::text])) = ((exit_sealed IS NOT NULL) AND (exit_seal_key_id IS NOT NULL) AND (exit_fingerprint IS NOT NULL)))),
    CONSTRAINT egress_profile_limits CHECK ((((idle_timeout_s >= 5) AND (idle_timeout_s <= 3600)) AND ((max_session_s >= 10) AND (max_session_s <= 86400)) AND ((max_concurrent >= 1) AND (max_concurrent <= 64)))),
    CONSTRAINT egress_profile_onion_only_tor CHECK (((NOT allow_onion) OR (kind = 'TOR'::text))),
    CONSTRAINT egress_profile_passive_default_active CHECK (((NOT is_passive_default) OR is_active)),
    CONSTRAINT egress_profile_ports CHECK ((((cardinality(allowed_ports) >= 1) AND (cardinality(allowed_ports) <= 16)) AND (array_position(allowed_ports, NULL::integer) IS NULL) AND (0 < ALL (allowed_ports)) AND (65536 > ALL (allowed_ports)))),
    CONSTRAINT egress_profile_retirement_complete CHECK (((retired_at IS NULL) OR ((NOT is_active) AND (NOT is_passive_default) AND (retired_by IS NOT NULL) AND (length(btrim(COALESCE(retire_reason, ''::text))) >= 5)))),
    CONSTRAINT egress_profile_rule_counts CHECK (((cardinality(allowed_host_suffixes) <= 64) AND (cardinality(allowed_cidrs) <= 64) AND (array_position(allowed_host_suffixes, NULL::text) IS NULL) AND (array_position(allowed_cidrs, NULL::cidr) IS NULL))),
    CONSTRAINT egress_profile_tor_shape CHECK (((kind <> 'TOR'::text) OR ((COALESCE(exit_kind, 'SOCKS5'::text) = 'SOCKS5'::text) AND (NOT resolve_at_proxy))))
);

--
-- Name: COLUMN egress_profile.endpoint_ciphertext; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.egress_profile.endpoint_ciphertext IS 'Retired by 0085 and always NULL: superseded by exit_sealed, sealed for the egress proxy under its own key.';

--
-- Name: COLUMN egress_profile.exit_sealed; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.egress_profile.exit_sealed IS 'The exit endpoint, HPKE-sealed to the egress proxy''s key (security/egress_seal.py): the API seals and cannot open it.';

--
-- Name: COLUMN egress_profile.reach_changed_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.egress_profile.reach_changed_at IS 'When this profile last reached further than before. Set by collect.egress_profile_reach() alone.';

--
-- Name: extraction; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.extraction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    document_id uuid NOT NULL,
    selector_type text NOT NULL,
    raw_value text NOT NULL,
    norm_value text NOT NULL,
    char_start integer,
    char_end integer,
    extractor text NOT NULL,
    extractor_version text,
    score numeric(4,3),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: forum_member; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.forum_member (
    document_id uuid NOT NULL,
    profile jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT forum_member_profile_object CHECK (((jsonb_typeof(profile) = 'object'::text) AND (octet_length((profile)::text) <= 16384)))
);

--
-- Name: TABLE forum_member; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.forum_member IS 'A collected forum member profile''s fields (title, joined, contact and custom fields, counters), one row per member document version (category FORUM_MEMBER). No label of its own: read only joined to its document. Deleted by the retention purge with its document''s text.';

--
-- Name: forum_post; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.forum_post (
    document_id uuid NOT NULL,
    signature_text text,
    quoted_post_refs text[] DEFAULT '{}'::text[] NOT NULL,
    reactions jsonb DEFAULT '{}'::jsonb NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT forum_post_quotes_capped CHECK (((cardinality(quoted_post_refs) <= 50) AND (array_position(quoted_post_refs, NULL::text) IS NULL))),
    CONSTRAINT forum_post_reactions_object CHECK (((jsonb_typeof(reactions) = 'object'::text) AND (octet_length((reactions)::text) <= 8192))),
    CONSTRAINT forum_post_signature_capped CHECK (((signature_text IS NULL) OR (char_length(signature_text) <= 4000)))
);

--
-- Name: TABLE forum_post; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.forum_post IS 'What a collected forum post carries beside its text: its signature, the posts it quotes and its reactions. No label of its own: read only joined to its document, under the document''s and the source''s labels and compartments. Deleted by the retention purge with its document''s text.';

--
-- Name: COLUMN forum_post.signature_text; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.forum_post.signature_text IS 'The signature printed under the post: repeated on every post its author writes, so it describes the author and is not an observation per post.';

--
-- Name: COLUMN forum_post.quoted_post_refs; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.forum_post.quoted_post_refs IS 'The posts this post quotes, typed post:<id>. The quoted text itself is never stored as this post''s.';

--
-- Name: COLUMN forum_post.reactions; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.forum_post.reactions IS 'A count, up to 50 reactor names as the forum shows them, and up to 10 reaction kinds.';

--
-- Name: COLUMN forum_post.observed_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.forum_post.observed_at IS 'When the side row was last written: a signature or reactions that changed without the text refresh it.';

--
-- Name: proposal; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.proposal (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    origin text NOT NULL,
    score numeric(4,3),
    rationale text NOT NULL,
    document_id uuid,
    state core.review_state DEFAULT 'PROPOSED'::core.review_state NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_note text,
    applied_node_id uuid,
    applied_edge_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    lookup_result_id uuid
);

--
-- Name: COLUMN proposal.lookup_result_id; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.proposal.lookup_result_id IS 'The lookup answer this proposal was raised from; its label joins the proposal''s read label.';

--
-- Name: source; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.source (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind collect.source_kind NOT NULL,
    name text NOT NULL,
    base_url text,
    default_reliability core.source_reliability DEFAULT 'F'::core.source_reliability NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    poll_interval_s integer DEFAULT 900 NOT NULL,
    jitter_pct integer DEFAULT 25 NOT NULL,
    max_rps numeric(6,3) DEFAULT 0.2 NOT NULL,
    parser_key text,
    parser_version text,
    last_ok_at timestamp with time zone,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    health text DEFAULT 'UNKNOWN'::text NOT NULL,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    next_due_at timestamp with time zone,
    last_request_at timestamp with time zone,
    parser_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    blocked_reason text,
    blocked_at timestamp with time zone,
    cursor_reset_at timestamp with time zone,
    collection_account_id uuid,
    egress_profile_id uuid,
    CONSTRAINT source_blocked_complete CHECK (((blocked_reason IS NULL) = (blocked_at IS NULL))),
    CONSTRAINT source_one_egress_binding CHECK (((collection_account_id IS NULL) OR (egress_profile_id IS NULL))),
    CONSTRAINT source_parser_config_is_object CHECK (((jsonb_typeof(parser_config) = 'object'::text) AND (octet_length((parser_config)::text) <= 16384)))
);

--
-- Name: COLUMN source.next_due_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.next_due_at IS 'When this source is next due. Rolled once with jitter after each run; re-rolling on read is what made the cadence regular -- docs/17 F15(i).';

--
-- Name: COLUMN source.last_request_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.last_request_at IS 'Last outbound attempt, successful or not. The per-source max_rps gap is measured from here so it survives the process.';

--
-- Name: COLUMN source.parser_config; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.parser_config IS 'Per-parser settings an adapter validates (a board''s time zone, a page budget). A JSON object of at most 16 KiB.';

--
-- Name: COLUMN source.blocked_reason; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.blocked_reason IS 'Why the last poll could not run at all: no authority, no egress, a suspended persona. Cleared by the next good poll. Configuration, never parser health.';

--
-- Name: COLUMN source.cursor_reset_at; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.cursor_reset_at IS 'Runs started before this are not a resume point: the next poll starts its reading position afresh.';

--
-- Name: COLUMN source.collection_account_id; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.collection_account_id IS 'The persona this source is polled as, one at a time. It reads through that persona''s egress profile.';

--
-- Name: COLUMN source.egress_profile_id; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.source.egress_profile_id IS 'The exit a persona-less source is read through. Never set beside a persona.';

--
-- Name: telegram_chat; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.telegram_chat (
    source_id uuid NOT NULL,
    peer_type text NOT NULL,
    peer_id bigint NOT NULL,
    durable_id text NOT NULL,
    access_mode text NOT NULL,
    provenance_class text NOT NULL,
    username_at_resolve text,
    title_at_resolve text,
    resolved_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_by uuid NOT NULL,
    access_hash bigint,
    access_hash_account_id uuid,
    member_since_observed timestamp with time zone,
    joined_by uuid,
    joined_at timestamp with time zone,
    is_forum boolean DEFAULT false NOT NULL,
    noforwards boolean DEFAULT false NOT NULL,
    migrated_to text,
    CONSTRAINT telegram_chat_access_known CHECK ((access_mode = ANY (ARRAY['PUBLIC_READ'::text, 'MEMBER'::text]))),
    CONSTRAINT telegram_chat_basic_groups_are_never_public CHECK (((peer_type <> 'CHAT'::text) OR (access_mode = 'MEMBER'::text))),
    CONSTRAINT telegram_chat_durable_typed CHECK ((durable_id = (
CASE
    WHEN (peer_type = 'CHAT'::text) THEN 'g:'::text
    ELSE 'c:'::text
END || (peer_id)::text))),
    CONSTRAINT telegram_chat_hash_has_owner CHECK (((access_hash IS NULL) = (access_hash_account_id IS NULL))),
    CONSTRAINT telegram_chat_join_complete CHECK ((((joined_by IS NULL) = (joined_at IS NULL)) AND ((joined_at IS NULL) OR (member_since_observed IS NOT NULL)))),
    CONSTRAINT telegram_chat_member_reads_as_member CHECK (((member_since_observed IS NULL) OR (access_mode = 'MEMBER'::text))),
    CONSTRAINT telegram_chat_migrated_typed CHECK (((migrated_to IS NULL) OR (migrated_to ~ '^c:[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT telegram_chat_names_capped CHECK (((COALESCE(length(username_at_resolve), 0) <= 32) AND (COALESCE(length(title_at_resolve), 0) <= 256))),
    CONSTRAINT telegram_chat_peer_known CHECK ((peer_type = ANY (ARRAY['CHANNEL'::text, 'MEGAGROUP'::text, 'GIGAGROUP'::text, 'CHAT'::text]))),
    CONSTRAINT telegram_chat_peer_positive CHECK ((peer_id > 0)),
    CONSTRAINT telegram_chat_provenance_follows_access CHECK ((((access_mode = 'PUBLIC_READ'::text) AND (provenance_class = 'OPEN_GROUP'::text)) OR ((access_mode = 'MEMBER'::text) AND (provenance_class = 'PERSONA_PARTY'::text))))
);

--
-- Name: TABLE telegram_chat; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.telegram_chat IS 'Which Telegram chat a source is, and how it is read. The identity is fixed and the row is never deleted, so a confirmed authority target never silently changes chat.';

--
-- Name: COLUMN telegram_chat.member_since_observed; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.telegram_chat.member_since_observed IS 'When Telegram last reported the reading persona a member. Only a member chat carries it; cleared when the persona is seen to have left.';

--
-- Name: telegram_message; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.telegram_message (
    document_id uuid NOT NULL,
    source_id uuid NOT NULL,
    chat_durable_id text NOT NULL,
    message_id bigint NOT NULL,
    seen_via_uid text NOT NULL,
    sender_uid text,
    sender_handle_at_capture text,
    post_author text,
    fwd_from_uid text,
    fwd_from_name text,
    fwd_from_message_id bigint,
    reply_to_message_id bigint,
    topic_id bigint,
    grouped_id bigint,
    via_bot_uid text,
    is_service boolean DEFAULT false NOT NULL,
    service_action text,
    is_self boolean DEFAULT false NOT NULL,
    media_kind text,
    noforwards boolean DEFAULT false NOT NULL,
    edit_date timestamp with time zone,
    views_at_capture integer,
    forwards_at_capture integer,
    deleted_seen_at timestamp with time zone,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT telegram_message_bot_typed CHECK (((via_bot_uid IS NULL) OR (via_bot_uid ~ '^u:[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT telegram_message_chat_typed CHECK ((chat_durable_id ~ '^[cg]:[1-9][0-9]{0,19}$'::text)),
    CONSTRAINT telegram_message_fwd_typed CHECK (((fwd_from_uid IS NULL) OR (fwd_from_uid ~ '^[ucg]:[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT telegram_message_id_positive CHECK ((message_id > 0)),
    CONSTRAINT telegram_message_media_known CHECK (((media_kind IS NULL) OR (media_kind ~ '^[a-z_]{1,32}$'::text))),
    CONSTRAINT telegram_message_names_capped CHECK (((COALESCE(length(sender_handle_at_capture), 0) <= 256) AND (COALESCE(length(post_author), 0) <= 256) AND (COALESCE(length(fwd_from_name), 0) <= 256))),
    CONSTRAINT telegram_message_sender_typed CHECK (((sender_uid IS NULL) OR (sender_uid ~ '^[ucg]:[1-9][0-9]{0,19}$'::text))),
    CONSTRAINT telegram_message_service_action_is_a_class_name CHECK (((service_action IS NULL) OR (service_action ~ '^[A-Za-z]{1,64}$'::text))),
    CONSTRAINT telegram_message_service_named CHECK ((is_service = (service_action IS NOT NULL))),
    CONSTRAINT telegram_message_via_typed CHECK ((seen_via_uid ~ '^u:[1-9][0-9]{0,19}$'::text))
);

--
-- Name: TABLE telegram_message; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON TABLE collect.telegram_message IS 'The capture record of one stored Telegram message. It has no label of its own and is read only joined to its document, whose classification, compartments and source''s classification gate it. Media is never downloaded by this adapter (docs/16 L1).';

--
-- Name: COLUMN telegram_message.service_action; Type: COMMENT; Schema: collect; Owner: -
--

COMMENT ON COLUMN collect.telegram_message.service_action IS 'The TL action''s class name for a service message (who joined or left is in the document body), never an id.';

--
-- Name: watch; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.watch (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    source_id uuid NOT NULL,
    collection_account_id uuid,
    name text NOT NULL,
    target_kind text NOT NULL,
    target_ref text NOT NULL,
    keywords text[],
    selector_watch text[],
    regexes text[],
    priority smallint DEFAULT 3 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    owner_user_id uuid NOT NULL,
    suppress_window_s integer DEFAULT 3600 NOT NULL,
    digest_only boolean DEFAULT false NOT NULL,
    quiet_hours int4range,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_hit_at timestamp with time zone,
    CONSTRAINT watch_priority_check CHECK (((priority >= 1) AND (priority <= 5)))
);

--
-- Name: watch_hit; Type: TABLE; Schema: collect; Owner: -
--

CREATE TABLE collect.watch_hit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    watch_id uuid NOT NULL,
    document_id uuid NOT NULL,
    matched_on jsonb NOT NULL,
    score numeric(4,3),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    notified_at timestamp with time zone,
    suppressed boolean DEFAULT false NOT NULL,
    suppress_reason text,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone
);

--
-- Name: channel_binding; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.channel_binding (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    platform_key text NOT NULL,
    identity_node_id uuid,
    observed_value text NOT NULL,
    durable_value text,
    verification text DEFAULT 'CLAIMED'::text NOT NULL,
    verification_note text,
    co_declaration_ref text,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT channel_binding_confirmation_has_method CHECK (((verification <> 'CONFIRMED'::text) OR (verification_note IS NOT NULL))),
    CONSTRAINT channel_binding_verification_known CHECK ((verification = ANY (ARRAY['CLAIMED'::text, 'OBSERVED'::text, 'CONFIRMED'::text])))
);

--
-- Name: contact_block; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.contact_block (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    publisher_identity_node_id uuid,
    publisher_handle text,
    source_ref text NOT NULL,
    document_id uuid,
    evidence_id uuid,
    raw_text text NOT NULL,
    raw_sha256 bytea NOT NULL,
    block_fingerprint text NOT NULL,
    parser_version text NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: contact_block_entry; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.contact_block_entry (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    block_id uuid NOT NULL,
    line_no integer NOT NULL,
    label text,
    platform_key text,
    selector_type text,
    observed_value text NOT NULL,
    durable_value text,
    role text NOT NULL,
    role_reason text NOT NULL,
    score numeric(4,3) NOT NULL,
    score_reason text NOT NULL,
    stoplist_id uuid,
    shared_service_publishers integer,
    shared_service_counted_at timestamp with time zone,
    proposal_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT contact_block_entry_role_known CHECK ((role = ANY (ARRAY['SELF'::text, 'THIRD_PARTY'::text, 'UNPARSED'::text]))),
    CONSTRAINT contact_block_entry_score_range CHECK (((score >= (0)::numeric) AND (score <= (1)::numeric))),
    CONSTRAINT contact_block_entry_self_has_a_kind CHECK (((role <> 'SELF'::text) OR (platform_key IS NOT NULL) OR (selector_type IS NOT NULL))),
    CONSTRAINT contact_block_entry_shared_count_dated CHECK (((shared_service_publishers IS NULL) = (shared_service_counted_at IS NULL))),
    CONSTRAINT contact_block_entry_stoplisted_is_third_party CHECK (((stoplist_id IS NULL) OR (role = 'THIRD_PARTY'::text))),
    CONSTRAINT contact_block_entry_unparsed_has_no_kind CHECK (((role <> 'UNPARSED'::text) OR ((platform_key IS NULL) AND (selector_type IS NULL))))
);

--
-- Name: conversation; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.conversation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    platform_key text NOT NULL,
    conversation_node_id uuid,
    external_ref text,
    title text,
    is_group boolean DEFAULT false NOT NULL,
    provenance_class text NOT NULL,
    collection_account_id uuid,
    legal_authority text,
    started_at timestamp with time zone,
    last_message_at timestamp with time zone,
    message_count integer DEFAULT 0 NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT conversation_needs_authority CHECK (((provenance_class = ANY (ARRAY['PERSONA_PARTY'::text, 'OPEN_GROUP'::text, 'UNKNOWN'::text])) OR (legal_authority IS NOT NULL))),
    CONSTRAINT conversation_persona_party_named CHECK (((provenance_class <> 'PERSONA_PARTY'::text) OR (collection_account_id IS NOT NULL))),
    CONSTRAINT conversation_provenance_known CHECK ((provenance_class = ANY (ARRAY['PERSONA_PARTY'::text, 'SEIZED_DEVICE'::text, 'PLATFORM_DISCLOSURE'::text, 'OPEN_GROUP'::text, 'THIRD_PARTY_REPORT'::text, 'UNKNOWN'::text])))
);

--
-- Name: device_fingerprint; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.device_fingerprint (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    platform_key text NOT NULL,
    device_node_id uuid,
    fingerprint text NOT NULL,
    algorithm text DEFAULT 'OMEMO'::text NOT NULL,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: message; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.message (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    conversation_id uuid NOT NULL,
    external_ref text,
    sender_handle text NOT NULL,
    sent_at timestamp with time zone,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    body text,
    content_sha256 bytea NOT NULL,
    has_attachment boolean DEFAULT false NOT NULL,
    body_minimised_at timestamp with time zone,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL
);

--
-- Name: participant; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.participant (
    conversation_id uuid NOT NULL,
    channel_binding_id uuid,
    observed_handle text NOT NULL,
    identity_node_id uuid,
    is_incidental boolean DEFAULT false NOT NULL,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    message_count integer DEFAULT 0 NOT NULL
);

--
-- Name: pgp_key; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.pgp_key (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    acquisition_id uuid NOT NULL,
    primary_fingerprint text NOT NULL,
    algorithm integer NOT NULL,
    curve text,
    key_bits integer,
    key_created_at timestamp with time zone NOT NULL,
    key_expires_at timestamp with time zone,
    revoked boolean NOT NULL,
    capabilities text NOT NULL,
    subkeys jsonb DEFAULT '[]'::jsonb NOT NULL,
    user_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    material text NOT NULL,
    material_sha256 bytea NOT NULL,
    confirmed_fingerprint text,
    confirmed_against text,
    confirmed_contact_block_entry_id uuid,
    confirmed_source_ref text,
    confirmation_statement text,
    confirmed_by uuid,
    confirmed_at timestamp with time zone,
    retired_at timestamp with time zone,
    retired_by uuid,
    retired_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pgp_key_against_known CHECK (((confirmed_against IS NULL) OR (confirmed_against = ANY (ARRAY['CONTACT_BLOCK'::text, 'PUBLISHED_ELSEWHERE'::text])))),
    CONSTRAINT pgp_key_algorithm_range CHECK (((algorithm >= 0) AND (algorithm <= 255))),
    CONSTRAINT pgp_key_bits_range CHECK (((key_bits IS NULL) OR ((key_bits >= 0) AND (key_bits <= 65536)))),
    CONSTRAINT pgp_key_capabilities_shape CHECK ((capabilities ~ '^[A-Za-z?]{0,32}$'::text)),
    CONSTRAINT pgp_key_confirmation_complete CHECK ((((confirmed_fingerprint IS NULL) = (confirmed_against IS NULL)) AND ((confirmed_fingerprint IS NULL) = (confirmed_by IS NULL)) AND ((confirmed_fingerprint IS NULL) = (confirmed_at IS NULL)))),
    CONSTRAINT pgp_key_confirmation_names_its_basis CHECK (((confirmed_against IS NULL) OR ((confirmed_against = 'CONTACT_BLOCK'::text) AND (confirmed_contact_block_entry_id IS NOT NULL) AND (confirmed_source_ref IS NULL)) OR ((confirmed_against = 'PUBLISHED_ELSEWHERE'::text) AND (confirmed_contact_block_entry_id IS NULL) AND (length(btrim(COALESCE(confirmed_source_ref, ''::text))) >= 3)))),
    CONSTRAINT pgp_key_confirms_its_own_fingerprint CHECK (((confirmed_fingerprint IS NULL) OR (confirmed_fingerprint = primary_fingerprint))),
    CONSTRAINT pgp_key_curve_size CHECK (((curve IS NULL) OR (length(curve) <= 64))),
    CONSTRAINT pgp_key_fp_shape CHECK (((primary_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (primary_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_key_material_digest_is_sha256 CHECK ((octet_length(material_sha256) = 32)),
    CONSTRAINT pgp_key_material_size CHECK (((length(material) >= 1) AND (length(material) <= 1000000))),
    CONSTRAINT pgp_key_retirement_complete CHECK ((((retired_at IS NULL) = (retired_by IS NULL)) AND ((retired_at IS NULL) = (retired_reason IS NULL)) AND ((retired_reason IS NULL) OR (length(btrim(retired_reason)) >= 3)))),
    CONSTRAINT pgp_key_source_ref_size CHECK (((confirmed_source_ref IS NULL) OR (length(confirmed_source_ref) <= 2000))),
    CONSTRAINT pgp_key_statement_needs_confirmation CHECK (((confirmation_statement IS NULL) OR (confirmed_at IS NOT NULL))),
    CONSTRAINT pgp_key_statement_size CHECK (((confirmation_statement IS NULL) OR (length(confirmation_statement) <= 2000)))
);

--
-- Name: TABLE pgp_key; Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON TABLE comms.pgp_key IS 'One primary key gpg read from an acquisition. A child of the acquisition (its labels). Never born confirmed; confirmed once, against a contact block line or a publication elsewhere; retired, never deleted (F10b).';

--
-- Name: pgp_key_acquisition; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.pgp_key_acquisition (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    source text NOT NULL,
    raw_bytes bytea NOT NULL,
    raw_sha256 bytea NOT NULL,
    filename text,
    source_ref text NOT NULL,
    channel_binding_id uuid,
    contact_block_id uuid,
    evidence_id uuid,
    classification core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    lookup_id uuid,
    CONSTRAINT pgp_key_acquisition_digest_is_sha256 CHECK ((octet_length(raw_sha256) = 32)),
    CONSTRAINT pgp_key_acquisition_file_is_named CHECK (((source = 'FILE'::text) = (filename IS NOT NULL))),
    CONSTRAINT pgp_key_acquisition_filename_size CHECK (((filename IS NULL) OR (length(filename) <= 255))),
    CONSTRAINT pgp_key_acquisition_raw_size CHECK (((octet_length(raw_bytes) >= 1) AND (octet_length(raw_bytes) <= 1000000))),
    CONSTRAINT pgp_key_acquisition_source_known CHECK ((source = ANY (ARRAY['PASTE'::text, 'FILE'::text, 'WKD'::text]))),
    CONSTRAINT pgp_key_acquisition_source_ref_size CHECK (((length(btrim(source_ref)) >= 3) AND (length(btrim(source_ref)) <= 2000))),
    CONSTRAINT pgp_key_acquisition_wkd_has_its_lookup CHECK (((source = 'WKD'::text) = (lookup_id IS NOT NULL))),
    CONSTRAINT pgp_key_acquisition_wkd_uncompartmented CHECK (((source <> 'WKD'::text) OR (cardinality(compartments) = 0)))
);

--
-- Name: TABLE pgp_key_acquisition; Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON TABLE comms.pgp_key_acquisition IS 'What vendor key material was obtained for a case, how and from where. Immutable and never deleted; carries the labels its keys are read under (F10b).';

--
-- Name: pgp_key_lookup; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.pgp_key_lookup (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    address text NOT NULL,
    local_part text NOT NULL,
    domain text NOT NULL,
    wkd_hash text NOT NULL,
    reason text NOT NULL,
    channel_binding_id uuid,
    contact_block_id uuid,
    classification core.tlp NOT NULL,
    ceiling core.tlp NOT NULL,
    route_name text NOT NULL,
    state text DEFAULT 'REQUESTED'::text NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision_note text,
    planned_urls text[],
    sent_at timestamp with time zone,
    method_used text,
    url_used text,
    http_status integer,
    response_sha256 bytea,
    response_bytes integer,
    detail text DEFAULT ''::text NOT NULL,
    finished_at timestamp with time zone,
    CONSTRAINT pgp_key_lookup_address_is_its_parts CHECK ((address = ((local_part || '@'::text) || domain))),
    CONSTRAINT pgp_key_lookup_ceiling_binds CHECK (((ceiling = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp, 'AMBER'::core.tlp])) AND (classification <= ceiling))),
    CONSTRAINT pgp_key_lookup_declined_says_why CHECK (((state <> 'DECLINED'::text) OR ((decided_by IS NOT NULL) AND (decided_at IS NOT NULL) AND (length(btrim(COALESCE(decision_note, ''::text))) >= 3) AND (planned_urls IS NULL) AND (sent_at IS NULL)))),
    CONSTRAINT pgp_key_lookup_detail_size CHECK ((length(detail) <= 2000)),
    CONSTRAINT pgp_key_lookup_digest_is_sha256 CHECK (((response_sha256 IS NULL) OR (octet_length(response_sha256) = 32))),
    CONSTRAINT pgp_key_lookup_domain_shape CHECK (((length(domain) <= 253) AND (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text))),
    CONSTRAINT pgp_key_lookup_expired_is_dated CHECK (((state <> 'EXPIRED'::text) OR ((decided_at IS NOT NULL) AND (planned_urls IS NULL) AND (sent_at IS NULL)))),
    CONSTRAINT pgp_key_lookup_finished_is_dated CHECK (((state = ANY (ARRAY['FOUND'::text, 'NOT_FOUND'::text, 'FAILED'::text])) = (finished_at IS NOT NULL))),
    CONSTRAINT pgp_key_lookup_found_is_whole CHECK (((state <> 'FOUND'::text) OR ((http_status = 200) AND (url_used IS NOT NULL) AND (method_used IS NOT NULL) AND (octet_length(response_sha256) = 32)))),
    CONSTRAINT pgp_key_lookup_hash_only_urls CHECK (((planned_urls IS NULL) OR (planned_urls <@ ARRAY[((((('https://openpgpkey.'::text || domain) || '/.well-known/openpgpkey/'::text) || domain) || '/hu/'::text) || wkd_hash), ((('https://'::text || domain) || '/.well-known/openpgpkey/hu/'::text) || wkd_hash)]))),
    CONSTRAINT pgp_key_lookup_hash_shape CHECK ((wkd_hash ~ '^[ybndrfg8ejkmcpqxot1uwisza345h769]{32}$'::text)),
    CONSTRAINT pgp_key_lookup_lapses CHECK (((expires_at > requested_at) AND (expires_at <= (requested_at + '72:00:00'::interval)))),
    CONSTRAINT pgp_key_lookup_leaves_at_most_amber CHECK ((classification = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp, 'AMBER'::core.tlp]))),
    CONSTRAINT pgp_key_lookup_method_known CHECK (((method_used IS NULL) OR (method_used = ANY (ARRAY['ADVANCED'::text, 'DIRECT'::text])))),
    CONSTRAINT pgp_key_lookup_not_found_is_404 CHECK (((state <> 'NOT_FOUND'::text) OR ((http_status = 404) AND (url_used IS NOT NULL)))),
    CONSTRAINT pgp_key_lookup_reason_size CHECK (((length(btrim(reason)) >= 10) AND (length(btrim(reason)) <= 2000))),
    CONSTRAINT pgp_key_lookup_requested_is_undecided CHECK (((state <> 'REQUESTED'::text) OR ((decided_by IS NULL) AND (decided_at IS NULL) AND (decision_note IS NULL) AND (planned_urls IS NULL) AND (sent_at IS NULL)))),
    CONSTRAINT pgp_key_lookup_route_name_shape CHECK ((route_name ~ '^[a-z][a-z0-9-]{1,39}$'::text)),
    CONSTRAINT pgp_key_lookup_sent_by_a_second_person CHECK (((state <> ALL (ARRAY['SENDING'::text, 'FOUND'::text, 'NOT_FOUND'::text, 'FAILED'::text])) OR ((decided_by IS NOT NULL) AND (decided_by <> requested_by) AND (decided_at IS NOT NULL) AND (sent_at IS NOT NULL) AND ((cardinality(planned_urls) >= 1) AND (cardinality(planned_urls) <= 2))))),
    CONSTRAINT pgp_key_lookup_state_known CHECK ((state = ANY (ARRAY['REQUESTED'::text, 'DECLINED'::text, 'EXPIRED'::text, 'SENDING'::text, 'FOUND'::text, 'NOT_FOUND'::text, 'FAILED'::text]))),
    CONSTRAINT pgp_key_lookup_used_was_planned CHECK (((url_used IS NULL) OR (url_used = ANY (planned_urls))))
);

--
-- Name: TABLE pgp_key_lookup; Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON TABLE comms.pgp_key_lookup IS 'Every Web Key Directory lookup asked for in a case: who asked, who approved it (always somebody else), what was planned and sent before the first packet, and what came back. Never deleted (F10c, docs/00 decision 75).';

--
-- Name: pgp_verification; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.pgp_verification (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    channel_binding_id uuid,
    contact_block_id uuid,
    claimed_fingerprint text NOT NULL,
    signing_fingerprint text,
    confirms_value text,
    signed_payload_sha256 bytea,
    value_in_payload boolean DEFAULT false NOT NULL,
    outcome text NOT NULL,
    verifier text NOT NULL,
    verifier_version text,
    status_output text,
    note text,
    verified_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    signature_form text DEFAULT 'CLEARSIGNED'::text NOT NULL,
    signing_primary_fingerprint text,
    signature_class text,
    pgp_key_id uuid,
    claimed_fingerprint_basis text DEFAULT 'STATED'::text NOT NULL,
    claimed_fingerprint_source_ref text,
    attribution text,
    CONSTRAINT pgp_verification_attribution_confirms_a_binding CHECK (((attribution IS NULL) OR ((outcome = 'VERIFIED'::text) AND (channel_binding_id IS NOT NULL)))),
    CONSTRAINT pgp_verification_attribution_known CHECK (((attribution IS NULL) OR (attribution = ANY (ARRAY['SAME_BLOCK'::text, 'SAME_IDENTITY'::text])))),
    CONSTRAINT pgp_verification_basis_is_the_key CHECK (((claimed_fingerprint_basis = 'CONFIRMED_KEY'::text) = (pgp_key_id IS NOT NULL))),
    CONSTRAINT pgp_verification_basis_known CHECK ((claimed_fingerprint_basis = ANY (ARRAY['STATED'::text, 'CONFIRMED_KEY'::text]))),
    CONSTRAINT pgp_verification_claimed_fp_shape CHECK (((claimed_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (claimed_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_verification_digest_is_sha256 CHECK (((signed_payload_sha256 IS NULL) OR (octet_length(signed_payload_sha256) = 32))),
    CONSTRAINT pgp_verification_form_known CHECK ((signature_form = ANY (ARRAY['CLEARSIGNED'::text, 'DETACHED'::text]))),
    CONSTRAINT pgp_verification_key_carries_its_provenance CHECK (((pgp_key_id IS NULL) OR (claimed_fingerprint_source_ref IS NULL))),
    CONSTRAINT pgp_verification_no_verifier_verifies_nothing CHECK (((verifier <> 'NONE'::text) OR (outcome = 'NO_VERIFIER'::text))),
    CONSTRAINT pgp_verification_outcome_known CHECK ((outcome = ANY (ARRAY['VERIFIED'::text, 'BAD_SIGNATURE'::text, 'KEY_MISMATCH'::text, 'VALUE_NOT_IN_PAYLOAD'::text, 'KEY_UNAVAILABLE'::text, 'EXPIRED_KEY'::text, 'REVOKED_KEY'::text, 'EXPIRED_SIGNATURE'::text, 'MALFORMED'::text, 'NO_VERIFIER'::text, 'UNATTRIBUTED'::text]))),
    CONSTRAINT pgp_verification_primary_fp_shape CHECK (((signing_primary_fingerprint IS NULL) OR (signing_primary_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (signing_primary_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_verification_sig_class_shape CHECK (((signature_class IS NULL) OR (signature_class ~ '^[0-9a-f]{2}$'::text))),
    CONSTRAINT pgp_verification_signing_fp_shape CHECK (((signing_fingerprint IS NULL) OR (signing_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (signing_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_verification_source_ref_size CHECK (((claimed_fingerprint_source_ref IS NULL) OR (length(claimed_fingerprint_source_ref) <= 2000))),
    CONSTRAINT pgp_verification_unattributed_is_otherwise_verified CHECK (((outcome <> 'UNATTRIBUTED'::text) OR ((channel_binding_id IS NOT NULL) AND (confirms_value IS NOT NULL) AND value_in_payload AND (signed_payload_sha256 IS NOT NULL) AND (status_output IS NOT NULL) AND (signing_fingerprint IS NOT NULL) AND ((claimed_fingerprint = signing_fingerprint) OR (NOT (claimed_fingerprint IS DISTINCT FROM signing_primary_fingerprint)))))),
    CONSTRAINT pgp_verification_verified_covers_value CHECK (((outcome <> 'VERIFIED'::text) OR ((confirms_value IS NOT NULL) AND value_in_payload AND (signed_payload_sha256 IS NOT NULL)))),
    CONSTRAINT pgp_verification_verified_is_re_readable CHECK (((outcome <> 'VERIFIED'::text) OR (status_output IS NOT NULL))),
    CONSTRAINT pgp_verification_verified_matches_claim CHECK (((outcome <> 'VERIFIED'::text) OR ((signing_fingerprint IS NOT NULL) AND ((claimed_fingerprint = signing_fingerprint) OR (NOT (claimed_fingerprint IS DISTINCT FROM signing_primary_fingerprint)))))),
    CONSTRAINT pgp_verification_verifier_known CHECK ((verifier = ANY (ARRAY['GPG'::text, 'EXTERNAL'::text, 'NONE'::text])))
);

--
-- Name: COLUMN pgp_verification.signature_form; Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON COLUMN comms.pgp_verification.signature_form IS 'CLEARSIGNED or DETACHED: which form of signature was checked (F10a).';

--
-- Name: COLUMN pgp_verification.signing_primary_fingerprint; Type: COMMENT; Schema: comms; Owner: -
--

COMMENT ON COLUMN comms.pgp_verification.signing_primary_fingerprint IS 'The primary key the signing key is bound under (gpg VALIDSIG, last field). A claim may name the signing key or this primary (F10a).';

--
-- Name: platform; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.platform (
    key text NOT NULL,
    display_name text NOT NULL,
    durable_selector_type text,
    displayed_id text NOT NULL,
    note text NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);

--
-- Name: service_selector; Type: TABLE; Schema: comms; Owner: -
--

CREATE TABLE comms.service_selector (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    scope text DEFAULT 'GLOBAL'::text NOT NULL,
    case_id uuid,
    platform_key text,
    selector_type text,
    durable_value text NOT NULL,
    observed_value text NOT NULL,
    role text NOT NULL,
    service_name text,
    note text DEFAULT ''::text NOT NULL,
    added_by uuid NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    retired_by uuid,
    retired_reason text,
    CONSTRAINT service_selector_has_a_kind CHECK (((platform_key IS NOT NULL) OR (selector_type IS NOT NULL))),
    CONSTRAINT service_selector_retirement_attributed CHECK (((retired_at IS NULL) OR ((retired_by IS NOT NULL) AND (retired_reason IS NOT NULL)))),
    CONSTRAINT service_selector_role_known CHECK ((role = ANY (ARRAY['ESCROW'::text, 'GUARANTOR'::text, 'ADMIN'::text, 'MODERATOR'::text, 'SUPPORT'::text, 'MARKET_STAFF'::text, 'EXCHANGER'::text, 'SHARED_SERVICE'::text, 'OTHER'::text]))),
    CONSTRAINT service_selector_scope_known CHECK ((scope = ANY (ARRAY['GLOBAL'::text, 'CASE'::text]))),
    CONSTRAINT service_selector_scope_matches_case CHECK (((scope = 'CASE'::text) = (case_id IS NOT NULL)))
);

--
-- Name: approval_request; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.approval_request (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    operation text NOT NULL,
    payload jsonb NOT NULL,
    payload_hash bytea NOT NULL,
    justification text NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    state text DEFAULT 'PENDING'::text NOT NULL,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision_note text,
    consumed_at timestamp with time zone,
    result_ref uuid,
    CONSTRAINT approval_consumed_has_timestamp CHECK (((state = 'CONSUMED'::text) = (consumed_at IS NOT NULL))),
    CONSTRAINT approval_decision_complete CHECK (((decided_at IS NULL) = (decided_by IS NULL))),
    CONSTRAINT approval_expiry_sane CHECK ((expires_at > requested_at)),
    CONSTRAINT approval_justification_present CHECK ((length(btrim(justification)) > 0)),
    CONSTRAINT approval_state_known CHECK ((state = ANY (ARRAY['PENDING'::text, 'APPROVED'::text, 'REJECTED'::text, 'WITHDRAWN'::text, 'CONSUMED'::text]))),
    CONSTRAINT approval_state_matches_decision CHECK (((state = ANY (ARRAY['APPROVED'::text, 'REJECTED'::text, 'CONSUMED'::text])) = (decided_by IS NOT NULL))),
    CONSTRAINT approval_two_distinct_humans CHECK (((decided_by IS NULL) OR (decided_by <> requested_by)))
);

--
-- Name: assertion_embedding; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.assertion_embedding (
    assertion_id uuid NOT NULL,
    slot smallint NOT NULL,
    space_id uuid NOT NULL,
    case_id uuid NOT NULL,
    status text NOT NULL,
    embedding public.vector(768),
    reason text,
    sent_classification core.tlp,
    input_chars integer DEFAULT 0 NOT NULL,
    truncated_chars integer DEFAULT 0 NOT NULL,
    attempts smallint DEFAULT 1 NOT NULL,
    first_failed_at timestamp with time zone,
    next_attempt_at timestamp with time zone,
    embedded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT assertion_embedding_attempts_check CHECK ((attempts >= 1)),
    CONSTRAINT assertion_embedding_failure_dated CHECK (((status = 'FAILED'::text) = (first_failed_at IS NOT NULL))),
    CONSTRAINT assertion_embedding_input_chars_check CHECK ((input_chars >= 0)),
    CONSTRAINT assertion_embedding_reason_unless_embedded CHECK (((status = 'EMBEDDED'::text) = (reason IS NULL))),
    CONSTRAINT assertion_embedding_retry_dated CHECK (((status <> ALL (ARRAY['FAILED'::text, 'WITHHELD'::text])) OR (next_attempt_at IS NOT NULL))),
    CONSTRAINT assertion_embedding_sent_only_embedded CHECK (((sent_classification IS NULL) OR (status = 'EMBEDDED'::text))),
    CONSTRAINT assertion_embedding_status_check CHECK ((status = ANY (ARRAY['EMBEDDED'::text, 'EMPTY'::text, 'EXCLUDED'::text, 'WITHHELD'::text, 'FAILED'::text]))),
    CONSTRAINT assertion_embedding_truncated_chars_check CHECK ((truncated_chars >= 0)),
    CONSTRAINT assertion_embedding_vector_iff_embedded CHECK (((status = 'EMBEDDED'::text) = (embedding IS NOT NULL)))
);

--
-- Name: TABLE assertion_embedding; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON TABLE core.assertion_embedding IS 'One similarity outcome per claim and slot (F6.4): rationale, reference and claimed values. Kept after retraction or supersession as history; search reads live claims only.';

--
-- Name: assumption; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.assumption (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    statement text NOT NULL,
    basis text,
    status text DEFAULT 'OPEN'::text NOT NULL,
    made_by uuid NOT NULL,
    made_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_note text,
    CONSTRAINT assumption_review_pair CHECK (((reviewed_by IS NULL) = (reviewed_at IS NULL))),
    CONSTRAINT assumption_status_known CHECK ((status = ANY (ARRAY['OPEN'::text, 'CONFIRMED'::text, 'REFUTED'::text, 'WITHDRAWN'::text])))
);

--
-- Name: TABLE assumption; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON TABLE core.assumption IS 'The assumptions a case''s findings rest on (docs/08 Phase 6). OPEN and CONFIRMED rows are premises the report states; REFUTED is a finding that a premise was false and stays on the record; WITHDRAWN means the row was entered in error and is terminal.';

--
-- Name: COLUMN assumption.review_note; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON COLUMN core.assumption.review_note IS 'Why the last review decided what it did. Required by the service when a REFUTED assumption is re-opened, because un-refuting in silence erases a finding.';

--
-- Name: case; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core."case" (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    title text NOT NULL,
    summary text,
    status core.case_status DEFAULT 'DRAFT'::core.case_status NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    owner_user_id uuid NOT NULL,
    deputy_user_id uuid,
    legal_basis text NOT NULL,
    authority_ref text,
    retention_until date NOT NULL,
    review_due date NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    dual_control_merge boolean DEFAULT false NOT NULL,
    withheld_disclosure text DEFAULT 'PRESENCE'::text NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    legal_hold_reason text,
    dual_control_merge_epoch bigint DEFAULT 0 NOT NULL,
    CONSTRAINT case_hold_has_reason CHECK (((NOT legal_hold) OR (legal_hold_reason IS NOT NULL))),
    CONSTRAINT case_retention_sane CHECK ((retention_until > ((created_at AT TIME ZONE 'UTC'::text))::date)),
    CONSTRAINT case_withheld_disclosure_known CHECK ((withheld_disclosure = ANY (ARRAY['NONE'::text, 'PRESENCE'::text, 'COUNT'::text])))
);

--
-- Name: COLUMN "case".dual_control_merge_epoch; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON COLUMN core."case".dual_control_merge_epoch IS 'Moves by one with every change of dual_control_merge. A case.policy.relax approval names the epoch it was raised against (migration case_merge_relax_two_people, F9b 2026-09-24).';

--
-- Name: edge; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.edge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    edge_type text NOT NULL,
    src_node_id uuid NOT NULL,
    dst_node_id uuid NOT NULL,
    sign smallint DEFAULT 1 NOT NULL,
    weight numeric(14,4) DEFAULT 1.0 NOT NULL,
    attrs jsonb DEFAULT '{}'::jsonb NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    confidence core.analytic_confidence DEFAULT 'LOW'::core.analytic_confidence NOT NULL,
    is_inferred boolean DEFAULT false NOT NULL,
    inference_method text,
    review core.review_state DEFAULT 'PROPOSED'::core.review_state NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    CONSTRAINT edge_no_self_loop CHECK ((src_node_id <> dst_node_id)),
    CONSTRAINT edge_sign_check CHECK ((sign = ANY (ARRAY['-1'::integer, 0, 1]))),
    CONSTRAINT edge_time_order CHECK (((valid_to IS NULL) OR (valid_from IS NULL) OR (valid_to >= valid_from)))
);

--
-- Name: edge_type; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.edge_type (
    key text NOT NULL,
    display_name text NOT NULL,
    inverse_name text,
    is_directed boolean DEFAULT true NOT NULL,
    default_sign smallint DEFAULT 1 NOT NULL,
    src_node_types text[] NOT NULL,
    dst_node_types text[] NOT NULL,
    is_social_tie boolean DEFAULT true NOT NULL,
    schema_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    CONSTRAINT edge_type_default_sign_check CHECK ((default_sign = ANY (ARRAY['-1'::integer, 0, 1])))
);

--
-- Name: embedding_pending; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.embedding_pending (
    slot smallint NOT NULL,
    kind text NOT NULL,
    item_id uuid NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT embedding_pending_kind_check CHECK ((kind = ANY (ARRAY['document'::text, 'evidence'::text, 'assertion'::text]))),
    CONSTRAINT embedding_pending_slot_check CHECK (((slot >= 1) AND (slot <= 3)))
);

--
-- Name: TABLE embedding_pending; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON TABLE core.embedding_pending IS 'Items that have no vector row yet in a slot (F6.1). Filled by triggers on new and changed items and in bulk when a space registers; drained by scripts/embed_pass.py. No foreign key: one queue serves three kinds, and the pass drops an entry whose item is gone or purged.';

--
-- Name: embedding_space; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.embedding_space (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role text NOT NULL,
    state text NOT NULL,
    slot smallint NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    fingerprint jsonb NOT NULL,
    fingerprint_sha256 bytea NOT NULL,
    dims_native integer NOT NULL,
    canary public.vector(768) NOT NULL,
    unicode_version text,
    registered_endpoint text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    activated_at timestamp with time zone,
    activated_by uuid,
    retired_at timestamp with time zone,
    retired_by uuid,
    retire_reason text,
    model_mismatch_at timestamp with time zone,
    gate_key bytea,
    enqueued_at timestamp with time zone,
    canary_checked_at timestamp with time zone,
    canary_ok boolean,
    canary_problem text,
    rows_cleared_at timestamp with time zone,
    CONSTRAINT embedding_space_active_dated CHECK (((state <> 'ACTIVE'::text) OR (activated_at IS NOT NULL))),
    CONSTRAINT embedding_space_cleared_when_retired CHECK (((rows_cleared_at IS NULL) OR (state = 'RETIRED'::text))),
    CONSTRAINT embedding_space_dims_native_check CHECK (((dims_native >= 1) AND (dims_native <= 768))),
    CONSTRAINT embedding_space_endpoint_recorded CHECK (((provider = 'endpoint'::text) = (registered_endpoint IS NOT NULL))),
    CONSTRAINT embedding_space_fingerprint_sha256_check CHECK ((length(fingerprint_sha256) = 32)),
    CONSTRAINT embedding_space_gate_endpoint_only CHECK (((gate_key IS NULL) OR (provider = 'endpoint'::text))),
    CONSTRAINT embedding_space_mismatch_endpoint_only CHECK (((model_mismatch_at IS NULL) OR (provider = 'endpoint'::text))),
    CONSTRAINT embedding_space_model_check CHECK ((btrim(model) <> ''::text)),
    CONSTRAINT embedding_space_provider_check CHECK ((provider = ANY (ARRAY['builtin'::text, 'endpoint'::text]))),
    CONSTRAINT embedding_space_retired_dated CHECK (((state <> 'RETIRED'::text) OR ((retired_at IS NOT NULL) AND (retire_reason IS NOT NULL)))),
    CONSTRAINT embedding_space_role_check CHECK ((role = ANY (ARRAY['WORDING'::text, 'MEANING'::text]))),
    CONSTRAINT embedding_space_role_provider CHECK (((provider = 'endpoint'::text) = (role = 'MEANING'::text))),
    CONSTRAINT embedding_space_slot_check CHECK (((slot >= 1) AND (slot <= 3))),
    CONSTRAINT embedding_space_state_check CHECK ((state = ANY (ARRAY['BUILDING'::text, 'ACTIVE'::text, 'RETIRED'::text])))
);

--
-- Name: TABLE embedding_space; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON TABLE core.embedding_space IS 'One similarity space per embedder fingerprint (F6.1). Vectors are compared only inside one space. registered_endpoint is host:port at registration, history only: the live endpoint, ceiling and declarations are read from the environment, never from this row.';

--
-- Name: evidence; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    title text NOT NULL,
    description text,
    media_type text NOT NULL,
    byte_size bigint NOT NULL,
    sha256 bytea NOT NULL,
    blake3 bytea,
    storage_key text NOT NULL,
    storage_bucket text NOT NULL,
    is_worm_locked boolean DEFAULT true NOT NULL,
    acquired_at timestamp with time zone NOT NULL,
    acquired_by uuid NOT NULL,
    acquisition_method text NOT NULL,
    source_url text,
    collection_account_id uuid,
    collection_run_id uuid,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    extracted_text text,
    extract_status text DEFAULT 'PENDING'::text NOT NULL,
    search_tsv tsvector,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    retention_until date,
    legal_hold_reason text,
    purged_at timestamp with time zone,
    is_hostile_markup boolean DEFAULT false NOT NULL,
    CONSTRAINT evidence_hold_has_reason CHECK (((NOT legal_hold) OR (legal_hold_reason IS NOT NULL)))
);

--
-- Name: COLUMN evidence.is_hostile_markup; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON COLUMN core.evidence.is_hostile_markup IS 'Attacker-authored markup/code (DOM, HAR, .eml, SVG). Download-only, and only from the separate sample origin. Never rendered inline by the API origin. See docs/19 and invariant 10.';

--
-- Name: evidence_custody; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.evidence_custody (
    id bigint NOT NULL,
    evidence_id uuid NOT NULL,
    action text NOT NULL,
    actor_id uuid NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    hash_verified boolean,
    prev_hash bytea,
    row_hash bytea NOT NULL
);

--
-- Name: evidence_custody_id_seq; Type: SEQUENCE; Schema: core; Owner: -
--

CREATE SEQUENCE core.evidence_custody_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: evidence_custody_id_seq; Type: SEQUENCE OWNED BY; Schema: core; Owner: -
--

ALTER SEQUENCE core.evidence_custody_id_seq OWNED BY core.evidence_custody.id;

--
-- Name: evidence_embedding; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.evidence_embedding (
    evidence_id uuid NOT NULL,
    slot smallint NOT NULL,
    space_id uuid NOT NULL,
    case_id uuid NOT NULL,
    status text NOT NULL,
    embedding public.vector(768),
    reason text,
    sent_classification core.tlp,
    input_chars integer DEFAULT 0 NOT NULL,
    truncated_chars integer DEFAULT 0 NOT NULL,
    attempts smallint DEFAULT 1 NOT NULL,
    first_failed_at timestamp with time zone,
    next_attempt_at timestamp with time zone,
    embedded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_embedding_attempts_check CHECK ((attempts >= 1)),
    CONSTRAINT evidence_embedding_failure_dated CHECK (((status = 'FAILED'::text) = (first_failed_at IS NOT NULL))),
    CONSTRAINT evidence_embedding_input_chars_check CHECK ((input_chars >= 0)),
    CONSTRAINT evidence_embedding_reason_unless_embedded CHECK (((status = 'EMBEDDED'::text) = (reason IS NULL))),
    CONSTRAINT evidence_embedding_retry_dated CHECK (((status <> ALL (ARRAY['FAILED'::text, 'WITHHELD'::text])) OR (next_attempt_at IS NOT NULL))),
    CONSTRAINT evidence_embedding_sent_only_embedded CHECK (((sent_classification IS NULL) OR (status = 'EMBEDDED'::text))),
    CONSTRAINT evidence_embedding_status_check CHECK ((status = ANY (ARRAY['EMBEDDED'::text, 'EMPTY'::text, 'EXCLUDED'::text, 'WITHHELD'::text, 'FAILED'::text]))),
    CONSTRAINT evidence_embedding_truncated_chars_check CHECK ((truncated_chars >= 0)),
    CONSTRAINT evidence_embedding_vector_iff_embedded CHECK (((status = 'EMBEDDED'::text) = (embedding IS NOT NULL)))
);

--
-- Name: TABLE evidence_embedding; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON TABLE core.evidence_embedding IS 'One similarity outcome per exhibit and slot (F6.4): the title, description and extracted text, never the bytes. case_id is set by trigger from the exhibit.';

--
-- Name: evidence_link; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.evidence_link (
    evidence_id uuid NOT NULL,
    node_id uuid,
    edge_id uuid,
    relevance text,
    page_ref text,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evlink_one_target CHECK ((num_nonnulls(node_id, edge_id) = 1))
);

--
-- Name: hypothesis; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.hypothesis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    statement text NOT NULL,
    confidence core.analytic_confidence DEFAULT 'LOW'::core.analytic_confidence NOT NULL,
    status core.review_state DEFAULT 'PROPOSED'::core.review_state NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: hypothesis_evidence; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.hypothesis_evidence (
    hypothesis_id uuid NOT NULL,
    assertion_id uuid NOT NULL,
    stance smallint NOT NULL,
    note text,
    CONSTRAINT hypothesis_evidence_stance_check CHECK ((stance = ANY (ARRAY['-2'::integer, '-1'::integer, 0, 1, 2])))
);

--
-- Name: node; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    node_type text NOT NULL,
    label text NOT NULL,
    attrs jsonb DEFAULT '{}'::jsonb NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    merged_into_id uuid,
    merged_at timestamp with time zone,
    merged_by uuid,
    search_tsv tsvector,
    embedding public.vector(768)
);

--
-- Name: node_merge; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node_merge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    source_node_id uuid NOT NULL,
    target_node_id uuid NOT NULL,
    reason text NOT NULL,
    basis_selector_id uuid,
    merged_at timestamp with time zone DEFAULT now() NOT NULL,
    merged_by uuid NOT NULL,
    reversed_at timestamp with time zone,
    reversed_by uuid,
    reversal_reason text,
    CONSTRAINT node_merge_not_self CHECK ((source_node_id <> target_node_id)),
    CONSTRAINT node_merge_reversal_complete CHECK ((((reversed_at IS NULL) = (reversed_by IS NULL)) AND ((reversed_at IS NULL) = (reversal_reason IS NULL))))
);

--
-- Name: node_merge_edge; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node_merge_edge (
    merge_id uuid NOT NULL,
    edge_id uuid NOT NULL,
    original_src_node_id uuid NOT NULL,
    original_dst_node_id uuid NOT NULL,
    deleted_by_merge boolean DEFAULT false NOT NULL
);

--
-- Name: COLUMN node_merge_edge.deleted_by_merge; Type: COMMENT; Schema: core; Owner: -
--

COMMENT ON COLUMN core.node_merge_edge.deleted_by_merge IS 'True when THIS merge soft-deleted the edge because repointing it would have produced a self-loop. Only these may have deleted_at cleared on reversal -- an edge retired later, for its own reasons, must stay retired.';

--
-- Name: node_set; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node_set (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    name text NOT NULL,
    purpose text,
    is_pinned boolean DEFAULT false NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: node_set_member; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node_set_member (
    set_id uuid NOT NULL,
    node_id uuid NOT NULL,
    note text
);

--
-- Name: node_type; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.node_type (
    key text NOT NULL,
    display_name text NOT NULL,
    category text NOT NULL,
    icon text,
    colour_token text,
    schema_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    sort_order integer DEFAULT 100 NOT NULL
);

--
-- Name: purge_tombstone; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.purge_tombstone (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    object_type text NOT NULL,
    object_count integer NOT NULL,
    earliest timestamp with time zone,
    latest timestamp with time zone,
    rule text,
    authority text NOT NULL,
    approval_request_id uuid,
    purged_by uuid NOT NULL,
    purged_at timestamp with time zone DEFAULT now() NOT NULL,
    storage_outcome text DEFAULT 'NOT_APPLICABLE'::text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT purge_tombstone_authority_present CHECK ((length(btrim(authority)) > 0)),
    CONSTRAINT purge_tombstone_count_positive CHECK ((object_count > 0)),
    CONSTRAINT purge_tombstone_storage_outcome_known CHECK ((storage_outcome = ANY (ARRAY['DELETED'::text, 'LOCKED_UNTIL_RETENTION'::text, 'FAILED'::text, 'NOT_APPLICABLE'::text])))
);

--
-- Name: retention_rule; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.retention_rule (
    category text NOT NULL,
    retain_days integer NOT NULL,
    rationale text NOT NULL,
    confirmed_by uuid,
    confirmed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT retention_rule_confirmation_complete CHECK (((confirmed_by IS NULL) = (confirmed_at IS NULL))),
    CONSTRAINT retention_rule_positive CHECK ((retain_days > 0))
);

--
-- Name: selector; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.selector (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    selector_type text NOT NULL,
    raw_value text NOT NULL,
    norm_value text NOT NULL,
    node_id uuid,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    observation_cnt integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: selector_type; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.selector_type (
    key text NOT NULL,
    display_name text NOT NULL,
    is_strong boolean DEFAULT false NOT NULL,
    is_pii boolean DEFAULT false NOT NULL,
    validator_regex text,
    normaliser text,
    is_active boolean DEFAULT true NOT NULL
);

--
-- Name: tag; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.tag (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    namespace text NOT NULL,
    name text NOT NULL,
    colour text,
    description text,
    parent_id uuid,
    external_id text
);

--
-- Name: tag_assignment; Type: TABLE; Schema: core; Owner: -
--

CREATE TABLE core.tag_assignment (
    tag_id uuid NOT NULL,
    node_id uuid,
    edge_id uuid,
    evidence_id uuid,
    document_id uuid,
    assigned_by uuid NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tag_one_target CHECK ((num_nonnulls(node_id, edge_id, evidence_id, document_id) = 1))
);

--
-- Name: call_record; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.call_record (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    presented_number text,
    presented_number_e164 text,
    presented_name text,
    originating_trunk text,
    p_asserted_identity text,
    carrier_name text,
    stir_shaken_attestation text,
    stir_shaken_verified boolean DEFAULT false NOT NULL,
    called_number_e164 text,
    direction text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    duration_seconds integer,
    disposition text,
    sip_call_id text,
    sip_from_uri text,
    sip_to_uri text,
    source_ip inet,
    user_agent text,
    record_source text NOT NULL,
    evidence_id uuid,
    recording_evidence_id uuid,
    recording_lawful_basis text,
    victim_node_id uuid,
    lure_node_id uuid,
    note text,
    recorded_by uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    CONSTRAINT call_attestation_known CHECK (((stir_shaken_attestation IS NULL) OR (stir_shaken_attestation = ANY (ARRAY['A'::text, 'B'::text, 'C'::text])))),
    CONSTRAINT call_direction_known CHECK ((direction = ANY (ARRAY['INBOUND_TO_VICTIM'::text, 'OUTBOUND_FROM_VICTIM'::text, 'UNKNOWN'::text]))),
    CONSTRAINT call_disposition_known CHECK (((disposition IS NULL) OR (disposition = ANY (ARRAY['ANSWERED'::text, 'NO_ANSWER'::text, 'BUSY'::text, 'VOICEMAIL'::text, 'REJECTED'::text, 'FAILED'::text])))),
    CONSTRAINT call_duration_nonneg CHECK (((duration_seconds IS NULL) OR (duration_seconds >= 0))),
    CONSTRAINT call_ends_after_it_starts CHECK (((ended_at IS NULL) OR (ended_at >= started_at))),
    CONSTRAINT call_record_source_known CHECK ((record_source = ANY (ARRAY['CARRIER_CDR'::text, 'PBX_LOG'::text, 'SIP_CAPTURE'::text, 'VICTIM_STATEMENT'::text, 'HANDSET_LOG'::text, 'THIRD_PARTY_REPORT'::text]))),
    CONSTRAINT call_recording_needs_basis CHECK (((recording_evidence_id IS NULL) OR (recording_lawful_basis IS NOT NULL))),
    CONSTRAINT call_verified_needs_attestation CHECK (((NOT stir_shaken_verified) OR (stir_shaken_attestation IS NOT NULL)))
);

--
-- Name: capture; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.capture (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    requested_url text NOT NULL,
    requested_url_norm text NOT NULL,
    final_url text,
    final_url_norm text,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    capture_method text NOT NULL,
    capture_tool text,
    egress_profile_id uuid,
    user_agent text,
    viewport text,
    http_status integer,
    is_live boolean,
    page_title text,
    visible_text text,
    favicon_hash text,
    screenshot_evidence_id uuid,
    dom_evidence_id uuid,
    har_evidence_id uuid,
    tls_subject text,
    tls_issuer text,
    tls_not_before timestamp with time zone,
    tls_not_after timestamp with time zone,
    tls_spki_sha256 bytea,
    submitted_input boolean DEFAULT false NOT NULL,
    submission_authority_ref text,
    captured_by uuid NOT NULL,
    note text,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT capture_active_needs_egress_profile CHECK (((capture_method = ANY (ARRAY['ANALYST_UPLOAD'::text, 'VICTIM_SUPPLIED'::text, 'PASSIVE_FEED'::text])) OR (egress_profile_id IS NOT NULL))),
    CONSTRAINT capture_method_known CHECK ((capture_method = ANY (ARRAY['MANUAL_BROWSER'::text, 'HEADLESS'::text, 'VENDOR_API'::text, 'ANALYST_UPLOAD'::text, 'VICTIM_SUPPLIED'::text, 'PASSIVE_FEED'::text]))),
    CONSTRAINT capture_spki_is_a_sha256 CHECK (((tls_spki_sha256 IS NULL) OR (octet_length(tls_spki_sha256) = 32))),
    CONSTRAINT capture_submission_needs_authority CHECK (((NOT submitted_input) OR (submission_authority_ref IS NOT NULL)))
);

--
-- Name: capture_hop; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.capture_hop (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    capture_id uuid NOT NULL,
    seq integer NOT NULL,
    url text NOT NULL,
    url_norm text NOT NULL,
    http_status integer,
    resolved_ip inet,
    asn integer,
    server_header text,
    hop_kind text NOT NULL,
    CONSTRAINT capture_hop_kind_known CHECK ((hop_kind = ANY (ARRAY['REQUESTED'::text, 'HTTP_30X'::text, 'META_REFRESH'::text, 'JS'::text, 'FRAME'::text, 'DNS_CNAME'::text]))),
    CONSTRAINT capture_hop_seq_nonneg CHECK ((seq >= 0))
);

--
-- Name: email_attachment; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.email_attachment (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    message_id uuid NOT NULL,
    filename text,
    media_type text,
    byte_size bigint,
    sha256 bytea,
    sample_id uuid,
    is_inline boolean DEFAULT false NOT NULL,
    content_id text,
    CONSTRAINT email_attachment_sha_is_sha256 CHECK (((sha256 IS NULL) OR (octet_length(sha256) = 32)))
);

--
-- Name: email_hop; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.email_hop (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    message_id uuid NOT NULL,
    seq integer NOT NULL,
    received_raw text NOT NULL,
    from_host text,
    from_ip inet,
    by_host text,
    protocol text,
    tls_used boolean,
    received_at timestamp with time zone,
    is_trusted_boundary boolean DEFAULT false NOT NULL,
    CONSTRAINT email_hop_seq_nonneg CHECK ((seq >= 0))
);

--
-- Name: email_message; Type: TABLE; Schema: deception; Owner: -
--

CREATE TABLE deception.email_message (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    message_id text,
    message_id_norm text,
    header_from text,
    header_from_display text,
    header_reply_to text,
    header_return_path text,
    envelope_from text,
    header_to text[],
    header_cc text[],
    subject text,
    date_header timestamp with time zone,
    in_reply_to text,
    thread_topic text,
    spf_result text,
    spf_domain text,
    dkim_result text,
    dkim_domain text,
    dmarc_result text,
    dmarc_domain text,
    auth_results_raw text,
    from_replyto_divergent boolean DEFAULT false NOT NULL,
    from_returnpath_divergent boolean DEFAULT false NOT NULL,
    display_name_impersonates text,
    reply_to_is_freemail boolean DEFAULT false NOT NULL,
    body_text text,
    has_html_body boolean DEFAULT false NOT NULL,
    extracted_urls text[] DEFAULT '{}'::text[] NOT NULL,
    direction text DEFAULT 'INBOUND_TO_VICTIM'::text NOT NULL,
    victim_node_id uuid,
    recorded_by uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    parse_gaps jsonb DEFAULT '[]'::jsonb NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    CONSTRAINT email_auth_result_known CHECK ((((spf_result IS NULL) OR (spf_result = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'SOFTFAIL'::text, 'NEUTRAL'::text, 'NONE'::text, 'TEMPERROR'::text, 'PERMERROR'::text]))) AND ((dkim_result IS NULL) OR (dkim_result = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'NONE'::text, 'TEMPERROR'::text, 'PERMERROR'::text]))) AND ((dmarc_result IS NULL) OR (dmarc_result = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'NONE'::text, 'TEMPERROR'::text, 'PERMERROR'::text]))))),
    CONSTRAINT email_direction_known CHECK ((direction = ANY (ARRAY['INBOUND_TO_VICTIM'::text, 'OUTBOUND_FROM_VICTIM'::text, 'INTERNAL'::text, 'UNKNOWN'::text]))),
    CONSTRAINT email_dkim_domain_needs_pass CHECK (((dkim_domain IS NULL) OR (dkim_result = 'PASS'::text)))
);

--
-- Name: app_user; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.app_user (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email public.citext NOT NULL,
    display_name text NOT NULL,
    password_hash text,
    is_active boolean DEFAULT true NOT NULL,
    tlp_clearance core.tlp DEFAULT 'GREEN'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    totp_secret_ciphertext bytea,
    totp_key_id text,
    totp_enrolled_at timestamp with time zone,
    mfa_required boolean DEFAULT true NOT NULL,
    recovery_codes_hash text[],
    failed_logins integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    last_login_at timestamp with time zone,
    password_changed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deactivated_at timestamp with time zone,
    totp_last_counter bigint,
    must_change_password boolean DEFAULT false NOT NULL
);

--
-- Name: COLUMN app_user.totp_last_counter; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.app_user.totp_last_counter IS 'Last accepted RFC 6238 TOTP step counter; a code with counter <= this is a replay.';

--
-- Name: COLUMN app_user.must_change_password; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.app_user.must_change_password IS 'Set when an administrator issues a one-time password; sign-in refuses to mint a session until the account chooses its own (0066).';

--
-- Name: break_glass; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.break_glass (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    case_id uuid,
    justification text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_outcome text,
    granted_permissions text[] DEFAULT '{}'::text[] NOT NULL,
    granted_classification core.tlp,
    used_at timestamp with time zone,
    action_count integer DEFAULT 0 NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    CONSTRAINT break_glass_is_short CHECK ((expires_at <= (started_at + '08:00:00'::interval))),
    CONSTRAINT break_glass_justification_present CHECK ((length(btrim(justification)) > 20)),
    CONSTRAINT break_glass_review_complete CHECK (((reviewed_by IS NULL) = (reviewed_at IS NULL)))
);

--
-- Name: case_assignment; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.case_assignment (
    case_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_key text NOT NULL,
    granted_by uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone
);

--
-- Name: compartment; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.compartment (
    key text NOT NULL,
    label text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT compartment_key_format CHECK ((key ~ '^[A-Z0-9_-]{2,32}$'::text))
);

--
-- Name: TABLE compartment; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON TABLE iam.compartment IS 'The closed vocabulary of compartment keys. cases.py and iam_admin.py refuse any key not in here, naming it, because an unregistered key is a typo and a typo in a need-to-know lock is silent no-access.';

--
-- Name: dual_control_operation; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.dual_control_operation (
    operation text NOT NULL,
    mode text NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    change_id uuid,
    CONSTRAINT dual_control_mode_known CHECK ((mode = ANY (ARRAY['PER_CASE'::text, 'ALWAYS'::text])))
);

--
-- Name: TABLE dual_control_operation; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON TABLE iam.dual_control_operation IS 'The deployment mode (PER_CASE or ALWAYS) of each configurable two-person operation. Changes only through iam.dual_control_policy_change. A later migration that must write it runs ALTER TABLE iam.dual_control_operation DISABLE TRIGGER dual_control_operation_written_by_ledger and ENABLE TRIGGER dual_control_operation_written_by_ledger inside its own run.';

--
-- Name: dual_control_policy_change; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.dual_control_policy_change (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    approval_request_id uuid NOT NULL,
    change text NOT NULL,
    operation text,
    mode_from text,
    mode_to text,
    permission_a text,
    permission_b text,
    why text,
    based_on uuid,
    requested_by uuid NOT NULL,
    countersigned_by uuid NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dual_control_change_known CHECK ((change = ANY (ARRAY['OPERATION_MODE'::text, 'SEPARATED_DUTY_ADD'::text, 'SEPARATED_DUTY_REMOVE'::text]))),
    CONSTRAINT dual_control_change_pair_says_why CHECK (((change <> 'SEPARATED_DUTY_ADD'::text) OR (length(btrim(why)) >= 10))),
    CONSTRAINT dual_control_change_shape CHECK ((((change = 'OPERATION_MODE'::text) AND (operation IS NOT NULL) AND (mode_from = ANY (ARRAY['PER_CASE'::text, 'ALWAYS'::text])) AND (mode_to = ANY (ARRAY['PER_CASE'::text, 'ALWAYS'::text])) AND (mode_from <> mode_to) AND (permission_a IS NULL) AND (permission_b IS NULL)) OR ((change <> 'OPERATION_MODE'::text) AND (operation IS NULL) AND (permission_a IS NOT NULL) AND (permission_b IS NOT NULL) AND (permission_a < permission_b)))),
    CONSTRAINT dual_control_change_two_people CHECK ((requested_by <> countersigned_by))
);

--
-- Name: TABLE dual_control_policy_change; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON TABLE iam.dual_control_policy_change IS 'Append-only ledger of two-person policy changes. Inserting a row is the only way iam.dual_control_operation and iam.separated_duty change, and the insert is refused unless a dual_control.policy approval for exactly that change was consumed in the same transaction (migration dual_control_policy, F9 2026-09-24).';

--
-- Name: dual_control_policy_change_seq_seq; Type: SEQUENCE; Schema: iam; Owner: -
--

ALTER TABLE iam.dual_control_policy_change ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME iam.dual_control_policy_change_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

--
-- Name: permission; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.permission (
    key text NOT NULL,
    description text NOT NULL,
    requires_step_up boolean DEFAULT false NOT NULL
);

--
-- Name: role; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.role (
    key text NOT NULL,
    display_name text NOT NULL,
    description text,
    is_system boolean DEFAULT false NOT NULL
);

--
-- Name: role_permission; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.role_permission (
    role_key text NOT NULL,
    permission_key text NOT NULL
);

--
-- Name: separated_duty; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.separated_duty (
    permission_a text NOT NULL,
    permission_b text NOT NULL,
    why text NOT NULL,
    origin text DEFAULT 'migration'::text NOT NULL,
    added_at timestamp with time zone,
    added_by_change uuid,
    CONSTRAINT separated_duty_origin_known CHECK ((origin = ANY (ARRAY['migration'::text, 'policy'::text]))),
    CONSTRAINT separated_duty_policy_origin_named CHECK (((origin = 'policy'::text) = (added_by_change IS NOT NULL))),
    CONSTRAINT separated_duty_says_why CHECK ((length(btrim(why)) > 0)),
    CONSTRAINT separated_duty_two_permissions CHECK ((permission_a <> permission_b))
);

--
-- Name: TABLE separated_duty; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON TABLE iam.separated_duty IS 'Pairs of permissions no single role may hold together: the two halves of a two-person control. Enforced on iam.role_permission by trigger role_permission_separated_duty (migration 0062). origin says who installed a pair: migration (a release or the database owner) or policy (a two-person change). Changes only through iam.dual_control_policy_change; a later migration that must write it runs ALTER TABLE iam.separated_duty DISABLE TRIGGER separated_duty_written_by_ledger and ENABLE TRIGGER separated_duty_written_by_ledger inside its own run.';

--
-- Name: session; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.session (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone,
    ip_hash bytea,
    user_agent text,
    mfa_satisfied_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoke_reason text,
    ip inet,
    rls_binding_hash bytea
);

--
-- Name: COLUMN session.user_agent; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.session.user_agent IS 'The User-Agent header presented at login. Column since 0012; first written with 0058.';

--
-- Name: COLUMN session.ip; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.session.ip IS 'The peer address the session was minted from (the outermost trusted proxy''s view when NOCTORNAL_TRUSTED_PROXY_HOPS is set). NULL when the transport had no address. Compared by validation only under NOCTORNAL_SESSION_STRICT_BINDING.';

--
-- Name: COLUMN session.rls_binding_hash; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.session.rls_binding_hash IS 'sha256 of the row-security binding proof derived from the raw token (security.tokens.rls_proof). iam.rls_actor() resolves a connection''s user by it. Set once at mint, on a system connection.';

--
-- Name: user_role; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.user_role (
    user_id uuid NOT NULL,
    role_key text NOT NULL
);

--
-- Name: webauthn_credential; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.webauthn_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    aaguid uuid,
    transports text[],
    nickname text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);

--
-- Name: api_key; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.api_key (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id text NOT NULL,
    secret_hmac bytea NOT NULL,
    pepper_id text NOT NULL,
    name text NOT NULL,
    environment text DEFAULT 'live'::text NOT NULL,
    scopes text[] DEFAULT '{ingest:write}'::text[] NOT NULL,
    source_id uuid,
    declared_category text DEFAULT 'UNKNOWN'::text NOT NULL,
    declared_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    default_reliability text DEFAULT 'F'::text NOT NULL,
    classification_ceiling core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    forced_compartment text,
    ip_allowlist inet[] DEFAULT '{}'::inet[] NOT NULL,
    max_records_per_hour integer DEFAULT 10000 NOT NULL,
    max_bytes_per_request bigint DEFAULT 33554432 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    owner_user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    replaces_key_id uuid,
    CONSTRAINT api_key_category_known CHECK ((declared_category = ANY (ARRAY['STEALER_LOG'::text, 'CREDENTIAL_DUMP'::text, 'DATABASE_LEAK'::text, 'RANSOM_LEAK_POST'::text, 'MARKET_LISTING'::text, 'FORUM_POST'::text, 'CHAT_EXPORT'::text, 'PASTE'::text, 'IOC_FEED'::text, 'VENDOR_REPORT'::text, 'MALWARE_SAMPLE'::text, 'BLOCKCHAIN_TX'::text, 'SANCTIONS_LIST'::text, 'COURT_RECORD'::text, 'TELEMETRY'::text, 'UNKNOWN'::text]))),
    CONSTRAINT api_key_environment_known CHECK ((environment = ANY (ARRAY['live'::text, 'test'::text]))),
    CONSTRAINT api_key_expiry_mandatory CHECK ((expires_at > created_at)),
    CONSTRAINT api_key_revocation_complete CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    CONSTRAINT api_key_stealer_needs_compartment CHECK (((declared_category <> 'STEALER_LOG'::text) OR (forced_compartment IS NOT NULL))),
    CONSTRAINT api_key_write_only CHECK (((scopes <@ ARRAY['ingest:write'::text, 'ingest:status'::text]) AND (NOT ('case:read'::text = ANY (scopes)))))
);

--
-- Name: batch; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.batch (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    api_key_id uuid NOT NULL,
    idempotency_key text,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    raw_key text NOT NULL,
    raw_bytes bigint NOT NULL,
    raw_sha256 bytea NOT NULL,
    content_type text,
    detected_format text,
    state text DEFAULT 'RECEIVED'::text NOT NULL,
    record_count integer DEFAULT 0 NOT NULL,
    dead_count integer DEFAULT 0 NOT NULL,
    parsed_at timestamp with time zone,
    parser_version text,
    error text,
    CONSTRAINT batch_state_known CHECK ((state = ANY (ARRAY['RECEIVED'::text, 'PARSING'::text, 'PARSED'::text, 'FAILED'::text, 'PURGED'::text])))
);

--
-- Name: category_rule; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.category_rule (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    category text NOT NULL,
    match_keys text[] DEFAULT '{}'::text[] NOT NULL,
    match_pattern text,
    confidence numeric(4,3) DEFAULT 0.7 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT category_rule_category_known CHECK ((category = ANY (ARRAY['STEALER_LOG'::text, 'CREDENTIAL_DUMP'::text, 'DATABASE_LEAK'::text, 'RANSOM_LEAK_POST'::text, 'MARKET_LISTING'::text, 'FORUM_POST'::text, 'CHAT_EXPORT'::text, 'PASTE'::text, 'IOC_FEED'::text, 'VENDOR_REPORT'::text, 'MALWARE_SAMPLE'::text, 'BLOCKCHAIN_TX'::text, 'SANCTIONS_LIST'::text, 'COURT_RECORD'::text, 'TELEMETRY'::text, 'UNKNOWN'::text]))),
    CONSTRAINT category_rule_confidence_range CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)))
);

--
-- Name: dead_letter; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.dead_letter (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid,
    api_key_id uuid,
    raw_fragment text NOT NULL,
    error_class text NOT NULL,
    error_detail text,
    parser_version text,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    replayed_at timestamp with time zone,
    replayed_by uuid,
    resolution text,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    retain_until timestamp with time zone,
    redacted boolean DEFAULT false NOT NULL,
    fragment_sha256 bytea,
    purged_at timestamp with time zone,
    CONSTRAINT dead_letter_replay_complete CHECK (((replayed_at IS NULL) = (replayed_by IS NULL)))
);

--
-- Name: COLUMN dead_letter.raw_fragment; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON COLUMN ingest.dead_letter.raw_fragment IS 'Redacted unless dead_letter.redacted is false. Verbatim bytes live in the batch raw object, not here -- docs/17 F15(d).';

--
-- Name: lookup; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.lookup (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    provider_id uuid NOT NULL,
    operation text NOT NULL,
    adapter_version text NOT NULL,
    subject_kind text NOT NULL,
    selector_id uuid,
    sample_id uuid,
    node_id uuid,
    selector_type text NOT NULL,
    query_value text NOT NULL,
    query_fingerprint bytea NOT NULL,
    classification core.tlp NOT NULL,
    exposure_level text NOT NULL,
    exposure_confirmed boolean DEFAULT false NOT NULL,
    authorised_by uuid,
    authorisation_note text,
    signoff_expires_at timestamp with time zone,
    signed_off_by uuid,
    signed_off_at timestamp with time zone,
    signoff_note text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    state text NOT NULL,
    not_before timestamp with time zone,
    attempts smallint DEFAULT 0 NOT NULL,
    sent_at timestamp with time zone,
    finished_at timestamp with time zone,
    http_status integer,
    outcome text,
    error_class text,
    error_detail text,
    refusal text,
    result_id uuid,
    purged_at timestamp with time zone,
    batch_id uuid,
    CONSTRAINT lookup_answer_has_result CHECK (
CASE
    WHEN (subject_kind = 'CANARY'::text) THEN (result_id IS NULL)
    ELSE (((state = ANY (ARRAY['ANSWERED'::text, 'CACHED'::text])) OR ((state = 'FAILED'::text) AND (outcome = 'UNREADABLE'::text))) = (result_id IS NOT NULL))
END),
    CONSTRAINT lookup_answered_has_outcome CHECK (((state <> 'ANSWERED'::text) OR (outcome = ANY (ARRAY['FOUND'::text, 'NOT_FOUND'::text])))),
    CONSTRAINT lookup_attempts_range CHECK (((attempts >= 0) AND (attempts <= 3))),
    CONSTRAINT lookup_awaiting_is_signed_kind CHECK (((state <> 'AWAITING_SIGNOFF'::text) OR (exposure_level <> 'NONE'::text))),
    CONSTRAINT lookup_canary_is_clear CHECK (((subject_kind <> 'CANARY'::text) OR (classification = 'CLEAR'::core.tlp))),
    CONSTRAINT lookup_case_unless_canary CHECK (((subject_kind = 'CANARY'::text) = (case_id IS NULL))),
    CONSTRAINT lookup_closure_says_why CHECK (((state = ANY (ARRAY['REFUSED'::text, 'CANCELLED'::text, 'DECLINED'::text, 'EXPIRED'::text])) = (refusal IS NOT NULL))),
    CONSTRAINT lookup_error_short CHECK (((error_detail IS NULL) OR (length(error_detail) <= 500))),
    CONSTRAINT lookup_exposure_known CHECK ((exposure_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text]))),
    CONSTRAINT lookup_fingerprint_size CHECK ((octet_length(query_fingerprint) = 32)),
    CONSTRAINT lookup_never_above_amber CHECK ((classification <= 'AMBER'::core.tlp)),
    CONSTRAINT lookup_one_subject CHECK (
CASE subject_kind
    WHEN 'SELECTOR'::text THEN ((selector_id IS NOT NULL) AND (sample_id IS NULL))
    WHEN 'SAMPLE'::text THEN ((sample_id IS NOT NULL) AND (selector_id IS NULL))
    WHEN 'CANARY'::text THEN ((selector_id IS NULL) AND (sample_id IS NULL) AND (node_id IS NULL))
    ELSE ((selector_id IS NULL) AND (sample_id IS NULL))
END),
    CONSTRAINT lookup_outcome_known CHECK ((outcome = ANY (ARRAY['FOUND'::text, 'NOT_FOUND'::text, 'UNREADABLE'::text]))),
    CONSTRAINT lookup_purge_empties CHECK (((purged_at IS NULL) OR ((query_value = ''::text) AND (error_detail IS NULL) AND (COALESCE(authorisation_note, ''::text) = ''::text) AND (COALESCE(signoff_note, ''::text) = ''::text) AND (COALESCE(refusal, ''::text) = ANY (ARRAY[''::text, 'purged'::text]))))),
    CONSTRAINT lookup_sending_has_time CHECK (((state <> ALL (ARRAY['SENDING'::text, 'ANSWERED'::text])) OR (sent_at IS NOT NULL))),
    CONSTRAINT lookup_sent_iff_attempted CHECK (((attempts = 0) = (sent_at IS NULL))),
    CONSTRAINT lookup_sent_only_when_signed_off CHECK (((exposure_level = 'NONE'::text) OR (subject_kind = 'CANARY'::text) OR (state <> ALL (ARRAY['SENDING'::text, 'ANSWERED'::text, 'FAILED'::text])) OR ((signed_off_by = authorised_by) AND (signed_off_at IS NOT NULL) AND (signed_off_at <= signoff_expires_at)))),
    CONSTRAINT lookup_signed_after_request CHECK (((signed_off_at IS NULL) OR (signed_off_at > requested_at))),
    CONSTRAINT lookup_signed_is_never_queued CHECK (((exposure_level = 'NONE'::text) OR (subject_kind = 'CANARY'::text) OR (state <> 'QUEUED'::text))),
    CONSTRAINT lookup_signoff_asks_another CHECK (((exposure_level = 'NONE'::text) OR (subject_kind = 'CANARY'::text) OR (state = ANY (ARRAY['REFUSED'::text, 'CACHED'::text])) OR (purged_at IS NOT NULL) OR ((authorised_by IS NOT NULL) AND (authorised_by <> requested_by) AND (length(btrim(COALESCE(authorisation_note, ''::text))) > 0) AND (signoff_expires_at IS NOT NULL) AND (signoff_expires_at <= (requested_at + '24:00:00'::interval)) AND exposure_confirmed))),
    CONSTRAINT lookup_signoff_complete CHECK (((signed_off_by IS NULL) = (signed_off_at IS NULL))),
    CONSTRAINT lookup_state_known CHECK ((state = ANY (ARRAY['AWAITING_SIGNOFF'::text, 'QUEUED'::text, 'SENDING'::text, 'ANSWERED'::text, 'CACHED'::text, 'FAILED'::text, 'REFUSED'::text, 'CANCELLED'::text, 'DECLINED'::text, 'EXPIRED'::text]))),
    CONSTRAINT lookup_subject_known CHECK ((subject_kind = ANY (ARRAY['SELECTOR'::text, 'SAMPLE'::text, 'VALUE'::text, 'CANARY'::text])))
);

--
-- Name: TABLE lookup; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.lookup IS 'One lookup request (docs/12 Part 3). Anything that is not NONE waits for a named second person''s sign-off (docs/00 decision 75). Emptied by retention, never deleted.';

--
-- Name: lookup_attempt; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.lookup_attempt (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    lookup_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    attempt smallint NOT NULL,
    interactive boolean NOT NULL,
    sent_at timestamp with time zone NOT NULL,
    CONSTRAINT lookup_attempt_range CHECK (((attempt >= 1) AND (attempt <= 3)))
);

--
-- Name: TABLE lookup_attempt; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.lookup_attempt IS 'One row per send: what the provider quota counts. Append-only.';

--
-- Name: lookup_batch; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.lookup_batch (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    operation text NOT NULL,
    exposure_level text NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    note text NOT NULL,
    plan_digest bytea NOT NULL,
    planned integer NOT NULL,
    cached integer DEFAULT 0 NOT NULL,
    cancelled_at timestamp with time zone,
    cancelled_by uuid,
    cancel_reason text,
    purged_at timestamp with time zone,
    CONSTRAINT lookup_batch_cached_check CHECK ((cached >= 0)),
    CONSTRAINT lookup_batch_cancel_complete CHECK ((((cancelled_at IS NULL) = (cancelled_by IS NULL)) AND ((cancelled_at IS NULL) = (cancel_reason IS NULL)))),
    CONSTRAINT lookup_batch_is_none CHECK ((exposure_level = 'NONE'::text)),
    CONSTRAINT lookup_batch_justified CHECK (((purged_at IS NOT NULL) OR (length(btrim(note)) > 10))),
    CONSTRAINT lookup_batch_plan_digest_check CHECK ((octet_length(plan_digest) = 32)),
    CONSTRAINT lookup_batch_planned_check CHECK (((planned >= 0) AND (planned <= 500))),
    CONSTRAINT lookup_batch_purge_empties CHECK (((purged_at IS NULL) OR ((note = ''::text) AND (COALESCE(cancel_reason, ''::text) = ''::text))))
);

--
-- Name: TABLE lookup_batch; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.lookup_batch IS 'A committed plan of NONE lookups, paced by the provider''s windows. Its totals are never served: progress is derived from the rows a reader can read.';

--
-- Name: lookup_result; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.lookup_result (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    lookup_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    operation text NOT NULL,
    adapter_version text NOT NULL,
    selector_type text NOT NULL,
    query_fingerprint bytea NOT NULL,
    fetched_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    http_status integer NOT NULL,
    outcome text NOT NULL,
    media_type text NOT NULL,
    raw_body bytea NOT NULL,
    raw_sha256 bytea NOT NULL,
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    findings_total integer DEFAULT 0 NOT NULL,
    findings_proposed integer DEFAULT 0 NOT NULL,
    interpret_error text,
    classification core.tlp NOT NULL,
    filed_evidence_id uuid,
    purged_at timestamp with time zone,
    CONSTRAINT lookup_result_body_cap CHECK ((octet_length(raw_body) <= 16777216)),
    CONSTRAINT lookup_result_findings_total_check CHECK ((findings_total >= 0)),
    CONSTRAINT lookup_result_fresh CHECK ((fresh_until >= fetched_at)),
    CONSTRAINT lookup_result_interpret_error_check CHECK (((interpret_error IS NULL) OR (length(interpret_error) <= 500))),
    CONSTRAINT lookup_result_outcome_check CHECK ((outcome = ANY (ARRAY['FOUND'::text, 'NOT_FOUND'::text, 'UNREADABLE'::text]))),
    CONSTRAINT lookup_result_proposed_range CHECK (((findings_proposed >= 0) AND (findings_proposed <= findings_total))),
    CONSTRAINT lookup_result_purge_empties CHECK (((purged_at IS NULL) OR ((octet_length(raw_body) = 0) AND (summary = '{}'::jsonb) AND (interpret_error IS NULL)))),
    CONSTRAINT lookup_result_query_fingerprint_check CHECK ((octet_length(query_fingerprint) = 32)),
    CONSTRAINT lookup_result_raw_sha256_check CHECK ((octet_length(raw_sha256) = 32)),
    CONSTRAINT lookup_result_unreadable_never_cached CHECK (((outcome <> 'UNREADABLE'::text) OR (fresh_until = fetched_at))),
    CONSTRAINT lookup_result_unreadable_says_why CHECK (((purged_at IS NOT NULL) OR ((outcome = 'UNREADABLE'::text) = (interpret_error IS NOT NULL))))
);

--
-- Name: TABLE lookup_result; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.lookup_result IS 'A provider''s answer, kept as case material and never labelled below the question. Emptied by retention, never deleted.';

--
-- Name: pii_authorisation; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.pii_authorisation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid NOT NULL,
    granted_to uuid NOT NULL,
    granted_by uuid NOT NULL,
    scope_note text NOT NULL,
    legal_basis text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    query_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT pii_authorisation_is_time_boxed CHECK (((expires_at > granted_at) AND (expires_at <= (granted_at + '30 days'::interval)))),
    CONSTRAINT pii_authorisation_justified CHECK (((length(btrim(scope_note)) > 20) AND (length(btrim(legal_basis)) > 0))),
    CONSTRAINT pii_authorisation_two_humans CHECK ((granted_to <> granted_by))
);

--
-- Name: provider; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.provider (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key text NOT NULL,
    display_name text NOT NULL,
    adapter text NOT NULL,
    adapter_version text NOT NULL,
    source_id uuid NOT NULL,
    base_url text NOT NULL,
    origin_host text NOT NULL,
    origin_port integer NOT NULL,
    egress_route text NOT NULL,
    exposure_level text NOT NULL,
    exposure_basis text NOT NULL,
    exposure_determined_by uuid NOT NULL,
    exposure_determined_at timestamp with time zone DEFAULT now() NOT NULL,
    needs_exposure_approval boolean DEFAULT false NOT NULL,
    classification_ceiling core.tlp DEFAULT 'GREEN'::core.tlp NOT NULL,
    result_floor core.tlp,
    use_private_ca boolean DEFAULT false NOT NULL,
    private_cidr cidr,
    cache_ttl interval DEFAULT '7 days'::interval NOT NULL,
    quota_per_minute integer,
    quota_per_hour integer,
    quota_per_day integer,
    quota_per_month integer,
    queue_reserve_pct smallint DEFAULT 20 NOT NULL,
    max_response_bytes integer DEFAULT 2097152 NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    status text DEFAULT 'HEALTHY'::text NOT NULL,
    locked_reason text,
    cooldown_until timestamp with time zone,
    consecutive_429 smallint DEFAULT 0 NOT NULL,
    secret_ciphertext bytea,
    secret_key_id text,
    secret_origin text,
    secret_set_at timestamp with time zone,
    secret_set_by uuid,
    rotate_by date,
    last_request_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    retired_by uuid,
    retired_reason text,
    CONSTRAINT provider_429_count CHECK ((consecutive_429 >= 0)),
    CONSTRAINT provider_base_url_shape CHECK ((base_url ~ '^https://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$'::text)),
    CONSTRAINT provider_cache_ttl_range CHECK (((cache_ttl >= '00:00:00'::interval) AND (cache_ttl <= '90 days'::interval))),
    CONSTRAINT provider_ceiling_below_floor CHECK ((classification_ceiling = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp, 'AMBER'::core.tlp]))),
    CONSTRAINT provider_enabled_needs_approval CHECK (((NOT enabled) OR (NOT needs_exposure_approval))),
    CONSTRAINT provider_enabled_needs_quota CHECK (((NOT enabled) OR (num_nonnulls(quota_per_minute, quota_per_hour, quota_per_day, quota_per_month) >= 1))),
    CONSTRAINT provider_enabled_needs_secret CHECK (((NOT enabled) OR (secret_ciphertext IS NOT NULL))),
    CONSTRAINT provider_exposure_justified CHECK ((length(btrim(exposure_basis)) > 20)),
    CONSTRAINT provider_exposure_known CHECK ((exposure_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text]))),
    CONSTRAINT provider_key_shape CHECK ((key ~ '^[a-z][a-z0-9_]{1,32}$'::text)),
    CONSTRAINT provider_locked_says_why CHECK (((status = 'LOCKED'::text) = (locked_reason IS NOT NULL))),
    CONSTRAINT provider_name_present CHECK (((length(btrim(display_name)) >= 3) AND (length(btrim(display_name)) <= 80))),
    CONSTRAINT provider_port_range CHECK (((origin_port >= 1) AND (origin_port <= 65535))),
    CONSTRAINT provider_private_ca_is_none CHECK (((NOT use_private_ca) OR (exposure_level = 'NONE'::text))),
    CONSTRAINT provider_private_cidr_is_none CHECK (((private_cidr IS NULL) OR (exposure_level = 'NONE'::text))),
    CONSTRAINT provider_public_ceiling_clear CHECK (((exposure_level <> 'PUBLIC'::text) OR (classification_ceiling = 'CLEAR'::core.tlp))),
    CONSTRAINT provider_quota_day CHECK ((quota_per_day > 0)),
    CONSTRAINT provider_quota_hour CHECK ((quota_per_hour > 0)),
    CONSTRAINT provider_quota_minute CHECK ((quota_per_minute > 0)),
    CONSTRAINT provider_quota_month CHECK ((quota_per_month > 0)),
    CONSTRAINT provider_reserve_range CHECK (((queue_reserve_pct >= 0) AND (queue_reserve_pct <= 90))),
    CONSTRAINT provider_response_cap CHECK (((max_response_bytes >= 65536) AND (max_response_bytes <= 16777216))),
    CONSTRAINT provider_retired_is_off CHECK (((retired_at IS NULL) OR ((NOT enabled) AND (secret_ciphertext IS NULL)))),
    CONSTRAINT provider_retirement_complete CHECK ((((retired_at IS NULL) = (retired_reason IS NULL)) AND ((retired_at IS NULL) = (retired_by IS NULL)))),
    CONSTRAINT provider_route_shape CHECK ((egress_route ~ '^lookup-[a-z0-9-]{1,33}$'::text)),
    CONSTRAINT provider_secret_complete CHECK ((((secret_ciphertext IS NULL) = (secret_key_id IS NULL)) AND ((secret_ciphertext IS NULL) = (secret_origin IS NULL)) AND ((secret_ciphertext IS NULL) = (secret_set_at IS NULL)) AND ((secret_ciphertext IS NULL) = (rotate_by IS NULL)))),
    CONSTRAINT provider_status_known CHECK ((status = ANY (ARRAY['HEALTHY'::text, 'LOCKED'::text]))),
    CONSTRAINT provider_vendor_ceiling_green CHECK (((exposure_level <> 'VENDOR'::text) OR (classification_ceiling = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp]))))
);

--
-- Name: TABLE provider; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.provider IS 'An outbound lookup provider (docs/12 Part 3). Its key is envelope-sealed and bound to the origin and route it was entered for. Retired, never deleted.';

--
-- Name: provider_exposure_change; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.provider_exposure_change (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_id uuid NOT NULL,
    from_level text NOT NULL,
    to_level text NOT NULL,
    origin text NOT NULL,
    private_cidr cidr,
    basis text NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decision text,
    decided_by uuid,
    decided_at timestamp with time zone,
    decision_note text,
    CONSTRAINT exposure_change_approved_in_time CHECK (((decision IS DISTINCT FROM 'APPROVED'::text) OR (decided_at <= expires_at))),
    CONSTRAINT exposure_change_decision_complete CHECK (((decision IS NULL) = (decided_at IS NULL))),
    CONSTRAINT exposure_change_expires CHECK (((expires_at > requested_at) AND (expires_at <= (requested_at + '72:00:00'::interval)))),
    CONSTRAINT exposure_change_expiry_has_no_decider CHECK (((decision IS DISTINCT FROM 'EXPIRED'::text) OR (decided_by IS NULL))),
    CONSTRAINT exposure_change_justified CHECK ((length(btrim(basis)) > 20)),
    CONSTRAINT exposure_change_lowers CHECK ((ingest.exposure_rank(to_level) < ingest.exposure_rank(from_level))),
    CONSTRAINT exposure_change_origin_shape CHECK ((origin ~ '^https://.+:[0-9]{1,5}$'::text)),
    CONSTRAINT exposure_change_two_admins CHECK (((decision IS NULL) OR (decision <> ALL (ARRAY['APPROVED'::text, 'DECLINED'::text])) OR ((decided_by IS NOT NULL) AND (decided_by <> requested_by)))),
    CONSTRAINT exposure_change_withdrawn_by_requester CHECK (((decision IS DISTINCT FROM 'WITHDRAWN'::text) OR (decided_by = requested_by))),
    CONSTRAINT provider_exposure_change_decision_check CHECK ((decision = ANY (ARRAY['APPROVED'::text, 'DECLINED'::text, 'WITHDRAWN'::text, 'EXPIRED'::text]))),
    CONSTRAINT provider_exposure_change_from_level_check CHECK ((from_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text]))),
    CONSTRAINT provider_exposure_change_to_level_check CHECK ((to_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text])))
);

--
-- Name: TABLE provider_exposure_change; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON TABLE ingest.provider_exposure_change IS 'Lowering a provider''s exposure, requested by one administrator and decided by a different one (docs/12 Part 3). Decided once, never deleted.';

--
-- Name: record; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.record (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    case_id uuid,
    category text DEFAULT 'UNKNOWN'::text NOT NULL,
    category_confidence numeric(4,3) DEFAULT 0.5 NOT NULL,
    category_source text DEFAULT 'DECLARED'::text NOT NULL,
    payload jsonb NOT NULL,
    content_sha256 bytea NOT NULL,
    simhash bigint,
    duplicate_of uuid,
    priority numeric(6,3) DEFAULT 0 NOT NULL,
    priority_detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    retain_until timestamp with time zone,
    purged_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    simhash_version smallint DEFAULT 1 NOT NULL,
    CONSTRAINT record_category_known CHECK ((category = ANY (ARRAY['STEALER_LOG'::text, 'CREDENTIAL_DUMP'::text, 'DATABASE_LEAK'::text, 'RANSOM_LEAK_POST'::text, 'MARKET_LISTING'::text, 'FORUM_POST'::text, 'CHAT_EXPORT'::text, 'PASTE'::text, 'IOC_FEED'::text, 'VENDOR_REPORT'::text, 'MALWARE_SAMPLE'::text, 'BLOCKCHAIN_TX'::text, 'SANCTIONS_LIST'::text, 'COURT_RECORD'::text, 'TELEMETRY'::text, 'UNKNOWN'::text]))),
    CONSTRAINT record_category_source_known CHECK ((category_source = ANY (ARRAY['DECLARED'::text, 'STRUCTURE'::text, 'STRUCTURE_NESTED'::text, 'CONTENT'::text, 'ANALYST'::text]))),
    CONSTRAINT record_confidence_range CHECK (((category_confidence >= (0)::numeric) AND (category_confidence <= (1)::numeric))),
    CONSTRAINT record_stealer_is_compartmented CHECK (((category <> 'STEALER_LOG'::text) OR (COALESCE(array_length(compartments, 1), 0) >= 1)))
);

--
-- Name: COLUMN record.simhash_version; Type: COMMENT; Schema: ingest; Owner: -
--

COMMENT ON COLUMN ingest.record.simhash_version IS 'Which tokeniser produced simhash. Fingerprints of different versions are not comparable -- see docs/17 F15(g).';

--
-- Name: victim_credential; Type: TABLE; Schema: ingest; Owner: -
--

CREATE TABLE ingest.victim_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    record_id uuid NOT NULL,
    victim_node_id uuid,
    kind text NOT NULL,
    service_domain text,
    value_fingerprint bytea NOT NULL,
    value_ciphertext bytea,
    value_key_id text,
    reveal_count integer DEFAULT 0 NOT NULL,
    last_revealed_at timestamp with time zone,
    captured_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT victim_credential_encrypted_or_absent CHECK (((value_ciphertext IS NULL) = (value_key_id IS NULL))),
    CONSTRAINT victim_credential_kind_known CHECK ((kind = ANY (ARRAY['PASSWORD'::text, 'COOKIE'::text, 'SESSION_TOKEN'::text, 'AUTOFILL'::text, 'WALLET_KEY'::text, 'DOCUMENT_PATH'::text, 'OTHER'::text])))
);

--
-- Name: detonation; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.detonation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sample_id uuid NOT NULL,
    target text NOT NULL,
    exposure_level text NOT NULL,
    authorised_by uuid,
    authorisation_note text,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    submitted_at timestamp with time zone,
    external_ref text,
    status text DEFAULT 'PENDING'::text NOT NULL,
    report jsonb,
    mode text DEFAULT 'RECORD_ONLY'::text NOT NULL,
    provider text,
    target_key text,
    target_host text,
    target_ceiling core.tlp,
    egress_route text,
    network_route text,
    route_class text,
    machine text,
    machine_class text,
    options jsonb DEFAULT '{}'::jsonb NOT NULL,
    signoff_required boolean DEFAULT false NOT NULL,
    signoff_expires_at timestamp with time zone,
    signed_off_by uuid,
    signed_off_at timestamp with time zone,
    signoff_decision text,
    signoff_note text,
    classification_sent core.tlp,
    egress_reason text,
    submitted_sha256 bytea,
    submit_outcome text,
    external_status text,
    attempts integer DEFAULT 0 NOT NULL,
    last_polled_at timestamp with time zone,
    last_error text,
    completed_at timestamp with time zone,
    report_sha256 bytea,
    report_bytes bigint,
    analysis_id uuid,
    cancelled_by uuid,
    CONSTRAINT detonation_attempts_non_negative CHECK ((attempts >= 0)),
    CONSTRAINT detonation_ceiling_leaves CHECK (((target_ceiling IS NULL) OR (target_ceiling = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp, 'AMBER'::core.tlp])))),
    CONSTRAINT detonation_confirmed_has_ref CHECK (((mode = 'RECORD_ONLY'::text) OR ((NOT (submit_outcome IS DISTINCT FROM 'CONFIRMED'::text)) = (external_ref IS NOT NULL)))),
    CONSTRAINT detonation_declined_is_signed CHECK (((status <> 'DECLINED'::text) OR (signoff_decision = 'DECLINED'::text))),
    CONSTRAINT detonation_exposure_known CHECK ((exposure_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text]))),
    CONSTRAINT detonation_exposure_needs_authoriser CHECK (((exposure_level = 'NONE'::text) OR (authorised_by IS NOT NULL))),
    CONSTRAINT detonation_exposure_needs_note CHECK (((exposure_level = 'NONE'::text) OR (authorisation_note IS NOT NULL))),
    CONSTRAINT detonation_machine_classed CHECK ((((machine IS NULL) = (machine_class IS NULL)) AND ((machine_class IS NULL) OR (machine_class = ANY (ARRAY['ISOLATED'::text, 'LIVE'::text]))))),
    CONSTRAINT detonation_mode_known CHECK ((mode = ANY (ARRAY['RECORD_ONLY'::text, 'SUBMIT'::text]))),
    CONSTRAINT detonation_queued_only_when_signed CHECK (((status <> ALL (ARRAY['QUEUED'::text, 'SUBMITTED'::text, 'REPORTED'::text, 'FAILED'::text])) OR (mode = 'RECORD_ONLY'::text) OR (NOT signoff_required) OR (signoff_decision = 'APPROVED'::text))),
    CONSTRAINT detonation_reported_is_complete CHECK (((status <> 'REPORTED'::text) OR (mode = 'RECORD_ONLY'::text) OR ((submit_outcome = 'CONFIRMED'::text) AND (report_sha256 IS NOT NULL) AND (completed_at IS NOT NULL) AND (analysis_id IS NOT NULL)))),
    CONSTRAINT detonation_route_class_known CHECK (((route_class IS NULL) OR (route_class = ANY (ARRAY['ISOLATED'::text, 'LIVE'::text])))),
    CONSTRAINT detonation_sent_is_dated CHECK (((mode = 'RECORD_ONLY'::text) OR (status <> ALL (ARRAY['SUBMITTED'::text, 'REPORTED'::text, 'FAILED'::text])) OR (submitted_at IS NOT NULL))),
    CONSTRAINT detonation_signoff_by_the_named_authoriser CHECK (((signed_off_by IS NULL) OR (signed_off_by = authorised_by))),
    CONSTRAINT detonation_signoff_complete CHECK ((((signed_off_at IS NULL) = (signed_off_by IS NULL)) AND ((signed_off_at IS NULL) = (signoff_decision IS NULL)))),
    CONSTRAINT detonation_signoff_decision_known CHECK (((signoff_decision IS NULL) OR (signoff_decision = ANY (ARRAY['APPROVED'::text, 'DECLINED'::text])))),
    CONSTRAINT detonation_signoff_names_an_authoriser CHECK (((NOT signoff_required) OR ((authorised_by IS NOT NULL) AND (authorisation_note IS NOT NULL)))),
    CONSTRAINT detonation_signoff_when_exposed CHECK (((mode = 'RECORD_ONLY'::text) OR (signoff_required = ((exposure_level <> 'NONE'::text) OR (route_class = 'LIVE'::text) OR COALESCE((machine_class = 'LIVE'::text), false))))),
    CONSTRAINT detonation_signoff_window CHECK ((signoff_required = (signoff_expires_at IS NOT NULL))),
    CONSTRAINT detonation_status_by_mode CHECK ((((mode = 'RECORD_ONLY'::text) AND (status = ANY (ARRAY['PENDING'::text, 'AUTHORISED'::text, 'SUBMITTED'::text, 'REPORTED'::text, 'REFUSED'::text]))) OR ((mode = 'SUBMIT'::text) AND (status = ANY (ARRAY['AWAITING_SIGNOFF'::text, 'QUEUED'::text, 'SUBMITTED'::text, 'REPORTED'::text, 'FAILED'::text, 'REFUSED'::text, 'DECLINED'::text, 'CANCELLED'::text]))))),
    CONSTRAINT detonation_submit_names_target CHECK (((mode = 'RECORD_ONLY'::text) OR (num_nulls(provider, target_key, target_host, target_ceiling, egress_route, network_route, route_class) = 0))),
    CONSTRAINT detonation_submit_outcome_known CHECK (((submit_outcome IS NULL) OR (submit_outcome = ANY (ARRAY['CONFIRMED'::text, 'NOT_SENT'::text, 'REJECTED_BY_TARGET'::text, 'UNCONFIRMED'::text])))),
    CONSTRAINT detonation_two_people CHECK (((mode = 'RECORD_ONLY'::text) OR (authorised_by IS DISTINCT FROM requested_by)))
);

--
-- Name: COLUMN detonation.mode; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON COLUMN lab.detonation.mode IS 'RECORD_ONLY: a request recorded and never sent (every row before 0103). SUBMIT: sent by scripts/sandbox_dispatch.py to the configured sandbox.';

--
-- Name: download_ticket; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.download_ticket (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash bytea NOT NULL,
    sample_id uuid,
    user_id uuid NOT NULL,
    session_id uuid,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    redeemed_at timestamp with time zone,
    ip_hash bytea,
    purpose text DEFAULT 'download'::text NOT NULL,
    evidence_id uuid,
    CONSTRAINT download_ticket_expiry_after_issue CHECK ((expires_at > issued_at)),
    CONSTRAINT download_ticket_names_one_object CHECK ((num_nonnulls(sample_id, evidence_id) = 1)),
    CONSTRAINT download_ticket_purpose_known CHECK ((purpose = ANY (ARRAY['download'::text, 'preserved_retrieval'::text, 'exhibit_production'::text]))),
    CONSTRAINT download_ticket_purpose_matches_object CHECK (((purpose = 'exhibit_production'::text) = (evidence_id IS NOT NULL)))
);

--
-- Name: TABLE download_ticket; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.download_ticket IS 'One-shot, sixty-second authority to download ONE sample, or to produce ONE exhibit of attacker markup, from the sample origin, minted on the application origin under a cookie session. Exhausted state, not a ledger: lab.sample_access and core.evidence_custody are the custody records and audit.event carries the issue and the redemption.';

--
-- Name: preservation_authorisation; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.preservation_authorisation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sample_id uuid NOT NULL,
    granted_to uuid NOT NULL,
    granted_by uuid NOT NULL,
    scope_note text NOT NULL,
    legal_basis text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    retrieval_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT preservation_authorisation_count_non_negative CHECK ((retrieval_count >= 0)),
    CONSTRAINT preservation_authorisation_is_time_boxed CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '30 days'::interval)))),
    CONSTRAINT preservation_authorisation_justified CHECK (((length(btrim(scope_note)) > 20) AND (length(btrim(legal_basis)) > 0))),
    CONSTRAINT preservation_authorisation_revocation_complete CHECK (((revoked_at IS NULL) = (revoked_by IS NULL))),
    CONSTRAINT preservation_authorisation_two_people CHECK ((granted_to <> granted_by))
);

--
-- Name: TABLE preservation_authorisation; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.preservation_authorisation IS 'One named person may retrieve one preserved (rejected) sample, in its encrypted archive, until expires_at. Granted by somebody else. Never deleted and never rewritten: revocation is a column.';

--
-- Name: sample; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.sample (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_id uuid,
    node_id uuid,
    sha256 bytea NOT NULL,
    sha1 bytea,
    md5 bytea,
    original_filename text,
    byte_size bigint NOT NULL,
    storage_key text NOT NULL,
    storage_bucket text NOT NULL,
    data_key_ciphertext bytea NOT NULL,
    data_key_id text NOT NULL,
    state lab.sample_state DEFAULT 'SUBMITTED'::lab.sample_state NOT NULL,
    reject_reason text,
    imphash text,
    rich_header_hash text,
    ssdeep text,
    tlsh text,
    file_type text,
    entropy numeric(6,4),
    triage_gaps jsonb DEFAULT '[]'::jsonb NOT NULL,
    submitted_by uuid NOT NULL,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    source_note text,
    assigned_to uuid,
    assigned_at timestamp with time zone,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    legal_hold boolean DEFAULT false NOT NULL,
    preserved_bucket text,
    preserved_key text,
    preserved_version_id text,
    preserved_at timestamp with time zone,
    ssdeep_tokens text[],
    tlsh_lvalue smallint,
    screening_outcome text DEFAULT 'NOT_SCREENED'::text NOT NULL,
    screened_at timestamp with time zone,
    screening_list_seq bigint,
    screening_bytes_absent_at timestamp with time zone,
    CONSTRAINT sample_assignment_complete CHECK (((assigned_to IS NULL) = (assigned_at IS NULL))),
    CONSTRAINT sample_bytes_absent_only_on_match CHECK (((screening_bytes_absent_at IS NULL) OR (screening_outcome = 'MATCH'::text))),
    CONSTRAINT sample_match_is_rejected CHECK (((screening_outcome <> 'MATCH'::text) OR (state = 'REJECTED'::lab.sample_state))),
    CONSTRAINT sample_preservation_complete CHECK ((((preserved_key IS NULL) = (preserved_bucket IS NULL)) AND ((preserved_key IS NULL) = (preserved_at IS NULL)) AND ((preserved_key IS NOT NULL) OR (preserved_version_id IS NULL)))),
    CONSTRAINT sample_preserved_keeps_its_key CHECK (((preserved_key IS NULL) OR (octet_length(data_key_ciphertext) > 0))),
    CONSTRAINT sample_preserved_only_when_rejected CHECK (((preserved_key IS NULL) OR (state = 'REJECTED'::lab.sample_state))),
    CONSTRAINT sample_rejection_has_reason CHECK (((state = 'REJECTED'::lab.sample_state) = (reject_reason IS NOT NULL))),
    CONSTRAINT sample_screening_dated CHECK ((((screening_outcome = 'NOT_SCREENED'::text) = (screened_at IS NULL)) AND ((screened_at IS NULL) = (screening_list_seq IS NULL)))),
    CONSTRAINT sample_screening_outcome_known CHECK ((screening_outcome = ANY (ARRAY['NOT_SCREENED'::text, 'NO_MATCH'::text, 'MATCH'::text]))),
    CONSTRAINT sample_ssdeep_tokens_with_ssdeep CHECK (((ssdeep IS NOT NULL) OR (ssdeep_tokens IS NULL))),
    CONSTRAINT sample_tlsh_lvalue_range CHECK (((tlsh_lvalue >= 0) AND (tlsh_lvalue <= 255))),
    CONSTRAINT sample_tlsh_lvalue_with_tlsh CHECK (((tlsh IS NULL) = (tlsh_lvalue IS NULL)))
);

--
-- Name: COLUMN sample.screening_outcome; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON COLUMN lab.sample.screening_outcome IS 'Prohibited-content screening by exact hash (F13). MATCH is permanent and implies REJECTED; retiring a list never un-matches a sample.';

--
-- Name: COLUMN sample.screening_bytes_absent_at; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON COLUMN lab.sample.screening_bytes_absent_at IS 'Set once when a matched sample''s bytes were found in neither store on two passes. Recorded, never acted on: the data key is kept.';

--
-- Name: sample_access; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.sample_access (
    id bigint NOT NULL,
    sample_id uuid NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    archive_format text,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    actor_kind text DEFAULT 'USER'::text NOT NULL,
    CONSTRAINT sample_access_action_known CHECK ((action = ANY (ARRAY['VIEWED_META'::text, 'DOWNLOADED'::text, 'SHARED'::text, 'DETONATED'::text, 'REJECTED'::text, 'ASSIGNED'::text, 'ANALYSED'::text, 'SCANNED'::text]))),
    CONSTRAINT sample_access_actor_kind_known CHECK ((actor_kind = ANY (ARRAY['USER'::text, 'SYSTEM'::text]))),
    CONSTRAINT sample_access_system_actions CHECK (((actor_kind = 'USER'::text) OR (action = ANY (ARRAY['SCANNED'::text, 'VIEWED_META'::text, 'REJECTED'::text, 'ANALYSED'::text])))),
    CONSTRAINT sample_access_system_names_nobody CHECK (((actor_kind = 'SYSTEM'::text) = (actor_id IS NULL)))
);

--
-- Name: COLUMN sample_access.actor_kind; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON COLUMN lab.sample_access.actor_kind IS 'USER names the person in actor_id; SYSTEM is the product acting on nobody''s request (actor_id NULL), allowed only for reads in memory (SCANNED), integrity alarms, screening isolation and machine findings.';

--
-- Name: sample_access_id_seq; Type: SEQUENCE; Schema: lab; Owner: -
--

CREATE SEQUENCE lab.sample_access_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: sample_access_id_seq; Type: SEQUENCE OWNED BY; Schema: lab; Owner: -
--

ALTER SEQUENCE lab.sample_access_id_seq OWNED BY lab.sample_access.id;

--
-- Name: sample_analysis; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.sample_analysis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sample_id uuid NOT NULL,
    kind text NOT NULL,
    analyst_id uuid,
    tool text,
    tool_version text,
    findings jsonb DEFAULT '{}'::jsonb NOT NULL,
    extracted_selectors jsonb DEFAULT '[]'::jsonb NOT NULL,
    yara_hits text[],
    family_assessment text,
    confidence core.analytic_confidence,
    narrative text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    origin text DEFAULT 'analyst'::text NOT NULL,
    run_id uuid,
    yara_ruleset_version_id uuid,
    CONSTRAINT sample_analysis_family_needs_confidence CHECK (((family_assessment IS NULL) OR (confidence IS NOT NULL))),
    CONSTRAINT sample_analysis_kind_known CHECK ((kind = ANY (ARRAY['STATIC'::text, 'YARA'::text, 'MANUAL_RE'::text, 'SANDBOX'::text, 'VENDOR'::text]))),
    CONSTRAINT sample_analysis_machine_names_no_analyst CHECK (((origin = 'analyst'::text) OR (analyst_id IS NULL))),
    CONSTRAINT sample_analysis_machine_yara_names_its_rules CHECK (((NOT ((origin = 'machine'::text) AND (kind = 'YARA'::text))) OR ((run_id IS NOT NULL) AND (yara_ruleset_version_id IS NOT NULL)))),
    CONSTRAINT sample_analysis_origin_known CHECK ((origin = ANY (ARRAY['analyst'::text, 'machine'::text]))),
    CONSTRAINT sample_analysis_run_only_on_machine_rows CHECK (((run_id IS NULL) OR (origin = 'machine'::text))),
    CONSTRAINT sample_analysis_static_names_its_run CHECK (((NOT ((origin = 'machine'::text) AND (kind = 'STATIC'::text))) OR (run_id IS NOT NULL)))
);

--
-- Name: screening_hash; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.screening_hash (
    list_id uuid NOT NULL,
    algorithm text NOT NULL,
    digest bytea NOT NULL,
    CONSTRAINT screening_hash_algorithm_known CHECK ((algorithm = ANY (ARRAY['md5'::text, 'sha1'::text, 'sha256'::text]))),
    CONSTRAINT screening_hash_digest_length CHECK ((octet_length(digest) =
CASE algorithm
    WHEN 'md5'::text THEN 16
    WHEN 'sha1'::text THEN 20
    ELSE 32
END))
);

--
-- Name: TABLE screening_hash; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.screening_hash IS 'The entries of the imported lists. Read only by the matcher (screening.screen_digests and the rescan); never returned by any route.';

--
-- Name: screening_list; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.screening_list (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    category text NOT NULL,
    authority_reference text NOT NULL,
    deployment_authority text NOT NULL,
    source_sha256 bytea NOT NULL,
    entry_count integer NOT NULL,
    algorithms text[] NOT NULL,
    imported_by uuid NOT NULL,
    imported_via text NOT NULL,
    imported_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    retired_by uuid,
    retire_reason text,
    purge_requested boolean DEFAULT false NOT NULL,
    purge_requested_by uuid,
    entries_purged_at timestamp with time zone,
    CONSTRAINT screening_list_algorithms CHECK (((cardinality(algorithms) >= 1) AND (algorithms <@ ARRAY['md5'::text, 'sha1'::text, 'sha256'::text]))),
    CONSTRAINT screening_list_authority CHECK (((length(btrim(authority_reference)) >= 6) AND (length(btrim(deployment_authority)) >= 6))),
    CONSTRAINT screening_list_category_known CHECK ((category = ANY (ARRAY['KNOWN_CSAM'::text, 'TERRORIST_CONTENT'::text, 'OTHER_PROHIBITED'::text]))),
    CONSTRAINT screening_list_named CHECK (((length(btrim(name)) > 0) AND (length(btrim(provider)) > 0))),
    CONSTRAINT screening_list_not_empty CHECK ((entry_count > 0)),
    CONSTRAINT screening_list_purge_after_retire CHECK (((NOT purge_requested) OR (retired_at IS NOT NULL))),
    CONSTRAINT screening_list_purge_names_who CHECK ((purge_requested = (purge_requested_by IS NOT NULL))),
    CONSTRAINT screening_list_purged_when_asked CHECK (((entries_purged_at IS NULL) OR purge_requested)),
    CONSTRAINT screening_list_retirement_complete CHECK ((((retired_at IS NULL) = (retired_by IS NULL)) AND ((retired_at IS NULL) = (retire_reason IS NULL)))),
    CONSTRAINT screening_list_source_digest CHECK ((octet_length(source_sha256) = 32)),
    CONSTRAINT screening_list_via_known CHECK ((imported_via = ANY (ARRAY['console'::text, 'cli'::text])))
);

--
-- Name: TABLE screening_list; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.screening_list IS 'Prohibited-content hash lists an operator imported under a recorded authority (F13). Never deleted; retirement and purge are stamped once.';

--
-- Name: screening_list_seq_seq; Type: SEQUENCE; Schema: lab; Owner: -
--

ALTER TABLE lab.screening_list ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME lab.screening_list_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

--
-- Name: screening_result; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.screening_result (
    id uuid NOT NULL,
    sample_id uuid NOT NULL,
    sha256 bytea NOT NULL,
    screened_at timestamp with time zone DEFAULT now() NOT NULL,
    trigger text NOT NULL,
    actor_id uuid,
    outcome text NOT NULL,
    lists_consulted uuid[] NOT NULL,
    list_seq bigint NOT NULL,
    matched_lists uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    matched_algorithms text[] DEFAULT '{}'::text[] NOT NULL,
    disposition text,
    alert_outcome text,
    officers_notified integer DEFAULT 0 NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT screening_result_alert_outcome_check CHECK ((alert_outcome = ANY (ARRAY['SENT'::text, 'COALESCED'::text, 'NONE_REACHED'::text, 'FAILED'::text]))),
    CONSTRAINT screening_result_disposition_check CHECK ((disposition = ANY (ARRAY['PRESERVE'::text, 'NOT_STORED'::text, 'STORE_FAILED'::text, 'ALREADY_PRESERVED'::text, 'NO_BYTES'::text, 'ALREADY_ISOLATED'::text]))),
    CONSTRAINT screening_result_lists_consulted_check CHECK ((cardinality(lists_consulted) > 0)),
    CONSTRAINT screening_result_match_is_disposed CHECK ((((outcome = 'MATCH'::text) = (disposition IS NOT NULL)) AND ((outcome = 'MATCH'::text) = (alert_outcome IS NOT NULL)))),
    CONSTRAINT screening_result_match_is_named CHECK (((outcome = 'MATCH'::text) = (cardinality(matched_lists) > 0))),
    CONSTRAINT screening_result_no_match_is_a_submission CHECK (((outcome = 'MATCH'::text) OR (trigger = 'SUBMISSION'::text))),
    CONSTRAINT screening_result_officers_notified_check CHECK ((officers_notified >= 0)),
    CONSTRAINT screening_result_outcome_check CHECK ((outcome = ANY (ARRAY['NO_MATCH'::text, 'MATCH'::text]))),
    CONSTRAINT screening_result_sha256_check CHECK ((octet_length(sha256) = 32)),
    CONSTRAINT screening_result_trigger_check CHECK ((trigger = ANY (ARRAY['SUBMISSION'::text, 'LIST_IMPORT'::text, 'RESCAN'::text])))
);

--
-- Name: screening_review; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.screening_review (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    result_id uuid NOT NULL,
    reviewed_by uuid NOT NULL,
    reviewed_at timestamp with time zone DEFAULT now() NOT NULL,
    action text NOT NULL,
    reference text,
    note text,
    CONSTRAINT screening_review_action_check CHECK ((action = ANY (ARRAY['ACKNOWLEDGED'::text, 'REFERRED'::text, 'FALSE_POSITIVE_SUSPECTED'::text, 'DISPOSED_OUTSIDE'::text, 'NOTE'::text]))),
    CONSTRAINT screening_review_referenced CHECK (((action <> ALL (ARRAY['REFERRED'::text, 'DISPOSED_OUTSIDE'::text])) OR (length(btrim(COALESCE(reference, ''::text))) > 0))),
    CONSTRAINT screening_review_says_something CHECK (((action = 'ACKNOWLEDGED'::text) OR (length(btrim((COALESCE(reference, ''::text) || COALESCE(note, ''::text)))) > 0)))
);

--
-- Name: static_run; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.static_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sample_id uuid NOT NULL,
    trigger text NOT NULL,
    requested_by uuid,
    requests jsonb DEFAULT '[]'::jsonb NOT NULL,
    priority smallint DEFAULT 1 NOT NULL,
    steps text[] DEFAULT '{pe,fuzzy,yara}'::text[] NOT NULL,
    yara_version_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    status text DEFAULT 'QUEUED'::text NOT NULL,
    attempt integer DEFAULT 1 NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    outcome jsonb DEFAULT '{}'::jsonb NOT NULL,
    failure text,
    CONSTRAINT static_run_attempt_positive CHECK ((attempt >= 1)),
    CONSTRAINT static_run_failure_says_why CHECK (((status = ANY (ARRAY['FAILED'::text, 'ABANDONED'::text, 'SKIPPED'::text])) = (failure IS NOT NULL))),
    CONSTRAINT static_run_finished CHECK (((status = ANY (ARRAY['QUEUED'::text, 'RUNNING'::text])) = (finished_at IS NULL))),
    CONSTRAINT static_run_person_named CHECK (((trigger <> ALL (ARRAY['ON_DEMAND'::text, 'RETROHUNT'::text])) OR (requested_by IS NOT NULL))),
    CONSTRAINT static_run_priority_known CHECK (((priority >= 0) AND (priority <= 2))),
    CONSTRAINT static_run_queued_untouched CHECK (((status <> 'QUEUED'::text) OR ((started_at IS NULL) AND (finished_at IS NULL)))),
    CONSTRAINT static_run_requests_is_a_list CHECK ((jsonb_typeof(requests) = 'array'::text)),
    CONSTRAINT static_run_started CHECK (((status <> ALL (ARRAY['RUNNING'::text, 'DONE'::text, 'FAILED'::text, 'ABANDONED'::text])) OR (started_at IS NOT NULL))),
    CONSTRAINT static_run_status_known CHECK ((status = ANY (ARRAY['QUEUED'::text, 'RUNNING'::text, 'DONE'::text, 'FAILED'::text, 'ABANDONED'::text, 'SKIPPED'::text]))),
    CONSTRAINT static_run_steps_known CHECK (((cardinality(steps) > 0) AND (steps <@ ARRAY['pe'::text, 'fuzzy'::text, 'yara'::text]))),
    CONSTRAINT static_run_trigger_known CHECK ((trigger = ANY (ARRAY['SUBMIT'::text, 'ON_DEMAND'::text, 'RETRY'::text, 'RETROHUNT'::text, 'BACKFILL'::text])))
);

--
-- Name: TABLE static_run; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.static_run IS 'The static-triage queue (F11). A queue, not a ledger: SCANNED custody and the audit chain record what was read and who caused it. requests lists every request merged into the run, so custody can name each requester.';

--
-- Name: yara_activation; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_activation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ruleset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    activated_by uuid NOT NULL,
    activated_at timestamp with time zone DEFAULT now() NOT NULL,
    licence_acknowledgement text,
    deactivated_by uuid,
    deactivated_at timestamp with time zone,
    deactivation_reason text,
    CONSTRAINT yara_activation_ack_says_something CHECK (((licence_acknowledgement IS NULL) OR (length(btrim(licence_acknowledgement)) > 20))),
    CONSTRAINT yara_activation_close_complete CHECK ((((deactivated_at IS NULL) = (deactivated_by IS NULL)) AND ((deactivated_at IS NULL) = (deactivation_reason IS NULL)))),
    CONSTRAINT yara_activation_reason_says_something CHECK (((deactivation_reason IS NULL) OR (length(btrim(deactivation_reason)) >= 10)))
);

--
-- Name: yara_compile_job; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_compile_job (
    version_id uuid NOT NULL,
    engine text NOT NULL,
    platform text NOT NULL,
    fingerprint text NOT NULL,
    status text DEFAULT 'QUEUED'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT yara_compile_job_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT yara_compile_job_status_check CHECK ((status = ANY (ARRAY['QUEUED'::text, 'RUNNING'::text, 'FAILED'::text])))
);

--
-- Name: yara_compiled; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_compiled (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    version_id uuid NOT NULL,
    engine text NOT NULL,
    platform text NOT NULL,
    fingerprint text NOT NULL,
    status text NOT NULL,
    rule_count integer DEFAULT 0 NOT NULL,
    warning_count integer DEFAULT 0 NOT NULL,
    report jsonb NOT NULL,
    compiled bytea,
    blob_sha256 bytea,
    mac_key_id text,
    mac bytea,
    compiled_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT yara_compiled_blob_when_built CHECK ((((status = 'FAILED'::text) = (compiled IS NULL)) AND ((compiled IS NULL) = (blob_sha256 IS NULL)) AND ((compiled IS NULL) = (mac IS NULL)) AND ((compiled IS NULL) = (mac_key_id IS NULL)))),
    CONSTRAINT yara_compiled_status_check CHECK ((status = ANY (ARRAY['COMPILED'::text, 'PARTIAL'::text, 'FAILED'::text])))
);

--
-- Name: yara_compiled_rejected; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_compiled_rejected (
    compiled_id uuid NOT NULL,
    reason text NOT NULL,
    rejected_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT yara_compiled_rejected_reason_check CHECK ((reason = ANY (ARRAY['mac_mismatch'::text, 'undecodable'::text])))
);

--
-- Name: yara_ruleset; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_ruleset (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key text NOT NULL,
    display_name text NOT NULL,
    description text,
    classification core.tlp DEFAULT 'AMBER'::core.tlp NOT NULL,
    compartments text[] DEFAULT '{}'::text[] NOT NULL,
    created_by uuid,
    created_via text DEFAULT 'console'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT yara_ruleset_created_via_check CHECK ((created_via = ANY (ARRAY['console'::text, 'yara_db.py'::text]))),
    CONSTRAINT yara_ruleset_creator_named CHECK (((created_via = 'console'::text) = (created_by IS NOT NULL))),
    CONSTRAINT yara_ruleset_display_name_check CHECK ((length(btrim(display_name)) > 0)),
    CONSTRAINT yara_ruleset_key_check CHECK ((key ~ '^[a-z0-9][a-z0-9-]{1,62}$'::text))
);

--
-- Name: TABLE yara_ruleset; Type: COMMENT; Schema: lab; Owner: -
--

COMMENT ON TABLE lab.yara_ruleset IS 'A labelled YARA rule set (F12). Never deleted; labels only rise; compartments change only by the registry''s rename.';

--
-- Name: yara_ruleset_version; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.yara_ruleset_version (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ruleset_id uuid NOT NULL,
    version integer NOT NULL,
    source_sha256 bytea NOT NULL,
    source_gz bytea NOT NULL,
    source_bytes bigint NOT NULL,
    files jsonb NOT NULL,
    file_count integer NOT NULL,
    licence text NOT NULL,
    licence_review_required boolean NOT NULL,
    provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    note text,
    uploaded_by uuid,
    uploaded_at timestamp with time zone DEFAULT now() NOT NULL,
    adopted_by uuid,
    adopted_at timestamp with time zone,
    CONSTRAINT yara_ruleset_version_file_count_check CHECK ((file_count >= 0)),
    CONSTRAINT yara_ruleset_version_licence_check CHECK ((length(btrim(licence)) > 0)),
    CONSTRAINT yara_ruleset_version_source_bytes_check CHECK ((source_bytes > 0)),
    CONSTRAINT yara_ruleset_version_source_sha256_check CHECK ((octet_length(source_sha256) = 32)),
    CONSTRAINT yara_ruleset_version_version_check CHECK ((version >= 1)),
    CONSTRAINT yara_version_adopted_only_when_imported CHECK (((adopted_by IS NULL) OR (uploaded_by IS NULL))),
    CONSTRAINT yara_version_adoption_complete CHECK (((adopted_by IS NULL) = (adopted_at IS NULL))),
    CONSTRAINT yara_version_files_is_a_list CHECK ((jsonb_typeof(files) = 'array'::text)),
    CONSTRAINT yara_version_uploader_or_script CHECK (((uploaded_by IS NOT NULL) OR ((provenance ->> 'via'::text) = 'yara_db.py'::text)))
);

--
-- Name: case_route_block; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.case_route_block (
    case_id uuid NOT NULL,
    channel text NOT NULL,
    reason text NOT NULL,
    blocked_by uuid NOT NULL,
    blocked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT case_route_block_channel_known CHECK ((channel = 'JIRA'::text)),
    CONSTRAINT case_route_block_reason_present CHECK (((length(btrim(reason)) >= 5) AND (length(btrim(reason)) <= 500)))
);

--
-- Name: TABLE case_route_block; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON TABLE notify.case_route_block IS 'A case owner keeps this case out of Jira. The history is in audit.event (NOTIFY_CASE_ROUTING_CHANGED); lifting the veto deletes the row.';

--
-- Name: delivery; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.delivery (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    notification_id uuid NOT NULL,
    channel text NOT NULL,
    state text NOT NULL,
    deliver_after timestamp with time zone DEFAULT now() NOT NULL,
    attempts smallint DEFAULT 0 NOT NULL,
    last_attempt_at timestamp with time zone,
    sent_at timestamp with time zone,
    detail text,
    redacted boolean DEFAULT false NOT NULL,
    sent_to text,
    cause text,
    exposure text,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    jira_link_id uuid,
    CONSTRAINT delivery_cause_known CHECK (((cause IS NULL) OR (cause = ANY (ARRAY['RECIPIENT_DISABLED'::text, 'BELOW_THRESHOLD'::text, 'CASELESS'::text, 'DESTINATION_OFF'::text, 'KIND_NOT_ROUTED'::text, 'CASE_NOT_ROUTED'::text, 'WITHDRAWN'::text, 'REVOKED'::text, 'EGRESS_REFUSED'::text, 'TRANSPORT_ERROR'::text, 'RATE_LIMITED'::text, 'GAVE_UP'::text, 'REQUEUED'::text, 'ALREADY_ON_ISSUE'::text, 'LEGACY'::text])))),
    CONSTRAINT delivery_channel_known CHECK ((channel = ANY (ARRAY['IN_APP'::text, 'SMTP'::text, 'WEBHOOK'::text, 'JIRA'::text]))),
    CONSTRAINT delivery_decided_has_cause CHECK (((state <> ALL (ARRAY['SUPPRESSED'::text, 'REFUSED'::text, 'FAILED'::text])) OR (cause IS NOT NULL))),
    CONSTRAINT delivery_exposure_known CHECK (((exposure IS NULL) OR (exposure = ANY (ARRAY['STUB'::text, 'SUBJECT'::text, 'SUMMARY'::text])))),
    CONSTRAINT delivery_in_app_never_leaves CHECK (((channel <> 'IN_APP'::text) OR (exposure IS NULL))),
    CONSTRAINT delivery_link_is_jira CHECK (((jira_link_id IS NULL) OR (channel = 'JIRA'::text))),
    CONSTRAINT delivery_on_issue_is_jira CHECK (((cause IS DISTINCT FROM 'ALREADY_ON_ISSUE'::text) OR ((channel = 'JIRA'::text) AND (state = 'SENT'::text)))),
    CONSTRAINT delivery_sent_has_timestamp CHECK (((state = 'SENT'::text) = (sent_at IS NOT NULL))),
    CONSTRAINT delivery_state_known CHECK ((state = ANY (ARRAY['PENDING'::text, 'SENT'::text, 'FAILED'::text, 'REFUSED'::text, 'SUPPRESSED'::text])))
);

--
-- Name: COLUMN delivery.sent_to; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.delivery.sent_to IS 'Where the delivery actually went, resolved at drain time (0044). Never backfilled. A webhook address keeps its scheme and host; its path and query are withheld behind a fingerprint because they commonly carry a bearer secret (0096 rewrote the stored ones: withheld, not invented).';

--
-- Name: COLUMN delivery.cause; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.delivery.cause IS 'Why the row is in its state: one stable code (transports.CAUSES). Code matches on this, never on detail, which is the human sentence.';

--
-- Name: COLUMN delivery.exposure; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.delivery.exposure IS 'What left the building on this channel: STUB, SUBJECT or SUMMARY. NULL while nothing left, and always NULL on IN_APP. Backfilled from the code that ran (render_email and webhook_payload only ever sent those).';

--
-- Name: COLUMN delivery.queued_at; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.delivery.queued_at IS 'When the delivery was queued: the notification''s time for rows written before 0095.';

--
-- Name: jira_destination; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.jira_destination (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    label text NOT NULL,
    base_url text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    flavour text DEFAULT 'AUTO'::text NOT NULL,
    auth_kind text NOT NULL,
    auth_user text,
    credential_ciphertext bytea NOT NULL,
    credential_key_id text,
    credential_set_at timestamp with time zone DEFAULT now() NOT NULL,
    credential_set_by uuid NOT NULL,
    project_key text NOT NULL,
    issue_type text DEFAULT 'Task'::text NOT NULL,
    issue_type_id text,
    ceiling core.tlp DEFAULT 'GREEN'::core.tlp NOT NULL,
    field_exposure text DEFAULT 'SUBJECT'::text NOT NULL,
    kinds text[] DEFAULT '{APPROVAL_REQUESTED,APPROVAL_DECIDED,PROPOSAL_QUEUED,CASE_REVIEW_DUE}'::text[] NOT NULL,
    state text DEFAULT 'DRAFT'::text NOT NULL,
    health text DEFAULT 'UNTESTED'::text NOT NULL,
    health_detail text,
    health_changed_at timestamp with time zone,
    tested_at timestamp with time zone,
    server_version text,
    deployment_type text,
    edit_caveat text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    CONSTRAINT jira_destination_auth_known CHECK ((auth_kind = ANY (ARRAY['CLOUD_API_TOKEN'::text, 'DC_PAT'::text, 'DC_BASIC'::text]))),
    CONSTRAINT jira_destination_auth_matches CHECK ((((flavour <> 'CLOUD'::text) OR (auth_kind = 'CLOUD_API_TOKEN'::text)) AND ((flavour <> 'DATA_CENTER'::text) OR (auth_kind = ANY (ARRAY['DC_PAT'::text, 'DC_BASIC'::text]))))),
    CONSTRAINT jira_destination_auth_user CHECK (((auth_kind = 'DC_PAT'::text) = (auth_user IS NULL))),
    CONSTRAINT jira_destination_below_floor CHECK ((ceiling = ANY (ARRAY['CLEAR'::core.tlp, 'GREEN'::core.tlp, 'AMBER'::core.tlp]))),
    CONSTRAINT jira_destination_exposure_known CHECK ((field_exposure = ANY (ARRAY['STUB'::text, 'SUBJECT'::text, 'SUMMARY'::text]))),
    CONSTRAINT jira_destination_flavour_known CHECK ((flavour = ANY (ARRAY['AUTO'::text, 'CLOUD'::text, 'DATA_CENTER'::text]))),
    CONSTRAINT jira_destination_health_known CHECK ((health = ANY (ARRAY['UNTESTED'::text, 'OK'::text, 'FAILING'::text, 'BROKEN'::text]))),
    CONSTRAINT jira_destination_host_shape CHECK (((host = lower(host)) AND (host ~ '^[a-z0-9.:\[\]-]{1,253}$'::text))),
    CONSTRAINT jira_destination_issue_type_id CHECK (((issue_type_id IS NULL) OR (issue_type_id ~ '^[0-9]{1,18}$'::text))),
    CONSTRAINT jira_destination_kinds_present CHECK ((COALESCE(array_length(kinds, 1), 0) >= 1)),
    CONSTRAINT jira_destination_label_present CHECK (((length(btrim(label)) >= 1) AND (length(btrim(label)) <= 80))),
    CONSTRAINT jira_destination_live_is_resolved CHECK (((state <> ALL (ARRAY['ACTIVE'::text, 'PAUSED'::text])) OR ((flavour <> 'AUTO'::text) AND (issue_type_id IS NOT NULL) AND (activated_at IS NOT NULL) AND (tested_at IS NOT NULL)))),
    CONSTRAINT jira_destination_port_range CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT jira_destination_project_key CHECK ((project_key ~ '^[A-Z][A-Z0-9_]{1,19}$'::text)),
    CONSTRAINT jira_destination_retired_is_shredded CHECK (((state <> 'RETIRED'::text) OR ((octet_length(credential_ciphertext) = 0) AND (credential_key_id IS NULL) AND (retired_at IS NOT NULL)))),
    CONSTRAINT jira_destination_state_known CHECK ((state = ANY (ARRAY['DRAFT'::text, 'ACTIVE'::text, 'PAUSED'::text, 'RETIRED'::text]))),
    CONSTRAINT jira_destination_url_shape CHECK (((base_url ~ '^https?://[^/?#@]+(/[^?#]*)?$'::text) AND ("right"(base_url, 1) <> '/'::text)))
);

--
-- Name: TABLE jira_destination; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON TABLE notify.jira_destination IS 'The one operator-declared Jira destination (F7). The credential is envelope-sealed and zero bytes after retire; reach is decided by the egress route "jira", never by this row.';

--
-- Name: jira_event; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.jira_event (
    link_id uuid NOT NULL,
    event_id uuid NOT NULL,
    marker text NOT NULL,
    state text NOT NULL,
    classification core.tlp NOT NULL,
    attempted_at timestamp with time zone NOT NULL,
    posted_at timestamp with time zone,
    posted_as text,
    comment_id text,
    CONSTRAINT jira_event_comment_shape CHECK (((comment_id IS NULL) OR ((posted_as = 'COMMENT'::text) AND (comment_id ~ '^[0-9]{1,18}$'::text)))),
    CONSTRAINT jira_event_marker_shape CHECK ((marker ~ '^[0-9a-f]{12}$'::text)),
    CONSTRAINT jira_event_posted_as_known CHECK (((posted_as IS NULL) OR (posted_as = ANY (ARRAY['CREATE'::text, 'COMMENT'::text])))),
    CONSTRAINT jira_event_posted_is_complete CHECK (((state = 'POSTED'::text) = ((posted_at IS NOT NULL) AND (posted_as IS NOT NULL)))),
    CONSTRAINT jira_event_state_known CHECK ((state = ANY (ARRAY['POSTING'::text, 'POSTED'::text])))
);

--
-- Name: TABLE jira_event; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON TABLE notify.jira_event IS 'Whether one event is already on its issue: what makes one event one post.';

--
-- Name: jira_link; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.jira_link (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    destination_id uuid NOT NULL,
    case_id uuid NOT NULL,
    work_key uuid NOT NULL,
    ref text NOT NULL,
    base_url text NOT NULL,
    project_key text NOT NULL,
    state text DEFAULT 'CREATING'::text NOT NULL,
    issue_key text,
    issue_id text,
    classification core.tlp NOT NULL,
    exposure text NOT NULL,
    create_attempted_at timestamp with time zone,
    creator_event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    linked_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    closed_at timestamp with time zone,
    closed_reason text,
    CONSTRAINT jira_link_closed_has_time CHECK (((state = 'CLOSED'::text) = (closed_at IS NOT NULL))),
    CONSTRAINT jira_link_closed_reason_known CHECK (((closed_reason IS NULL) OR (closed_reason = ANY (ARRAY['done in Jira'::text, 'deleted in Jira'::text, 'destination retired'::text, 'destination moved'::text, 'case kept out'::text])))),
    CONSTRAINT jira_link_create_recorded CHECK (((create_attempted_at IS NULL) = (creator_event_id IS NULL))),
    CONSTRAINT jira_link_exposure_known CHECK ((exposure = ANY (ARRAY['STUB'::text, 'SUBJECT'::text, 'SUMMARY'::text]))),
    CONSTRAINT jira_link_id_shape CHECK (((issue_id IS NULL) OR (issue_id ~ '^[0-9]{1,18}$'::text))),
    CONSTRAINT jira_link_key_shape CHECK (((issue_key IS NULL) OR (issue_key ~ '^[A-Z][A-Z0-9_]{1,19}-[1-9][0-9]{0,9}$'::text))),
    CONSTRAINT jira_link_linked_has_key CHECK (((state <> 'LINKED'::text) OR ((issue_key IS NOT NULL) AND (linked_at IS NOT NULL)))),
    CONSTRAINT jira_link_linked_was_created CHECK (((state <> 'LINKED'::text) OR (create_attempted_at IS NOT NULL))),
    CONSTRAINT jira_link_ref_shape CHECK ((ref ~ '^[a-z2-7]{16}$'::text)),
    CONSTRAINT jira_link_state_known CHECK ((state = ANY (ARRAY['CREATING'::text, 'LINKED'::text, 'CLOSED'::text])))
);

--
-- Name: TABLE jira_link; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON TABLE notify.jira_link IS 'One Jira issue per work item. case_id exists so the issues raised about a purged case can be found, and is never shown without being asked for. Closed, never deleted.';

--
-- Name: notification; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.notification (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    recipient_id uuid NOT NULL,
    case_id uuid,
    kind text NOT NULL,
    priority smallint DEFAULT 2 NOT NULL,
    subject text NOT NULL,
    summary text NOT NULL,
    body text NOT NULL,
    classification core.tlp NOT NULL,
    compartments text[] NOT NULL,
    object_type text,
    object_id uuid,
    actor_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    read_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    event_id uuid DEFAULT gen_random_uuid(),
    CONSTRAINT notification_ack_implies_read CHECK (((acknowledged_at IS NULL) OR (read_at IS NOT NULL))),
    CONSTRAINT notification_priority_range CHECK (((priority >= 1) AND (priority <= 3))),
    CONSTRAINT notification_subject_present CHECK ((length(btrim(subject)) > 0))
);

--
-- Name: COLUMN notification.event_id; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.notification.event_id IS 'Shared by every row one event fanned out to. NULL before 0095, where readers take the row''s own id.';

--
-- Name: preference; Type: TABLE; Schema: notify; Owner: -
--

CREATE TABLE notify.preference (
    user_id uuid NOT NULL,
    channel text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    min_priority smallint DEFAULT 3 NOT NULL,
    digest boolean DEFAULT false NOT NULL,
    quiet_from time without time zone,
    quiet_to time without time zone,
    timezone text DEFAULT 'UTC'::text NOT NULL,
    address text,
    CONSTRAINT preference_channel_known CHECK ((channel = ANY (ARRAY['IN_APP'::text, 'SMTP'::text, 'WEBHOOK'::text, 'JIRA'::text]))),
    CONSTRAINT preference_priority_range CHECK (((min_priority >= 1) AND (min_priority <= 3))),
    CONSTRAINT preference_quiet_window_complete CHECK (((quiet_from IS NULL) = (quiet_to IS NULL)))
);

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);

--
-- Name: event seq; Type: DEFAULT; Schema: audit; Owner: -
--

ALTER TABLE ONLY audit.event ALTER COLUMN seq SET DEFAULT nextval('audit.event_seq_seq'::regclass);

--
-- Name: egress_binding seq; Type: DEFAULT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_binding ALTER COLUMN seq SET DEFAULT nextval('collect.egress_binding_seq_seq'::regclass);

--
-- Name: evidence_custody id; Type: DEFAULT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_custody ALTER COLUMN id SET DEFAULT nextval('core.evidence_custody_id_seq'::regclass);

--
-- Name: sample_access id; Type: DEFAULT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_access ALTER COLUMN id SET DEFAULT nextval('lab.sample_access_id_seq'::regclass);

--
-- Name: community_assignment community_assignment_pkey; Type: CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.community_assignment
    ADD CONSTRAINT community_assignment_pkey PRIMARY KEY (metric_run_id, node_id);

--
-- Name: layout_position layout_position_pkey; Type: CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.layout_position
    ADD CONSTRAINT layout_position_pkey PRIMARY KEY (projection_id, node_id);

--
-- Name: metric_run metric_run_pkey; Type: CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.metric_run
    ADD CONSTRAINT metric_run_pkey PRIMARY KEY (id);

--
-- Name: node_metric node_metric_pkey; Type: CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.node_metric
    ADD CONSTRAINT node_metric_pkey PRIMARY KEY (metric_run_id, node_id, metric);

--
-- Name: projection projection_pkey; Type: CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.projection
    ADD CONSTRAINT projection_pkey PRIMARY KEY (id);

--
-- Name: event event_pkey; Type: CONSTRAINT; Schema: audit; Owner: -
--

ALTER TABLE ONLY audit.event
    ADD CONSTRAINT event_pkey PRIMARY KEY (seq);

--
-- Name: collection_account collection_account_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_account
    ADD CONSTRAINT collection_account_pkey PRIMARY KEY (id);

--
-- Name: collection_authority collection_authority_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority
    ADD CONSTRAINT collection_authority_pkey PRIMARY KEY (id);

--
-- Name: collection_authority_target collection_authority_target_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_pkey PRIMARY KEY (id);

--
-- Name: collection_run collection_run_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_pkey PRIMARY KEY (id);

--
-- Name: document_embedding document_embedding_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document_embedding
    ADD CONSTRAINT document_embedding_pkey PRIMARY KEY (document_id, slot);

--
-- Name: document document_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_pkey PRIMARY KEY (id);

--
-- Name: document document_source_id_external_id_version_key; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_source_id_external_id_version_key UNIQUE (source_id, external_id, version);

--
-- Name: egress_binding egress_binding_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_binding
    ADD CONSTRAINT egress_binding_pkey PRIMARY KEY (seq);

--
-- Name: egress_connection egress_connection_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_connection
    ADD CONSTRAINT egress_connection_pkey PRIMARY KEY (seq);

--
-- Name: egress_destination egress_destination_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_destination
    ADD CONSTRAINT egress_destination_pkey PRIMARY KEY (id);

--
-- Name: egress_integration_route egress_integration_route_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_integration_route
    ADD CONSTRAINT egress_integration_route_pkey PRIMARY KEY (id);

--
-- Name: egress_profile egress_profile_name_key; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_name_key UNIQUE (name);

--
-- Name: egress_profile egress_profile_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_pkey PRIMARY KEY (id);

--
-- Name: extraction extraction_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.extraction
    ADD CONSTRAINT extraction_pkey PRIMARY KEY (id);

--
-- Name: forum_member forum_member_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.forum_member
    ADD CONSTRAINT forum_member_pkey PRIMARY KEY (document_id);

--
-- Name: forum_post forum_post_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.forum_post
    ADD CONSTRAINT forum_post_pkey PRIMARY KEY (document_id);

--
-- Name: proposal proposal_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_pkey PRIMARY KEY (id);

--
-- Name: source source_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.source
    ADD CONSTRAINT source_pkey PRIMARY KEY (id);

--
-- Name: telegram_chat telegram_chat_one_source; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_one_source UNIQUE (durable_id);

--
-- Name: telegram_chat telegram_chat_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_pkey PRIMARY KEY (source_id);

--
-- Name: telegram_message telegram_message_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_message
    ADD CONSTRAINT telegram_message_pkey PRIMARY KEY (document_id);

--
-- Name: watch_hit watch_hit_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch_hit
    ADD CONSTRAINT watch_hit_pkey PRIMARY KEY (id);

--
-- Name: watch_hit watch_hit_watch_id_document_id_key; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch_hit
    ADD CONSTRAINT watch_hit_watch_id_document_id_key UNIQUE (watch_id, document_id);

--
-- Name: watch watch_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch
    ADD CONSTRAINT watch_pkey PRIMARY KEY (id);

--
-- Name: channel_binding channel_binding_id_case_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_id_case_key UNIQUE (id, case_id);

--
-- Name: channel_binding channel_binding_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_pkey PRIMARY KEY (id);

--
-- Name: contact_block contact_block_case_id_raw_sha256_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_case_id_raw_sha256_key UNIQUE (case_id, raw_sha256);

--
-- Name: contact_block_entry contact_block_entry_block_id_line_no_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_block_id_line_no_key UNIQUE (block_id, line_no);

--
-- Name: contact_block_entry contact_block_entry_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_pkey PRIMARY KEY (id);

--
-- Name: contact_block contact_block_id_case_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_id_case_key UNIQUE (id, case_id);

--
-- Name: contact_block contact_block_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_pkey PRIMARY KEY (id);

--
-- Name: conversation conversation_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.conversation
    ADD CONSTRAINT conversation_pkey PRIMARY KEY (id);

--
-- Name: device_fingerprint device_fingerprint_case_id_platform_key_fingerprint_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.device_fingerprint
    ADD CONSTRAINT device_fingerprint_case_id_platform_key_fingerprint_key UNIQUE (case_id, platform_key, fingerprint);

--
-- Name: device_fingerprint device_fingerprint_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.device_fingerprint
    ADD CONSTRAINT device_fingerprint_pkey PRIMARY KEY (id);

--
-- Name: message message_conversation_id_content_sha256_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.message
    ADD CONSTRAINT message_conversation_id_content_sha256_key UNIQUE (conversation_id, content_sha256);

--
-- Name: message message_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.message
    ADD CONSTRAINT message_pkey PRIMARY KEY (id);

--
-- Name: participant participant_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.participant
    ADD CONSTRAINT participant_pkey PRIMARY KEY (conversation_id, observed_handle);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_id_case_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_id_case_key UNIQUE (id, case_id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_pkey PRIMARY KEY (id);

--
-- Name: pgp_key pgp_key_id_case_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_id_case_key UNIQUE (id, case_id);

--
-- Name: pgp_key_lookup pgp_key_lookup_id_case_key; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_id_case_key UNIQUE (id, case_id);

--
-- Name: pgp_key_lookup pgp_key_lookup_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_pkey PRIMARY KEY (id);

--
-- Name: pgp_key pgp_key_once_per_acquisition; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_once_per_acquisition UNIQUE (acquisition_id, primary_fingerprint);

--
-- Name: pgp_key pgp_key_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_pkey PRIMARY KEY (id);

--
-- Name: pgp_verification pgp_verification_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_pkey PRIMARY KEY (id);

--
-- Name: platform platform_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.platform
    ADD CONSTRAINT platform_pkey PRIMARY KEY (key);

--
-- Name: service_selector service_selector_pkey; Type: CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.service_selector
    ADD CONSTRAINT service_selector_pkey PRIMARY KEY (id);

--
-- Name: approval_request approval_request_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.approval_request
    ADD CONSTRAINT approval_request_pkey PRIMARY KEY (id);

--
-- Name: assertion_embedding assertion_embedding_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion_embedding
    ADD CONSTRAINT assertion_embedding_pkey PRIMARY KEY (assertion_id, slot);

--
-- Name: assertion assertion_lookup_is_inference; Type: CHECK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE core.assertion
    ADD CONSTRAINT assertion_lookup_is_inference CHECK (((lookup_result_id IS NULL) OR (basis = 'AUTOMATED_INFERENCE'::core.assertion_basis))) NOT VALID;

--
-- Name: assertion assertion_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_pkey PRIMARY KEY (id);

--
-- Name: assumption assumption_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assumption
    ADD CONSTRAINT assumption_pkey PRIMARY KEY (id);

--
-- Name: case case_code_key; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core."case"
    ADD CONSTRAINT case_code_key UNIQUE (code);

--
-- Name: case case_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core."case"
    ADD CONSTRAINT case_pkey PRIMARY KEY (id);

--
-- Name: edge edge_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_pkey PRIMARY KEY (id);

--
-- Name: edge_type edge_type_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge_type
    ADD CONSTRAINT edge_type_pkey PRIMARY KEY (key);

--
-- Name: embedding_pending embedding_pending_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_pending
    ADD CONSTRAINT embedding_pending_pkey PRIMARY KEY (slot, kind, item_id);

--
-- Name: embedding_space embedding_space_id_slot_key; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_space
    ADD CONSTRAINT embedding_space_id_slot_key UNIQUE (id, slot);

--
-- Name: embedding_space embedding_space_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_space
    ADD CONSTRAINT embedding_space_pkey PRIMARY KEY (id);

--
-- Name: evidence evidence_case_id_sha256_key; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_case_id_sha256_key UNIQUE (case_id, sha256);

--
-- Name: evidence_custody evidence_custody_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_custody
    ADD CONSTRAINT evidence_custody_pkey PRIMARY KEY (id);

--
-- Name: evidence_embedding evidence_embedding_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_embedding
    ADD CONSTRAINT evidence_embedding_pkey PRIMARY KEY (evidence_id, slot);

--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);

--
-- Name: hypothesis_evidence hypothesis_evidence_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.hypothesis_evidence
    ADD CONSTRAINT hypothesis_evidence_pkey PRIMARY KEY (hypothesis_id, assertion_id);

--
-- Name: hypothesis hypothesis_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.hypothesis
    ADD CONSTRAINT hypothesis_pkey PRIMARY KEY (id);

--
-- Name: node_merge_edge node_merge_edge_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge_edge
    ADD CONSTRAINT node_merge_edge_pkey PRIMARY KEY (merge_id, edge_id);

--
-- Name: node_merge node_merge_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge
    ADD CONSTRAINT node_merge_pkey PRIMARY KEY (id);

--
-- Name: node node_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node
    ADD CONSTRAINT node_pkey PRIMARY KEY (id);

--
-- Name: node_set_member node_set_member_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_set_member
    ADD CONSTRAINT node_set_member_pkey PRIMARY KEY (set_id, node_id);

--
-- Name: node_set node_set_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_set
    ADD CONSTRAINT node_set_pkey PRIMARY KEY (id);

--
-- Name: node_type node_type_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_type
    ADD CONSTRAINT node_type_pkey PRIMARY KEY (key);

--
-- Name: purge_tombstone purge_tombstone_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.purge_tombstone
    ADD CONSTRAINT purge_tombstone_pkey PRIMARY KEY (id);

--
-- Name: retention_rule retention_rule_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.retention_rule
    ADD CONSTRAINT retention_rule_pkey PRIMARY KEY (category);

--
-- Name: selector selector_case_id_selector_type_norm_value_key; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector
    ADD CONSTRAINT selector_case_id_selector_type_norm_value_key UNIQUE (case_id, selector_type, norm_value);

--
-- Name: selector selector_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector
    ADD CONSTRAINT selector_pkey PRIMARY KEY (id);

--
-- Name: selector_type selector_type_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector_type
    ADD CONSTRAINT selector_type_pkey PRIMARY KEY (key);

--
-- Name: tag tag_pkey; Type: CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag
    ADD CONSTRAINT tag_pkey PRIMARY KEY (id);

--
-- Name: call_record call_record_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_pkey PRIMARY KEY (id);

--
-- Name: capture_hop capture_hop_capture_id_seq_key; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture_hop
    ADD CONSTRAINT capture_hop_capture_id_seq_key UNIQUE (capture_id, seq);

--
-- Name: capture_hop capture_hop_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture_hop
    ADD CONSTRAINT capture_hop_pkey PRIMARY KEY (id);

--
-- Name: capture capture_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_pkey PRIMARY KEY (id);

--
-- Name: email_attachment email_attachment_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_attachment
    ADD CONSTRAINT email_attachment_pkey PRIMARY KEY (id);

--
-- Name: email_hop email_hop_message_id_seq_key; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_hop
    ADD CONSTRAINT email_hop_message_id_seq_key UNIQUE (message_id, seq);

--
-- Name: email_hop email_hop_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_hop
    ADD CONSTRAINT email_hop_pkey PRIMARY KEY (id);

--
-- Name: email_message email_message_pkey; Type: CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_message
    ADD CONSTRAINT email_message_pkey PRIMARY KEY (id);

--
-- Name: app_user app_user_email_key; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.app_user
    ADD CONSTRAINT app_user_email_key UNIQUE (email);

--
-- Name: app_user app_user_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.app_user
    ADD CONSTRAINT app_user_pkey PRIMARY KEY (id);

--
-- Name: break_glass break_glass_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.break_glass
    ADD CONSTRAINT break_glass_pkey PRIMARY KEY (id);

--
-- Name: case_assignment case_assignment_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.case_assignment
    ADD CONSTRAINT case_assignment_pkey PRIMARY KEY (case_id, user_id);

--
-- Name: compartment compartment_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.compartment
    ADD CONSTRAINT compartment_pkey PRIMARY KEY (key);

--
-- Name: dual_control_operation dual_control_operation_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_operation
    ADD CONSTRAINT dual_control_operation_pkey PRIMARY KEY (operation);

--
-- Name: dual_control_policy_change dual_control_policy_change_approval_request_id_key; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_approval_request_id_key UNIQUE (approval_request_id);

--
-- Name: dual_control_policy_change dual_control_policy_change_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_pkey PRIMARY KEY (id);

--
-- Name: dual_control_policy_change dual_control_policy_change_seq_key; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_seq_key UNIQUE (seq);

--
-- Name: permission permission_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.permission
    ADD CONSTRAINT permission_pkey PRIMARY KEY (key);

--
-- Name: role_permission role_permission_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.role_permission
    ADD CONSTRAINT role_permission_pkey PRIMARY KEY (role_key, permission_key);

--
-- Name: role role_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (key);

--
-- Name: separated_duty separated_duty_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.separated_duty
    ADD CONSTRAINT separated_duty_pkey PRIMARY KEY (permission_a, permission_b);

--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (id);

--
-- Name: session session_token_hash_key; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.session
    ADD CONSTRAINT session_token_hash_key UNIQUE (token_hash);

--
-- Name: user_role user_role_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.user_role
    ADD CONSTRAINT user_role_pkey PRIMARY KEY (user_id, role_key);

--
-- Name: webauthn_credential webauthn_credential_credential_id_key; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.webauthn_credential
    ADD CONSTRAINT webauthn_credential_credential_id_key UNIQUE (credential_id);

--
-- Name: webauthn_credential webauthn_credential_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.webauthn_credential
    ADD CONSTRAINT webauthn_credential_pkey PRIMARY KEY (id);

--
-- Name: api_key api_key_key_id_key; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.api_key
    ADD CONSTRAINT api_key_key_id_key UNIQUE (key_id);

--
-- Name: api_key api_key_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.api_key
    ADD CONSTRAINT api_key_pkey PRIMARY KEY (id);

--
-- Name: batch batch_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.batch
    ADD CONSTRAINT batch_pkey PRIMARY KEY (id);

--
-- Name: category_rule category_rule_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.category_rule
    ADD CONSTRAINT category_rule_pkey PRIMARY KEY (id);

--
-- Name: dead_letter dead_letter_new_rows_are_redacted; Type: CHECK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ingest.dead_letter
    ADD CONSTRAINT dead_letter_new_rows_are_redacted CHECK (redacted) NOT VALID;

--
-- Name: dead_letter dead_letter_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.dead_letter
    ADD CONSTRAINT dead_letter_pkey PRIMARY KEY (id);

--
-- Name: lookup_attempt lookup_attempt_lookup_id_attempt_key; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_attempt
    ADD CONSTRAINT lookup_attempt_lookup_id_attempt_key UNIQUE (lookup_id, attempt);

--
-- Name: lookup_attempt lookup_attempt_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_attempt
    ADD CONSTRAINT lookup_attempt_pkey PRIMARY KEY (id);

--
-- Name: lookup_batch lookup_batch_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_batch
    ADD CONSTRAINT lookup_batch_pkey PRIMARY KEY (id);

--
-- Name: lookup lookup_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_pkey PRIMARY KEY (id);

--
-- Name: lookup_result lookup_result_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_pkey PRIMARY KEY (id);

--
-- Name: pii_authorisation pii_authorisation_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.pii_authorisation
    ADD CONSTRAINT pii_authorisation_pkey PRIMARY KEY (id);

--
-- Name: provider_exposure_change provider_exposure_change_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider_exposure_change
    ADD CONSTRAINT provider_exposure_change_pkey PRIMARY KEY (id);

--
-- Name: provider provider_key_key; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_key_key UNIQUE (key);

--
-- Name: provider provider_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_pkey PRIMARY KEY (id);

--
-- Name: provider provider_source_id_key; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_source_id_key UNIQUE (source_id);

--
-- Name: record record_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.record
    ADD CONSTRAINT record_pkey PRIMARY KEY (id);

--
-- Name: victim_credential victim_credential_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.victim_credential
    ADD CONSTRAINT victim_credential_pkey PRIMARY KEY (id);

--
-- Name: detonation detonation_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_pkey PRIMARY KEY (id);

--
-- Name: download_ticket download_ticket_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.download_ticket
    ADD CONSTRAINT download_ticket_pkey PRIMARY KEY (id);

--
-- Name: download_ticket download_ticket_token_hash_key; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.download_ticket
    ADD CONSTRAINT download_ticket_token_hash_key UNIQUE (token_hash);

--
-- Name: preservation_authorisation preservation_authorisation_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.preservation_authorisation
    ADD CONSTRAINT preservation_authorisation_pkey PRIMARY KEY (id);

--
-- Name: sample_access sample_access_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_access
    ADD CONSTRAINT sample_access_pkey PRIMARY KEY (id);

--
-- Name: sample_analysis sample_analysis_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_pkey PRIMARY KEY (id);

--
-- Name: sample sample_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_pkey PRIMARY KEY (id);

--
-- Name: sample sample_sha256_key; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_sha256_key UNIQUE (sha256);

--
-- Name: screening_hash screening_hash_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_hash
    ADD CONSTRAINT screening_hash_pkey PRIMARY KEY (algorithm, digest, list_id);

--
-- Name: screening_list screening_list_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_list
    ADD CONSTRAINT screening_list_pkey PRIMARY KEY (id);

--
-- Name: screening_list screening_list_seq_key; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_list
    ADD CONSTRAINT screening_list_seq_key UNIQUE (seq);

--
-- Name: screening_result screening_result_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_result
    ADD CONSTRAINT screening_result_pkey PRIMARY KEY (id);

--
-- Name: screening_review screening_review_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_review
    ADD CONSTRAINT screening_review_pkey PRIMARY KEY (id);

--
-- Name: static_run static_run_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.static_run
    ADD CONSTRAINT static_run_pkey PRIMARY KEY (id);

--
-- Name: yara_activation yara_activation_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_activation
    ADD CONSTRAINT yara_activation_pkey PRIMARY KEY (id);

--
-- Name: yara_compile_job yara_compile_job_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compile_job
    ADD CONSTRAINT yara_compile_job_pkey PRIMARY KEY (version_id, engine, platform, fingerprint);

--
-- Name: yara_compiled yara_compiled_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compiled
    ADD CONSTRAINT yara_compiled_pkey PRIMARY KEY (id);

--
-- Name: yara_compiled_rejected yara_compiled_rejected_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compiled_rejected
    ADD CONSTRAINT yara_compiled_rejected_pkey PRIMARY KEY (compiled_id);

--
-- Name: yara_ruleset yara_ruleset_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset
    ADD CONSTRAINT yara_ruleset_pkey PRIMARY KEY (id);

--
-- Name: yara_ruleset_version yara_ruleset_version_pkey; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_pkey PRIMARY KEY (id);

--
-- Name: yara_ruleset_version yara_ruleset_version_ruleset_id_source_sha256_key; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_ruleset_id_source_sha256_key UNIQUE (ruleset_id, source_sha256);

--
-- Name: yara_ruleset_version yara_ruleset_version_ruleset_id_version_key; Type: CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_ruleset_id_version_key UNIQUE (ruleset_id, version);

--
-- Name: case_route_block case_route_block_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.case_route_block
    ADD CONSTRAINT case_route_block_pkey PRIMARY KEY (case_id, channel);

--
-- Name: delivery delivery_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.delivery
    ADD CONSTRAINT delivery_pkey PRIMARY KEY (id);

--
-- Name: jira_destination jira_destination_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_destination
    ADD CONSTRAINT jira_destination_pkey PRIMARY KEY (id);

--
-- Name: jira_event jira_event_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_event
    ADD CONSTRAINT jira_event_pkey PRIMARY KEY (link_id, event_id);

--
-- Name: jira_link jira_link_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_link
    ADD CONSTRAINT jira_link_pkey PRIMARY KEY (id);

--
-- Name: jira_link jira_link_ref_key; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_link
    ADD CONSTRAINT jira_link_ref_key UNIQUE (ref);

--
-- Name: notification notification_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.notification
    ADD CONSTRAINT notification_pkey PRIMARY KEY (id);

--
-- Name: preference preference_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.preference
    ADD CONSTRAINT preference_pkey PRIMARY KEY (user_id, channel);

--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);

--
-- Name: metric_run_cache_idx; Type: INDEX; Schema: analytics; Owner: -
--

CREATE INDEX metric_run_cache_idx ON analytics.metric_run USING btree (projection_id, algorithm, graph_hash, visibility_clearance, started_at DESC) WHERE (status = 'COMPLETE'::text);

--
-- Name: node_metric_node_id_metric_idx; Type: INDEX; Schema: analytics; Owner: -
--

CREATE INDEX node_metric_node_id_metric_idx ON analytics.node_metric USING btree (node_id, metric);

--
-- Name: projection_case_name_uk; Type: INDEX; Schema: analytics; Owner: -
--

CREATE UNIQUE INDEX projection_case_name_uk ON analytics.projection USING btree (case_id, name);

--
-- Name: event_actor_id_occurred_at_idx; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX event_actor_id_occurred_at_idx ON audit.event USING btree (actor_id, occurred_at DESC);

--
-- Name: event_case_id_occurred_at_idx; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX event_case_id_occurred_at_idx ON audit.event USING btree (case_id, occurred_at DESC);

--
-- Name: event_object_id_idx; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX event_object_id_idx ON audit.event USING btree (object_id);

--
-- Name: event_occurred_at_idx; Type: INDEX; Schema: audit; Owner: -
--

CREATE INDEX event_occurred_at_idx ON audit.event USING btree (occurred_at DESC);

--
-- Name: authority_target_once; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX authority_target_once ON collect.collection_authority_target USING btree (authority_id, source_id) WHERE (revoked_at IS NULL);

--
-- Name: authority_target_source_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX authority_target_source_idx ON collect.collection_authority_target USING btree (source_id) WHERE (revoked_at IS NULL);

--
-- Name: collection_account_platform_uid_unique; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX collection_account_platform_uid_unique ON collect.collection_account USING btree (platform, platform_uid) WHERE (platform_uid IS NOT NULL);

--
-- Name: collection_account_telegram_egress_unique; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX collection_account_telegram_egress_unique ON collect.collection_account USING btree (egress_profile_id) WHERE (platform = 'TELEGRAM'::collect.source_kind);

--
-- Name: collection_authority_live_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_authority_live_idx ON collect.collection_authority USING btree (collection_account_id, valid_until) WHERE ((revoked_at IS NULL) AND (confirmed_at IS NOT NULL));

--
-- Name: collection_authority_pending_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_authority_pending_idx ON collect.collection_authority USING btree (recorded_at) WHERE ((confirmed_at IS NULL) AND (revoked_at IS NULL));

--
-- Name: collection_run_resume_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_run_resume_idx ON collect.collection_run USING btree (source_id, started_at DESC NULLS LAST, id DESC) WHERE (status <> 'RUNNING'::collect.run_status);

--
-- Name: collection_run_source_id_started_at_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_run_source_id_started_at_idx ON collect.collection_run USING btree (source_id, started_at DESC);

--
-- Name: collection_run_started_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_run_started_idx ON collect.collection_run USING btree (started_at DESC NULLS LAST, id DESC);

--
-- Name: collection_run_status_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_run_status_idx ON collect.collection_run USING btree (status) WHERE (status = ANY (ARRAY['QUEUED'::collect.run_status, 'RUNNING'::collect.run_status]));

--
-- Name: document_author_handle_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_author_handle_idx ON collect.document USING gin (author_handle public.gin_trgm_ops);

--
-- Name: document_category_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_category_idx ON collect.document USING btree (category);

--
-- Name: document_compartments_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_compartments_idx ON collect.document USING gin (compartments) WHERE (cardinality(compartments) > 0);

--
-- Name: document_content_sha256_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_content_sha256_idx ON collect.document USING btree (content_sha256);

--
-- Name: document_embedding_compartmented; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_compartmented ON collect.document_embedding USING gin (read_compartments) WHERE (read_compartments <> '{}'::text[]);

--
-- Name: document_embedding_due; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_due ON collect.document_embedding USING btree (slot, next_attempt_at) WHERE (status = ANY (ARRAY['FAILED'::text, 'WITHHELD'::text]));

--
-- Name: document_embedding_s1_amber_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s1_amber_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 1) AND (read_classification = 'AMBER'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s1_amber_strict_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s1_amber_strict_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 1) AND (read_classification = 'AMBER_STRICT'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s1_clear_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s1_clear_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 1) AND (read_classification = 'CLEAR'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s1_green_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s1_green_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 1) AND (read_classification = 'GREEN'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s1_red_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s1_red_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 1) AND (read_classification = 'RED'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s2_amber_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s2_amber_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 2) AND (read_classification = 'AMBER'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s2_amber_strict_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s2_amber_strict_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 2) AND (read_classification = 'AMBER_STRICT'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s2_clear_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s2_clear_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 2) AND (read_classification = 'CLEAR'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s2_green_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s2_green_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 2) AND (read_classification = 'GREEN'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s2_red_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s2_red_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 2) AND (read_classification = 'RED'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s3_amber_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s3_amber_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 3) AND (read_classification = 'AMBER'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s3_amber_strict_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s3_amber_strict_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 3) AND (read_classification = 'AMBER_STRICT'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s3_clear_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s3_clear_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 3) AND (read_classification = 'CLEAR'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s3_green_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s3_green_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 3) AND (read_classification = 'GREEN'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_s3_red_hnsw; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_s3_red_hnsw ON collect.document_embedding USING hnsw (embedding public.vector_cosine_ops) WHERE ((slot = 3) AND (read_classification = 'RED'::core.tlp) AND (read_compartments = '{}'::text[]) AND (embedding IS NOT NULL));

--
-- Name: document_embedding_space_status; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_space_status ON collect.document_embedding USING btree (space_id, status);

--
-- Name: document_retention_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_retention_idx ON collect.document USING btree (retain_until) WHERE ((purged_at IS NULL) AND (NOT legal_hold));

--
-- Name: document_search_tsv_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_search_tsv_idx ON collect.document USING gin (search_tsv);

--
-- Name: document_source_id_posted_at_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_source_id_posted_at_idx ON collect.document USING btree (source_id, posted_at DESC);

--
-- Name: document_triage_state_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_triage_state_idx ON collect.document USING btree (triage_state) WHERE (triage_state = 'NEW'::text);

--
-- Name: egress_binding_persona_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_binding_persona_idx ON collect.egress_binding USING btree (collection_account_id, bound_at DESC) WHERE (collection_account_id IS NOT NULL);

--
-- Name: egress_binding_source_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_binding_source_idx ON collect.egress_binding USING btree (source_id, bound_at DESC) WHERE (source_id IS NOT NULL);

--
-- Name: egress_connection_connection_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_connection_idx ON collect.egress_connection USING btree (connection_id);

--
-- Name: egress_connection_preauth_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_preauth_idx ON collect.egress_connection USING btree (peer_address, occurred_at DESC) WHERE (event = 'PREAUTH'::text);

--
-- Name: egress_connection_profile_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_profile_idx ON collect.egress_connection USING btree (egress_profile_id, occurred_at DESC);

--
-- Name: egress_connection_refused_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_refused_idx ON collect.egress_connection USING btree (occurred_at DESC) WHERE (event = 'REFUSED'::text);

--
-- Name: egress_connection_route_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_route_idx ON collect.egress_connection USING btree (integration_route_id, occurred_at DESC);

--
-- Name: egress_connection_run_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_run_idx ON collect.egress_connection USING btree (collection_run_id);

--
-- Name: egress_connection_stop_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_stop_idx ON collect.egress_connection USING btree (collection_account_id, occurred_at DESC) WHERE (context_kind = 'stop'::text);

--
-- Name: egress_connection_time_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX egress_connection_time_idx ON collect.egress_connection USING btree (occurred_at DESC);

--
-- Name: egress_destination_live_entry; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX egress_destination_live_entry ON collect.egress_destination USING btree (route_id, entry) WHERE (retired_at IS NULL);

--
-- Name: egress_integration_route_live_name; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX egress_integration_route_live_name ON collect.egress_integration_route USING btree (name) WHERE (retired_at IS NULL);

--
-- Name: egress_profile_one_passive_default; Type: INDEX; Schema: collect; Owner: -
--

CREATE UNIQUE INDEX egress_profile_one_passive_default ON collect.egress_profile USING btree ((true)) WHERE is_passive_default;

--
-- Name: extraction_document_id_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX extraction_document_id_idx ON collect.extraction USING btree (document_id);

--
-- Name: extraction_norm_value_selector_type_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX extraction_norm_value_selector_type_idx ON collect.extraction USING btree (norm_value, selector_type);

--
-- Name: proposal_case_id_state_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX proposal_case_id_state_idx ON collect.proposal USING btree (case_id, state) WHERE (state = 'PROPOSED'::core.review_state);

--
-- Name: proposal_document_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX proposal_document_idx ON collect.proposal USING btree (document_id);

--
-- Name: proposal_lookup_result_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX proposal_lookup_result_idx ON collect.proposal USING btree (lookup_result_id) WHERE (lookup_result_id IS NOT NULL);

--
-- Name: source_collection_account_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX source_collection_account_idx ON collect.source USING btree (collection_account_id) WHERE (collection_account_id IS NOT NULL);

--
-- Name: source_due_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX source_due_idx ON collect.source USING btree (next_due_at) WHERE is_active;

--
-- Name: source_egress_profile_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX source_egress_profile_idx ON collect.source USING btree (egress_profile_id) WHERE (egress_profile_id IS NOT NULL);

--
-- Name: telegram_message_fwd_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX telegram_message_fwd_idx ON collect.telegram_message USING btree (fwd_from_uid) WHERE (fwd_from_uid IS NOT NULL);

--
-- Name: telegram_message_recheck_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX telegram_message_recheck_idx ON collect.telegram_message USING btree (source_id, captured_at DESC) WHERE ((deleted_seen_at IS NULL) AND (NOT is_service));

--
-- Name: telegram_message_sender_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX telegram_message_sender_idx ON collect.telegram_message USING btree (sender_uid) WHERE (sender_uid IS NOT NULL);

--
-- Name: telegram_message_source_msg_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX telegram_message_source_msg_idx ON collect.telegram_message USING btree (source_id, message_id DESC);

--
-- Name: watch_hit_created_at_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX watch_hit_created_at_idx ON collect.watch_hit USING btree (created_at DESC) WHERE ((notified_at IS NULL) AND (NOT suppressed));

--
-- Name: watch_hit_document_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX watch_hit_document_idx ON collect.watch_hit USING btree (document_id);

--
-- Name: channel_binding_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX channel_binding_case_idx ON comms.channel_binding USING btree (case_id);

--
-- Name: channel_binding_codecl_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX channel_binding_codecl_idx ON comms.channel_binding USING btree (co_declaration_ref) WHERE (co_declaration_ref IS NOT NULL);

--
-- Name: channel_binding_durable_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX channel_binding_durable_idx ON comms.channel_binding USING btree (platform_key, durable_value) WHERE (durable_value IS NOT NULL);

--
-- Name: channel_binding_identity_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX channel_binding_identity_idx ON comms.channel_binding USING btree (identity_node_id);

--
-- Name: contact_block_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_case_idx ON comms.contact_block USING btree (case_id, created_at DESC);

--
-- Name: contact_block_document_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_document_idx ON comms.contact_block USING btree (document_id);

--
-- Name: contact_block_entry_block_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_entry_block_idx ON comms.contact_block_entry USING btree (block_id, line_no);

--
-- Name: contact_block_entry_durable_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_entry_durable_idx ON comms.contact_block_entry USING btree (platform_key, durable_value) WHERE (durable_value IS NOT NULL);

--
-- Name: contact_block_entry_proposal_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_entry_proposal_idx ON comms.contact_block_entry USING btree (proposal_id) WHERE (proposal_id IS NOT NULL);

--
-- Name: contact_block_fingerprint_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_fingerprint_idx ON comms.contact_block USING btree (block_fingerprint);

--
-- Name: contact_block_publisher_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_publisher_idx ON comms.contact_block USING btree (publisher_identity_node_id) WHERE (publisher_identity_node_id IS NOT NULL);

--
-- Name: conversation_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX conversation_case_idx ON comms.conversation USING btree (case_id, last_message_at DESC);

--
-- Name: conversation_external_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE UNIQUE INDEX conversation_external_idx ON comms.conversation USING btree (case_id, platform_key, external_ref) WHERE (external_ref IS NOT NULL);

--
-- Name: device_fingerprint_value_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX device_fingerprint_value_idx ON comms.device_fingerprint USING btree (platform_key, fingerprint);

--
-- Name: message_conversation_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX message_conversation_idx ON comms.message USING btree (conversation_id, sent_at);

--
-- Name: message_sender_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX message_sender_idx ON comms.message USING btree (conversation_id, sender_handle);

--
-- Name: participant_identity_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX participant_identity_idx ON comms.participant USING btree (identity_node_id) WHERE (identity_node_id IS NOT NULL);

--
-- Name: participant_incidental_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX participant_incidental_idx ON comms.participant USING btree (conversation_id) WHERE is_incidental;

--
-- Name: pgp_key_acquisition_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_key_acquisition_case_idx ON comms.pgp_key_acquisition USING btree (case_id, requested_at DESC);

--
-- Name: pgp_key_acquisition_once; Type: INDEX; Schema: comms; Owner: -
--

CREATE UNIQUE INDEX pgp_key_acquisition_once ON comms.pgp_key_acquisition USING btree (case_id, source, raw_sha256, source_ref, classification, compartments) WHERE (source = ANY (ARRAY['PASTE'::text, 'FILE'::text]));

--
-- Name: pgp_key_acquisition_one_per_lookup; Type: INDEX; Schema: comms; Owner: -
--

CREATE UNIQUE INDEX pgp_key_acquisition_one_per_lookup ON comms.pgp_key_acquisition USING btree (lookup_id) WHERE (lookup_id IS NOT NULL);

--
-- Name: pgp_key_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_key_case_idx ON comms.pgp_key USING btree (case_id, created_at DESC);

--
-- Name: pgp_key_fingerprint_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_key_fingerprint_idx ON comms.pgp_key USING btree (primary_fingerprint);

--
-- Name: pgp_key_lookup_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_key_lookup_case_idx ON comms.pgp_key_lookup USING btree (case_id, requested_at DESC);

--
-- Name: pgp_key_lookup_waiting_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_key_lookup_waiting_idx ON comms.pgp_key_lookup USING btree (case_id) WHERE (state = 'REQUESTED'::text);

--
-- Name: pgp_verification_binding_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_verification_binding_idx ON comms.pgp_verification USING btree (channel_binding_id) WHERE (channel_binding_id IS NOT NULL);

--
-- Name: pgp_verification_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_verification_case_idx ON comms.pgp_verification USING btree (case_id, verified_at DESC);

--
-- Name: pgp_verification_claimed_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_verification_claimed_idx ON comms.pgp_verification USING btree (claimed_fingerprint);

--
-- Name: pgp_verification_key_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX pgp_verification_key_idx ON comms.pgp_verification USING btree (pgp_key_id) WHERE (pgp_key_id IS NOT NULL);

--
-- Name: service_selector_case_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE UNIQUE INDEX service_selector_case_idx ON comms.service_selector USING btree (case_id, COALESCE(platform_key, ''::text), COALESCE(selector_type, ''::text), durable_value) WHERE ((scope = 'CASE'::text) AND (retired_at IS NULL));

--
-- Name: service_selector_global_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE UNIQUE INDEX service_selector_global_idx ON comms.service_selector USING btree (COALESCE(platform_key, ''::text), COALESCE(selector_type, ''::text), durable_value) WHERE ((scope = 'GLOBAL'::text) AND (retired_at IS NULL));

--
-- Name: service_selector_lookup_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX service_selector_lookup_idx ON comms.service_selector USING btree (durable_value) WHERE (retired_at IS NULL);

--
-- Name: approval_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX approval_case_idx ON core.approval_request USING btree (case_id, state, requested_at DESC);

--
-- Name: approval_one_pending_per_payload; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX approval_one_pending_per_payload ON core.approval_request USING btree (operation, payload_hash) WHERE (state = 'PENDING'::text);

--
-- Name: approval_pending_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX approval_pending_idx ON core.approval_request USING btree (requested_at DESC) WHERE (state = 'PENDING'::text);

--
-- Name: approval_requester_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX approval_requester_idx ON core.approval_request USING btree (requested_by, requested_at DESC);

--
-- Name: assertion_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_case_idx ON core.assertion USING btree (case_id);

--
-- Name: assertion_document_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_document_id_idx ON core.assertion USING btree (document_id);

--
-- Name: assertion_edge_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_edge_id_idx ON core.assertion USING btree (edge_id) WHERE ((retracted_at IS NULL) AND (superseded_at IS NULL));

--
-- Name: assertion_embedding_case; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_embedding_case ON core.assertion_embedding USING btree (case_id, slot);

--
-- Name: assertion_embedding_due; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_embedding_due ON core.assertion_embedding USING btree (slot, next_attempt_at) WHERE (status = ANY (ARRAY['FAILED'::text, 'WITHHELD'::text]));

--
-- Name: assertion_embedding_space_status; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_embedding_space_status ON core.assertion_embedding USING btree (space_id, status);

--
-- Name: assertion_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_node_id_idx ON core.assertion USING btree (node_id) WHERE ((retracted_at IS NULL) AND (superseded_at IS NULL));

--
-- Name: assertion_source_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_source_id_idx ON core.assertion USING btree (source_id);

--
-- Name: assumption_case_status_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assumption_case_status_idx ON core.assumption USING btree (case_id, status);

--
-- Name: case_review_due_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX case_review_due_idx ON core."case" USING btree (review_due) WHERE (status = 'ACTIVE'::core.case_status);

--
-- Name: case_status_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX case_status_idx ON core."case" USING btree (status) WHERE (status = ANY (ARRAY['ACTIVE'::core.case_status, 'DORMANT'::core.case_status]));

--
-- Name: edge_case_id_edge_type_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX edge_case_id_edge_type_idx ON core.edge USING btree (case_id, edge_type) WHERE (deleted_at IS NULL);

--
-- Name: edge_dst_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX edge_dst_node_id_idx ON core.edge USING btree (dst_node_id) WHERE (deleted_at IS NULL);

--
-- Name: edge_review_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX edge_review_idx ON core.edge USING btree (review) WHERE (review = 'PROPOSED'::core.review_state);

--
-- Name: edge_src_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX edge_src_node_id_idx ON core.edge USING btree (src_node_id) WHERE (deleted_at IS NULL);

--
-- Name: edge_uniq_active; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX edge_uniq_active ON core.edge USING btree (src_node_id, dst_node_id, edge_type, COALESCE(valid_from, '-infinity'::timestamp with time zone)) WHERE (deleted_at IS NULL);

--
-- Name: embedding_space_one_active; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX embedding_space_one_active ON core.embedding_space USING btree (role) WHERE (state = 'ACTIVE'::text);

--
-- Name: embedding_space_one_building; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX embedding_space_one_building ON core.embedding_space USING btree (role) WHERE (state = 'BUILDING'::text);

--
-- Name: embedding_space_slot_held; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX embedding_space_slot_held ON core.embedding_space USING btree (slot) WHERE (rows_cleared_at IS NULL);

--
-- Name: evidence_case_id_acquired_at_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_case_id_acquired_at_idx ON core.evidence USING btree (case_id, acquired_at DESC);

--
-- Name: evidence_custody_evidence_id_occurred_at_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_custody_evidence_id_occurred_at_idx ON core.evidence_custody USING btree (evidence_id, occurred_at);

--
-- Name: evidence_embedding_case; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_embedding_case ON core.evidence_embedding USING btree (case_id, slot);

--
-- Name: evidence_embedding_due; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_embedding_due ON core.evidence_embedding USING btree (slot, next_attempt_at) WHERE (status = ANY (ARRAY['FAILED'::text, 'WITHHELD'::text]));

--
-- Name: evidence_embedding_space_status; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_embedding_space_status ON core.evidence_embedding USING btree (space_id, status);

--
-- Name: evidence_hostile_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_hostile_idx ON core.evidence USING btree (case_id) WHERE is_hostile_markup;

--
-- Name: evidence_link_edge_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_link_edge_id_idx ON core.evidence_link USING btree (edge_id);

--
-- Name: evidence_link_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_link_node_id_idx ON core.evidence_link USING btree (node_id);

--
-- Name: evidence_purgeable_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_purgeable_idx ON core.evidence USING btree (case_id) WHERE ((purged_at IS NULL) AND (NOT legal_hold));

--
-- Name: evidence_search_tsv_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_search_tsv_idx ON core.evidence USING gin (search_tsv);

--
-- Name: evidence_sha256_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_sha256_idx ON core.evidence USING btree (sha256);

--
-- Name: evidence_title_trgm_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_title_trgm_idx ON core.evidence USING gin (title public.gin_trgm_ops);

--
-- Name: hypothesis_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX hypothesis_case_idx ON core.hypothesis USING btree (case_id);

--
-- Name: node_attrs_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_attrs_idx ON core.node USING gin (attrs jsonb_path_ops);

--
-- Name: node_case_id_node_type_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_case_id_node_type_idx ON core.node USING btree (case_id, node_type) WHERE ((deleted_at IS NULL) AND (merged_into_id IS NULL));

--
-- Name: node_embedding_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_embedding_idx ON core.node USING hnsw (embedding public.vector_cosine_ops);

--
-- Name: node_label_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_label_idx ON core.node USING gin (label public.gin_trgm_ops);

--
-- Name: node_merge_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_merge_case_idx ON core.node_merge USING btree (case_id, merged_at DESC);

--
-- Name: node_merge_one_live_per_source; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX node_merge_one_live_per_source ON core.node_merge USING btree (source_node_id) WHERE (reversed_at IS NULL);

--
-- Name: node_merge_target_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_merge_target_idx ON core.node_merge USING btree (target_node_id) WHERE (reversed_at IS NULL);

--
-- Name: node_merged_into_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_merged_into_id_idx ON core.node USING btree (merged_into_id) WHERE (merged_into_id IS NOT NULL);

--
-- Name: node_search_tsv_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_search_tsv_idx ON core.node USING gin (search_tsv);

--
-- Name: node_set_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX node_set_case_idx ON core.node_set USING btree (case_id);

--
-- Name: purge_tombstone_case_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX purge_tombstone_case_idx ON core.purge_tombstone USING btree (case_id, purged_at DESC);

--
-- Name: purge_tombstone_time_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX purge_tombstone_time_idx ON core.purge_tombstone USING btree (purged_at DESC);

--
-- Name: selector_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX selector_node_id_idx ON core.selector USING btree (node_id);

--
-- Name: selector_norm_value_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX selector_norm_value_idx ON core.selector USING gin (norm_value public.gin_trgm_ops);

--
-- Name: selector_raw_value_trgm_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX selector_raw_value_trgm_idx ON core.selector USING gin (raw_value public.gin_trgm_ops);

--
-- Name: selector_selector_type_norm_value_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX selector_selector_type_norm_value_idx ON core.selector USING btree (selector_type, norm_value);

--
-- Name: tag_assignment_document_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX tag_assignment_document_idx ON core.tag_assignment USING btree (document_id);

--
-- Name: tag_assignment_node_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX tag_assignment_node_id_idx ON core.tag_assignment USING btree (node_id);

--
-- Name: tag_assignment_tag_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX tag_assignment_tag_id_idx ON core.tag_assignment USING btree (tag_id);

--
-- Name: tag_assignment_uniq_document_id; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_assignment_uniq_document_id ON core.tag_assignment USING btree (tag_id, document_id) WHERE (document_id IS NOT NULL);

--
-- Name: tag_assignment_uniq_edge_id; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_assignment_uniq_edge_id ON core.tag_assignment USING btree (tag_id, edge_id) WHERE (edge_id IS NOT NULL);

--
-- Name: tag_assignment_uniq_evidence_id; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_assignment_uniq_evidence_id ON core.tag_assignment USING btree (tag_id, evidence_id) WHERE (evidence_id IS NOT NULL);

--
-- Name: tag_assignment_uniq_node_id; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_assignment_uniq_node_id ON core.tag_assignment USING btree (tag_id, node_id) WHERE (node_id IS NOT NULL);

--
-- Name: tag_uniq_case; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_uniq_case ON core.tag USING btree (case_id, namespace, name) WHERE (case_id IS NOT NULL);

--
-- Name: tag_uniq_global; Type: INDEX; Schema: core; Owner: -
--

CREATE UNIQUE INDEX tag_uniq_global ON core.tag USING btree (namespace, name) WHERE (case_id IS NULL);

--
-- Name: call_called_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_called_idx ON deception.call_record USING btree (called_number_e164) WHERE (called_number_e164 IS NOT NULL);

--
-- Name: call_case_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_case_idx ON deception.call_record USING btree (case_id, started_at DESC);

--
-- Name: call_pai_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_pai_idx ON deception.call_record USING btree (p_asserted_identity) WHERE (p_asserted_identity IS NOT NULL);

--
-- Name: call_presented_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_presented_idx ON deception.call_record USING btree (presented_number_e164) WHERE (presented_number_e164 IS NOT NULL);

--
-- Name: call_recorded_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_recorded_idx ON deception.call_record USING btree (case_id) WHERE (recording_evidence_id IS NOT NULL);

--
-- Name: call_trunk_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX call_trunk_idx ON deception.call_record USING btree (originating_trunk) WHERE (originating_trunk IS NOT NULL);

--
-- Name: capture_case_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_case_idx ON deception.capture USING btree (case_id, captured_at DESC);

--
-- Name: capture_favicon_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_favicon_idx ON deception.capture USING btree (favicon_hash) WHERE (favicon_hash IS NOT NULL);

--
-- Name: capture_final_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_final_idx ON deception.capture USING btree (final_url_norm) WHERE (final_url_norm IS NOT NULL);

--
-- Name: capture_hop_url_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_hop_url_idx ON deception.capture_hop USING btree (url_norm);

--
-- Name: capture_spki_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_spki_idx ON deception.capture USING btree (tls_spki_sha256) WHERE (tls_spki_sha256 IS NOT NULL);

--
-- Name: capture_url_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX capture_url_idx ON deception.capture USING btree (requested_url_norm);

--
-- Name: email_attachment_msg_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_attachment_msg_idx ON deception.email_attachment USING btree (message_id);

--
-- Name: email_attachment_sha_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_attachment_sha_idx ON deception.email_attachment USING btree (sha256) WHERE (sha256 IS NOT NULL);

--
-- Name: email_case_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_case_idx ON deception.email_message USING btree (case_id, recorded_at DESC);

--
-- Name: email_divergent_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_divergent_idx ON deception.email_message USING btree (case_id) WHERE from_replyto_divergent;

--
-- Name: email_from_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_from_idx ON deception.email_message USING btree (lower(header_from)) WHERE (header_from IS NOT NULL);

--
-- Name: email_hop_ip_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_hop_ip_idx ON deception.email_hop USING btree (from_ip) WHERE (from_ip IS NOT NULL);

--
-- Name: email_hop_one_boundary_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE UNIQUE INDEX email_hop_one_boundary_idx ON deception.email_hop USING btree (message_id) WHERE is_trusted_boundary;

--
-- Name: email_msgid_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_msgid_idx ON deception.email_message USING btree (message_id_norm) WHERE (message_id_norm IS NOT NULL);

--
-- Name: email_replyto_idx; Type: INDEX; Schema: deception; Owner: -
--

CREATE INDEX email_replyto_idx ON deception.email_message USING btree (lower(header_reply_to)) WHERE (header_reply_to IS NOT NULL);

--
-- Name: break_glass_live_idx; Type: INDEX; Schema: iam; Owner: -
--

CREATE INDEX break_glass_live_idx ON iam.break_glass USING btree (user_id, expires_at) WHERE (revoked_at IS NULL);

--
-- Name: break_glass_unreviewed_idx; Type: INDEX; Schema: iam; Owner: -
--

CREATE INDEX break_glass_unreviewed_idx ON iam.break_glass USING btree (started_at DESC) WHERE (reviewed_at IS NULL);

--
-- Name: case_assignment_user_id_expires_at_idx; Type: INDEX; Schema: iam; Owner: -
--

CREATE INDEX case_assignment_user_id_expires_at_idx ON iam.case_assignment USING btree (user_id, expires_at);

--
-- Name: session_rls_binding_hash_key; Type: INDEX; Schema: iam; Owner: -
--

CREATE UNIQUE INDEX session_rls_binding_hash_key ON iam.session USING btree (rls_binding_hash) WHERE (rls_binding_hash IS NOT NULL);

--
-- Name: session_user_id_idx; Type: INDEX; Schema: iam; Owner: -
--

CREATE INDEX session_user_id_idx ON iam.session USING btree (user_id) WHERE (revoked_at IS NULL);

--
-- Name: api_key_live_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX api_key_live_idx ON ingest.api_key USING btree (expires_at) WHERE (revoked_at IS NULL);

--
-- Name: api_key_owner_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX api_key_owner_idx ON ingest.api_key USING btree (owner_user_id);

--
-- Name: api_key_stale_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX api_key_stale_idx ON ingest.api_key USING btree (last_used_at NULLS FIRST) WHERE (revoked_at IS NULL);

--
-- Name: batch_idempotency_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE UNIQUE INDEX batch_idempotency_idx ON ingest.batch USING btree (api_key_id, idempotency_key) WHERE (idempotency_key IS NOT NULL);

--
-- Name: batch_key_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX batch_key_idx ON ingest.batch USING btree (api_key_id, received_at DESC);

--
-- Name: batch_unparsed_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX batch_unparsed_idx ON ingest.batch USING btree (received_at) WHERE (state = ANY (ARRAY['RECEIVED'::text, 'PARSING'::text]));

--
-- Name: category_rule_active_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX category_rule_active_idx ON ingest.category_rule USING btree (category) WHERE is_active;

--
-- Name: dead_letter_batch_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX dead_letter_batch_idx ON ingest.dead_letter USING btree (batch_id);

--
-- Name: dead_letter_key_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX dead_letter_key_idx ON ingest.dead_letter USING btree (api_key_id, occurred_at DESC);

--
-- Name: dead_letter_labels_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX dead_letter_labels_idx ON ingest.dead_letter USING btree (classification);

--
-- Name: dead_letter_open_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX dead_letter_open_idx ON ingest.dead_letter USING btree (occurred_at DESC) WHERE (replayed_at IS NULL);

--
-- Name: dead_letter_retention_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX dead_letter_retention_idx ON ingest.dead_letter USING btree (retain_until) WHERE (purged_at IS NULL);

--
-- Name: exposure_change_one_open; Type: INDEX; Schema: ingest; Owner: -
--

CREATE UNIQUE INDEX exposure_change_one_open ON ingest.provider_exposure_change USING btree (provider_id) WHERE (decision IS NULL);

--
-- Name: lookup_attempt_quota_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_attempt_quota_idx ON ingest.lookup_attempt USING btree (provider_id, sent_at);

--
-- Name: lookup_awaiting_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_awaiting_idx ON ingest.lookup USING btree (authorised_by, signoff_expires_at) WHERE (state = 'AWAITING_SIGNOFF'::text);

--
-- Name: lookup_batch_case_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_batch_case_idx ON ingest.lookup_batch USING btree (case_id, requested_at DESC);

--
-- Name: lookup_batch_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_batch_idx ON ingest.lookup USING btree (batch_id) WHERE (batch_id IS NOT NULL);

--
-- Name: lookup_case_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_case_idx ON ingest.lookup USING btree (case_id, requested_at DESC);

--
-- Name: lookup_queue_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_queue_idx ON ingest.lookup USING btree (provider_id, not_before NULLS FIRST, requested_at) WHERE (state = 'QUEUED'::text);

--
-- Name: lookup_result_cache_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_result_cache_idx ON ingest.lookup_result USING btree (case_id, provider_id, operation, query_fingerprint, fetched_at DESC) WHERE ((purged_at IS NULL) AND (outcome <> 'UNREADABLE'::text));

--
-- Name: lookup_sending_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX lookup_sending_idx ON ingest.lookup USING btree (sent_at) WHERE (state = 'SENDING'::text);

--
-- Name: pii_authorisation_live_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX pii_authorisation_live_idx ON ingest.pii_authorisation USING btree (granted_to, expires_at) WHERE (revoked_at IS NULL);

--
-- Name: provider_origin_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX provider_origin_idx ON ingest.provider USING btree (origin_host, origin_port);

--
-- Name: record_batch_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_batch_idx ON ingest.record USING btree (batch_id);

--
-- Name: record_content_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_content_idx ON ingest.record USING btree (content_sha256);

--
-- Name: record_duplicate_of_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_duplicate_of_idx ON ingest.record USING btree (duplicate_of) WHERE (duplicate_of IS NOT NULL);

--
-- Name: record_retention_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_retention_idx ON ingest.record USING btree (retain_until) WHERE (purged_at IS NULL);

--
-- Name: record_simhash_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_simhash_idx ON ingest.record USING btree (simhash_version, created_at DESC) WHERE ((simhash IS NOT NULL) AND (duplicate_of IS NULL));

--
-- Name: record_triage_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_triage_idx ON ingest.record USING btree (priority DESC, created_at DESC) WHERE ((duplicate_of IS NULL) AND (purged_at IS NULL));

--
-- Name: victim_credential_fingerprint_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX victim_credential_fingerprint_idx ON ingest.victim_credential USING btree (value_fingerprint);

--
-- Name: victim_credential_record_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX victim_credential_record_idx ON ingest.victim_credential USING btree (record_id);

--
-- Name: victim_credential_service_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX victim_credential_service_idx ON ingest.victim_credential USING btree (service_domain);

--
-- Name: detonation_analysis_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX detonation_analysis_idx ON lab.detonation USING btree (analysis_id) WHERE (analysis_id IS NOT NULL);

--
-- Name: detonation_due_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX detonation_due_idx ON lab.detonation USING btree (status, requested_at) WHERE ((mode = 'SUBMIT'::text) AND (status = ANY (ARRAY['AWAITING_SIGNOFF'::text, 'QUEUED'::text, 'SUBMITTED'::text])));

--
-- Name: detonation_one_in_flight; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX detonation_one_in_flight ON lab.detonation USING btree (sample_id, target_key) WHERE ((mode = 'SUBMIT'::text) AND (status = ANY (ARRAY['AWAITING_SIGNOFF'::text, 'QUEUED'::text, 'SUBMITTED'::text])));

--
-- Name: detonation_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX detonation_sample_idx ON lab.detonation USING btree (sample_id, requested_at DESC);

--
-- Name: detonation_signoff_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX detonation_signoff_idx ON lab.detonation USING btree (authorised_by) WHERE (status = 'AWAITING_SIGNOFF'::text);

--
-- Name: download_ticket_evidence_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX download_ticket_evidence_idx ON lab.download_ticket USING btree (evidence_id, issued_at DESC) WHERE (evidence_id IS NOT NULL);

--
-- Name: download_ticket_live_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX download_ticket_live_idx ON lab.download_ticket USING btree (expires_at) WHERE (redeemed_at IS NULL);

--
-- Name: download_ticket_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX download_ticket_sample_idx ON lab.download_ticket USING btree (sample_id, issued_at DESC);

--
-- Name: preservation_authorisation_live_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX preservation_authorisation_live_idx ON lab.preservation_authorisation USING btree (granted_to, sample_id, expires_at) WHERE (revoked_at IS NULL);

--
-- Name: preservation_authorisation_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX preservation_authorisation_sample_idx ON lab.preservation_authorisation USING btree (sample_id, created_at DESC);

--
-- Name: sample_access_actor_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_access_actor_idx ON lab.sample_access USING btree (actor_id, occurred_at DESC);

--
-- Name: sample_access_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_access_sample_idx ON lab.sample_access USING btree (sample_id, occurred_at DESC);

--
-- Name: sample_analysis_machine_yara_hits_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_analysis_machine_yara_hits_idx ON lab.sample_analysis USING gin (yara_hits) WHERE ((origin = 'machine'::text) AND (yara_ruleset_version_id IS NOT NULL));

--
-- Name: sample_analysis_run_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_analysis_run_idx ON lab.sample_analysis USING btree (run_id) WHERE (run_id IS NOT NULL);

--
-- Name: sample_analysis_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_analysis_sample_idx ON lab.sample_analysis USING btree (sample_id, created_at DESC);

--
-- Name: sample_analysis_yara_version_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_analysis_yara_version_idx ON lab.sample_analysis USING btree (yara_ruleset_version_id) WHERE (yara_ruleset_version_id IS NOT NULL);

--
-- Name: sample_assigned_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_assigned_idx ON lab.sample USING btree (assigned_to) WHERE (assigned_to IS NOT NULL);

--
-- Name: sample_case_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_case_idx ON lab.sample USING btree (case_id, submitted_at DESC);

--
-- Name: sample_imphash_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_imphash_idx ON lab.sample USING btree (imphash) WHERE (imphash IS NOT NULL);

--
-- Name: sample_match_pending_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_match_pending_idx ON lab.sample USING btree (screened_at) WHERE ((screening_outcome = 'MATCH'::text) AND (preserved_key IS NULL) AND (octet_length(data_key_ciphertext) > 0) AND (screening_bytes_absent_at IS NULL));

--
-- Name: sample_queue_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_queue_idx ON lab.sample USING btree (state, submitted_at DESC) WHERE (state = ANY (ARRAY['QUARANTINED'::lab.sample_state, 'TRIAGED'::lab.sample_state, 'ASSIGNED'::lab.sample_state, 'IN_ANALYSIS'::lab.sample_state]));

--
-- Name: sample_rich_header_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_rich_header_idx ON lab.sample USING btree (rich_header_hash) WHERE (rich_header_hash IS NOT NULL);

--
-- Name: sample_screening_behind_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_screening_behind_idx ON lab.sample USING btree (screening_list_seq NULLS FIRST, id) WHERE (screening_outcome <> 'MATCH'::text);

--
-- Name: sample_ssdeep_tokens_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_ssdeep_tokens_idx ON lab.sample USING gin (ssdeep_tokens);

--
-- Name: sample_tlsh_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_tlsh_idx ON lab.sample USING btree (tlsh) WHERE (tlsh IS NOT NULL);

--
-- Name: sample_tlsh_lvalue_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_tlsh_lvalue_idx ON lab.sample USING btree (tlsh_lvalue) WHERE (tlsh IS NOT NULL);

--
-- Name: screening_hash_list_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX screening_hash_list_idx ON lab.screening_hash USING btree (list_id);

--
-- Name: screening_list_one_active_copy; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX screening_list_one_active_copy ON lab.screening_list USING btree (source_sha256) WHERE (retired_at IS NULL);

--
-- Name: screening_result_match_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX screening_result_match_idx ON lab.screening_result USING btree (screened_at DESC) WHERE (outcome = 'MATCH'::text);

--
-- Name: screening_result_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX screening_result_sample_idx ON lab.screening_result USING btree (sample_id, screened_at DESC);

--
-- Name: screening_review_result_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX screening_review_result_idx ON lab.screening_review USING btree (result_id, reviewed_at);

--
-- Name: static_run_one_queued; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX static_run_one_queued ON lab.static_run USING btree (sample_id) WHERE (status = 'QUEUED'::text);

--
-- Name: static_run_one_running; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX static_run_one_running ON lab.static_run USING btree (sample_id) WHERE (status = 'RUNNING'::text);

--
-- Name: static_run_queue_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX static_run_queue_idx ON lab.static_run USING btree (priority, queued_at) WHERE (status = 'QUEUED'::text);

--
-- Name: static_run_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX static_run_sample_idx ON lab.static_run USING btree (sample_id, queued_at DESC);

--
-- Name: yara_activation_one_open; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX yara_activation_one_open ON lab.yara_activation USING btree (ruleset_id) WHERE (deactivated_at IS NULL);

--
-- Name: yara_compiled_lookup; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX yara_compiled_lookup ON lab.yara_compiled USING btree (version_id, engine, platform, fingerprint, compiled_at DESC);

--
-- Name: yara_ruleset_key_per_labels; Type: INDEX; Schema: lab; Owner: -
--

CREATE UNIQUE INDEX yara_ruleset_key_per_labels ON lab.yara_ruleset USING btree (key, classification, lab.yara_label_set(compartments));

--
-- Name: delivery_due_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX delivery_due_idx ON notify.delivery USING btree (deliver_after) WHERE (state = 'PENDING'::text);

--
-- Name: delivery_jira_link_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX delivery_jira_link_idx ON notify.delivery USING btree (jira_link_id) WHERE (jira_link_id IS NOT NULL);

--
-- Name: delivery_ledger_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX delivery_ledger_idx ON notify.delivery USING btree (COALESCE(last_attempt_at, sent_at, queued_at) DESC, id DESC);

--
-- Name: delivery_one_per_channel; Type: INDEX; Schema: notify; Owner: -
--

CREATE UNIQUE INDEX delivery_one_per_channel ON notify.delivery USING btree (notification_id, channel);

--
-- Name: jira_destination_one_live; Type: INDEX; Schema: notify; Owner: -
--

CREATE UNIQUE INDEX jira_destination_one_live ON notify.jira_destination USING btree ((1)) WHERE (state <> 'RETIRED'::text);

--
-- Name: jira_link_case_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX jira_link_case_idx ON notify.jira_link USING btree (case_id, created_at DESC);

--
-- Name: jira_link_issue_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX jira_link_issue_idx ON notify.jira_link USING btree (destination_id, issue_key) WHERE (issue_key IS NOT NULL);

--
-- Name: jira_link_one_open; Type: INDEX; Schema: notify; Owner: -
--

CREATE UNIQUE INDEX jira_link_one_open ON notify.jira_link USING btree (destination_id, work_key) WHERE (state <> 'CLOSED'::text);

--
-- Name: notification_case_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX notification_case_idx ON notify.notification USING btree (case_id, created_at DESC);

--
-- Name: notification_object_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX notification_object_idx ON notify.notification USING btree (object_id) WHERE (object_id IS NOT NULL);

--
-- Name: notification_recipient_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX notification_recipient_idx ON notify.notification USING btree (recipient_id, created_at DESC);

--
-- Name: notification_unread_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX notification_unread_idx ON notify.notification USING btree (recipient_id, created_at DESC) WHERE (read_at IS NULL);

--
-- Name: metric_run compartments_registered; Type: TRIGGER; Schema: analytics; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF visibility_compartments ON analytics.metric_run FOR EACH ROW WHEN ((cardinality(new.visibility_compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('visibility_compartments', 'array');

--
-- Name: event audit_chain; Type: TRIGGER; Schema: audit; Owner: -
--

CREATE TRIGGER audit_chain BEFORE INSERT ON audit.event FOR EACH ROW EXECUTE FUNCTION audit.chain_hash();

--
-- Name: event event_append_only; Type: TRIGGER; Schema: audit; Owner: -
--

CREATE TRIGGER event_append_only BEFORE DELETE OR UPDATE ON audit.event FOR EACH ROW EXECUTE FUNCTION audit.block_mutation();

--
-- Name: event event_no_truncate; Type: TRIGGER; Schema: audit; Owner: -
--

CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON audit.event FOR EACH STATEMENT EXECUTE FUNCTION audit.block_mutation();

--
-- Name: collection_account collection_account_egress_bound; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_account_egress_bound AFTER INSERT ON collect.collection_account FOR EACH ROW WHEN ((new.egress_profile_id IS NOT NULL)) EXECUTE FUNCTION collect.record_egress_binding();

--
-- Name: collection_account collection_account_egress_rebound; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_account_egress_rebound AFTER UPDATE OF egress_profile_id ON collect.collection_account FOR EACH ROW WHEN ((old.egress_profile_id IS DISTINCT FROM new.egress_profile_id)) EXECUTE FUNCTION collect.record_egress_binding();

--
-- Name: collection_account collection_account_holds_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_account_holds_guarded BEFORE DELETE OR UPDATE ON collect.collection_account FOR EACH ROW EXECUTE FUNCTION collect.guard_persona_holds();

--
-- Name: collection_account collection_account_telegram_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_account_telegram_guarded BEFORE UPDATE ON collect.collection_account FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_persona();

--
-- Name: collection_authority collection_authority_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_authority_guarded BEFORE DELETE OR UPDATE ON collect.collection_authority FOR EACH ROW EXECUTE FUNCTION collect.guard_collection_authority();

--
-- Name: collection_authority collection_authority_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_authority_no_truncate BEFORE TRUNCATE ON collect.collection_authority FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_collection_authority();

--
-- Name: collection_authority_target collection_authority_target_fits; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_authority_target_fits BEFORE INSERT ON collect.collection_authority_target FOR EACH ROW EXECUTE FUNCTION collect.authority_target_fits();

--
-- Name: collection_authority_target collection_authority_target_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_authority_target_guarded BEFORE DELETE OR UPDATE ON collect.collection_authority_target FOR EACH ROW EXECUTE FUNCTION collect.guard_collection_authority_target();

--
-- Name: collection_authority_target collection_authority_target_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_authority_target_no_truncate BEFORE TRUNCATE ON collect.collection_authority_target FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_collection_authority_target();

--
-- Name: collection_run collection_run_requests_once; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER collection_run_requests_once BEFORE UPDATE OF requests ON collect.collection_run FOR EACH ROW EXECUTE FUNCTION collect.guard_run_requests();

--
-- Name: document compartments_registered; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON collect.document FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: document_embedding compartments_registered; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF read_compartments ON collect.document_embedding FOR EACH ROW WHEN ((cardinality(new.read_compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('read_compartments', 'array');

--
-- Name: document_embedding document_embedding_labels; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER document_embedding_labels BEFORE INSERT OR UPDATE OF document_id, read_classification, read_compartments ON collect.document_embedding FOR EACH ROW EXECUTE FUNCTION collect.document_embedding_labels();

--
-- Name: document document_embedding_queued; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER document_embedding_queued AFTER INSERT ON collect.document FOR EACH ROW WHEN ((new.purged_at IS NULL)) EXECUTE FUNCTION collect.document_embedding_queued();

--
-- Name: document document_tsv; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER document_tsv BEFORE INSERT OR UPDATE OF title, author_handle, body_text, purged_at ON collect.document FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();

--
-- Name: document document_vectors_follow; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER document_vectors_follow AFTER UPDATE OF classification, compartments, category, title, body_text, purged_at ON collect.document FOR EACH ROW WHEN (((old.classification IS DISTINCT FROM new.classification) OR (old.compartments IS DISTINCT FROM new.compartments) OR (old.category IS DISTINCT FROM new.category) OR (old.title IS DISTINCT FROM new.title) OR (old.body_text IS DISTINCT FROM new.body_text) OR (old.purged_at IS DISTINCT FROM new.purged_at))) EXECUTE FUNCTION collect.document_vectors_follow();

--
-- Name: egress_binding egress_binding_append_only; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_binding_append_only BEFORE DELETE OR UPDATE ON collect.egress_binding FOR EACH ROW EXECUTE FUNCTION collect.egress_binding_block();

--
-- Name: egress_binding egress_binding_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_binding_no_truncate BEFORE TRUNCATE ON collect.egress_binding FOR EACH STATEMENT EXECUTE FUNCTION collect.egress_binding_block();

--
-- Name: egress_connection egress_connection_append_only; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_connection_append_only BEFORE DELETE OR UPDATE ON collect.egress_connection FOR EACH ROW EXECUTE FUNCTION collect.egress_connection_block();

--
-- Name: egress_connection egress_connection_chain; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_connection_chain BEFORE INSERT ON collect.egress_connection FOR EACH ROW EXECUTE FUNCTION collect.egress_connection_chain();

--
-- Name: egress_connection egress_connection_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_connection_no_truncate BEFORE TRUNCATE ON collect.egress_connection FOR EACH STATEMENT EXECUTE FUNCTION collect.egress_connection_block();

--
-- Name: egress_destination egress_destination_terminal; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_destination_terminal BEFORE UPDATE ON collect.egress_destination FOR EACH ROW EXECUTE FUNCTION collect.egress_route_terminal();

--
-- Name: egress_integration_route egress_integration_route_terminal; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_integration_route_terminal BEFORE UPDATE ON collect.egress_integration_route FOR EACH ROW EXECUTE FUNCTION collect.egress_route_terminal();

--
-- Name: egress_profile egress_profile_reach; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER egress_profile_reach BEFORE UPDATE ON collect.egress_profile FOR EACH ROW EXECUTE FUNCTION collect.egress_profile_reach();

--
-- Name: source source_egress_bound; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER source_egress_bound AFTER INSERT ON collect.source FOR EACH ROW WHEN ((new.egress_profile_id IS NOT NULL)) EXECUTE FUNCTION collect.record_egress_binding();

--
-- Name: source source_egress_rebound; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER source_egress_rebound AFTER UPDATE OF egress_profile_id ON collect.source FOR EACH ROW WHEN ((old.egress_profile_id IS DISTINCT FROM new.egress_profile_id)) EXECUTE FUNCTION collect.record_egress_binding();

--
-- Name: source source_raises_authority_labels; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER source_raises_authority_labels AFTER UPDATE OF classification ON collect.source FOR EACH ROW EXECUTE FUNCTION collect.raise_authority_labels();

--
-- Name: source source_vectors_follow; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER source_vectors_follow AFTER UPDATE OF classification, kind ON collect.source FOR EACH ROW WHEN (((old.classification IS DISTINCT FROM new.classification) OR (old.kind IS DISTINCT FROM new.kind))) EXECUTE FUNCTION collect.source_vectors_follow();

--
-- Name: telegram_chat telegram_chat_identity_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER telegram_chat_identity_guarded BEFORE DELETE OR UPDATE ON collect.telegram_chat FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_chat();

--
-- Name: telegram_chat telegram_chat_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER telegram_chat_no_truncate BEFORE TRUNCATE ON collect.telegram_chat FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_telegram_chat();

--
-- Name: telegram_message telegram_message_guarded; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER telegram_message_guarded BEFORE DELETE OR UPDATE ON collect.telegram_message FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_message();

--
-- Name: telegram_message telegram_message_no_truncate; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER telegram_message_no_truncate BEFORE TRUNCATE ON collect.telegram_message FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_telegram_message();

--
-- Name: pgp_key_acquisition acquisition_tlp; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER acquisition_tlp BEFORE INSERT OR UPDATE ON comms.pgp_key_acquisition FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: channel_binding compartments_registered; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON comms.channel_binding FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: contact_block compartments_registered; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON comms.contact_block FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: conversation compartments_registered; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON comms.conversation FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: message compartments_registered; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON comms.message FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: pgp_key_acquisition compartments_registered; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON comms.pgp_key_acquisition FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: pgp_key_acquisition pgp_key_acquisition_guarded; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_acquisition_guarded BEFORE INSERT OR DELETE OR UPDATE ON comms.pgp_key_acquisition FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key_acquisition();

--
-- Name: pgp_key_acquisition pgp_key_acquisition_no_truncate; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_acquisition_no_truncate BEFORE TRUNCATE ON comms.pgp_key_acquisition FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key_acquisition();

--
-- Name: pgp_key pgp_key_guarded; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_guarded BEFORE INSERT OR DELETE OR UPDATE ON comms.pgp_key FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key();

--
-- Name: pgp_key_lookup pgp_key_lookup_guarded; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_lookup_guarded BEFORE INSERT OR DELETE OR UPDATE ON comms.pgp_key_lookup FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key_lookup();

--
-- Name: pgp_key_lookup pgp_key_lookup_no_truncate; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_lookup_no_truncate BEFORE TRUNCATE ON comms.pgp_key_lookup FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key_lookup();

--
-- Name: pgp_key pgp_key_no_truncate; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_key_no_truncate BEFORE TRUNCATE ON comms.pgp_key FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key();

--
-- Name: pgp_verification pgp_verification_cites_a_confirmed_key; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_cites_a_confirmed_key BEFORE INSERT ON comms.pgp_verification FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_cites_a_confirmed_key();

--
-- Name: pgp_verification pgp_verification_confirms_its_binding; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_confirms_its_binding BEFORE INSERT OR UPDATE ON comms.pgp_verification FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_confirms_its_binding();

--
-- Name: pgp_verification pgp_verification_guarded; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_guarded BEFORE DELETE OR UPDATE ON comms.pgp_verification FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_verification();

--
-- Name: pgp_verification pgp_verification_is_attributed; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_is_attributed BEFORE INSERT ON comms.pgp_verification FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_is_attributed();

--
-- Name: pgp_verification pgp_verification_no_truncate; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_no_truncate BEFORE TRUNCATE ON comms.pgp_verification FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_verification();

--
-- Name: approval_request approval_request_frozen; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER approval_request_frozen BEFORE INSERT OR UPDATE ON core.approval_request FOR EACH ROW EXECUTE FUNCTION core.guard_approval_request();

--
-- Name: assertion assertion_derives_tie_confidence; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER assertion_derives_tie_confidence AFTER INSERT OR DELETE OR UPDATE OF edge_id, confidence, claim_path, claim_value, retracted_at, superseded_at ON core.assertion FOR EACH ROW EXECUTE FUNCTION core.assertion_derives_tie_confidence();

--
-- Name: assertion_embedding assertion_embedding_case; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER assertion_embedding_case BEFORE INSERT OR UPDATE OF assertion_id, case_id ON core.assertion_embedding FOR EACH ROW EXECUTE FUNCTION core.assertion_embedding_case();

--
-- Name: assertion assertion_embedding_dequeued; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER assertion_embedding_dequeued AFTER UPDATE OF retracted_at, superseded_at ON core.assertion FOR EACH ROW WHEN (((new.retracted_at IS NOT NULL) OR (new.superseded_at IS NOT NULL))) EXECUTE FUNCTION core.assertion_embedding_queued();

--
-- Name: assertion assertion_embedding_queued; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER assertion_embedding_queued AFTER INSERT ON core.assertion FOR EACH ROW WHEN (((new.retracted_at IS NULL) AND (new.superseded_at IS NULL))) EXECUTE FUNCTION core.assertion_embedding_queued();

--
-- Name: assertion assertion_protects_element; Type: TRIGGER; Schema: core; Owner: -
--

CREATE CONSTRAINT TRIGGER assertion_protects_element AFTER DELETE OR UPDATE OF node_id, edge_id ON core.assertion DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core.assertion_protects_element();

--
-- Name: case case_merge_switch_guarded; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER case_merge_switch_guarded BEFORE UPDATE ON core."case" FOR EACH ROW WHEN (((old.dual_control_merge IS DISTINCT FROM new.dual_control_merge) OR (old.dual_control_merge_epoch IS DISTINCT FROM new.dual_control_merge_epoch))) EXECUTE FUNCTION core.guard_case_merge_switch();

--
-- Name: case compartments_registered; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON core."case" FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: edge compartments_registered; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON core.edge FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: evidence compartments_registered; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON core.evidence FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: node compartments_registered; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON core.node FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: evidence_custody custody_chain; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER custody_chain BEFORE INSERT ON core.evidence_custody FOR EACH ROW EXECUTE FUNCTION core.custody_chain_hash();

--
-- Name: edge edge_announce_del; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_announce_del AFTER DELETE ON core.edge REFERENCING OLD TABLE AS oldrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('edge');

--
-- Name: edge edge_announce_ins; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_announce_ins AFTER INSERT ON core.edge REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('edge');

--
-- Name: edge edge_announce_upd; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_announce_upd AFTER UPDATE ON core.edge REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('edge');

--
-- Name: edge edge_confidence_is_derived; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_confidence_is_derived BEFORE UPDATE OF confidence ON core.edge FOR EACH ROW EXECUTE FUNCTION core.edge_confidence_is_derived();

--
-- Name: edge edge_requires_assertion; Type: TRIGGER; Schema: core; Owner: -
--

CREATE CONSTRAINT TRIGGER edge_requires_assertion AFTER INSERT ON core.edge DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core.require_edge_assertion();

--
-- Name: edge edge_tlp; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_tlp BEFORE INSERT OR UPDATE ON core.edge FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: edge edge_validate; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER edge_validate BEFORE INSERT OR UPDATE ON core.edge FOR EACH ROW EXECUTE FUNCTION core.validate_edge_endpoints();

--
-- Name: embedding_space embedding_space_transition; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER embedding_space_transition BEFORE UPDATE ON core.embedding_space FOR EACH ROW EXECUTE FUNCTION core.embedding_space_transition();

--
-- Name: evidence_custody evidence_custody_append_only; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_custody_append_only BEFORE DELETE OR UPDATE ON core.evidence_custody FOR EACH ROW EXECUTE FUNCTION core.block_custody_mutation();

--
-- Name: evidence_custody evidence_custody_no_truncate; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_custody_no_truncate BEFORE TRUNCATE ON core.evidence_custody FOR EACH STATEMENT EXECUTE FUNCTION core.block_custody_mutation();

--
-- Name: evidence_embedding evidence_embedding_case; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_embedding_case BEFORE INSERT OR UPDATE OF evidence_id, case_id ON core.evidence_embedding FOR EACH ROW EXECUTE FUNCTION core.evidence_embedding_case();

--
-- Name: evidence evidence_embedding_queued; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_embedding_queued AFTER INSERT ON core.evidence FOR EACH ROW WHEN ((new.purged_at IS NULL)) EXECUTE FUNCTION core.evidence_embedding_queued();

--
-- Name: evidence evidence_tlp; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_tlp BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: evidence evidence_tsv; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_tsv BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.evidence_tsv_update();

--
-- Name: evidence evidence_vectors_follow; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_vectors_follow AFTER UPDATE OF title, description, extracted_text, classification, compartments, purged_at ON core.evidence FOR EACH ROW WHEN (((old.title IS DISTINCT FROM new.title) OR (old.description IS DISTINCT FROM new.description) OR (old.extracted_text IS DISTINCT FROM new.extracted_text) OR (old.classification IS DISTINCT FROM new.classification) OR (old.compartments IS DISTINCT FROM new.compartments) OR (old.purged_at IS DISTINCT FROM new.purged_at))) EXECUTE FUNCTION core.evidence_vectors_follow();

--
-- Name: node node_announce_del; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER node_announce_del AFTER DELETE ON core.node REFERENCING OLD TABLE AS oldrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('node');

--
-- Name: node node_announce_ins; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER node_announce_ins AFTER INSERT ON core.node REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('node');

--
-- Name: node node_announce_upd; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER node_announce_upd AFTER UPDATE ON core.node REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('node');

--
-- Name: node node_requires_assertion; Type: TRIGGER; Schema: core; Owner: -
--

CREATE CONSTRAINT TRIGGER node_requires_assertion AFTER INSERT ON core.node DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core.require_node_assertion();

--
-- Name: node node_tlp; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER node_tlp BEFORE INSERT OR UPDATE ON core.node FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: node node_tsv; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER node_tsv BEFORE INSERT OR UPDATE ON core.node FOR EACH ROW EXECUTE FUNCTION core.node_tsv_update();

--
-- Name: purge_tombstone purge_tombstone_append_only; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER purge_tombstone_append_only BEFORE DELETE OR UPDATE ON core.purge_tombstone FOR EACH ROW EXECUTE FUNCTION core.block_tombstone_mutation();

--
-- Name: purge_tombstone purge_tombstone_no_truncate; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER purge_tombstone_no_truncate BEFORE TRUNCATE ON core.purge_tombstone FOR EACH STATEMENT EXECUTE FUNCTION core.block_tombstone_mutation();

--
-- Name: call_record call_record_tlp; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER call_record_tlp BEFORE INSERT OR UPDATE ON deception.call_record FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: capture capture_tlp; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER capture_tlp BEFORE INSERT OR UPDATE ON deception.capture FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: call_record compartments_registered; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON deception.call_record FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: capture compartments_registered; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON deception.capture FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: email_message compartments_registered; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON deception.email_message FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: email_message email_message_tlp; Type: TRIGGER; Schema: deception; Owner: -
--

CREATE TRIGGER email_message_tlp BEFORE INSERT OR UPDATE ON deception.email_message FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: compartment compartment_in_use; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER compartment_in_use BEFORE DELETE OR UPDATE OF key ON iam.compartment FOR EACH ROW EXECUTE FUNCTION iam.refuse_compartment_removal();

--
-- Name: app_user compartments_registered; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON iam.app_user FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: dual_control_policy_change dual_control_change_append_only; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_change_append_only BEFORE DELETE OR UPDATE ON iam.dual_control_policy_change FOR EACH ROW EXECUTE FUNCTION iam.guard_dual_control_ledger();

--
-- Name: dual_control_policy_change dual_control_change_applied; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_change_applied AFTER INSERT ON iam.dual_control_policy_change FOR EACH ROW EXECUTE FUNCTION iam.apply_dual_control_change();

--
-- Name: dual_control_policy_change dual_control_change_checked; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_change_checked BEFORE INSERT ON iam.dual_control_policy_change FOR EACH ROW EXECUTE FUNCTION iam.check_dual_control_change();

--
-- Name: dual_control_policy_change dual_control_change_no_truncate; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_change_no_truncate BEFORE TRUNCATE ON iam.dual_control_policy_change FOR EACH STATEMENT EXECUTE FUNCTION iam.guard_dual_control_ledger();

--
-- Name: dual_control_operation dual_control_operation_no_truncate; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_operation_no_truncate BEFORE TRUNCATE ON iam.dual_control_operation FOR EACH STATEMENT EXECUTE FUNCTION iam.policy_changed_only_by_ledger();

--
-- Name: dual_control_operation dual_control_operation_written_by_ledger; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER dual_control_operation_written_by_ledger BEFORE INSERT OR DELETE OR UPDATE ON iam.dual_control_operation FOR EACH ROW EXECUTE FUNCTION iam.policy_changed_only_by_ledger();

--
-- Name: role_permission role_permission_separated_duty; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER role_permission_separated_duty BEFORE INSERT OR UPDATE ON iam.role_permission FOR EACH ROW EXECUTE FUNCTION iam.refuse_separated_duty_grant();

--
-- Name: separated_duty separated_duty_no_truncate; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER separated_duty_no_truncate BEFORE TRUNCATE ON iam.separated_duty FOR EACH STATEMENT EXECUTE FUNCTION iam.policy_changed_only_by_ledger();

--
-- Name: separated_duty separated_duty_not_already_violated; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER separated_duty_not_already_violated BEFORE INSERT OR UPDATE ON iam.separated_duty FOR EACH ROW EXECUTE FUNCTION iam.refuse_violated_separation();

--
-- Name: separated_duty separated_duty_written_by_ledger; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER separated_duty_written_by_ledger BEFORE INSERT OR DELETE OR UPDATE ON iam.separated_duty FOR EACH ROW EXECUTE FUNCTION iam.policy_changed_only_by_ledger();

--
-- Name: session session_guard; Type: TRIGGER; Schema: iam; Owner: -
--

CREATE TRIGGER session_guard BEFORE UPDATE ON iam.session FOR EACH ROW EXECUTE FUNCTION iam.session_guard();

--
-- Name: api_key compartments_registered; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF forced_compartment ON ingest.api_key FOR EACH ROW WHEN ((new.forced_compartment IS NOT NULL)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('forced_compartment', 'scalar');

--
-- Name: dead_letter compartments_registered; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON ingest.dead_letter FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: record compartments_registered; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON ingest.record FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: provider_exposure_change exposure_change_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER exposure_change_guarded BEFORE DELETE OR UPDATE ON ingest.provider_exposure_change FOR EACH ROW EXECUTE FUNCTION ingest.guard_exposure_change();

--
-- Name: provider_exposure_change exposure_change_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER exposure_change_no_truncate BEFORE TRUNCATE ON ingest.provider_exposure_change FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_exposure_change();

--
-- Name: lookup_attempt lookup_attempt_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_attempt_guarded BEFORE DELETE OR UPDATE ON ingest.lookup_attempt FOR EACH ROW EXECUTE FUNCTION ingest.lookup_attempt_append_only();

--
-- Name: lookup_attempt lookup_attempt_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_attempt_no_truncate BEFORE TRUNCATE ON ingest.lookup_attempt FOR EACH STATEMENT EXECUTE FUNCTION ingest.lookup_attempt_append_only();

--
-- Name: lookup_batch lookup_batch_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_batch_guarded BEFORE DELETE OR UPDATE ON ingest.lookup_batch FOR EACH ROW EXECUTE FUNCTION ingest.guard_lookup_batch();

--
-- Name: lookup_batch lookup_batch_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_batch_no_truncate BEFORE TRUNCATE ON ingest.lookup_batch FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_lookup_batch();

--
-- Name: lookup lookup_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_guarded BEFORE INSERT OR DELETE OR UPDATE ON ingest.lookup FOR EACH ROW EXECUTE FUNCTION ingest.lookup_is_a_record();

--
-- Name: lookup lookup_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_no_truncate BEFORE TRUNCATE ON ingest.lookup FOR EACH STATEMENT EXECUTE FUNCTION ingest.lookup_is_a_record();

--
-- Name: lookup lookup_result_dominates; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_result_dominates BEFORE INSERT OR UPDATE OF result_id ON ingest.lookup FOR EACH ROW EXECUTE FUNCTION ingest.lookup_result_dominates();

--
-- Name: lookup_result lookup_result_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_result_guarded BEFORE DELETE OR UPDATE ON ingest.lookup_result FOR EACH ROW EXECUTE FUNCTION ingest.guard_lookup_result();

--
-- Name: lookup_result lookup_result_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_result_no_truncate BEFORE TRUNCATE ON ingest.lookup_result FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_lookup_result();

--
-- Name: lookup_result lookup_result_tlp; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_result_tlp BEFORE INSERT OR UPDATE ON ingest.lookup_result FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: lookup lookup_tlp; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER lookup_tlp BEFORE INSERT OR UPDATE ON ingest.lookup FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: provider provider_guarded; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER provider_guarded BEFORE DELETE OR UPDATE ON ingest.provider FOR EACH ROW EXECUTE FUNCTION ingest.guard_provider();

--
-- Name: provider provider_no_truncate; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER provider_no_truncate BEFORE TRUNCATE ON ingest.provider FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_provider();

--
-- Name: provider provider_starts_unapproved; Type: TRIGGER; Schema: ingest; Owner: -
--

CREATE TRIGGER provider_starts_unapproved BEFORE INSERT ON ingest.provider FOR EACH ROW EXECUTE FUNCTION ingest.provider_starts_unapproved();

--
-- Name: sample compartments_registered; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON lab.sample FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: yara_ruleset compartments_registered; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON lab.yara_ruleset FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: detonation detonation_guard; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER detonation_guard BEFORE DELETE OR UPDATE ON lab.detonation FOR EACH ROW EXECUTE FUNCTION lab.guard_detonation();

--
-- Name: detonation detonation_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER detonation_no_truncate BEFORE TRUNCATE ON lab.detonation FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_detonation();

--
-- Name: download_ticket download_ticket_guard; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER download_ticket_guard BEFORE UPDATE ON lab.download_ticket FOR EACH ROW EXECUTE FUNCTION lab.download_ticket_guard();

--
-- Name: preservation_authorisation preservation_authorisation_guarded; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER preservation_authorisation_guarded BEFORE DELETE OR UPDATE ON lab.preservation_authorisation FOR EACH ROW EXECUTE FUNCTION lab.guard_preservation_authorisation();

--
-- Name: preservation_authorisation preservation_authorisation_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER preservation_authorisation_no_truncate BEFORE TRUNCATE ON lab.preservation_authorisation FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_preservation_authorisation();

--
-- Name: sample_access sample_access_append_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_access_append_only BEFORE DELETE OR UPDATE ON lab.sample_access FOR EACH ROW EXECUTE FUNCTION lab.block_access_mutation();

--
-- Name: sample_access sample_access_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_access_no_truncate BEFORE TRUNCATE ON lab.sample_access FOR EACH STATEMENT EXECUTE FUNCTION lab.block_access_mutation();

--
-- Name: sample sample_match_is_permanent; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_match_is_permanent BEFORE UPDATE OF screening_outcome, screening_bytes_absent_at ON lab.sample FOR EACH ROW EXECUTE FUNCTION lab.guard_screening_outcome();

--
-- Name: sample sample_tlp; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_tlp BEFORE INSERT OR UPDATE ON lab.sample FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: screening_hash screening_hash_delete_guard; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_hash_delete_guard AFTER DELETE ON lab.screening_hash REFERENCING OLD TABLE AS gone FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_screening_hash_delete();

--
-- Name: screening_hash screening_hash_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_hash_no_truncate BEFORE TRUNCATE ON lab.screening_hash FOR EACH STATEMENT EXECUTE FUNCTION lab.refuse_screening_hash_change();

--
-- Name: screening_hash screening_hash_no_update; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_hash_no_update BEFORE UPDATE ON lab.screening_hash FOR EACH STATEMENT EXECUTE FUNCTION lab.refuse_screening_hash_change();

--
-- Name: screening_list screening_list_guard; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_list_guard BEFORE DELETE OR UPDATE ON lab.screening_list FOR EACH ROW EXECUTE FUNCTION lab.guard_screening_list();

--
-- Name: screening_list screening_list_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_list_no_truncate BEFORE TRUNCATE ON lab.screening_list FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_screening_list();

--
-- Name: screening_result screening_result_append_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_result_append_only BEFORE DELETE OR UPDATE ON lab.screening_result FOR EACH ROW EXECUTE FUNCTION lab.block_screening_mutation();

--
-- Name: screening_result screening_result_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_result_no_truncate BEFORE TRUNCATE ON lab.screening_result FOR EACH STATEMENT EXECUTE FUNCTION lab.block_screening_mutation();

--
-- Name: screening_review screening_review_append_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_review_append_only BEFORE DELETE OR UPDATE ON lab.screening_review FOR EACH ROW EXECUTE FUNCTION lab.block_screening_mutation();

--
-- Name: screening_review screening_review_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER screening_review_no_truncate BEFORE TRUNCATE ON lab.screening_review FOR EACH STATEMENT EXECUTE FUNCTION lab.block_screening_mutation();

--
-- Name: yara_activation yara_activation_guarded; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_activation_guarded BEFORE DELETE OR UPDATE ON lab.yara_activation FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_activation();

--
-- Name: yara_activation yara_activation_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_activation_no_truncate BEFORE TRUNCATE ON lab.yara_activation FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_activation();

--
-- Name: yara_activation yara_activation_rules; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_activation_rules BEFORE INSERT ON lab.yara_activation FOR EACH ROW EXECUTE FUNCTION lab.yara_activation_rules();

--
-- Name: yara_compiled yara_compiled_insert_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_compiled_insert_only BEFORE DELETE OR UPDATE ON lab.yara_compiled FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_insert_only();

--
-- Name: yara_compiled yara_compiled_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_compiled_no_truncate BEFORE TRUNCATE ON lab.yara_compiled FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_insert_only();

--
-- Name: yara_compiled_rejected yara_compiled_rejected_insert_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_compiled_rejected_insert_only BEFORE DELETE OR UPDATE ON lab.yara_compiled_rejected FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_insert_only();

--
-- Name: yara_compiled_rejected yara_compiled_rejected_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_compiled_rejected_no_truncate BEFORE TRUNCATE ON lab.yara_compiled_rejected FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_insert_only();

--
-- Name: yara_ruleset yara_ruleset_guarded; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_ruleset_guarded BEFORE DELETE OR UPDATE ON lab.yara_ruleset FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_ruleset();

--
-- Name: yara_ruleset yara_ruleset_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_ruleset_no_truncate BEFORE TRUNCATE ON lab.yara_ruleset FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_ruleset();

--
-- Name: yara_ruleset_version yara_ruleset_version_guarded; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_ruleset_version_guarded BEFORE DELETE OR UPDATE ON lab.yara_ruleset_version FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_ruleset_version();

--
-- Name: yara_ruleset_version yara_ruleset_version_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER yara_ruleset_version_no_truncate BEFORE TRUNCATE ON lab.yara_ruleset_version FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_ruleset_version();

--
-- Name: notification compartments_registered; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON notify.notification FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: jira_event jira_event_guarded; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER jira_event_guarded BEFORE DELETE OR UPDATE ON notify.jira_event FOR EACH ROW EXECUTE FUNCTION notify.guard_jira_event();

--
-- Name: jira_event jira_event_no_truncate; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER jira_event_no_truncate BEFORE TRUNCATE ON notify.jira_event FOR EACH STATEMENT EXECUTE FUNCTION notify.guard_jira_event();

--
-- Name: jira_link jira_link_guarded; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER jira_link_guarded BEFORE DELETE OR UPDATE ON notify.jira_link FOR EACH ROW EXECUTE FUNCTION notify.guard_jira_link();

--
-- Name: jira_link jira_link_no_truncate; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER jira_link_no_truncate BEFORE TRUNCATE ON notify.jira_link FOR EACH STATEMENT EXECUTE FUNCTION notify.guard_jira_link();

--
-- Name: notification notification_announce; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER notification_announce AFTER INSERT ON notify.notification REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT EXECUTE FUNCTION notify.announce_notification();

--
-- Name: community_assignment community_assignment_metric_run_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.community_assignment
    ADD CONSTRAINT community_assignment_metric_run_id_fkey FOREIGN KEY (metric_run_id) REFERENCES analytics.metric_run(id) ON DELETE CASCADE;

--
-- Name: community_assignment community_assignment_node_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.community_assignment
    ADD CONSTRAINT community_assignment_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id) ON DELETE CASCADE;

--
-- Name: layout_position layout_position_node_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.layout_position
    ADD CONSTRAINT layout_position_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id) ON DELETE CASCADE;

--
-- Name: layout_position layout_position_projection_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.layout_position
    ADD CONSTRAINT layout_position_projection_id_fkey FOREIGN KEY (projection_id) REFERENCES analytics.projection(id) ON DELETE CASCADE;

--
-- Name: metric_run metric_run_projection_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.metric_run
    ADD CONSTRAINT metric_run_projection_id_fkey FOREIGN KEY (projection_id) REFERENCES analytics.projection(id) ON DELETE CASCADE;

--
-- Name: node_metric node_metric_metric_run_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.node_metric
    ADD CONSTRAINT node_metric_metric_run_id_fkey FOREIGN KEY (metric_run_id) REFERENCES analytics.metric_run(id) ON DELETE CASCADE;

--
-- Name: node_metric node_metric_node_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.node_metric
    ADD CONSTRAINT node_metric_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id) ON DELETE CASCADE;

--
-- Name: projection projection_case_id_fkey; Type: FK CONSTRAINT; Schema: analytics; Owner: -
--

ALTER TABLE ONLY analytics.projection
    ADD CONSTRAINT projection_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: collection_account collection_account_egress_fk; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_account
    ADD CONSTRAINT collection_account_egress_fk FOREIGN KEY (egress_profile_id) REFERENCES collect.egress_profile(id);

--
-- Name: collection_account collection_account_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_account
    ADD CONSTRAINT collection_account_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: collection_authority collection_authority_collection_account_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority
    ADD CONSTRAINT collection_authority_collection_account_id_fkey FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: collection_authority collection_authority_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority
    ADD CONSTRAINT collection_authority_confirmed_by_fkey FOREIGN KEY (confirmed_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority collection_authority_recorded_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority
    ADD CONSTRAINT collection_authority_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority collection_authority_revoked_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority
    ADD CONSTRAINT collection_authority_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority_target collection_authority_target_added_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_added_by_fkey FOREIGN KEY (added_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority_target collection_authority_target_authority_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_authority_id_fkey FOREIGN KEY (authority_id) REFERENCES collect.collection_authority(id);

--
-- Name: collection_authority_target collection_authority_target_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_confirmed_by_fkey FOREIGN KEY (confirmed_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority_target collection_authority_target_revoked_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES iam.app_user(id);

--
-- Name: collection_authority_target collection_authority_target_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: collection_authority_target collection_authority_target_target_egress_profile_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_authority_target
    ADD CONSTRAINT collection_authority_target_target_egress_profile_id_fkey FOREIGN KEY (target_egress_profile_id) REFERENCES collect.egress_profile(id);

--
-- Name: collection_run collection_run_authority_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_authority_id_fkey FOREIGN KEY (authority_id) REFERENCES collect.collection_authority(id);

--
-- Name: collection_run collection_run_authority_target_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_authority_target_id_fkey FOREIGN KEY (authority_target_id) REFERENCES collect.collection_authority_target(id);

--
-- Name: collection_run collection_run_collection_account_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_collection_account_id_fkey FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: collection_run collection_run_egress_profile_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_egress_profile_id_fkey FOREIGN KEY (egress_profile_id) REFERENCES collect.egress_profile(id);

--
-- Name: collection_run collection_run_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: collection_run collection_run_watch_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_watch_id_fkey FOREIGN KEY (watch_id) REFERENCES collect.watch(id);

--
-- Name: document document_collection_run_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_collection_run_id_fkey FOREIGN KEY (collection_run_id) REFERENCES collect.collection_run(id);

--
-- Name: document_embedding document_embedding_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document_embedding
    ADD CONSTRAINT document_embedding_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: document_embedding document_embedding_space_id_slot_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document_embedding
    ADD CONSTRAINT document_embedding_space_id_slot_fkey FOREIGN KEY (space_id, slot) REFERENCES core.embedding_space(id, slot);

--
-- Name: document document_legal_hold_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_legal_hold_by_fkey FOREIGN KEY (legal_hold_by) REFERENCES iam.app_user(id);

--
-- Name: document document_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: document document_supersedes_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_supersedes_id_fkey FOREIGN KEY (supersedes_id) REFERENCES collect.document(id);

--
-- Name: document document_watch_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.document
    ADD CONSTRAINT document_watch_id_fkey FOREIGN KEY (watch_id) REFERENCES collect.watch(id);

--
-- Name: egress_destination egress_destination_created_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_destination
    ADD CONSTRAINT egress_destination_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: egress_destination egress_destination_retired_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_destination
    ADD CONSTRAINT egress_destination_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: egress_destination egress_destination_route_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_destination
    ADD CONSTRAINT egress_destination_route_id_fkey FOREIGN KEY (route_id) REFERENCES collect.egress_integration_route(id);

--
-- Name: egress_integration_route egress_integration_route_created_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_integration_route
    ADD CONSTRAINT egress_integration_route_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: egress_integration_route egress_integration_route_retired_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_integration_route
    ADD CONSTRAINT egress_integration_route_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: egress_integration_route egress_integration_route_updated_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_integration_route
    ADD CONSTRAINT egress_integration_route_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES iam.app_user(id);

--
-- Name: egress_profile egress_profile_created_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: egress_profile egress_profile_exit_sealed_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_exit_sealed_by_fkey FOREIGN KEY (exit_sealed_by) REFERENCES iam.app_user(id);

--
-- Name: egress_profile egress_profile_retired_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: egress_profile egress_profile_updated_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.egress_profile
    ADD CONSTRAINT egress_profile_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES iam.app_user(id);

--
-- Name: extraction extraction_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.extraction
    ADD CONSTRAINT extraction_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: extraction extraction_selector_type_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.extraction
    ADD CONSTRAINT extraction_selector_type_fkey FOREIGN KEY (selector_type) REFERENCES core.selector_type(key);

--
-- Name: forum_member forum_member_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.forum_member
    ADD CONSTRAINT forum_member_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: forum_post forum_post_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.forum_post
    ADD CONSTRAINT forum_post_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: proposal proposal_applied_edge_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_applied_edge_id_fkey FOREIGN KEY (applied_edge_id) REFERENCES core.edge(id);

--
-- Name: proposal proposal_applied_node_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_applied_node_id_fkey FOREIGN KEY (applied_node_id) REFERENCES core.node(id);

--
-- Name: proposal proposal_case_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: proposal proposal_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id);

--
-- Name: proposal proposal_lookup_result_fk; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.proposal
    ADD CONSTRAINT proposal_lookup_result_fk FOREIGN KEY (lookup_result_id) REFERENCES ingest.lookup_result(id) NOT VALID;

--
-- Name: source source_collection_account_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.source
    ADD CONSTRAINT source_collection_account_id_fkey FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: source source_egress_profile_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.source
    ADD CONSTRAINT source_egress_profile_id_fkey FOREIGN KEY (egress_profile_id) REFERENCES collect.egress_profile(id);

--
-- Name: telegram_chat telegram_chat_access_hash_account_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_access_hash_account_id_fkey FOREIGN KEY (access_hash_account_id) REFERENCES collect.collection_account(id);

--
-- Name: telegram_chat telegram_chat_joined_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_joined_by_fkey FOREIGN KEY (joined_by) REFERENCES iam.app_user(id);

--
-- Name: telegram_chat telegram_chat_resolved_by_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES iam.app_user(id);

--
-- Name: telegram_chat telegram_chat_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_chat
    ADD CONSTRAINT telegram_chat_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: telegram_message telegram_message_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_message
    ADD CONSTRAINT telegram_message_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE RESTRICT;

--
-- Name: telegram_message telegram_message_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.telegram_message
    ADD CONSTRAINT telegram_message_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: watch watch_case_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch
    ADD CONSTRAINT watch_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: watch watch_collection_account_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch
    ADD CONSTRAINT watch_collection_account_id_fkey FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: watch_hit watch_hit_document_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch_hit
    ADD CONSTRAINT watch_hit_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: watch_hit watch_hit_watch_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch_hit
    ADD CONSTRAINT watch_hit_watch_id_fkey FOREIGN KEY (watch_id) REFERENCES collect.watch(id) ON DELETE CASCADE;

--
-- Name: watch watch_source_id_fkey; Type: FK CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.watch
    ADD CONSTRAINT watch_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: channel_binding channel_binding_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: channel_binding channel_binding_created_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: channel_binding channel_binding_identity_node_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_identity_node_id_fkey FOREIGN KEY (identity_node_id) REFERENCES core.node(id);

--
-- Name: channel_binding channel_binding_platform_key_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.channel_binding
    ADD CONSTRAINT channel_binding_platform_key_fkey FOREIGN KEY (platform_key) REFERENCES comms.platform(key);

--
-- Name: contact_block contact_block_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: contact_block contact_block_created_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: contact_block contact_block_document_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_document_id_fkey FOREIGN KEY (document_id) REFERENCES collect.document(id);

--
-- Name: contact_block_entry contact_block_entry_block_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_block_id_fkey FOREIGN KEY (block_id) REFERENCES comms.contact_block(id) ON DELETE CASCADE;

--
-- Name: contact_block_entry contact_block_entry_platform_key_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_platform_key_fkey FOREIGN KEY (platform_key) REFERENCES comms.platform(key);

--
-- Name: contact_block_entry contact_block_entry_proposal_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES collect.proposal(id);

--
-- Name: contact_block_entry contact_block_entry_stoplist_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block_entry
    ADD CONSTRAINT contact_block_entry_stoplist_id_fkey FOREIGN KEY (stoplist_id) REFERENCES comms.service_selector(id);

--
-- Name: contact_block contact_block_evidence_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: contact_block contact_block_publisher_identity_node_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.contact_block
    ADD CONSTRAINT contact_block_publisher_identity_node_id_fkey FOREIGN KEY (publisher_identity_node_id) REFERENCES core.node(id);

--
-- Name: conversation conversation_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.conversation
    ADD CONSTRAINT conversation_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: conversation conversation_collection_account_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.conversation
    ADD CONSTRAINT conversation_collection_account_id_fkey FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: conversation conversation_conversation_node_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.conversation
    ADD CONSTRAINT conversation_conversation_node_id_fkey FOREIGN KEY (conversation_node_id) REFERENCES core.node(id);

--
-- Name: conversation conversation_platform_key_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.conversation
    ADD CONSTRAINT conversation_platform_key_fkey FOREIGN KEY (platform_key) REFERENCES comms.platform(key);

--
-- Name: device_fingerprint device_fingerprint_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.device_fingerprint
    ADD CONSTRAINT device_fingerprint_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: device_fingerprint device_fingerprint_device_node_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.device_fingerprint
    ADD CONSTRAINT device_fingerprint_device_node_id_fkey FOREIGN KEY (device_node_id) REFERENCES core.node(id);

--
-- Name: device_fingerprint device_fingerprint_platform_key_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.device_fingerprint
    ADD CONSTRAINT device_fingerprint_platform_key_fkey FOREIGN KEY (platform_key) REFERENCES comms.platform(key);

--
-- Name: message message_conversation_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.message
    ADD CONSTRAINT message_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES comms.conversation(id) ON DELETE CASCADE;

--
-- Name: participant participant_channel_binding_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.participant
    ADD CONSTRAINT participant_channel_binding_id_fkey FOREIGN KEY (channel_binding_id) REFERENCES comms.channel_binding(id);

--
-- Name: participant participant_conversation_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.participant
    ADD CONSTRAINT participant_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES comms.conversation(id) ON DELETE CASCADE;

--
-- Name: participant participant_identity_node_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.participant
    ADD CONSTRAINT participant_identity_node_id_fkey FOREIGN KEY (identity_node_id) REFERENCES core.node(id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_binding_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_binding_same_case FOREIGN KEY (channel_binding_id, case_id) REFERENCES comms.channel_binding(id, case_id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_block_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_block_same_case FOREIGN KEY (contact_block_id, case_id) REFERENCES comms.contact_block(id, case_id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_evidence_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_lookup_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_lookup_same_case FOREIGN KEY (lookup_id, case_id) REFERENCES comms.pgp_key_lookup(id, case_id);

--
-- Name: pgp_key_acquisition pgp_key_acquisition_requested_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_acquisition
    ADD CONSTRAINT pgp_key_acquisition_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_key pgp_key_acquisition_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_acquisition_same_case FOREIGN KEY (acquisition_id, case_id) REFERENCES comms.pgp_key_acquisition(id, case_id);

--
-- Name: pgp_key pgp_key_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_confirmed_by_fkey FOREIGN KEY (confirmed_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_key pgp_key_confirmed_contact_block_entry_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_confirmed_contact_block_entry_id_fkey FOREIGN KEY (confirmed_contact_block_entry_id) REFERENCES comms.contact_block_entry(id);

--
-- Name: pgp_key_lookup pgp_key_lookup_binding_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_binding_same_case FOREIGN KEY (channel_binding_id, case_id) REFERENCES comms.channel_binding(id, case_id);

--
-- Name: pgp_key_lookup pgp_key_lookup_block_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_block_same_case FOREIGN KEY (contact_block_id, case_id) REFERENCES comms.contact_block(id, case_id);

--
-- Name: pgp_key_lookup pgp_key_lookup_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: pgp_key_lookup pgp_key_lookup_decided_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_key_lookup pgp_key_lookup_requested_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key_lookup
    ADD CONSTRAINT pgp_key_lookup_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_key pgp_key_retired_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_key
    ADD CONSTRAINT pgp_key_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_verification pgp_verification_binding_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_binding_same_case FOREIGN KEY (channel_binding_id, case_id) REFERENCES comms.channel_binding(id, case_id);

--
-- Name: pgp_verification pgp_verification_block_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_block_same_case FOREIGN KEY (contact_block_id, case_id) REFERENCES comms.contact_block(id, case_id);

--
-- Name: pgp_verification pgp_verification_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: pgp_verification pgp_verification_channel_binding_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_channel_binding_id_fkey FOREIGN KEY (channel_binding_id) REFERENCES comms.channel_binding(id);

--
-- Name: pgp_verification pgp_verification_contact_block_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_contact_block_id_fkey FOREIGN KEY (contact_block_id) REFERENCES comms.contact_block(id);

--
-- Name: pgp_verification pgp_verification_created_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: pgp_verification pgp_verification_key_same_case; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.pgp_verification
    ADD CONSTRAINT pgp_verification_key_same_case FOREIGN KEY (pgp_key_id, case_id) REFERENCES comms.pgp_key(id, case_id);

--
-- Name: service_selector service_selector_added_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.service_selector
    ADD CONSTRAINT service_selector_added_by_fkey FOREIGN KEY (added_by) REFERENCES iam.app_user(id);

--
-- Name: service_selector service_selector_case_id_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.service_selector
    ADD CONSTRAINT service_selector_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: service_selector service_selector_platform_key_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.service_selector
    ADD CONSTRAINT service_selector_platform_key_fkey FOREIGN KEY (platform_key) REFERENCES comms.platform(key);

--
-- Name: service_selector service_selector_retired_by_fkey; Type: FK CONSTRAINT; Schema: comms; Owner: -
--

ALTER TABLE ONLY comms.service_selector
    ADD CONSTRAINT service_selector_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: approval_request approval_request_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.approval_request
    ADD CONSTRAINT approval_request_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: approval_request approval_request_decided_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.approval_request
    ADD CONSTRAINT approval_request_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES iam.app_user(id);

--
-- Name: approval_request approval_request_requested_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.approval_request
    ADD CONSTRAINT approval_request_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: assertion assertion_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: assertion assertion_created_by_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: assertion assertion_document_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_document_fk FOREIGN KEY (document_id) REFERENCES collect.document(id);

--
-- Name: assertion assertion_edge_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES core.edge(id);

--
-- Name: assertion_embedding assertion_embedding_assertion_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion_embedding
    ADD CONSTRAINT assertion_embedding_assertion_id_fkey FOREIGN KEY (assertion_id) REFERENCES core.assertion(id) ON DELETE CASCADE;

--
-- Name: assertion_embedding assertion_embedding_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion_embedding
    ADD CONSTRAINT assertion_embedding_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id) ON DELETE CASCADE;

--
-- Name: assertion_embedding assertion_embedding_space_id_slot_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion_embedding
    ADD CONSTRAINT assertion_embedding_space_id_slot_fkey FOREIGN KEY (space_id, slot) REFERENCES core.embedding_space(id, slot);

--
-- Name: assertion assertion_evidence_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_evidence_fk FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: assertion assertion_lookup_result_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_lookup_result_fk FOREIGN KEY (lookup_result_id) REFERENCES ingest.lookup_result(id) NOT VALID;

--
-- Name: assertion assertion_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: assertion assertion_source_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_source_fk FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: assertion assertion_superseded_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_superseded_by_fkey FOREIGN KEY (superseded_by) REFERENCES core.assertion(id);

--
-- Name: assumption assumption_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assumption
    ADD CONSTRAINT assumption_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id) ON DELETE CASCADE;

--
-- Name: assumption assumption_made_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assumption
    ADD CONSTRAINT assumption_made_by_fkey FOREIGN KEY (made_by) REFERENCES iam.app_user(id);

--
-- Name: assumption assumption_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assumption
    ADD CONSTRAINT assumption_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES iam.app_user(id);

--
-- Name: case case_deputy_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core."case"
    ADD CONSTRAINT case_deputy_fk FOREIGN KEY (deputy_user_id) REFERENCES iam.app_user(id);

--
-- Name: case case_owner_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core."case"
    ADD CONSTRAINT case_owner_fk FOREIGN KEY (owner_user_id) REFERENCES iam.app_user(id);

--
-- Name: edge edge_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: edge edge_created_by_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: edge edge_dst_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_dst_node_id_fkey FOREIGN KEY (dst_node_id) REFERENCES core.node(id);

--
-- Name: edge edge_edge_type_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_edge_type_fkey FOREIGN KEY (edge_type) REFERENCES core.edge_type(key);

--
-- Name: edge edge_src_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.edge
    ADD CONSTRAINT edge_src_node_id_fkey FOREIGN KEY (src_node_id) REFERENCES core.node(id);

--
-- Name: embedding_space embedding_space_activated_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_space
    ADD CONSTRAINT embedding_space_activated_by_fkey FOREIGN KEY (activated_by) REFERENCES iam.app_user(id);

--
-- Name: embedding_space embedding_space_created_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_space
    ADD CONSTRAINT embedding_space_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: embedding_space embedding_space_retired_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.embedding_space
    ADD CONSTRAINT embedding_space_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: evidence evidence_acquired_by_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_acquired_by_fk FOREIGN KEY (acquired_by) REFERENCES iam.app_user(id);

--
-- Name: evidence evidence_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: evidence evidence_collection_account_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_collection_account_fk FOREIGN KEY (collection_account_id) REFERENCES collect.collection_account(id);

--
-- Name: evidence evidence_collection_run_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence
    ADD CONSTRAINT evidence_collection_run_fk FOREIGN KEY (collection_run_id) REFERENCES collect.collection_run(id);

--
-- Name: evidence_custody evidence_custody_actor_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_custody
    ADD CONSTRAINT evidence_custody_actor_fk FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

--
-- Name: evidence_custody evidence_custody_evidence_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_custody
    ADD CONSTRAINT evidence_custody_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: evidence_embedding evidence_embedding_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_embedding
    ADD CONSTRAINT evidence_embedding_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id) ON DELETE CASCADE;

--
-- Name: evidence_embedding evidence_embedding_evidence_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_embedding
    ADD CONSTRAINT evidence_embedding_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id) ON DELETE CASCADE;

--
-- Name: evidence_embedding evidence_embedding_space_id_slot_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_embedding
    ADD CONSTRAINT evidence_embedding_space_id_slot_fkey FOREIGN KEY (space_id, slot) REFERENCES core.embedding_space(id, slot);

--
-- Name: evidence_link evidence_link_edge_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_link
    ADD CONSTRAINT evidence_link_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES core.edge(id);

--
-- Name: evidence_link evidence_link_evidence_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_link
    ADD CONSTRAINT evidence_link_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id) ON DELETE CASCADE;

--
-- Name: evidence_link evidence_link_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.evidence_link
    ADD CONSTRAINT evidence_link_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: hypothesis hypothesis_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.hypothesis
    ADD CONSTRAINT hypothesis_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: hypothesis_evidence hypothesis_evidence_assertion_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.hypothesis_evidence
    ADD CONSTRAINT hypothesis_evidence_assertion_id_fkey FOREIGN KEY (assertion_id) REFERENCES core.assertion(id);

--
-- Name: hypothesis_evidence hypothesis_evidence_hypothesis_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.hypothesis_evidence
    ADD CONSTRAINT hypothesis_evidence_hypothesis_id_fkey FOREIGN KEY (hypothesis_id) REFERENCES core.hypothesis(id) ON DELETE CASCADE;

--
-- Name: node node_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node
    ADD CONSTRAINT node_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id) ON DELETE RESTRICT;

--
-- Name: node node_created_by_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node
    ADD CONSTRAINT node_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: node_merge node_merge_basis_selector_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge
    ADD CONSTRAINT node_merge_basis_selector_id_fkey FOREIGN KEY (basis_selector_id) REFERENCES core.selector(id);

--
-- Name: node_merge node_merge_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge
    ADD CONSTRAINT node_merge_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: node_merge_edge node_merge_edge_edge_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge_edge
    ADD CONSTRAINT node_merge_edge_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES core.edge(id);

--
-- Name: node_merge_edge node_merge_edge_merge_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge_edge
    ADD CONSTRAINT node_merge_edge_merge_id_fkey FOREIGN KEY (merge_id) REFERENCES core.node_merge(id) ON DELETE CASCADE;

--
-- Name: node_merge_edge node_merge_edge_original_dst_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge_edge
    ADD CONSTRAINT node_merge_edge_original_dst_node_id_fkey FOREIGN KEY (original_dst_node_id) REFERENCES core.node(id);

--
-- Name: node_merge_edge node_merge_edge_original_src_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge_edge
    ADD CONSTRAINT node_merge_edge_original_src_node_id_fkey FOREIGN KEY (original_src_node_id) REFERENCES core.node(id);

--
-- Name: node_merge node_merge_source_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge
    ADD CONSTRAINT node_merge_source_node_id_fkey FOREIGN KEY (source_node_id) REFERENCES core.node(id);

--
-- Name: node_merge node_merge_target_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_merge
    ADD CONSTRAINT node_merge_target_node_id_fkey FOREIGN KEY (target_node_id) REFERENCES core.node(id);

--
-- Name: node node_merged_into_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node
    ADD CONSTRAINT node_merged_into_id_fkey FOREIGN KEY (merged_into_id) REFERENCES core.node(id);

--
-- Name: node node_node_type_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node
    ADD CONSTRAINT node_node_type_fkey FOREIGN KEY (node_type) REFERENCES core.node_type(key);

--
-- Name: node_set node_set_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_set
    ADD CONSTRAINT node_set_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: node_set_member node_set_member_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_set_member
    ADD CONSTRAINT node_set_member_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id) ON DELETE CASCADE;

--
-- Name: node_set_member node_set_member_set_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.node_set_member
    ADD CONSTRAINT node_set_member_set_id_fkey FOREIGN KEY (set_id) REFERENCES core.node_set(id) ON DELETE CASCADE;

--
-- Name: purge_tombstone purge_tombstone_approval_request_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.purge_tombstone
    ADD CONSTRAINT purge_tombstone_approval_request_id_fkey FOREIGN KEY (approval_request_id) REFERENCES core.approval_request(id);

--
-- Name: purge_tombstone purge_tombstone_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.purge_tombstone
    ADD CONSTRAINT purge_tombstone_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: purge_tombstone purge_tombstone_purged_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.purge_tombstone
    ADD CONSTRAINT purge_tombstone_purged_by_fkey FOREIGN KEY (purged_by) REFERENCES iam.app_user(id);

--
-- Name: retention_rule retention_rule_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.retention_rule
    ADD CONSTRAINT retention_rule_confirmed_by_fkey FOREIGN KEY (confirmed_by) REFERENCES iam.app_user(id);

--
-- Name: selector selector_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector
    ADD CONSTRAINT selector_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: selector selector_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector
    ADD CONSTRAINT selector_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: selector selector_selector_type_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.selector
    ADD CONSTRAINT selector_selector_type_fkey FOREIGN KEY (selector_type) REFERENCES core.selector_type(key);

--
-- Name: tag_assignment tag_assignment_document_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag_assignment
    ADD CONSTRAINT tag_assignment_document_fk FOREIGN KEY (document_id) REFERENCES collect.document(id) ON DELETE CASCADE;

--
-- Name: tag_assignment tag_assignment_edge_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag_assignment
    ADD CONSTRAINT tag_assignment_edge_id_fkey FOREIGN KEY (edge_id) REFERENCES core.edge(id);

--
-- Name: tag_assignment tag_assignment_evidence_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag_assignment
    ADD CONSTRAINT tag_assignment_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: tag_assignment tag_assignment_node_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag_assignment
    ADD CONSTRAINT tag_assignment_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: tag_assignment tag_assignment_tag_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag_assignment
    ADD CONSTRAINT tag_assignment_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES core.tag(id) ON DELETE CASCADE;

--
-- Name: tag tag_case_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag
    ADD CONSTRAINT tag_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: tag tag_parent_id_fkey; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.tag
    ADD CONSTRAINT tag_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES core.tag(id);

--
-- Name: call_record call_record_case_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: call_record call_record_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: call_record call_record_lure_node_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_lure_node_id_fkey FOREIGN KEY (lure_node_id) REFERENCES core.node(id);

--
-- Name: call_record call_record_recorded_by_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES iam.app_user(id);

--
-- Name: call_record call_record_recording_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_recording_evidence_id_fkey FOREIGN KEY (recording_evidence_id) REFERENCES core.evidence(id);

--
-- Name: call_record call_record_victim_node_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.call_record
    ADD CONSTRAINT call_record_victim_node_id_fkey FOREIGN KEY (victim_node_id) REFERENCES core.node(id);

--
-- Name: capture capture_captured_by_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_captured_by_fkey FOREIGN KEY (captured_by) REFERENCES iam.app_user(id);

--
-- Name: capture capture_case_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: capture capture_dom_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_dom_evidence_id_fkey FOREIGN KEY (dom_evidence_id) REFERENCES core.evidence(id);

--
-- Name: capture capture_egress_profile_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_egress_profile_id_fkey FOREIGN KEY (egress_profile_id) REFERENCES collect.egress_profile(id);

--
-- Name: capture capture_har_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_har_evidence_id_fkey FOREIGN KEY (har_evidence_id) REFERENCES core.evidence(id);

--
-- Name: capture_hop capture_hop_capture_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture_hop
    ADD CONSTRAINT capture_hop_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES deception.capture(id) ON DELETE CASCADE;

--
-- Name: capture capture_screenshot_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.capture
    ADD CONSTRAINT capture_screenshot_evidence_id_fkey FOREIGN KEY (screenshot_evidence_id) REFERENCES core.evidence(id);

--
-- Name: email_attachment email_attachment_message_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_attachment
    ADD CONSTRAINT email_attachment_message_id_fkey FOREIGN KEY (message_id) REFERENCES deception.email_message(id) ON DELETE CASCADE;

--
-- Name: email_attachment email_attachment_sample_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_attachment
    ADD CONSTRAINT email_attachment_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: email_hop email_hop_message_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_hop
    ADD CONSTRAINT email_hop_message_id_fkey FOREIGN KEY (message_id) REFERENCES deception.email_message(id) ON DELETE CASCADE;

--
-- Name: email_message email_message_case_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_message
    ADD CONSTRAINT email_message_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: email_message email_message_evidence_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_message
    ADD CONSTRAINT email_message_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: email_message email_message_recorded_by_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_message
    ADD CONSTRAINT email_message_recorded_by_fkey FOREIGN KEY (recorded_by) REFERENCES iam.app_user(id);

--
-- Name: email_message email_message_victim_node_id_fkey; Type: FK CONSTRAINT; Schema: deception; Owner: -
--

ALTER TABLE ONLY deception.email_message
    ADD CONSTRAINT email_message_victim_node_id_fkey FOREIGN KEY (victim_node_id) REFERENCES core.node(id);

--
-- Name: break_glass break_glass_case_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.break_glass
    ADD CONSTRAINT break_glass_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: break_glass break_glass_revoked_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.break_glass
    ADD CONSTRAINT break_glass_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES iam.app_user(id);

--
-- Name: break_glass break_glass_user_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.break_glass
    ADD CONSTRAINT break_glass_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id);

--
-- Name: case_assignment case_assignment_case_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.case_assignment
    ADD CONSTRAINT case_assignment_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id) ON DELETE CASCADE;

--
-- Name: case_assignment case_assignment_role_key_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.case_assignment
    ADD CONSTRAINT case_assignment_role_key_fkey FOREIGN KEY (role_key) REFERENCES iam.role(key);

--
-- Name: case_assignment case_assignment_user_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.case_assignment
    ADD CONSTRAINT case_assignment_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id) ON DELETE CASCADE;

--
-- Name: compartment compartment_created_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.compartment
    ADD CONSTRAINT compartment_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id) ON DELETE SET NULL;

--
-- Name: dual_control_operation dual_control_operation_change_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_operation
    ADD CONSTRAINT dual_control_operation_change_id_fkey FOREIGN KEY (change_id) REFERENCES iam.dual_control_policy_change(id);

--
-- Name: dual_control_policy_change dual_control_policy_change_approval_request_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_approval_request_id_fkey FOREIGN KEY (approval_request_id) REFERENCES core.approval_request(id);

--
-- Name: dual_control_policy_change dual_control_policy_change_based_on_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_based_on_fkey FOREIGN KEY (based_on) REFERENCES iam.dual_control_policy_change(id);

--
-- Name: dual_control_policy_change dual_control_policy_change_countersigned_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_countersigned_by_fkey FOREIGN KEY (countersigned_by) REFERENCES iam.app_user(id);

--
-- Name: dual_control_policy_change dual_control_policy_change_requested_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_policy_change
    ADD CONSTRAINT dual_control_policy_change_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: role_permission role_permission_permission_key_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.role_permission
    ADD CONSTRAINT role_permission_permission_key_fkey FOREIGN KEY (permission_key) REFERENCES iam.permission(key) ON DELETE CASCADE;

--
-- Name: role_permission role_permission_role_key_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.role_permission
    ADD CONSTRAINT role_permission_role_key_fkey FOREIGN KEY (role_key) REFERENCES iam.role(key) ON DELETE CASCADE;

--
-- Name: separated_duty separated_duty_added_by_change_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.separated_duty
    ADD CONSTRAINT separated_duty_added_by_change_fkey FOREIGN KEY (added_by_change) REFERENCES iam.dual_control_policy_change(id);

--
-- Name: session session_user_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.session
    ADD CONSTRAINT session_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id) ON DELETE CASCADE;

--
-- Name: user_role user_role_role_key_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.user_role
    ADD CONSTRAINT user_role_role_key_fkey FOREIGN KEY (role_key) REFERENCES iam.role(key);

--
-- Name: user_role user_role_user_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.user_role
    ADD CONSTRAINT user_role_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id) ON DELETE CASCADE;

--
-- Name: webauthn_credential webauthn_credential_user_id_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.webauthn_credential
    ADD CONSTRAINT webauthn_credential_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id) ON DELETE CASCADE;

--
-- Name: api_key api_key_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.api_key
    ADD CONSTRAINT api_key_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES iam.app_user(id);

--
-- Name: api_key api_key_replaces_key_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.api_key
    ADD CONSTRAINT api_key_replaces_key_id_fkey FOREIGN KEY (replaces_key_id) REFERENCES ingest.api_key(id);

--
-- Name: api_key api_key_source_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.api_key
    ADD CONSTRAINT api_key_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: batch batch_api_key_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.batch
    ADD CONSTRAINT batch_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES ingest.api_key(id);

--
-- Name: dead_letter dead_letter_api_key_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.dead_letter
    ADD CONSTRAINT dead_letter_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES ingest.api_key(id);

--
-- Name: dead_letter dead_letter_batch_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.dead_letter
    ADD CONSTRAINT dead_letter_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES ingest.batch(id);

--
-- Name: dead_letter dead_letter_replayed_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.dead_letter
    ADD CONSTRAINT dead_letter_replayed_by_fkey FOREIGN KEY (replayed_by) REFERENCES iam.app_user(id);

--
-- Name: lookup_attempt lookup_attempt_lookup_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_attempt
    ADD CONSTRAINT lookup_attempt_lookup_id_fkey FOREIGN KEY (lookup_id) REFERENCES ingest.lookup(id);

--
-- Name: lookup_attempt lookup_attempt_provider_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_attempt
    ADD CONSTRAINT lookup_attempt_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ingest.provider(id);

--
-- Name: lookup lookup_authorised_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_authorised_by_fkey FOREIGN KEY (authorised_by) REFERENCES iam.app_user(id);

--
-- Name: lookup_batch lookup_batch_cancelled_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_batch
    ADD CONSTRAINT lookup_batch_cancelled_by_fkey FOREIGN KEY (cancelled_by) REFERENCES iam.app_user(id);

--
-- Name: lookup_batch lookup_batch_case_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_batch
    ADD CONSTRAINT lookup_batch_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: lookup lookup_batch_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES ingest.lookup_batch(id);

--
-- Name: lookup_batch lookup_batch_provider_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_batch
    ADD CONSTRAINT lookup_batch_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ingest.provider(id);

--
-- Name: lookup_batch lookup_batch_requested_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_batch
    ADD CONSTRAINT lookup_batch_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: lookup lookup_case_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: lookup lookup_node_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: lookup lookup_provider_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ingest.provider(id);

--
-- Name: lookup lookup_requested_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: lookup_result lookup_result_case_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: lookup_result lookup_result_filed_evidence_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_filed_evidence_id_fkey FOREIGN KEY (filed_evidence_id) REFERENCES core.evidence(id);

--
-- Name: lookup lookup_result_fk; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_result_fk FOREIGN KEY (result_id) REFERENCES ingest.lookup_result(id);

--
-- Name: lookup_result lookup_result_lookup_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_lookup_id_fkey FOREIGN KEY (lookup_id) REFERENCES ingest.lookup(id);

--
-- Name: lookup_result lookup_result_provider_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ingest.provider(id);

--
-- Name: lookup_result lookup_result_selector_type_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup_result
    ADD CONSTRAINT lookup_result_selector_type_fkey FOREIGN KEY (selector_type) REFERENCES core.selector_type(key);

--
-- Name: lookup lookup_sample_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: lookup lookup_selector_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_selector_id_fkey FOREIGN KEY (selector_id) REFERENCES core.selector(id);

--
-- Name: lookup lookup_selector_type_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_selector_type_fkey FOREIGN KEY (selector_type) REFERENCES core.selector_type(key);

--
-- Name: lookup lookup_signed_off_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.lookup
    ADD CONSTRAINT lookup_signed_off_by_fkey FOREIGN KEY (signed_off_by) REFERENCES iam.app_user(id);

--
-- Name: pii_authorisation pii_authorisation_case_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.pii_authorisation
    ADD CONSTRAINT pii_authorisation_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: pii_authorisation pii_authorisation_granted_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.pii_authorisation
    ADD CONSTRAINT pii_authorisation_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES iam.app_user(id);

--
-- Name: pii_authorisation pii_authorisation_granted_to_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.pii_authorisation
    ADD CONSTRAINT pii_authorisation_granted_to_fkey FOREIGN KEY (granted_to) REFERENCES iam.app_user(id);

--
-- Name: provider provider_created_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: provider_exposure_change provider_exposure_change_decided_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider_exposure_change
    ADD CONSTRAINT provider_exposure_change_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES iam.app_user(id);

--
-- Name: provider_exposure_change provider_exposure_change_provider_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider_exposure_change
    ADD CONSTRAINT provider_exposure_change_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES ingest.provider(id);

--
-- Name: provider_exposure_change provider_exposure_change_requested_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider_exposure_change
    ADD CONSTRAINT provider_exposure_change_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: provider provider_exposure_determined_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_exposure_determined_by_fkey FOREIGN KEY (exposure_determined_by) REFERENCES iam.app_user(id);

--
-- Name: provider provider_retired_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: provider provider_secret_set_by_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_secret_set_by_fkey FOREIGN KEY (secret_set_by) REFERENCES iam.app_user(id);

--
-- Name: provider provider_source_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.provider
    ADD CONSTRAINT provider_source_id_fkey FOREIGN KEY (source_id) REFERENCES collect.source(id);

--
-- Name: record record_batch_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.record
    ADD CONSTRAINT record_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES ingest.batch(id);

--
-- Name: record record_case_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.record
    ADD CONSTRAINT record_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: record record_duplicate_of_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.record
    ADD CONSTRAINT record_duplicate_of_fkey FOREIGN KEY (duplicate_of) REFERENCES ingest.record(id);

--
-- Name: victim_credential victim_credential_record_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.victim_credential
    ADD CONSTRAINT victim_credential_record_id_fkey FOREIGN KEY (record_id) REFERENCES ingest.record(id) ON DELETE CASCADE;

--
-- Name: victim_credential victim_credential_victim_node_id_fkey; Type: FK CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.victim_credential
    ADD CONSTRAINT victim_credential_victim_node_id_fkey FOREIGN KEY (victim_node_id) REFERENCES core.node(id);

--
-- Name: detonation detonation_analysis_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES lab.sample_analysis(id);

--
-- Name: detonation detonation_authorised_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_authorised_by_fkey FOREIGN KEY (authorised_by) REFERENCES iam.app_user(id);

--
-- Name: detonation detonation_cancelled_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_cancelled_by_fkey FOREIGN KEY (cancelled_by) REFERENCES iam.app_user(id);

--
-- Name: detonation detonation_requested_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: detonation detonation_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: detonation detonation_signed_off_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_signed_off_by_fkey FOREIGN KEY (signed_off_by) REFERENCES iam.app_user(id);

--
-- Name: download_ticket download_ticket_evidence_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.download_ticket
    ADD CONSTRAINT download_ticket_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

--
-- Name: download_ticket download_ticket_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.download_ticket
    ADD CONSTRAINT download_ticket_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: download_ticket download_ticket_user_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.download_ticket
    ADD CONSTRAINT download_ticket_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id);

--
-- Name: preservation_authorisation preservation_authorisation_granted_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.preservation_authorisation
    ADD CONSTRAINT preservation_authorisation_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES iam.app_user(id);

--
-- Name: preservation_authorisation preservation_authorisation_granted_to_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.preservation_authorisation
    ADD CONSTRAINT preservation_authorisation_granted_to_fkey FOREIGN KEY (granted_to) REFERENCES iam.app_user(id);

--
-- Name: preservation_authorisation preservation_authorisation_revoked_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.preservation_authorisation
    ADD CONSTRAINT preservation_authorisation_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES iam.app_user(id);

--
-- Name: preservation_authorisation preservation_authorisation_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.preservation_authorisation
    ADD CONSTRAINT preservation_authorisation_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: sample_access sample_access_actor_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_access
    ADD CONSTRAINT sample_access_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

--
-- Name: sample_access sample_access_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_access
    ADD CONSTRAINT sample_access_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: sample_analysis sample_analysis_analyst_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_analyst_id_fkey FOREIGN KEY (analyst_id) REFERENCES iam.app_user(id);

--
-- Name: sample_analysis sample_analysis_run_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_run_id_fkey FOREIGN KEY (run_id) REFERENCES lab.static_run(id);

--
-- Name: sample_analysis sample_analysis_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id) ON DELETE CASCADE;

--
-- Name: sample_analysis sample_analysis_yara_ruleset_version_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_yara_ruleset_version_id_fkey FOREIGN KEY (yara_ruleset_version_id) REFERENCES lab.yara_ruleset_version(id);

--
-- Name: sample sample_assigned_to_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES iam.app_user(id);

--
-- Name: sample sample_case_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: sample sample_node_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_node_id_fkey FOREIGN KEY (node_id) REFERENCES core.node(id);

--
-- Name: sample sample_submitted_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample
    ADD CONSTRAINT sample_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES iam.app_user(id);

--
-- Name: screening_hash screening_hash_list_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_hash
    ADD CONSTRAINT screening_hash_list_id_fkey FOREIGN KEY (list_id) REFERENCES lab.screening_list(id);

--
-- Name: screening_list screening_list_imported_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_list
    ADD CONSTRAINT screening_list_imported_by_fkey FOREIGN KEY (imported_by) REFERENCES iam.app_user(id);

--
-- Name: screening_list screening_list_purge_requested_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_list
    ADD CONSTRAINT screening_list_purge_requested_by_fkey FOREIGN KEY (purge_requested_by) REFERENCES iam.app_user(id);

--
-- Name: screening_list screening_list_retired_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_list
    ADD CONSTRAINT screening_list_retired_by_fkey FOREIGN KEY (retired_by) REFERENCES iam.app_user(id);

--
-- Name: screening_result screening_result_actor_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_result
    ADD CONSTRAINT screening_result_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

--
-- Name: screening_result screening_result_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_result
    ADD CONSTRAINT screening_result_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id);

--
-- Name: screening_review screening_review_result_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_review
    ADD CONSTRAINT screening_review_result_id_fkey FOREIGN KEY (result_id) REFERENCES lab.screening_result(id);

--
-- Name: screening_review screening_review_reviewed_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.screening_review
    ADD CONSTRAINT screening_review_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES iam.app_user(id);

--
-- Name: static_run static_run_requested_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.static_run
    ADD CONSTRAINT static_run_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

--
-- Name: static_run static_run_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.static_run
    ADD CONSTRAINT static_run_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id) ON DELETE CASCADE;

--
-- Name: yara_activation yara_activation_activated_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_activation
    ADD CONSTRAINT yara_activation_activated_by_fkey FOREIGN KEY (activated_by) REFERENCES iam.app_user(id);

--
-- Name: yara_activation yara_activation_deactivated_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_activation
    ADD CONSTRAINT yara_activation_deactivated_by_fkey FOREIGN KEY (deactivated_by) REFERENCES iam.app_user(id);

--
-- Name: yara_activation yara_activation_ruleset_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_activation
    ADD CONSTRAINT yara_activation_ruleset_id_fkey FOREIGN KEY (ruleset_id) REFERENCES lab.yara_ruleset(id);

--
-- Name: yara_activation yara_activation_version_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_activation
    ADD CONSTRAINT yara_activation_version_id_fkey FOREIGN KEY (version_id) REFERENCES lab.yara_ruleset_version(id);

--
-- Name: yara_compile_job yara_compile_job_version_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compile_job
    ADD CONSTRAINT yara_compile_job_version_id_fkey FOREIGN KEY (version_id) REFERENCES lab.yara_ruleset_version(id);

--
-- Name: yara_compiled_rejected yara_compiled_rejected_compiled_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compiled_rejected
    ADD CONSTRAINT yara_compiled_rejected_compiled_id_fkey FOREIGN KEY (compiled_id) REFERENCES lab.yara_compiled(id);

--
-- Name: yara_compiled yara_compiled_version_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_compiled
    ADD CONSTRAINT yara_compiled_version_id_fkey FOREIGN KEY (version_id) REFERENCES lab.yara_ruleset_version(id);

--
-- Name: yara_ruleset yara_ruleset_created_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset
    ADD CONSTRAINT yara_ruleset_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: yara_ruleset_version yara_ruleset_version_adopted_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_adopted_by_fkey FOREIGN KEY (adopted_by) REFERENCES iam.app_user(id);

--
-- Name: yara_ruleset_version yara_ruleset_version_ruleset_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_ruleset_id_fkey FOREIGN KEY (ruleset_id) REFERENCES lab.yara_ruleset(id);

--
-- Name: yara_ruleset_version yara_ruleset_version_uploaded_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.yara_ruleset_version
    ADD CONSTRAINT yara_ruleset_version_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES iam.app_user(id);

--
-- Name: case_route_block case_route_block_blocked_by_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.case_route_block
    ADD CONSTRAINT case_route_block_blocked_by_fkey FOREIGN KEY (blocked_by) REFERENCES iam.app_user(id);

--
-- Name: case_route_block case_route_block_case_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.case_route_block
    ADD CONSTRAINT case_route_block_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: delivery delivery_jira_link_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.delivery
    ADD CONSTRAINT delivery_jira_link_id_fkey FOREIGN KEY (jira_link_id) REFERENCES notify.jira_link(id);

--
-- Name: delivery delivery_notification_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.delivery
    ADD CONSTRAINT delivery_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES notify.notification(id) ON DELETE CASCADE;

--
-- Name: jira_destination jira_destination_created_by_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_destination
    ADD CONSTRAINT jira_destination_created_by_fkey FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

--
-- Name: jira_destination jira_destination_credential_set_by_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_destination
    ADD CONSTRAINT jira_destination_credential_set_by_fkey FOREIGN KEY (credential_set_by) REFERENCES iam.app_user(id);

--
-- Name: jira_destination jira_destination_updated_by_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_destination
    ADD CONSTRAINT jira_destination_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES iam.app_user(id);

--
-- Name: jira_event jira_event_link_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_event
    ADD CONSTRAINT jira_event_link_id_fkey FOREIGN KEY (link_id) REFERENCES notify.jira_link(id);

--
-- Name: jira_link jira_link_case_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_link
    ADD CONSTRAINT jira_link_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: jira_link jira_link_destination_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.jira_link
    ADD CONSTRAINT jira_link_destination_id_fkey FOREIGN KEY (destination_id) REFERENCES notify.jira_destination(id);

--
-- Name: notification notification_actor_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.notification
    ADD CONSTRAINT notification_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES iam.app_user(id);

--
-- Name: notification notification_case_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.notification
    ADD CONSTRAINT notification_case_id_fkey FOREIGN KEY (case_id) REFERENCES core."case"(id);

--
-- Name: notification notification_recipient_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.notification
    ADD CONSTRAINT notification_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES iam.app_user(id);

--
-- Name: preference preference_user_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.preference
    ADD CONSTRAINT preference_user_id_fkey FOREIGN KEY (user_id) REFERENCES iam.app_user(id);

--
-- Name: community_assignment; Type: ROW SECURITY; Schema: analytics; Owner: -
--

ALTER TABLE analytics.community_assignment ENABLE ROW LEVEL SECURITY;

--
-- Name: layout_position; Type: ROW SECURITY; Schema: analytics; Owner: -
--

ALTER TABLE analytics.layout_position ENABLE ROW LEVEL SECURITY;

--
-- Name: metric_run; Type: ROW SECURITY; Schema: analytics; Owner: -
--

ALTER TABLE analytics.metric_run ENABLE ROW LEVEL SECURITY;

--
-- Name: node_metric; Type: ROW SECURITY; Schema: analytics; Owner: -
--

ALTER TABLE analytics.node_metric ENABLE ROW LEVEL SECURITY;

--
-- Name: projection; Type: ROW SECURITY; Schema: analytics; Owner: -
--

ALTER TABLE analytics.projection ENABLE ROW LEVEL SECURITY;

--
-- Name: community_assignment rls_gate; Type: POLICY; Schema: analytics; Owner: -
--

CREATE POLICY rls_gate ON analytics.community_assignment USING (((EXISTS ( SELECT 1
   FROM analytics.metric_run p
  WHERE (p.id = community_assignment.metric_run_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = community_assignment.node_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM analytics.metric_run p
  WHERE (p.id = community_assignment.metric_run_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = community_assignment.node_id)))));

--
-- Name: layout_position rls_gate; Type: POLICY; Schema: analytics; Owner: -
--

CREATE POLICY rls_gate ON analytics.layout_position USING (((EXISTS ( SELECT 1
   FROM analytics.projection p
  WHERE (p.id = layout_position.projection_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = layout_position.node_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM analytics.projection p
  WHERE (p.id = layout_position.projection_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = layout_position.node_id)))));

--
-- Name: metric_run rls_gate; Type: POLICY; Schema: analytics; Owner: -
--

CREATE POLICY rls_gate ON analytics.metric_run USING (((EXISTS ( SELECT 1
   FROM analytics.projection p
  WHERE ((p.id = metric_run.projection_id) AND ((metric_run.visibility_clearance <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (metric_run.visibility_clearance <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), p.case_id)))))) AND (visibility_compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((EXISTS ( SELECT 1
   FROM analytics.projection p
  WHERE ((p.id = metric_run.projection_id) AND ((metric_run.visibility_clearance <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (metric_run.visibility_clearance <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), p.case_id)))))) AND (visibility_compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: node_metric rls_gate; Type: POLICY; Schema: analytics; Owner: -
--

CREATE POLICY rls_gate ON analytics.node_metric USING (((EXISTS ( SELECT 1
   FROM analytics.metric_run p
  WHERE (p.id = node_metric.metric_run_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = node_metric.node_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM analytics.metric_run p
  WHERE (p.id = node_metric.metric_run_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = node_metric.node_id)))));

--
-- Name: projection rls_gate; Type: POLICY; Schema: analytics; Owner: -
--

CREATE POLICY rls_gate ON analytics.projection USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: document; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.document ENABLE ROW LEVEL SECURITY;

--
-- Name: document_embedding; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.document_embedding ENABLE ROW LEVEL SECURITY;

--
-- Name: extraction; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.extraction ENABLE ROW LEVEL SECURITY;

--
-- Name: forum_member; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.forum_member ENABLE ROW LEVEL SECURITY;

--
-- Name: forum_post; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.forum_post ENABLE ROW LEVEL SECURITY;

--
-- Name: proposal; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.proposal ENABLE ROW LEVEL SECURITY;

--
-- Name: document rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.document USING (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: document_embedding rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.document_embedding USING ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = document_embedding.document_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = document_embedding.document_id))));

--
-- Name: extraction rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.extraction USING ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = extraction.document_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = extraction.document_id))));

--
-- Name: forum_member rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.forum_member USING ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = forum_member.document_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = forum_member.document_id))));

--
-- Name: forum_post rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.forum_post USING ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = forum_post.document_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = forum_post.document_id))));

--
-- Name: proposal rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.proposal USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: telegram_message rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.telegram_message USING ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = telegram_message.document_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = telegram_message.document_id))));

--
-- Name: watch rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.watch USING ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])))) WITH CHECK ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))));

--
-- Name: watch_hit rls_gate; Type: POLICY; Schema: collect; Owner: -
--

CREATE POLICY rls_gate ON collect.watch_hit USING (((EXISTS ( SELECT 1
   FROM collect.watch p
  WHERE (p.id = watch_hit.watch_id))) AND (EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = watch_hit.document_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM collect.watch p
  WHERE (p.id = watch_hit.watch_id))) AND (EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = watch_hit.document_id)))));

--
-- Name: telegram_message; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.telegram_message ENABLE ROW LEVEL SECURITY;

--
-- Name: watch; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.watch ENABLE ROW LEVEL SECURITY;

--
-- Name: watch_hit; Type: ROW SECURITY; Schema: collect; Owner: -
--

ALTER TABLE collect.watch_hit ENABLE ROW LEVEL SECURITY;

--
-- Name: channel_binding; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.channel_binding ENABLE ROW LEVEL SECURITY;

--
-- Name: contact_block; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.contact_block ENABLE ROW LEVEL SECURITY;

--
-- Name: contact_block_entry; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.contact_block_entry ENABLE ROW LEVEL SECURITY;

--
-- Name: conversation; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.conversation ENABLE ROW LEVEL SECURITY;

--
-- Name: device_fingerprint; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.device_fingerprint ENABLE ROW LEVEL SECURITY;

--
-- Name: message; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.message ENABLE ROW LEVEL SECURITY;

--
-- Name: participant; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.participant ENABLE ROW LEVEL SECURITY;

--
-- Name: pgp_key; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.pgp_key ENABLE ROW LEVEL SECURITY;

--
-- Name: pgp_key_acquisition; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.pgp_key_acquisition ENABLE ROW LEVEL SECURITY;

--
-- Name: pgp_key_lookup; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.pgp_key_lookup ENABLE ROW LEVEL SECURITY;

--
-- Name: pgp_verification; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.pgp_verification ENABLE ROW LEVEL SECURITY;

--
-- Name: channel_binding rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.channel_binding USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: contact_block rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.contact_block USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: contact_block_entry rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.contact_block_entry USING ((EXISTS ( SELECT 1
   FROM comms.contact_block p
  WHERE (p.id = contact_block_entry.block_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM comms.contact_block p
  WHERE (p.id = contact_block_entry.block_id))));

--
-- Name: conversation rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.conversation USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: device_fingerprint rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.device_fingerprint USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: message rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.message USING (((EXISTS ( SELECT 1
   FROM comms.conversation p
  WHERE ((p.id = message.conversation_id) AND ((message.classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (message.classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), p.case_id)))))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((EXISTS ( SELECT 1
   FROM comms.conversation p
  WHERE ((p.id = message.conversation_id) AND ((message.classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (message.classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), p.case_id)))))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: participant rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.participant USING ((EXISTS ( SELECT 1
   FROM comms.conversation p
  WHERE (p.id = participant.conversation_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM comms.conversation p
  WHERE (p.id = participant.conversation_id))));

--
-- Name: pgp_key rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.pgp_key USING ((EXISTS ( SELECT 1
   FROM comms.pgp_key_acquisition p
  WHERE (p.id = pgp_key.acquisition_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM comms.pgp_key_acquisition p
  WHERE (p.id = pgp_key.acquisition_id))));

--
-- Name: pgp_key_acquisition rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.pgp_key_acquisition USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: pgp_key_lookup rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.pgp_key_lookup USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id)))));

--
-- Name: pgp_verification rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.pgp_verification USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: service_selector rls_gate; Type: POLICY; Schema: comms; Owner: -
--

CREATE POLICY rls_gate ON comms.service_selector USING ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])))) WITH CHECK ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))));

--
-- Name: service_selector; Type: ROW SECURITY; Schema: comms; Owner: -
--

ALTER TABLE comms.service_selector ENABLE ROW LEVEL SECURITY;

--
-- Name: approval_request; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.approval_request ENABLE ROW LEVEL SECURITY;

--
-- Name: assertion; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.assertion ENABLE ROW LEVEL SECURITY;

--
-- Name: assertion_embedding; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.assertion_embedding ENABLE ROW LEVEL SECURITY;

--
-- Name: assumption; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.assumption ENABLE ROW LEVEL SECURITY;

--
-- Name: case; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core."case" ENABLE ROW LEVEL SECURITY;

--
-- Name: edge; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.edge ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_custody; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.evidence_custody ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_embedding; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.evidence_embedding ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_link; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.evidence_link ENABLE ROW LEVEL SECURITY;

--
-- Name: hypothesis; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.hypothesis ENABLE ROW LEVEL SECURITY;

--
-- Name: hypothesis_evidence; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.hypothesis_evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: node; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.node ENABLE ROW LEVEL SECURITY;

--
-- Name: node_merge; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.node_merge ENABLE ROW LEVEL SECURITY;

--
-- Name: node_merge_edge; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.node_merge_edge ENABLE ROW LEVEL SECURITY;

--
-- Name: node_set; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.node_set ENABLE ROW LEVEL SECURITY;

--
-- Name: node_set_member; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.node_set_member ENABLE ROW LEVEL SECURITY;

--
-- Name: purge_tombstone; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.purge_tombstone ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence_custody rls_append; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_append ON core.evidence_custody FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM core.evidence v
  WHERE (v.id = evidence_custody.evidence_id))));

--
-- Name: case rls_change; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_change ON core."case" FOR UPDATE USING ((id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK (((id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: approval_request rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.approval_request USING ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])))) WITH CHECK ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))));

--
-- Name: assertion rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.assertion USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node n
  WHERE (n.id = assertion.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge e
  WHERE (e.id = assertion.edge_id)))))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node n
  WHERE (n.id = assertion.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge e
  WHERE (e.id = assertion.edge_id))))));

--
-- Name: assertion_embedding rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.assertion_embedding USING ((EXISTS ( SELECT 1
   FROM core.assertion p
  WHERE (p.id = assertion_embedding.assertion_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM core.assertion p
  WHERE (p.id = assertion_embedding.assertion_id))));

--
-- Name: assumption rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.assumption USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: edge rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.edge USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: evidence rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.evidence USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: evidence_embedding rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.evidence_embedding USING ((EXISTS ( SELECT 1
   FROM core.evidence p
  WHERE (p.id = evidence_embedding.evidence_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM core.evidence p
  WHERE (p.id = evidence_embedding.evidence_id))));

--
-- Name: evidence_link rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.evidence_link USING (((EXISTS ( SELECT 1
   FROM core.evidence v
  WHERE (v.id = evidence_link.evidence_id))) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node n
  WHERE (n.id = evidence_link.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge e
  WHERE (e.id = evidence_link.edge_id)))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM core.evidence v
  WHERE (v.id = evidence_link.evidence_id))) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node n
  WHERE (n.id = evidence_link.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge e
  WHERE (e.id = evidence_link.edge_id))))));

--
-- Name: hypothesis rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.hypothesis USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: hypothesis_evidence rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.hypothesis_evidence USING (((EXISTS ( SELECT 1
   FROM core.hypothesis p
  WHERE (p.id = hypothesis_evidence.hypothesis_id))) AND (EXISTS ( SELECT 1
   FROM core.assertion p
  WHERE (p.id = hypothesis_evidence.assertion_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM core.hypothesis p
  WHERE (p.id = hypothesis_evidence.hypothesis_id))) AND (EXISTS ( SELECT 1
   FROM core.assertion p
  WHERE (p.id = hypothesis_evidence.assertion_id)))));

--
-- Name: node rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.node USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: node_merge rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.node_merge USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: node_merge_edge rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.node_merge_edge USING (((EXISTS ( SELECT 1
   FROM core.node_merge p
  WHERE (p.id = node_merge_edge.merge_id))) AND (EXISTS ( SELECT 1
   FROM core.edge p
  WHERE (p.id = node_merge_edge.edge_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM core.node_merge p
  WHERE (p.id = node_merge_edge.merge_id))) AND (EXISTS ( SELECT 1
   FROM core.edge p
  WHERE (p.id = node_merge_edge.edge_id)))));

--
-- Name: node_set rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.node_set USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: node_set_member rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.node_set_member USING (((EXISTS ( SELECT 1
   FROM core.node_set p
  WHERE (p.id = node_set_member.set_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = node_set_member.node_id))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM core.node_set p
  WHERE (p.id = node_set_member.set_id))) AND (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = node_set_member.node_id)))));

--
-- Name: selector rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.selector USING ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))) WITH CHECK ((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: tag rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.tag USING ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])))) WITH CHECK ((((case_id IS NULL) AND (( SELECT iam.rls_clearance() AS rls_clearance) IS NOT NULL)) OR (case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[]))));

--
-- Name: tag_assignment rls_gate; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_gate ON core.tag_assignment USING (((EXISTS ( SELECT 1
   FROM core.tag p
  WHERE (p.id = tag_assignment.tag_id))) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = tag_assignment.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge p
  WHERE (p.id = tag_assignment.edge_id)))) AND ((evidence_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.evidence p
  WHERE (p.id = tag_assignment.evidence_id)))) AND ((document_id IS NULL) OR (EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = tag_assignment.document_id)))))) WITH CHECK (((EXISTS ( SELECT 1
   FROM core.tag p
  WHERE (p.id = tag_assignment.tag_id))) AND ((node_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.node p
  WHERE (p.id = tag_assignment.node_id)))) AND ((edge_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.edge p
  WHERE (p.id = tag_assignment.edge_id)))) AND ((evidence_id IS NULL) OR (EXISTS ( SELECT 1
   FROM core.evidence p
  WHERE (p.id = tag_assignment.evidence_id)))) AND ((document_id IS NULL) OR (EXISTS ( SELECT 1
   FROM collect.document p
  WHERE (p.id = tag_assignment.document_id))))));

--
-- Name: case rls_read; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_read ON core."case" FOR SELECT USING ((id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])));

--
-- Name: evidence_custody rls_read; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_read ON core.evidence_custody FOR SELECT USING ((EXISTS ( SELECT 1
   FROM core.evidence v
  WHERE (v.id = evidence_custody.evidence_id))));

--
-- Name: purge_tombstone rls_read; Type: POLICY; Schema: core; Owner: -
--

CREATE POLICY rls_read ON core.purge_tombstone FOR SELECT USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) OR ((case_id IS NULL) AND ( SELECT iam.rls_holds_global('retention.read'::text) AS rls_holds_global))));

--
-- Name: selector; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.selector ENABLE ROW LEVEL SECURITY;

--
-- Name: tag; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.tag ENABLE ROW LEVEL SECURITY;

--
-- Name: tag_assignment; Type: ROW SECURITY; Schema: core; Owner: -
--

ALTER TABLE core.tag_assignment ENABLE ROW LEVEL SECURITY;

--
-- Name: call_record; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.call_record ENABLE ROW LEVEL SECURITY;

--
-- Name: capture; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.capture ENABLE ROW LEVEL SECURITY;

--
-- Name: capture_hop; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.capture_hop ENABLE ROW LEVEL SECURITY;

--
-- Name: email_attachment; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.email_attachment ENABLE ROW LEVEL SECURITY;

--
-- Name: email_hop; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.email_hop ENABLE ROW LEVEL SECURITY;

--
-- Name: email_message; Type: ROW SECURITY; Schema: deception; Owner: -
--

ALTER TABLE deception.email_message ENABLE ROW LEVEL SECURITY;

--
-- Name: call_record rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.call_record USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: capture rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.capture USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: capture_hop rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.capture_hop USING ((EXISTS ( SELECT 1
   FROM deception.capture p
  WHERE (p.id = capture_hop.capture_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM deception.capture p
  WHERE (p.id = capture_hop.capture_id))));

--
-- Name: email_attachment rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.email_attachment USING ((EXISTS ( SELECT 1
   FROM deception.email_message p
  WHERE (p.id = email_attachment.message_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM deception.email_message p
  WHERE (p.id = email_attachment.message_id))));

--
-- Name: email_hop rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.email_hop USING ((EXISTS ( SELECT 1
   FROM deception.email_message p
  WHERE (p.id = email_hop.message_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM deception.email_message p
  WHERE (p.id = email_hop.message_id))));

--
-- Name: email_message rls_gate; Type: POLICY; Schema: deception; Owner: -
--

CREATE POLICY rls_gate ON deception.email_message USING (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((case_id = ANY (( SELECT iam.rls_cases() AS rls_cases)::uuid[])) AND ((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) OR (classification <= iam.rls_ceiling_for(( SELECT iam.rls_ceilings() AS rls_ceilings), case_id))) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: detonation; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.detonation ENABLE ROW LEVEL SECURITY;

--
-- Name: preservation_authorisation; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.preservation_authorisation ENABLE ROW LEVEL SECURITY;

--
-- Name: sample_access rls_append; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_append ON lab.sample_access FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = sample_access.sample_id))));

--
-- Name: detonation rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.detonation USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = detonation.sample_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = detonation.sample_id))));

--
-- Name: preservation_authorisation rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.preservation_authorisation USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = preservation_authorisation.sample_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = preservation_authorisation.sample_id))));

--
-- Name: sample rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.sample USING (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)) AND ((case_id IS NULL) OR (( SELECT iam.rls_cases_in_reach() AS rls_cases_in_reach) ? (case_id)::text)))) WITH CHECK (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)) AND ((case_id IS NULL) OR (( SELECT iam.rls_cases_in_reach() AS rls_cases_in_reach) ? (case_id)::text))));

--
-- Name: sample_analysis rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.sample_analysis USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = sample_analysis.sample_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = sample_analysis.sample_id))));

--
-- Name: screening_result rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.screening_result USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = screening_result.sample_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = screening_result.sample_id))));

--
-- Name: screening_review rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.screening_review USING ((EXISTS ( SELECT 1
   FROM lab.screening_result p
  WHERE (p.id = screening_review.result_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.screening_result p
  WHERE (p.id = screening_review.result_id))));

--
-- Name: static_run rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.static_run USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = static_run.sample_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = static_run.sample_id))));

--
-- Name: yara_activation rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.yara_activation USING ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset p
  WHERE (p.id = yara_activation.ruleset_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset p
  WHERE (p.id = yara_activation.ruleset_id))));

--
-- Name: yara_compiled rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.yara_compiled USING ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset_version p
  WHERE (p.id = yara_compiled.version_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset_version p
  WHERE (p.id = yara_compiled.version_id))));

--
-- Name: yara_compiled_rejected rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.yara_compiled_rejected USING ((EXISTS ( SELECT 1
   FROM lab.yara_compiled p
  WHERE (p.id = yara_compiled_rejected.compiled_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.yara_compiled p
  WHERE (p.id = yara_compiled_rejected.compiled_id))));

--
-- Name: yara_ruleset rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.yara_ruleset USING (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments)))) WITH CHECK (((classification <= ( SELECT iam.rls_clearance() AS rls_clearance)) AND (compartments <@ ( SELECT iam.rls_compartments() AS rls_compartments))));

--
-- Name: yara_ruleset_version rls_gate; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_gate ON lab.yara_ruleset_version USING ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset p
  WHERE (p.id = yara_ruleset_version.ruleset_id)))) WITH CHECK ((EXISTS ( SELECT 1
   FROM lab.yara_ruleset p
  WHERE (p.id = yara_ruleset_version.ruleset_id))));

--
-- Name: sample_access rls_read; Type: POLICY; Schema: lab; Owner: -
--

CREATE POLICY rls_read ON lab.sample_access FOR SELECT USING ((EXISTS ( SELECT 1
   FROM lab.sample p
  WHERE (p.id = sample_access.sample_id))));

--
-- Name: sample; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.sample ENABLE ROW LEVEL SECURITY;

--
-- Name: sample_access; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.sample_access ENABLE ROW LEVEL SECURITY;

--
-- Name: sample_analysis; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.sample_analysis ENABLE ROW LEVEL SECURITY;

--
-- Name: screening_result; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.screening_result ENABLE ROW LEVEL SECURITY;

--
-- Name: screening_review; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.screening_review ENABLE ROW LEVEL SECURITY;

--
-- Name: static_run; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.static_run ENABLE ROW LEVEL SECURITY;

--
-- Name: yara_activation; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.yara_activation ENABLE ROW LEVEL SECURITY;

--
-- Name: yara_compiled; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.yara_compiled ENABLE ROW LEVEL SECURITY;

--
-- Name: yara_compiled_rejected; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.yara_compiled_rejected ENABLE ROW LEVEL SECURITY;

--
-- Name: yara_ruleset; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.yara_ruleset ENABLE ROW LEVEL SECURITY;

--
-- Name: yara_ruleset_version; Type: ROW SECURITY; Schema: lab; Owner: -
--

ALTER TABLE lab.yara_ruleset_version ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--
