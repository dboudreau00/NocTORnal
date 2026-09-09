-- =====================================================================
-- NocTORnal -- db/schema.sql
--
-- GENERATED MIRROR of the schema at Alembic revision 0059.
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
-- Alembic revision: 0059
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
-- Name: document_tsv_update(); Type: FUNCTION; Schema: collect; Owner: -
--

CREATE FUNCTION collect.document_tsv_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.search_tsv :=
      setweight(to_tsvector('simple', coalesce(NEW.title,'')), 'A')
   || setweight(to_tsvector('simple', coalesce(NEW.author_handle,'')), 'B')
   -- Capped: combo lists / credential dumps exceed the 1MB tsvector limit
   -- and must land with degraded search rather than fail to land at all.
   || setweight(to_tsvector('simple', left(coalesce(NEW.body_text,''), 500000)), 'C');
  RETURN NEW;
END $$;

--
-- Name: pgp_verification_confirms_its_binding(); Type: FUNCTION; Schema: comms; Owner: -
--

CREATE FUNCTION comms.pgp_verification_confirms_its_binding() RETURNS trigger
    LANGUAGE plpgsql
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
-- Name: assertion_protects_element(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.assertion_protects_element() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'core', 'public'
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
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
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
-- Name: enforce_tlp_floor(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.enforce_tlp_floor() RETURNS trigger
    LANGUAGE plpgsql
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
    LANGUAGE plpgsql
    SET search_path TO 'core', 'public'
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
    LANGUAGE plpgsql
    SET search_path TO 'core', 'public'
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
-- Name: validate_edge_endpoints(); Type: FUNCTION; Schema: core; Owner: -
--

CREATE FUNCTION core.validate_edge_endpoints() RETURNS trigger
    LANGUAGE plpgsql
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
-- Name: compartment_in_use(text); Type: FUNCTION; Schema: iam; Owner: -
--

CREATE FUNCTION iam.compartment_in_use(key text) RETURNS text[]
    LANGUAGE sql STABLE
    AS $_$
  SELECT array_agg(col ORDER BY col) FROM (
        SELECT 'iam.app_user.compartments' AS col WHERE EXISTS (SELECT 1 FROM iam."app_user" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'core.case.compartments' AS col WHERE EXISTS (SELECT 1 FROM core."case" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'core.node.compartments' AS col WHERE EXISTS (SELECT 1 FROM core."node" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'core.edge.compartments' AS col WHERE EXISTS (SELECT 1 FROM core."edge" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'core.evidence.compartments' AS col WHERE EXISTS (SELECT 1 FROM core."evidence" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'analytics.metric_run.visibility_compartments' AS col WHERE EXISTS (SELECT 1 FROM analytics."metric_run" WHERE $1 = ANY(visibility_compartments))
        UNION ALL
        SELECT 'notify.notification.compartments' AS col WHERE EXISTS (SELECT 1 FROM notify."notification" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'lab.sample.compartments' AS col WHERE EXISTS (SELECT 1 FROM lab."sample" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'ingest.record.compartments' AS col WHERE EXISTS (SELECT 1 FROM ingest."record" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'ingest.dead_letter.compartments' AS col WHERE EXISTS (SELECT 1 FROM ingest."dead_letter" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'comms.channel_binding.compartments' AS col WHERE EXISTS (SELECT 1 FROM comms."channel_binding" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'comms.conversation.compartments' AS col WHERE EXISTS (SELECT 1 FROM comms."conversation" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'comms.message.compartments' AS col WHERE EXISTS (SELECT 1 FROM comms."message" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'comms.contact_block.compartments' AS col WHERE EXISTS (SELECT 1 FROM comms."contact_block" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'deception.capture.compartments' AS col WHERE EXISTS (SELECT 1 FROM deception."capture" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'deception.email_message.compartments' AS col WHERE EXISTS (SELECT 1 FROM deception."email_message" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'deception.call_record.compartments' AS col WHERE EXISTS (SELECT 1 FROM deception."call_record" WHERE $1 = ANY(compartments))
        UNION ALL
        SELECT 'ingest.api_key.forced_compartment' AS col WHERE EXISTS (SELECT 1 FROM ingest."api_key" WHERE forced_compartment = $1)
  ) s
$_$;

--
-- Name: FUNCTION compartment_in_use(key text); Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON FUNCTION iam.compartment_in_use(key text) IS 'The bound columns (schema.table.column) that still carry the key, or NULL. Used by the registry trigger that refuses to drop or rename a key in use.';

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
-- Name: block_access_mutation(); Type: FUNCTION; Schema: lab; Owner: -
--

CREATE FUNCTION lab.block_access_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'lab.sample_access is append-only (docs/11 custody)';
END $$;

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
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

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
    parser_version text
);

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
    embedding public.vector(768),
    triage_state text DEFAULT 'NEW'::text NOT NULL,
    category text DEFAULT 'UNKNOWN'::text NOT NULL,
    retain_until timestamp with time zone,
    legal_hold boolean DEFAULT false NOT NULL,
    purged_at timestamp with time zone
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
    is_active boolean DEFAULT true NOT NULL
);

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
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

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
    last_request_at timestamp with time zone
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
    CONSTRAINT pgp_verification_claimed_fp_shape CHECK (((claimed_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (claimed_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_verification_digest_is_sha256 CHECK (((signed_payload_sha256 IS NULL) OR (octet_length(signed_payload_sha256) = 32))),
    CONSTRAINT pgp_verification_no_verifier_verifies_nothing CHECK (((verifier <> 'NONE'::text) OR (outcome = 'NO_VERIFIER'::text))),
    CONSTRAINT pgp_verification_outcome_known CHECK ((outcome = ANY (ARRAY['VERIFIED'::text, 'BAD_SIGNATURE'::text, 'KEY_MISMATCH'::text, 'VALUE_NOT_IN_PAYLOAD'::text, 'KEY_UNAVAILABLE'::text, 'EXPIRED_KEY'::text, 'REVOKED_KEY'::text, 'EXPIRED_SIGNATURE'::text, 'MALFORMED'::text, 'NO_VERIFIER'::text]))),
    CONSTRAINT pgp_verification_signing_fp_shape CHECK (((signing_fingerprint IS NULL) OR (signing_fingerprint ~ '^[0-9A-F]{40}$'::text) OR (signing_fingerprint ~ '^[0-9A-F]{64}$'::text))),
    CONSTRAINT pgp_verification_verified_covers_value CHECK (((outcome <> 'VERIFIED'::text) OR ((confirms_value IS NOT NULL) AND value_in_payload AND (signed_payload_sha256 IS NOT NULL)))),
    CONSTRAINT pgp_verification_verified_is_re_readable CHECK (((outcome <> 'VERIFIED'::text) OR (status_output IS NOT NULL))),
    CONSTRAINT pgp_verification_verified_matches_claim CHECK (((outcome <> 'VERIFIED'::text) OR ((signing_fingerprint IS NOT NULL) AND (signing_fingerprint = claimed_fingerprint)))),
    CONSTRAINT pgp_verification_verifier_known CHECK ((verifier = ANY (ARRAY['GPG'::text, 'EXTERNAL'::text, 'NONE'::text])))
);

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
    CONSTRAINT assertion_inference_needs_rationale CHECK (((basis <> ALL (ARRAY['ANALYST_INFERENCE'::core.assertion_basis, 'AUTOMATED_INFERENCE'::core.assertion_basis])) OR (rationale IS NOT NULL))),
    CONSTRAINT assertion_one_subject CHECK ((num_nonnulls(node_id, edge_id) = 1))
);

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
    CONSTRAINT case_hold_has_reason CHECK (((NOT legal_hold) OR (legal_hold_reason IS NOT NULL))),
    CONSTRAINT case_retention_sane CHECK ((retention_until > ((created_at AT TIME ZONE 'UTC'::text))::date)),
    CONSTRAINT case_withheld_disclosure_known CHECK ((withheld_disclosure = ANY (ARRAY['NONE'::text, 'PRESENCE'::text, 'COUNT'::text])))
);

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
    totp_last_counter bigint
);

--
-- Name: COLUMN app_user.totp_last_counter; Type: COMMENT; Schema: iam; Owner: -
--

COMMENT ON COLUMN iam.app_user.totp_last_counter IS 'Last accepted RFC 6238 TOTP step counter; a code with counter <= this is a replay.';

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
-- Name: dual_control_request; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.dual_control_request (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_by uuid,
    approved_at timestamp with time zone,
    executed_at timestamp with time zone,
    state text DEFAULT 'PENDING'::text NOT NULL,
    CONSTRAINT dual_control_distinct CHECK (((approved_by IS NULL) OR (approved_by <> requested_by)))
);

--
-- Name: permission; Type: TABLE; Schema: iam; Owner: -
--

CREATE TABLE iam.permission (
    key text NOT NULL,
    description text NOT NULL,
    requires_step_up boolean DEFAULT false NOT NULL,
    requires_dual_control boolean DEFAULT false NOT NULL
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
    ip inet
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
    CONSTRAINT detonation_exposure_known CHECK ((exposure_level = ANY (ARRAY['NONE'::text, 'VENDOR'::text, 'PUBLIC'::text]))),
    CONSTRAINT detonation_exposure_needs_authoriser CHECK (((exposure_level = 'NONE'::text) OR (authorised_by IS NOT NULL))),
    CONSTRAINT detonation_exposure_needs_note CHECK (((exposure_level = 'NONE'::text) OR (authorisation_note IS NOT NULL))),
    CONSTRAINT detonation_status_known CHECK ((status = ANY (ARRAY['PENDING'::text, 'AUTHORISED'::text, 'SUBMITTED'::text, 'REPORTED'::text, 'REFUSED'::text])))
);

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
    CONSTRAINT sample_assignment_complete CHECK (((assigned_to IS NULL) = (assigned_at IS NULL))),
    CONSTRAINT sample_rejection_has_reason CHECK (((state = 'REJECTED'::lab.sample_state) = (reject_reason IS NOT NULL)))
);

--
-- Name: sample_access; Type: TABLE; Schema: lab; Owner: -
--

CREATE TABLE lab.sample_access (
    id bigint NOT NULL,
    sample_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    action text NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    archive_format text,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT sample_access_action_known CHECK ((action = ANY (ARRAY['VIEWED_META'::text, 'DOWNLOADED'::text, 'SHARED'::text, 'DETONATED'::text, 'REJECTED'::text, 'ASSIGNED'::text, 'ANALYSED'::text])))
);

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
    CONSTRAINT sample_analysis_family_needs_confidence CHECK (((family_assessment IS NULL) OR (confidence IS NOT NULL))),
    CONSTRAINT sample_analysis_kind_known CHECK ((kind = ANY (ARRAY['STATIC'::text, 'YARA'::text, 'MANUAL_RE'::text, 'SANDBOX'::text, 'VENDOR'::text])))
);

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
    CONSTRAINT delivery_channel_known CHECK ((channel = ANY (ARRAY['IN_APP'::text, 'SMTP'::text, 'WEBHOOK'::text, 'JIRA'::text]))),
    CONSTRAINT delivery_sent_has_timestamp CHECK (((state = 'SENT'::text) = (sent_at IS NOT NULL))),
    CONSTRAINT delivery_state_known CHECK ((state = ANY (ARRAY['PENDING'::text, 'SENT'::text, 'FAILED'::text, 'REFUSED'::text, 'SUPPRESSED'::text])))
);

--
-- Name: COLUMN delivery.sent_to; Type: COMMENT; Schema: notify; Owner: -
--

COMMENT ON COLUMN notify.delivery.sent_to IS 'The address or endpoint this delivery actually resolved to at drain time. NULL on rows written before migration 0044, and on SUPPRESSED rows that never resolved one. Never backfilled: an invented value would make the ledger look complete when it is not.';

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
    CONSTRAINT notification_ack_implies_read CHECK (((acknowledged_at IS NULL) OR (read_at IS NOT NULL))),
    CONSTRAINT notification_priority_range CHECK (((priority >= 1) AND (priority <= 3))),
    CONSTRAINT notification_subject_present CHECK ((length(btrim(subject)) > 0))
);

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
-- Name: collection_run collection_run_pkey; Type: CONSTRAINT; Schema: collect; Owner: -
--

ALTER TABLE ONLY collect.collection_run
    ADD CONSTRAINT collection_run_pkey PRIMARY KEY (id);

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
-- Name: dual_control_request dual_control_request_pkey; Type: CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_request
    ADD CONSTRAINT dual_control_request_pkey PRIMARY KEY (id);

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
-- Name: pii_authorisation pii_authorisation_pkey; Type: CONSTRAINT; Schema: ingest; Owner: -
--

ALTER TABLE ONLY ingest.pii_authorisation
    ADD CONSTRAINT pii_authorisation_pkey PRIMARY KEY (id);

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
-- Name: delivery delivery_pkey; Type: CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.delivery
    ADD CONSTRAINT delivery_pkey PRIMARY KEY (id);

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
-- Name: collection_run_source_id_started_at_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX collection_run_source_id_started_at_idx ON collect.collection_run USING btree (source_id, started_at DESC);

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
-- Name: document_content_sha256_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_content_sha256_idx ON collect.document USING btree (content_sha256);

--
-- Name: document_embedding_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX document_embedding_idx ON collect.document USING hnsw (embedding public.vector_cosine_ops);

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
-- Name: source_due_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX source_due_idx ON collect.source USING btree (next_due_at) WHERE is_active;

--
-- Name: watch_hit_created_at_idx; Type: INDEX; Schema: collect; Owner: -
--

CREATE INDEX watch_hit_created_at_idx ON collect.watch_hit USING btree (created_at DESC) WHERE ((notified_at IS NULL) AND (NOT suppressed));

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
-- Name: contact_block_entry_block_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_entry_block_idx ON comms.contact_block_entry USING btree (block_id, line_no);

--
-- Name: contact_block_entry_durable_idx; Type: INDEX; Schema: comms; Owner: -
--

CREATE INDEX contact_block_entry_durable_idx ON comms.contact_block_entry USING btree (platform_key, durable_value) WHERE (durable_value IS NOT NULL);

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
-- Name: assertion_document_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_document_id_idx ON core.assertion USING btree (document_id);

--
-- Name: assertion_edge_id_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX assertion_edge_id_idx ON core.assertion USING btree (edge_id) WHERE ((retracted_at IS NULL) AND (superseded_at IS NULL));

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
-- Name: evidence_case_id_acquired_at_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_case_id_acquired_at_idx ON core.evidence USING btree (case_id, acquired_at DESC);

--
-- Name: evidence_custody_evidence_id_occurred_at_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX evidence_custody_evidence_id_occurred_at_idx ON core.evidence_custody USING btree (evidence_id, occurred_at);

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
-- Name: selector_selector_type_norm_value_idx; Type: INDEX; Schema: core; Owner: -
--

CREATE INDEX selector_selector_type_norm_value_idx ON core.selector USING btree (selector_type, norm_value);

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
-- Name: pii_authorisation_live_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX pii_authorisation_live_idx ON ingest.pii_authorisation USING btree (granted_to, expires_at) WHERE (revoked_at IS NULL);

--
-- Name: record_batch_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_batch_idx ON ingest.record USING btree (batch_id);

--
-- Name: record_content_idx; Type: INDEX; Schema: ingest; Owner: -
--

CREATE INDEX record_content_idx ON ingest.record USING btree (content_sha256);

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
-- Name: detonation_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX detonation_sample_idx ON lab.detonation USING btree (sample_id, requested_at DESC);

--
-- Name: sample_access_actor_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_access_actor_idx ON lab.sample_access USING btree (actor_id, occurred_at DESC);

--
-- Name: sample_access_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_access_sample_idx ON lab.sample_access USING btree (sample_id, occurred_at DESC);

--
-- Name: sample_analysis_sample_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_analysis_sample_idx ON lab.sample_analysis USING btree (sample_id, created_at DESC);

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
-- Name: sample_queue_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_queue_idx ON lab.sample USING btree (state, submitted_at DESC) WHERE (state = ANY (ARRAY['QUARANTINED'::lab.sample_state, 'TRIAGED'::lab.sample_state, 'ASSIGNED'::lab.sample_state, 'IN_ANALYSIS'::lab.sample_state]));

--
-- Name: sample_tlsh_idx; Type: INDEX; Schema: lab; Owner: -
--

CREATE INDEX sample_tlsh_idx ON lab.sample USING btree (tlsh) WHERE (tlsh IS NOT NULL);

--
-- Name: delivery_due_idx; Type: INDEX; Schema: notify; Owner: -
--

CREATE INDEX delivery_due_idx ON notify.delivery USING btree (deliver_after) WHERE (state = 'PENDING'::text);

--
-- Name: delivery_one_per_channel; Type: INDEX; Schema: notify; Owner: -
--

CREATE UNIQUE INDEX delivery_one_per_channel ON notify.delivery USING btree (notification_id, channel);

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
-- Name: document document_tsv; Type: TRIGGER; Schema: collect; Owner: -
--

CREATE TRIGGER document_tsv BEFORE INSERT OR UPDATE ON collect.document FOR EACH ROW EXECUTE FUNCTION collect.document_tsv_update();

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
-- Name: pgp_verification pgp_verification_confirms_its_binding; Type: TRIGGER; Schema: comms; Owner: -
--

CREATE TRIGGER pgp_verification_confirms_its_binding BEFORE INSERT OR UPDATE ON comms.pgp_verification FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_confirms_its_binding();

--
-- Name: assertion assertion_protects_element; Type: TRIGGER; Schema: core; Owner: -
--

CREATE CONSTRAINT TRIGGER assertion_protects_element AFTER DELETE OR UPDATE OF node_id, edge_id ON core.assertion DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION core.assertion_protects_element();

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
-- Name: evidence_custody evidence_custody_append_only; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_custody_append_only BEFORE DELETE OR UPDATE ON core.evidence_custody FOR EACH ROW EXECUTE FUNCTION core.block_custody_mutation();

--
-- Name: evidence_custody evidence_custody_no_truncate; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_custody_no_truncate BEFORE TRUNCATE ON core.evidence_custody FOR EACH STATEMENT EXECUTE FUNCTION core.block_custody_mutation();

--
-- Name: evidence evidence_tlp; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_tlp BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: evidence evidence_tsv; Type: TRIGGER; Schema: core; Owner: -
--

CREATE TRIGGER evidence_tsv BEFORE INSERT OR UPDATE ON core.evidence FOR EACH ROW EXECUTE FUNCTION core.evidence_tsv_update();

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
-- Name: sample compartments_registered; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON lab.sample FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

--
-- Name: sample_access sample_access_append_only; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_access_append_only BEFORE DELETE OR UPDATE ON lab.sample_access FOR EACH ROW EXECUTE FUNCTION lab.block_access_mutation();

--
-- Name: sample_access sample_access_no_truncate; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_access_no_truncate BEFORE TRUNCATE ON lab.sample_access FOR EACH STATEMENT EXECUTE FUNCTION lab.block_access_mutation();

--
-- Name: sample sample_tlp; Type: TRIGGER; Schema: lab; Owner: -
--

CREATE TRIGGER sample_tlp BEFORE INSERT OR UPDATE ON lab.sample FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

--
-- Name: notification compartments_registered; Type: TRIGGER; Schema: notify; Owner: -
--

CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF compartments ON notify.notification FOR EACH ROW WHEN ((cardinality(new.compartments) > 0)) EXECUTE FUNCTION iam.refuse_unregistered_compartment('compartments', 'array');

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
-- Name: assertion assertion_evidence_fk; Type: FK CONSTRAINT; Schema: core; Owner: -
--

ALTER TABLE ONLY core.assertion
    ADD CONSTRAINT assertion_evidence_fk FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

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
-- Name: dual_control_request dual_control_request_approved_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_request
    ADD CONSTRAINT dual_control_request_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES iam.app_user(id);

--
-- Name: dual_control_request dual_control_request_requested_by_fkey; Type: FK CONSTRAINT; Schema: iam; Owner: -
--

ALTER TABLE ONLY iam.dual_control_request
    ADD CONSTRAINT dual_control_request_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES iam.app_user(id);

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
-- Name: detonation detonation_authorised_by_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.detonation
    ADD CONSTRAINT detonation_authorised_by_fkey FOREIGN KEY (authorised_by) REFERENCES iam.app_user(id);

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
-- Name: sample_analysis sample_analysis_sample_id_fkey; Type: FK CONSTRAINT; Schema: lab; Owner: -
--

ALTER TABLE ONLY lab.sample_analysis
    ADD CONSTRAINT sample_analysis_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES lab.sample(id) ON DELETE CASCADE;

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
-- Name: delivery delivery_notification_id_fkey; Type: FK CONSTRAINT; Schema: notify; Owner: -
--

ALTER TABLE ONLY notify.delivery
    ADD CONSTRAINT delivery_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES notify.notification(id) ON DELETE CASCADE;

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
-- PostgreSQL database dump complete
--
