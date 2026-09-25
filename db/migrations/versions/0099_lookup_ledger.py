"""The lookup ledger: what left for a provider, when, and what came back
(F15.3, 2026-09-24).

## Decision 75, read strictly

A lookup that sends case material to a provider is requested by one
person and signed off by a different, eligible person in a separate
action before anything is sent; the sign-off is audited and the request
lapses (docs/00 decision 75). Both VENDOR and PUBLIC send case material
to somebody else's system, and the sandbox reads the same decision as
"sign-off unless NONE" (decision 127), so this ledger does too: every
lookup that is not NONE is AWAITING_SIGNOFF until the named authoriser
signs it off, and there are no standing authorisations. The CHECKs are
keyed on exposure_level <> 'NONE'.

## What this adds

- `ingest.lookup`: one request. A provider test (a canary, no case
  material) is the only row with no case.
- `ingest.lookup_attempt`: one row per send, append-only; the quota
  counts these, so a retry spends a window as the vendor sees it.
- `ingest.lookup_result`: the answer, kept as case material, never
  labelled below the question (lookup_result_dominates).
- permissions lookup.request (Lead investigator and Analyst) and
  lookup.authorise (Lead investigator, step-up).

## The database holds decision 75 too

A guard runs BEFORE INSERT as well as UPDATE: a new row starts
AWAITING_SIGNOFF, QUEUED or CACHED, with nothing sent and nothing signed,
so a "signed off" send cannot be inserted in one statement. A sign-off is
recorded once, after the request, by the authoriser the requester named;
a non-NONE row is sent only while that sign-off stands and before it
lapses, and it is never QUEUED.

## Records

DELETE and TRUNCATE are refused on all three tables and the runtime role
loses DELETE (and UPDATE on the attempts). Retention empties values,
notes and bodies (purged_at) and keeps every row, fingerprint and attempt.

## Downgrade

Refuses while any lookup or result belongs to a case under legal hold
(legal hold overrides deletion). Otherwise drops the tables, the
functions and the two permissions: the per-case record of what was sent
goes, and audit.event keeps LOOKUP_SENT and the sign-off events.
"""
from alembic import op

revision = "0099"
down_revision = "0098"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

GUARDED_TABLES = {
    "ingest.lookup": ("SELECT", "INSERT", "UPDATE"),
    "ingest.lookup_result": ("SELECT", "INSERT", "UPDATE"),
    "ingest.lookup_attempt": ("SELECT", "INSERT"),
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(r"""
CREATE TABLE ingest.lookup (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid REFERENCES core."case"(id),
  provider_id uuid NOT NULL REFERENCES ingest.provider(id),
  operation text NOT NULL,
  adapter_version text NOT NULL,
  subject_kind text NOT NULL
    CONSTRAINT lookup_subject_known CHECK (subject_kind IN ('SELECTOR', 'SAMPLE', 'VALUE', 'CANARY')),
  selector_id uuid REFERENCES core.selector(id),
  sample_id uuid REFERENCES lab.sample(id),
  node_id uuid REFERENCES core.node(id),
  selector_type text NOT NULL REFERENCES core.selector_type(key),
  query_value text NOT NULL,
  query_fingerprint bytea NOT NULL
    CONSTRAINT lookup_fingerprint_size CHECK (octet_length(query_fingerprint) = 32),
  classification core.tlp NOT NULL
    CONSTRAINT lookup_never_above_amber CHECK (classification <= 'AMBER'),
  exposure_level text NOT NULL
    CONSTRAINT lookup_exposure_known CHECK (exposure_level IN ('NONE', 'VENDOR', 'PUBLIC')),
  exposure_confirmed boolean NOT NULL DEFAULT false,
  authorised_by uuid REFERENCES iam.app_user(id),
  authorisation_note text,
  signoff_expires_at timestamptz,
  signed_off_by uuid REFERENCES iam.app_user(id),
  signed_off_at timestamptz,
  signoff_note text,
  requested_by uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at timestamptz NOT NULL DEFAULT now(),
  state text NOT NULL
    CONSTRAINT lookup_state_known CHECK (state IN ('AWAITING_SIGNOFF', 'QUEUED', 'SENDING',
      'ANSWERED', 'CACHED', 'FAILED', 'REFUSED', 'CANCELLED', 'DECLINED', 'EXPIRED')),
  not_before timestamptz,
  attempts smallint NOT NULL DEFAULT 0 CONSTRAINT lookup_attempts_range CHECK (attempts BETWEEN 0 AND 3),
  sent_at timestamptz,
  finished_at timestamptz,
  http_status integer,
  outcome text CONSTRAINT lookup_outcome_known CHECK (outcome IN ('FOUND', 'NOT_FOUND', 'UNREADABLE')),
  error_class text,
  error_detail text CONSTRAINT lookup_error_short CHECK (error_detail IS NULL OR length(error_detail) <= 500),
  refusal text,
  result_id uuid,
  purged_at timestamptz,
  CONSTRAINT lookup_case_unless_canary CHECK ((subject_kind = 'CANARY') = (case_id IS NULL)),
  CONSTRAINT lookup_one_subject CHECK (CASE subject_kind
    WHEN 'SELECTOR' THEN selector_id IS NOT NULL AND sample_id IS NULL
    WHEN 'SAMPLE' THEN sample_id IS NOT NULL AND selector_id IS NULL
    WHEN 'CANARY' THEN selector_id IS NULL AND sample_id IS NULL AND node_id IS NULL
    ELSE selector_id IS NULL AND sample_id IS NULL END),
  CONSTRAINT lookup_canary_is_clear CHECK (subject_kind <> 'CANARY' OR classification = 'CLEAR'),
  CONSTRAINT lookup_sent_iff_attempted CHECK ((attempts = 0) = (sent_at IS NULL)),
  -- Decision 75: a lookup that is not NONE names a different person, with a note,
  -- and lapses within a day.
  CONSTRAINT lookup_signoff_asks_another CHECK (
    exposure_level = 'NONE' OR subject_kind = 'CANARY'
    OR state IN ('REFUSED', 'CACHED') OR purged_at IS NOT NULL
    OR (authorised_by IS NOT NULL AND authorised_by <> requested_by
        AND length(btrim(coalesce(authorisation_note, ''))) > 0
        AND signoff_expires_at IS NOT NULL
        AND signoff_expires_at <= requested_at + interval '24 hours'
        AND exposure_confirmed)),
  CONSTRAINT lookup_sent_only_when_signed_off CHECK (
    exposure_level = 'NONE' OR subject_kind = 'CANARY'
    OR state NOT IN ('SENDING', 'ANSWERED', 'FAILED')
    OR (signed_off_by = authorised_by AND signed_off_at IS NOT NULL
        AND signed_off_at <= signoff_expires_at)),
  CONSTRAINT lookup_signed_is_never_queued CHECK (
    exposure_level = 'NONE' OR subject_kind = 'CANARY' OR state <> 'QUEUED'),
  CONSTRAINT lookup_awaiting_is_signed_kind CHECK (
    state <> 'AWAITING_SIGNOFF' OR exposure_level <> 'NONE'),
  CONSTRAINT lookup_signoff_complete CHECK ((signed_off_by IS NULL) = (signed_off_at IS NULL)),
  CONSTRAINT lookup_signed_after_request CHECK (signed_off_at IS NULL OR signed_off_at > requested_at),
  CONSTRAINT lookup_sending_has_time CHECK (state NOT IN ('SENDING', 'ANSWERED') OR sent_at IS NOT NULL),
  CONSTRAINT lookup_answered_has_outcome CHECK (state <> 'ANSWERED' OR outcome IN ('FOUND', 'NOT_FOUND')),
  CONSTRAINT lookup_answer_has_result CHECK (CASE WHEN subject_kind = 'CANARY' THEN result_id IS NULL
    ELSE (state IN ('ANSWERED', 'CACHED') OR (state = 'FAILED' AND outcome = 'UNREADABLE'))
         = (result_id IS NOT NULL) END),
  CONSTRAINT lookup_closure_says_why CHECK (
    (state IN ('REFUSED', 'CANCELLED', 'DECLINED', 'EXPIRED')) = (refusal IS NOT NULL)),
  CONSTRAINT lookup_purge_empties CHECK (purged_at IS NULL OR (
    query_value = '' AND error_detail IS NULL AND coalesce(authorisation_note, '') = ''
    AND coalesce(signoff_note, '') = '' AND coalesce(refusal, '') IN ('', 'purged')))
);

CREATE TABLE ingest.lookup_attempt (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  lookup_id uuid NOT NULL REFERENCES ingest.lookup(id),
  provider_id uuid NOT NULL REFERENCES ingest.provider(id),
  attempt smallint NOT NULL CONSTRAINT lookup_attempt_range CHECK (attempt BETWEEN 1 AND 3),
  interactive boolean NOT NULL,
  sent_at timestamptz NOT NULL,
  UNIQUE (lookup_id, attempt)
);
CREATE INDEX lookup_attempt_quota_idx ON ingest.lookup_attempt (provider_id, sent_at);

CREATE TABLE ingest.lookup_result (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES core."case"(id),
  lookup_id uuid NOT NULL REFERENCES ingest.lookup(id),
  provider_id uuid NOT NULL REFERENCES ingest.provider(id),
  operation text NOT NULL,
  adapter_version text NOT NULL,
  selector_type text NOT NULL REFERENCES core.selector_type(key),
  query_fingerprint bytea NOT NULL CHECK (octet_length(query_fingerprint) = 32),
  fetched_at timestamptz NOT NULL,
  fresh_until timestamptz NOT NULL CONSTRAINT lookup_result_fresh CHECK (fresh_until >= fetched_at),
  http_status integer NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('FOUND', 'NOT_FOUND', 'UNREADABLE')),
  media_type text NOT NULL,
  raw_body bytea NOT NULL CONSTRAINT lookup_result_body_cap CHECK (octet_length(raw_body) <= 16777216),
  raw_sha256 bytea NOT NULL CHECK (octet_length(raw_sha256) = 32),
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  findings_total integer NOT NULL DEFAULT 0 CHECK (findings_total >= 0),
  findings_proposed integer NOT NULL DEFAULT 0
    CONSTRAINT lookup_result_proposed_range CHECK (findings_proposed BETWEEN 0 AND findings_total),
  interpret_error text CHECK (interpret_error IS NULL OR length(interpret_error) <= 500),
  classification core.tlp NOT NULL,
  filed_evidence_id uuid REFERENCES core.evidence(id),
  purged_at timestamptz,
  CONSTRAINT lookup_result_unreadable_says_why CHECK (
    purged_at IS NOT NULL OR (outcome = 'UNREADABLE') = (interpret_error IS NOT NULL)),
  CONSTRAINT lookup_result_unreadable_never_cached CHECK (
    outcome <> 'UNREADABLE' OR fresh_until = fetched_at),
  CONSTRAINT lookup_result_purge_empties CHECK (purged_at IS NULL OR (
    octet_length(raw_body) = 0 AND summary = '{}'::jsonb AND interpret_error IS NULL))
);
CREATE INDEX lookup_result_cache_idx ON ingest.lookup_result
  (case_id, provider_id, operation, query_fingerprint, fetched_at DESC)
  WHERE purged_at IS NULL AND outcome <> 'UNREADABLE';

ALTER TABLE ingest.lookup ADD CONSTRAINT lookup_result_fk
  FOREIGN KEY (result_id) REFERENCES ingest.lookup_result(id);

CREATE INDEX lookup_case_idx ON ingest.lookup (case_id, requested_at DESC);
CREATE INDEX lookup_queue_idx ON ingest.lookup (provider_id, not_before NULLS FIRST, requested_at)
  WHERE state = 'QUEUED';
CREATE INDEX lookup_awaiting_idx ON ingest.lookup (authorised_by, signoff_expires_at)
  WHERE state = 'AWAITING_SIGNOFF';
CREATE INDEX lookup_sending_idx ON ingest.lookup (sent_at) WHERE state = 'SENDING';

CREATE TRIGGER lookup_tlp BEFORE INSERT OR UPDATE ON ingest.lookup
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
CREATE TRIGGER lookup_result_tlp BEFORE INSERT OR UPDATE ON ingest.lookup_result
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

-- An answer is never labelled below the question.
CREATE FUNCTION ingest.lookup_result_dominates() RETURNS trigger AS $$
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
END $$ LANGUAGE plpgsql;

CREATE TRIGGER lookup_result_dominates
  BEFORE INSERT OR UPDATE OF result_id ON ingest.lookup
  FOR EACH ROW EXECUTE FUNCTION ingest.lookup_result_dominates();

CREATE FUNCTION ingest.lookup_is_a_record() RETURNS trigger AS $$
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
END $$ LANGUAGE plpgsql;

CREATE TRIGGER lookup_guarded
  BEFORE INSERT OR UPDATE OR DELETE ON ingest.lookup
  FOR EACH ROW EXECUTE FUNCTION ingest.lookup_is_a_record();
CREATE TRIGGER lookup_no_truncate
  BEFORE TRUNCATE ON ingest.lookup
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.lookup_is_a_record();

CREATE FUNCTION ingest.lookup_attempt_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'a lookup attempt is what the quota counts: append-only';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER lookup_attempt_guarded
  BEFORE UPDATE OR DELETE ON ingest.lookup_attempt
  FOR EACH ROW EXECUTE FUNCTION ingest.lookup_attempt_append_only();
CREATE TRIGGER lookup_attempt_no_truncate
  BEFORE TRUNCATE ON ingest.lookup_attempt
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.lookup_attempt_append_only();

CREATE FUNCTION ingest.guard_lookup_result() RETURNS trigger AS $$
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
END $$ LANGUAGE plpgsql;

CREATE TRIGGER lookup_result_guarded
  BEFORE UPDATE OR DELETE ON ingest.lookup_result
  FOR EACH ROW EXECUTE FUNCTION ingest.guard_lookup_result();
CREATE TRIGGER lookup_result_no_truncate
  BEFORE TRUNCATE ON ingest.lookup_result
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_lookup_result();

COMMENT ON TABLE ingest.lookup IS
  'One lookup request (docs/12 Part 3). Anything that is not NONE waits for '
  'a named second person''s sign-off (docs/00 decision 75). Emptied by retention, never deleted.';
COMMENT ON TABLE ingest.lookup_attempt IS
  'One row per send: what the provider quota counts. Append-only.';
COMMENT ON TABLE ingest.lookup_result IS
  'A provider''s answer, kept as case material and never labelled below the '
  'question. Emptied by retention, never deleted.';

INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  ('lookup.request', 'Send a case selector to an outbound lookup provider', false),
  ('lookup.authorise', 'Sign off a colleague''s lookup that sends case material to a vendor or the public', true)
ON CONFLICT (key) DO NOTHING;
INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  ('CASE_OWNER', 'lookup.request'),
  ('CASE_OWNER', 'lookup.authorise'),
  ('ANALYST', 'lookup.request')
ON CONFLICT DO NOTHING;
""")
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON ingest.lookup, ingest.lookup_result FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE UPDATE, DELETE ON ingest.lookup_attempt FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE n bigint;
BEGIN
  IF to_regclass('ingest.lookup') IS NOT NULL THEN
    SELECT count(*) INTO n FROM ingest.lookup l JOIN core."case" c ON c.id = l.case_id
     WHERE c.legal_hold;
    IF n > 0 THEN
      RAISE EXCEPTION 'refusing to downgrade 0099: lookups belong to a case under legal hold, and legal hold overrides deletion';
    END IF;
  END IF;
END
$pre$;
DELETE FROM iam.role_permission WHERE permission_key IN ('lookup.request', 'lookup.authorise');
DELETE FROM iam.permission WHERE key IN ('lookup.request', 'lookup.authorise');
DROP TABLE IF EXISTS ingest.lookup_attempt;
ALTER TABLE IF EXISTS ingest.lookup DROP CONSTRAINT IF EXISTS lookup_result_fk;
DROP TABLE IF EXISTS ingest.lookup_result;
DROP TABLE IF EXISTS ingest.lookup;
DROP FUNCTION IF EXISTS ingest.guard_lookup_result();
DROP FUNCTION IF EXISTS ingest.lookup_attempt_append_only();
DROP FUNCTION IF EXISTS ingest.lookup_is_a_record();
DROP FUNCTION IF EXISTS ingest.lookup_result_dominates();
""")
