"""Prohibited-content screening: operator-imported exact-hash lists, and
what a match does to a sample (F13, 2026-09-24).

## What was wrong

Nothing screened anything. samples.py said so: "No prohibited-content
hash screening. The hook and the REJECTED path exist. The hash sets do
not", and every sample carried a gap saying the REJECTED path is manual.
docs/16 L1 item 5 and C3: holding known-material hash sets needs an
authority this deployment records before any list is held.

## What this adds

1. `lab.sample` gains `screening_outcome` (NOT_SCREENED, NO_MATCH or
   MATCH), `screened_at`, `screening_list_seq` (the newest list the row was
   screened against) and `screening_bytes_absent_at` (the
   worker RECORDS that a matched sample's bytes were not found in either
   store; it never zeroes a data key on its own). A MATCH is REJECTED by
   CHECK and permanent by trigger: retiring a list never un-matches a
   sample. Two partial indexes: the matches still waiting for their bytes
   to move, and the rows the next pass has to screen.
2. `lab.screening_list`: one row per imported list, with its licence
   reference, the deployment's hash-set authority copied at import, and
   its retirement. Rows are never deleted; retiring stamps four columns
   once, and purging its entries may be asked for then or later.
3. `lab.screening_hash`: the entries, (algorithm, digest, list). Never
   updated; deleted only in a statement whose every row belongs to a list
   retired with its purge requested (a statement-level check on the
   transition table, so a purge of fifty thousand rows is one check).
4. `lab.screening_result` and `lab.screening_review`: append-only records
   of every match (and every submission screened with no match) and of
   the officer's review of each.

`GUARDED_TABLES` declares what the runtime role keeps; the REVOKE takes
back exactly the rest. Two permissions, both the Security Officer's and
both step-up: `sample.screening.manage` (import and retire lists, start a
pass) and `sample.screening.review` (see matches and record a review).

## Downgrade

Refuses while any result records a MATCH, naming the count: dropping the
record would return matched rows to the Lab queue with their filenames.
Otherwise it drops the four tables, the sample columns and the two
permissions. Custody rows the screening wrote stay (custody is never
deleted); 0078's own downgrade refuses on them.
"""
from __future__ import annotations

from alembic import op

revision = "0102"
down_revision = "0101"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: Guarded tables and the privileges the runtime role KEEPS on each. Read by
#: test_app_role_privileges_pg.py; the REVOKE below takes the complement.
GUARDED_TABLES = {
    "lab.screening_list": ("SELECT", "INSERT", "UPDATE"),
    "lab.screening_hash": ("SELECT", "INSERT", "DELETE"),
    "lab.screening_result": ("SELECT", "INSERT"),
    "lab.screening_review": ("SELECT", "INSERT"),
}

OUTCOMES = ("NOT_SCREENED", "NO_MATCH", "MATCH")
CATEGORIES = ("KNOWN_CSAM", "TERRORIST_CONTENT", "OTHER_PROHIBITED")
TRIGGERS = ("SUBMISSION", "LIST_IMPORT", "RESCAN")
DISPOSITIONS = ("PRESERVE", "NOT_STORED", "STORE_FAILED", "ALREADY_PRESERVED",
                "NO_BYTES", "ALREADY_ISOLATED")
ALERT_OUTCOMES = ("SENT", "COALESCED", "NONE_REACHED", "FAILED")
REVIEW_ACTIONS = ("ACKNOWLEDGED", "REFERRED", "FALSE_POSITIVE_SUSPECTED",
                  "DISPOSED_OUTSIDE", "NOTE")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


UPGRADE_SQL = f"""
SET search_path = lab, core, public;

ALTER TABLE sample
  ADD COLUMN screening_outcome text NOT NULL DEFAULT 'NOT_SCREENED',
  ADD COLUMN screened_at timestamptz,
  ADD COLUMN screening_list_seq bigint,
  ADD COLUMN screening_bytes_absent_at timestamptz,
  ADD CONSTRAINT sample_screening_outcome_known
    CHECK (screening_outcome IN ({_in(OUTCOMES)})),
  ADD CONSTRAINT sample_screening_dated
    CHECK ((screening_outcome = 'NOT_SCREENED') = (screened_at IS NULL)
           AND (screened_at IS NULL) = (screening_list_seq IS NULL)),
  ADD CONSTRAINT sample_match_is_rejected
    CHECK (screening_outcome <> 'MATCH' OR state = 'REJECTED'),
  ADD CONSTRAINT sample_bytes_absent_only_on_match
    CHECK (screening_bytes_absent_at IS NULL OR screening_outcome = 'MATCH');

COMMENT ON COLUMN sample.screening_outcome IS
  'Prohibited-content screening by exact hash (F13). MATCH is permanent '
  'and implies REJECTED; retiring a list never un-matches a sample.';
COMMENT ON COLUMN sample.screening_bytes_absent_at IS
  'Set once when a matched sample''s bytes were found in neither store on '
  'two passes. Recorded, never acted on: the data key is kept.';

-- A match is permanent, and "the bytes were not found" is said once.
CREATE FUNCTION lab.guard_screening_outcome() RETURNS trigger
LANGUAGE plpgsql AS $$
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
CREATE TRIGGER sample_match_is_permanent
  BEFORE UPDATE OF screening_outcome, screening_bytes_absent_at ON sample
  FOR EACH ROW EXECUTE FUNCTION lab.guard_screening_outcome();

-- The matches whose bytes still sit in the working store, and the rows the
-- next pass screens.
CREATE INDEX sample_match_pending_idx ON sample (screened_at)
  WHERE screening_outcome = 'MATCH' AND preserved_key IS NULL
    AND octet_length(data_key_ciphertext) > 0
    AND screening_bytes_absent_at IS NULL;
CREATE INDEX sample_screening_behind_idx
  ON sample (screening_list_seq NULLS FIRST, id)
  WHERE screening_outcome <> 'MATCH';

CREATE TABLE screening_list (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  seq                  bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  name                 text NOT NULL,
  provider             text NOT NULL,
  category             text NOT NULL,
  authority_reference  text NOT NULL,
  deployment_authority text NOT NULL,
  source_sha256        bytea NOT NULL,
  entry_count          integer NOT NULL,
  algorithms           text[] NOT NULL,
  imported_by          uuid NOT NULL REFERENCES iam.app_user(id),
  imported_via         text NOT NULL,
  imported_at          timestamptz NOT NULL DEFAULT now(),
  retired_at           timestamptz,
  retired_by           uuid REFERENCES iam.app_user(id),
  retire_reason        text,
  purge_requested      boolean NOT NULL DEFAULT false,
  purge_requested_by   uuid REFERENCES iam.app_user(id),
  entries_purged_at    timestamptz,
  CONSTRAINT screening_list_named
    CHECK (length(btrim(name)) > 0 AND length(btrim(provider)) > 0),
  CONSTRAINT screening_list_authority
    CHECK (length(btrim(authority_reference)) >= 6
           AND length(btrim(deployment_authority)) >= 6),
  CONSTRAINT screening_list_category_known
    CHECK (category IN ({_in(CATEGORIES)})),
  CONSTRAINT screening_list_via_known CHECK (imported_via IN ('console', 'cli')),
  CONSTRAINT screening_list_source_digest CHECK (octet_length(source_sha256) = 32),
  CONSTRAINT screening_list_not_empty CHECK (entry_count > 0),
  -- cardinality, never array_length, which is NULL for an empty array.
  CONSTRAINT screening_list_algorithms
    CHECK (cardinality(algorithms) >= 1
           AND algorithms <@ ARRAY['md5','sha1','sha256']::text[]),
  CONSTRAINT screening_list_retirement_complete
    CHECK ((retired_at IS NULL) = (retired_by IS NULL)
           AND (retired_at IS NULL) = (retire_reason IS NULL)),
  CONSTRAINT screening_list_purge_after_retire
    CHECK (NOT purge_requested OR retired_at IS NOT NULL),
  CONSTRAINT screening_list_purge_names_who
    CHECK (purge_requested = (purge_requested_by IS NOT NULL)),
  CONSTRAINT screening_list_purged_when_asked
    CHECK (entries_purged_at IS NULL OR purge_requested)
);
CREATE UNIQUE INDEX screening_list_one_active_copy
  ON screening_list (source_sha256) WHERE retired_at IS NULL;
COMMENT ON TABLE screening_list IS
  'Prohibited-content hash lists an operator imported under a recorded '
  'authority (F13). Never deleted; retirement and purge are stamped once.';

-- Never deleted. Retirement is stamped once (the three columns together);
-- the purge may be asked for with it or later, once; the purge is stamped
-- done once. Nothing else ever changes (a list retired without its purge
-- could otherwise never have its entries removed when a licence ends).
CREATE FUNCTION lab.guard_screening_list() RETURNS trigger
LANGUAGE plpgsql AS $$
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
CREATE TRIGGER screening_list_guard BEFORE UPDATE OR DELETE ON screening_list
  FOR EACH ROW EXECUTE FUNCTION lab.guard_screening_list();
CREATE TRIGGER screening_list_no_truncate BEFORE TRUNCATE ON screening_list
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_screening_list();

CREATE TABLE screening_hash (
  list_id    uuid NOT NULL REFERENCES lab.screening_list(id),
  algorithm  text NOT NULL,
  digest     bytea NOT NULL,
  PRIMARY KEY (algorithm, digest, list_id),
  CONSTRAINT screening_hash_algorithm_known
    CHECK (algorithm IN ('md5', 'sha1', 'sha256')),
  CONSTRAINT screening_hash_digest_length
    CHECK (octet_length(digest) = CASE algorithm WHEN 'md5' THEN 16
                                                 WHEN 'sha1' THEN 20
                                                 ELSE 32 END)
);
CREATE INDEX screening_hash_list_idx ON screening_hash (list_id);
COMMENT ON TABLE screening_hash IS
  'The entries of the imported lists. Read only by the matcher '
  '(screening.screen_digests and the rescan); never returned by any route.';

CREATE FUNCTION lab.refuse_screening_hash_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'screening list entries are never % ; retire the list and '
    'purge its entries instead', lower(TG_OP);
END $$;
CREATE FUNCTION lab.guard_screening_hash_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM gone g
               JOIN lab.screening_list l ON l.id = g.list_id
              WHERE l.retired_at IS NULL OR NOT l.purge_requested) THEN
    RAISE EXCEPTION 'only the entries of a list retired with its purge '
      'requested may be deleted';
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER screening_hash_no_update BEFORE UPDATE ON screening_hash
  FOR EACH STATEMENT EXECUTE FUNCTION lab.refuse_screening_hash_change();
CREATE TRIGGER screening_hash_delete_guard AFTER DELETE ON screening_hash
  REFERENCING OLD TABLE AS gone
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_screening_hash_delete();
CREATE TRIGGER screening_hash_no_truncate BEFORE TRUNCATE ON screening_hash
  FOR EACH STATEMENT EXECUTE FUNCTION lab.refuse_screening_hash_change();

CREATE TABLE screening_result (
  id                 uuid PRIMARY KEY,
  sample_id          uuid NOT NULL REFERENCES lab.sample(id),
  sha256             bytea NOT NULL CHECK (octet_length(sha256) = 32),
  screened_at        timestamptz NOT NULL DEFAULT now(),
  trigger            text NOT NULL CHECK (trigger IN ({_in(TRIGGERS)})),
  actor_id           uuid REFERENCES iam.app_user(id),
  outcome            text NOT NULL CHECK (outcome IN ('NO_MATCH', 'MATCH')),
  lists_consulted    uuid[] NOT NULL CHECK (cardinality(lists_consulted) > 0),
  list_seq           bigint NOT NULL,
  matched_lists      uuid[] NOT NULL DEFAULT '{{}}',
  matched_algorithms text[] NOT NULL DEFAULT '{{}}',
  disposition        text CHECK (disposition IN ({_in(DISPOSITIONS)})),
  alert_outcome      text CHECK (alert_outcome IN ({_in(ALERT_OUTCOMES)})),
  officers_notified  integer NOT NULL DEFAULT 0 CHECK (officers_notified >= 0),
  detail             jsonb NOT NULL DEFAULT '{{}}',
  CONSTRAINT screening_result_match_is_named
    CHECK ((outcome = 'MATCH') = (cardinality(matched_lists) > 0)),
  CONSTRAINT screening_result_match_is_disposed
    CHECK ((outcome = 'MATCH') = (disposition IS NOT NULL)
           AND (outcome = 'MATCH') = (alert_outcome IS NOT NULL)),
  -- A pass writes its counts to the audit chain, not a row per sample:
  -- NO_MATCH rows are the submission's alone.
  CONSTRAINT screening_result_no_match_is_a_submission
    CHECK (outcome = 'MATCH' OR trigger = 'SUBMISSION')
);
CREATE INDEX screening_result_sample_idx
  ON screening_result (sample_id, screened_at DESC);
CREATE INDEX screening_result_match_idx
  ON screening_result (screened_at DESC) WHERE outcome = 'MATCH';

CREATE TABLE screening_review (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  result_id    uuid NOT NULL REFERENCES lab.screening_result(id),
  reviewed_by  uuid NOT NULL REFERENCES iam.app_user(id),
  reviewed_at  timestamptz NOT NULL DEFAULT now(),
  action       text NOT NULL CHECK (action IN ({_in(REVIEW_ACTIONS)})),
  reference    text,
  note         text,
  CONSTRAINT screening_review_referenced
    CHECK (action NOT IN ('REFERRED', 'DISPOSED_OUTSIDE')
           OR length(btrim(coalesce(reference, ''))) > 0),
  CONSTRAINT screening_review_says_something
    CHECK (action = 'ACKNOWLEDGED'
           OR length(btrim(coalesce(reference, '') || coalesce(note, ''))) > 0)
);
CREATE INDEX screening_review_result_idx ON screening_review (result_id, reviewed_at);

CREATE FUNCTION lab.block_screening_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: a screening record is history',
    TG_TABLE_NAME;
END $$;
CREATE TRIGGER screening_result_append_only
  BEFORE UPDATE OR DELETE ON screening_result
  FOR EACH ROW EXECUTE FUNCTION lab.block_screening_mutation();
CREATE TRIGGER screening_result_no_truncate BEFORE TRUNCATE ON screening_result
  FOR EACH STATEMENT EXECUTE FUNCTION lab.block_screening_mutation();
CREATE TRIGGER screening_review_append_only
  BEFORE UPDATE OR DELETE ON screening_review
  FOR EACH ROW EXECUTE FUNCTION lab.block_screening_mutation();
CREATE TRIGGER screening_review_no_truncate BEFORE TRUNCATE ON screening_review
  FOR EACH STATEMENT EXECUTE FUNCTION lab.block_screening_mutation();
"""

REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON lab.screening_list FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE UPDATE ON lab.screening_hash FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE UPDATE, DELETE ON lab.screening_result, '
                   'lab.screening_review FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

PERMISSIONS_SQL = """
INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  ('sample.screening.manage',
   'Import and retire prohibited-content hash lists, and start a screening pass',
   true),
  ('sample.screening.review',
   'See prohibited-content screening matches and record their review',
   true)
ON CONFLICT (key) DO NOTHING;
INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  ('SECURITY_OFFICER', 'sample.screening.manage'),
  ('SECURITY_OFFICER', 'sample.screening.review')
ON CONFLICT DO NOTHING;
"""

COUNT_SQL = "SELECT count(*) FROM lab.screening_result WHERE outcome = 'MATCH'"


def downgrade_refusal(n: int) -> str:
    return (f"refusing to downgrade 0102: {n} prohibited-content screening "
            f"{'match is' if n == 1 else 'matches are'} recorded. Dropping the "
            f"record would return matched samples to the Lab queue with their "
            f"filenames. Stay at this revision.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)
    run(REVOKE_SQL)
    run(PERMISSIONS_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run("""
DELETE FROM iam.role_permission
 WHERE permission_key IN ('sample.screening.manage', 'sample.screening.review');
DELETE FROM iam.permission
 WHERE key IN ('sample.screening.manage', 'sample.screening.review');
SET search_path = lab, core, public;
DROP TABLE screening_review;
DROP TABLE screening_result;
DROP TABLE screening_hash;
DROP TABLE screening_list;
DROP FUNCTION lab.block_screening_mutation();
DROP FUNCTION lab.guard_screening_hash_delete();
DROP FUNCTION lab.refuse_screening_hash_change();
DROP FUNCTION lab.guard_screening_list();
DROP INDEX sample_screening_behind_idx;
DROP INDEX sample_match_pending_idx;
DROP TRIGGER sample_match_is_permanent ON sample;
DROP FUNCTION lab.guard_screening_outcome();
ALTER TABLE sample
  DROP CONSTRAINT sample_bytes_absent_only_on_match,
  DROP CONSTRAINT sample_match_is_rejected,
  DROP CONSTRAINT sample_screening_dated,
  DROP CONSTRAINT sample_screening_outcome_known,
  DROP COLUMN screening_bytes_absent_at,
  DROP COLUMN screening_list_seq,
  DROP COLUMN screened_at,
  DROP COLUMN screening_outcome;
""")
