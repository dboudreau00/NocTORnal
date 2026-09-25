"""The static-triage queue, machine findings and the similarity columns
(F11, 2026-09-24).

## What was wrong

`lab.sample` has carried imphash, rich_header_hash, ssdeep and tlsh
columns since 0031, and nothing ever wrote them: submit() ran a synchronous
triage of hashes, file type and entropy and recorded every other check as
a gap. Computing the rest means parsing and hashing hostile bytes, which
cannot happen inside an upload request (the parsers have had CPU and
memory blow-ups on crafted files), so it runs afterwards, as a queue that
a cron pass and an analyst's request drain (decision 30: functions you
call, no resident worker).

## What this adds

1. `lab.static_run`: one row per requested run. At most one QUEUED and one
   RUNNING run per sample (partial unique indexes); a later request merges
   into the queued run, recording every requester in `requests` so that
   custody can name each person whose request caused the read.
   `priority` orders the claim: an analyst's
   request (0) before submissions and retries (1) before retrohunts and
   backfills (2), and a merged run keeps the highest it absorbed. A queue,
   not a ledger: SCANNED custody and the audit chain are the record, so
   the runtime role keeps full DML and the table has no guard.
2. `lab.sample_analysis.origin` ('analyst' or 'machine') and `run_id`. A
   machine row names no analyst; a machine STATIC row names its run. The
   sandbox (F14) writes machine SANDBOX rows with no run, which
   these CHECKs allow. There is deliberately no "analyst rows name an
   analyst" CHECK: legacy rows are not re-validated, and an existing
   test inserts one without.
3. `lab.sample.ssdeep_tokens` (the exact candidate filter a similarity
   search reads through a GIN index) and `tlsh_lvalue` (the TLSH length
   bucket, which bounds the distance from below), with their CHECKs and
   indexes, and a partial index on rich_header_hash. No column had ever
   been written, so every new CHECK holds on existing rows.
4. Legacy `triage_gaps` rewritten to the new vocabulary {step, status,
   reason}: the five checks static triage now runs become `pending`,
   archive expansion `unavailable`, and the stored prohibited-content
   screening entry is removed, because that gap is derived at read time
   (F11). Nothing is enqueued: decrypting every held sample is the
   operator's decision (`scripts/lab_triage.py --backfill`).

## Downgrade

Refuses, before changing anything, while a run has started or a machine
analysis exists, naming both counts: the findings behind proposals and the
record of what was run would be lost, and rebuilding them decrypts every
sample again. With neither, only never-started queue rows exist, so it
drops the table (a queue), the columns and the indexes, and puts every
row's gaps back to the seven-entry list triage() wrote before this
revision. 0078's downgrade refuses on the same facts (a SCANNED row exists
only once a run started), so a downgrade below here cannot stop half way.
"""
from __future__ import annotations

import json

from alembic import op

revision = "0079"
down_revision = "0078"
branch_labels = None
depends_on = None

#: The gaps triage() wrote before this revision, in its order: what the
#: downgrade restores. Every row in a database at 0078 carries exactly
#: this list, because triage() was deterministic.
GAPS_BEFORE = [
    {"step": "imphash", "reason": "pefile is not a dependency"},
    {"step": "rich_header_hash", "reason": "pefile is not a dependency"},
    {"step": "ssdeep", "reason": "ssdeep needs a C toolchain"},
    {"step": "tlsh", "reason": "py-tlsh is not a dependency"},
    {"step": "yara", "reason": "no rule corpus and no yara-python"},
    {"step": "archive_expansion",
     "reason": "not built: an expander without depth and ratio caps is a "
               "zip bomb waiting to be sent one"},
    {"step": "prohibited_content_screening",
     "reason": "no authorised hash set; the REJECTED path is manual"},
]

#: The five checks static triage runs, and what a legacy row now says
#: about each.
PENDING_STEPS = ("imphash", "rich_header_hash", "ssdeep", "tlsh", "yara")
LEGACY_PENDING = ("recorded before static triage existed; run it from the "
                  "sample card, or scripts/lab_triage.py --backfill")

UPGRADE_SQL = f"""
SET search_path = lab, core, public;

CREATE TABLE static_run (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id        uuid NOT NULL REFERENCES lab.sample(id) ON DELETE CASCADE,
  trigger          text NOT NULL,
  requested_by     uuid REFERENCES iam.app_user(id),
  requests         jsonb NOT NULL DEFAULT '[]',
  priority         smallint NOT NULL DEFAULT 1,
  steps            text[] NOT NULL DEFAULT '{{pe,fuzzy,yara}}',
  yara_version_ids uuid[] NOT NULL DEFAULT '{{}}',
  status           text NOT NULL DEFAULT 'QUEUED',
  attempt          integer NOT NULL DEFAULT 1,
  queued_at        timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  finished_at      timestamptz,
  outcome          jsonb NOT NULL DEFAULT '{{}}',
  failure          text,
  CONSTRAINT static_run_trigger_known
    CHECK (trigger IN ('SUBMIT','ON_DEMAND','RETRY','RETROHUNT','BACKFILL')),
  CONSTRAINT static_run_priority_known CHECK (priority BETWEEN 0 AND 2),
  CONSTRAINT static_run_attempt_positive CHECK (attempt >= 1),
  CONSTRAINT static_run_status_known
    CHECK (status IN ('QUEUED','RUNNING','DONE','FAILED','ABANDONED',
                      'SKIPPED')),
  CONSTRAINT static_run_steps_known
    CHECK (cardinality(steps) > 0
           AND steps <@ ARRAY['pe','fuzzy','yara']::text[]),
  CONSTRAINT static_run_started
    CHECK (status NOT IN ('RUNNING','DONE','FAILED','ABANDONED')
           OR started_at IS NOT NULL),
  CONSTRAINT static_run_queued_untouched
    CHECK (status <> 'QUEUED' OR (started_at IS NULL AND finished_at IS NULL)),
  CONSTRAINT static_run_finished
    CHECK ((status IN ('QUEUED','RUNNING')) = (finished_at IS NULL)),
  CONSTRAINT static_run_failure_says_why
    CHECK ((status IN ('FAILED','ABANDONED','SKIPPED')) = (failure IS NOT NULL)),
  CONSTRAINT static_run_person_named
    CHECK (trigger NOT IN ('ON_DEMAND','RETROHUNT') OR requested_by IS NOT NULL),
  CONSTRAINT static_run_requests_is_a_list
    CHECK (jsonb_typeof(requests) = 'array')
);
CREATE UNIQUE INDEX static_run_one_running ON static_run (sample_id)
  WHERE status = 'RUNNING';
CREATE UNIQUE INDEX static_run_one_queued ON static_run (sample_id)
  WHERE status = 'QUEUED';
CREATE INDEX static_run_queue_idx ON static_run (priority, queued_at)
  WHERE status = 'QUEUED';
CREATE INDEX static_run_sample_idx ON static_run (sample_id, queued_at DESC);

COMMENT ON TABLE static_run IS
  'The static-triage queue (F11). A queue, not a ledger: SCANNED custody '
  'and the audit chain record what was read and who caused it. requests '
  'lists every request merged into the run, so custody can name each '
  'requester.';

ALTER TABLE sample_analysis
  ADD COLUMN origin text NOT NULL DEFAULT 'analyst',
  ADD COLUMN run_id uuid REFERENCES lab.static_run(id),
  ADD CONSTRAINT sample_analysis_origin_known
    CHECK (origin IN ('analyst','machine')),
  ADD CONSTRAINT sample_analysis_machine_names_no_analyst
    CHECK (origin = 'analyst' OR analyst_id IS NULL),
  ADD CONSTRAINT sample_analysis_run_only_on_machine_rows
    CHECK (run_id IS NULL OR origin = 'machine'),
  ADD CONSTRAINT sample_analysis_static_names_its_run
    CHECK (NOT (origin = 'machine' AND kind = 'STATIC') OR run_id IS NOT NULL);
CREATE INDEX sample_analysis_run_idx ON sample_analysis (run_id)
  WHERE run_id IS NOT NULL;

ALTER TABLE sample
  ADD COLUMN ssdeep_tokens text[],
  ADD COLUMN tlsh_lvalue smallint,
  ADD CONSTRAINT sample_tlsh_lvalue_range
    CHECK (tlsh_lvalue BETWEEN 0 AND 255),
  ADD CONSTRAINT sample_tlsh_lvalue_with_tlsh
    CHECK ((tlsh IS NULL) = (tlsh_lvalue IS NULL)),
  ADD CONSTRAINT sample_ssdeep_tokens_with_ssdeep
    CHECK (ssdeep IS NOT NULL OR ssdeep_tokens IS NULL);
CREATE INDEX sample_ssdeep_tokens_idx ON sample USING gin (ssdeep_tokens);
CREATE INDEX sample_tlsh_lvalue_idx ON sample (tlsh_lvalue)
  WHERE tlsh IS NOT NULL;
CREATE INDEX sample_rich_header_idx ON sample (rich_header_hash)
  WHERE rich_header_hash IS NOT NULL;

-- Legacy gaps, element by element and in their order.
UPDATE sample s
   SET triage_gaps = coalesce((
     SELECT jsonb_agg(
              CASE
                WHEN g.e->>'step' IN ({", ".join(f"'{x}'" for x in PENDING_STEPS)})
                     AND NOT g.e ? 'status'
                  THEN jsonb_build_object('step', g.e->>'step',
                                          'status', 'pending',
                                          'reason', '{LEGACY_PENDING}')
                WHEN g.e->>'step' = 'archive_expansion'
                     AND NOT g.e ? 'status'
                  THEN g.e || jsonb_build_object('status', 'unavailable')
                ELSE g.e
              END ORDER BY g.n)
       FROM jsonb_array_elements(s.triage_gaps) WITH ORDINALITY AS g(e, n)
      WHERE g.e->>'step' IS DISTINCT FROM 'prohibited_content_screening'),
     '[]'::jsonb)
 WHERE jsonb_typeof(s.triage_gaps) = 'array'
   AND jsonb_array_length(s.triage_gaps) > 0;
"""

COUNT_SQL = """
SELECT (SELECT count(*) FROM lab.static_run WHERE started_at IS NOT NULL),
       (SELECT count(*) FROM lab.sample_analysis WHERE origin = 'machine')"""


def downgrade_refusal(started: int, machine: int) -> str:
    def n(k: int, one: str, many: str) -> str:
        return f"{k} {one if k == 1 else many}"
    return (
        "refusing to downgrade 0079: "
        + n(started, "static triage run has", "static triage runs have")
        + " started and "
        + n(machine, "machine analysis exists", "machine analyses exist")
        + ". The findings behind proposals and the record of what was run "
        "would be lost, and rebuilding them decrypts every sample again. "
        "Stay at this revision.")


def run(sql: str, params=None) -> None:
    op.get_bind().connection.driver_connection.execute(sql, params)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    started, machine = query(COUNT_SQL)[0]
    if started or machine:
        raise RuntimeError(downgrade_refusal(started, machine))
    run("""
SET search_path = lab, core, public;
DROP INDEX sample_rich_header_idx;
DROP INDEX sample_tlsh_lvalue_idx;
DROP INDEX sample_ssdeep_tokens_idx;
ALTER TABLE sample
  DROP CONSTRAINT sample_ssdeep_tokens_with_ssdeep,
  DROP CONSTRAINT sample_tlsh_lvalue_with_tlsh,
  DROP CONSTRAINT sample_tlsh_lvalue_range,
  DROP COLUMN tlsh_lvalue,
  DROP COLUMN ssdeep_tokens;
DROP INDEX sample_analysis_run_idx;
ALTER TABLE sample_analysis
  DROP CONSTRAINT sample_analysis_static_names_its_run,
  DROP CONSTRAINT sample_analysis_run_only_on_machine_rows,
  DROP CONSTRAINT sample_analysis_machine_names_no_analyst,
  DROP CONSTRAINT sample_analysis_origin_known,
  DROP COLUMN run_id,
  DROP COLUMN origin;
DROP TABLE static_run;
""")
    run("UPDATE lab.sample SET triage_gaps = %s::jsonb",
        (json.dumps(GAPS_BEFORE),))
