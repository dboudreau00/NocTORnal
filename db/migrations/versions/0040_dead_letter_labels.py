"""The dead-letter queue was the one table that held victim data unlabelled.

docs/17 F15(d). `ingest.record` carries a classification, compartments and
a retention clock, and every read path checks them. `ingest.dead_letter`
carried none of the three, and it holds the SAME data -- a fragment
dead-letters because it would not parse, not because it was harmless.

The route in is routine rather than adversarial: `categorise` sends any
record with top-level `email` + `password` to `CREDENTIAL_DUMP`, only
`STEALER_LOG` is gated for a compartment at key issue, and a partner whose
schema drifts dead-letters their whole feed. So a table with no
classification, no compartments and no expiry accumulates victim
credentials in the clear, and nothing in the system knows to stop.

## The retention default is 90 days, not 365

`IngestService._retain_until` defaults an unknown category to 365. That is
right for a record, whose category was at least *assessed*. A dead letter's
category is unknown BY CONSTRUCTION -- the parse failed, so nothing looked
at the content -- and the safe default for unassessed third-party content
is the shortest rule, not the longest. A fragment that turns out to matter
gets replayed into a record within days; one that nobody replays in three
months is landfill with a legal cost attached.

## What this migration does NOT do

It does not rewrite the fragments already in the table. Redaction is not
reversible, and this project's rule is that a migration is. Existing rows
get labels and a clock -- so they are protected and they expire -- and the
in-place repair is `scripts/redact_dead_letters.py`, which a human runs
deliberately and which reports what it changed. docs/17 F15(d) records that
the repair is outstanding until somebody runs it.

Going forward `IngestService._dead_letter` redacts before the INSERT, so
the repair is a one-off for data recorded before today.
"""
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = ingest, core, public;

ALTER TABLE dead_letter
  ADD COLUMN classification core.tlp NOT NULL DEFAULT 'AMBER',
  ADD COLUMN compartments   text[]   NOT NULL DEFAULT '{}',
  ADD COLUMN retain_until   timestamptz,
  -- Whether `raw_fragment` is verbatim. False on every row recorded
  -- before this migration, and an analyst reading one needs to know
  -- which they are looking at before they quote it in a report.
  ADD COLUMN redacted       boolean  NOT NULL DEFAULT false,
  -- The digest of what ACTUALLY arrived, taken before redaction. The
  -- verbatim bytes remain in the batch's raw object under the batch's own
  -- retention; this is how you prove the redacted text corresponds to
  -- them without keeping a second copy of the credential.
  ADD COLUMN fragment_sha256 bytea,
  ADD COLUMN purged_at      timestamptz;

COMMENT ON COLUMN dead_letter.raw_fragment IS
  'Redacted unless dead_letter.redacted is false. Verbatim bytes live in '
  'the batch raw object, not here -- docs/17 F15(d).';

-- Backfill the labels from the key that issued the batch. A dead letter
-- inherits the ceiling and the compartment of the feed it arrived on: it
-- is the same data, and the parse failing does not declassify it.
UPDATE dead_letter dl
   SET classification = k.classification_ceiling,
       compartments   = CASE WHEN k.forced_compartment IS NULL THEN '{}'
                             ELSE ARRAY[k.forced_compartment] END
  FROM api_key k
 WHERE k.id = dl.api_key_id;

-- And the clock. `occurred_at` rather than now(), so a backfilled row is
-- already most of the way through its life rather than getting a fresh
-- three months for having been overlooked.
UPDATE dead_letter dl
   SET retain_until = dl.occurred_at
                    + (coalesce(r.retain_days, 90) || ' days')::interval
  FROM api_key k
  LEFT JOIN core.retention_rule r ON r.category = k.declared_category
 WHERE k.id = dl.api_key_id;

-- Rows with no key at all (there should be none, the column is nullable
-- for historical reasons) still get a clock rather than living forever.
UPDATE dead_letter
   SET retain_until = occurred_at + interval '90 days'
 WHERE retain_until IS NULL;

-- The sweep. Partial, because a purged row is not a candidate again.
CREATE INDEX dead_letter_retention_idx ON dead_letter (retain_until)
  WHERE purged_at IS NULL;
-- The read path filters on both labels; a compartmented queue is small
-- and the classification is the selective half.
CREATE INDEX dead_letter_labels_idx ON dead_letter (classification);

-- NOT VALID is the whole point, not a shortcut: Postgres enforces a NOT
-- VALID check on every INSERT and UPDATE and does not apply it to rows
-- already present. That is exactly the grandfather clause this needs --
-- nothing may write a verbatim fragment from now on, the rows recorded
-- before the redactor existed stay readable, and any UPDATE to one of
-- them (which is what the repair script does) has to set the flag
-- honestly. Deterministic, unlike a hard-coded cutoff date.
--
-- It is a claim, not a proof: a caller could set redacted = true over
-- verbatim text. It forces the claim to be explicit, which is the most a
-- constraint can do about the CONTENT of a text column.
ALTER TABLE dead_letter ADD CONSTRAINT dead_letter_new_rows_are_redacted
  CHECK (redacted) NOT VALID;
""")


def downgrade() -> None:
    run("""
ALTER TABLE ingest.dead_letter DROP CONSTRAINT dead_letter_new_rows_are_redacted;
DROP INDEX ingest.dead_letter_labels_idx;
DROP INDEX ingest.dead_letter_retention_idx;
COMMENT ON COLUMN ingest.dead_letter.raw_fragment IS NULL;
ALTER TABLE ingest.dead_letter
  DROP COLUMN purged_at,
  DROP COLUMN fragment_sha256,
  DROP COLUMN redacted,
  DROP COLUMN retain_until,
  DROP COLUMN compartments,
  DROP COLUMN classification;
""")
