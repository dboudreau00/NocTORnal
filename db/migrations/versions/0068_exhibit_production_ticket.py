"""A download ticket may name an EXHIBIT: attacker markup is produced
through the sample origin, the only origin allowed to serve it.

## What was wrong (x-hostile-export, 2026-09-24)

docs/19 section 1.1: a DOM, HAR or `.eml` exhibit is attacker-authored
markup, download-only, "and only from the separate sample origin. The
same gate `lab.sample.download` already passes through. The API origin
never serves those bytes." Since 2026-09-23 the application origin keeps
the last sentence: `GET .../content` and `POST .../export` refuse such an
exhibit with 409 and audit the refusal. Nothing kept the first two. The
sample origin serves sample downloads and nothing else
(`app._allowed_on_sample_origin`), and the one credential that crosses to
it, `lab.download_ticket`, could only name a sample: `sample_id` NOT NULL
(0061) and a purpose CHECK over `download` and `preserved_retrieval`
(0063). So an exhibit of attacker markup could not be produced at all, by
anyone, and the card said "No export here". The flagship demo case's only
exhibit is an `.eml`.

## What this changes

1. `evidence_id`, a foreign key to `core.evidence`: a ticket may name ONE
   exhibit instead of one sample.
2. `sample_id` loses NOT NULL, and `download_ticket_names_one_object`
   says a ticket names exactly one of the two. A ticket naming both would
   be two authorities in one row; naming neither, none.
3. A third purpose, `exhibit_production`, and
   `download_ticket_purpose_matches_object`: an exhibit ticket is always
   `exhibit_production` and `exhibit_production` always names an exhibit.
   The Lab's redemption matches on `sample_id` and the exhibit's on
   `evidence_id`, so a ticket minted for one can never be spent at the
   other's path; the constraint makes that a property of the table rather
   than of two WHERE clauses agreeing.
4. `download_ticket_evidence_idx`, the audit trail's read for one exhibit,
   in the shape of `download_ticket_sample_idx`.

## Why the Lab's ticket and not a table of its own

Everything 0061 argues for the sample ticket holds for this one word for
word: minted on the APPLICATION origin under the cookie session and its
CSRF double-submit, stored as its SHA-256 only, good for one redemption
within sixty seconds, spent by one atomic `UPDATE ... RETURNING`, and
exhausted state rather than a ledger (the custody row EXPORTED and the
audit chain are the record). A second table would be a second copy of
each of those decisions, and `download_ticket_live_idx` already serves
the retention sweep 0061 describes for both.

The redemption re-derives the mint's decision on the sample origin before
a byte moves, as the Lab's does: the holder's account is active and still
holds `evidence.export` on the exhibit's case at its labels, the exhibit
is still attacker markup, unpurged, and still allowed out by the egress
gate. The session is not re-read, the residual 0061 states.

## Downgrade

Deletes the exhibit tickets, which is what makes the old NOT NULL and
CHECK true again. They are exhausted state (0061): the issue, the
redemption and every refusal naming a real ticket are in `audit.event`,
and a production that served bytes is an EXPORTED custody row, neither of
which a downgrade touches.
"""
from alembic import op

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = lab, core, public;

ALTER TABLE download_ticket
  ADD COLUMN evidence_id uuid REFERENCES core.evidence(id),
  ALTER COLUMN sample_id DROP NOT NULL;

ALTER TABLE download_ticket
  DROP CONSTRAINT download_ticket_purpose_known;

ALTER TABLE download_ticket
  ADD CONSTRAINT download_ticket_purpose_known
    CHECK (purpose IN ('download', 'preserved_retrieval',
                       'exhibit_production')),
  ADD CONSTRAINT download_ticket_names_one_object
    CHECK (num_nonnulls(sample_id, evidence_id) = 1),
  ADD CONSTRAINT download_ticket_purpose_matches_object
    CHECK ((purpose = 'exhibit_production') = (evidence_id IS NOT NULL));

CREATE INDEX download_ticket_evidence_idx
  ON download_ticket (evidence_id, issued_at DESC)
  WHERE evidence_id IS NOT NULL;

COMMENT ON TABLE download_ticket IS
  'One-shot, sixty-second authority to download ONE sample, or to produce '
  'ONE exhibit of attacker markup, from the sample origin, minted on the '
  'application origin under a cookie session. Exhausted state, not a '
  'ledger: lab.sample_access and core.evidence_custody are the custody '
  'records and audit.event carries the issue and the redemption.';
""")


def downgrade() -> None:
    run("""
SET search_path = lab, core, public;

DELETE FROM download_ticket WHERE evidence_id IS NOT NULL;

DROP INDEX IF EXISTS download_ticket_evidence_idx;

ALTER TABLE download_ticket
  DROP CONSTRAINT IF EXISTS download_ticket_purpose_matches_object,
  DROP CONSTRAINT IF EXISTS download_ticket_names_one_object,
  DROP CONSTRAINT IF EXISTS download_ticket_purpose_known,
  DROP COLUMN IF EXISTS evidence_id,
  ALTER COLUMN sample_id SET NOT NULL;

ALTER TABLE download_ticket
  ADD CONSTRAINT download_ticket_purpose_known
    CHECK (purpose IN ('download', 'preserved_retrieval'));

COMMENT ON TABLE download_ticket IS
  'One-shot, sixty-second authority to download ONE sample from the '
  'sample origin, minted on the application origin under a cookie '
  'session. Exhausted state, not a ledger: lab.sample_access is the '
  'custody record and audit.event carries the issue and the redemption.';
""")
