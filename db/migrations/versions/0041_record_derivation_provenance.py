"""A record now says HOW its category and its fingerprint were derived.

One concern -- the provenance of the two fields the parser derives -- and
both halves exist because the derivations changed in a way that makes old
values and new values incomparable. Storing the new value next to the old
one without saying which is which is how a dedup pass starts marking
unrelated records as duplicates of each other.

## `simhash_version`

docs/17 F15(g). The old fingerprint tokenised `\\w+` over the serialised
JSON, so key names counted as content and field position was lost:
`{"note": "leaked by LockBit", "victim": "ACME"}` and the same document
with those two values swapped hashed IDENTICALLY, hamming distance 0, and
the second was filed as a duplicate of the first. Meanwhile a genuine
repost carrying a mirror's envelope fields landed at 6-13, above the
threshold of 3. It false-positived on semantics and false-negatived on the
one case it exists for.

Version 2 tokenises path-qualified VALUES and drops envelope keys. A
version 1 fingerprint and a version 2 fingerprint mean different things, so
`_near_duplicate` compares within a version and existing rows keep their 1.
They age out of the 500-row comparison window on their own; nothing needs
to be recomputed, and nothing may be compared across the boundary.

## `STRUCTURE_NESTED`

docs/17 F15(h). `categorise` inspected top-level keys only, so a partner
wrapping their payload -- `{"log": {...}}` -- had their stealer log
classified UNKNOWN, which skipped the high-risk compartment check and gave
the record 365 days instead of 90. It now descends. A nested match is real
evidence but weaker evidence about the document as a whole, and an analyst
correcting a category needs to see which it was rather than inferring it
from a confidence of 0.8 versus 0.9.
"""
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = ingest, core, public;

-- 1, not 2: every row already here was fingerprinted by the old
-- tokeniser, and defaulting them to the current version would assert
-- something false about data nobody re-read.
ALTER TABLE record ADD COLUMN simhash_version smallint NOT NULL DEFAULT 1;
COMMENT ON COLUMN record.simhash_version IS
  'Which tokeniser produced simhash. Fingerprints of different versions '
  'are not comparable -- see docs/17 F15(g).';

-- The comparison window is ordered by created_at and filtered by version,
-- so both belong in the index or the filter is a scan.
DROP INDEX IF EXISTS record_simhash_idx;
CREATE INDEX record_simhash_idx
  ON record (simhash_version, created_at DESC)
  WHERE simhash IS NOT NULL AND duplicate_of IS NULL;

ALTER TABLE record DROP CONSTRAINT record_category_source_known;
ALTER TABLE record ADD CONSTRAINT record_category_source_known
  CHECK (category_source IN ('DECLARED', 'STRUCTURE', 'STRUCTURE_NESTED',
                             'CONTENT', 'ANALYST'));
""")


def downgrade() -> None:
    run("""
SET search_path = ingest, core, public;

-- A nested structural match is still a structural match, so the value
-- collapses rather than being lost. The confidence already records that
-- it was the weaker kind.
UPDATE record SET category_source = 'STRUCTURE'
 WHERE category_source = 'STRUCTURE_NESTED';
ALTER TABLE record DROP CONSTRAINT record_category_source_known;
ALTER TABLE record ADD CONSTRAINT record_category_source_known
  CHECK (category_source IN ('DECLARED', 'STRUCTURE', 'CONTENT', 'ANALYST'));

DROP INDEX IF EXISTS record_simhash_idx;
-- Restored exactly as 0033 created it: a downgrade that leaves the schema
-- one index short is a downgrade that only works once.
CREATE INDEX record_simhash_idx ON record (simhash) WHERE simhash IS NOT NULL;
ALTER TABLE record DROP COLUMN simhash_version;
""")
