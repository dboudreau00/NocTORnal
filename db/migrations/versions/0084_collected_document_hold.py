"""An attributable legal hold on a collected document (the collection
foundation, 2026-09-24; docs/00 decision 74).

## Why

The collector now writes `collect.document.retain_until` for documents
whose category has a retention rule, which arms the document leg of the
purge for the first time. docs/00 decision 74: no code may arm it without
honouring legal hold on the document AND its case. The case half is
queries over existing foreign keys (retention.py's citation registry). The
document half needs a hold a person can place, and a hold nobody can
attribute is a hold nobody can lift, so it gains its reason and who placed
it:

- `legal_hold_reason`, required whenever `legal_hold` is true (CHECK
  `document_hold_has_reason`; every existing row has legal_hold false, so
  it is added validated);
- `legal_hold_by`, the person who last placed or lifted it.

## Indexes

Every leg of the hold predicate and the per-version recheck inside the
purge reads a citing table by `document_id`, and four of them had no index
leading on it: `collect.proposal`, `comms.contact_block`,
`collect.watch_hit` (its unique index leads on `watch_id`) and
`core.tag_assignment` (its unique index leads on `tag_id`).
`core.assertion` already has one. The builds run inside this migration's
transaction, which holds a SHARE lock on each of the four tables while it
builds: writes to them wait for the upgrade.

## Downgrade

Refuses while any document is held: dropping the reason would leave a hold
nobody can attribute. Otherwise it drops the indexes, the constraint and
the columns.
"""
from alembic import op

revision = "0084"
down_revision = "0083"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE collect.document
  ADD COLUMN legal_hold_reason text,
  ADD COLUMN legal_hold_by uuid REFERENCES iam.app_user(id),
  ADD CONSTRAINT document_hold_has_reason
    CHECK (NOT legal_hold OR length(btrim(coalesce(legal_hold_reason, ''))) > 0);

COMMENT ON COLUMN collect.document.legal_hold_reason IS
  'Why this document, and every earlier version of it, is frozen against deletion. Set and lifted by a person with retention.manage; the purge also honours holds on every case that cites it.';
COMMENT ON COLUMN collect.document.legal_hold_by IS
  'Who last placed or lifted the document-level hold.';

CREATE INDEX proposal_document_idx ON collect.proposal (document_id);
CREATE INDEX contact_block_document_idx ON comms.contact_block (document_id);
CREATE INDEX watch_hit_document_idx ON collect.watch_hit (document_id);
CREATE INDEX tag_assignment_document_idx ON core.tag_assignment (document_id);
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM collect.document WHERE legal_hold;
  IF n > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0084: ' || n
      || CASE WHEN n = 1 THEN ' collected document is' ELSE ' collected documents are' END
      || ' under a legal hold, and dropping the reason would leave a hold '
      || 'nobody can attribute';
  END IF;
END
$pre$;

DROP INDEX IF EXISTS core.tag_assignment_document_idx;
DROP INDEX IF EXISTS collect.watch_hit_document_idx;
DROP INDEX IF EXISTS comms.contact_block_document_idx;
DROP INDEX IF EXISTS collect.proposal_document_idx;
ALTER TABLE collect.document
  DROP CONSTRAINT IF EXISTS document_hold_has_reason,
  DROP COLUMN IF EXISTS legal_hold_by,
  DROP COLUMN IF EXISTS legal_hold_reason;
""")
