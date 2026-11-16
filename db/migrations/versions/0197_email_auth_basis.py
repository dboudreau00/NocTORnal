"""What made a stored mail verdict believable, and which ones were recorded before the mail stamp.

## Why

Until this release an `Authentication-Results` header was believed when it
sat above every `Received` header and the topmost of those named a trusted
MTA. Both are bytes a sender writes, so a message handed over as a file could
carry a forged verdict and a forged `Received` line under it, and the parser
recorded `dkim=pass` for a domain of the sender's choosing (docs/17,
http_ui-007). The parser now believes a header only under a valid mail stamp
(docs/19 section 2.1), but a verdict already stored cannot be told apart from
one stored under the old rule.

## What

`deception.email_message.auth_basis`: `MAIL_STAMP` on a row whose SPF, DKIM
and DMARC results were read from the header a valid stamp attests, NULL on a
row that records none. Two checks: the value is known, and a row with any
verdict names a basis. The second is NOT VALID, so the rows recorded before
it (a verdict and no basis) stay as they are and every new row is held to it;
the column comment says what such a row means, and the console marks it.

No grant changes: the request role's table-level INSERT covers the column.

## Downgrade

Drops the two checks, then the column. On a database with rows recorded
after this revision the basis is lost; the verdicts stay.
"""
from alembic import op

revision = "0197"
down_revision = "0196"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
ALTER TABLE deception.email_message ADD COLUMN auth_basis text;

ALTER TABLE deception.email_message
  ADD CONSTRAINT email_auth_basis_known
  CHECK (auth_basis IS NULL OR auth_basis = 'MAIL_STAMP');

ALTER TABLE deception.email_message
  ADD CONSTRAINT email_verdict_needs_basis
  CHECK ((spf_result IS NULL AND dkim_result IS NULL AND dmarc_result IS NULL)
         OR auth_basis IS NOT NULL) NOT VALID;

COMMENT ON COLUMN deception.email_message.auth_basis IS
  'MAIL_STAMP: the SPF, DKIM and DMARC results were read from the Authentication-Results header a valid '
  'mail stamp attests (docs/19 section 2.1). NULL on a row that carries a verdict means it was recorded '
  'before the mail stamp (0197), on its place in the Received chain alone: the sender may have chosen it.';
""")


def downgrade() -> None:
    op.execute("""
ALTER TABLE deception.email_message DROP CONSTRAINT email_verdict_needs_basis;
ALTER TABLE deception.email_message DROP CONSTRAINT email_auth_basis_known;
ALTER TABLE deception.email_message DROP COLUMN auth_basis;
""")
