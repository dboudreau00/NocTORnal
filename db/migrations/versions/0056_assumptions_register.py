"""The assumptions register (docs/08 Phase 6): what a case's findings rest on.

docs/08 asks for it in one paragraph -- per case, list the load-bearing
assumptions explicitly, with a review flag -- and nothing existed for it
until 2026-09-02: no table, no service, no route. The consequence was
structural rather than cosmetic. A report stated its conclusions without
stating its premises, so a reader could not tell a finding ("this wallet
received the ransom") from a working assumption ("the same PGP key means
the same operator") that the finding depended on. The second kind is
exactly what a defence challenges, and it was written down nowhere it
could be challenged.

## Shape

One row per assumption, owned by its case (ON DELETE CASCADE: an
assumption about a case that no longer exists is not a record of
anything). `status` is a closed set enforced by the schema and not by the
service alone, because the service is not the only writer of a Postgres
table -- the same reasoning 0057 applies to compartment keys.

`reviewed_by` and `reviewed_at` are ONE fact, who last passed judgement and
when, so the check forbids a row that names a reviewer with no time or a
time with no reviewer. `review_note` is the reviewer's reason. The service
makes it mandatory for the one transition that erases a finding (REFUTED
back to anything else); the schema leaves it nullable because a
confirmation needs no essay.

`made_by` and `reviewed_by` reference `iam.app_user`: an assumption with no
identifiable author is an anonymous premise, which is the thing the
register exists to abolish.

The index on (case_id, status) serves the two reads that exist: the
register itself, and the report builder asking for the still-standing
subset (`assumptions.REPORTABLE_STATUSES`).

Reversible on an empty database; the downgrade drops the table.
"""
from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE core.assumption (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      uuid NOT NULL REFERENCES core."case"(id) ON DELETE CASCADE,
  statement    text NOT NULL,
  basis        text,
  status       text NOT NULL DEFAULT 'OPEN'
               CONSTRAINT assumption_status_known
               CHECK (status IN ('OPEN', 'CONFIRMED', 'REFUTED', 'WITHDRAWN')),
  made_by      uuid NOT NULL REFERENCES iam.app_user(id),
  made_at      timestamptz NOT NULL DEFAULT now(),
  reviewed_by  uuid REFERENCES iam.app_user(id),
  reviewed_at  timestamptz,
  review_note  text,
  -- One fact, two columns: a reviewer with no time, or a time with no
  -- reviewer, is a row that says "reviewed" without saying by whom or when.
  CONSTRAINT assumption_review_pair
    CHECK ((reviewed_by IS NULL) = (reviewed_at IS NULL))
);

CREATE INDEX assumption_case_status_idx ON core.assumption (case_id, status);

COMMENT ON TABLE core.assumption IS
  'The assumptions a case''s findings rest on (docs/08 Phase 6). OPEN and '
  'CONFIRMED rows are premises the report states; REFUTED is a finding '
  'that a premise was false and stays on the record; WITHDRAWN means the '
  'row was entered in error and is terminal.';
COMMENT ON COLUMN core.assumption.review_note IS
  'Why the last review decided what it did. Required by the service when '
  'a REFUTED assumption is re-opened, because un-refuting in silence '
  'erases a finding.';
""")


def downgrade() -> None:
    run("DROP TABLE core.assumption;")
