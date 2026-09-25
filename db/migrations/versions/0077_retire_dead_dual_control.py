"""Retire the dual-control configuration nothing reads (F9c, dual-control,
2026-09-24).

## What was wrong

0012 created two things for a second authoriser, before there was one:

- `iam.permission.requires_dual_control`, seeded true by 0017 for
  case.delete, evidence.purge, collection_account.reveal and role.manage
  and written false by later seeds. Nothing in the application ever read
  it, and it disagreed with the code: case.delete read as dual-controlled
  and marking a case PURGED took one signature.
- `iam.dual_control_request`, a request table 0028's
  `core.approval_request` replaced before anything wrote to it.

A second, wrong answer to "which operations need two people" is worse than
none: `routers/cases.py` quoted the column in a docstring as if it meant
something. `approvals.OPERATIONS` and `iam.dual_control_operation` are now
the one reader.

## What this does

Drops both. It refuses, naming the count, when `iam.dual_control_request`
holds any row: nothing in the product ever wrote one, so a row there is
something somebody did by hand, and dropping rows nobody understood is not
this migration's call.

## Where it sits

It is independent of the rest of this cluster in code. Every migration
that writes the column (0017, 0053, and the collection authority of wave
0) runs before it; a later migration that names the column fails at
upgrade, which `test_approvals_catalogue.py` catches before it merges.

## Downgrade

Restores the column (true for the four operations 0017 marked) and the
table exactly as 0012 created them.
"""
from alembic import op

revision = "0077"
down_revision = "0076"
branch_labels = None
depends_on = None

#: What 0017 marked, restored on downgrade.
MARKED = ("case.delete", "evidence.purge", "collection_account.reveal",
          "role.manage")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(f"""
DO $pre$
DECLARE
  n bigint;
BEGIN
  IF to_regclass('iam.dual_control_request') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM iam.dual_control_request' INTO n;
    IF n > 0 THEN
      RAISE EXCEPTION USING MESSAGE =
        'refusing to upgrade {revision}: iam.dual_control_request holds ' || n
        || CASE WHEN n = 1 THEN ' row' ELSE ' rows' END
        || ' nothing in the product ever wrote; read '
        || CASE WHEN n = 1 THEN 'it' ELSE 'them' END
        || ', then delete '
        || CASE WHEN n = 1 THEN 'it' ELSE 'them' END || ' by hand';
    END IF;
  END IF;
END
$pre$;

ALTER TABLE iam.permission DROP COLUMN IF EXISTS requires_dual_control;
DROP TABLE IF EXISTS iam.dual_control_request;
""")


def downgrade() -> None:
    marked = ", ".join(f"'{k}'" for k in MARKED)
    run(f"""
ALTER TABLE iam.permission
  ADD COLUMN IF NOT EXISTS requires_dual_control boolean NOT NULL DEFAULT false;
UPDATE iam.permission SET requires_dual_control = true WHERE key IN ({marked});

CREATE TABLE IF NOT EXISTS iam.dual_control_request (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action        text NOT NULL,
  payload       jsonb NOT NULL,
  requested_by  uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  approved_by   uuid REFERENCES iam.app_user(id),
  approved_at   timestamptz,
  executed_at   timestamptz,
  state         text NOT NULL DEFAULT 'PENDING',
  CONSTRAINT dual_control_distinct
    CHECK (approved_by IS NULL OR approved_by <> requested_by)
);
""")
