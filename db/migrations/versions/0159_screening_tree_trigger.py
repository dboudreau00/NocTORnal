"""A screening result can record that its sample was isolated because a
member of its archive tree matched (roadmap phase 8 "archive expansion",
2026-10-02).

## What this changes

`lab.screening_result.trigger` gains the value ARCHIVE_MEMBER beside
SUBMISSION, LIST_IMPORT and RESCAN. When a member of an archive matches a
prohibited-content hash list, at its creation or on a later import, the
archive and every other member cut from it are isolated through the same
`reject_by_screening` path, and each of those results names what
happened: not that its own hashes matched (they did not), but that the
tree it belongs to holds matched material. The result's detail names the
sample the match was found on (`via_sample`). A result that said RESCAN
or SUBMISSION there would be a false record of why.

The NO_MATCH rule is unchanged: a NO_MATCH result is still only ever a
submission's.

## Downgrade

Refuses while any result carries the new trigger, naming the count: the
records are append-only and the old CHECK would reject them. Otherwise
restores the three-value CHECK.
"""
from __future__ import annotations

from alembic import op

revision = "0159"
down_revision = "0158"
branch_labels = None
depends_on = None

TRIGGERS_0102 = ("SUBMISSION", "LIST_IMPORT", "RESCAN")
TRIGGERS = TRIGGERS_0102 + ("ARCHIVE_MEMBER",)


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


UPGRADE_SQL = f"""
SET search_path = lab, core, public;
ALTER TABLE screening_result
  DROP CONSTRAINT screening_result_trigger_check,
  ADD CONSTRAINT screening_result_trigger_check
    CHECK (trigger IN ({_in(TRIGGERS)}));
COMMENT ON COLUMN screening_result.trigger IS
  'SUBMISSION, LIST_IMPORT, RESCAN, or ARCHIVE_MEMBER: this sample was '
  'isolated because a member of its archive tree matched (the detail '
  'names which).';
"""

DOWNGRADE_SQL = f"""
SET search_path = lab, core, public;
COMMENT ON COLUMN screening_result.trigger IS NULL;
ALTER TABLE screening_result
  DROP CONSTRAINT screening_result_trigger_check,
  ADD CONSTRAINT screening_result_trigger_check
    CHECK (trigger IN ({_in(TRIGGERS_0102)}));
"""

COUNT_SQL = "SELECT count(*) FROM lab.screening_result WHERE trigger = 'ARCHIVE_MEMBER'"


def downgrade_refusal(n: int) -> str:
    rows = "row" if n == 1 else "rows"
    return (f"refusing to downgrade 0159: {n} screening result {rows} record "
            f"an isolation through an archive member, and the record of why a "
            f"sample was isolated is never rewritten")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(DOWNGRADE_SQL)
