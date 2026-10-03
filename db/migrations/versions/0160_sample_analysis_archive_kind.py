"""A machine finding of kind ARCHIVE: what the expansion of an archive
sample found and refused (roadmap phase 8 "archive expansion",
2026-10-02).

## What this changes

`lab.sample_analysis.kind` gains ARCHIVE beside STATIC, YARA, MANUAL_RE,
SANDBOX and VENDOR. The expansion writes one machine row of this kind on
the archive sample, naming its run: the archive's family, the limits in
force, every member stored (its path and child sample), every entry
refused with the reason, and a whole-archive refusal where there was one.
It is a finding like the static-triage row (origin `machine`, no analyst,
`run_id` set), and it is the record a reader of the archive sees of what
was cut from it and what was not; the gap `archive_expansion` on the
sample carries the one-line answer, and is removed once the expansion is
done.

The existing rule that a machine STATIC row names its run is unchanged;
an ARCHIVE row names its run the same way and that is held by the
expansion, not by a CHECK, as the SANDBOX rows are.

## Downgrade

Refuses while any ARCHIVE row exists, naming the count: a finding is
never deleted, and the old CHECK would reject the rows. Otherwise
restores the five-value CHECK.
"""
from __future__ import annotations

from alembic import op

revision = "0160"
down_revision = "0159"
branch_labels = None
depends_on = None

KINDS_BEFORE = ("STATIC", "YARA", "MANUAL_RE", "SANDBOX", "VENDOR")
KINDS = KINDS_BEFORE + ("ARCHIVE",)


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


UPGRADE_SQL = f"""
SET search_path = lab, core, public;
ALTER TABLE sample_analysis
  DROP CONSTRAINT sample_analysis_kind_known,
  ADD CONSTRAINT sample_analysis_kind_known
    CHECK (kind IN ({_in(KINDS)}));
"""

DOWNGRADE_SQL = f"""
SET search_path = lab, core, public;
ALTER TABLE sample_analysis
  DROP CONSTRAINT sample_analysis_kind_known,
  ADD CONSTRAINT sample_analysis_kind_known
    CHECK (kind IN ({_in(KINDS_BEFORE)}));
"""

COUNT_SQL = "SELECT count(*) FROM lab.sample_analysis WHERE kind = 'ARCHIVE'"


def downgrade_refusal(n: int) -> str:
    rows = "row" if n == 1 else "rows"
    return (f"refusing to downgrade 0160: {n} archive expansion finding "
            f"{rows} exist, and a finding is never deleted")


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
