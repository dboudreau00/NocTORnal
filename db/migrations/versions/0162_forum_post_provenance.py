"""A forum post or member profile says whether it was read as a member,
and by which persona under which authority (the authenticated forum
path, 2026-10-02).

## What this adds

`collect.forum_post` and `collect.forum_member` gain:

- `provenance text NOT NULL DEFAULT 'PUBLIC'`, PUBLIC or MEMBER. A member
  read is a different act from a public one (docs/16 L3, L4), and the
  record of which it was belongs on the row, not in a join to a run.
- `collection_account_id` (the persona that read it) and `authority_id`
  (the confirmed authority the read ran under), both set exactly when the
  provenance is MEMBER (`forum_post_member_names_its_persona`): a public
  read has no persona and names none.

Both reference their tables without ON DELETE: a persona and an authority
are never deleted (0083 refuses while one exists), so a side row never
dangles.

Row-level security: both tables keep their CHILD policy of the document
(0118, rls_registry.py). A member row is no more visible than its
document, which carries its source's compartments once 0163 lands.

## Downgrade

Refuses while any row records a member read, naming the count: dropping
the provenance would turn a member read into a public one on the record.
Otherwise drops the six columns.
"""
from __future__ import annotations

from alembic import op

revision = "0162"
down_revision = "0161"
branch_labels = None
depends_on = None

PROVENANCES = ("PUBLIC", "MEMBER")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _table_sql(table: str) -> str:
    return f"""
ALTER TABLE collect.{table}
  ADD COLUMN provenance text NOT NULL DEFAULT 'PUBLIC',
  ADD COLUMN collection_account_id uuid REFERENCES collect.collection_account(id),
  ADD COLUMN authority_id uuid REFERENCES collect.collection_authority(id),
  ADD CONSTRAINT {table}_provenance_known
    CHECK (provenance IN ({_in(PROVENANCES)})),
  ADD CONSTRAINT {table}_member_names_its_persona
    CHECK ((provenance = 'MEMBER') = (collection_account_id IS NOT NULL)
           AND (provenance = 'MEMBER') = (authority_id IS NOT NULL));
COMMENT ON COLUMN collect.{table}.provenance IS
  'PUBLIC: read without signing in. MEMBER: read as the persona named, '
  'under the authority named (2026-10-02).';
"""


UPGRADE_SQL = _table_sql("forum_post") + _table_sql("forum_member")

DOWNGRADE_SQL = "".join(f"""
ALTER TABLE collect.{table}
  DROP CONSTRAINT {table}_member_names_its_persona,
  DROP CONSTRAINT {table}_provenance_known,
  DROP COLUMN authority_id,
  DROP COLUMN collection_account_id,
  DROP COLUMN provenance;
""" for table in ("forum_member", "forum_post"))

COUNT_SQL = ("SELECT (SELECT count(*) FROM collect.forum_post WHERE provenance = 'MEMBER')"
             " + (SELECT count(*) FROM collect.forum_member WHERE provenance = 'MEMBER')")


def downgrade_refusal(n: int) -> str:
    rows = "row records" if n == 1 else "rows record"
    return (f"refusing to downgrade 0162: {n} forum {rows} a read as a member, "
            f"and dropping the provenance would record it as a public read")


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
