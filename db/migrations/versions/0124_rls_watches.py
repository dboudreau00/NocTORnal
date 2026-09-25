"""Row-level security on watches and what they matched (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `collect.watch` (CUSTOM): a case's watches in a case the user may read;
  a case-less watch to every bound user. A watch names a selector or a
  keyword and a case: that is the case's content.
- `collect.watch_hit` (CHILD of the watch and of the document): a hit is
  shown in its watch's case and never beside a document the reader may not
  see (the document's own policy, 0118, is the case-less ceiling, which is
  exactly the watch-hit queue's documented rule, the DOCUMENT's label).

Who must see every watch, and runs as a system purpose: the collector,
which matches every case's watches (COLLECTION, 0118 onwards), and ingest
scoring, which scores a quarantined record against every watch in the
deployment and a case's record against its case's and the case-less ones
(`IngestService._watches_for`, INGEST). The router still withholds a watch
the operator may not read from the score's reasons.

Acknowledging a hit now reaches only a hit in a case the caller may read:
the route checks the case it is asked under, and the service never did.

## Downgrade

Drops both policies and disables row security on the two tables.
"""
from alembic import op

revision = "0124"
down_revision = "0123"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"

#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "collect.watch": (f"(watch.case_id IS NULL AND {_CLR} IS NOT NULL) OR "
                      f"watch.case_id = ANY ({_CASES})"),
    "collect.watch_hit": (
        "EXISTS (SELECT 1 FROM collect.watch p WHERE p.id = watch_hit.watch_id) AND "
        "EXISTS (SELECT 1 FROM collect.document p WHERE p.id = watch_hit.document_id)"),
}


def upgrade_sql() -> str:
    out = []
    for table, qual in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_gate ON {table} FOR ALL "
                   f"USING ({qual}) WITH CHECK ({qual});")
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table in reversed(list(POLICIES)):
        out.append(f"DROP POLICY rls_gate ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
