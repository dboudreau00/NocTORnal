"""A merge is visible only where both of its entities are (beta review,
2026-10-03: rls-1, graph-merge-ledger-and-approvals-leak, http_ui-001).

## What this enforces, and for whom

`core.node_merge` carried the CASE template alone (0116), so the request
role read every merge of a readable case: both node ids, the merger's free
reason and the reversal's reason, for merges of entities above the reader
or outside their compartments. The history route served exactly that to
every case reader, LIAISON and READ_ONLY included. The policy is restated
as the case term AND both entities visible: an EXISTS over `core.node`,
which is itself under its ELEMENT policy, for the source and for the
target. `core.node_merge_edge` is a CHILD of this table (0123), so a merge's
re-pointed ties follow it without a change of their own.

The application filters the same way first (`MergeService.history_for_
reader`, `get_for_reader`), so a development stack, whose request
connection row security does not filter, answers the same; this is the
defence behind it, for an injected statement on the request role.

## Who it does not touch

The owner (Alembic, fixtures, pg_dump) and `noctornal_worker`: the merge
and its reversal run as the MERGE system purpose and see every merge, the
withheld count of merges runs as WITHHELD, and the retirement guard that
looks for a live merge into an entity runs as GRAPH_GUARD.

No anti-join and no caller-settable value (test_rls_registry_pg): two
EXISTS over a policied table.

## Downgrade

Restores the CASE template of 0116, as frozen text.
"""
from alembic import op

revision = "0132"
down_revision = "0131"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"

#: Frozen text: a later revision that changes this restates it.
_CASE_TERM = f"node_merge.case_id = ANY ({_CASES})"
_BOTH_ENDS = (
    f"{_CASE_TERM}"
    " AND EXISTS (SELECT 1 FROM core.node s"
    " WHERE s.id = node_merge.source_node_id)"
    " AND EXISTS (SELECT 1 FROM core.node t"
    " WHERE t.id = node_merge.target_node_id)")


def upgrade_sql() -> str:
    return (f"ALTER POLICY rls_gate ON core.node_merge "
            f"USING ({_BOTH_ENDS}) WITH CHECK ({_BOTH_ENDS});")


def downgrade_sql() -> str:
    return (f"ALTER POLICY rls_gate ON core.node_merge "
            f"USING ({_CASE_TERM}) WITH CHECK ({_CASE_TERM});")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
