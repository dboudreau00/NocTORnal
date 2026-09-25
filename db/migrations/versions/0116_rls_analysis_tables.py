"""Row-level security on the case's analysis records (S1, 2026-09-25).

0114 put the case record, the graph and the exhibits under policy. This
adds the analysis built on them, whose readers are all case members on
the request connection or already system purposes (the merge and unmerge,
the ACH withheld count):

- `core.hypothesis`, `core.assumption`, `core.node_set`, `core.node_merge`
  (the CASE template): visible in a case the user may read.
- `core.hypothesis_evidence` (CHILD of the hypothesis and the assertion):
  a stance is never more visible than the claim it scores, which is the
  filter `reports.ach_cells` applies itself.
- `core.node_set_member` (CHILD of the set and the node): a membership is
  never more visible than the node it names.

`core.node_merge_edge` stays DEFERRED on purpose: the merge history counts
the ties each merge re-pointed, hidden ones included, and whether that
count is withheld material the case's disclosure setting governs is a
decision this revision does not make by filtering it.

The templates are those of 0114 and `rls_registry.py`, restated here as
frozen text. 0115 gives `core.hypothesis` and `core.node_set` the case_id
index the CASE template needs.

## Downgrade

Drops the policies and disables row security on the six tables.
"""
from alembic import op

revision = "0116"
down_revision = "0115"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"


def _case(table: str) -> str:
    return f"{table}.case_id = ANY ({_CASES})"


def _child(table: str, *parents: tuple[str, str]) -> str:
    return " AND ".join(
        f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"
        for parent, fk in parents)


#: table -> (USING and WITH CHECK), one FOR ALL policy each.
POLICIES: dict[str, str] = {
    "core.hypothesis": _case("hypothesis"),
    "core.assumption": _case("assumption"),
    "core.node_set": _case("node_set"),
    "core.node_merge": _case("node_merge"),
    "core.hypothesis_evidence": _child(
        "hypothesis_evidence", ("core.hypothesis", "hypothesis_id"),
        ("core.assertion", "assertion_id")),
    "core.node_set_member": _child(
        "node_set_member", ("core.node_set", "set_id"), ("core.node", "node_id")),
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
