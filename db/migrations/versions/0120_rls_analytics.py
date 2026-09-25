"""Row-level security on the stored analysis runs and layouts (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `analytics.projection` (the CASE template): in a case the user may read.
- `analytics.metric_run` (CUSTOM, docs/00 decision 31): a run of a
  visible projection whose `visibility_clearance` is within the user's
  ceiling for that projection's case and whose `visibility_compartments`
  they hold. A run is computed over one reader's view of the graph and
  cached at exactly that view; every reader in `analytics_runs.py` asks
  for runs at its own visibility, so the policy admits everything the
  application reads and nothing computed over a view above the reader.
- `analytics.node_metric`, `analytics.community_assignment` (CHILD of the
  run and of the node, CONCOR positions included) and
  `analytics.layout_position` (CHILD of the projection and of the node):
  a score, a block or a saved position is never more visible than the
  entity it describes. The saved canvas used to hand every position in the
  case, hidden entities' ids included, to any reader of the case.

Nothing that reads these tables needs to see more than its reader may:
the cache is keyed on the reader's own visibility, and the layout and the
trend are the reader's view of the graph.

## Downgrade

Drops every policy and disables row security on the five tables.
"""
from alembic import op

revision = "0120"
down_revision = "0119"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"


def _child(table: str, *parents: tuple[str, str]) -> str:
    return " AND ".join(
        f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"
        for parent, fk in parents)


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "analytics.projection": f"projection.case_id = ANY ({_CASES})",
    "analytics.metric_run": (
        "EXISTS (SELECT 1 FROM analytics.projection p "
        "WHERE p.id = metric_run.projection_id "
        f"AND (metric_run.visibility_clearance <= {_CLR} "
        f"OR metric_run.visibility_clearance <= "
        f"iam.rls_ceiling_for({_CEIL}, p.case_id))) "
        f"AND metric_run.visibility_compartments <@ {_HELD}"),
    "analytics.node_metric": _child(
        "node_metric", ("analytics.metric_run", "metric_run_id"),
        ("core.node", "node_id")),
    "analytics.community_assignment": _child(
        "community_assignment", ("analytics.metric_run", "metric_run_id"),
        ("core.node", "node_id")),
    "analytics.layout_position": _child(
        "layout_position", ("analytics.projection", "projection_id"),
        ("core.node", "node_id")),
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
