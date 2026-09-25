"""Row-level security on the case record, the graph and the exhibits (S1).

## What this enforces, and for whom

`noctornal_app`, the role every request connects as, now sees and writes
only the rows its bound user may read (0111's functions, bound per
request by `db.bind_session` / `db.bind_ticket`):

- `core."case"`: a case on an unexpired assignment, within the user's
  clearance (raised by a live break-glass grant, global or for that case)
  and compartments. Updatable only to labels the user could still read.
  No INSERT or DELETE policy: a case is created on the system connection,
  because its owner's assignment is an IAM write (0109), and nothing
  deletes a case row outside the system purge.
- `core.node`, `core.edge`, `core.evidence` (the ELEMENT template): in a
  readable case, the element's own classification within the user's
  ceiling for that case, its compartments held.
- `core.assertion`: in a readable case, about a node or edge the user can
  see. A claim is never more visible than its subject.
- `core.evidence_link` (CHILD): its exhibit, and its node or edge, visible.
- `core.evidence_custody` (LEDGER CHILD): readable and appendable where
  its exhibit is visible; it keeps no UPDATE or DELETE privilege at all.

The verb and the step-up clock are NOT mirrored: a row does not know which
verb is reading it, and `security.access.evaluate` stays the one place
they are decided. Everything else in `evaluate` (assignment, lattice,
compartments, break-glass) is.

## Who it does not touch

The owner (Alembic, the test suite's fixtures, pg_dump): tables are
ENABLEd, never FORCEd. `noctornal_worker`: BYPASSRLS, for the system
purposes that must see every row (retention, lock extension, legal hold,
the withheld counts, the retirement guard, merges). Development and CI
connect as the owner and see no difference at all.

## How the per-row cost is bounded

Every definer call is an uncorrelated scalar subquery, so it is planned
as ONE initplan per statement; per row a policy does an enum comparison,
an array containment and, for a child or an assertion, a primary-key
probe of the parent. `iam.rls_ceiling_for` is plain SQL and inlines; its
branch runs only for a row above the user's global ceiling.

## Other tables

`noctornal_api/rls_registry.py` classifies every table in the product
schemas: under policy (these seven), EXEMPT with a reason, or DEFERRED
with the reader work its policy still needs. `test_rls_registry_pg.py`
holds the catalog to it.

## Downgrade

Drops every policy this revision created and disables row security on
the seven tables. No data changes either way.
"""
from alembic import op

revision = "0114"
down_revision = "0113"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"


def _lbl(case_col: str, cls_col: str) -> str:
    """The lattice test for one row: within the global ceiling, or within
    a case-scoped grant's raise for that row's case."""
    return (f"({cls_col} <= {_CLR} OR "
            f"{cls_col} <= iam.rls_ceiling_for({_CEIL}, {case_col}))")


def _element(alias: str) -> str:
    return (f"{alias}.case_id = ANY ({_CASES}) AND "
            f"{_lbl(f'{alias}.case_id', f'{alias}.classification')} AND "
            f"{alias}.compartments <@ {_HELD}")


#: table -> [(policy, command, USING, WITH CHECK)]. Frozen text: a later
#: revision that changes a policy restates it rather than importing this.
POLICIES: dict[str, list[tuple[str, str, str | None, str | None]]] = {
    # Unqualified: the policy has no subquery a column could bind into.
    'core."case"': [
        ("rls_read", "SELECT", f"id = ANY ({_CASES})", None),
        ("rls_change", "UPDATE", f"id = ANY ({_CASES})",
         f"id = ANY ({_CASES}) AND {_lbl('id', 'classification')} AND "
         f"compartments <@ {_HELD}"),
    ],
    "core.node": [("rls_gate", "ALL", _element("node"), _element("node"))],
    "core.edge": [("rls_gate", "ALL", _element("edge"), _element("edge"))],
    "core.evidence": [("rls_gate", "ALL", _element("evidence"), _element("evidence"))],
    "core.assertion": [(
        "rls_gate", "ALL",
        f"assertion.case_id = ANY ({_CASES}) AND "
        "(assertion.node_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.node n WHERE n.id = assertion.node_id)) AND "
        "(assertion.edge_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.edge e WHERE e.id = assertion.edge_id))",
        f"assertion.case_id = ANY ({_CASES}) AND "
        "(assertion.node_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.node n WHERE n.id = assertion.node_id)) AND "
        "(assertion.edge_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.edge e WHERE e.id = assertion.edge_id))")],
    "core.evidence_link": [(
        "rls_gate", "ALL",
        "EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_link.evidence_id) AND "
        "(evidence_link.node_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.node n WHERE n.id = evidence_link.node_id)) AND "
        "(evidence_link.edge_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.edge e WHERE e.id = evidence_link.edge_id))",
        "EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_link.evidence_id) AND "
        "(evidence_link.node_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.node n WHERE n.id = evidence_link.node_id)) AND "
        "(evidence_link.edge_id IS NULL OR EXISTS "
        "(SELECT 1 FROM core.edge e WHERE e.id = evidence_link.edge_id))")],
    "core.evidence_custody": [
        ("rls_read", "SELECT",
         "EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_custody.evidence_id)",
         None),
        ("rls_append", "INSERT", None,
         "EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_custody.evidence_id)"),
    ],
}


def _create(table: str, name: str, command: str, using: str | None,
            check: str | None) -> str:
    parts = [f"CREATE POLICY {name} ON {table} FOR {command}"]
    if using is not None:
        parts.append(f"  USING ({using})")
    if check is not None:
        parts.append(f"  WITH CHECK ({check})")
    return "\n".join(parts) + ";"


def upgrade_sql() -> str:
    out = []
    for table, policies in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        for name, command, using, check in policies:
            out.append(_create(table, name, command, using, check))
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table, policies in reversed(list(POLICIES.items())):
        for name, *_ in policies:
            out.append(f"DROP POLICY {name} ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
