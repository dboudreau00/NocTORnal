"""The role -> permission matrix (RBAC verbs).

Roles and permissions were seeded (0017) but never linked, so the verb
check had nothing to read. This is the starting matrix, derived from the
role intents in db/seed_ontology.sql and docs/05:

- SYS_ADMIN / SECURITY_OFFICER hold NO case-content permissions
  (separation of duties: the admin configures, the officer audits, and
  neither reads case data by default).
- CASE_OWNER has full control of an assigned case incl. grants and the
  dual-controlled destructive verbs.
- ANALYST creates/edits graph, assertions and evidence but does not grant
  access, review proposals, or export/purge.
- REVIEWER approves (proposals, merges) but cannot originate.
- CONTRIBUTOR uploads and reads but cannot accept changes.
- COLLECTOR manages collection; READ_ONLY / LIAISON view only; SERVICE
  can attach captured evidence.

It is data, not structure — change it via role.manage (dual-controlled)
and a follow-up migration. Idempotent; mirrored in db/seed_ontology.sql.
"""
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

MATRIX: dict[str, list[str]] = {
    "SYS_ADMIN": ["user.manage", "role.manage", "integration.manage"],
    "SECURITY_OFFICER": ["audit.read"],
    "CASE_OWNER": [
        "case.create", "case.read", "case.update", "case.close", "case.delete",
        "case.grant", "graph.node.create", "graph.node.update", "graph.node.delete",
        "graph.edge.create", "graph.edge.update", "graph.merge", "graph.unmerge",
        "assertion.create", "assertion.retract", "proposal.review",
        "evidence.upload", "evidence.read", "evidence.export", "evidence.purge",
        "analytics.run", "report.generate", "report.export",
    ],
    "ANALYST": [
        "case.read", "graph.node.create", "graph.node.update", "graph.node.delete",
        "graph.edge.create", "graph.edge.update", "graph.merge", "graph.unmerge",
        "assertion.create", "assertion.retract", "evidence.upload", "evidence.read",
        "analytics.run", "report.generate",
    ],
    "COLLECTOR": [
        "source.manage", "watch.manage",
        "collection_account.manage", "collection_account.reveal",
    ],
    "REVIEWER": [
        "case.read", "evidence.read", "proposal.review", "graph.merge", "graph.unmerge",
    ],
    "CONTRIBUTOR": ["case.read", "evidence.read", "evidence.upload"],
    "READ_ONLY": ["case.read", "evidence.read"],
    "LIAISON": ["case.read", "evidence.read"],
    "SERVICE": ["evidence.upload"],
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _values() -> str:
    rows = []
    for role, perms in MATRIX.items():
        for perm in perms:
            rows.append(f"('{role}','{perm}')")
    return ",\n".join(rows)


def upgrade() -> None:
    run(f"""
SET search_path = iam, core, public;
INSERT INTO role_permission (role_key, permission_key) VALUES
{_values()}
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    keys = ",".join(f"'{r}'" for r in MATRIX)
    run(f"DELETE FROM iam.role_permission WHERE role_key IN ({keys});")
