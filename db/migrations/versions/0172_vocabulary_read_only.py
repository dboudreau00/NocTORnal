"""The ontology and its reference vocabulary are read-only to the request
role (Beta 1 authorization gate, 2026-10-07).

## Why

0060 handed `noctornal_app` INSERT, UPDATE and DELETE on every table, and
0109 took the IAM plane back. Five reference tables that nothing writes at
run time kept the full four: the ontology's `core.node_type`,
`core.edge_type` and `core.selector_type`, the comms catalogue
`comms.platform`, and the ingest category vocabulary
`ingest.category_rule`. They are written by migrations alone (the ontology
by `definition.py` and a revision, CLAUDE.md), carry no case and no label,
and are under no policy (`rls_registry.EXEMPT`, reference vocabulary), so
the request role's write reached every row.

What those rows decide is not cosmetic. `selector_type.is_strong` decides
which shared identifier is raised as a merge lead (invariant 3);
`comms.platform.durable_selector_type` decides which identifier a platform
is indexed on (invariant 9); an edge type's flags drive the graph's
arithmetic. One statement injected into a request could rewrite any of
them for every case at once, with no audit row. No code path in
`apps/api/src` writes these tables, as either role, so the request role
loses INSERT, UPDATE and DELETE on them and keeps SELECT.

The system role keeps what it holds: nothing writes these through it
either, and narrowing it is not this revision's concern.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0060 and 0109 are. The downgrade grants back the
three privileges 0060 gave.
"""
from alembic import op

revision = "0172"
down_revision = "0171"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES = (
    "core.node_type",
    "core.edge_type",
    "core.selector_type",
    "comms.platform",
    "ingest.category_rule",
)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _each(verb: str, preposition: str) -> str:
    return "\n".join(
        f"    EXECUTE format('{verb} INSERT, UPDATE, DELETE ON {table} "
        f"{preposition} %I', app);"
        for table in RUNTIME_READ_ONLY_TABLES)


def _block(body: str) -> str:
    return f"""
DO $noc$
DECLARE
  app text := '{APP_ROLE}';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{body}
  END IF;
END
$noc$;
"""


def upgrade() -> None:
    run(_block(_each("REVOKE", "FROM")))


def downgrade() -> None:
    run(_block(_each("GRANT", "TO")))
