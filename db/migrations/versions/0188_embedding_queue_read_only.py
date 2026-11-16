"""The embedding queue is read-only to the request role, and the triggers
that queue an item run as their definer
(the heartbeat and the queues, 2026-11-15).

## Why

0179 left `core.embedding_pending` writable by the request role because it
is not configuration. One statement injected into a request could empty
the queue, so a new document, exhibit or claim would not be embedded until
the index was rebuilt and would be missing from every similarity search
meanwhile, or fill it with ids for the pass to read.

## What

The request role loses INSERT, UPDATE and DELETE on the queue and keeps
SELECT. Its writes reached the queue two ways:

- Three trigger functions ran as the writer: `core.assertion_embedding_queued`
  (a claim recorded, and a claim retracted or superseded, which dequeues
  it), `core.evidence_embedding_queued` (an upload) and
  `collect.document_embedding_queued` (a collected document). Each becomes
  SECURITY DEFINER with its search path pinned to `pg_catalog, pg_temp`;
  their bodies are untouched and already name every object fully.
  `core.embedding_enqueue` stays SECURITY INVOKER: called from a definer it
  runs as the owner, and called directly by the request role it is refused,
  which is what the revoke is for. The other queueing triggers
  (`*_vectors_follow`) were definers already.
- One item embedded on demand by a similarity route, which now runs on the
  EMBEDDINGS system connection after the route's readability check
  (`routers/similarity.py`, the commit before this revision).

Everything else that writes the queue (the pass, a space's registration and
retirement, the victim sweep) already runs as the system role. The three
vector tables (`collect.document_embedding`, `core.evidence_embedding`,
`core.assertion_embedding`) keep the request role's writes: they are the
next residual (docs/17).

`RUNTIME_READ_ONLY_TABLES` declares the queue for
`test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
`PRIVILEGES_SQL` is repeatable and `scripts/runtime_roles.py ensure`
replays it after 0108's blanket grant. `FUNCTION_SQL` is frozen.

## No-op without the role; downgrade

The revoke is guarded on `pg_roles` as 0187's is. The downgrade gives the
three writes back and returns the three functions to SECURITY INVOKER with
no search path, as 0092 and 0093 created them.
"""
from alembic import op

revision = "0188"
down_revision = "0187"
branch_labels = None
depends_on = None

#: Fired by the request role's own writes; each queues or dequeues the item.
QUEUEING_TRIGGERS: tuple[str, ...] = (
    "core.assertion_embedding_queued()",
    "core.evidence_embedding_queued()",
    "collect.document_embedding_queued()",
)

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = ("core.embedding_pending",)

#: Frozen text.
FUNCTION_SQL = "".join(
    f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = pg_catalog, pg_temp;\n"
    for fn in QUEUEING_TRIGGERS)


def _block(verb: str, preposition: str) -> str:
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
    {verb} INSERT, UPDATE, DELETE ON core.embedding_pending {preposition} noctornal_app;
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
PRIVILEGES_SQL = _block("REVOKE", "FROM")

DOWNGRADE_SQL = _block("GRANT", "TO") + "".join(
    f"ALTER FUNCTION {fn} SECURITY INVOKER RESET search_path;\n"
    for fn in QUEUEING_TRIGGERS)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL)
    run(PRIVILEGES_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
