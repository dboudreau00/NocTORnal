"""Invariant triggers read the truth, not the caller's view (S1).

## Why

A trigger function runs as the role whose statement fired it. Once 0114
puts `core."case"`, `core.node`, `core.edge`, `core.evidence`,
`core.assertion` and the custody ledger under row-level security, every
trigger below that READS one of them would read only the rows the writer
may see, and each would then fail OPEN:

- `core.validate_edge_endpoints` reads each endpoint's node type and case;
  an invisible endpoint reads as NULL and `NOT (NULL = ANY(...))` is NULL,
  so both the type check and the cross-case check would pass.
- `core.enforce_tlp_floor` compares a child with its case's
  classification; an invisible case reads as NULL and the floor passes.
- `core.assertion_protects_element`, `core.require_node_assertion` and
  `core.require_edge_assertion` count an element's live assertions; an
  invisible one counts zero and the last claim could go.
- `core.assertion_derives_tie_confidence` (through `sync_tie_confidence`)
  and `core.edge_confidence_is_derived` (through `tie_confidence`) derive
  a tie's confidence from EVERY live assertion; a filtered read would
  derive it from some.
- `core.custody_chain_hash` chains to the ledger's tail; a filtered tail
  would fork the custody chain.
- `core.assertion_embedding_case` / `core.evidence_embedding_case` copy
  the item's case onto its vector row (F6).
- `comms.guard_pgp_key_acquisition` and `comms.guard_pgp_key_lookup`
  (F10) read the case's and the cited exhibit's labels for their floor.

An invariant is about the database, not about the writer's view, so each
becomes SECURITY DEFINER with its search path pinned (pg_catalog first,
the schemas it already named, pg_temp last). The functions they call run
inside the definer context and need nothing. `test_rls_registry_pg.py`
fails when a trigger function whose body names a policied table is not
SECURITY DEFINER and not allow-listed, so a later one cannot be missed.

## Downgrade

Restores each function's exact prior state (`PRIOR_CONFIG`): SECURITY
INVOKER, and its old search path or none.
"""
from alembic import op

revision = "0113"
down_revision = "0112"
branch_labels = None
depends_on = None

#: function -> its search_path before this revision (None: it had none).
PRIOR_CONFIG: dict[str, str | None] = {
    "comms.guard_pgp_key_acquisition()": None,
    "comms.guard_pgp_key_lookup()": None,
    "core.assertion_derives_tie_confidence()": "core, public",
    "core.assertion_embedding_case()": None,
    "core.assertion_protects_element()": "core, public",
    "core.custody_chain_hash()": "public, pg_catalog",
    "core.edge_confidence_is_derived()": "core, public",
    "core.enforce_tlp_floor()": None,
    "core.evidence_embedding_case()": None,
    "core.require_edge_assertion()": "core, public",
    "core.require_node_assertion()": "core, public",
    "core.validate_edge_endpoints()": None,
}


def pinned_path(prior: str | None) -> str:
    """pg_catalog first, the function's own schemas (public where it had
    none, which is what the caller's default path resolved to), pg_temp
    last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    for fn, prior in PRIOR_CONFIG.items():
        run(f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};")


def downgrade() -> None:
    for fn, prior in PRIOR_CONFIG.items():
        if prior is None:
            run(f"ALTER FUNCTION {fn} SECURITY INVOKER RESET search_path;")
        else:
            run(f"ALTER FUNCTION {fn} SECURITY INVOKER SET search_path = {prior};")
