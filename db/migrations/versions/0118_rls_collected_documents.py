"""Row-level security on collected documents and Triage's proposals (S1).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `collect.document`: a document whose classification is within the
  user's CASE-LESS ceiling (their clearance, raised only by a live global
  break-glass grant) and whose compartments they hold. A document hangs
  off a source that any number of cases cite, so a grant scoped to one
  case never raises it: the rule every collection view, the case search,
  watch hits and the inspector already apply (final review C11,
  2026-09-23). The source's own label stays an application predicate:
  the watch-hit queue deliberately reads a hit's document on the
  document's label alone (`CollectionService.watch_hits`), and a policy
  stricter than the gate would take those hits away.
- `collect.extraction`, `collect.forum_post`, `collect.forum_member`,
  `collect.telegram_message`, `collect.document_embedding` (the CHILD
  template): visible where their document is. None carries a label of
  its own that its document's does not already bound.
- `collect.proposal` (the CASE template): in a case the user may read.
  A proposal's label is DERIVED (the strictest of its payload's, its
  captured document's, its contact block's, its lookup result's and its
  case's), and the application reads it on every Triage read
  (`proposals._READABLE`), the document leg now through
  `iam.element_facts` (0117) so it can never read low. The policy keeps
  the case term only, on purpose: the document leg would hide a proposal
  a case-scoped grant legitimately shows; the contact-block leg is a
  reverse reference a policy could express only with an anti-join or a
  per-row definer call, both ruled out (0114); and machine paths raise
  proposals for readers who may be below them, which a label WITH CHECK
  would refuse.

## Trigger functions that now read a policied table

`collect.document_embedding_labels`, `collect.document_vectors_follow`,
`collect.source_vectors_follow` and `collect.guard_telegram_message`
read or write documents and their vectors whatever the writer may see
(a relabel's vector reset, a source reclassification's requeue, a purge's
identifier check). As the invoker each would act on the writer's view
and an invariant would fail open, so each becomes SECURITY DEFINER with
its search path pinned, as 0113 did for the graph's.

## Who it does not touch

The owner (Alembic, fixtures, pg_dump; ENABLE, never FORCE) and
`noctornal_worker`: the collection poll and a manual run, a pasted
capture, the embedding pass and the index administration, retention and
document holds all run as system purposes (`db.SystemPurpose`).
`noctornal_egress` reads none of these tables.

## Downgrade

Drops every policy, disables row security on the seven tables, and
restores each trigger function to SECURITY INVOKER with no search path.
"""
from alembic import op

revision = "0118"
down_revision = "0117"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_HELD = "(SELECT iam.rls_compartments())"

#: function -> its search_path before this revision (None: it had none).
PRIOR_CONFIG: dict[str, str | None] = {
    "collect.document_embedding_labels()": None,
    "collect.document_vectors_follow()": None,
    "collect.guard_telegram_message()": None,
    "collect.source_vectors_follow()": None,
}


def _child(table: str, parent: str, fk: str) -> str:
    return f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "collect.document": (f"document.classification <= {_CLR} AND "
                         f"document.compartments <@ {_HELD}"),
    "collect.extraction": _child("extraction", "collect.document", "document_id"),
    "collect.forum_post": _child("forum_post", "collect.document", "document_id"),
    "collect.forum_member": _child("forum_member", "collect.document", "document_id"),
    "collect.telegram_message": _child("telegram_message", "collect.document",
                                       "document_id"),
    "collect.document_embedding": _child("document_embedding", "collect.document",
                                         "document_id"),
    "collect.proposal": f"proposal.case_id = ANY ({_CASES})",
}


def pinned_path(prior: str | None) -> str:
    """0113's rule: pg_catalog first, the function's own schemas (public
    where it had none), pg_temp last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def upgrade_sql() -> str:
    out = [f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};"
           for fn, prior in PRIOR_CONFIG.items()]
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
    for fn, prior in PRIOR_CONFIG.items():
        if prior is None:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER RESET search_path;")
        else:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER SET search_path = {prior};")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
