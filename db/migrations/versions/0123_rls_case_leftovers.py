"""Row-level security on the rest of the case record (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `core.selector` (the CASE template): in a case the user may read. The
  observable's own visibility is its entity's, which every reader of it
  applies (the search's selector match, `GET /selectors`); the policy keeps the case
  term only, because `SelectorStore.record` is an upsert that meets the
  case's existing row whoever linked it, and an upsert against a row the
  writer cannot see is refused where the application would have counted
  one more observation.
- `core.assertion_embedding`, `core.evidence_embedding` (CHILD of the claim
  or exhibit): a vector is never more visible than its item. The pass and
  the index administration run as the system role (EMBEDDINGS).
- `core.node_merge_edge` (CHILD of the merge and of the tie): a merge's
  record of the ties it re-pointed shows only the ties the reader can see.
  The count on the merge history is therefore the reader's count, the
  conservative reading: a re-pointed tie above the reader is withheld
  material, and nothing announces it (the merge and its reversal run as
  the system role and re-point every tie, hidden ones included).
- `core.purge_tombstone` (CUSTOM, read-only): a case's tombstones in a case
  the user may read; a tombstone with no case (a collected document's)
  under a global `retention.read`. No INSERT, UPDATE or DELETE policy: a
  tombstone is written only by the purge, which runs as the system role.
- `core.tag` (CUSTOM): a case's own tags in a case the user may read; the
  shared global taxonomy (no case) to every bound user.
- `core.tag_assignment` (CHILD of the tag and of whichever target it
  names: an entity, a tie, an exhibit or a collected document).
- `core.approval_request` (CUSTOM): a case's two-person requests in a case
  the user may read; a deployment-wide request (no case: a two-person
  policy change, an integration's activation) to every bound user, whose
  routes then decide who may list, sign or apply it (the requester and
  signer permissions live with each operation, in `approvals.OPERATIONS`).
  A consume that must see a request above its caller (a merge under dual
  control) runs on the MERGE system connection already.

`core.evidence_vectors_follow`, which resets an exhibit's vectors when
the exhibit changes, and `core.guard_case_merge_switch`, which reads the
relax approval consumed with the change, become SECURITY DEFINER with
their search paths pinned, as 0113 did.

## Downgrade

Drops every policy, disables row security on the eight tables, and
restores the trigger functions.
"""
from alembic import op

revision = "0123"
down_revision = "0122"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"

#: function -> its search_path before this revision (None: it had none).
#: An exhibit's change resets its vectors whatever the writer may see.
PRIOR_CONFIG: dict[str, str | None] = {
    "core.evidence_vectors_follow()": None,
    # The case merge switch's guard reads the consumed relax approval.
    "core.guard_case_merge_switch()": None,
}


def pinned_path(prior: str | None) -> str:
    """0113's rule: pg_catalog first, the function's own schemas (public
    where it had none), pg_temp last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def _exists(parent: str, table: str, fk: str) -> str:
    return f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"


def _optional(parent: str, table: str, fk: str) -> str:
    return f"({table}.{fk} IS NULL OR {_exists(parent, table, fk)})"


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "core.selector": f"selector.case_id = ANY ({_CASES})",
    "core.assertion_embedding": _exists("core.assertion", "assertion_embedding",
                                        "assertion_id"),
    "core.evidence_embedding": _exists("core.evidence", "evidence_embedding",
                                       "evidence_id"),
    "core.node_merge_edge": (
        f"EXISTS (SELECT 1 FROM core.node_merge p WHERE p.id = node_merge_edge.merge_id) "
        f"AND {_exists('core.edge', 'node_merge_edge', 'edge_id')}"),
    "core.tag": (f"(tag.case_id IS NULL AND {_CLR} IS NOT NULL) OR "
                 f"tag.case_id = ANY ({_CASES})"),
    "core.approval_request": (f"(approval_request.case_id IS NULL AND {_CLR} IS NOT NULL) "
                              f"OR approval_request.case_id = ANY ({_CASES})"),
    "core.tag_assignment": " AND ".join([
        _exists("core.tag", "tag_assignment", "tag_id"),
        _optional("core.node", "tag_assignment", "node_id"),
        _optional("core.edge", "tag_assignment", "edge_id"),
        _optional("core.evidence", "tag_assignment", "evidence_id"),
        _optional("collect.document", "tag_assignment", "document_id")]),
}

#: Read-only: a SELECT policy and nothing else.
READ_ONLY: dict[str, str] = {
    "core.purge_tombstone": (
        f"purge_tombstone.case_id = ANY ({_CASES}) OR "
        "(purge_tombstone.case_id IS NULL AND "
        "(SELECT iam.rls_holds_global('retention.read')))"),
}


def upgrade_sql() -> str:
    out = [f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};"
           for fn, prior in PRIOR_CONFIG.items()]
    for table, qual in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_gate ON {table} FOR ALL "
                   f"USING ({qual}) WITH CHECK ({qual});")
    for table, qual in READ_ONLY.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_read ON {table} FOR SELECT USING ({qual});")
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table in reversed(list(READ_ONLY)):
        out.append(f"DROP POLICY rls_read ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
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
