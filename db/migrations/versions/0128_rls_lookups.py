"""Row-level security on the lookup ledger (F51, 2026-10-02).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `ingest.lookup` (CASE_LABELLED): in a case the user may read, the
  lookup's classification within the user's ceiling for that case. A
  provider test's canary row has no case, so no request role sees it; the
  test runs as the LOOKUPS purpose and nothing on the request connection
  reads one.
- `ingest.lookup_result` (CASE_LABELLED): the same test, on the answer's
  own label, which the provider decides (up to RED). The ledger and Triage
  read that label through `iam.lookup_result_facts` (0127), never through
  a join to a row the reader may not see.
- `ingest.lookup_attempt` (LEDGER_CHILD of the lookup): read and appended
  where its lookup is visible. The table keeps no UPDATE or DELETE
  privilege (0099), so a SELECT and an INSERT policy are all it takes.
- `ingest.lookup_batch` (CASE): in a case the user may read. Its totals
  are never served (0101), so it carries no label of its own.

## Who must see every row, and runs as LOOKUPS

`db.SystemPurpose.LOOKUPS`, which the drain already ran as:

- an interactive request and a sign-off, from the gates onwards: each
  stores the answer at the label the provider decides, raises proposals
  from it and records their counts on it, and the answer row's INSERT ...
  RETURNING would be refused for a requester below it. What the requester
  is then shown is read back on the request connection, at their labels;
- the gates' own completeness checks: a VALUE is never declared below what
  the case already holds for it (every earlier lookup of the value
  included), and a fresh answer above the requester is served from the
  cache rather than sent for again;
- the quota: every attempt on a provider counts, whichever case it was for;
- the provider test, whose canary has no case;
- a provider's withdrawal (disable, retire, a lowered exposure), which
  cancels every case's waiting and queued lookups of that provider, and a
  batch's cancellation, which cancels every queued row of the batch.

## The trigger that reads a policied table

`ingest.lookup_result_dominates` compares a lookup with the answer it
names, which may sit above the writer (a cached answer served to a
requester below it). It becomes SECURITY DEFINER with its search path
pinned, as 0113 did; PRIOR_CONFIG restores it exactly.

## Downgrade

Drops every policy, disables row security on the four tables, and restores
the trigger function.
"""
from alembic import op

revision = "0128"
down_revision = "0127"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"

#: function -> its search_path before this revision (None: it had none).
PRIOR_CONFIG: dict[str, str | None] = {
    "ingest.lookup_result_dominates()": None,
}


def _case_labelled(alias: str) -> str:
    return (f"{alias}.case_id = ANY ({_CASES}) AND "
            f"({alias}.classification <= {_CLR} OR "
            f"{alias}.classification <= iam.rls_ceiling_for({_CEIL}, {alias}.case_id))")


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "ingest.lookup": _case_labelled("lookup"),
    "ingest.lookup_result": _case_labelled("lookup_result"),
    "ingest.lookup_batch": f"lookup_batch.case_id = ANY ({_CASES})",
}

#: table -> the CHILD test, as a SELECT policy and an INSERT policy only.
LEDGER: dict[str, str] = {
    "ingest.lookup_attempt": (
        "EXISTS (SELECT 1 FROM ingest.lookup p WHERE p.id = lookup_attempt.lookup_id)"),
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
    for table, qual in LEDGER.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_read ON {table} FOR SELECT USING ({qual});")
        out.append(f"CREATE POLICY rls_append ON {table} FOR INSERT WITH CHECK ({qual});")
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table in reversed(list(LEDGER)):
        out.append(f"DROP POLICY rls_append ON {table};")
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
