"""The countersigning rule reads all of the audit log (F51, 2026-10-02).

## Why

0168 puts `audit.event` under row-level security. A function that reads
the log from inside the database runs as the role whose statement called
it, so under a policy it would read only the caller's rows and fail OPEN.
Three do. The chain trigger `audit.chain_hash()` is a definer since 0149,
which restates it whole, so an append chains to the true tail whoever makes
it. The other two are:

- `iam.countersign_blocked_by(...)`, the seven-day countersigning rule
  (0075), which looks for a password reset, re-enrolment, reactivation,
  unlock or role grant on the signer's or proposer's account. Those rows
  carry no case and were written by somebody else (an administrator), so a
  signer could see none of them, and the rule would permit on zero: a
  two-person control that switches itself off.
- `audit.last_screening_pass(...)`, the Lab's "screening last ran" fact,
  which is 0167's and a definer from the start.

The rule becomes SECURITY DEFINER with its search path pinned by 0113's rule
(pg_catalog first, the schemas it named, pg_temp last). Its body already names
every object fully. `audit.block_mutation()` names the table only in the
sentence it raises and reads nothing, so it stays SECURITY INVOKER and is
allow-listed in `rls_registry.INVOKER_TRIGGER_FUNCTIONS`.

What the definer answers: for the two accounts it is asked about, the newest
of six account events in the window asked for: the action, its time, who made
it and the role a grant named. Any bound caller may ask it about any accounts,
so that much is readable to every request: administration of accounts on the
IAM plane (0109), never a case and never any other detail, and all of it was
readable to every request before 0168. It is the narrowest read the rule
needs.

## Downgrade

Restores the function's exact prior state (`PRIOR_CONFIG`): SECURITY
INVOKER, and no search path. 0168 goes down first.
"""
from alembic import op

revision = "0166"
down_revision = "0165"
branch_labels = None
depends_on = None

#: function -> its search_path before this revision (None: it had none).
PRIOR_CONFIG: dict[str, str | None] = {
    "iam.countersign_blocked_by(uuid, text, timestamptz, uuid, text, interval)": None,
}


def pinned_path(prior: str | None) -> str:
    """0113's rule: pg_catalog first, the function's own schemas (public
    where it had none), pg_temp last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def upgrade_sql() -> str:
    return "\n".join(
        f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};"
        for fn, prior in PRIOR_CONFIG.items())


def downgrade_sql() -> str:
    out = []
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
