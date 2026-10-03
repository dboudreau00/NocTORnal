"""The two database readers of the audit log read all of it (F51, 2026-10-02).

## Why

0168 puts `audit.event` under row-level security. Two functions read it
from inside the database, and a function runs as the role whose statement
called it, so under a policy each would read only the caller's rows and
fail OPEN:

- `audit.chain_hash()`, the BEFORE INSERT trigger that chains every row to
  the log's tail (0013). Read as the writer, the tail is the newest row the
  WRITER may see: a request that may see none of it (an unbound
  connection, the out-of-band refusal rows of `approvals.record_out_of_band`
  and `errors._audit_rls_refused`, or an analyst who sees only their own
  case) would chain to an older row, or to none, and every such append
  would fork the chain or start a second genesis, which `audit_verify`
  reports as tampering. The append must read the true tail.
- `iam.countersign_blocked_by(...)`, the seven-day countersigning rule
  (0075), which looks for a password reset, re-enrolment, reactivation,
  unlock or role grant on the signer's or proposer's account. Those rows
  carry no case and were written by somebody else (an administrator), so a
  signer could see none of them, and the rule would permit on zero: a
  two-person control that switches itself off.

Each becomes SECURITY DEFINER with its search path pinned by 0113's rule
(pg_catalog first, the schemas it named, pg_temp last). Both bodies already
name every object fully. `audit.block_mutation()` names the table only in
the sentence it raises and reads nothing, so it stays SECURITY INVOKER and
is allow-listed in `rls_registry.INVOKER_TRIGGER_FUNCTIONS`.

What the definer answers: the chain reads one row (the tail) and writes
two columns of the new row. The countersign rule answers, for the two
accounts it is asked about, the newest of six account events in the window
asked for: the action, its time, who made it and the role a grant named.
Any bound caller may ask it about any accounts, so that much is readable
to every request: administration of accounts on the IAM plane (0109),
never a case and never any other detail, and all of it was readable to
every request before 0168. It is the narrowest read the rule needs.

## Downgrade

Restores each function's exact prior state (`PRIOR_CONFIG`): SECURITY
INVOKER, and its old search path or none. 0168 goes down first.
"""
from alembic import op

revision = "0166"
down_revision = "0165"
branch_labels = None
depends_on = None

#: function -> its search_path before this revision (None: it had none).
PRIOR_CONFIG: dict[str, str | None] = {
    "audit.chain_hash()": "public, pg_catalog",
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
