"""When screening last ran, read as a fact (F51, 2026-10-02).

## Why

0168 puts `audit.event` under row-level security. The Lab's policy block
(`screening.policy_block`, `GET /samples/policy`, read on every Lab visit
by anyone who may use the Lab) says when the prohibited-content screening
last passed over the store, from the newest SCREENING_RESCAN row. That row
carries no case and is written by the screening worker or by the Security
Officer's console pass, so under the policy an analyst would read none of
it and the card would say screening has not run when it has.

`audit.last_screening_pass(within)` answers that one deployment-wide fact,
the newest SCREENING_RESCAN time inside the window, and nothing else: not
the row, its detail or who ran it. SECURITY DEFINER with `SET search_path
= pg_catalog, pg_temp`, static SQL over a fully qualified name, as
`iam.lookup_result_facts` (0127). The officer's own reader
(`screening.state`) asks the same function, so the fact has one reader.

## Downgrade

Drops the function. 0168, whose readers need it, goes down first.
"""
from alembic import op

revision = "0167"
down_revision = "0166"
branch_labels = None
depends_on = None

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

LAST_SCREENING_PASS = f"""
CREATE FUNCTION audit.last_screening_pass(p_within interval)
  RETURNS timestamptz
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT max(e.occurred_at)
    FROM audit.event e
   WHERE e.action = 'SCREENING_RESCAN'
     AND e.occurred_at > pg_catalog.now() - p_within
$$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(LAST_SCREENING_PASS)


def downgrade() -> None:
    run("DROP FUNCTION audit.last_screening_pass(interval);")
