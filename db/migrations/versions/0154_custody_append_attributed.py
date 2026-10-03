"""A custody row names the user who wrote it (F51, 2026-10-03).

## What was wrong (evidence-ledger-actor-time-forgeable, 2026-10-03)

`core.evidence_custody`'s INSERT policy (0114) asked only that the exhibit
be one the writer may read. A connection bound to analyst A could insert
"EXPORTED by user B, hash verified" for any exhibit A can see, and the chain
hashed whatever the INSERT supplied, so the verifier could not tell. The
time was already the database's (0024 pins `occurred_at`); the actor was
the caller's.

## What this changes

The INSERT policy keeps its exhibit test and adds the actor test:
`actor_id = (SELECT iam.rls_actor())`. The column is NOT NULL, so there is
no unattributed custody row to allow. The system role and the owner are not
subject to the policy (they bypass row security), so the writers that are
not a user's request keep working: the maintenance scripts, the retention
sweeps and the lookup drain run as system purposes.

The request-role writers all pass the bound user: every `EvidenceService`
verb is called from a route with `user.user_id`, and the production-ticket
redemption (`redeem_production_ticket`) runs on a connection bound to the
ticket's holder (`bind_ticket`), whose id it writes.

The SELECT policy is unchanged.

## Downgrade

Restores 0114's INSERT policy, text for text.
"""
from alembic import op

revision = "0154"
down_revision = "0153"
branch_labels = None
depends_on = None

_VISIBLE = ("EXISTS (SELECT 1 FROM core.evidence v "
            "WHERE v.id = evidence_custody.evidence_id)")

#: Frozen text. A later revision that changes it restates it.
APPEND = f"{_VISIBLE} AND evidence_custody.actor_id = (SELECT iam.rls_actor())"

UPGRADE_SQL = f"""
DROP POLICY rls_append ON core.evidence_custody;
CREATE POLICY rls_append ON core.evidence_custody FOR INSERT WITH CHECK ({APPEND});
"""

DOWNGRADE_SQL = f"""
DROP POLICY rls_append ON core.evidence_custody;
CREATE POLICY rls_append ON core.evidence_custody FOR INSERT WITH CHECK ({_VISIBLE});
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
