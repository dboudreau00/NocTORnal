"""The request role cannot attribute a custody row to another user
(evidence-ledger-actor-time-forgeable, 2026-10-03).

## What was wrong

`core.evidence_custody` pins `occurred_at` (0024) but never checked the
actor. Its INSERT policy, `rls_append`, asked only that the exhibit be one the
caller may see. A connection bound to analyst A could therefore write
`EXPORTED by user B, hash_verified true` into the record that is produced to
a court, and the chain verified because it is computed over the forged row.

## The fix

The INSERT policy also requires `actor_id = (SELECT iam.rls_actor())`, the
user the connection is bound to and nobody else; an unbound connection has no
actor and so writes no custody row. The template is the one every other
policy uses (the actor comes only from `iam.rls_actor()`, in an initplan).
The policy binds the request role only: the owner and the system role are
exempt from row security and keep writing on behalf of a named person (the
lookup drain's acquisition, a lock extension), which is the point of the
system role.

Every writer of the ledger in the product is `EvidenceService._custody`, and
its callers pass the acting user, who is the bound user on a request, or run
on a system connection (a retention or lock job). The one request path that
binds to someone else's authority, the production ticket's redemption,
binds to the ticket's holder before it writes (`bind_ticket`).

## Downgrade

Restores `rls_append` as 0114 wrote it.
"""
from alembic import op

revision = "0151"
down_revision = "0150"
branch_labels = None
depends_on = None

UPGRADE_SQL = """
DROP POLICY rls_append ON core.evidence_custody;
CREATE POLICY rls_append ON core.evidence_custody FOR INSERT
  WITH CHECK (actor_id = (SELECT iam.rls_actor())
              AND EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_custody.evidence_id));
"""

DOWNGRADE_SQL = """
DROP POLICY rls_append ON core.evidence_custody;
CREATE POLICY rls_append ON core.evidence_custody FOR INSERT
  WITH CHECK (EXISTS (SELECT 1 FROM core.evidence v WHERE v.id = evidence_custody.evidence_id));
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
