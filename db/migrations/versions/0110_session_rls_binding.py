"""A session carries the hash of its row-security binding proof (S1).

## Why a second hash beside token_hash

Row-level security needs to know, inside SQL, which user a request's
connection belongs to. A setting that simply held a user id would be
forged by the first injected `set_config(...)`, which is the statement
RLS exists to contain. So the connection is bound by a PROOF: a value
derived from the raw session token under a fixed context
(`security.tokens.rls_proof`), which only the holder of the raw token can
compute. The session row stores `sha256(proof)` here, and
`iam.rls_actor()` (0111) resolves the actor by hashing the connection's
proof and looking it up by this column.

It is not `token_hash` itself, and must not be. `token_hash` is the
SHA-256 of the raw token and is readable by the request role (the
session store reads it); a binding keyed on it would let anyone who can
read `iam.session` bind as any live session. The proof is one derivation
further away, so reading this column gives nothing that binds, and a
proof captured in a database log is not the HTTP credential.

## No backfill

Only hashes are stored, so a session minted before this revision has no
binding and cannot be bound: in production, where the request role is
subject to row security, such a session is refused once (401,
RLS_BINDING_FAILED "no_binding") and the person signs in again. The
absolute lifetime is 12 hours, so none survives a day. In development and
in the test suite the connection is the owner, which binds nothing and
refuses nothing.

## Downgrade

Drops the index and the column. Sessions minted meanwhile keep working
under a build without row security, which never read the column.
"""
from alembic import op

revision = "0110"
down_revision = "0109"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


UPGRADE_SQL = """
ALTER TABLE iam.session ADD COLUMN rls_binding_hash bytea;
CREATE UNIQUE INDEX session_rls_binding_hash_key
    ON iam.session (rls_binding_hash) WHERE rls_binding_hash IS NOT NULL;
COMMENT ON COLUMN iam.session.rls_binding_hash IS
  'sha256 of the row-security binding proof derived from the raw token '
  '(security.tokens.rls_proof). iam.rls_actor() resolves a connection''s '
  'user by it. Set once at mint, on a system connection.';
"""

DOWNGRADE_SQL = """
DROP INDEX iam.session_rls_binding_hash_key;
ALTER TABLE iam.session DROP COLUMN rls_binding_hash;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
