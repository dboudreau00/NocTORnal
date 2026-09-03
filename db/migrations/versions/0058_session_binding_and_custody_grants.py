"""Where a session was minted, and the custody ledger's missing REVOKE.

## A stolen token was perfectly portable

A session token is an opaque bearer credential: whoever presents it IS the
analyst, from anywhere, on anything, for up to twelve hours. 0012 gave
`iam.session` an `ip_hash` and a `user_agent` column for exactly this
reason, and nothing ever wrote either -- so a token lifted from a laptop
and replayed from another continent left a row indistinguishable from the
analyst's own, and validation had no fact on record to compare the replay
against.

This adds `ip inet` (the address itself, not a hash: a hash can be
compared for equality, but an address can also be read by the security
officer looking at the row, and the session table is not the public
audit log). The login handler now writes it and `user_agent` at creation,
and `NOCTORNAL_SESSION_STRICT_BINDING` makes validation refuse a
presentation whose address or User-Agent differs from the recorded ones.
Off by default, because a browser update changes the User-Agent
mid-session and a laptop moving between networks changes the address;
strict binding is a deliberate posture for a deployment that would rather
re-authenticate than risk it. `ip_hash` stays as it was, unwritten: two
representations of one fact would be two things to keep consistent.

"Validation" means BOTH of the application's two validation sites: HTTP
requests, through `deps.current_user`, and the WebSocket handshake in
`http/routers/live.py`. The websocket was not covered when this migration
first shipped and this paragraph is why it is now: a control disclosed to
an operator as covering validation, with one of two call sites exempt, is
a control the operator cannot reason about. Both refuse before sliding
the idle window, so a refused replay cannot keep a session alive.

Two kinds of session can never satisfy the comparison and are refused
under strict binding by design: one minted before this migration (no
recorded address), and one minted by `scripts/bootstrap.py session`,
which runs in a shell for a browser it has never met. The audit row for
those carries `unbound: true`, so a refusal that means "this could never
be verified" is distinguishable from one that means "this token moved".

## The custody ledger's REVOKE

0013 pairs `audit.event`'s append-only triggers with `REVOKE UPDATE,
DELETE, TRUNCATE ... FROM PUBLIC` and explains why: the trigger is the
enforcement, and the REVOKE is belt-and-braces because the principal who
can TRUNCATE can also drop the trigger. 0052 added the same REVOKE to
`core.purge_tombstone` and `lab.sample_access` on that argument. 0023
installed `core.evidence_custody`'s triggers and never the REVOKE, so the
one ledger whose whole purpose is to be evidence about who handled the
evidence was the one ledger the argument was not applied to.

The statement is a module constant so the test can read it from the
version file and compare it with the catalog state it leaves behind. Not
reversed on downgrade, matching 0013 and 0052: granting PUBLIC mutation on
an append-only ledger is never a state anyone wants back, and PUBLIC held
none before either -- "before" is merely the state in which the ACL was
implicit.
"""
from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None

CUSTODY_REVOKE_SQL = "REVOKE UPDATE, DELETE, TRUNCATE ON core.evidence_custody FROM PUBLIC"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("ALTER TABLE iam.session ADD COLUMN ip inet")
    run("""
COMMENT ON COLUMN iam.session.ip IS
  'The peer address the session was minted from (the outermost trusted '
  'proxy''s view when NOCTORNAL_TRUSTED_PROXY_HOPS is set). NULL when the '
  'transport had no address. Compared by validation only under '
  'NOCTORNAL_SESSION_STRICT_BINDING.'
""")
    run("""
COMMENT ON COLUMN iam.session.user_agent IS
  'The User-Agent header presented at login. Column since 0012; first '
  'written with 0058.'
""")
    run(CUSTODY_REVOKE_SQL)


def downgrade() -> None:
    run("ALTER TABLE iam.session DROP COLUMN ip")
    run("COMMENT ON COLUMN iam.session.user_agent IS NULL")
