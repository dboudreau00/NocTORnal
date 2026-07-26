"""A delivery records WHERE it went, not just that it went.

docs/17 F19. `notify.delivery` has carried the channel, the state, the
attempt count and the refusal reason since migration 0029, and never the
destination. `transports._DUE_SQL` resolves the recipient as
`coalesce(p.address, u.email)` at drain time, so the address a message
actually reached lived only in the SMTP server's log — and only if one was
kept.

That is a gap on its own, and it is a hole next to the finding it comes
from: until F19 any authenticated user could redirect their own
notifications to an arbitrary mailbox with no validation and no audit
event. Even with that closed — an operator-declared domain allowlist, and
an audit row on every change — an auditor reconstructing an incident needs
to know where a specific message went, not merely what the preference said
at the time they looked. The preference is current state; the delivery is
history, and history is the thing that answers "what left the building".

`sent_to` is nullable and only ever written by the drain, because the
value is not known until the drain resolves it: a delivery queued while
the preference said one thing may be sent after it says another, which is
precisely the case worth being able to see.

Not backfilled. The rows written before this column existed genuinely do
not carry the information, and inventing `u.email` for them would produce
a ledger that looks complete and is not — which is worse than one with an
honest NULL in it.
"""
from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
        ALTER TABLE notify.delivery
            ADD COLUMN sent_to text
    """)
    run("""
        COMMENT ON COLUMN notify.delivery.sent_to IS
        'The address or endpoint this delivery actually resolved to at '
        'drain time. NULL on rows written before migration 0044, and on '
        'SUPPRESSED rows that never resolved one. Never backfilled: an '
        'invented value would make the ledger look complete when it is not.'
    """)


def downgrade() -> None:
    run("ALTER TABLE notify.delivery DROP COLUMN sent_to")
