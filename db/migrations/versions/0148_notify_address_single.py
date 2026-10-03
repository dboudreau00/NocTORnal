"""A personal notification address is one plain address (finding
egress-notify-address-list, review of 2026-10-03).

## Why

F19 lets a user redirect their own email notifications only to a domain the
operator declared in NOCTORNAL_NOTIFY_ADDRESS_DOMAINS. The service checked
the text after the LAST '@', so 'collector@attacker.example,
me@corp.example' passed, was stored here, and smtplib's send_message turned
the To header into one RCPT per address. Every later subject (with the case
code) and summary went to the outside mailbox as well.

The service now parses one plain addr-spec before it checks the domain, and
the drain refuses to send to a stored value that fails the same rule. This
CHECK is the backstop for any writer that is not the service.

## What this adds

`preference_address_single`: NULL, or at most 254 characters of a local part
of letters, digits and '_', '+', "'" and '-' joined by single dots, '@', LDH
domain labels. No display name, group, list, comment, whitespace, CR or LF,
and none of the characters a mail server reads as routing in a local part
('%', '!', '|', '/' and their kind): the allowlist reads the domain after the
last '@', and a local part that carries a second destination escapes it.
`notifications.SINGLE_ADDRESS_PATTERN` spells the same pattern and a test
holds the two equal.

NOT VALID: a value stored before this revision is left as it is (the
NOTIFY_ADDRESS_CHANGED audit rows record who set it and when), the drain
never delivers to it, and the service refuses to rewrite the row until the
user sets a new address or clears it. Rewriting user rows here would take a
decision away from the person who made it without an audit row saying so.

## Downgrade

Drops the constraint. Nothing is lost: no row was changed.
"""
from alembic import op

revision = "0148"
down_revision = "0147"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes the rule restates it.
UPGRADE_SQL = r"""
ALTER TABLE notify.preference
  ADD CONSTRAINT preference_address_single
  CHECK (address IS NULL
         OR (length(address) <= 254
             AND address ~ $addr$^[A-Za-z0-9_+'-]+(\.[A-Za-z0-9_+'-]+)*@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$$addr$))
  NOT VALID;

COMMENT ON CONSTRAINT preference_address_single ON notify.preference IS
  'One plain address and nothing else (migration 0148, finding '
  'egress-notify-address-list, 2026-10-03). A list would reach every '
  'recipient in it and escape the domain allowlist.';
"""

DOWNGRADE_SQL = """
ALTER TABLE notify.preference DROP CONSTRAINT preference_address_single;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
