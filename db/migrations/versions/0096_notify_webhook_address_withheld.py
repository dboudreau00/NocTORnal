"""Withhold the path of every webhook address the ledger stored (notify F8,
2026-09-24).

## What was wrong

`transports._succeed` wrote NOCTORNAL_WEBHOOK_URL into
`notify.delivery.sent_to` verbatim for every webhook delivery (0044).
Incoming-webhook URLs commonly carry a bearer secret in the path (a chat
service's hook id, a token segment), and the ledger returned it to the
browser of every holder of integration.manage, whose console then called
it "already the server's redacted form", which it was not.

## What this does

Rewrites every stored WEBHOOK `sent_to` into the form
`transports.redact_endpoint` now writes: the scheme and the authority as
written, userinfo always dropped, and a path or query replaced by
"/[path withheld: <first 8 hex of the sha256 of the raw text>]" so two
endpoints stay distinguishable. Text that does not parse as a URL becomes
"[endpoint withheld: <8 hex>]". Rows already in either form are left
alone, so the rewrite is idempotent. Both sides work on the RAW text (no
lower-casing, IPv6 brackets kept, a bare "?" withholds);
test_notify_ledger_migration_pg.py holds the SQL equal to the Python over
a corpus.

`public.digest` is pgcrypto, installed and executable through PUBLIC
(0060's docstring).

## Downgrade

A no-op by design: the withheld text is a credential and cannot be
restored, and should not be. Round trip on an empty database is clean.
0044's column comment gains a sentence saying withheld paths were
rewritten, not invented.
"""
from alembic import op

revision = "0096"
down_revision = "0095"
branch_labels = None
depends_on = None

#: The SQL twin of transports.redact_endpoint, over the column `sent_to`.
#: Module level so the parity test runs exactly this text.
TWIN = r"""CASE
  WHEN {col} ~ '^[A-Za-z][A-Za-z0-9+.-]*://' THEN
    substring({col} from '^([A-Za-z][A-Za-z0-9+.-]*)://') || '://'
    || regexp_replace(substring({col} from '^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)'),
                      '^.*@', '')
    || CASE WHEN {col} ~ '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*(/[^?#]+|/?\?)'
            THEN '/[path withheld: '
                 || left(encode(public.digest({col}, 'sha256'), 'hex'), 8) || ']'
            ELSE '' END
  ELSE '[endpoint withheld: '
       || left(encode(public.digest({col}, 'sha256'), 'hex'), 8) || ']'
END"""

#: Already withheld: left alone, so a second run changes nothing.
ALREADY = (r"{col} ~ '/\[path withheld: [0-9a-f]{{8}}\]$' "
           r"OR {col} ~ '^\[endpoint withheld: [0-9a-f]{{8}}\]$'")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    twin = TWIN.format(col="sent_to")
    already = ALREADY.format(col="sent_to")
    run(f"""
UPDATE notify.delivery
   SET sent_to = {twin}
 WHERE channel = 'WEBHOOK' AND sent_to IS NOT NULL
   AND NOT ({already});

COMMENT ON COLUMN notify.delivery.sent_to IS
  'Where the delivery actually went, resolved at drain time (0044). Never '
  'backfilled. A webhook address keeps its scheme and host; its path and '
  'query are withheld behind a fingerprint because they commonly carry a '
  'bearer secret (0096 rewrote the stored ones: withheld, not invented).';
""")


def downgrade() -> None:
    # The withheld text was a credential; nothing restores it (see above).
    pass
