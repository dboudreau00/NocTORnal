"""Re-normalise stored TELEGRAM_ID selectors after the CR3 arithmetic fix.

`telegram_id_norm` decoded the Bot-API channel encoding by string-dropping
a leading "100". The encoding is arithmetic — `chat_id = -(10**12 + id)` —
so the shortcut inverted it only for a channel id of exactly ten digits.
Everything else was silently wrong, and `TELEGRAM_ID` is `is_strong`, so
wrong feeds the auto-merge path.

The function now decodes arithmetically and namespaces by type
(`u:` user, `c:` channel/supergroup, `g:` basic group). Stored
`core.selector.norm_value` rows were written by the old function, so they
are in the old format and would never match anything the new one produces.
This rewrites them.

## What this migration CANNOT do

It cannot undo a merge that already happened.

The worst case in CR3 was a ten-digit channel id normalising to bare
digits equal to an unrelated USER id — two different things landing on one
strong selector row and, from there, onto one actor. By the time this runs
those two observations are a single row with a single `node_id`, and
nothing in the data records that they were ever separate. Recomputing the
norm value cannot split them back apart.

So this migration fixes the FORMAT going forward and is honest that any
false merge already made is an analyst's problem, not a migration's. An
operator who has run Telegram collection against real data should re-check
`TELEGRAM_ID` selectors whose `node_id` links a channel-ish node to a
person-ish one.

## Why the recompute is done in SQL rather than by importing the function

A migration that imports application code runs whatever that code says
TODAY, which is not necessarily what it said when the migration was
written — the next change to `telegram_id_norm` would silently change what
revision 0051 does to a database being upgraded from scratch. The
arithmetic is four lines; it is pinned here.

The UNIQUE constraint is `(case_id, selector_type, norm_value)`. The new
format strictly SEPARATES values that previously collided (a user and a
channel now differ by prefix), so this can only reduce collisions, never
create them — with one exception handled below: two rows that were already
distinct in the old format could map onto one new value if a case held
both `-1001234567890` and a bare `c:`-style value. That cannot arise,
because nothing wrote `c:` before this revision.
"""
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    # Order matters: the channel rule must run before the bare-positive
    # rule, or a decoded channel would immediately be re-prefixed 'u:'.
    # Each statement is guarded on the value not already carrying a
    # prefix, so the set is idempotent.
    run(r"""
        UPDATE core.selector
           SET norm_value = 'c:' || (
                 (regexp_replace(norm_value, '\D', '', 'g'))::numeric
                 - 1000000000000)::bigint::text
         WHERE selector_type = 'TELEGRAM_ID'
           AND norm_value !~ '^[ucg]:'
           AND norm_value ~ '^-'
           AND (regexp_replace(norm_value, '\D', '', 'g'))::numeric
               > 1000000000000
    """)
    run(r"""
        UPDATE core.selector
           SET norm_value = 'g:' || (
                 regexp_replace(norm_value, '\D', '', 'g'))::numeric::bigint::text
         WHERE selector_type = 'TELEGRAM_ID'
           AND norm_value !~ '^[ucg]:'
           AND norm_value ~ '^-'
           AND regexp_replace(norm_value, '\D', '', 'g') <> ''
    """)
    run(r"""
        UPDATE core.selector
           SET norm_value = 'u:' || (
                 regexp_replace(norm_value, '\D', '', 'g'))::numeric::bigint::text
         WHERE selector_type = 'TELEGRAM_ID'
           AND norm_value !~ '^[ucg]:'
           AND regexp_replace(norm_value, '\D', '', 'g') <> ''
    """)


def downgrade() -> None:
    # Deliberately NOT reversed. Going back would mean recreating values
    # the old function produced, which for 9- and 11-digit channel ids were
    # wrong — a downgrade that restores a known defect is not a downgrade,
    # and the old and new formats are distinguishable, so a re-upgrade is
    # a no-op rather than a double-application.
    pass
