"""Re-derive stored TELEGRAM_ID selectors from `raw_value`, not `norm_value`.

`telegram_id_norm` decoded the Bot-API channel encoding by string-dropping
a leading "100". The encoding is arithmetic — `chat_id = -(10**12 + id)` —
so the shortcut inverted it only for a channel id of exactly ten digits.
`TELEGRAM_ID` is `is_strong`, so wrong feeds the auto-merge path.

The function now decodes arithmetically and namespaces by type (`u:` user,
`c:` channel/supergroup, `g:` basic group). Stored `core.selector.norm_value`
rows were written by the old function and must be re-keyed.

## Why this reads `raw_value` and NOT `norm_value`

The first version of this migration transformed `norm_value` in place, and
it was WRONG in the most damaging possible direction. An adversarial pass
on 2026-07-26 caught it before it ever ran against real data.

The old function ALREADY stripped the `-100` prefix. So a Bot-API channel
`-1001234567890` was stored as the bare positive `1234567890` — with no
leading minus. A rewrite keyed on `norm_value ~ '^-'` therefore missed it
and fell through to the bare-positive branch, stamping a CHANNEL as
`u:1234567890`:

    raw            old norm_value   in-place rewrite   correct
    -1001234567890 1234567890       u:1234567890  ✗    c:1234567890
    -1000123456789 0123456789       u:123456789   ✗    c:123456789
    -1012345678901 -1012345678901   c:12345678901 ✓    c:12345678901
    -987654321     -987654321       g:987654321   ✓    g:987654321

A later observation of Telegram USER 1234567890 would then have matched
that strong selector and auto-merged a person onto a channel — which is
precisely the harm CR3 exists to remove, recreated by the migration
written to remove it. It could also have aborted mid-upgrade on
`UNIQUE (case_id, selector_type, norm_value)` where a case held both a
9-digit channel and the same-numbered user.

`raw_value` is the value AS OBSERVED and is not lossy, so re-deriving from
it is both correct and complete. The arithmetic below is pinned here
rather than imported from `noctornal_ontology`, because a migration that
calls application code runs whatever that code says TODAY — the next
change to `telegram_id_norm` would silently change what revision 0051 does
to a database being upgraded from scratch.

## What this still CANNOT do

It cannot undo a merge that already happened. Where the old function
collided a ten-digit channel with a same-numbered user, those two
observations are already one row with one `node_id`, and nothing records
that they were ever separate. Recomputing a value cannot split them.

An operator who has run Telegram collection against real data should
re-check `TELEGRAM_ID` selectors whose `node_id` links a channel-ish node
to a person-ish one. The pre-flight below reports how many rows are at
risk rather than leaving that invisible.
"""
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def run(sql: str):
    return op.get_bind().connection.driver_connection.execute(sql)


#: The new norm, expressed once in SQL over `raw_value`. Mirrors
#: `noctornal_ontology.normalisers.telegram_id_norm` exactly, including the
#: rule that a bare positive is ambiguous between a user and an MTProto
#: channel and is assumed `u:` — the same assumption the live code makes,
#: so migration and runtime agree.
_NEW_NORM = r"""
    CASE
      WHEN lower(raw_value) ~ '^[ucg]:' THEN
        lower(substring(btrim(raw_value) from 1 for 2))
        || (regexp_replace(raw_value, '\D', '', 'g'))::numeric::bigint::text
      WHEN btrim(raw_value) ~ '^-'
           AND (regexp_replace(raw_value, '\D', '', 'g'))::numeric > 1000000000000
        THEN 'c:' || ((regexp_replace(raw_value, '\D', '', 'g'))::numeric
                      - 1000000000000)::bigint::text
      WHEN btrim(raw_value) ~ '^-'
        THEN 'g:' || (regexp_replace(raw_value, '\D', '', 'g'))::numeric::bigint::text
      ELSE 'u:' || (regexp_replace(raw_value, '\D', '', 'g'))::numeric::bigint::text
    END
"""

_ELIGIBLE = (
    "selector_type = 'TELEGRAM_ID' "
    "AND norm_value !~ '^[ucg]:' "
    "AND regexp_replace(raw_value, '\\D', '', 'g') <> ''"
)


def upgrade() -> None:
    # PRE-FLIGHT 1: would re-deriving collide two existing rows inside one
    # case? Merging selectors silently is exactly what this migration is
    # about avoiding, so it fails loudly and names the damage instead.
    clash = run(f"""
        SELECT count(*) FROM (
            SELECT case_id, {_NEW_NORM} AS nv, count(*) AS n
              FROM core.selector
             WHERE {_ELIGIBLE}
             GROUP BY case_id, nv
            HAVING count(*) > 1
        ) t
    """).fetchone()[0]
    if clash:
        raise RuntimeError(
            f"{clash} (case, telegram id) group(s) would collapse onto one "
            "selector row if this migration ran. That means two rows this "
            "system has been treating as different identifiers re-derive to "
            "the same one. Merging them is a case decision, not a "
            "migration's. Resolve them first:\n\n"
            "  SELECT case_id, raw_value, norm_value, node_id\n"
            "    FROM core.selector WHERE selector_type = 'TELEGRAM_ID'\n"
            "   ORDER BY case_id, raw_value;")

    # PRE-FLIGHT 2: report rows the OLD function may already have merged
    # wrongly. A ten-digit Bot-API channel and a same-numbered user both
    # normalised to bare digits, so a single row may be carrying both.
    # Recomputing cannot split them; saying so is the only honest option.
    suspect = run("""
        SELECT count(*) FROM core.selector
         WHERE selector_type = 'TELEGRAM_ID'
           AND btrim(raw_value) !~ '^-'
           AND regexp_replace(raw_value, '\\D', '', 'g') ~ '^[0-9]{10}$'
    """).fetchone()[0]
    if suspect:
        print(
            f"\n  0051 NOTE: {suspect} TELEGRAM_ID selector(s) hold a bare "
            "ten-digit id.\n"
            "  Under the old normaliser a Bot-API CHANNEL and a same-numbered "
            "USER both\n  reduced to that form, so any of these may already be "
            "a wrong merge.\n  This migration re-keys the value; it cannot "
            "un-merge what was merged.\n  Re-check their node_id "
            "attributions.\n")

    run(f"""
        UPDATE core.selector
           SET norm_value = {_NEW_NORM}
         WHERE {_ELIGIBLE}
    """)


def downgrade() -> None:
    # Deliberately NOT reversed. Going back would mean recreating values the
    # old function produced, which for 9- and 11-digit channel ids were
    # wrong — a downgrade that restores a known defect is not a downgrade.
    # The two formats are distinguishable (`^[ucg]:`), so a re-upgrade is a
    # no-op rather than a double application.
    pass
