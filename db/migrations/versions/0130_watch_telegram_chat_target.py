"""A watch may target a Telegram chat, and names it by its typed id (F47, 2026-10-02).

## What this enforces

`collect.watch.target_kind` is free text (0010 listed BOARD, THREAD, USER,
CHANNEL, FEED and SEARCH in a comment, and nothing has ever checked it), so
there was no enum or CHECK to extend. TELEGRAM_CHAT is the one kind the
matcher now acts on: a hit of a watch of that kind is scoped to the chat the
watch names, and says so (`chat:<id>` leads its reasons). For that kind
`target_ref` has to be the chat's typed durable id, `c:<id>` or `g:<id>`:
invariant 9 (index durable identifiers, not displayed ones) applies to a
watch's target as it does to a selector, because an `@username` is recycled
and a watch that followed one would follow whoever held the name next.

The CHECK is `watch_telegram_chat_typed`. It reads on the kind only: every
other kind keeps the free text it had, so no existing watch, test fixture or
seed changes meaning. The kind is matched exactly and a case-insensitive
spelling of it ('telegram_chat') is refused outright rather than stored as
a different, unrecognised kind the matcher would never act on. The pattern
is the one `telegram.CHAT_PATTERN` spells (test_watch_targets_pg holds the
two equal).

## The upgrade refuses before it changes anything

A row that already says TELEGRAM_CHAT (in any spelling) and does not name a
typed chat id cannot be made valid by this migration without choosing what it
meant, and a migration does not rewrite what it cannot be sure of. The
upgrade counts them first and stops with a sentence that says how many,
names up to five by id, and what to do (2026-10-07: the count
alone left the operator to find the rows). None can exist from the application: nothing in this tree
creates a watch, and the kind was not recognised before this revision, so
the count is of rows somebody wrote by hand.

## Row-level security

`collect.watch` is under policy (0124, CUSTOM_WATCH). A CHECK constraint is
validated by the owner's ALTER and is not a statement a role runs, and
`ENABLE ROW LEVEL SECURITY` without FORCE leaves the owner's pre-check
reading every row, so the count below sees all of them.

## Downgrade

Drops the constraint. Nothing is rewritten: a TELEGRAM_CHAT watch stays as
it is, and goes back to being a label the matcher does not read.
"""
from alembic import op

revision = "0130"
down_revision = "0129"
branch_labels = None
depends_on = None

#: The typed chat ids telegram.CHAT_PATTERN spells (a channel, a supergroup
#: or a basic group), without its anchors.
CHAT_ID = r"[cg]:[1-9][0-9]{0,19}"

#: Frozen text: a later revision that changes it restates it.
OFFENDING = (
    "upper(target_kind) = 'TELEGRAM_CHAT' AND NOT ("
    "target_kind = 'TELEGRAM_CHAT' AND target_ref ~ '^" + CHAT_ID + "$')")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade_sql() -> str:
    return f"""
DO $pre$
DECLARE
  bad bigint;
  ids text;
BEGIN
  SELECT count(*) INTO bad FROM collect.watch WHERE {OFFENDING};
  IF bad > 0 THEN
    SELECT string_agg(w.id::text, ', ' ORDER BY w.id) INTO ids
      FROM (SELECT id FROM collect.watch WHERE {OFFENDING} ORDER BY id LIMIT 5) w;
    RAISE EXCEPTION USING MESSAGE =
      'refusing to upgrade 0130: ' || bad
      || CASE WHEN bad = 1 THEN ' watch targets' ELSE ' watches target' END
      || ' a Telegram chat without being written as TELEGRAM_CHAT with a '
      || 'typed chat id (c:<id> or g:<id>). Correct '
      || CASE WHEN bad = 1 THEN 'it' ELSE 'each' END
      || ' by hand first ('
      || CASE WHEN bad = 1 THEN 'watch id: ' ELSE 'watch ids: ' END || ids
      || CASE WHEN bad > 5 THEN ' and ' || (bad - 5) || ' more' ELSE '' END
      || '): a watch on a chat by its @username follows whoever '
      || 'holds the name next. The upgrade stopped at 0129, with every '
      || 'earlier revision applied; run the upgrade again once corrected.';
  END IF;
END
$pre$;

ALTER TABLE collect.watch
  ADD CONSTRAINT watch_telegram_chat_typed
  CHECK (NOT ({OFFENDING}));
"""


def downgrade_sql() -> str:
    return "ALTER TABLE collect.watch DROP CONSTRAINT watch_telegram_chat_typed;"


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
