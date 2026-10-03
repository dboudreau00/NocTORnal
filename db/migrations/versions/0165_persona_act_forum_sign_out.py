"""A persona act for signing a forum persona out (the persona vault split
merged with the authenticated forum path, 2026-10-03).

0156 made every attended persona act a row in `collect.persona_act` for the
collector, the one process that holds the persona key. The authenticated
forum path (0161) keeps a persona's forum session cookies sealed under that
key, so the board's own sign-out on a stop can only be done where the key
is: the persona's stop route asks the collector for it, as an act of the
kind `FORUM_SIGN_OUT`, and waits a bounded time like every other act route
(`persona_acts.py`, `routers/collection.py`). This revision adds the kind to
`persona_act_kind`; nothing else about the queue changes (the table, its
policies, its guard and its privileges are 0156's, and the act carries no
secret: the persona's id, the label its sources are held at, and who asked).

## Downgrade

Work in flight is not dropped: it refuses, naming how many, while a
sign-out act is pending or running (0156's own rule for the queue). A
finished act is a record and is never deleted (`collect.guard_persona_act`),
so the check cannot be narrowed under one; it is restored as 0156 wrote it
and, only when a finished sign-out act exists, left NOT VALID, which keeps
the record, refuses a new act of any other kind than 0156's six, and is
validated again by the next upgrade's restatement. With no sign-out act
recorded the restored check is validated and 0156's exactly.
"""
from alembic import op

revision = "0165"
down_revision = "0164"
branch_labels = None
depends_on = None

#: Frozen text: 0156's kinds, and with this revision the sign-out.
KINDS_0156 = ("'TELEGRAM_RESOLVE', 'TELEGRAM_JOIN', 'TELEGRAM_MEMBERSHIP', "
              "'TELEGRAM_MARK_MEMBER', 'TELEGRAM_REBIND', 'SOURCE_POLL'")
KINDS_0165 = KINDS_0156 + ", 'FORUM_SIGN_OUT'"


def _restate(kinds: str, *, not_valid: bool = False) -> str:
    tail = " NOT VALID" if not_valid else ""
    return ("ALTER TABLE collect.persona_act DROP CONSTRAINT persona_act_kind;\n"
            "ALTER TABLE collect.persona_act ADD CONSTRAINT persona_act_kind "
            f"CHECK (kind IN ({kinds})){tail};")


UPGRADE_SQL = _restate(KINDS_0165)

DOWNGRADE_SQL = """
DO $noc$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM collect.persona_act
   WHERE kind = 'FORUM_SIGN_OUT' AND status IN ('PENDING', 'RUNNING');
  IF n > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0165: ' || n
      || CASE WHEN n = 1 THEN ' forum sign-out act is' ELSE ' forum sign-out acts are' END
      || ' still pending or running, and narrowing the check would strand '
      || CASE WHEN n = 1 THEN 'it' ELSE 'them' END
      || '; let the collector finish what is pending or cancel it, then downgrade';
  END IF;
END
$noc$;
""" + _restate(KINDS_0156, not_valid=True) + """
DO $noc$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM collect.persona_act WHERE kind = 'FORUM_SIGN_OUT') THEN
    ALTER TABLE collect.persona_act VALIDATE CONSTRAINT persona_act_kind;
  END IF;
END
$noc$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
