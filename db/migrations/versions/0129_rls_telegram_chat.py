"""Row-level security on which Telegram chat a source is (F51, 2026-10-02).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes a
`collect.telegram_chat` row only where its source's classification is
within the user's CASE-LESS ceiling (their clearance, raised only by a
live global break-glass grant). That is `collection._SOURCE_VISIBLE`, the
one predicate every chat route already applies through `_chat_row` and
the listing: a Telegram source belongs to no case, so a grant scoped to
one case never raises it.

The source's label is tested INLINE (the CUSTOM_SOURCE_CHILD template),
not through a policy on the source: `collect.source` is exempt, because
the egress proxy reads it as `noctornal_egress`, which is subject to row
security and must not be given a bypass, so there is no policy on the
parent for a CHILD test to lean on. A chat carries no label of its own.
An unbound connection's ceiling is NULL and sees and writes nothing.

## The readers this waited for (F51)

- `TelegramChats.create`'s duplicate check must see a chat whose source
  sits above the adder: it audits TELEGRAM_CHAT_DUPLICATE_HIDDEN and
  answers exactly as for an unresolvable reference. Under this policy it
  would see nothing, and the INSERT would meet the unique durable id
  instead, a duplicate-key error about a chat the caller may not know
  exists. The check runs as the TELEGRAM_INTAKE system purpose, and an
  INSERT that still meets the unique durable id (a chat added between the
  check and the insert) is answered by the same check.
- The attended acts (join, check membership, mark as member, rebind)
  update the chat by source id after `_chat_row` and a persona act; a
  source raised above the caller in between would leave the update
  matching no visible row, silently, while the act was audited as
  recorded. Each now refuses a change of no row as a missing chat.
- `attach_target_chats` and `attach_due_facts` read only the chats of
  sources their callers already filtered at the same ceiling, so each
  reads on the request connection unchanged. The officer was thought to
  sit below a target's source; the code does not allow it: an authority
  is never labelled below a source it covers (`_target_sources`, and
  `collect.raise_authority_labels` raises it with a reclassified source),
  and `CollectionAuthorityService._targets` withholds any other target
  before the chats are read.

## Who it does not touch

The owner (Alembic, fixtures, pg_dump; ENABLE, never FORCE) and
`noctornal_worker`: the poll and a manual run read the chat (refusal,
plan) and write what a session learnt of it (commit, settle) as the
COLLECTION purpose. `noctornal_egress` holds no privilege on this table.
`collect.guard_telegram_chat` compares the row with itself and reads no
table, so it stays SECURITY INVOKER.

## Downgrade

Drops the policy and disables row security on the table.
"""
from alembic import op

revision = "0129"
down_revision = "0128"
branch_labels = None
depends_on = None

_CLR = "(SELECT iam.rls_clearance())"

#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "collect.telegram_chat": (
        "EXISTS (SELECT 1 FROM collect.source p "
        "WHERE p.id = telegram_chat.source_id "
        f"AND p.classification <= {_CLR})"),
}


def upgrade_sql() -> str:
    out = []
    for table, qual in POLICIES.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_gate ON {table} FOR ALL "
                   f"USING ({qual}) WITH CHECK ({qual});")
    return "\n".join(out)


def downgrade_sql() -> str:
    out = []
    for table in reversed(list(POLICIES)):
        out.append(f"DROP POLICY rls_gate ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
