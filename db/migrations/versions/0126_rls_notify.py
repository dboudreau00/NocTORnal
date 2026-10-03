"""Row-level security on notifications and what they reached (F51, 2026-10-02).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `notify.notification` (CUSTOM_NOTICE): the recipient's own, at a
  classification within the recipient's case-less ceiling, with
  compartments they hold, and when it names a case, in a case they may
  read. The inbox, the badge, reading and acknowledgement work on exactly
  this, and `notifications.readable_predicate` stays on top of it (it
  reads the clearance without a break-glass raise, so it is the narrower
  of the two on labels). A notice labelled under an older, lower label of
  a case since raised above its recipient is hidden with the case, the
  conservative reading. A SELECT and an UPDATE policy: the request role
  inserts and deletes no notification. Every notice is raised through
  `notify.enqueue` (0125), the definer that checks the recipient instead
  of the writer.
- `notify.delivery` (CHILD of the notification and, when it names one, of
  its Jira link), `notify.jira_link` (CASE_LABELLED: an issue about a case,
  at a classification within the reader's ceiling for that case, the count
  the case's Integrations view already applied) and `notify.jira_event`
  (CHILD of the link): READ ONLY, a SELECT policy and nothing else. Only
  the definer and the system purposes below write them, and with no INSERT
  policy an INSERT is refused before any unique key is compared, so a
  request cannot learn from a duplicate key that another case has an open
  Jira link for a work item (the key is a uuid5 of the case and the
  object, which a caller can compute).
- `notify.case_route_block` (CASE): a case owner's Jira veto, in a case the
  user may read. The case's Integrations view reads and writes it there.

Who must see every row, and runs as a system purpose: the drain, which
sends every recipient's due deliveries, withdraws and revokes, posts to
Jira and runs the review and escalation producers (NOTIFY, for the cron
script and for Drain now); the delivery ledger, its requeue and the Jira
destination's administration, which span every recipient and case for an
administrator and never show content (NOTIFY_ADMIN); the count of signers
a two-person request reached (WITHHELD); readiness (READINESS) and the
purge's Jira warning (RETENTION) already did.

## Downgrade

Drops every policy and disables row security on the five tables.
"""
from alembic import op

revision = "0126"
down_revision = "0125"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"


def _exists(parent: str, table: str, fk: str) -> str:
    return f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"


def _optional(parent: str, table: str, fk: str) -> str:
    return f"({table}.{fk} IS NULL OR {_exists(parent, table, fk)})"


#: The recipient's own notice, within their labels (CUSTOM_NOTICE): a
#: SELECT policy (rls_read) and an UPDATE policy (rls_update).
#: Frozen text: a later revision that changes one restates it.
NOTICE = ("notification.recipient_id = (SELECT iam.rls_actor()) AND "
          f"notification.classification <= {_CLR} AND "
          f"notification.compartments <@ {_HELD} AND "
          f"(notification.case_id IS NULL OR notification.case_id = ANY ({_CASES}))")

#: table -> USING, one FOR ALL policy named rls_gate (USING and WITH CHECK).
POLICIES: dict[str, str] = {
    "notify.case_route_block": f"case_route_block.case_id = ANY ({_CASES})",
}

#: Read-only: a SELECT policy named rls_read and nothing else.
READ_ONLY: dict[str, str] = {
    "notify.jira_link": (
        f"jira_link.case_id = ANY ({_CASES}) AND "
        f"(jira_link.classification <= {_CLR} OR "
        f"jira_link.classification <= iam.rls_ceiling_for({_CEIL}, jira_link.case_id))"),
    "notify.delivery": (
        f"{_exists('notify.notification', 'delivery', 'notification_id')} AND "
        f"{_optional('notify.jira_link', 'delivery', 'jira_link_id')}"),
    "notify.jira_event": _exists("notify.jira_link", "jira_event", "link_id"),
}


def upgrade_sql() -> str:
    out = ["ALTER TABLE notify.notification ENABLE ROW LEVEL SECURITY;",
           f"CREATE POLICY rls_read ON notify.notification FOR SELECT USING ({NOTICE});",
           f"CREATE POLICY rls_update ON notify.notification FOR UPDATE "
           f"USING ({NOTICE}) WITH CHECK ({NOTICE});"]
    for table, qual in READ_ONLY.items():
        out.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        out.append(f"CREATE POLICY rls_read ON {table} FOR SELECT USING ({qual});")
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
    for table in reversed(list(READ_ONLY)):
        out.append(f"DROP POLICY rls_read ON {table};")
        out.append(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
    out += ["DROP POLICY rls_update ON notify.notification;",
            "DROP POLICY rls_read ON notify.notification;",
            "ALTER TABLE notify.notification DISABLE ROW LEVEL SECURITY;"]
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
