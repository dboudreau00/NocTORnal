"""Row-level security on a Telegram chat honours its source's compartments
(docs/17 F43, 2026-10-02).

0129 put `collect.telegram_chat` under a policy that tests its source's
classification inline (CUSTOM_SOURCE_CHILD), because the source is exempt
(the egress proxy reads it) and carries no policy for a CHILD test to lean
on. 0163 gave the source compartments. This revision restates that policy
with the source's compartments held by the bound user, so a chat under a
compartmented source is hidden from a reader who lacks the compartment, as
`collection._SOURCE_VISIBLE_HELD` hides the source itself. The readers
0129 named are unchanged: the duplicate check runs as a system purpose,
the attended acts refuse a write that changed no chat, and the poll runs
as `noctornal_worker`.

The policy text is frozen here, as 0129's was; the downgrade restores
0129's exactly.
"""
from alembic import op

revision = "0164"
down_revision = "0163"
branch_labels = None
depends_on = None

_CLR = "(SELECT iam.rls_clearance())"
_HELD = "(SELECT iam.rls_compartments())"

#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "collect.telegram_chat": (
        "EXISTS (SELECT 1 FROM collect.source p "
        "WHERE p.id = telegram_chat.source_id "
        f"AND p.classification <= {_CLR} "
        f"AND p.compartments <@ {_HELD})"),
}

#: 0129's text, restored by the downgrade.
POLICIES_0129: dict[str, str] = {
    "collect.telegram_chat": (
        "EXISTS (SELECT 1 FROM collect.source p "
        "WHERE p.id = telegram_chat.source_id "
        f"AND p.classification <= {_CLR})"),
}


def _restate(policies: dict[str, str]) -> str:
    out = []
    for table, qual in policies.items():
        out.append(f"DROP POLICY rls_gate ON {table};")
        out.append(f"CREATE POLICY rls_gate ON {table} FOR ALL "
                   f"USING ({qual}) WITH CHECK ({qual});")
    return "\n".join(out)


def upgrade_sql() -> str:
    return _restate(POLICIES)


def downgrade_sql() -> str:
    return _restate(POLICIES_0129)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
