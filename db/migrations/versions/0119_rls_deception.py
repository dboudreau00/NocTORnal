"""Row-level security on the deception records (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `deception.capture`, `deception.email_message`, `deception.call_record`
  (the ELEMENT template, as 0114 applies it to the graph): in a case the
  user may read, the record's classification within the user's ceiling
  for that case (a live break-glass grant on the case raises it, as the
  deception routes' own `_ceiling` does), its compartments held. Exactly
  the composed rule `deception._labels_clause` applies on every read: the
  case term is the case being readable, which already means its labels
  are within reach.
- `deception.capture_hop` (CHILD of the capture), `deception.email_hop`
  and `deception.email_attachment` (CHILD of the message): a redirect
  chain, a Received chain or an attachment list is never more visible
  than the record it belongs to.

Every reader in `deception.py` already filters by those labels and every
writer raises a record to its case's floor (`_raise_to_case_floor`) after
the route has held the author to their own ceiling, so nothing it reads
or writes changes. `enforce_tlp_floor`, the one trigger function on these
tables that reads another policied table, has been SECURITY DEFINER since
0113.

Who it does not touch: the owner (ENABLE, never FORCE) and
`noctornal_worker` (the legacy-record listings, `scripts/legacy_records.py`
and the readiness register, which run as system purposes).

## Downgrade

Drops every policy and disables row security on the six tables.
"""
from alembic import op

revision = "0119"
down_revision = "0118"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"


def _element(alias: str) -> str:
    return (f"{alias}.case_id = ANY ({_CASES}) AND "
            f"({alias}.classification <= {_CLR} OR "
            f"{alias}.classification <= iam.rls_ceiling_for({_CEIL}, {alias}.case_id)) "
            f"AND {alias}.compartments <@ {_HELD}")


def _child(table: str, parent: str, fk: str) -> str:
    return f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{fk})"


#: table -> (USING and WITH CHECK), one FOR ALL policy named rls_gate.
#: Frozen text: a later revision that changes one restates it.
POLICIES: dict[str, str] = {
    "deception.capture": _element("capture"),
    "deception.email_message": _element("email_message"),
    "deception.call_record": _element("call_record"),
    "deception.capture_hop": _child("capture_hop", "deception.capture", "capture_id"),
    "deception.email_hop": _child("email_hop", "deception.email_message", "message_id"),
    "deception.email_attachment": _child("email_attachment",
                                         "deception.email_message", "message_id"),
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
