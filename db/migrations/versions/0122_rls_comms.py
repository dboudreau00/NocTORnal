"""Row-level security on the communications records (S1, 2026-09-25).

## What this enforces, and for whom

`noctornal_app`, bound per request (0111), now sees and writes:

- `comms.channel_binding`, `comms.contact_block`, `comms.conversation`,
  `comms.pgp_key_acquisition` (the ELEMENT template): in a case the user
  may read, the record's classification within the user's ceiling for
  that case, its compartments held. Every reader in comms.py,
  contact_blocks.py, pgp.py and pgp_keys.py already filters on the
  record's labels (a record can sit above its case, and each learned that
  once: CR5, F19, F10-fix).
- `comms.contact_block_entry` (CHILD of the block), `comms.participant`
  (CHILD of the conversation) and `comms.pgp_key` (CHILD of its
  acquisition, which carries the key's labels).
- `comms.message` (CUSTOM): its own labels, within the ceiling for its
  conversation's case, inside a conversation the user may see.
- `comms.device_fingerprint`, `comms.pgp_verification` (the CASE
  template): a verification carries no labels of its own; the ledger and
  queue read it through `pgp._VISIBLE_VERIFICATION`, whose EXISTS legs
  over the binding, the block and the key now meet those rows' policies
  as well as the reader's labels.
- `comms.pgp_key_lookup` (CASE_LABELLED: a lookup carries a
  classification and never compartments).
- `comms.service_selector` (CUSTOM): a case's stoplist entries in a case
  the user may read; the global stoplist (no case) to any bound user,
  since every parse applies it.

Minimisation and the incidental-party flag it relies on run as a system
purpose (`db.SystemPurpose.MINIMISATION`, docs/16 L4): dropping bodies
is a legal obligation, and one done partly because a message sat above
the minimiser, while reporting a count, would be the wrong-thing report.

`comms.contact_block_entry (proposal_id)` gains a partial index: Triage
reads a proposal's contact block through `iam.element_facts` (0117) by
that column.

## Trigger functions that now read a policied table

Each becomes SECURITY DEFINER with its search path pinned, as 0113 did
(PRIOR_CONFIG below restores them exactly).

## Downgrade

Restores the trigger functions, drops the index, every policy, and
disables row security on the twelve tables.
"""
from alembic import op

revision = "0122"
down_revision = "0121"
branch_labels = None
depends_on = None

_CASES = "(SELECT iam.rls_cases())::uuid[]"
_CLR = "(SELECT iam.rls_clearance())"
_CEIL = "(SELECT iam.rls_ceilings())"
_HELD = "(SELECT iam.rls_compartments())"

#: function -> its search_path before this revision (None: it had none).
#: Every trigger function whose body reads one of these tables and was
#: not SECURITY DEFINER already (0113 made the acquisition's and the
#: lookup's guards so).
PRIOR_CONFIG: dict[str, str | None] = {
    "comms.guard_pgp_key()": None,
    "comms.pgp_verification_cites_a_confirmed_key()": None,
    "comms.pgp_verification_is_attributed()": None,
    "comms.pgp_verification_confirms_its_binding()": None,
}


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
    "comms.channel_binding": _element("channel_binding"),
    "comms.contact_block": _element("contact_block"),
    "comms.conversation": _element("conversation"),
    "comms.pgp_key_acquisition": _element("pgp_key_acquisition"),
    "comms.contact_block_entry": _child("contact_block_entry", "comms.contact_block",
                                        "block_id"),
    "comms.participant": _child("participant", "comms.conversation",
                                "conversation_id"),
    "comms.pgp_key": _child("pgp_key", "comms.pgp_key_acquisition", "acquisition_id"),
    "comms.message": (
        "EXISTS (SELECT 1 FROM comms.conversation p "
        "WHERE p.id = message.conversation_id "
        f"AND (message.classification <= {_CLR} "
        f"OR message.classification <= iam.rls_ceiling_for({_CEIL}, p.case_id))) "
        f"AND message.compartments <@ {_HELD}"),
    "comms.device_fingerprint": f"device_fingerprint.case_id = ANY ({_CASES})",
    "comms.pgp_verification": f"pgp_verification.case_id = ANY ({_CASES})",
    "comms.pgp_key_lookup": (
        f"pgp_key_lookup.case_id = ANY ({_CASES}) AND "
        f"(pgp_key_lookup.classification <= {_CLR} OR "
        f"pgp_key_lookup.classification <= "
        f"iam.rls_ceiling_for({_CEIL}, pgp_key_lookup.case_id))"),
    "comms.service_selector": (
        f"(service_selector.case_id IS NULL AND {_CLR} IS NOT NULL) OR "
        f"service_selector.case_id = ANY ({_CASES})"),
}

INDEX = ("CREATE INDEX IF NOT EXISTS contact_block_entry_proposal_idx "
         "ON comms.contact_block_entry (proposal_id) WHERE proposal_id IS NOT NULL;")


def pinned_path(prior: str | None) -> str:
    """0113's rule: pg_catalog first, the function's own schemas (public
    where it had none), pg_temp last."""
    names = [n.strip() for n in (prior or "public").split(",")]
    names = [n for n in names if n not in ("pg_catalog", "pg_temp")]
    return ", ".join(["pg_catalog", *names, "pg_temp"])


def upgrade_sql() -> str:
    out = [f"ALTER FUNCTION {fn} SECURITY DEFINER SET search_path = {pinned_path(prior)};"
           for fn, prior in PRIOR_CONFIG.items()]
    out.append(INDEX)
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
    out.append("DROP INDEX IF EXISTS comms.contact_block_entry_proposal_idx;")
    for fn, prior in PRIOR_CONFIG.items():
        if prior is None:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER RESET search_path;")
        else:
            out.append(f"ALTER FUNCTION {fn} SECURITY INVOKER SET search_path = {prior};")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(upgrade_sql())


def downgrade() -> None:
    run(downgrade_sql())
