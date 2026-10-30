"""The request role cannot lower the labels of case material.

## Why

0183 stopped the request role lowering a node's or a tie's classification and
left two gaps. A compartment can still be dropped from a node or a tie: the
row policy asks only that the new compartments be within the writer's own, so
an assignee read into a compartment could write `{}` over it and every
teammate cleared to the level would read the row. And the same two columns,
classification and compartments, are writable by the request role on the other
tables that hold case material, where no route lowers either: documents,
selectors, samples, messages, conversations, contact blocks, channel bindings,
key acquisitions, captures, e-mails, call records and dead letters.

## What

`core.compartments_never_dropped()` refuses a compartment list that no longer
holds everything the old one did. It is set on both columns' tables listed
below, and 0183's `core.classification_never_lowered()` is set on the
classification of the tables 0183 did not reach. Both read the caller through
`iam.rls_caller_exempt()`, so the schema owner and the system role are left as
they were, which is what a compartment rename or retirement, a merge and an
operator's remediation run as. Raising a label, or adding a compartment, stays
open.

Left alone on purpose: `core."case"` (the case route governs its label and
refuses a lower one itself, and its compartments are fixed at opening),
`collect.source` and the other configuration tables, and `notify.*`, whose
labels the notification writer sets when it enqueues.

## Downgrade

Drops the triggers and the function this revision added. No row is written.
"""
from alembic import op

revision = "0184"
down_revision = "0183"
branch_labels = None
depends_on = None

#: Node and tie: 0183 holds their classification.
COMPARTMENT_ONLY = ("core.node", "core.edge")

#: Case material whose classification and compartments no route lowers.
BOTH = (
    "core.selector",
    "collect.document",
    "comms.channel_binding",
    "comms.contact_block",
    "comms.conversation",
    "comms.message",
    "comms.pgp_key_acquisition",
    "deception.call_record",
    "deception.capture",
    "deception.email_message",
    "lab.sample",
    "ingest.dead_letter",
)

#: Frozen text. A later revision that changes the function restates it.
FUNCTION_SQL = """
CREATE FUNCTION core.compartments_never_dropped() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF NOT (COALESCE(OLD.compartments, '{}') <@ COALESCE(NEW.compartments, '{}')) THEN
    RAISE EXCEPTION '%: compartments % may not be dropped (new %)',
      TG_TABLE_NAME, OLD.compartments, NEW.compartments
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $fn$;

COMMENT ON FUNCTION core.compartments_never_dropped() IS
  'The request role may add a compartment to case material and never drop one, so a row read into a compartment is not shown to readers who are not (0184).';
"""


def _statements(downgrade: bool) -> str:
    out = []
    for table in COMPARTMENT_ONLY + BOTH:
        if downgrade:
            out.append(f"DROP TRIGGER compartments_kept ON {table};")
        else:
            out.append(
                f"CREATE TRIGGER compartments_kept BEFORE UPDATE OF compartments ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION core.compartments_never_dropped();")
    for table in BOTH:
        if downgrade:
            out.append(f"DROP TRIGGER classification_kept ON {table};")
        else:
            out.append(
                f"CREATE TRIGGER classification_kept BEFORE UPDATE OF classification ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION core.classification_never_lowered();")
    return "\n".join(out)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL + _statements(downgrade=False))


def downgrade() -> None:
    run(_statements(downgrade=True) + "\nDROP FUNCTION core.compartments_never_dropped();")
