"""The request role cannot lower the classification of a node or a tie.

## Why

`core.enforce_tlp_floor` (0016) refuses a label below the case and nothing
else, and the element policy's `WITH CHECK` (0114) asks only that the new
label be within the writer's ceiling. `noctornal_app` keeps table UPDATE on
`core.node` and `core.edge` for the label, attribute and merge writes, so one
statement as an assignee cleared to RED could rewrite a RED entity or tie on
an AMBER case down to AMBER, and every teammate cleared only to AMBER would
then read it, attributes included. No route writes these columns: the
correction routes refuse classification, and a merge refuses a survivor less
restricted than the entity merged into it (`merges.py`).

## What

A BEFORE UPDATE OF classification trigger on both tables refuses
`NEW.classification < OLD.classification` for any caller that row security
does not exempt (`iam.rls_caller_exempt()`). Raising a label stays open. The
owner and the system role keep the write, as 0171 leaves them theirs, so a
migration or an operator can still remediate a label filed too high.
`core.evidence` needs no trigger: 0178 left the request role UPDATE of
`storage_version_id` only.

The function is SECURITY DEFINER with `search_path = pg_catalog, pg_temp`, as
0171's is, and reads the caller through `iam.rls_caller_exempt()` rather than
`current_user`, which inside a definer is the owner.

## Downgrade

Drops the two triggers and the function. No row is written by this revision.
"""
from alembic import op

revision = "0183"
down_revision = "0182"
branch_labels = None
depends_on = None

#: Frozen text. A later revision that changes the function restates it.
UPGRADE_SQL = """
CREATE FUNCTION core.classification_never_lowered() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF NEW.classification < OLD.classification THEN
    RAISE EXCEPTION '%: classification % may not be lowered to %',
      TG_TABLE_NAME, OLD.classification, NEW.classification
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $fn$;

CREATE TRIGGER node_classification_kept BEFORE UPDATE OF classification ON core.node
  FOR EACH ROW EXECUTE FUNCTION core.classification_never_lowered();
CREATE TRIGGER edge_classification_kept BEFORE UPDATE OF classification ON core.edge
  FOR EACH ROW EXECUTE FUNCTION core.classification_never_lowered();

COMMENT ON FUNCTION core.classification_never_lowered() IS
  'The request role may raise a node''s or a tie''s classification and never lower it, so an element filed above the case floor is not shown to readers cleared only to the floor. The owner and the system role (row security exempt) are left as they were (0183).';
"""

DOWNGRADE_SQL = """
DROP TRIGGER edge_classification_kept ON core.edge;
DROP TRIGGER node_classification_kept ON core.node;
DROP FUNCTION core.classification_never_lowered();
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
