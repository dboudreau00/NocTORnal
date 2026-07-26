"""lab.sample joins the classification floor every other labelled table has.

docs/17 F19. `core.enforce_tlp_floor` is attached to `core.node`,
`core.edge` and `core.evidence` and has been since the schema was written:
"A child may be more restricted than its case, never less." `lab.sample`
was created in migration 0031 with a `classification` column, a
`compartments` column, and neither trigger nor check.

The consequence was not theoretical. `routers/samples.py` takes
`classification` as a `Form(...)` defaulting to `"AMBER"`, so an analyst
attaching the recovered dropper from a RED, compartmented case and
touching nothing else produced a row at AMBER with `compartments = '{}'`.
Every read that consulted the sample's own labels — the queue, the detail
endpoint — then handed it to anybody holding AMBER clearance, including a
MALWARE_ANALYST whom migration 0031 deliberately grants no case access at
all.

The service now raises a sample to its case's floor on submit and composes
the case's labels at read time. This is the backstop for everything that
does not come through the service: a migration, a fix-up script, a
psql session. Three of the four Phase 8 label findings shared this root,
and a rule enforced only in application code is a rule that holds until
somebody writes the second caller.

## Compartments are NOT propagated by the trigger

Deliberately, and consistently with node/edge/evidence, which the trigger
also leaves alone. Compartments are composed at READ time everywhere in
this system (`deps.effective_labels`, and now `SampleService.queue` /
`visible` / `download`), because a compartment added to a case after the
fact must apply to what is already in it — and a trigger cannot reach
backwards. Storing them would create a second copy that drifts.

## The existing rows

`VALIDATE`d rather than `NOT VALID`. There are only two ways this could
fail: a sample below its case's floor, which is exactly the defect being
closed and must not be grandfathered on the one table that holds malware;
or a sample whose case has since been reclassified upward, which is the
same thing arriving by a different route. The upgrade raises the offending
rows to their case's floor first, so the trigger has nothing to reject —
raising a classification is always the safe direction and never discloses
anything.
"""
from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    # Remediate before constraining. A sample sitting below its case's
    # floor is the defect; leaving it there and merely stopping new ones
    # would protect future submissions and none of the existing malware.
    run("""
        UPDATE lab.sample s
           SET classification = c.classification
          FROM core."case" c
         WHERE c.id = s.case_id
           AND s.classification < c.classification
    """)
    run("""
        CREATE TRIGGER sample_tlp
        BEFORE INSERT OR UPDATE ON lab.sample
        FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor()
    """)


def downgrade() -> None:
    # The classification raises are NOT undone. Lowering a label is a
    # disclosure decision and a migration is not the place one gets made;
    # an operator who genuinely wants a sample back at AMBER can say so
    # explicitly, on the record.
    run("DROP TRIGGER IF EXISTS sample_tlp ON lab.sample")
