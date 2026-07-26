"""Tell an analyst when their picture is incomplete (docs/14 U2).

An under-cleared analyst currently sees a smaller graph with **no indication
that anything was withheld**. That is not a presentation problem, it is a
correctness one: an analyst who does not know a node is missing draws
conclusions from a network they believe is complete, and the whole premise
of Phase 3 is that structure means something. A broker who looks peripheral
because the two ties that make them central are RED is a wrong answer
delivered confidently.

## Why it is a per-case setting and not a constant

Telling someone that something is hidden is itself a disclosure. Three
positions are defensible for different cases, so the case says which:

- `NONE` — say nothing. The current behaviour, kept available for the case
  where even "there is something here you cannot see" matters.
- `PRESENCE` — say that the view is incomplete, with no number. **The
  default**, because it fixes the analytical error while disclosing close to
  the minimum: one bit, in a case the analyst is already assigned to and
  whose own classification usually implies it.
- `COUNT` — say how many elements and ties. Useful when the analyst needs to
  judge how badly the picture is degraded before relying on a metric.

## The honest limitation

None of these is leak-proof, and PRESENCE is not meaningfully safer than
COUNT against a determined reader. Both can be **differenced**: vary the
projection, watch the flag or the number move, and localise what is hidden.
Narrowing to a single suspected actor and reading the delta is a handful of
requests.

That is accepted rather than solved, for three reasons. The reader is
already assigned to the case and already cleared to some level of it. Every
projection request is audited, so a differencing sweep is a visible pattern
rather than a silent one. And the alternative -- an analyst who cannot tell
a sparse network from a censored one -- is a worse failure in a tool whose
output goes into a prosecution file.

What is NOT disclosed, at any setting: which classification, which
compartment, and **where**. The count is per case, never per node. "There is
a hidden tie adjacent to this person" would localise the withheld material,
which is the disclosure that actually matters.
"""
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

ALTER TABLE "case"
  ADD COLUMN withheld_disclosure text NOT NULL DEFAULT 'PRESENCE';

ALTER TABLE "case" ADD CONSTRAINT case_withheld_disclosure_known
  CHECK (withheld_disclosure IN ('NONE', 'PRESENCE', 'COUNT'));
""")


def downgrade() -> None:
    run("""
ALTER TABLE core."case" DROP CONSTRAINT case_withheld_disclosure_known;
ALTER TABLE core."case" DROP COLUMN withheld_disclosure;
""")
