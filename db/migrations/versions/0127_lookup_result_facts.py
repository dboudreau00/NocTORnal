"""The label of a lookup's answer, read as a fact (F51, 2026-10-02).

## Why

0128 puts `ingest.lookup_result` under row-level security. Two readers
compose a label as the strictest of joined rows, and each joined the
answer with a LEFT JOIN:

- the lookup ledger (`LookupService._READ` in lookups.py), which shows a
  lookup with its answer's outcome, status and counts withheld from a
  reader who does not dominate the answer's label;
- Triage (`proposals._SOURCE_FROM`), which reads a proposal raised from an
  answer at the strictest of its payload's, its document's, its contact
  block's and its answer's labels.

Under a policy, a RED answer an AMBER reader may not see drops out of the
join and reads as no answer at all: the ledger would then serve the very
outcome it withholds, and Triage would read the proposal at the lower
label that is left. That is the anti-join trap turned into a leak
(docs/00 decision 146).

`iam.lookup_result_facts(id)` answers an answer's case and classification
whatever the caller may see, as `iam.element_facts` does for the graph,
the exhibits, collected documents, samples and conversations. It is a
function of its own rather than a new `iam.element_facts` branch, so that
it is added without restating that function's frozen text. It reads one
row by primary key: static SQL over a fully qualified name, SECURITY
DEFINER with `SET search_path = pg_catalog, pg_temp`.

## Downgrade

Drops the function. 0128, whose readers need it, goes down first.
"""
from alembic import op

revision = "0127"
down_revision = "0126"
branch_labels = None
depends_on = None

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

LOOKUP_RESULT_FACTS = f"""
CREATE FUNCTION iam.lookup_result_facts(p_id uuid)
  RETURNS TABLE (case_id uuid, classification core.tlp)
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT r.case_id, r.classification
    FROM ingest.lookup_result r
   WHERE r.id = p_id
$$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(LOOKUP_RESULT_FACTS)


def downgrade() -> None:
    run("DROP FUNCTION iam.lookup_result_facts(uuid);")
