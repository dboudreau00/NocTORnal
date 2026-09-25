"""Label the captures made before documents had compartments, from the
cases that cite them (L1, 2026-09-24).

## What was wrong

Before final review c15 (2026-09-24) a capture into a compartmented case
was stored with no compartments and at the label the analyst asked for,
so a thread pasted into RED OP-HALCYON-25 in STEALER-2026 could sit in the
collection at AMBER, listed and searchable by every AMBER reader of
collected documents. 0070 gives documents compartments, and a capture now
copies its case's. This labels the ones already there.

## The rule

A captured document (its source is MANUAL or PASTE; collected documents
belong to no case and are not touched) is CITED by a case when a proposal,
a claim or a contact block of that case names it, or when that case's
DOCUMENT_CAPTURED audit row does (a capture that raised no proposal is
still a capture into that case). For each captured document still carrying
no compartment:

- compartments: the keys held by EVERY citing case, when every citing
  case is compartmented. Each citing case's readers hold their case's
  compartments (the case gate, security/access.py), so the intersection
  hides the document from none of them;
- classification: raised to the LEAST citing case's, never lowered. It
  only narrows, never below any citing case's own readers, and it closes
  the c15 residue (a RED case's capture stored at AMBER and cited only by
  RED cases becomes RED).

A document cited by an uncompartmented case, or by compartmented cases
with no key in common, keeps no compartment: no lock fits every case that
cites it. Those are counted in the summary row, listed by
`python scripts/legacy_records.py --section captures`, and shown on the
readiness register (`captured_documents_compartmented`).

Every document it changes gets a DOCUMENT_LABELS_BACKFILLED audit row
(actor SYSTEM), and one DOCUMENT_LABELS_BACKFILL_SUMMARY row counts what
was labelled and what was left. `BACKFILL_SQL` is one statement, so it
commits whole; run again it changes nothing and writes nothing. It reaches
the audit trail through `event_object_id_idx`, from the captured
documents, never by scanning the trail for an action. On a new database it
finds nothing. The updated rows do not re-index (0070 gave `document_tsv`
a column list).

## Downgrade

Nothing. The labels stay what this set them to, and so do the audit rows
(`audit.event` is append-only). Once it has labelled any document, 0070's
downgrade refuses, because dropping the column would declassify it.
"""
from __future__ import annotations

from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None

#: The `by` both audit actions carry.
BY = "the upgrade that gave captured documents compartments"

BACKFILL_SQL = f"""
WITH captured AS (
  SELECT d.id, d.classification
    FROM collect.document d
    JOIN collect.source s ON s.id = d.source_id
   WHERE s.kind IN ('MANUAL', 'PASTE')
     AND cardinality(d.compartments) = 0),
cites AS (
  SELECT p.document_id, p.case_id
    FROM collect.proposal p JOIN captured k ON k.id = p.document_id
  UNION
  SELECT a.document_id, a.case_id
    FROM core.assertion a JOIN captured k ON k.id = a.document_id
  UNION
  SELECT b.document_id, b.case_id
    FROM comms.contact_block b JOIN captured k ON k.id = b.document_id
  UNION
  SELECT e.object_id, e.case_id
    FROM captured k JOIN audit.event e ON e.object_id = k.id
   WHERE e.action = 'DOCUMENT_CAPTURED' AND e.object_type = 'document'
     AND e.case_id IS NOT NULL),
per_doc AS (
  SELECT ci.document_id,
         count(DISTINCT ci.case_id) AS cases,
         bool_and(cardinality(c.compartments) > 0) AS all_compartmented,
         bool_or(cardinality(c.compartments) > 0) AS any_compartmented,
         min(c.classification) AS floor
    FROM cites ci JOIN core."case" c ON c.id = ci.case_id
   GROUP BY ci.document_id),
inter AS (
  SELECT x.document_id, array_agg(x.key ORDER BY x.key) AS keys
    FROM (SELECT ci.document_id, k.key
            FROM cites ci
            JOIN core."case" c ON c.id = ci.case_id
            JOIN per_doc pd ON pd.document_id = ci.document_id
                           AND pd.all_compartmented
            CROSS JOIN LATERAL unnest(c.compartments) AS k(key)
           GROUP BY ci.document_id, k.key
          HAVING count(DISTINCT ci.case_id) = max(pd.cases)) x
   GROUP BY x.document_id),
changed AS (
  UPDATE collect.document d
     SET compartments = coalesce(i.keys, d.compartments),
         classification = greatest(d.classification, pd.floor)
    FROM per_doc pd
    JOIN captured k ON k.id = pd.document_id
    LEFT JOIN inter i ON i.document_id = pd.document_id
   WHERE d.id = pd.document_id
     AND cardinality(d.compartments) = 0
     AND (cardinality(coalesce(i.keys, '{{}}'::text[])) > 0
          OR d.classification < pd.floor)
  RETURNING d.id, d.compartments, d.classification,
            k.classification AS was, pd.cases),
logged AS (
  INSERT INTO audit.event
         (actor_id, actor_kind, action, object_type, object_id, case_id,
          detail)
  SELECT NULL, 'SYSTEM', 'DOCUMENT_LABELS_BACKFILLED', 'document', ch.id,
         NULL,
         jsonb_build_object(
           'compartments', to_jsonb(ch.compartments),
           'classification_was', ch.was,
           'classification', ch.classification,
           'cases', ch.cases,
           'by', '{BY}')
    FROM changed ch
  RETURNING object_id),
left_open AS (
  SELECT count(*) AS n
    FROM per_doc pd LEFT JOIN inter i ON i.document_id = pd.document_id
   WHERE pd.any_compartmented
     AND cardinality(coalesce(i.keys, '{{}}'::text[])) = 0),
summary AS (
  INSERT INTO audit.event
         (actor_id, actor_kind, action, object_type, object_id, case_id,
          detail)
  SELECT NULL, 'SYSTEM', 'DOCUMENT_LABELS_BACKFILL_SUMMARY', 'document',
         NULL, NULL,
         jsonb_build_object(
           'labelled', (SELECT count(*) FROM logged),
           'left_without_compartments', (SELECT n FROM left_open),
           'by', '{BY}')
   WHERE EXISTS (SELECT 1 FROM logged)
  RETURNING 1)
SELECT (SELECT count(*) FROM logged), (SELECT count(*) FROM summary),
       (SELECT n FROM left_open);
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(BACKFILL_SQL)


def downgrade() -> None:
    pass
