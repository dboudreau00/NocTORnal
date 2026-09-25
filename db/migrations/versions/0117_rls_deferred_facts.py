"""Facts and searches for the tables row-level security takes on next (S1).

## What this adds

0111 gave the gate `iam.element_facts(kind, id)`: the case and labels of
a node, edge, exhibit or claim, read as the definer so that a router's
pre-read, or a label join feeding a decision, still sees an element the
caller's own view would hide. The tables 0118 onwards put under policy
need the same, so the function gains one static branch per new kind:

- `document`: a collected document's classification and compartments.
  It has no case (a document hangs off a source that any number of cases
  cite), so `case_id` is NULL. Triage's proposal labels join through it:
  a proposal is read at the strictest of its own label and its source
  material's, and a LEFT JOIN to a document the reader cannot see would
  read as "no document" and LOWER that label, which is the anti-join trap
  (docs/20, the gate reads facts) turned into a leak.
- `sample`: a Lab sample's case and its OWN labels (the caller composes
  them with the case's), for the lookup ledger, which reads a lookup at
  the strictest of its own label, its entity's, its sample's and its
  case's.
- `conversation`: a captured conversation's case and labels, for the
  comms routes that must find a conversation's case before the gate
  decides (`_own_conversation`).
- `proposal_block`: the labels of the contact block a proposal was parsed
  from (the entry naming the proposal points back at it), Triage's third
  source leg beside the document's; `id` is the PROPOSAL's.

The branches stay a fixed whitelist of static SQL; an unknown kind still
raises.

`iam.rls_cases_in_reach()` is the Lab's case term. Lab analysts hold no
case assignment (the Lab is global under `sample.read`), so a sample is
read at its own labels composed with its case's, against the reader's
CASE-LESS ceiling (`samples.lab_gate`), never at whether the reader is on
the case. As a policy it is one initplan: a JSON object whose keys are the
cases whose classification is within the bound user's case-less ceiling
and whose compartments they hold, tested per row with `?`, a key lookup.
Unbound, it is empty.

`iam.search_document_hits(...)` is the cross-case document search
(`SearchService._document_rows`) moved into SQL. Under a policy, full
text (`@@`) and trigram (`ILIKE`) are not leakproof, so a search as the
request role cannot use the GIN indexes and scans every collected
document. As the definer it reads the table unfiltered and applies every
predicate the application applies (unpurged; the document's label and its
source's within the caller's ceiling; its compartments held) and, for a
caller row security does not exempt, the bound actor's own ceiling and
compartments on top: a caller argument can only narrow what the actor
may read, never widen it, and an unbound request connection gets nothing.
The limit is clamped to 200, the search routes' own ceiling.

Both are SECURITY DEFINER with `SET search_path = pg_catalog, pg_temp`
and fully qualified names (`public.similarity` is pg_trgm's).

## Downgrade

Restores 0111's `iam.element_facts` exactly and drops the other two.
"""
from alembic import op

revision = "0117"
down_revision = "0116"
branch_labels = None
depends_on = None

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

#: 0111's definition, frozen, for the downgrade.
PRIOR_ELEMENT_FACTS = f"""
CREATE OR REPLACE FUNCTION iam.element_facts(p_kind text, p_id uuid)
  RETURNS TABLE (case_id uuid, classification core.tlp, compartments text[])
  LANGUAGE plpgsql STABLE PARALLEL SAFE {_DEFINER}
AS $$
BEGIN
  IF p_kind = 'node' THEN
    RETURN QUERY SELECT n.case_id, n.classification, n.compartments
                   FROM core.node n WHERE n.id = p_id;
  ELSIF p_kind = 'edge' THEN
    RETURN QUERY SELECT e.case_id, e.classification, e.compartments
                   FROM core.edge e WHERE e.id = p_id;
  ELSIF p_kind = 'evidence' THEN
    RETURN QUERY SELECT v.case_id, v.classification, v.compartments
                   FROM core.evidence v WHERE v.id = p_id;
  ELSIF p_kind = 'assertion' THEN
    RETURN QUERY
      SELECT a.case_id, coalesce(n.classification, e.classification),
             coalesce(n.compartments, e.compartments)
        FROM core.assertion a
        LEFT JOIN core.node n ON n.id = a.node_id
        LEFT JOIN core.edge e ON e.id = a.edge_id
       WHERE a.id = p_id;
  ELSE
    RAISE EXCEPTION 'iam.element_facts: unknown kind %', p_kind
      USING ERRCODE = '22023';
  END IF;
END
$$;
"""

ELEMENT_FACTS = f"""
CREATE OR REPLACE FUNCTION iam.element_facts(p_kind text, p_id uuid)
  RETURNS TABLE (case_id uuid, classification core.tlp, compartments text[])
  LANGUAGE plpgsql STABLE PARALLEL SAFE {_DEFINER}
AS $$
BEGIN
  IF p_kind = 'node' THEN
    RETURN QUERY SELECT n.case_id, n.classification, n.compartments
                   FROM core.node n WHERE n.id = p_id;
  ELSIF p_kind = 'edge' THEN
    RETURN QUERY SELECT e.case_id, e.classification, e.compartments
                   FROM core.edge e WHERE e.id = p_id;
  ELSIF p_kind = 'evidence' THEN
    RETURN QUERY SELECT v.case_id, v.classification, v.compartments
                   FROM core.evidence v WHERE v.id = p_id;
  ELSIF p_kind = 'assertion' THEN
    RETURN QUERY
      SELECT a.case_id, coalesce(n.classification, e.classification),
             coalesce(n.compartments, e.compartments)
        FROM core.assertion a
        LEFT JOIN core.node n ON n.id = a.node_id
        LEFT JOIN core.edge e ON e.id = a.edge_id
       WHERE a.id = p_id;
  ELSIF p_kind = 'document' THEN
    RETURN QUERY SELECT NULL::uuid, d.classification, d.compartments
                   FROM collect.document d WHERE d.id = p_id;
  ELSIF p_kind = 'sample' THEN
    RETURN QUERY SELECT s.case_id, s.classification, s.compartments
                   FROM lab.sample s WHERE s.id = p_id;
  ELSIF p_kind = 'conversation' THEN
    RETURN QUERY SELECT c.case_id, c.classification, c.compartments
                   FROM comms.conversation c WHERE c.id = p_id;
  ELSIF p_kind = 'proposal_block' THEN
    RETURN QUERY SELECT cb.case_id, cb.classification, cb.compartments
                   FROM comms.contact_block_entry e
                   JOIN comms.contact_block cb ON cb.id = e.block_id
                  WHERE e.proposal_id = p_id
                  LIMIT 1;
  ELSE
    RAISE EXCEPTION 'iam.element_facts: unknown kind %', p_kind
      USING ERRCODE = '22023';
  END IF;
END
$$;
"""

CASES_IN_REACH = f"""
CREATE FUNCTION iam.rls_cases_in_reach() RETURNS jsonb
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT coalesce(pg_catalog.jsonb_object_agg(c.id::text, true), '{{}}'::jsonb)
    FROM core."case" c
   WHERE c.classification <= iam.rls_clearance()
     AND coalesce(c.compartments, '{{}}'::text[])
         OPERATOR(pg_catalog.<@) iam.rls_compartments()
$$;
"""

#: The most rows one search returns (the search routes cap `limit` at 200).
SEARCH_LIMIT = 200

SEARCH_DOCUMENT_HITS = f"""
CREATE FUNCTION iam.search_document_hits(
    p_tsq text, p_q text, p_pattern text, p_clearance core.tlp,
    p_compartments text[], p_limit integer)
  RETURNS TABLE (id uuid, label text, excerpt text, source_name text,
                 posted_at timestamptz, external_url text, rank float8,
                 total bigint, classification text, author_handle text,
                 compartments text[])
  LANGUAGE sql STABLE PARALLEL RESTRICTED {_DEFINER}
AS $$
  WITH me AS (
    SELECT iam.rls_caller_exempt() AS exempt,
           iam.rls_clearance() AS clr,
           iam.rls_compartments() AS held
  )
  SELECT h.id, h.label, h.excerpt, h.source_name, h.posted_at,
         h.external_url, h.rank, pg_catalog.count(*) OVER () AS total,
         h.classification, h.author_handle, h.compartments
    FROM (
      SELECT d.id,
             coalesce(nullif(d.title, ''), pg_catalog.left(d.body_text, 80)) AS label,
             pg_catalog.left(d.body_text, 240) AS excerpt, s.name AS source_name,
             d.posted_at, d.external_url,
             d.classification::text AS classification, d.author_handle,
             d.compartments,
             LEAST(0.99::float8, GREATEST(
               coalesce(pg_catalog.ts_rank(d.search_tsv,
                        pg_catalog.to_tsquery('simple', p_tsq)), 0)::float8,
               coalesce(public.similarity(d.author_handle, p_q), 0)::float8))
               AS rank
        FROM collect.document d
        JOIN collect.source s ON s.id = d.source_id
        CROSS JOIN me
       WHERE d.purged_at IS NULL
         AND d.classification <= p_clearance
         AND s.classification <= p_clearance
         AND d.compartments OPERATOR(pg_catalog.<@) p_compartments
         AND (me.exempt
              OR (me.clr IS NOT NULL
                  AND d.classification <= me.clr
                  AND s.classification <= me.clr
                  AND d.compartments OPERATOR(pg_catalog.<@) me.held))
         AND (d.search_tsv OPERATOR(pg_catalog.@@) pg_catalog.to_tsquery('simple', p_tsq)
              OR d.author_handle OPERATOR(pg_catalog.~~*) p_pattern)
    ) h
   ORDER BY h.rank DESC, h.id
   LIMIT LEAST(greatest(p_limit, 0), {SEARCH_LIMIT})
$$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(ELEMENT_FACTS)
    run(SEARCH_DOCUMENT_HITS)
    run(CASES_IN_REACH)


def downgrade() -> None:
    run("DROP FUNCTION iam.rls_cases_in_reach();")
    run("DROP FUNCTION iam.search_document_hits(text, text, text, core.tlp, "
        "text[], integer);")
    run(PRIOR_ELEMENT_FACTS)
