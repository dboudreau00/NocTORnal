"""The facts of an ingest record and of a batch's cases, read as the
definer (F51, 2026-10-02).

## Why

0154 puts `ingest.record` and `ingest.dead_letter` under row-level
security. Three things the ingest routes decide on must not read as
absence for a caller the policy hides a row from:

- a record's own case and labels, which `routers/ingest._own_record`
  hands to the gate. Read through the policy, a record above the caller
  in a case they work would be "no such record" with no AUTHZ_DENIED row,
  where the gate refuses it and audits the refusal (decision 141: the gate
  reads facts, content reads go through policy);
- the cases a dead letter's batch fed. A dead letter carries no case of
  its own, so its case is any case a record of its batch went to. Read
  through the record policy, a batch whose records sit above the reader
  would read as feeding nothing: the listing would show another case's
  feed failures to the operator as unattached, and the replay would take
  the batch's own case for a different one. That is the anti-join trap
  (decision 146) turned into a leak;
- whether a dead letter is visible at all, which is 0154's policy on
  `ingest.dead_letter` and must ask the same question.

## What each answers

- `iam.ingest_record_facts(id)`: a record's case, classification and
  compartments, whatever the caller may see, as `iam.element_facts` does
  for the graph. One primary-key probe.
- `iam.ingest_batch_reach(batch, cases)`: of the cases the batch fed, those
  in `cases` (NULL: every one) that the bound caller may read
  (`iam.rls_cases()`), and whether the batch fed NO case at all, which is
  answered true only to a holder of `ingest.manage` (the operator, whose
  quarantine it is) or an exempt caller. The listing and the replay ask it.
- `iam.ingest_dead_letter_visible(batch, classification, cases, clearance,
  ceilings, manages)`: 0154's one definer predicate. Its last four
  arguments are the caller's own initplans in the policy; a batch that fed
  no case is the operator's within their case-less ceiling, and one that
  fed a case is visible through any of its cases the caller may read, at
  the label that case allows.

## Why the arguments cannot widen anything

Every function here is executable by the request role, so a statement
injected into a request can call each with arguments of its choosing. The
two that take a caller's reach as arguments use it only to say no quickly:
every yes is confirmed against the bound actor (`iam.rls_cases()`,
`iam.rls_clearance()`, `iam.rls_ceilings()`, `iam.rls_holds_global()`)
before it is returned, so a call with other cases, another clearance or
another verb learns nothing about a batch the caller could not already
read. The confirmation runs only on a row that is visible, and it reads the
actor's reach afresh each time (three definer reads through a case, two in
quarantine), because a function called per row cannot keep it: a dead
letter the caller may not see costs the walk below and an array test. 0154
states what that measured to. An exempt caller (the owner, the system role)
is answered without confirmation, as row security answers it.

`iam.ingest_record_facts` is a fact of the gate's kind, like
`iam.element_facts`: it names the case and labels of a record whose id the
caller already holds.

## The walk

The cases a batch fed are read as a loose index scan over 0152's
`record_batch_case_idx (batch_id, case_id)`: the first case of the batch,
then the next one above it, one probe per distinct case, never one row per
record. A NULL batch fed nothing.

Definer, with `SET search_path = pg_catalog, pg_temp` and every name fully
qualified, as 0111, 0117 and 0127. The two that read the caller's reach
are PARALLEL RESTRICTED, as `iam.rls_caller_exempt` is.

## Downgrade

Drops the three functions. 0154, whose policy needs one of them, goes down
first.
"""
from alembic import op

revision = "0153"
down_revision = "0152"
branch_labels = None
depends_on = None

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

#: The functions this revision creates, by signature, in creation order.
FUNCTIONS = (
    "iam.ingest_record_facts(uuid)",
    "iam.ingest_batch_reach(uuid, uuid[])",
    "iam.ingest_dead_letter_visible(uuid, core.tlp, uuid[], core.tlp, jsonb, boolean)",
)

#: Every case a batch's records went to, ascending, as a loose index scan.
#: Frozen text, used by both functions below.
_FED = """ARRAY(
    WITH RECURSIVE walk(case_id) AS (
      (SELECT r.case_id FROM ingest.record r
        WHERE r.batch_id = p_batch AND r.case_id IS NOT NULL
        ORDER BY r.case_id LIMIT 1)
      UNION ALL
      SELECT (SELECT r.case_id FROM ingest.record r
                WHERE r.batch_id = p_batch AND r.case_id > w.case_id
                ORDER BY r.case_id LIMIT 1)
        FROM walk w WHERE w.case_id IS NOT NULL)
    SELECT w.case_id FROM walk w WHERE w.case_id IS NOT NULL)"""

RECORD_FACTS = f"""
CREATE FUNCTION iam.ingest_record_facts(p_id uuid)
  RETURNS TABLE (case_id uuid, classification core.tlp, compartments text[])
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT r.case_id, r.classification, r.compartments
    FROM ingest.record r
   WHERE r.id = p_id
$$;
"""

BATCH_REACH = f"""
CREATE FUNCTION iam.ingest_batch_reach(p_batch uuid, p_cases uuid[])
  RETURNS TABLE (cases uuid[], unattached boolean)
  LANGUAGE plpgsql STABLE PARALLEL RESTRICTED {_DEFINER}
AS $$
DECLARE
  v_fed uuid[] := {_FED};
  v_seen uuid[];
  v_mine uuid[];
BEGIN
  IF pg_catalog.cardinality(v_fed) = 0 THEN
    RETURN QUERY SELECT '{{}}'::uuid[],
                        iam.rls_caller_exempt() OR iam.rls_holds_global('ingest.manage');
    RETURN;
  END IF;
  v_seen := ARRAY(SELECT f.c FROM pg_catalog.unnest(v_fed) AS f(c)
                   WHERE p_cases IS NULL OR f.c = ANY (p_cases));
  IF pg_catalog.cardinality(v_seen) > 0 AND NOT iam.rls_caller_exempt() THEN
    v_mine := coalesce(iam.rls_cases(), '{{}}'::uuid[]);
    v_seen := ARRAY(SELECT f.c FROM pg_catalog.unnest(v_seen) AS f(c)
                     WHERE f.c = ANY (v_mine));
  END IF;
  RETURN QUERY SELECT v_seen, false;
END
$$;

COMMENT ON FUNCTION iam.ingest_batch_reach(uuid, uuid[]) IS
  'Of the cases a batch fed, those in the argument (NULL: all) the bound caller '
  'may read, and whether it fed none, said only to an ingest.manage holder '
  '(F51, 2026-10-02).';
"""

DEAD_LETTER_VISIBLE = f"""
CREATE FUNCTION iam.ingest_dead_letter_visible(
    p_batch uuid, p_classification core.tlp, p_cases uuid[],
    p_clearance core.tlp, p_ceilings jsonb, p_manages boolean)
  RETURNS boolean
  LANGUAGE plpgsql STABLE PARALLEL RESTRICTED {_DEFINER}
AS $$
DECLARE
  v_fed uuid[] := {_FED};
  v_cases uuid[];
  v_clr core.tlp;
  v_ceil jsonb;
BEGIN
  IF pg_catalog.cardinality(v_fed) = 0 THEN
    -- A batch that fed no case: the operator's, at their case-less ceiling.
    IF NOT coalesce(p_manages, false)
       OR NOT coalesce(p_classification <= p_clearance, false) THEN
      RETURN false;
    END IF;
    RETURN iam.rls_caller_exempt()
           OR (iam.rls_holds_global('ingest.manage')
               AND coalesce(p_classification <= iam.rls_clearance(), false));
  END IF;
  -- The caller's own initplans say no to most rows, cheaply.
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.unnest(v_fed) AS f(c)
       WHERE f.c = ANY (p_cases)
         AND (p_classification <= p_clearance
              OR p_classification <= iam.rls_ceiling_for(p_ceilings, f.c))) THEN
    RETURN false;
  END IF;
  IF iam.rls_caller_exempt() THEN
    RETURN true;
  END IF;
  -- A yes is confirmed against the bound actor, never taken from arguments.
  v_cases := coalesce(iam.rls_cases(), '{{}}'::uuid[]);
  v_clr := iam.rls_clearance();
  v_ceil := coalesce(iam.rls_ceilings(), '{{}}'::jsonb);
  RETURN EXISTS (
    SELECT 1 FROM pg_catalog.unnest(v_fed) AS f(c)
     WHERE f.c = ANY (v_cases)
       AND (p_classification <= v_clr
            OR p_classification <= iam.rls_ceiling_for(v_ceil, f.c)));
END
$$;

COMMENT ON FUNCTION iam.ingest_dead_letter_visible(uuid, core.tlp, uuid[], core.tlp, jsonb, boolean) IS
  'The one predicate of ingest.dead_letter''s policy (F51, 2026-10-02): visible '
  'through a case its batch fed, at that case''s ceiling, or, for a batch that '
  'fed none, to the operator at their case-less ceiling. Arguments only narrow.';
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(RECORD_FACTS)
    run(BATCH_REACH)
    run(DEAD_LETTER_VISIBLE)


def downgrade() -> None:
    run("\n".join(f"DROP FUNCTION {fn};" for fn in reversed(FUNCTIONS)))
