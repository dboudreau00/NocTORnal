-- Alpha 6 upgrade. Run BEFORE upgrading an Alpha 5.2 database (Alembic
-- 0059, or anything short of 0064), and keep the output with the upgrade
-- record.
--
-- Lists every tie that migration 0064's backfill will change:
--   now_value        the confidence the tie holds today;
--   alpha6_value     the confidence it will hold after 0064;
--   last_correction  the value the analyst's most recent live confidence
--                    correction states, if any;
--   analyst_lowered  true when today's value was set by an analyst's
--                    correction and the backfill will RAISE it: under
--                    Alpha 6 a correction cannot hold a tie below a live
--                    claim that grades it higher;
--   soft_deleted     the tie was deleted and is not drawn.
--
-- Why this exists: the backfill writes no audit event for the ties it
-- changes (Alpha 6 pre-release check, 2026-09-23: 265 ties changed on a
-- populated Alpha 5.2 database and the audit log gained no edge event),
-- so this output is the only record of the values they held before.
--
-- Read-only, and plain SQL: it calls no function that 0064 installs, so it
-- runs on the Alpha 5.2 schema. alpha6_value is 0064's rule
-- (core.tie_confidence) restated: the highest grade among the tie's live
-- claims about the tie, and LOW when none grades it.
-- test_alpha6_upgrade_ties_pg.py holds the two equal.
--
-- Corrections are put in order by the EDGE_UPDATED audit row each one
-- wrote (audit.event.seq), not by recorded_at alone: a database clock can
-- step backwards, and recorded_at follows it (the same check measured a
-- 12.8 s step under WSL that put two corrections out of order).
WITH live AS (
  SELECT a.id, a.edge_id, a.recorded_at,
         CASE WHEN a.claim_value ->> 'confidence' IN ('LOW', 'MODERATE', 'HIGH')
              THEN (a.claim_value ->> 'confidence')::core.analytic_confidence
              WHEN a.claim_path IS NULL
                   AND coalesce(jsonb_typeof(a.claim_value), 'null') = 'null'
              THEN a.confidence END AS grade,
         coalesce(a.claim_value ->> 'confidence' IN ('LOW', 'MODERATE', 'HIGH'),
                  false) AS is_correction
    FROM core.assertion a
   WHERE a.edge_id IS NOT NULL
     AND a.retracted_at IS NULL
     AND a.superseded_at IS NULL),
corr AS (
  SELECT l.edge_id, l.grade,
         row_number() OVER (PARTITION BY l.edge_id
                            ORDER BY ev.seq DESC NULLS LAST,
                                     l.recorded_at DESC, l.id DESC) AS nth
    FROM live l
    LEFT JOIN audit.event ev
           ON ev.action = 'EDGE_UPDATED' AND ev.object_type = 'edge'
          AND ev.object_id = l.edge_id AND ev.occurred_at = l.recorded_at
   WHERE l.is_correction),
tie AS (
  SELECT e.id, e.case_id, e.confidence AS now_value, e.deleted_at,
         coalesce((SELECT max(l.grade) FROM live l WHERE l.edge_id = e.id),
                  'LOW') AS alpha6_value,
         (SELECT c.grade FROM corr c WHERE c.edge_id = e.id AND c.nth = 1)
           AS last_correction,
         EXISTS (SELECT 1 FROM corr c
                  WHERE c.edge_id = e.id AND c.grade = e.confidence)
           AS held_by_a_correction
    FROM core.edge e)
SELECT c.code AS case_code, t.id AS edge_id, t.now_value, t.alpha6_value,
       t.last_correction,
       (t.held_by_a_correction AND t.alpha6_value > t.now_value)
         AS analyst_lowered,
       t.deleted_at IS NOT NULL AS soft_deleted
  FROM tie t
  JOIN core."case" c ON c.id = t.case_id
 WHERE t.now_value IS DISTINCT FROM t.alpha6_value
 ORDER BY analyst_lowered DESC, c.code, t.id;
