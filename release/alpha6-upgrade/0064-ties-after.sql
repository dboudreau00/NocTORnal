-- Alpha 6 upgrade. Run AFTER upgrading to Alpha 6 (Alembic 0064 or
-- later), and hand the list to the analysts.
--
-- Lists every tie whose most recent live confidence correction states a
-- LOWER value than the tie now holds. Those are ties an analyst lowered
-- under Alpha 5.2 that migration 0064 raised back to their strongest live
-- claim: under Alpha 6 a correction cannot hold a tie below a live claim
-- that grades it higher, and the backfill writes no audit event for what
-- it changed (Alpha 6 pre-release check, 2026-09-23). The correction
-- itself, the value it states and its EDGE_UPDATED audit row are kept.
--
-- To lower such a tie again the Alpha 6 way: add a claim at the lower
-- grade (the tie inspector has the control), then retract the claim that
-- grades the tie higher. A tie corroborated at a higher grade AFTER the
-- correction is listed too, and its rise may be deserved, so review each
-- row rather than redoing it blindly. A soft-deleted tie is not drawn.
--
-- Read-only. A tie the analyst lowered and later put back is not listed:
-- only the most recent correction counts, in the order of the EDGE_UPDATED
-- audit rows the corrections wrote (audit.event.seq), not recorded_at
-- alone, because a database clock can step backwards and recorded_at
-- follows it (the same check measured a 12.8 s step under WSL that put
-- two corrections out of order).
SELECT c.code AS case_code, e.id AS edge_id, e.confidence AS tie_now,
       lc.stated AS last_correction, lc.recorded_at AS corrected_at,
       u.email AS corrected_by, e.deleted_at IS NOT NULL AS soft_deleted
  FROM core.edge e
  JOIN core."case" c ON c.id = e.case_id
  CROSS JOIN LATERAL (
       SELECT (a.claim_value ->> 'confidence')::core.analytic_confidence AS stated,
              a.recorded_at, a.created_by
         FROM core.assertion a
         LEFT JOIN audit.event ev
                ON ev.action = 'EDGE_UPDATED' AND ev.object_type = 'edge'
               AND ev.object_id = a.edge_id AND ev.occurred_at = a.recorded_at
        WHERE a.edge_id = e.id
          AND a.retracted_at IS NULL
          AND a.superseded_at IS NULL
          AND a.claim_value ->> 'confidence' IN ('LOW', 'MODERATE', 'HIGH')
        ORDER BY ev.seq DESC NULLS LAST, a.recorded_at DESC, a.id DESC
        LIMIT 1) lc
  LEFT JOIN iam.app_user u ON u.id = lc.created_by
 WHERE lc.stated < e.confidence
 ORDER BY c.code, e.id;
