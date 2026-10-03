"""One way to raise a notification for someone else (F51, 2026-10-02).

## Why a function

A notification is written for SOMEONE ELSE: a merge tells the case owner, a
two-person request tells every signer, an integrity alarm tells the owner
of the exhibit's case. Each is raised inside the transaction that does the
thing it reports (`NotificationService.notify`), so the act and the notice
commit or roll back together. 0126 puts `notify.notification` under a
policy that shows a row to its recipient alone, and as the request role
each part of the old write then fails: the INSERT ... RETURNING of another
person's row is refused, the reads that coalesce (one open alarm per
exhibit, one alert per officer per hour) see only the caller's own rows and
stop coalescing, and the deliveries go with the row.

`notify.enqueue(...)` is that write as the definer, called inside the
caller's transaction, so the atomicity every caller relies on stays. It is
the only writer of a notification in the application, and it does four
things in this order:

1. Coalescing, when asked (`p_open`): write nothing and answer COALESCED
   when an open notice of the same kind already covers this one (the same
   object, the same case, this recipient's or anyone's, within a window,
   unread or unacknowledged). For a caller that row security filters, a
   notice counts only within the caller's own reach: in a case it may
   read, at a classification within its ceiling for that case, with
   compartments it holds; a case-less one within its case-less ceiling.
   The answer never tells a caller about a notice it could not have read
   had the notice been its own.
2. Eligibility (suppression 2, docs/07): the recipient is an active
   account whose clearance dominates the notice's classification and whose
   compartments contain its compartments, and for a case notice holds a
   live assignment to that case. Otherwise SUPPRESSED, and nothing is
   written. The check is the recipient's, whoever the caller is.
3. The row, and its deliveries from the plan the caller computed. The
   recipient's preferences, quiet hours and digest stay Python's
   (`NotificationService._plan`). A JIRA delivery may carry the row it
   becomes when the case's owner keeps the case out of Jira: the veto
   (`notify.case_route_block`) is read here, as the definer, because the
   caller may not be on the case (a Lab analyst's detonation request, an
   ingest operator's selector hit) and would read no veto at all.
4. The answer: (outcome, id, created_at). The row itself is never handed
   back. The caller wrote it and holds every field already, and a RETURNING
   of the recipient's row would be a read the policy refuses.

Whoever calls it, the function writes nothing a plain INSERT could not
before 0126, and less: never a row above its recipient, never one for an
inactive or unassigned recipient.

Definer, with `SET search_path = pg_catalog, pg_temp` and every name fully
qualified, as 0111 and 0117.

## Downgrade

Drops the function. Run after 0126's downgrade (the chain does), and take
the code back with the schema: this release's code raises every notice
through the function.
"""
from alembic import op

revision = "0125"
down_revision = "0124"
branch_labels = None
depends_on = None

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

SIGNATURE = ("notify.enqueue(uuid, uuid, text, smallint, text, text, text, core.tlp, "
             "text[], text, uuid, uuid, uuid, jsonb, jsonb)")

#: Frozen text: a later revision that changes the function restates it.
UPGRADE_SQL = f"""
CREATE FUNCTION notify.enqueue(
    p_recipient uuid, p_case uuid, p_kind text, p_priority smallint,
    p_subject text, p_summary text, p_body text,
    p_classification core.tlp, p_compartments text[],
    p_object_type text, p_object_id uuid, p_actor uuid, p_event uuid,
    p_deliveries jsonb, p_open jsonb)
  RETURNS TABLE (outcome text, raised_id uuid, raised_at timestamptz)
  LANGUAGE plpgsql VOLATILE {_DEFINER}
AS $$
DECLARE
  v_labels text[] := coalesce(p_compartments, '{{}}'::text[]);
  v_exempt boolean;
  v_clr core.tlp;
  v_held text[];
  v_cases uuid[];
  v_ceil jsonb;
  v_id uuid;
  v_at timestamptz;
BEGIN
  IF p_open IS NOT NULL THEN
    v_exempt := iam.rls_caller_exempt();
    IF NOT v_exempt THEN
      v_clr := iam.rls_clearance();
      v_held := coalesce(iam.rls_compartments(), '{{}}'::text[]);
      v_cases := coalesce(iam.rls_cases(), '{{}}'::uuid[]);
      v_ceil := coalesce(iam.rls_ceilings(), '{{}}'::jsonb);
    END IF;
    IF EXISTS (
        SELECT 1 FROM notify.notification n
         WHERE n.kind = p_kind
           AND (coalesce((p_open ->> 'anyone')::boolean, false)
                OR n.recipient_id = p_recipient)
           AND (NOT coalesce((p_open ->> 'object')::boolean, false)
                OR (n.object_type IS NOT DISTINCT FROM p_object_type
                    AND n.object_id IS NOT DISTINCT FROM p_object_id))
           AND (NOT coalesce((p_open ->> 'case')::boolean, false)
                OR n.case_id IS NOT DISTINCT FROM p_case)
           AND (p_open ->> 'within' IS NULL
                OR n.created_at > pg_catalog.now() - (p_open ->> 'within')::interval)
           AND CASE WHEN coalesce((p_open ->> 'unread')::boolean, false)
                    THEN n.read_at IS NULL ELSE n.acknowledged_at IS NULL END
           AND (v_exempt
                OR ((n.case_id IS NULL OR n.case_id = ANY (v_cases))
                    AND (n.classification <= v_clr
                         OR n.classification <= iam.rls_ceiling_for(v_ceil, n.case_id))
                    AND n.compartments OPERATOR(pg_catalog.<@) v_held))) THEN
      RETURN QUERY SELECT 'COALESCED'::text, NULL::uuid, NULL::timestamptz;
      RETURN;
    END IF;
  END IF;

  IF NOT EXISTS (
        SELECT 1 FROM iam.app_user u
         WHERE u.id = p_recipient AND u.is_active
           AND p_classification <= u.tlp_clearance
           AND v_labels OPERATOR(pg_catalog.<@) coalesce(u.compartments, '{{}}'::text[]))
     OR (p_case IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM iam.case_assignment a
         WHERE a.case_id = p_case AND a.user_id = p_recipient
           AND (a.expires_at IS NULL OR a.expires_at > pg_catalog.now()))) THEN
    RETURN QUERY SELECT 'SUPPRESSED'::text, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;

  INSERT INTO notify.notification
         (recipient_id, case_id, kind, priority, subject, summary, body,
          classification, compartments, object_type, object_id, actor_id, event_id)
  VALUES (p_recipient, p_case, p_kind, p_priority, p_subject, p_summary, p_body,
          p_classification, v_labels, p_object_type, p_object_id, p_actor,
          coalesce(p_event, pg_catalog.gen_random_uuid()))
  RETURNING id, created_at INTO v_id, v_at;

  INSERT INTO notify.delivery
         (notification_id, channel, state, deliver_after, sent_at, detail, cause)
  SELECT v_id, x.channel,
         CASE WHEN k.kept_out THEN x.blocked ->> 'state' ELSE x.state END,
         coalesce(x.deliver_after, pg_catalog.now()),
         CASE WHEN k.kept_out THEN NULL ELSE x.sent_at END,
         CASE WHEN k.kept_out THEN x.blocked ->> 'detail' ELSE x.detail END,
         CASE WHEN k.kept_out THEN x.blocked ->> 'cause' ELSE x.cause END
    FROM pg_catalog.jsonb_to_recordset(coalesce(p_deliveries, '[]'::jsonb))
         AS x(channel text, state text, deliver_after timestamptz,
              sent_at timestamptz, detail text, cause text, blocked jsonb)
   CROSS JOIN LATERAL (
         SELECT x.blocked IS NOT NULL AND p_case IS NOT NULL AND EXISTS (
                  SELECT 1 FROM notify.case_route_block r
                   WHERE r.case_id = p_case AND r.channel = x.channel) AS kept_out) k
  ON CONFLICT (notification_id, channel) DO NOTHING;

  RETURN QUERY SELECT 'WRITTEN'::text, v_id, v_at;
END
$$;

COMMENT ON FUNCTION {SIGNATURE} IS
  'The one writer of a notification (F51, 2026-10-02): coalescing within the '
  'caller''s reach, then the recipient''s eligibility, then the row and its '
  'deliveries, in the caller''s transaction. Answers WRITTEN, SUPPRESSED or '
  'COALESCED with the new id, never the row.';
"""

DOWNGRADE_SQL = f"DROP FUNCTION {SIGNATURE};"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
