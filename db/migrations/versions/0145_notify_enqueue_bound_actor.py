"""notify.enqueue answers only a bound caller, as itself (rls-8, 2026-10-03).

## Why

0125 made `notify.enqueue` the one writer of a notification, as the
definer, inside the caller's transaction so a notice commits or rolls back
with the act it reports. It checked the recipient and nothing about the
caller: a request-role connection need not be bound at all, `p_actor` was
stored as the notice's actor unverified, and the delivery plan was written
as given. A statement injected into any request-role connection, the
unauthenticated ones included, could therefore raise in-app and mail
notices to any active account signed as any other account (a phishing
"action needed" from the case owner), and forge the delivery ledger with
SENT rows at any time.

## What

The function keeps its signature, its four steps and its atomic place in
the caller's transaction. For a caller row security does not exempt (the
owner and the system role stay trusted, as in 0112):

- the connection must be bound to a live session (`iam.rls_actor()`);
- `p_actor` must be NULL or that bound account;
- every planned delivery must be PENDING or SUPPRESSED, or SENT for the
  IN_APP copy alone, and a `blocked` alternative must be SUPPRESSED;
- a SENT row's `sent_at` is the database's clock, never the caller's, and
  no other row carries one.

Each refusal is 42501 with a sentence saying which rule. EXECUTE is taken
from PUBLIC; the two runtime roles keep the grants they already hold
explicitly.

## Downgrade

Restores 0125's function text and the PUBLIC grant.
"""
from alembic import op

revision = "0145"
down_revision = "0144"
branch_labels = None
depends_on = None

SIGNATURE = ("notify.enqueue(uuid, uuid, text, smallint, text, text, text, core.tlp, "
             "text[], text, uuid, uuid, uuid, jsonb, jsonb)")

#: Frozen text: a later revision that changes the function restates it.
UPGRADE_SQL = """
CREATE OR REPLACE FUNCTION notify.enqueue(
    p_recipient uuid, p_case uuid, p_kind text, p_priority smallint,
    p_subject text, p_summary text, p_body text,
    p_classification core.tlp, p_compartments text[],
    p_object_type text, p_object_id uuid, p_actor uuid, p_event uuid,
    p_deliveries jsonb, p_open jsonb)
  RETURNS TABLE (outcome text, raised_id uuid, raised_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_labels text[] := coalesce(p_compartments, '{}'::text[]);
  v_exempt boolean := iam.rls_caller_exempt();
  v_bound uuid;
  v_clr core.tlp;
  v_held text[];
  v_cases uuid[];
  v_ceil jsonb;
  v_id uuid;
  v_at timestamptz;
BEGIN
  IF NOT v_exempt THEN
    v_bound := iam.rls_actor();
    IF v_bound IS NULL THEN
      RAISE EXCEPTION 'notify.enqueue: the caller is bound to no session'
        USING ERRCODE = '42501';
    END IF;
    IF p_actor IS NOT NULL AND p_actor IS DISTINCT FROM v_bound THEN
      RAISE EXCEPTION 'notify.enqueue: the actor of a notice is the account that raises it'
        USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.jsonb_to_recordset(coalesce(p_deliveries, '[]'::jsonb))
               AS x(channel text, state text, blocked jsonb)
         WHERE NOT coalesce(x.state IN ('PENDING', 'SUPPRESSED')
                            OR (x.state = 'SENT' AND x.channel = 'IN_APP'), false)
            OR (x.blocked IS NOT NULL
                AND (x.blocked ->> 'state') IS DISTINCT FROM 'SUPPRESSED')) THEN
      RAISE EXCEPTION 'notify.enqueue: a delivery is planned PENDING or SUPPRESSED, or SENT for the in-app copy alone'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF p_open IS NOT NULL THEN
    IF NOT v_exempt THEN
      v_clr := iam.rls_clearance();
      v_held := coalesce(iam.rls_compartments(), '{}'::text[]);
      v_cases := coalesce(iam.rls_cases(), '{}'::uuid[]);
      v_ceil := coalesce(iam.rls_ceilings(), '{}'::jsonb);
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
           AND v_labels OPERATOR(pg_catalog.<@) coalesce(u.compartments, '{}'::text[]))
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
         CASE WHEN k.kept_out THEN NULL
              WHEN v_exempt THEN x.sent_at
              WHEN x.state = 'SENT' THEN pg_catalog.now()
              ELSE NULL END,
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

REVOKE ALL ON FUNCTION notify.enqueue(uuid, uuid, text, smallint, text, text, text,
                                      core.tlp, text[], text, uuid, uuid, uuid, jsonb, jsonb)
  FROM PUBLIC;
"""

DOWNGRADE_SQL = """
CREATE OR REPLACE FUNCTION notify.enqueue(
    p_recipient uuid, p_case uuid, p_kind text, p_priority smallint,
    p_subject text, p_summary text, p_body text,
    p_classification core.tlp, p_compartments text[],
    p_object_type text, p_object_id uuid, p_actor uuid, p_event uuid,
    p_deliveries jsonb, p_open jsonb)
  RETURNS TABLE (outcome text, raised_id uuid, raised_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_labels text[] := coalesce(p_compartments, '{}'::text[]);
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
      v_held := coalesce(iam.rls_compartments(), '{}'::text[]);
      v_cases := coalesce(iam.rls_cases(), '{}'::uuid[]);
      v_ceil := coalesce(iam.rls_ceilings(), '{}'::jsonb);
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
           AND v_labels OPERATOR(pg_catalog.<@) coalesce(u.compartments, '{}'::text[]))
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

GRANT EXECUTE ON FUNCTION notify.enqueue(uuid, uuid, text, smallint, text, text, text,
                                         core.tlp, text[], text, uuid, uuid, uuid, jsonb, jsonb)
  TO PUBLIC;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
