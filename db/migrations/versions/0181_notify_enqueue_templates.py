"""A request raises only the notices the product writes, in its own words
(`notify.enqueue` text, Beta 1.1, 2026-10-08).

## Why

0145 made `notify.enqueue` answer a request-role caller only when it is
bound to a live session, as itself, with an honest delivery plan. It did
not limit what that caller may say: a statement injected into a request
could raise any kind, at any priority, with any subject and summary, to any
recipient the function admits, and the summary and subject are what leave
the building, by mail, webhook and Jira. A bound account could send its
colleagues a priority-1 "action needed" in words of its own choosing, or
with no actor named at all.

## What

For a caller row security does not exempt (the owner and the system role
stay trusted, as in 0112 and 0145), on top of 0145's rules:

- the notice names the account that raises it: `p_actor` is the bound
  account, never NULL (every request-role producer passes it);
- the kind is one a request raises (`REQUEST_KINDS`), at its own priority:
  an approval asked for or decided (`APPROVAL_REQUESTED`,
  `APPROVAL_DECIDED`), proposals waiting (`PROPOSAL_QUEUED`), an exhibit
  that failed its check on an analyst's read (`EVIDENCE_INTEGRITY_ALARM`),
  and a detonation's sign-off asked for, decided, or naming its authoriser
  (`DETONATION_*`). Every other kind is raised on a system connection
  (merges, break-glass, Lab screening, lookups, feed hits, the drain's
  reviews and escalations, collection authorities, provider changes,
  personas), where it stays the system role's to write;
- the subject and the summary each match one of that kind's templates
  (`TEMPLATES`, the wording of `notify_events.py`), where a case's code is
  the code of the case the notice names (or `?`, which
  `notify_events._case` writes for a code the caller may not read), a count
  is a number, an operation is an operation key, a verdict is one of the
  words the producer writes, and a deployment-wide operation is named by
  its description. The body is not held to a template: it is read in-app
  only, behind the gate, under the actor's name, and carries the
  justification, the note or the reason a person typed;
- a notice that names a case names one the caller may act on: one of its
  cases (`iam.rls_cases()`, where the gate let its act through), or for the
  Lab's detonation notices (`LAB_KINDS`), a case within the Lab's reach
  (`iam.rls_cases_in_reach()`: the Lab is global under `sample.read`). A
  bound account cannot raise a priority-1 integrity alarm about a case it
  is not on.

Each refusal is 42501 with a sentence saying which rule. Everything else is
0145's text, character for character. `test_notify_templates_pg.py` holds
every request-role producer's wording to these templates and every
deployment-wide operation's description to `GLOBAL_DESCRIPTIONS`, so a
wording change that the database would refuse fails there first.

## Downgrade

Restores 0145's function text.
"""
import re

from alembic import op

revision = "0181"
down_revision = "0180"
branch_labels = None
depends_on = None

#: The kinds a request-role caller raises, with their priority
#: (`notifications.KINDS`).
REQUEST_KINDS: dict[str, int] = {
    "APPROVAL_REQUESTED": 2,
    "APPROVAL_DECIDED": 2,
    "PROPOSAL_QUEUED": 3,
    "EVIDENCE_INTEGRITY_ALARM": 1,
    "DETONATION_SIGNOFF_REQUESTED": 2,
    "DETONATION_SIGNOFF_DECIDED": 2,
    "DETONATION_NAMED": 2,
}

#: The Lab's notices, which may name a case within the Lab's reach rather
#: than one of the caller's cases.
LAB_KINDS: tuple[str, ...] = ("DETONATION_SIGNOFF_REQUESTED", "DETONATION_SIGNOFF_DECIDED",
                              "DETONATION_NAMED")

#: The deployment-wide operations' descriptions (`approvals.OPERATIONS`,
#: scope global), which a global approval's subject names.
GLOBAL_DESCRIPTIONS: tuple[str, ...] = (
    "Change a role definition",
    "Reveal a persona credential",
    "Change which operations need two people",
)

#: (kind, subject template, summary template), in `notify_events.py`'s
#: words. `{code}` is the named case's code; `{n}` a count; `{op}` an
#: operation key; `{global}` a deployment-wide operation; `{one:a|b}` one
#: of the words given.
TEMPLATES: tuple[tuple[str, str, str], ...] = (
    ("APPROVAL_REQUESTED",
     "{code}: a second signature is needed",
     "Someone on {code} is asking for a second signature on a {op} operation. "
     "Sign in to review it."),
    ("APPROVAL_REQUESTED",
     "A second signature is needed: {global}",
     "A deployment-wide change is waiting for a second signature. Sign in to review it."),
    ("APPROVAL_DECIDED",
     "{code}: your request was {one:approved|declined}",
     "Your {op} request on {code} was {one:approved|declined}."),
    ("APPROVAL_DECIDED",
     "Your request was {one:countersigned|refused}: {global}",
     "Your deployment-wide request was {one:countersigned|refused}."),
    ("PROPOSAL_QUEUED",
     "{code}: {n} {one:proposal|proposals} waiting in triage",
     "{n} new {one:proposal|proposals} {one:is|are} waiting for review on {code}."),
    ("EVIDENCE_INTEGRITY_ALARM",
     "{code}: an exhibit failed its integrity check",
     "An exhibit on {code} no longer matches the hash recorded when it was acquired. "
     "Treat the case's evidence as suspect until this is explained."),
    ("DETONATION_SIGNOFF_REQUESTED",
     "{code}: a detonation needs your sign-off",
     "A colleague asked to send a sample to a sandbox, and you are named to sign it off. "
     "Sign in to approve or decline it."),
    ("DETONATION_SIGNOFF_REQUESTED",
     "A detonation needs your sign-off",
     "A colleague asked to send a sample to a sandbox, and you are named to sign it off. "
     "Sign in to approve or decline it."),
    ("DETONATION_SIGNOFF_DECIDED",
     "Your detonation was {one:approved|declined}",
     "The sign-off on your detonation request was {one:approved|declined}."),
    ("DETONATION_NAMED",
     "{code}: you are named as a detonation's authoriser",
     "A colleague recorded a detonation outside the product and named you as the "
     "person who agreed to it."),
    ("DETONATION_NAMED",
     "You are named as a detonation's authoriser",
     "A colleague recorded a detonation outside the product and named you as the "
     "person who agreed to it."),
)

_OP = r"[a-z][a-z_]*(\.[a-z][a-z_]*)+"


def _escape(text: str) -> str:
    """Literal text as a PostgreSQL advanced regular expression."""
    return re.sub(r"([\\^$.\[\]|()*+?{}])", r"\\\1", text)


def pattern(template: str) -> str:
    """The anchored expression for one template; `{code}` is left for the
    function to fill with the named case's code."""
    out = []
    for part in re.split(r"(\{[a-z]+(?::[^}]*)?\})", template):
        if part == "{code}":
            out.append("{code}")
        elif part == "{n}":
            out.append("[0-9]{1,9}")
        elif part == "{op}":
            out.append(_OP)
        elif part == "{global}":
            out.append("(" + "|".join(_escape(d) for d in GLOBAL_DESCRIPTIONS)
                       + "|" + _OP + ")")
        elif part.startswith("{one:"):
            out.append("(" + "|".join(_escape(w) for w in part[5:-1].split("|")) + ")")
        else:
            out.append(_escape(part))
    return "^" + "".join(out) + "$"


def _literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


_ROWS = ",\n".join(
    f"              ({_literal(kind)}, {REQUEST_KINDS[kind]}, "
    f"{_literal(pattern(subject))}, {_literal(pattern(summary))})"
    for kind, subject, summary in TEMPLATES)

#: 0145's text, from `CREATE OR REPLACE` to the end of the delivery check.
_HEAD = """
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
  v_at timestamptz;@DECLARE@
BEGIN
  IF NOT v_exempt THEN
    v_bound := iam.rls_actor();
    IF v_bound IS NULL THEN
      RAISE EXCEPTION 'notify.enqueue: the caller is bound to no session'
        USING ERRCODE = '42501';
    END IF;
    IF @ACTOR_RULE@ THEN
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
    END IF;@TEMPLATES@
  END IF;
"""

#: 0145's text, from the coalescing check to the end.
_TAIL = """
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
"""

#: What a request may raise, and in which words (0181).
_TEMPLATE_CHECK = f"""
    -- The kinds a request raises, at their own priority and in the
    -- product's own words (0181). A case's code is the named case's,
    -- escaped for the expression, or the `?` notify_events writes for one
    -- the caller may not read.
    v_code := (SELECT c.code FROM core."case" c WHERE c.id = p_case);
    v_code := '(' || coalesce(pg_catalog.regexp_replace(
                 v_code, '([][\\\\^$.|()*+?{{}}-])', '\\\\\\1', 'g') || '|', '')
              || '\\?)';
    IF NOT EXISTS (
        SELECT 1
          FROM (VALUES
{_ROWS}
               ) AS t(kind, priority, subject, summary)
         WHERE t.kind = p_kind AND t.priority = p_priority
           AND p_subject ~ pg_catalog.replace(t.subject, '{{code}}', v_code)
           AND p_summary ~ pg_catalog.replace(t.summary, '{{code}}', v_code)) THEN
      RAISE EXCEPTION 'notify.enqueue: a request raises only the notices the product writes, at their own priority and in its own words'
        USING ERRCODE = '42501';
    END IF;
    IF p_case IS NOT NULL AND NOT (
         p_case = ANY (coalesce(iam.rls_cases(), '{{}}'::uuid[]))
         OR (p_kind IN ({", ".join(f"'{k}'" for k in LAB_KINDS)})
             AND iam.rls_cases_in_reach() OPERATOR(pg_catalog.?) p_case::text)) THEN
      RAISE EXCEPTION 'notify.enqueue: a request raises a notice only about a case it may act on'
        USING ERRCODE = '42501';
    END IF;"""

def _function(declare: str, actor_rule: str, templates: str) -> str:
    return (_HEAD.replace("@DECLARE@", declare).replace("@ACTOR_RULE@", actor_rule)
            .replace("@TEMPLATES@", templates) + _TAIL)


#: Frozen text: a later revision that changes the function restates it.
UPGRADE_SQL = _function("\n  v_code text;", "p_actor IS DISTINCT FROM v_bound",
                        _TEMPLATE_CHECK)

#: 0145's text.
DOWNGRADE_SQL = _function("", "p_actor IS NOT NULL AND p_actor IS DISTINCT FROM v_bound",
                          "")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
