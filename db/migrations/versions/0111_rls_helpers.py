"""The functions row-level security is built from (S1, 2026-09-25).

## What each is for

The policies (0114) never read the IAM plane themselves. They call these,
each as an uncorrelated scalar subquery, so each runs ONCE per statement
as an initplan and a policy's per-row work is an enum comparison, an
array containment and at most a primary-key probe.

- `iam.rls_actor()`: the user this connection is bound to, or NULL. A
  session binding is `sha256(noctornal.rls_proof)` found on a live,
  unrevoked session of an active account (0110); a ticket binding is
  `sha256(noctornal.rls_ticket)` found on a ticket redeemed within five
  minutes, for the sample origin, which serves a spent ticket's holder and
  runs no session. Nothing the request role can write feeds either branch
  (0109).
- `iam.rls_caller_exempt()`: whether the role that CALLED into SQL is
  exempt from row security (a superuser, a BYPASSRLS role, or a member of
  the owner). It reads `session_user` and the `role` setting rather than
  `current_user`, because inside a SECURITY DEFINER function `current_user`
  is the owner and every caller would look exempt. Neither can be changed
  by the request role: SET SESSION AUTHORIZATION needs a superuser, and
  SET ROLE needs a membership it does not have.
- `iam.rls_bind(proof)` / `iam.rls_bind_ticket(ticket)`: set the
  session-scoped setting and report (actor, exempt) in one round trip, for
  `db.bind_session` / `db.bind_ticket`.
- `iam.rls_clearance()`, `iam.rls_compartments()`, `iam.rls_ceilings()`,
  `iam.rls_ceiling_for(ceilings, case)`, `iam.rls_cases()`: the gate's
  lattice (`security.access.evaluate`) in SQL, minus the verb and the
  step-up clock: the account's clearance raised by the highest live
  break-glass grant (global everywhere, case-scoped on its case),
  compartments never widened, the case readable only on an unexpired
  assignment whose case labels are within reach.
- `iam.rls_holds_global(permission)`: a verb held through a global role
  on an active account.
- `iam.case_code(case)`: the code, only for an exempt caller, the bound
  actor's own assignment, or a holder of break_glass.review or sample.read
  (the officer's queue and the Lab name a case they may not open).
- `iam.case_facts(case)`: the lock facts of any case (id, status, labels,
  owner, deputy, legal hold and the two policy switches, and the code as
  `iam.case_code` answers it), for the gate, which must decide and audit
  exactly as it did before a case row could be hidden from it, and for the
  Lab, whose samples compose their case's labels and read-only state for
  analysts on no case at all (`LEFT JOIN LATERAL iam.case_facts(s.case_id)`).
  Never the title, summary or legal basis.
- `iam.element_facts(kind, id)`: the case and labels of a node, edge,
  exhibit or assertion, for the router pre-reads that feed the gate.
- `iam.rls_record_break_glass_use(grant)`: the gate counts a use of a
  grant on the request connection, which may no longer UPDATE
  iam.break_glass (0109). This increments only the bound actor's own live
  grant, and can never decrease a count.

## Why SECURITY DEFINER, and how that is kept safe

They read the IAM plane and `core."case"`, which the policies protect;
run as the caller they would read their own filtered view and loop. Each
definer body is static SQL over fully qualified names, with
`SET search_path = pg_catalog, pg_temp` (pg_temp last, so a temporary
object can never shadow a catalog one). `iam.rls_ceiling_for` is the
exception on purpose: plain SQL, no SET clause, so the planner inlines it
into each policy.

## Downgrade

Drops them. 0114's policies depend on them and are dropped first by the
chain.
"""
from alembic import op

revision = "0111"
down_revision = "0110"
branch_labels = None
depends_on = None

#: The functions this revision creates, by signature, in creation order.
#: The downgrade drops them in reverse.
FUNCTIONS = (
    "iam.rls_caller_exempt()",
    "iam.rls_actor()",
    "iam.rls_bind(text)",
    "iam.rls_bind_ticket(text)",
    "iam.rls_clearance()",
    "iam.rls_compartments()",
    "iam.rls_ceilings()",
    "iam.rls_ceiling_for(jsonb, uuid)",
    "iam.rls_cases()",
    "iam.rls_holds_global(text)",
    "iam.case_code(uuid)",
    "iam.case_facts(uuid)",
    "iam.element_facts(text, uuid)",
    "iam.rls_record_break_glass_use(uuid)",
)

#: How long a spent ticket binds its holder (the sample origin serves the
#: bytes inside one request, well within it).
TICKET_BINDING_MINUTES = 5

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

UPGRADE_SQL = f"""
CREATE FUNCTION iam.rls_caller_exempt() RETURNS boolean
  LANGUAGE sql STABLE PARALLEL RESTRICTED
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT coalesce(bool_or(r.rolsuper OR r.rolbypassrls
                          OR pg_catalog.pg_has_role(r.oid, c.relowner, 'USAGE')), false)
    FROM pg_catalog.pg_roles r, pg_catalog.pg_class c
   WHERE r.rolname = CASE WHEN pg_catalog.current_setting('role') = 'none'
                          THEN session_user::text
                          ELSE pg_catalog.current_setting('role') END
     AND c.oid = 'core.node'::pg_catalog.regclass
$$;

CREATE FUNCTION iam.rls_actor() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT coalesce(
    (SELECT s.user_id
       FROM iam.session s
       JOIN iam.app_user u ON u.id = s.user_id
      WHERE s.rls_binding_hash = pg_catalog.sha256(pg_catalog.convert_to(
              nullif(pg_catalog.current_setting('noctornal.rls_proof', true), ''),
              'UTF8'))
        AND s.revoked_at IS NULL
        AND s.expires_at > pg_catalog.now()
        AND u.is_active),
    (SELECT t.user_id
       FROM lab.download_ticket t
       JOIN iam.app_user u ON u.id = t.user_id
      WHERE t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
              nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''),
              'UTF8'))
        AND t.redeemed_at IS NOT NULL
        AND t.redeemed_at > pg_catalog.now() - interval '{TICKET_BINDING_MINUTES} minutes'
        AND u.is_active))
$$;

CREATE FUNCTION iam.rls_bind(p_proof text)
  RETURNS TABLE (actor uuid, exempt boolean)
  LANGUAGE plpgsql VOLATILE
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_catalog.set_config('noctornal.rls_proof', coalesce(p_proof, ''), false);
  RETURN QUERY SELECT iam.rls_actor(), iam.rls_caller_exempt();
END
$$;

CREATE FUNCTION iam.rls_bind_ticket(p_ticket text)
  RETURNS TABLE (actor uuid, exempt boolean)
  LANGUAGE plpgsql VOLATILE
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_catalog.set_config('noctornal.rls_ticket', coalesce(p_ticket, ''), false);
  RETURN QUERY SELECT iam.rls_actor(), iam.rls_caller_exempt();
END
$$;

CREATE FUNCTION iam.rls_clearance() RETURNS core.tlp
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT GREATEST(u.tlp_clearance,
                  (SELECT max(g.granted_classification)
                     FROM iam.break_glass g
                    WHERE g.user_id = u.id AND g.case_id IS NULL
                      AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
                      AND g.granted_classification IS NOT NULL))
    FROM iam.app_user u
   WHERE u.id = iam.rls_actor() AND u.is_active
$$;

CREATE FUNCTION iam.rls_compartments() RETURNS text[]
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT coalesce(u.compartments, '{{}}'::text[])
    FROM iam.app_user u
   WHERE u.id = iam.rls_actor() AND u.is_active
$$;

CREATE FUNCTION iam.rls_ceilings() RETURNS jsonb
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT coalesce(pg_catalog.jsonb_object_agg(x.case_id::text, x.level), '{{}}'::jsonb)
    FROM (SELECT g.case_id, max(g.granted_classification) AS level
            FROM iam.break_glass g
           WHERE g.user_id = iam.rls_actor() AND g.case_id IS NOT NULL
             AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
             AND g.granted_classification IS NOT NULL
           GROUP BY g.case_id) x
   WHERE x.level > iam.rls_clearance()
$$;

CREATE FUNCTION iam.rls_ceiling_for(p_ceilings jsonb, p_case uuid) RETURNS core.tlp
  LANGUAGE sql STABLE PARALLEL SAFE
AS $$
  SELECT (p_ceilings ->> p_case::text)::core.tlp
$$;

CREATE FUNCTION iam.rls_cases() RETURNS uuid[]
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  WITH me AS (
    SELECT u.id, u.tlp_clearance, coalesce(u.compartments, '{{}}'::text[]) AS held
      FROM iam.app_user u
     WHERE u.id = iam.rls_actor() AND u.is_active
  ), grants AS (
    SELECT g.case_id, g.granted_classification
      FROM iam.break_glass g, me
     WHERE g.user_id = me.id
       AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()
       AND g.granted_classification IS NOT NULL
  )
  SELECT coalesce(pg_catalog.array_agg(c.id), '{{}}'::uuid[])
    FROM me
    JOIN iam.case_assignment a ON a.user_id = me.id
    JOIN core."case" c ON c.id = a.case_id
   WHERE (a.expires_at IS NULL OR a.expires_at > pg_catalog.now())
     AND coalesce(c.compartments, '{{}}'::text[]) OPERATOR(pg_catalog.<@) me.held
     AND c.classification <= GREATEST(
           me.tlp_clearance,
           (SELECT max(gr.granted_classification) FROM grants gr
             WHERE gr.case_id IS NULL OR gr.case_id = c.id))
$$;

CREATE FUNCTION iam.rls_holds_global(p_permission text) RETURNS boolean
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM iam.user_role ur
      JOIN iam.role_permission rp ON rp.role_key = ur.role_key
      JOIN iam.app_user u ON u.id = ur.user_id
     WHERE ur.user_id = iam.rls_actor() AND rp.permission_key = p_permission
       AND u.is_active)
$$;

CREATE FUNCTION iam.case_code(p_case uuid) RETURNS text
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT c.code
    FROM core."case" c
   WHERE c.id = p_case
     AND (iam.rls_caller_exempt()
          OR EXISTS (SELECT 1 FROM iam.case_assignment a
                      WHERE a.case_id = c.id AND a.user_id = iam.rls_actor()
                        AND (a.expires_at IS NULL OR a.expires_at > pg_catalog.now()))
          OR iam.rls_holds_global('break_glass.review')
          OR iam.rls_holds_global('sample.read'))
$$;

CREATE FUNCTION iam.case_facts(p_case uuid)
  RETURNS TABLE (id uuid, code text, status core.case_status,
                 classification core.tlp, compartments text[],
                 owner_user_id uuid, deputy_user_id uuid, legal_hold boolean,
                 withheld_disclosure text, dual_control_merge boolean)
  LANGUAGE sql STABLE PARALLEL SAFE {_DEFINER}
AS $$
  SELECT c.id, iam.case_code(c.id), c.status, c.classification, c.compartments,
         c.owner_user_id, c.deputy_user_id, c.legal_hold, c.withheld_disclosure,
         c.dual_control_merge
    FROM core."case" c
   WHERE c.id = p_case
$$;

CREATE FUNCTION iam.element_facts(p_kind text, p_id uuid)
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

CREATE FUNCTION iam.rls_record_break_glass_use(p_grant uuid) RETURNS boolean
  LANGUAGE sql VOLATILE {_DEFINER}
AS $$
  WITH counted AS (
    UPDATE iam.break_glass g
       SET used_at = coalesce(g.used_at, pg_catalog.now()),
           action_count = g.action_count + 1
     WHERE g.id = p_grant
       AND (iam.rls_caller_exempt()
            OR (g.user_id = iam.rls_actor()
                AND g.revoked_at IS NULL AND g.expires_at > pg_catalog.now()))
    RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM counted)
$$;
"""

DOWNGRADE_SQL = "\n".join(f"DROP FUNCTION {fn};" for fn in reversed(FUNCTIONS))


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
