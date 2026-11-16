"""The Lab reads a case's lead investigators through a definer (rls-6, 2026-11-15).

## Why

Who holds which role on which case is to be filtered for the request role (rls-6, docs/17): a request
will read its own assignments and the team of every case it may open, and nothing else. One reader
needs more than that. A non-private detonation is signed off by a lead investigator (a live
`CASE_OWNER` assignment) on the sample's own case (docs/11), and the Lab analyst who asks is global
under `sample.read` and is usually on no case at all, so `SampleService.detonation_authorisers` reads
another person's assignment on a case the analyst is not on. A row policy would empty that read and
the sign-off would find nobody.

## What

`iam.case_leads(p_case)` answers, as the definer, the users holding a live `CASE_OWNER` assignment on
`p_case`, to three callers and nobody else:

- an exempt caller: the owner, or the system role (the sandbox worker's re-checks run as SANDBOX);
- a caller who may read the case's team: `p_case` is in `iam.rls_cases()`, the same arm the row
  policy will give a request, so a member is told nothing the table will not show them;
- a holder of `sample.read` through a global role, for a case within their reach
  (`iam.rls_cases_in_reach()`): the reach a sample of the case is read at (0121), so the Lab learns
  the leads of the cases whose samples it may see, and of no case above it.

It answers user ids alone, never the role or the dates of anyone's assignment. EXECUTE is taken from
PUBLIC and given to the two runtime roles, as 0177 does.

## Downgrade

Drops the function. No row is written.
"""
from alembic import op

revision = "0191"
down_revision = "0190"
branch_labels = None
depends_on = None

FUNCTION = "iam.case_leads(uuid)"

#: Frozen text. A later revision that changes the function restates it.
FUNCTION_SQL = """
CREATE FUNCTION iam.case_leads(p_case uuid) RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT a.user_id
    FROM iam.case_assignment a
   WHERE a.case_id = p_case
     AND a.role_key = 'CASE_OWNER'
     AND (a.expires_at IS NULL OR a.expires_at > pg_catalog.now())
     AND (iam.rls_caller_exempt()
          OR p_case = ANY (iam.rls_cases())
          OR (iam.rls_holds_global('sample.read')
              AND iam.rls_cases_in_reach() OPERATOR(pg_catalog.?) p_case::text))
$$;

COMMENT ON FUNCTION iam.case_leads(uuid) IS
  'The lead investigators (live CASE_OWNER assignments) of a case, for the Lab''s detonation '
  'sign-off (rls-6, 0191): to an exempt caller, to one who may read the case''s team '
  '(iam.rls_cases), and to a holder of sample.read for a case within their reach; nothing to '
  'anyone else.';

REVOKE ALL ON FUNCTION iam.case_leads(uuid) FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION iam.case_leads(uuid) TO %I', r);
    END IF;
  END LOOP;
END
$noc$;
"""

DOWNGRADE_SQL = "DROP FUNCTION iam.case_leads(uuid);"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
