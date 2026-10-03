"""The request role cannot read an account's credentials (rls-6, 2026-10-03).

## Why

0109 made the IAM plane read-only to `noctornal_app` and left it SELECT
on every column, so a statement injected into any request-role
connection, bound or not (the unauthenticated ingest submit, the sample
origin before a ticket is spent), could read every account's argon2id
password hash for offline cracking, its sealed TOTP secret with the id of
the key that seals it, its recovery-code hashes and its TOTP replay
counter. Nothing on the request role needs them: sign-in, second factors,
recovery codes, password changes and administration run on the AUTH and
IAM_ADMIN system connections (`http/routers/auth.py`, `iam_admin.py`).
The one request-role reader was the recovery-code COUNT that `/auth/me`
shows.

## What

- Table SELECT on `iam.app_user` is replaced by a column grant over every
  column the table has when the revision runs, except the five in
  `CREDENTIAL_COLUMNS`. The columns are discovered from the catalog rather
  than listed, so a column an earlier revision on the chain added is
  granted, and none of the five can be. A column a LATER revision adds is
  unreadable to the request role until that revision grants it, which is
  the safe default for this table.
- `iam.recovery_codes_remaining(p_user)` answers the count, as the
  definer, for the caller's own bound account. An exempt caller (the
  owner in development and the suite, the system role) may ask about any
  account. Anyone else gets NULL, the answer an account that does not
  exist gets, and so does a request whose session was revoked while it
  ran (`/auth/me` then answers 401 rather than 500). EXECUTE is taken
  from PUBLIC and given to the two runtime roles.

`PRIVILEGES_SQL` is idempotent so `scripts/runtime_roles.py ensure` can
replay it, as it replays 0109.

## No-op without the role; downgrade

The grants are guarded on `pg_roles` as 0109's are. The downgrade drops
the function and gives the request role table SELECT back.
"""
from alembic import op

revision = "0143"
down_revision = "0142"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"
WORKER_ROLE = "noctornal_worker"

#: Never readable by the request role. `test_g45_session_plane_pg.py` reads
#: this and asserts each is refused.
CREDENTIAL_COLUMNS = ("password_hash", "totp_secret_ciphertext", "totp_key_id",
                      "recovery_codes_hash", "totp_last_counter")

#: The table whose request-role SELECT is by column. Read by
#: `test_app_role_privileges_pg.py`, which then asks the catalog whether the
#: role can reach the table at all rather than naming its columns.
RUNTIME_COLUMN_SELECTS: dict[str, tuple[str, ...]] = {
    "iam.app_user": (),
}

FUNCTION = "iam.recovery_codes_remaining(uuid)"

PRIVILEGES_SQL = """
DO $noc$
DECLARE
  app text := 'noctornal_app';
  readable text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO readable
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = 'iam.app_user'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped
       AND a.attname NOT IN ('password_hash', 'totp_secret_ciphertext', 'totp_key_id',
                             'recovery_codes_hash', 'totp_last_counter');
    EXECUTE format('REVOKE SELECT ON iam.app_user FROM %I', app);
    EXECUTE format('REVOKE SELECT (password_hash, totp_secret_ciphertext, totp_key_id,'
                   || ' recovery_codes_hash, totp_last_counter) ON iam.app_user FROM %I', app);
    EXECUTE format('GRANT SELECT (%s) ON iam.app_user TO %I', readable, app);
  END IF;
END
$noc$;
"""

FUNCTION_SQL = """
CREATE FUNCTION iam.recovery_codes_remaining(p_user uuid) RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT iam.rls_caller_exempt() AND p_user IS DISTINCT FROM iam.rls_actor() THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT coalesce(pg_catalog.cardinality(u.recovery_codes_hash), 0)
            FROM iam.app_user u WHERE u.id = p_user);
END
$$;

COMMENT ON FUNCTION iam.recovery_codes_remaining(uuid) IS
  'How many recovery codes an account has left, for that account alone '
  '(rls-6, 2026-10-03): the request role cannot read the hashes.';

REVOKE ALL ON FUNCTION iam.recovery_codes_remaining(uuid) FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION iam.recovery_codes_remaining(uuid) TO %I', r);
    END IF;
  END LOOP;
END
$noc$;
"""

DOWNGRADE_SQL = """
DROP FUNCTION iam.recovery_codes_remaining(uuid);

DO $noc$
DECLARE
  app text := 'noctornal_app';
  every text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO every
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = 'iam.app_user'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped;
    EXECUTE format('REVOKE SELECT (%s) ON iam.app_user FROM %I', every, app);
    EXECUTE format('GRANT SELECT ON iam.app_user TO %I', app);
  END IF;
END
$noc$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(PRIVILEGES_SQL)
    run(FUNCTION_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
