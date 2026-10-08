"""The request role reads no session's token, binding or address, and no
break-glass justification (rls-6, Beta 1.1, 2026-10-08).

## Why

0109 made the IAM plane read-only to `noctornal_app` and left it every
column, because the gate and the policies read the plane on every request;
0143 took the accounts' credential columns back out. What stayed readable
to any request-role connection, bound or not (the unauthenticated ingest
submit and the sample origin before a ticket is spent included), was every
session's `token_hash`, `rls_binding_hash`, `ip`, `ip_hash` and
`user_agent`, and every break-glass grant's `justification`. Neither hash
opens a session (the token hash is sha256 of a 256-bit token, and the
binding proof is derived from the raw token, not from that hash), so what a
statement injected into a request learned was who signs in from where, and
the text an analyst wrote about an emergency, which describes its case.

## What

- `iam.session` is read by column: every column the table has when this
  revision runs except the five in `SESSION_SEALED`, discovered from the
  catalog as 0143 does it. The request role keeps what it reads by name:
  a session's id, account, times and revocation (the idle window's slide,
  a sign-out, `/auth/me`, the account list's last-seen time), and its
  column UPDATEs (0109, 0144).
- `iam.session_by_token(p_token_hash)` answers, as the definer, the one
  session a presented token names: the request role's one reader of the
  sealed columns, `PgSessionStore.get_by_token_hash`, which the HTTP and
  websocket validation call before anybody is bound, and which compares the
  address and the client a session was minted from under strict binding
  (0058). A hash can be had only from the raw token, and the table no
  longer gives one up.
- `iam.break_glass` is read by column, every column but `justification`.
- `iam.break_glass_justification(p_grant)` answers the text, as the
  definer, to an exempt caller (the owner, the system role), to the grant's
  own holder, and to a holder of `break_glass.review` through a global role
  (the Security Officer's queue, which is the permission that authorises
  reading it); NULL to anyone else, the answer a grant that does not exist
  gets. Read by `BreakGlassService.live_grant`, `live_grants` and
  `unreviewed`.
- EXECUTE on both functions is taken from PUBLIC and given to the two
  runtime roles, as 0143 does.

`PRIVILEGES_SQL` is idempotent so `scripts/runtime_roles.py ensure` can
replay it after 0109's grants, as it replays 0143.

## What it does not do: iam.case_assignment

Filtering who holds which role on which case needs its request-role readers
moved first, and two of them cannot read through a row policy as they are:
the live socket's rechecks run on a fresh request connection that is bound
to nobody (`live._recheck`, `_session_alive`), and the Lab reads another
person's role on a case the Lab analyst is not on (`samples.py`, the
detonation authoriser's eligibility). A policy would refuse both silently.
It stays readable, as docs/17 says.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0109 and 0143 are. The downgrade drops both
functions and gives table SELECT back on both tables.
"""
from alembic import op

revision = "0177"
down_revision = "0176"
branch_labels = None
depends_on = None

#: Never readable by the request role. `test_rls_iam_columns_pg.py` reads
#: these and asserts each is refused.
SESSION_SEALED = ("token_hash", "rls_binding_hash", "ip", "ip_hash", "user_agent")
BREAK_GLASS_SEALED = ("justification",)

#: The tables whose request-role SELECT is by column. Read by
#: `test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
RUNTIME_COLUMN_SELECTS: dict[str, tuple[str, ...]] = {
    "iam.session": (),
    "iam.break_glass": (),
}

FUNCTIONS = ("iam.session_by_token(bytea)", "iam.break_glass_justification(uuid)")


def _by_column(table: str, sealed: tuple[str, ...]) -> str:
    names = ", ".join(f"'{c}'" for c in sealed)
    cols = ", ".join(sealed)
    return f"""
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO readable
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = '{table}'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped
       AND a.attname NOT IN ({names});
    EXECUTE format('REVOKE SELECT ON {table} FROM %I', app);
    EXECUTE format('REVOKE SELECT ({cols}) ON {table} FROM %I', app);
    EXECUTE format('GRANT SELECT (%s) ON {table} TO %I', readable, app);"""


PRIVILEGES_SQL = f"""
DO $noc$
DECLARE
  app text := 'noctornal_app';
  readable text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN{_by_column("iam.session", SESSION_SEALED)}{_by_column("iam.break_glass", BREAK_GLASS_SEALED)}
  END IF;
END
$noc$;
"""

#: Frozen text.
FUNCTION_SQL = """
CREATE FUNCTION iam.session_by_token(p_token_hash bytea)
  RETURNS TABLE (id uuid, user_id uuid, issued_at timestamptz,
                 expires_at timestamptz, last_seen_at timestamptz,
                 mfa_satisfied_at timestamptz, revoked_at timestamptz,
                 revoke_reason text, ip inet, user_agent text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.id, s.user_id, s.issued_at, s.expires_at, s.last_seen_at,
         s.mfa_satisfied_at, s.revoked_at, s.revoke_reason, s.ip, s.user_agent
    FROM iam.session s
   WHERE s.token_hash = p_token_hash
$$;

COMMENT ON FUNCTION iam.session_by_token(bytea) IS
  'The one session whose token hashes to this, for the validation that runs '
  'before a connection is bound (rls-6, 0177): the request role cannot read a '
  'session''s token hash, binding, address or client.';

CREATE FUNCTION iam.break_glass_justification(p_grant uuid) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT g.justification
    FROM iam.break_glass g
   WHERE g.id = p_grant
     AND (iam.rls_caller_exempt()
          OR g.user_id = iam.rls_actor()
          OR iam.rls_holds_global('break_glass.review'))
$$;

COMMENT ON FUNCTION iam.break_glass_justification(uuid) IS
  'A grant''s justification, for its holder and for break_glass.review alone '
  '(rls-6, 0177); NULL to anyone else.';

REVOKE ALL ON FUNCTION iam.session_by_token(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.break_glass_justification(uuid) FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION iam.session_by_token(bytea) TO %I', r);
      EXECUTE format('GRANT EXECUTE ON FUNCTION iam.break_glass_justification(uuid) TO %I', r);
    END IF;
  END LOOP;
END
$noc$;
"""


def _every_column(table: str) -> str:
    return f"""
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO every
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = '{table}'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped;
    EXECUTE format('REVOKE SELECT (%s) ON {table} FROM %I', every, app);
    EXECUTE format('GRANT SELECT ON {table} TO %I', app);"""


DOWNGRADE_SQL = "\n".join(f"DROP FUNCTION {fn};" for fn in reversed(FUNCTIONS)) + f"""

DO $noc$
DECLARE
  app text := 'noctornal_app';
  every text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN{_every_column("iam.session")}{_every_column("iam.break_glass")}
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
