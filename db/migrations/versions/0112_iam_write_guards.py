"""Guards on the two IAM columns the request role may still write (S1).

0109 left the request role exactly two column grants on the IAM plane,
because a request needs them and a system connection per request would
cost one more connection on every call:

- `iam.session (last_seen_at, mfa_satisfied_at, revoked_at, revoke_reason)`
  for sliding the idle window, stamping a step-up and logging out;
- `lab.download_ticket (redeemed_at)` for the sample origin spending a
  ticket before anybody is bound.

A column grant says WHICH columns, not WHICH rows or which values, so an
injected statement could slide every session's idle window, un-revoke a
revoked session, or un-spend a ticket. These BEFORE UPDATE triggers close
that, for a caller that is not exempt from row security (the owner and
the system role are trusted, which keeps every fixture that ages a
session or a ticket by hand working exactly as before):

- a session may be changed only when it is the one this connection is
  bound to (its rls_binding_hash is the hash of the connection's proof),
  and once revoked its revocation cannot change;
- a ticket may only go from unspent to spent.

`iam.rls_caller_exempt()` is 0111's; it reads the calling role, not
`current_user`, and these trigger functions are SECURITY INVOKER anyway.

## Downgrade

Drops the two triggers and their functions.
"""
from alembic import op

revision = "0112"
down_revision = "0111"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


UPGRADE_SQL = """
CREATE FUNCTION iam.session_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF OLD.rls_binding_hash IS NULL
     OR OLD.rls_binding_hash IS DISTINCT FROM pg_catalog.sha256(pg_catalog.convert_to(
          nullif(pg_catalog.current_setting('noctornal.rls_proof', true), ''), 'UTF8')) THEN
    RAISE EXCEPTION 'iam.session: this connection may change only the session it is bound to'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'iam.session: a revoked session stays revoked'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER session_guard
  BEFORE UPDATE ON iam.session
  FOR EACH ROW EXECUTE FUNCTION iam.session_guard();

CREATE FUNCTION lab.download_ticket_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF OLD.redeemed_at IS NOT NULL OR NEW.redeemed_at IS NULL THEN
    RAISE EXCEPTION 'lab.download_ticket: a ticket may only be spent, once'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER download_ticket_guard
  BEFORE UPDATE ON lab.download_ticket
  FOR EACH ROW EXECUTE FUNCTION lab.download_ticket_guard();
"""

DOWNGRADE_SQL = """
DROP TRIGGER download_ticket_guard ON lab.download_ticket;
DROP FUNCTION lab.download_ticket_guard();
DROP TRIGGER session_guard ON iam.session;
DROP FUNCTION iam.session_guard();
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
