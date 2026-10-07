"""The request role cannot forge step-up or stretch the idle window (rls-7, 2026-10-03).

## Why

0109 left `noctornal_app` UPDATE on `iam.session (last_seen_at,
mfa_satisfied_at, revoked_at, revoke_reason)`, and 0112's guard confines
those writes to the session the connection is bound to without looking
at the values. So a statement injected into an authenticated request
could stamp `mfa_satisfied_at = now()` on its own session, and pass the
step-up gate that guards merge, export, purge and sample download without
a second factor; or set `last_seen_at` to a far-future time and defeat
the 30-minute idle timeout.

Nothing legitimate writes `mfa_satisfied_at` on the request role: a
step-up is a fresh sign-in, minted on the AUTH system connection with the
stamp already set, and the only reason the column was granted was that
the idle-window touch rewrote the whole row. That touch is now one
statement naming `last_seen_at` alone (`PgSessionStore.slide`,
authz-session-revoke-bypass), which is why this revision can follow it.

## What

- UPDATE (mfa_satisfied_at) is revoked from the request role. It keeps
  last_seen_at (the slide) and revoked_at, revoke_reason (logout).
- `iam.session_guard()` is restated with two more refusals for a caller
  row security does not exempt: `mfa_satisfied_at` never changes, and
  `last_seen_at` only moves forward and never past the database's clock
  plus `CLOCK_SKEW`. A slide is written from the API's clock, so the store
  (`PgSessionStore.slide`) clamps what it writes to the database's clock
  plus one minute: an API host whose clock runs fast cannot trip this
  refusal and turn every request into a 500, and only a forged value does.
  The 0112 refusals are kept word for word.

`PRIVILEGES_SQL` is idempotent so `scripts/runtime_roles.py ensure` can
replay it after 0109.

## Downgrade

Restores 0112's function text and the column grant.
"""
from alembic import op

revision = "0144"
down_revision = "0143"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: The column UPDATEs the request role keeps on iam.session after this
#: revision (0109 granted these plus mfa_satisfied_at).
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {
    "iam.session": ("last_seen_at", "revoked_at", "revoke_reason"),
}
#: How far ahead of the database's clock a slide may land.
CLOCK_SKEW = "5 minutes"

PRIVILEGES_SQL = """
DO $noc$
DECLARE
  app text := 'noctornal_app';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    EXECUTE format('REVOKE UPDATE (mfa_satisfied_at) ON iam.session FROM %I', app);
  END IF;
END
$noc$;
"""

GUARD_SQL = """
CREATE OR REPLACE FUNCTION iam.session_guard() RETURNS trigger
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
  IF NEW.mfa_satisfied_at IS DISTINCT FROM OLD.mfa_satisfied_at THEN
    RAISE EXCEPTION 'iam.session: a second factor is recorded only at sign-in'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.last_seen_at IS DISTINCT FROM OLD.last_seen_at
     AND (NEW.last_seen_at IS NULL
          OR NEW.last_seen_at < OLD.last_seen_at
          OR NEW.last_seen_at > pg_catalog.now() + interval '5 minutes') THEN
    RAISE EXCEPTION 'iam.session: the idle window only slides forward, to the present'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
"""

DOWNGRADE_SQL = """
CREATE OR REPLACE FUNCTION iam.session_guard() RETURNS trigger
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

DO $noc$
DECLARE
  app text := 'noctornal_app';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
    EXECUTE format('GRANT UPDATE (mfa_satisfied_at) ON iam.session TO %I', app);
  END IF;
END
$noc$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(PRIVILEGES_SQL)
    run(GUARD_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
