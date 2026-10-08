"""A connection binds only to a session inside its idle window
(idle window at the binding, Beta 1.1, 2026-10-08).

## Why

`iam.rls_actor()` (0111) resolves the user a request's connection is bound
to: a live, unrevoked session of an active account whose binding hash
matches the connection's proof. It checked the session's absolute expiry
(12 hours) and not its idle window (30 minutes, `security.sessions
.IDLE_TIMEOUT`). The HTTP layer refuses an idle session before it binds
anything, so the gap was the database's alone: a raw token from a session
left idle for hours, presented to the database directly, still bound as
its user and read what they may read, until the absolute expiry.

## What

The session branch also requires `last_seen_at` inside the idle window,
`last_seen_at > now() - interval '30 minutes'`: the boundary
`SessionService.validate` uses (idle when `now - last_seen_at >=
IDLE_TIMEOUT`). A request binds before it slides its window
(`deps.current_user`), so the binding judges the window the HTTP check has
just judged. The ticket branch is unchanged (a spent ticket binds its holder
for five minutes, 0111). Everything else in the function is 0111's text,
character for character; it stays SECURITY DEFINER, STABLE and PARALLEL
SAFE with its pinned search path, and `CREATE OR REPLACE` keeps every
policy that calls it.

What a reader sees differently: a request still running when its session's
window has passed binds to nobody for its remaining statements, as it would
for a session revoked meanwhile. Nothing in the product holds one request
open for half an hour.

## Downgrade

Restores 0111's text.
"""
from alembic import op

revision = "0174"
down_revision = "0173"
branch_labels = None
depends_on = None

#: The idle window, as `security.sessions.IDLE_TIMEOUT` (30 minutes).
#: `test_rls_idle_binding_pg.py` holds the two equal.
IDLE_WINDOW = "30 minutes"

_DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"


def _function(session_window: str) -> str:
    return f"""
CREATE OR REPLACE FUNCTION iam.rls_actor() RETURNS uuid
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
        AND s.expires_at > pg_catalog.now(){session_window}
        AND u.is_active),
    (SELECT t.user_id
       FROM lab.download_ticket t
       JOIN iam.app_user u ON u.id = t.user_id
      WHERE t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
              nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''),
              'UTF8'))
        AND t.redeemed_at IS NOT NULL
        AND t.redeemed_at > pg_catalog.now() - interval '5 minutes'
        AND u.is_active))
$$;
"""


#: Frozen text: a later revision that changes the function restates it.
UPGRADE_SQL = _function(
    f"\n        AND s.last_seen_at > pg_catalog.now() - interval '{IDLE_WINDOW}'")

#: 0111's text.
DOWNGRADE_SQL = _function("")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
