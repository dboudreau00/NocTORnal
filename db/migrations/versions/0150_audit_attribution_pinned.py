"""The request role cannot attribute or date an audit row
(evidence-ledger-actor-time-forgeable, 2026-10-03).

## What was wrong

`audit.chain_hash()` hashes whatever the INSERT supplies. A connection bound
to analyst A could write `LEGAL_HOLD_LIFTED by user B, 2020-01-01` into
`audit.event`: both the actor and the date were the caller's to choose, and
the chain still verified because it is computed over the forged row. The
custody ledger pins its own time (0024) and so shows the author knew the
pattern, but the audit chain did not use it. Anyone who reaches SQL as the
request role (an injection, a compromised process) could plant an attributed,
backdated entry in the record produced to a court, and no verifier could tell.

## The fix: a trigger, not a policy

The review proposed a WITH CHECK policy. `audit.event` is not under row-level
security (rls_registry DEFERRED), and turning it on means a SELECT policy and
the conversion of about a hundred readers in 53 modules, which is its own
piece of work. A BEFORE INSERT trigger answers the same question for the
write, today, without touching one reader.

A caller that row security exempts (the owner, the system role, a
superuser) is left exactly as it was. The system role is how the product
writes on behalf of a person it has authenticated by other means, and the
owner can drop the trigger anyway; what stops the owner is the external
anchor (`/audit/verify` tail_row_hash), not this.

Any other caller, the request role, gets three things:

1. `occurred_at` is `now()`, whatever it supplied.
2. A row that names no actor stays as it is.
3. A row that names an actor is checked against `iam.rls_actor()`, the user
   the connection is bound to. Equal: kept. A connection bound to someone
   ELSE is refused with insufficient_privilege: it is a forgery or a bug,
   and no writer in the product does it (measured, 2026-10-03, over the
   row-security, session, ticket, approval, dual-control, evidence and HTTP
   suites run in the request role's posture: 65 writes that named a user
   the connection was not bound to, every one from a connection bound to
   nobody). A connection bound to NOBODY has its claim demoted: `actor_id`
   becomes NULL and the claim is kept in `detail` as `unverified_actor_id`.
   One more proof is accepted: a connection that presented the secret of a
   ticket spent in the last five minutes may name that ticket's holder, active
   or not. `iam.rls_actor()` binds only an active account, because binding
   grants reach; naming a holder grants none, and the refusal of a deactivated
   holder's download is exactly the row that must still name them.

The third case is deliberate. Several honest writers record an event about a
person without being bound to them: a refused session, a ticket spent at the
sample origin, a refusal written on a side connection so that a rollback
cannot take it. The database cannot tell them from a forger, and refusing
them would lose an audit row (or fail the request that wrote it) in a log
whose rule is that nothing is silently dropped. A row the database could not
attribute is attributed to nobody, and says so; it cannot be passed off as
the other person's act, which is the harm. Where the writer can be bound (a
refusal on a side connection, a spent ticket) it now is, so the row keeps
its actor.

The function is SECURITY DEFINER with `search_path = pg_catalog, pg_temp`,
because the exempt test and the binding read the IAM plane. The trigger is
called `audit_attribution` so that it fires BEFORE `audit_chain` (BEFORE row
triggers run in name order): the chain hashes the pinned values.

`actor_kind`, `session_id` and `ip_hash` are not checked here. They are
labels on a row, not a claim about which person acted, and a check on them
would refuse the writers that record a ticket holder's session.

## Downgrade

Drops the trigger and the function. Rows written meanwhile stay as they are.
"""
from alembic import op

revision = "0150"
down_revision = "0149"
branch_labels = None
depends_on = None

#: Frozen text. A later revision that changes the function restates it.
UPGRADE_SQL = """
CREATE FUNCTION audit.pin_attribution() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE who uuid; holder uuid;
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  NEW.occurred_at := pg_catalog.now();
  IF NEW.actor_id IS NULL THEN
    RETURN NEW;
  END IF;
  who := iam.rls_actor();
  IF who IS NOT DISTINCT FROM NEW.actor_id THEN
    RETURN NEW;
  END IF;
  IF who IS NOT NULL THEN
    RAISE EXCEPTION 'audit.event: a connection bound to one user may not attribute a row to another'
      USING ERRCODE = '42501';
  END IF;
  SELECT t.user_id INTO holder
    FROM lab.download_ticket t
   WHERE t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
           nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''), 'UTF8'))
     AND t.redeemed_at IS NOT NULL
     AND t.redeemed_at > pg_catalog.now() - interval '5 minutes';
  IF holder IS NOT DISTINCT FROM NEW.actor_id THEN
    RETURN NEW;
  END IF;
  IF pg_catalog.jsonb_typeof(NEW.detail) = 'object' THEN
    NEW.detail := NEW.detail || pg_catalog.jsonb_build_object(
      'unverified_actor_id', NEW.actor_id::text);
  ELSE
    NEW.detail := pg_catalog.jsonb_build_object(
      'unverified_actor_id', NEW.actor_id::text, 'detail', NEW.detail);
  END IF;
  NEW.actor_id := NULL;
  RETURN NEW;
END $fn$;

CREATE TRIGGER audit_attribution BEFORE INSERT ON audit.event
  FOR EACH ROW EXECUTE FUNCTION audit.pin_attribution();

COMMENT ON FUNCTION audit.pin_attribution() IS
  'The request role may not date an audit row. A claimed actor must be the user its connection is bound to, or the holder of a ticket it spent: another user is refused, and a claim from a connection bound to nobody is kept in detail as unverified_actor_id with actor_id NULL (0150). Fires before audit_chain.';
"""

DOWNGRADE_SQL = """
DROP TRIGGER audit_attribution ON audit.event;
DROP FUNCTION audit.pin_attribution();
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
