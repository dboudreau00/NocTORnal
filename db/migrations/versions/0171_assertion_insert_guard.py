"""The request role cannot forge a claim as it is recorded
(graph-assertion-insert-unguarded, verifier N3, 2026-10-07).

## What was wrong

0135 closed UPDATE, DELETE and TRUNCATE on `core.assertion` to the runtime
roles and held the marks (`retracted_*`, `superseded_*`) to "once, from
NULL". Its triggers fire on UPDATE only, and INSERT stayed open because
recording a claim is the product's main write. Nothing looked at what an
INSERT NAMED. The verifier, bound to an AMBER analyst as `noctornal_app`,
ran four statements and all four succeeded:

1. a claim with `created_by` set to another user;
2. a claim with `recorded_at` 400 days in the past;
3. a claim inserted already retracted, with no author and no reason;
4. a claim inserted already superseded.

The policy on the table (`rls_gate`) asks only that the case and the element
be readable.
`graph.py` always passes the signed-in user, and `db.py` says the request
role cannot attribute a row to a user it is not bound to; for claims that was
a convention of the application and not a property of the database. A claim
is what a prosecution file cites: who said it, when it was recorded, and
whether it was withdrawn. Anyone who reaches SQL as the request role (an
injection, a compromised process) could plant an attributed, backdated claim
in that record, or hide a live one under a retraction nobody made.

## The fix: a trigger, not a policy

A BEFORE INSERT trigger, `assertion_insert_guarded`, the pattern 0150 set on
the audit log (`audit.pin_attribution`). The ledgers' other fix, 0151, is a
policy, and a policy cannot do the second item below: it can refuse a row but
not correct one. One mechanism says all three, and it fires before the
table's policy is checked.

A caller that row security exempts (`iam.rls_caller_exempt()`: the owner, a
member of the owner, a superuser, a BYPASSRLS role such as the system role)
is left exactly as it was. Any other caller, the request role, gets:

1. **A claim is recorded live.** A row inserted with any of `retracted_at`,
   `retracted_by`, `retraction_reason`, `superseded_at` or `superseded_by`
   set is refused. A retraction and a supersession are stamped afterwards,
   once, on a claim that exists (0135), and no writer in the product inserts
   a row already marked: `GraphWriteService._insert_assertion` names none of
   the five columns. The refusal is the plain exception 0135's mark guards
   raise.
2. **A claim names the person its connection is bound to.** `created_by`
   must equal `iam.rls_actor()`. A different user is refused with
   insufficient_privilege, as 0150 refuses an audit row: it is a forgery or a
   bug. Every request-role writer passes the signed-in user (the create
   routes, `add_assertion`, a correction, `supersede_assertion`, and
   `ProposalReview.accept`, whose `reviewed_by` is the analyst who accepted).
   A connection bound to NOBODY is refused as well. 0150 demotes a claim it
   cannot attribute to `unverified_actor_id`; `created_by` is NOT NULL and a
   claim is nothing without its author, so there is nothing to demote it to.
   The table's policy admits no case to an unbound connection already, so no
   honest write is lost: this makes the refusal the trigger's own and not a
   side effect of the case gate.
3. **`recorded_at` is the database's.** Whatever the statement supplied is
   replaced by `clock_timestamp()`. Not `now()`, which is the start of the
   caller's transaction: a request-role transaction held open (nothing sets
   `idle_in_transaction_session_timeout`) would date its claims by the time it
   began, which is how 0149 found the audit log forgeable in time. What a
   reader sees differently: two claims recorded in one transaction used to tie
   on `recorded_at` (the column default is `now()`) and now differ, in the
   order they were written. Nothing in the application compares a claim's
   `recorded_at` with a `now()`.

The function is SECURITY DEFINER with `search_path = pg_catalog, pg_temp`, as
0135's and 0150's are, because the exempt test and the binding read the IAM
plane. It reads the caller's role through `iam.rls_caller_exempt()` and not
through `current_user`, which inside a definer is the owner. Its name sorts it
first among the table's BEFORE INSERT triggers, ahead of
`assertion_supersedes_guarded`, so a forged row is refused before any other
trigger reads another claim.

## What the owner and the system role keep

The owner keeps full control (migrations, restores, the test suite's
teardown), and can disable the trigger by name as the table's comments say of
the other guards; the owner's password reaching the runtime services is
docs/17 F52, and what stops the owner is not this trigger.

The system role (`noctornal_worker`, BYPASSRLS) is how the product writes on
behalf of a person it has authenticated by other means, and every claim it
writes names a person it is not bound to: `scripts/bootstrap.py`,
`seed_showcase.py` and `seed_readme_showcase.py` (all
`connect_system(SystemPurpose.SCRIPT)`) record claims in the name of the
accounts they create, and the suites run an added claim, a retraction and a
supersession as it. It is exempt exactly as 0150 exempts it, from all three
rules.

## Residual

- The system role can still insert a claim naming any user, at any time,
  already marked. Nothing in the application does the last two; the first is
  its job. A process that holds the system role's DSN is trusted with the
  graph's attribution: the same boundary as the audit log's (docs/05).
- The system role can still retract naming any existing user. 0135 holds a
  runtime role's retraction to an existing person and, on a bound connection,
  to the person signed in; a system connection is bound to nobody, so only the
  first holds. Documented here, not fixed.
- As the person it is bound to, the request role can still insert a claim of
  any content (grade, rationale, `claim_value`, `prior_value`, `observed_at`)
  and, with `supersedes_id`, a replacement of a live claim on the same element,
  then stamp the replaced claim (0135 admits that stamp when the replacement
  names it). The replacement is attributed to that person and the old row is
  kept, but no audit row says it happened: only the supersede route writes
  one. What a claim says is the claimant's own statement and this trigger does
  not judge it.

## Downgrade

Drops the trigger and the function. Nothing else changed: no row is written by
this revision, and the claims written meanwhile stay as they are.
"""
from alembic import op

revision = "0171"
down_revision = "0170"
branch_labels = None
depends_on = None

#: Frozen text. A later revision that changes the function restates it.
UPGRADE_SQL = """
CREATE FUNCTION core.assertion_insert_guard() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE who uuid;
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF NEW.retracted_at IS NOT NULL OR NEW.retracted_by IS NOT NULL
     OR NEW.retraction_reason IS NOT NULL
     OR NEW.superseded_at IS NOT NULL OR NEW.superseded_by IS NOT NULL THEN
    RAISE EXCEPTION 'core.assertion: a claim is recorded live; a retraction or a supersession is stamped afterwards, once, on a claim that exists';
  END IF;
  who := iam.rls_actor();
  IF who IS NULL THEN
    RAISE EXCEPTION 'core.assertion: a claim is recorded by a connection bound to its author, and this one is bound to nobody'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.created_by IS DISTINCT FROM who THEN
    RAISE EXCEPTION 'core.assertion: a connection bound to one user may not attribute a claim to another'
      USING ERRCODE = '42501';
  END IF;
  NEW.recorded_at := pg_catalog.clock_timestamp();
  RETURN NEW;
END $fn$;

CREATE TRIGGER assertion_insert_guarded BEFORE INSERT ON core.assertion
  FOR EACH ROW EXECUTE FUNCTION core.assertion_insert_guard();

COMMENT ON FUNCTION core.assertion_insert_guard() IS
  'The request role records a claim live, as the user its connection is bound to, at the database''s time: a claim inserted already retracted or superseded, naming another user, or naming nobody bound is refused, and recorded_at is replaced by clock_timestamp(). The owner and the system role (row security exempt) are left as they were (0171). Fires before assertion_supersedes_guarded.';
"""

DOWNGRADE_SQL = """
DROP TRIGGER assertion_insert_guarded ON core.assertion;
DROP FUNCTION core.assertion_insert_guard();
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
