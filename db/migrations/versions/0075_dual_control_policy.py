"""Which operations need two people, and which permission pairs no role may
hold, as data that changes only through two people (F9,
2026-09-24).

## What was wrong

The two-person policy lived in two places nobody could see or change
without a release: `approvals.OPERATIONS` in code, which says which
operations take a second signature, and `iam.separated_duty` (0062), which
says which permission pairs no single role may hold. The one switch that
did exist, `core.case.dual_control_merge` (0028), was per case and could be
turned off by one person. A unit whose standing orders say "every merge
takes two people" had no way to say so for the deployment, and nothing
recorded who had decided what.

## What this adds

1. Two permissions, held apart: `dual_control.manage` (SYS_ADMIN: propose
   and apply a change) and `dual_control.countersign` (SECURITY_OFFICER:
   countersign one), declared as a separated pair so no ROLE ever holds
   both. `iam.separated_duty` separates ROLES, not people: one account can
   hold both roles (the first-run account does). So the ledger trigger
   below also refuses a countersigner who holds `dual_control.manage`
   through any role (2026-09-24: otherwise one person holding SYS_ADMIN
   and SECURITY_OFFICER could change the policy alone through a second
   account they created).
2. `iam.dual_control_policy_change`, an append-only ledger. A row is a
   change; inserting one is the ONLY way the policy moves, and the insert
   is refused unless a `dual_control.policy` approval was consumed in the
   same transaction for exactly that change, by an active proposer holding
   `dual_control.manage` and an active countersigner holding
   `dual_control.countersign` and not `dual_control.manage`.
3. `iam.dual_control_operation`: the deployment's mode per configurable
   operation (`node.merge` today: PER_CASE, the 0028 behaviour, or
   ALWAYS). Only operations whose catalogue entry lists more than one mode
   get a row; the rest are ALWAYS by code, and the code reads a row only
   when it is one of the operation's own modes, so the table can make an
   operation stricter than its code floor and never looser.
4. `iam.separated_duty.origin`: 'migration' for every pair installed by a
   release or by the database owner, 'policy' for a pair a two-person
   change added. Only a 'policy' pair can be removed by a two-person change.
5. The countersigner's seven-day rule, `iam.countersign_blocked_by`: for
   seven days after SOMEONE ELSE resets or re-enrols an account's
   credentials, reactivates or unlocks it, or creates it with or grants it
   a role that countersigns, that account may not countersign; and for
   seven days after the countersigner does any of those to the PROPOSER's
   account (creating it or granting it a role that proposes), they may not
   countersign that proposer's change. The first direction stops one
   person with two administrator accounts taking over the officer; the
   second stops the officer who made the proposer's account. Both are
   checked by the API at the countersignature, with a sentence that says
   who and when, and again by this trigger at apply, against `decided_at`,
   which the previous revision pins to the database's clock.
6. Guards: the two policy tables change only from inside a trigger
   (`pg_trigger_depth`), and every such write must be exactly what a
   ledger row inserted in the same transaction says (that row's id, its
   operation and modes or its pair, and `applied_at = now()`, which the
   ledger's own trigger pins). Depth alone would accept a write from ANY
   trigger, and the runtime role can make one on a temporary table of its
   own, so without the binding a compromised API process could move the
   policy with no ledger row, no approval and no audit event (found
   2026-09-24). None of the three tables can be
   truncated, and the ledger is append-only. A later migration that must
   write `iam.separated_duty` or `iam.dual_control_operation` disables the
   guard trigger by name for its own run (the table COMMENTs say so and
   `test_approvals_catalogue.py` enforces it).

## What the database cannot tell

Whether the API process that raised and decided a request was honest. The
runtime role must be able to insert requests and record decisions, so a
compromised API process can forge both in two names. That is the ceiling
of every approval in the product (docs/05); the hash-chained audit trail
still records every step it did not forge.

## The lost-record guard

The upgrade refuses when `iam.separated_duty` already holds a pair whose
latest `DUAL_CONTROL_POLICY_CHANGED` audit event is an ADD: a pair a
two-person change added, whose ledger row a downgrade dropped. Upgrading
over it would relabel it 'migration', a pair nobody can remove from the
screen. The audit trail is append-only and survives the downgrade, so it
is the one record that can tell.

## Downgrade

Refuses while any operation is stricter than its default, or while any
pair a two-person change added still exists: dropping either would loosen
the policy by one person's hand. Otherwise it drops everything added here;
the audit trail keeps every change in full.
"""
from alembic import op

revision = "0075"
down_revision = "0074"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060's `APP_ROLE` spells it.
APP_ROLE = "noctornal_app"

#: The mode each configurable operation starts in: where 0028 left it.
DEFAULT_MODES = {"node.merge": "PER_CASE"}

#: The pair this revision declares: the proposer's and the countersigner's
#: halves of a policy change. Sorted, as the ledger stores pairs.
NEW_PAIR = (
    "dual_control.countersign", "dual_control.manage",
    "docs/05: a change to which operations need two people is proposed by "
    "one person and countersigned by another")

#: 0062's constant name, so every loader that collects declared pairs from
#: the migrations finds this one too (test_approvals_catalogue.py).
SEPARATED_DUTIES = (NEW_PAIR,)

#: How long an account stays unable to countersign after someone else
#: touched its credentials or its roles. The one place the window lives;
#: `iam.countersigner_seasoning()` returns it and Python reads it there.
SEASONING = "7 days"

#: The audit actions (all written by `iam_admin.py`) after which an account
#: may not countersign for SEASONING. ROLE_GRANTED and USER_CREATED count
#: only when the role carries the permission in question.
COUNTERSIGN_BLOCKING_EVENTS = (
    "PASSWORD_RESET", "TOTP_REENROLLED", "USER_REACTIVATED", "USER_UNLOCKED",
    "ROLE_GRANTED", "USER_CREATED")

#: Guarded without being plain ledgers: each keeps exactly these privileges
#: for the runtime role. All three carry a BEFORE TRUNCATE trigger. The two
#: policy tables keep their writes because the ledger's own trigger performs
#: them as the invoking role; what stops any other write is the guard
#: trigger, which accepts only a write a ledger row of the same transaction
#: names (item 6 above).
GUARDED_TABLES = {
    "iam.dual_control_policy_change": ("SELECT", "INSERT"),
    "iam.dual_control_operation": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "iam.separated_duty": ("SELECT", "INSERT", "UPDATE", "DELETE"),
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _q(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _in_list(values) -> str:
    return ", ".join(_q(v) for v in values)


_PLAIN_EVENTS = ("PASSWORD_RESET", "TOTP_REENROLLED", "USER_REACTIVATED",
                 "USER_UNLOCKED")


def upgrade() -> None:
    a, b, why = NEW_PAIR
    run(f"""
DO $pre$
DECLARE
  lost record;
BEGIN
  SELECT s.permission_a, s.permission_b, e.seq INTO lost
    FROM iam.separated_duty s
    CROSS JOIN LATERAL (
      SELECT ev.seq, ev.detail->>'change' AS change
        FROM audit.event ev
       WHERE ev.action = 'DUAL_CONTROL_POLICY_CHANGED'
         AND ev.detail->>'change' IN ('SEPARATED_DUTY_ADD', 'SEPARATED_DUTY_REMOVE')
         AND least(ev.detail->>'permission_a', ev.detail->>'permission_b')
             = least(s.permission_a, s.permission_b)
         AND greatest(ev.detail->>'permission_a', ev.detail->>'permission_b')
             = greatest(s.permission_a, s.permission_b)
       ORDER BY ev.seq DESC LIMIT 1) e
   WHERE e.change = 'SEPARATED_DUTY_ADD'
   LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to upgrade {revision}: iam.separated_duty holds '
      || lost.permission_a || ' and ' || lost.permission_b
      || ', which a two-person change added (audit event ' || lost.seq
      || ') and no change removed, and the record of that change did not'
      || ' survive a downgrade. Delete the pair by hand, upgrade, and add it'
      || ' again from Administration, Two-person controls';
  END IF;
END
$pre$;

INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  ('dual_control.manage',
   'Propose and apply a change to which operations need two people', true),
  ('dual_control.countersign',
   'Countersign a change to which operations need two people', true)
ON CONFLICT (key) DO NOTHING;

INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  ('SYS_ADMIN', 'dual_control.manage'),
  ('SECURITY_OFFICER', 'dual_control.countersign')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- Before any guard exists; 0062's separated_duty_not_already_violated
-- still checks that no role holds both halves.
INSERT INTO iam.separated_duty (permission_a, permission_b, why)
VALUES ({_q(a)}, {_q(b)}, {_q(why)})
ON CONFLICT (permission_a, permission_b) DO NOTHING;

CREATE TABLE iam.dual_control_policy_change (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Orders "the latest change naming a pair" without trusting applied_at,
  -- which is each transaction's start time.
  seq                 bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  approval_request_id uuid NOT NULL UNIQUE REFERENCES core.approval_request(id),
  change              text NOT NULL,
  operation           text,
  mode_from           text,
  mode_to             text,
  permission_a        text,
  permission_b        text,
  why                 text,
  based_on            uuid REFERENCES iam.dual_control_policy_change(id),
  requested_by        uuid NOT NULL REFERENCES iam.app_user(id),
  countersigned_by    uuid NOT NULL REFERENCES iam.app_user(id),
  applied_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT dual_control_change_known
    CHECK (change IN ('OPERATION_MODE', 'SEPARATED_DUTY_ADD', 'SEPARATED_DUTY_REMOVE')),
  CONSTRAINT dual_control_change_two_people
    CHECK (requested_by <> countersigned_by),
  CONSTRAINT dual_control_change_shape CHECK (
    (change = 'OPERATION_MODE' AND operation IS NOT NULL
     AND mode_from IN ('PER_CASE', 'ALWAYS') AND mode_to IN ('PER_CASE', 'ALWAYS')
     AND mode_from <> mode_to AND permission_a IS NULL AND permission_b IS NULL)
    OR (change <> 'OPERATION_MODE' AND operation IS NULL
        AND permission_a IS NOT NULL AND permission_b IS NOT NULL
        AND permission_a < permission_b)),
  CONSTRAINT dual_control_change_pair_says_why
    CHECK (change <> 'SEPARATED_DUTY_ADD' OR length(btrim(why)) >= 10)
);

ALTER TABLE iam.separated_duty
  ADD COLUMN origin text NOT NULL DEFAULT 'migration',
  ADD COLUMN added_at timestamptz,
  ADD COLUMN added_by_change uuid REFERENCES iam.dual_control_policy_change(id),
  ADD CONSTRAINT separated_duty_origin_known CHECK (origin IN ('migration', 'policy')),
  ADD CONSTRAINT separated_duty_policy_origin_named
    CHECK ((origin = 'policy') = (added_by_change IS NOT NULL));

CREATE TABLE iam.dual_control_operation (
  operation  text PRIMARY KEY,
  mode       text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT now(),
  change_id  uuid REFERENCES iam.dual_control_policy_change(id),
  CONSTRAINT dual_control_mode_known CHECK (mode IN ('PER_CASE', 'ALWAYS'))
);
INSERT INTO iam.dual_control_operation (operation, mode) VALUES
  {", ".join(f"({_q(k)}, {_q(v)})" for k, v in DEFAULT_MODES.items())};

CREATE FUNCTION iam.countersigner_seasoning() RETURNS interval
LANGUAGE sql IMMUTABLE AS $f$ SELECT interval {_q(SEASONING)} $f$;

-- Whether one audited account event counts against a countersignature:
-- the credential and lifecycle events always, a role grant or an account
-- creation only when the role carries `wanted`.
CREATE FUNCTION iam.countersign_event_counts(
    ev_action text, ev_detail jsonb, wanted text) RETURNS boolean
LANGUAGE sql STABLE AS $f$
  SELECT CASE
    WHEN ev_action IN ({_in_list(_PLAIN_EVENTS)}) THEN true
    WHEN ev_action = 'ROLE_GRANTED' THEN EXISTS (
      SELECT 1 FROM iam.role_permission rp
       WHERE rp.role_key = ev_detail->>'role' AND rp.permission_key = wanted)
    WHEN ev_action = 'USER_CREATED'
         AND jsonb_typeof(ev_detail->'roles') = 'array' THEN EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(ev_detail->'roles') AS r(role_key)
        JOIN iam.role_permission rp ON rp.role_key = r.role_key
       WHERE rp.permission_key = wanted)
    ELSE false
  END
$f$;

-- The latest event inside the window before `as_of` that stops `signer`
-- countersigning: one on the signer's account by anybody else, or, when
-- a proposer is named, one on the proposer's account by the signer.
-- ONE reader: the API's decide, its listing, the overview and the ledger
-- trigger all call this. `lookback` widens the window for the change
-- card's provenance line only; left NULL it is the seasoning window.
-- actor_id NULL (the first-run account, scripts on the server) is out of
-- scope: whoever holds the server shell holds the schema owner, which is
-- the stated ceiling.
CREATE FUNCTION iam.countersign_blocked_by(
    signer uuid, signer_permission text,
    as_of timestamptz DEFAULT now(),
    proposer uuid DEFAULT NULL, proposer_permission text DEFAULT NULL,
    lookback interval DEFAULT NULL)
RETURNS TABLE (action text, occurred_at timestamptz, actor_id uuid,
               subject_id uuid, role_key text)
LANGUAGE sql STABLE AS $f$
  SELECT e.action, e.occurred_at, e.actor_id, e.object_id,
         CASE WHEN e.action = 'ROLE_GRANTED' THEN e.detail->>'role' END
    FROM audit.event e
   WHERE e.object_type = 'app_user'
     AND e.object_id IN (signer, proposer)
     AND e.occurred_at > as_of - coalesce(lookback, iam.countersigner_seasoning())
     AND e.occurred_at <= as_of
     AND e.actor_id IS NOT NULL
     AND e.action IN ({_in_list(COUNTERSIGN_BLOCKING_EVENTS)})
     AND ((e.object_id = signer AND e.actor_id <> signer
           AND iam.countersign_event_counts(e.action, e.detail, signer_permission))
       OR (proposer IS NOT NULL AND e.object_id = proposer
           AND e.actor_id = signer
           AND iam.countersign_event_counts(e.action, e.detail, proposer_permission)))
   ORDER BY e.occurred_at DESC, e.seq DESC
   LIMIT 1
$f$;

CREATE FUNCTION iam.guard_dual_control_ledger() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION 'iam.dual_control_policy_change is append-only: a change is corrected by another change';
END
$f$;

CREATE TRIGGER dual_control_change_append_only
  BEFORE UPDATE OR DELETE ON iam.dual_control_policy_change
  FOR EACH ROW EXECUTE FUNCTION iam.guard_dual_control_ledger();
CREATE TRIGGER dual_control_change_no_truncate
  BEFORE TRUNCATE ON iam.dual_control_policy_change
  FOR EACH STATEMENT EXECUTE FUNCTION iam.guard_dual_control_ledger();

CREATE FUNCTION iam.check_dual_control_change() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  r record;
  p jsonb;
  blocked record;
  cur record;
  latest uuid;
BEGIN
  -- Serialises every policy change, so the reads below cannot race.
  PERFORM pg_advisory_xact_lock(hashtextextended('iam.dual_control_policy', 0));
  -- Pinned, never taken from the caller: the policy tables' guard accepts
  -- a write only when the ledger row naming it has applied_at = now(),
  -- which is what marks the row as inserted by this transaction.
  NEW.applied_at := now();

  SELECT a.operation, a.case_id, a.state, a.consumed_at, a.requested_by,
         a.decided_by, a.decided_at, a.payload
    INTO r FROM core.approval_request a WHERE a.id = NEW.approval_request_id;
  IF NOT FOUND OR r.operation IS DISTINCT FROM 'dual_control.policy'
     OR r.case_id IS NOT NULL THEN
    RAISE EXCEPTION 'a two-person policy change applies only a deployment-wide dual_control.policy approval';
  END IF;
  IF r.state IS DISTINCT FROM 'CONSUMED' OR r.consumed_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'a two-person policy change applies only an approval consumed in the same transaction';
  END IF;
  IF r.requested_by IS DISTINCT FROM NEW.requested_by
     OR r.decided_by IS DISTINCT FROM NEW.countersigned_by THEN
    RAISE EXCEPTION 'a two-person policy change names the two people on its approval';
  END IF;
  p := r.payload;
  IF p->>'change' IS DISTINCT FROM NEW.change
     OR p->>'operation' IS DISTINCT FROM NEW.operation
     OR p->>'from' IS DISTINCT FROM NEW.mode_from
     OR p->>'to' IS DISTINCT FROM NEW.mode_to
     OR p->>'permission_a' IS DISTINCT FROM NEW.permission_a
     OR p->>'permission_b' IS DISTINCT FROM NEW.permission_b
     OR p->>'why' IS DISTINCT FROM NEW.why
     OR p->>'based_on' IS DISTINCT FROM NEW.based_on::text THEN
    RAISE EXCEPTION 'a two-person policy change applies exactly what was countersigned';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM iam.app_user u
        JOIN iam.user_role ur ON ur.user_id = u.id
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE u.id = NEW.requested_by AND u.is_active
         AND rp.permission_key = 'dual_control.manage') THEN
    RAISE EXCEPTION 'the proposer is no longer an active account holding dual_control.manage: propose it again';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM iam.app_user u
        JOIN iam.user_role ur ON ur.user_id = u.id
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE u.id = NEW.countersigned_by AND u.is_active
         AND rp.permission_key = 'dual_control.countersign') THEN
    RAISE EXCEPTION 'the countersigner is no longer an active account holding dual_control.countersign: propose it again';
  END IF;
  -- iam.separated_duty keeps the two halves in different ROLES; this keeps
  -- them in different PEOPLE (2026-09-24).
  IF EXISTS (
      SELECT 1 FROM iam.user_role ur
        JOIN iam.role_permission rp ON rp.role_key = ur.role_key
       WHERE ur.user_id = NEW.countersigned_by
         AND rp.permission_key = 'dual_control.manage') THEN
    RAISE EXCEPTION 'the countersigner can also propose changes to which operations need two people, so they are not a second person: propose it again for a Security officer who is not an administrator';
  END IF;
  SELECT * INTO blocked FROM iam.countersign_blocked_by(
      NEW.countersigned_by, 'dual_control.countersign', r.decided_at,
      NEW.requested_by, 'dual_control.manage');
  IF FOUND THEN
    IF blocked.subject_id = NEW.countersigned_by THEN
      RAISE EXCEPTION '%', 'the countersigner''s account '
        || CASE blocked.action
             WHEN 'PASSWORD_RESET' THEN 'had its password reset'
             WHEN 'TOTP_REENROLLED' THEN 'had its authenticator re-enrolled'
             WHEN 'USER_REACTIVATED' THEN 'was reactivated'
             WHEN 'USER_UNLOCKED' THEN 'was unlocked'
             WHEN 'ROLE_GRANTED' THEN 'was given a role that countersigns'
             ELSE 'was created with a role that countersigns' END
        || ' by someone else in the seven days before they countersigned: propose it again';
    END IF;
    RAISE EXCEPTION '%', 'the countersigner '
      || CASE blocked.action
           WHEN 'PASSWORD_RESET' THEN 'reset the proposer''s password'
           WHEN 'TOTP_REENROLLED' THEN 're-enrolled the proposer''s authenticator'
           WHEN 'USER_REACTIVATED' THEN 'reactivated the proposer''s account'
           WHEN 'USER_UNLOCKED' THEN 'unlocked the proposer''s account'
           WHEN 'ROLE_GRANTED' THEN 'gave the proposer a role that proposes'
           ELSE 'created the proposer''s account' END
      || ' in the seven days before they countersigned: propose it again';
  END IF;

  IF NEW.change = 'OPERATION_MODE' THEN
    SELECT o.mode, o.change_id INTO cur
      FROM iam.dual_control_operation o
     WHERE o.operation = NEW.operation FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'no configurable two-person policy for %', NEW.operation;
    END IF;
    IF cur.mode IS DISTINCT FROM NEW.mode_from
       OR cur.change_id IS DISTINCT FROM NEW.based_on THEN
      RAISE EXCEPTION '% changed after this was countersigned (it is % now): propose it again',
        NEW.operation, cur.mode;
    END IF;
    RETURN NEW;
  END IF;

  SELECT c.id INTO latest FROM iam.dual_control_policy_change c
   WHERE c.change IN ('SEPARATED_DUTY_ADD', 'SEPARATED_DUTY_REMOVE')
     AND c.permission_a = NEW.permission_a AND c.permission_b = NEW.permission_b
   ORDER BY c.seq DESC LIMIT 1;
  IF latest IS DISTINCT FROM NEW.based_on THEN
    RAISE EXCEPTION 'the pair % and % changed after this was countersigned: propose it again',
      NEW.permission_a, NEW.permission_b;
  END IF;
  IF NEW.change = 'SEPARATED_DUTY_ADD' THEN
    IF (SELECT count(*) FROM iam.permission
         WHERE key IN (NEW.permission_a, NEW.permission_b)) <> 2 THEN
      RAISE EXCEPTION 'a separated pair names two permissions that exist';
    END IF;
    IF EXISTS (SELECT 1 FROM iam.separated_duty s
                WHERE (s.permission_a, s.permission_b) IN
                      ((NEW.permission_a, NEW.permission_b),
                       (NEW.permission_b, NEW.permission_a))) THEN
      RAISE EXCEPTION 'the pair % and % is already declared', NEW.permission_a, NEW.permission_b;
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM iam.separated_duty s
                     WHERE s.origin = 'policy'
                       AND (s.permission_a, s.permission_b) IN
                           ((NEW.permission_a, NEW.permission_b),
                            (NEW.permission_b, NEW.permission_a))) THEN
    RAISE EXCEPTION 'the pair % and % was not added by a two-person change, so a two-person change cannot remove it',
      NEW.permission_a, NEW.permission_b;
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER dual_control_change_checked
  BEFORE INSERT ON iam.dual_control_policy_change
  FOR EACH ROW EXECUTE FUNCTION iam.check_dual_control_change();

CREATE FUNCTION iam.apply_dual_control_change() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.change = 'OPERATION_MODE' THEN
    UPDATE iam.dual_control_operation
       SET mode = NEW.mode_to, changed_at = now(), change_id = NEW.id
     WHERE operation = NEW.operation;
  ELSIF NEW.change = 'SEPARATED_DUTY_ADD' THEN
    -- 0062's separated_duty_not_already_violated still fires, and refuses
    -- by role name, rolling the consume back with it.
    INSERT INTO iam.separated_duty
           (permission_a, permission_b, why, origin, added_at, added_by_change)
    VALUES (NEW.permission_a, NEW.permission_b, NEW.why, 'policy', now(), NEW.id);
  ELSE
    DELETE FROM iam.separated_duty
     WHERE origin = 'policy'
       AND (permission_a, permission_b) IN
           ((NEW.permission_a, NEW.permission_b),
            (NEW.permission_b, NEW.permission_a));
  END IF;
  RETURN NULL;
END
$f$;

CREATE TRIGGER dual_control_change_applied
  AFTER INSERT ON iam.dual_control_policy_change
  FOR EACH ROW EXECUTE FUNCTION iam.apply_dual_control_change();

CREATE FUNCTION iam.policy_changed_only_by_ledger() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  bound boolean := false;
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' is never truncated: it changes only through a two-person policy change';
  END IF;
  -- Depth 1 is a statement from outside any trigger. The ledger's AFTER
  -- INSERT trigger writes at depth 2.
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' changes only through a two-person policy change'
      || ' (iam.dual_control_policy_change); a migration that must write it'
      || ' disables trigger ' || TG_NAME || ' by name for its own run';
  END IF;
  IF TG_OP = 'DELETE' AND TG_TABLE_NAME = 'separated_duty' THEN
    IF OLD.origin = 'migration' THEN
      RAISE EXCEPTION 'a pair installed with the software or by the database owner is removed only the same way';
    END IF;
  END IF;
  -- Depth alone accepts a write from ANY trigger, and the runtime role can
  -- make one (a trigger on a temporary table of its own; PUBLIC holds
  -- TEMP). So the write must also be exactly what a ledger row inserted in
  -- THIS transaction says: the ledger pins applied_at to now(), the
  -- transaction's start, so a row from any earlier transaction never
  -- matches (F9, 2026-09-24).
  IF TG_TABLE_NAME = 'dual_control_operation' THEN
    IF TG_OP = 'UPDATE' THEN
      bound := NEW.operation = OLD.operation AND EXISTS (
        SELECT 1 FROM iam.dual_control_policy_change c
         WHERE c.id = NEW.change_id
           AND c.applied_at = now()
           AND c.change = 'OPERATION_MODE'
           AND c.operation = NEW.operation
           AND c.mode_from = OLD.mode
           AND c.mode_to = NEW.mode);
    END IF;
  ELSIF TG_OP = 'INSERT' THEN
    bound := NEW.origin = 'policy' AND EXISTS (
      SELECT 1 FROM iam.dual_control_policy_change c
       WHERE c.id = NEW.added_by_change
         AND c.applied_at = now()
         AND c.change = 'SEPARATED_DUTY_ADD'
         AND c.permission_a = NEW.permission_a
         AND c.permission_b = NEW.permission_b
         AND c.why IS NOT DISTINCT FROM NEW.why);
  ELSIF TG_OP = 'DELETE' THEN
    bound := EXISTS (
      SELECT 1 FROM iam.dual_control_policy_change c
       WHERE c.applied_at = now()
         AND c.change = 'SEPARATED_DUTY_REMOVE'
         AND c.permission_a = least(OLD.permission_a, OLD.permission_b)
         AND c.permission_b = greatest(OLD.permission_a, OLD.permission_b));
  END IF;
  IF bound IS NOT TRUE THEN
    RAISE EXCEPTION '%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
      || ' changes only as a two-person policy change applied in the same'
      || ' transaction says, and this ' || lower(TG_OP) || ' matches none';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$f$;

-- The name sorts after 0062's separated_duty_not_already_violated, so a
-- direct insert over a violating role still gets 0062's message first.
CREATE TRIGGER dual_control_operation_written_by_ledger
  BEFORE INSERT OR UPDATE OR DELETE ON iam.dual_control_operation
  FOR EACH ROW EXECUTE FUNCTION iam.policy_changed_only_by_ledger();
CREATE TRIGGER dual_control_operation_no_truncate
  BEFORE TRUNCATE ON iam.dual_control_operation
  FOR EACH STATEMENT EXECUTE FUNCTION iam.policy_changed_only_by_ledger();
CREATE TRIGGER separated_duty_written_by_ledger
  BEFORE INSERT OR UPDATE OR DELETE ON iam.separated_duty
  FOR EACH ROW EXECUTE FUNCTION iam.policy_changed_only_by_ledger();
CREATE TRIGGER separated_duty_no_truncate
  BEFORE TRUNCATE ON iam.separated_duty
  FOR EACH STATEMENT EXECUTE FUNCTION iam.policy_changed_only_by_ledger();

COMMENT ON TABLE iam.dual_control_policy_change IS
  'Append-only ledger of two-person policy changes. Inserting a row is the '
  'only way iam.dual_control_operation and iam.separated_duty change, and '
  'the insert is refused unless a dual_control.policy approval for exactly '
  'that change was consumed in the same transaction (migration '
  'dual_control_policy, F9 2026-09-24).';
COMMENT ON TABLE iam.dual_control_operation IS
  'The deployment mode (PER_CASE or ALWAYS) of each configurable two-person '
  'operation. Changes only through iam.dual_control_policy_change. A later '
  'migration that must write it runs ALTER TABLE iam.dual_control_operation '
  'DISABLE TRIGGER dual_control_operation_written_by_ledger and ENABLE '
  'TRIGGER dual_control_operation_written_by_ledger inside its own run.';
COMMENT ON TABLE iam.separated_duty IS
  'Pairs of permissions no single role may hold together: the two halves of '
  'a two-person control. Enforced on iam.role_permission by trigger '
  'role_permission_separated_duty (migration 0062). origin says who '
  'installed a pair: migration (a release or the database owner) or policy '
  '(a two-person change). Changes only through '
  'iam.dual_control_policy_change; a later migration that must write it runs '
  'ALTER TABLE iam.separated_duty DISABLE TRIGGER '
  'separated_duty_written_by_ledger and ENABLE TRIGGER '
  'separated_duty_written_by_ledger inside its own run.';
""")

    # A no-op where the role does not exist (every developer database and
    # the dev compose), in 0063's exact shape. After the CREATE TABLE
    # above: the UPDATE and DELETE being taken back are the ones 0060's
    # default privileges handed out the moment the ledger was created.
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE UPDATE, DELETE ON iam.dual_control_policy_change FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    a, b, _ = NEW_PAIR
    defaults = ", ".join(f"({_q(k)}, {_q(v)})" for k, v in DEFAULT_MODES.items())
    run(f"""
DO $pre$
DECLARE
  stricter text;
  pairs text;
  n integer;
  kept bigint;
BEGIN
  IF to_regclass('iam.dual_control_operation') IS NOT NULL THEN
    SELECT string_agg(o.operation || ' is ' || o.mode, ', ' ORDER BY o.operation)
      INTO stricter
      FROM iam.dual_control_operation o
      LEFT JOIN (VALUES {defaults}) AS d(operation, mode)
        ON d.operation = o.operation
     WHERE d.mode IS DISTINCT FROM o.mode;
    IF stricter IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'refusing to downgrade {revision}: ' || stricter || ', and dropping'
        || ' the policy would loosen it without two people; set it back from'
        || ' Administration, Two-person controls, then downgrade';
    END IF;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'iam' AND table_name = 'separated_duty'
                AND column_name = 'origin') THEN
    EXECUTE $q$SELECT count(*), string_agg(permission_a || ' and ' || permission_b,
                                            ', ' ORDER BY permission_a, permission_b)
                 FROM iam.separated_duty WHERE origin = 'policy'$q$
      INTO n, pairs;
    IF n > 0 THEN
      RAISE EXCEPTION USING MESSAGE =
        'refusing to downgrade {revision}: ' || n || CASE WHEN n = 1
          THEN ' pair was' ELSE ' pairs were' END
        || ' added by a two-person change (' || pairs || '); remove '
        || CASE WHEN n = 1 THEN 'it' ELSE 'them' END
        || ' from Administration, Two-person controls, then downgrade';
    END IF;
  END IF;
  IF to_regclass('iam.dual_control_policy_change') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM iam.dual_control_policy_change' INTO kept;
    RAISE NOTICE 'dropping iam.dual_control_policy_change (% rows); audit.event keeps every change in full as DUAL_CONTROL_POLICY_CHANGED', kept;
  END IF;
END
$pre$;

DROP TRIGGER IF EXISTS separated_duty_written_by_ledger ON iam.separated_duty;
DROP TRIGGER IF EXISTS separated_duty_no_truncate ON iam.separated_duty;
ALTER TABLE iam.separated_duty
  DROP CONSTRAINT IF EXISTS separated_duty_policy_origin_named,
  DROP CONSTRAINT IF EXISTS separated_duty_origin_known,
  DROP COLUMN IF EXISTS added_by_change,
  DROP COLUMN IF EXISTS origin,
  DROP COLUMN IF EXISTS added_at;
COMMENT ON TABLE iam.separated_duty IS
  'Pairs of permissions no single role may hold together: the two halves of '
  'a two-person control. Enforced on iam.role_permission by trigger '
  'role_permission_separated_duty (migration 0062).';
DROP TABLE IF EXISTS iam.dual_control_operation;
DROP TABLE IF EXISTS iam.dual_control_policy_change;
DELETE FROM iam.separated_duty
 WHERE (permission_a, permission_b) IN (({_q(a)}, {_q(b)}), ({_q(b)}, {_q(a)}));
DELETE FROM iam.role_permission
 WHERE (role_key, permission_key) IN (('SYS_ADMIN', 'dual_control.manage'),
                                      ('SECURITY_OFFICER', 'dual_control.countersign'));
DELETE FROM iam.permission
 WHERE key IN ('dual_control.manage', 'dual_control.countersign');
DROP FUNCTION IF EXISTS iam.policy_changed_only_by_ledger();
DROP FUNCTION IF EXISTS iam.apply_dual_control_change();
DROP FUNCTION IF EXISTS iam.check_dual_control_change();
DROP FUNCTION IF EXISTS iam.guard_dual_control_ledger();
DROP FUNCTION IF EXISTS iam.countersign_blocked_by(uuid, text, timestamptz, uuid, text, interval);
DROP FUNCTION IF EXISTS iam.countersign_event_counts(text, jsonb, text);
DROP FUNCTION IF EXISTS iam.countersigner_seasoning();
""")
