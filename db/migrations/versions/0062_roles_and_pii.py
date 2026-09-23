"""The owner's role decisions of 2026-09-22: the Lead investigator, victim PII
as two people by construction, and no role holding both halves of a
two-person control.

## "Keep the split"

The review of 2026-09-22 asked whether CASE_OWNER and SECURITY_OFFICER were
two roles or one role in two hats. The owner kept them apart: CASE_OWNER is
the law-enforcement or threat investigator who controls their case, and
SECURITY_OFFICER stays the independent overseer who cannot read case content
(docs/05). Three things follow, and this revision does all three.

## CASE_OWNER is displayed as "Lead investigator"

"Case owner" described a database relationship; the person holding the role
is the investigator leading the case, and that is what the console now calls
them. Only `display_name` and `description` move. The KEY stays `CASE_OWNER`,
because every permission check, every case assignment and every test reads
the key, and a renamed key would move all of them for a change that is about
a label.

## docs/17 F16: `victim_pii.reveal` goes to CASE_OWNER, `authorise` leaves it

Until today `victim_pii.reveal` was granted to no role, so the reveal route
refused everyone, and `victim_pii.authorise` was held by BOTH
SECURITY_OFFICER and CASE_OWNER. That second grant is what made the first one
unsafe to make: a role that may both authorise and reveal is one person
doing both, with the constraint `pii_authorisation_two_humans` as the only
thing between them and a colleague holding the same role.

So CASE_OWNER gains `reveal` and loses `authorise`, and authorising is the
Security Officer's alone. The reveal is then two different people by
construction rather than by convention. `grant_pii_authorisation` runs the
case-scoped gate, which reads the permission off the caller's ONE role on
that case: a Lead investigator on their own case holds `reveal` and not
`authorise`, and an officer assigned to the case as SECURITY_OFFICER holds
`authorise` and not `reveal` (and, as ever, no case content). Even the
first-run operator who holds both roles globally cannot authorise their own
reveal, because their assignment on the case is one role, not two.

### The authorisations a Lead investigator granted before today are revoked

Moving the grants is not enough on its own, and the verifier of 2026-09-22
showed why with a rolled-back reproduction. Before this revision a
CASE_OWNER held `authorise`, so one lead could authorise a co-lead on the
same case for up to 30 days (`granted_to <> granted_by` was satisfied).
Nobody held `reveal`, so that row opened nothing. After the grants above the
co-lead holds `reveal`, and `IngestService._live_authorisation` matches the
row on grantee, case, `revoked_at` and `expires_at`, never on who granted
it: the reveal the owner decided must take a Security Officer would have
gone through for up to a month with no Security Officer anywhere in it.

So the upgrade revokes every live authorisation whose grantor could not
grant it TODAY: one whose grantor holds no unexpired assignment on that case
under a role that carries `victim_pii.authorise`. That is exactly the
Lead-investigator grants, and it errs towards revoking in one further case
(an officer who has since left the case), where the grantee asks the
Security Officer again and nothing is lost that a second authorisation
cannot restore. Authorisations a Security Officer granted and still could
stand, which matters because `search_by_fingerprint` (correlation, gated on
`ingest.read`) has always been able to use them, so revoking every live row
would have taken away a working capability for no reason.

Each revocation writes an `audit.event` (`PII_AUTHORISATION_REVOKED`, actor
kind SYSTEM, as `scripts/bootstrap.py` and `rewrap_secrets.py` record their
own acts), naming the authorisation, both people and this migration, so the
grantee's next 451 has a reason on the record. The downgrade does NOT
un-revoke them: a revocation is an event that happened, and restoring an
authorisation nobody re-granted would be a second one nobody decided.

## docs/17 F14: break-glass holders are decided, and unchanged

`break_glass.invoke` stays with CASE_OWNER and SYS_ADMIN, and
`break_glass.review` stays with SECURITY_OFFICER only, as 0039 granted them.
Nothing is re-granted here. What IS new is the guard below, which makes
"the people who invoke are not the people who review" a property the
database keeps rather than one a later grant can quietly undo.

## `iam.separated_duty`: no role holds both halves of a two-person control

Each row names a pair of permissions that must never meet in one role, and a
trigger on `iam.role_permission` refuses the grant that would bring them
together. Three pairs are seeded:

- `victim_pii.authorise` / `victim_pii.reveal` (docs/17 F16, above);
- `break_glass.review` / `break_glass.invoke` (0039: "granting the review
  permission to anyone else would let a team review its own emergencies");
- `sample.preserved.authorise` / `sample.preserved.retrieve`, the
  preserved-sample pair migration 0063 creates for docs/17 F2. Named here
  before those permissions exist, which is harmless: the keys are text, not
  foreign keys, so a pair is inert until both halves are real.

A user may still hold two such roles globally (the first-run operator holds
four). That is deliberate and is not what this guards: the case-scoped gate
reads one role per case, and the service refuses `granted_to = granted_by`.
What this guards is a ROLE DEFINITION that would collapse the two people into
one for everybody who holds it, which no request-time check can see.

The upgrade refuses, by name, a database where some role already holds both
halves of a pair after the changes above. Installing a separation control
over a role definition that already violates it would report the control as
present while it is not, which is the quiet green this codebase keeps
finding; the operator resolves the grant and re-runs.
"""
from __future__ import annotations

from alembic import op

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None

#: The Lead investigator's label and what it means. The key is unchanged.
_LEAD_NAME = "Lead investigator"
_LEAD_DESCRIPTION = (
    "The law-enforcement or threat investigator who leads and controls their "
    "cases, including access grants. Reveals victim PII only under an "
    "authorisation a Security officer grants.")

#: What 0017 seeded, restored on downgrade.
_OLD_NAME = "Case owner"
_OLD_DESCRIPTION = "Full control of assigned cases including access grants."

#: The reason each transition revocation carries in its audit event.
_REVOKE_REASON = (
    "docs/17 F16, decided 2026-09-22: authorising a victim-PII reveal is the "
    "Security Officer's alone, and the grantor of this authorisation holds no "
    "role on the case that may authorise one. Ask the Security Officer for a "
    "new authorisation.")

#: (permission_a, permission_b, why). Order within a pair carries no meaning;
#: the trigger checks both directions.
SEPARATED_DUTIES: tuple[tuple[str, str, str], ...] = (
    ("victim_pii.authorise", "victim_pii.reveal",
     "docs/17 F16: whoever authorises a victim-PII reveal is not whoever "
     "performs it"),
    ("break_glass.review", "break_glass.invoke",
     "docs/17 F14: the role that reviews an emergency is never a role that "
     "can invoke one"),
    ("sample.preserved.authorise", "sample.preserved.retrieve",
     "docs/17 F2: retrieving a preserved rejected sample needs a second "
     "person's authorisation"),
)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _q(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def upgrade() -> None:
    pairs = ",\n  ".join(f"({_q(a)}, {_q(b)}, {_q(why)})"
                         for a, b, why in SEPARATED_DUTIES)
    run(f"""
SET search_path = iam, core, public;

UPDATE iam.role
   SET display_name = {_q(_LEAD_NAME)}, description = {_q(_LEAD_DESCRIPTION)}
 WHERE key = 'CASE_OWNER';

-- Revoke before granting, so the separation check below never sees the
-- intermediate state in which CASE_OWNER held both halves.
DELETE FROM iam.role_permission
 WHERE role_key = 'CASE_OWNER' AND permission_key = 'victim_pii.authorise';
INSERT INTO iam.role_permission (role_key, permission_key)
VALUES ('CASE_OWNER', 'victim_pii.reveal')
ON CONFLICT (role_key, permission_key) DO NOTHING;

CREATE TABLE iam.separated_duty (
  permission_a text NOT NULL,
  permission_b text NOT NULL,
  why          text NOT NULL,
  PRIMARY KEY (permission_a, permission_b),
  CONSTRAINT separated_duty_two_permissions CHECK (permission_a <> permission_b),
  CONSTRAINT separated_duty_says_why CHECK (length(btrim(why)) > 0)
);
COMMENT ON TABLE iam.separated_duty IS
  'Pairs of permissions no single role may hold together: the two halves of '
  'a two-person control. Enforced on iam.role_permission by trigger '
  'role_permission_separated_duty (migration 0062).';

INSERT INTO iam.separated_duty (permission_a, permission_b, why) VALUES
  {pairs};

-- Every (role, pair) where the role holds both halves. Used by the trigger
-- and by the pre-flight, so both refuse on the same reading.
CREATE FUNCTION iam.separated_duty_violations()
RETURNS TABLE (role_key text, permission_a text, permission_b text)
LANGUAGE sql STABLE AS $f$
  SELECT a.role_key, s.permission_a, s.permission_b
    FROM iam.separated_duty s
    JOIN iam.role_permission a ON a.permission_key = s.permission_a
    JOIN iam.role_permission b ON b.permission_key = s.permission_b
                              AND b.role_key = a.role_key
$f$;

CREATE FUNCTION iam.refuse_separated_duty_grant() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  other text;
  was_role text;
  was_permission text;
BEGIN
  -- On an UPDATE the row being replaced is still visible to the lookup
  -- below, and it is not a grant the role keeps. Without this, moving
  -- CASE_OWNER's reveal row to authorise in place was refused: the lookup
  -- found the very reveal row being replaced and counted it as the other
  -- half (verifier, 2026-09-22). ROW(...) IS DISTINCT FROM a pair of NULLs
  -- is true, so an INSERT, where these stay NULL, excludes nothing.
  IF TG_OP = 'UPDATE' THEN
    was_role := OLD.role_key;
    was_permission := OLD.permission_key;
  END IF;
  SELECT CASE WHEN s.permission_a = NEW.permission_key
              THEN s.permission_b ELSE s.permission_a END
    INTO other
    FROM iam.separated_duty s
    JOIN iam.role_permission rp
      ON rp.role_key = NEW.role_key
     AND rp.permission_key = CASE WHEN s.permission_a = NEW.permission_key
                                  THEN s.permission_b ELSE s.permission_a END
   WHERE NEW.permission_key IN (s.permission_a, s.permission_b)
     AND (rp.role_key, rp.permission_key)
         IS DISTINCT FROM (was_role, was_permission)
   LIMIT 1;
  IF other IS NOT NULL THEN
    -- One line, no DETAIL, for the reason 0059 gives: safe_detail forwards
    -- only the first line of a P0001.
    RAISE EXCEPTION USING MESSAGE =
      'role ' || NEW.role_key || ' already holds ' || other
      || ', and ' || NEW.permission_key || ' is the other half of the same'
      || ' two-person control (iam.separated_duty): one role holding both'
      || ' makes every holder of it both people';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER role_permission_separated_duty
  BEFORE INSERT OR UPDATE ON iam.role_permission
  FOR EACH ROW EXECUTE FUNCTION iam.refuse_separated_duty_grant();

-- A pair added later must not arrive already violated either.
CREATE FUNCTION iam.refuse_violated_separation() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  holder text;
BEGIN
  SELECT a.role_key INTO holder
    FROM iam.role_permission a
    JOIN iam.role_permission b ON b.role_key = a.role_key
   WHERE a.permission_key = NEW.permission_a
     AND b.permission_key = NEW.permission_b
   LIMIT 1;
  IF holder IS NOT NULL THEN
    RAISE EXCEPTION USING MESSAGE =
      'role ' || holder || ' already holds both ' || NEW.permission_a
      || ' and ' || NEW.permission_b || ': revoke one of them before'
      || ' declaring the pair separated';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER separated_duty_not_already_violated
  BEFORE INSERT OR UPDATE ON iam.separated_duty
  FOR EACH ROW EXECUTE FUNCTION iam.refuse_violated_separation();

DO $pre$
DECLARE
  found text;
BEGIN
  SELECT string_agg(role_key || ' holds ' || permission_a || ' and '
                    || permission_b, '; ' ORDER BY role_key)
    INTO found
    FROM iam.separated_duty_violations();
  IF found IS NOT NULL THEN
    RAISE EXCEPTION USING MESSAGE =
      'migration 0062 refuses to install the separated-duty guard over role'
      || ' definitions that already break it (' || found || '). Revoke one'
      || ' half of each pair from that role, then run alembic upgrade again';
  END IF;
END
$pre$;

-- The transition (docstring, "The authorisations a Lead investigator
-- granted before today are revoked"). After the grants above, so "could
-- grant it today" is read under the new rule.
WITH stale AS (
  UPDATE ingest.pii_authorisation pa
     SET revoked_at = now()
   WHERE pa.revoked_at IS NULL
     AND pa.expires_at > now()
     AND NOT EXISTS (
       SELECT 1
         FROM iam.case_assignment ca
         JOIN iam.role_permission rp ON rp.role_key = ca.role_key
        WHERE ca.case_id = pa.case_id
          AND ca.user_id = pa.granted_by
          AND (ca.expires_at IS NULL OR ca.expires_at > now())
          AND rp.permission_key = 'victim_pii.authorise')
  RETURNING pa.id, pa.case_id, pa.granted_to, pa.granted_by, pa.expires_at
)
INSERT INTO audit.event
       (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
SELECT NULL, 'SYSTEM', 'PII_AUTHORISATION_REVOKED', 'ingest', id, case_id,
       jsonb_build_object(
         'authorisation_id', id::text,
         'granted_to', granted_to::text,
         'granted_by', granted_by::text,
         'would_have_expired_at', expires_at,
         'by', 'migration 0062',
         'reason', {_q(_REVOKE_REASON)})
  FROM stale;
""")


def downgrade() -> None:
    # IF EXISTS on every drop, for one reason: this revision shipped first as
    # a no-op stub (2026-09-22, so ten groups could share one revision
    # chain), and databases stamped through the stub have none of these
    # objects. Downgrading one of them to 0061 must still work; everything
    # else below is already idempotent, so on such a database the downgrade
    # is correctly a no-op.
    run(f"""
SET search_path = iam, core, public;

DROP TRIGGER IF EXISTS role_permission_separated_duty ON iam.role_permission;
DROP TABLE IF EXISTS iam.separated_duty;
DROP FUNCTION IF EXISTS iam.refuse_violated_separation();
DROP FUNCTION IF EXISTS iam.refuse_separated_duty_grant();
DROP FUNCTION IF EXISTS iam.separated_duty_violations();

-- The grants as 0033 left them: reveal held by no role, authorise by
-- CASE_OWNER and SECURITY_OFFICER. The authorisations the upgrade revoked
-- stay revoked (docstring): a revocation happened, and undoing it here
-- would re-grant something nobody decided to grant.
DELETE FROM iam.role_permission
 WHERE role_key = 'CASE_OWNER' AND permission_key = 'victim_pii.reveal';
INSERT INTO iam.role_permission (role_key, permission_key)
VALUES ('CASE_OWNER', 'victim_pii.authorise')
ON CONFLICT (role_key, permission_key) DO NOTHING;

UPDATE iam.role
   SET display_name = {_q(_OLD_NAME)}, description = {_q(_OLD_DESCRIPTION)}
 WHERE key = 'CASE_OWNER';
""")
