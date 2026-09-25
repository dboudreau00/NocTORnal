"""A persona is one account on one platform, and a source says who reads it
and through which exit (the collection foundation, docs/00 decision 69,
2026-09-24).

## Personas

`collect.collection_account` gains:

- `platform`: the `collect.source_kind` whose sources the persona reads
  (XENFORO, MYBB, PHPBB, TELEGRAM or DISCORD). NULL for the existing
  venue-registered forum personas until somebody sets it.
- `platform_uid`: the persona's own durable account id on that platform,
  typed (`u:700000001`). Unique per platform.
- `last_request_at`: the per-persona request clock, so the gap between two
  requests as one account survives the process and is shared by workers.
- `status_changed_at`: when a person last moved the status.
- The MACHINE columns, which only `PersonaVault.signal()` writes and the
  human `set_status` never touches: `machine_hold_until` and
  `machine_hold_reason` (a platform-imposed wait: RATE_LIMITED, or
  ABANDONED for a session that outlived its budget), `machine_lock_code`
  and `machine_lock_at` (a platform refused the credential).

Keeping the machine's columns apart from the human's `status` is what makes
a platform's wait impossible to undo by hand in any number of steps, and a
human burn or lock possible at any moment, whatever the machine holds.

## The guard

`collect.guard_persona_holds()` runs BEFORE UPDATE OR DELETE on every row,
whoever writes it, and compares OLD with NEW whatever the status becomes:

- a live machine hold is never shortened or cleared;
- a machine lock clears only in the same UPDATE that stores a NEW sealed
  credential (the ciphertext changes and `secret_rotated_at` moves past the
  lock), never by a timestamp alone (an UPDATE that moves
  `secret_rotated_at` and clears the lock without a new ciphertext is
  refused);
- `machine_lock_at` never moves while its code stays set, except forward
  with a later lock;
- `secret_rotated_at` never moves without the ciphertext changing;
- `platform` and `platform_uid` never change once set;
- a persona bound to a platform is never deleted: it is burnt instead, so
  deleting one can never free its account or its exit.

## Sources

`collect.source` gains `collection_account_id` (the persona a source is
polled AS, one at a time) and `egress_profile_id` (the exit a PERSONA-LESS
source is read through). A source never carries both: a persona reads
through its own egress profile.

## Downgrade

Refuses while any source is bound (a persona or an exit) or any persona
names a platform: dropping them would silently unbind who reads what.
"""
from alembic import op

revision = "0082"
down_revision = "0081"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE collect.collection_account
  ADD COLUMN platform collect.source_kind,
  ADD COLUMN platform_uid text,
  ADD COLUMN last_request_at timestamptz,
  ADD COLUMN status_changed_at timestamptz,
  ADD COLUMN machine_hold_until timestamptz,
  ADD COLUMN machine_hold_reason text,
  ADD COLUMN machine_lock_code text,
  ADD COLUMN machine_lock_at timestamptz,
  ADD CONSTRAINT collection_account_platform_is_persona_kind
    CHECK (platform IS NULL
           OR platform IN ('XENFORO', 'MYBB', 'PHPBB', 'TELEGRAM', 'DISCORD')),
  ADD CONSTRAINT collection_account_uid_needs_platform
    CHECK (platform_uid IS NULL OR platform IS NOT NULL),
  ADD CONSTRAINT collection_account_uid_typed
    CHECK (platform_uid IS NULL
           OR platform_uid ~ '^[a-z]{1,8}:[A-Za-z0-9_.-]{1,128}$'),
  ADD CONSTRAINT collection_account_machine_hold_known
    CHECK ((machine_hold_until IS NULL) = (machine_hold_reason IS NULL)
           AND (machine_hold_reason IS NULL
                OR machine_hold_reason IN ('RATE_LIMITED', 'ABANDONED'))),
  ADD CONSTRAINT collection_account_machine_lock_known
    CHECK ((machine_lock_code IS NULL) = (machine_lock_at IS NULL)
           AND (machine_lock_code IS NULL
                OR machine_lock_code IN ('CREDENTIAL_REVOKED',
                                         'CREDENTIAL_DUPLICATED',
                                         'ACCOUNT_BANNED', 'WRONG_ACCOUNT',
                                         'PLATFORM_REFUSED')));

CREATE UNIQUE INDEX collection_account_platform_uid_unique
  ON collect.collection_account (platform, platform_uid)
  WHERE platform_uid IS NOT NULL;

COMMENT ON COLUMN collect.collection_account.platform IS
  'The source kind this persona reads as (a collect.source_kind). One account on one platform for life.';
COMMENT ON COLUMN collect.collection_account.platform_uid IS
  'The persona''s own durable account id on its platform, typed (u:700000001).';
COMMENT ON COLUMN collect.collection_account.last_request_at IS
  'The per-persona request clock: the gap between two requests as this account is measured from here.';
COMMENT ON COLUMN collect.collection_account.status_changed_at IS
  'When a person last moved the status. The machine columns have their own times.';
COMMENT ON COLUMN collect.collection_account.machine_hold_until IS
  'A wait the platform imposed (RATE_LIMITED) or a session that outlived its budget (ABANDONED). Written only by PersonaVault.signal, never shortened.';
COMMENT ON COLUMN collect.collection_account.machine_lock_code IS
  'The platform refused this persona''s credential. Cleared only by storing a new credential after the lock.';

ALTER TABLE collect.source
  ADD COLUMN collection_account_id uuid
    REFERENCES collect.collection_account(id),
  ADD COLUMN egress_profile_id uuid REFERENCES collect.egress_profile(id),
  ADD CONSTRAINT source_one_egress_binding
    CHECK (collection_account_id IS NULL OR egress_profile_id IS NULL);

CREATE INDEX source_collection_account_idx
  ON collect.source (collection_account_id)
  WHERE collection_account_id IS NOT NULL;
CREATE INDEX source_egress_profile_idx
  ON collect.source (egress_profile_id)
  WHERE egress_profile_id IS NOT NULL;

COMMENT ON COLUMN collect.source.collection_account_id IS
  'The persona this source is polled as, one at a time. It reads through that persona''s egress profile.';
COMMENT ON COLUMN collect.source.egress_profile_id IS
  'The exit a persona-less source is read through. Never set beside a persona.';

CREATE FUNCTION collect.guard_persona_holds() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.platform IS NOT NULL THEN
      RAISE EXCEPTION USING MESSAGE =
        'a persona bound to a platform account is never deleted: burn it instead';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.machine_hold_until IS NOT NULL
     AND OLD.machine_hold_until > clock_timestamp()
     AND (NEW.machine_hold_until IS NULL
          OR NEW.machine_hold_until < OLD.machine_hold_until) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a platform''s wait on a persona is never shortened: it ends when the platform said';
  END IF;
  IF OLD.machine_lock_code IS NOT NULL AND NEW.machine_lock_code IS NULL
     AND NOT (NEW.secret_ciphertext IS DISTINCT FROM OLD.secret_ciphertext
              AND coalesce(octet_length(NEW.secret_ciphertext), 0) > 0
              AND coalesce(NEW.secret_rotated_at > OLD.machine_lock_at, false)) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona locked over its credential comes back only with a new credential enrolled after the lock';
  END IF;
  IF OLD.machine_lock_code IS NOT NULL AND NEW.machine_lock_code IS NOT NULL
     AND NEW.machine_lock_at IS DISTINCT FROM OLD.machine_lock_at
     AND NOT coalesce(NEW.machine_lock_at > OLD.machine_lock_at, false) THEN
    RAISE EXCEPTION USING MESSAGE =
      'the time a persona was locked moves only forward, with a later lock';
  END IF;
  IF NEW.secret_rotated_at IS DISTINCT FROM OLD.secret_rotated_at
     AND NEW.secret_ciphertext IS NOT DISTINCT FROM OLD.secret_ciphertext THEN
    RAISE EXCEPTION USING MESSAGE =
      'a credential''s rotation time moves only when a new credential is stored';
  END IF;
  IF (OLD.platform IS NOT NULL AND NEW.platform IS DISTINCT FROM OLD.platform)
     OR (OLD.platform_uid IS NOT NULL
         AND NEW.platform_uid IS DISTINCT FROM OLD.platform_uid) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona is one account on one platform for life';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER collection_account_holds_guarded
  BEFORE UPDATE OR DELETE ON collect.collection_account
  FOR EACH ROW EXECUTE FUNCTION collect.guard_persona_holds();
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  bound bigint;
  placed bigint;
BEGIN
  SELECT count(*) INTO bound FROM collect.source
   WHERE collection_account_id IS NOT NULL OR egress_profile_id IS NOT NULL;
  SELECT count(*) INTO placed FROM collect.collection_account
   WHERE platform IS NOT NULL;
  IF bound > 0 OR placed > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0082: ' || bound
      || CASE WHEN bound = 1 THEN ' source is' ELSE ' sources are' END
      || ' bound to a persona or an exit and ' || placed
      || CASE WHEN placed = 1 THEN ' persona names' ELSE ' personas name' END
      || ' a platform; dropping them would silently unbind who reads what';
  END IF;
END
$pre$;

DROP TRIGGER IF EXISTS collection_account_holds_guarded ON collect.collection_account;
DROP FUNCTION IF EXISTS collect.guard_persona_holds();
DROP INDEX IF EXISTS collect.source_egress_profile_idx;
DROP INDEX IF EXISTS collect.source_collection_account_idx;
ALTER TABLE collect.source
  DROP CONSTRAINT IF EXISTS source_one_egress_binding,
  DROP COLUMN IF EXISTS egress_profile_id,
  DROP COLUMN IF EXISTS collection_account_id;
DROP INDEX IF EXISTS collect.collection_account_platform_uid_unique;
ALTER TABLE collect.collection_account
  DROP CONSTRAINT IF EXISTS collection_account_machine_lock_known,
  DROP CONSTRAINT IF EXISTS collection_account_machine_hold_known,
  DROP CONSTRAINT IF EXISTS collection_account_uid_typed,
  DROP CONSTRAINT IF EXISTS collection_account_uid_needs_platform,
  DROP CONSTRAINT IF EXISTS collection_account_platform_is_persona_kind,
  DROP COLUMN IF EXISTS machine_lock_at,
  DROP COLUMN IF EXISTS machine_lock_code,
  DROP COLUMN IF EXISTS machine_hold_reason,
  DROP COLUMN IF EXISTS machine_hold_until,
  DROP COLUMN IF EXISTS status_changed_at,
  DROP COLUMN IF EXISTS last_request_at,
  DROP COLUMN IF EXISTS platform_uid,
  DROP COLUMN IF EXISTS platform;
""")
