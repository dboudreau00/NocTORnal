"""The Telegram specifics of a collection persona (roadmap F5.2,
2026-09-24).

## Why

The collection foundation (0082) made a persona one account on one
platform: `platform`, `platform_uid`, the machine holds and locks, and a
guard that keeps an account and its platform for life. A Telegram persona
needs three more facts the database holds rather than the code:

- when its sealed MTProto session was enrolled (`session_enrolled_at`,
  NULL again after a logout), so the poll can refuse a persona that has
  no session without opening the vault;
- that it names an egress profile from creation, keeps it for life, and
  never shares it with another Telegram persona in any status, BURNED
  included. Telegram links accounts that were seen from one address, so a
  burnt persona's exit is the one exit that must never carry the next
  persona;
- that it reads many chats through `collect.source.collection_account_id`
  and is registered on no venue source.

## What this adds

- `collection_account.session_enrolled_at`.
- CHECKs: an ENROLLED Telegram persona carries a typed user id
  (`u:<digits>`, never a bare positive, the form `telegram_id_norm`
  produces) and its five device fields (what Telegram is told the device
  is); an enrolment has an id and a sealed secret; a Telegram persona
  names an egress profile and no venue.
- `collection_account_telegram_egress_unique`: one Telegram persona per
  egress profile, over every status.
- `collect.guard_telegram_persona()`: a Telegram persona's egress profile
  never changes.

Holds, locks, deletion and platform identity are 0082's guard and are not
restated here.

## Why the typed-id and device CHECKs bind enrolled personas only

The collection foundation's own suites create TELEGRAM personas as a
stand-in platform with no device fields and account ids such as
`u:3f9a0b1c2d4e` (0082 accepts any namespaced id). Binding the Telegram
shape at enrolment holds it exactly where it matters: nothing but the
enrolment script writes `session_enrolled_at`, it writes the typed id and
the persona form requires the device fields, and no poll or act reads a
persona that has no enrolled session (2026-09-25).

## Upgrade

Refuses, naming the counts, when an existing Telegram persona has no
egress profile, a venue, or an egress profile another Telegram persona
holds: the constraints would fail on it, and retiring a persona silently
is not this migration's decision.

## Downgrade

Refuses while any persona has an enrolled session: dropping the column
loses when each session was enrolled. Otherwise drops everything added.
"""
from alembic import op

revision = "0105"
down_revision = "0104"
branch_labels = None
depends_on = None

#: The typed Telegram user id, as telegram.TELEGRAM_UID_PATTERN spells it
#: (test_telegram_ids holds the two equal).
UID_PATTERN = r"^u:[1-9][0-9]{0,19}$"

#: The device fields a Telegram persona tells Telegram, as
#: telegram.DEVICE_FIELDS lists them.
DEVICE_FIELDS = ("device_model", "system_version", "app_version",
                 "lang_code", "system_lang_code")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    fields = ", ".join(f"'{f}'" for f in DEVICE_FIELDS)
    run("""
DO $pre$
DECLARE
  no_exit bigint;
  on_venue bigint;
  shared bigint;
BEGIN
  SELECT count(*) INTO no_exit FROM collect.collection_account
   WHERE platform = 'TELEGRAM' AND egress_profile_id IS NULL;
  SELECT count(*) INTO on_venue FROM collect.collection_account
   WHERE platform = 'TELEGRAM' AND source_id IS NOT NULL;
  SELECT count(*) INTO shared FROM (
    SELECT egress_profile_id FROM collect.collection_account
     WHERE platform = 'TELEGRAM' AND egress_profile_id IS NOT NULL
     GROUP BY egress_profile_id HAVING count(*) > 1) s;
  IF no_exit + on_venue + shared > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to upgrade 0105: ' || no_exit
      || CASE WHEN no_exit = 1 THEN ' Telegram persona has' ELSE ' Telegram personas have' END
      || ' no egress profile, ' || on_venue
      || CASE WHEN on_venue = 1 THEN ' is' ELSE ' are' END
      || ' registered on a venue source and ' || shared
      || CASE WHEN shared = 1 THEN ' egress profile carries' ELSE ' egress profiles carry' END
      || ' more than one Telegram persona. Settle each by hand first.';
  END IF;
END
$pre$;
""")
    run(f"""
ALTER TABLE collect.collection_account
  ADD COLUMN session_enrolled_at timestamptz,
  ADD CONSTRAINT collection_account_telegram_uid_typed
    CHECK (platform IS DISTINCT FROM 'TELEGRAM' OR session_enrolled_at IS NULL
           OR platform_uid ~ '{UID_PATTERN}'),
  ADD CONSTRAINT collection_account_enrolled_has_uid
    CHECK (session_enrolled_at IS NULL OR platform_uid IS NOT NULL),
  ADD CONSTRAINT collection_account_enrolled_has_secret
    CHECK (session_enrolled_at IS NULL
           OR coalesce(octet_length(secret_ciphertext), 0) > 0),
  ADD CONSTRAINT collection_account_telegram_needs_egress
    CHECK (platform IS DISTINCT FROM 'TELEGRAM' OR egress_profile_id IS NOT NULL),
  ADD CONSTRAINT collection_account_telegram_has_no_venue
    CHECK (platform IS DISTINCT FROM 'TELEGRAM' OR source_id IS NULL),
  ADD CONSTRAINT collection_account_telegram_fingerprint
    CHECK (platform IS DISTINCT FROM 'TELEGRAM' OR session_enrolled_at IS NULL
           OR fingerprint_profile ?& ARRAY[{fields}]);

CREATE UNIQUE INDEX collection_account_telegram_egress_unique
  ON collect.collection_account (egress_profile_id)
  WHERE platform = 'TELEGRAM';

COMMENT ON COLUMN collect.collection_account.session_enrolled_at IS
  'When the sealed Telegram session was enrolled; NULL after a logout.';

CREATE FUNCTION collect.guard_telegram_persona() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF OLD.platform = 'TELEGRAM'
     AND NEW.egress_profile_id IS DISTINCT FROM OLD.egress_profile_id THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a Telegram persona keeps its egress profile for life';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER collection_account_telegram_guarded
  BEFORE UPDATE ON collect.collection_account
  FOR EACH ROW EXECUTE FUNCTION collect.guard_telegram_persona();
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM collect.collection_account
   WHERE session_enrolled_at IS NOT NULL;
  IF n > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0105: ' || n
      || CASE WHEN n = 1 THEN ' persona has' ELSE ' personas have' END
      || ' an enrolled Telegram session, and dropping the column loses when '
      || 'each was enrolled';
  END IF;
END
$pre$;

DROP TRIGGER IF EXISTS collection_account_telegram_guarded ON collect.collection_account;
DROP FUNCTION IF EXISTS collect.guard_telegram_persona();
DROP INDEX IF EXISTS collect.collection_account_telegram_egress_unique;
ALTER TABLE collect.collection_account
  DROP CONSTRAINT IF EXISTS collection_account_telegram_fingerprint,
  DROP CONSTRAINT IF EXISTS collection_account_telegram_has_no_venue,
  DROP CONSTRAINT IF EXISTS collection_account_telegram_needs_egress,
  DROP CONSTRAINT IF EXISTS collection_account_enrolled_has_secret,
  DROP CONSTRAINT IF EXISTS collection_account_enrolled_has_uid,
  DROP CONSTRAINT IF EXISTS collection_account_telegram_uid_typed,
  DROP COLUMN IF EXISTS session_enrolled_at;
""")
