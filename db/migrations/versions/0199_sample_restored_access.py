"""Where a preserved sample's ciphertext now lives, after a restore into a store that never held it
(decision 240, 2026-11-15).

## What was wrong

`lab.sample.preserved_version_id` names the held version a retrieval reads, written once at rejection
and guarded by nothing but the row's own CHECKs. A mirror to disk keeps neither the legal hold nor the
version id, so a preserved sample restored into a new store could not be read: the README said "nothing
in this release restores one".

## What this adds

The sample side of 0198, and nothing writes `lab.sample`.

- `RESTORED` joins the closed set of `lab.sample_access.action` (`sample_access_action_known`, restated
  with the eight it had). It stays a USER action: `sample_access_system_actions` is untouched, so a
  restore always names the account that answers for it. One row per restored sample; its detail names
  `new_version_id`, `old_version_id`, the bucket, the sample's SHA-256, whether the hold was read back,
  and the run it belongs to.
- `lab.sample_current_preserved_version(p_sample uuid)`, the version a retrieval reads: the
  `new_version_id` of the newest `RESTORED` row, else `preserved_version_id`. Under the caller's own row
  security, so a caller who cannot see the sample is answered NULL.
- `lab.guard_sample_restored()`, BEFORE INSERT on `lab.sample_access` for a `RESTORED` row only: an
  exempt caller (the system role the restore job connects as, or the schema owner), naming the new
  version and attesting a verified copy under a hold (`verified` and `hold_confirmed` both true in the
  detail). Named to fire before `sample_access_numbered`.

A forged pointer buys nothing: every retrieval still opens the ciphertext with the sample's data key and
compares the SHA-256 (`SampleService._verified_plaintext`), and a retrieval needs two people.

## Grants

None, for the reason 0198 gives.

## Downgrade

Counts the samples that have been restored and refuses, naming the count and no value, before it
changes anything: narrowing the action set would fail on their rows with a violation whose DETAIL prints
a row, and dropping the function would send each retrieval to a version its store never held. The way
back is a backup taken before 0199 was applied (CONVENTIONS.md, Migrations; `db/README.md`, Downgrades
that refuse). On an empty database it never refuses.
"""
from alembic import op

revision = "0199"
down_revision = "0198"
branch_labels = None
depends_on = None

_EIGHT = ("'VIEWED_META', 'DOWNLOADED', 'SHARED', 'DETONATED', 'REJECTED', 'ASSIGNED', "
          "'ANALYSED', 'SCANNED'")

UPGRADE_SQL = f"""
ALTER TABLE lab.sample_access DROP CONSTRAINT sample_access_action_known;
ALTER TABLE lab.sample_access ADD CONSTRAINT sample_access_action_known
  CHECK (action = ANY (ARRAY[{_EIGHT}, 'RESTORED']));

CREATE FUNCTION lab.sample_current_preserved_version(p_sample uuid) RETURNS text
  LANGUAGE sql STABLE
  SET search_path = pg_catalog, pg_temp
AS $f$
  SELECT CASE WHEN r.id IS NOT NULL THEN r.detail ->> 'new_version_id'
              ELSE s.preserved_version_id END
    FROM lab.sample s
    LEFT JOIN LATERAL (
         SELECT a.id, a.detail
           FROM lab.sample_access a
          WHERE a.sample_id = s.id AND a.action = 'RESTORED'
          ORDER BY a.id DESC LIMIT 1) r ON true
   WHERE s.id = p_sample
$f$;

COMMENT ON FUNCTION lab.sample_current_preserved_version(uuid) IS
  'The held version a retrieval of this sample reads: where the newest RESTORED access row put the '
  'verified ciphertext, else the version the sample was preserved as (decision 240, 0199).';

CREATE FUNCTION lab.guard_sample_restored() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  IF NOT iam.rls_caller_exempt() THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE =
      'lab.sample_access: a RESTORED row is written by the restore job on a system connection, '
      || 'never by a request';
  END IF;
  IF NOT (NEW.detail ? 'new_version_id') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'lab.sample_access: a RESTORED row names the version the restored object was given '
      || '(new_version_id)';
  END IF;
  IF (NEW.detail ->> 'verified') IS DISTINCT FROM 'true'
     OR (NEW.detail ->> 'hold_confirmed') IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'lab.sample_access: a RESTORED row attests a copy that opened to the sample''s SHA-256 and '
      || 'reads back under a legal hold (verified and hold_confirmed)';
  END IF;
  RETURN NEW;
END
$f$;

COMMENT ON FUNCTION lab.guard_sample_restored() IS
  'A RESTORED access row redirects a preserved sample''s retrievals, so only an exempt caller writes '
  'one, and only one that names the new version and attests a verified, held copy (decision 240, '
  '0199).';

CREATE TRIGGER sample_access_a_restored_exempt_only
  BEFORE INSERT ON lab.sample_access
  FOR EACH ROW WHEN (NEW.action = 'RESTORED')
  EXECUTE FUNCTION lab.guard_sample_restored();
"""

DOWNGRADE_SQL = f"""
DROP TRIGGER sample_access_a_restored_exempt_only ON lab.sample_access;
DROP FUNCTION lab.guard_sample_restored();
DROP FUNCTION lab.sample_current_preserved_version(uuid);
ALTER TABLE lab.sample_access DROP CONSTRAINT sample_access_action_known;
ALTER TABLE lab.sample_access ADD CONSTRAINT sample_access_action_known
  CHECK (action = ANY (ARRAY[{_EIGHT}]));
"""

COUNT_SQL = """
SELECT count(DISTINCT sample_id) FROM lab.sample_access WHERE action = 'RESTORED'
"""


def downgrade_refusal(n: int) -> str:
    restored = "sample has" if n == 1 else "samples have"
    return (f"refusing to downgrade 0199: {n} preserved {restored} been restored into a new object "
            "store, and their retrievals follow the RESTORED access rows this revision's function "
            "resolves. Without it each would read a held version its store never had. This "
            "revision's downgrade changed nothing, so the database is now at 0199 and the "
            "revisions above it are already undone. Run alembic upgrade head to return, or "
            "restore a backup taken before 0199 was applied.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(DOWNGRADE_SQL)
