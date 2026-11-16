"""Where an exhibit's bytes now live, after a restore into a store that never held them
(decision 240, 2026-11-15).

## What was wrong

From 0139 an exhibit names the object-store VERSION it was lodged as, and every read asks for exactly
that version. A backup mirror keeps bytes and not version ids, and an upload cannot choose its version
id, so an exhibit restored into a new store read as missing and raised an integrity alarm. The only
recovery was an owner step that set every `storage_version_id` to NULL, which makes reads take whatever
is newest on the key and undoes the pin for good.

## What this adds

No table and no column, and no anchor is written: the exhibit's hashes, size, key, bucket and lodged
version stay as lodging fixed them (0140), and a court can read "lodged as X" beside "restored as Y".
The one column the restore tool moves is `core.evidence.retention_until`, forward only and only when the
restored lock ends later, in the transaction that appends the `RESTORED` row, as a lock extension moves it;
it is not an anchor and the guard lets it change.

- A custody action `RESTORED` on the hash-chained `core.evidence_custody`. The ledger has no CHECK on
  `action`, so no constraint changes. One such row says where verified bytes now live: its detail names
  `new_version_id` (the version the store gave the re-lodged object), `old_version_id` (the lodged one),
  the bucket, the lock's end and the run it belongs to.
- `core.evidence_current_version(p_evidence uuid)`, the version a read asks for: the `new_version_id` of
  the newest `RESTORED` row when there is one (NULL when that store keeps no versions, which reads the
  latest), otherwise `storage_version_id`. It reads under the caller's own row security, so a caller who
  cannot see the exhibit is answered NULL. A forged pointer buys nothing: every read still checks the
  SHA-256, the BLAKE3 and the hash-chained ACQUIRED row against the bytes it gets.
- `core.guard_custody_restored()`, BEFORE INSERT on `core.evidence_custody` for a `RESTORED` row only:
  the caller must be exempt from row security (the system role, which the restore job connects as, or
  the schema owner), and the row must name a `new_version_id` and attest a verified read-back
  (`hash_verified` true). The request role could otherwise write a `RESTORED` row as itself for an
  exhibit it can see, and redirect that exhibit's reads. The trigger is named to fire before
  `custody_chain`, so a refused row never takes the ledger's chain lock.

## Grants

None. The function reaches the request role through the default privileges 0108 set, as every function
in these schemas does; `scripts/runtime_roles.py` replays them. The trigger function is not called by a
role.

## Downgrade

Counts the exhibits that have been restored and refuses, naming the count and no value, before it
changes anything: the custody rows stay (the ledger is append-only), and dropping the function would
send every restored exhibit's reads back to a version its store never held, which reads as an integrity
alarm on each. A database that has restored is taken back by restoring a backup taken before 0198 was
applied (CONVENTIONS.md, Migrations; `db/README.md`, Downgrades that refuse). On an empty database it
never refuses.
"""
from alembic import op

revision = "0198"
down_revision = "0197"
branch_labels = None
depends_on = None

UPGRADE_SQL = """
CREATE FUNCTION core.evidence_current_version(p_evidence uuid) RETURNS text
  LANGUAGE sql STABLE
  SET search_path = pg_catalog, pg_temp
AS $f$
  SELECT CASE WHEN r.id IS NOT NULL THEN r.detail ->> 'new_version_id'
              ELSE e.storage_version_id END
    FROM core.evidence e
    LEFT JOIN LATERAL (
         SELECT c.id, c.detail
           FROM core.evidence_custody c
          WHERE c.evidence_id = e.id AND c.action = 'RESTORED'
          ORDER BY c.id DESC LIMIT 1) r ON true
   WHERE e.id = p_evidence
$f$;

COMMENT ON FUNCTION core.evidence_current_version(uuid) IS
  'The object version a read of this exhibit asks for: where the newest RESTORED custody row put the '
  'verified bytes, else the version the exhibit was lodged as. NULL reads the latest (decision 240, 0198).';

CREATE FUNCTION core.guard_custody_restored() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  IF NOT iam.rls_caller_exempt() THEN
    RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE =
      'core.evidence_custody: a RESTORED row is written by the restore job on a system connection, '
      || 'never by a request';
  END IF;
  IF NOT (NEW.detail ? 'new_version_id') THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'core.evidence_custody: a RESTORED row names the version the restored object was given '
      || '(new_version_id)';
  END IF;
  IF NEW.hash_verified IS DISTINCT FROM true THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'core.evidence_custody: a RESTORED row attests a read-back of the restored object that matched '
      || 'the recorded hashes';
  END IF;
  RETURN NEW;
END
$f$;

COMMENT ON FUNCTION core.guard_custody_restored() IS
  'A RESTORED custody row redirects an exhibit''s reads, so only an exempt caller writes one, and only '
  'one that names the new version and attests a verified read-back (decision 240, 0198).';

CREATE TRIGGER custody_a_restored_exempt_only
  BEFORE INSERT ON core.evidence_custody
  FOR EACH ROW WHEN (NEW.action = 'RESTORED')
  EXECUTE FUNCTION core.guard_custody_restored();
"""

DOWNGRADE_SQL = """
DROP TRIGGER custody_a_restored_exempt_only ON core.evidence_custody;
DROP FUNCTION core.guard_custody_restored();
DROP FUNCTION core.evidence_current_version(uuid);
"""

COUNT_SQL = """
SELECT count(DISTINCT evidence_id) FROM core.evidence_custody WHERE action = 'RESTORED'
"""


def downgrade_refusal(n: int) -> str:
    restored = "exhibit has" if n == 1 else "exhibits have"
    return (f"refusing to downgrade 0198: {n} {restored} been restored into a new object store, "
            "and their reads follow the RESTORED custody rows this revision's function resolves. "
            "Without it each would read a version its store never held and raise an integrity "
            "alarm. This revision's downgrade changed nothing, so the database is now at 0198 and "
            "the revisions above it are already undone. Run alembic upgrade head to return, or "
            "restore a backup taken before 0198 was applied.")


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
