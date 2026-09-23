"""Rejected samples preserved in their own store, two people to retrieve.

## The decision this implements (F2, owner, 2026-09-22)

Until this revision a rejection destroyed the sample: `reject()` deleted
the object from the samples bucket and zeroed `data_key_ciphertext`, on
the first click, by default. The review of 2026-09-22 found that
(ux13-lab:reject-one-click-destroy) and the owner decided the default:
**a rejected sample is PRESERVED, not destroyed.** Its ciphertext moves
into a separate, object-locked bucket under a per-object LEGAL HOLD, the
data key that can open it is kept, and getting it back out needs two
people: a Security Officer who authorises one named person for one
sample, and that person.

Destruction still exists, as a deployment decision rather than a click:
`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` restores the old
behaviour, and a legal hold on the sample or its case still refuses it.
Some prohibited material must not be kept at all, and whether a given
deployment is one of those is for counsel, not for this schema.

## What this adds

1. **Where a preserved sample went**, on `lab.sample`: `preserved_bucket`,
   `preserved_key`, `preserved_version_id` and `preserved_at`. The key is
   `preserved/<sha256[:2]>/<sha256>`, the same content-addressing the
   samples bucket uses, and the version id is recorded because the bucket
   is versioned (object lock forces it) and the legal hold is on ONE
   version. Three CHECKs hold the shape the service relies on:

   - the four columns are set together or not at all (the version id is
     allowed to be NULL, because a store that does not version returns
     none, and the service refuses such a store before it gets here);
   - only a REJECTED sample can be preserved;
   - a preserved sample KEEPS its data key. Preserving ciphertext while
     zeroing the only key that opens it would satisfy a preservation
     order in form and defeat it in substance, which is the exact
     objection `reject()`'s old comment raised against keeping bytes
     without the key. A constraint, so it holds against a future code
     path as well as this one.

2. **`lab.preservation_authorisation`**, modelled on
   `ingest.pii_authorisation` (0033): one row authorises ONE named person
   (`granted_to`) to retrieve ONE preserved sample, granted by somebody
   else (`granted_by`), with a written scope, a mandatory legal basis and
   an expiry no more than thirty days out. `granted_to <> granted_by` is
   a CHECK, so "two people" is a property of the table and not only of
   the endpoint. Revocation is a column, not a DELETE.

   Unlike its model it is guarded against being rewritten. A trigger
   refuses DELETE and TRUNCATE, and refuses an UPDATE that changes
   anything except the revocation and the retrieval counter, or that
   clears a revocation. The authorisation is the record of who allowed a
   hold-protected sample out of the building; a row that can be edited
   after the fact, or deleted once it has been used, is not a record.

   It is NOT one of 0060's ledgers, because revoking and counting are
   UPDATEs, so the runtime role keeps UPDATE and the row trigger bounds
   what an UPDATE may change. DELETE is another matter: 0060's default
   privileges hand `noctornal_app` DELETE on every table created after
   it, silently, and 0060's docstring says the migration that creates a
   guarded table must take that back itself. This one does, where the
   role exists. TRUNCATE needs no REVOKE (0060 never grants it; not being
   the owner is what denies it), and the statement trigger is for the
   deployments whose API still connects as the owner.

   `GUARDED_TABLES` below declares the table and exactly what the runtime
   role keeps on it, and `test_app_role_privileges_pg.py` reads that
   declaration beside 0060's `LEDGERS`: that file treats every table with
   a BEFORE TRUNCATE trigger as something a migration must account for,
   and until the verifier's pass of 2026-09-22 this one was unaccounted
   for and CI (which creates the role) failed on it.

3. **Two permissions**, both step-up:

   - `sample.preserved.authorise`, granted to SECURITY_OFFICER only;
   - `sample.preserved.retrieve`, granted to CASE_OWNER only.

   Neither role holds the other's verb, so the person who wants the
   material and the person who permits it are structurally different
   people, the same reasoning as victim PII (0033) and break-glass
   review. MALWARE_ANALYST holds neither: `sample.download` is about live
   samples in the working queue, and a rejected sample is not one.

4. **`lab.download_ticket.purpose`**, `download` (every existing row) or
   `preserved_retrieval`. A retrieval crosses to the sample origin on the
   same one-shot, sixty-second ticket a download does (0061), because the
   sample process serves the download path and nothing else; the purpose
   is how the redemption knows which permission to re-read and which
   store to read from. A ticket minted for one purpose can never be spent
   as the other.

## Downgrade

Refuses while any sample is preserved. Dropping the columns would leave
held objects in an object-locked bucket that no row names and nobody can
delete, which is the one outcome `submit()`'s row-first ordering exists
to prevent. Release nothing to downgrade: retrieve what you need, then
clear the rows deliberately.
"""
from alembic import op

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060's `APP_ROLE` spells
#: it. Migrations do not import each other, so the name is repeated here;
#: `test_app_role_privileges_pg.py` asserts what the role actually holds.
APP_ROLE = "noctornal_app"

#: Guarded against deletion without being append-only: the table, and the
#: privileges the runtime role KEEPS on it (everything else is absent).
#: Read by `test_app_role_privileges_pg.py` alongside 0060's `LEDGERS`.
GUARDED_TABLES = {
    "lab.preservation_authorisation": ("SELECT", "INSERT", "UPDATE"),
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = lab, core, public;

ALTER TABLE sample
  ADD COLUMN preserved_bucket     text,
  ADD COLUMN preserved_key        text,
  ADD COLUMN preserved_version_id text,
  ADD COLUMN preserved_at         timestamptz;

ALTER TABLE sample
  ADD CONSTRAINT sample_preservation_complete
    CHECK ((preserved_key IS NULL) = (preserved_bucket IS NULL)
       AND (preserved_key IS NULL) = (preserved_at IS NULL)
       AND (preserved_key IS NOT NULL OR preserved_version_id IS NULL)),
  ADD CONSTRAINT sample_preserved_only_when_rejected
    CHECK (preserved_key IS NULL OR state = 'REJECTED'),
  ADD CONSTRAINT sample_preserved_keeps_its_key
    CHECK (preserved_key IS NULL OR octet_length(data_key_ciphertext) > 0);

CREATE TABLE preservation_authorisation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id       uuid NOT NULL REFERENCES sample(id),
  granted_to      uuid NOT NULL REFERENCES iam.app_user(id),
  granted_by      uuid NOT NULL REFERENCES iam.app_user(id),
  -- What this release covers and why. A blanket authorisation is not
  -- one, so the floor is the same as victim PII's.
  scope_note      text NOT NULL,
  legal_basis     text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  revoked_by      uuid REFERENCES iam.app_user(id),
  retrieval_count integer NOT NULL DEFAULT 0,

  CONSTRAINT preservation_authorisation_two_people
    CHECK (granted_to <> granted_by),
  CONSTRAINT preservation_authorisation_is_time_boxed
    CHECK (expires_at > created_at
       AND expires_at <= created_at + interval '30 days'),
  CONSTRAINT preservation_authorisation_justified
    CHECK (length(btrim(scope_note)) > 20 AND length(btrim(legal_basis)) > 0),
  CONSTRAINT preservation_authorisation_revocation_complete
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
  CONSTRAINT preservation_authorisation_count_non_negative
    CHECK (retrieval_count >= 0)
);
CREATE INDEX preservation_authorisation_live_idx
  ON preservation_authorisation (granted_to, sample_id, expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX preservation_authorisation_sample_idx
  ON preservation_authorisation (sample_id, created_at DESC);

COMMENT ON TABLE preservation_authorisation IS
  'One named person may retrieve one preserved (rejected) sample, in its '
  'encrypted archive, until expires_at. Granted by somebody else. Never '
  'deleted and never rewritten: revocation is a column.';

CREATE FUNCTION lab.guard_preservation_authorisation() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'lab.preservation_authorisation is never deleted: it is the record of who allowed a held sample out (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.sample_id IS DISTINCT FROM OLD.sample_id
     OR NEW.granted_to IS DISTINCT FROM OLD.granted_to
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
     OR NEW.scope_note IS DISTINCT FROM OLD.scope_note
     OR NEW.legal_basis IS DISTINCT FROM OLD.legal_basis
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'a preservation authorisation cannot be rewritten; revoke it and grant another';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
                                     OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
    RAISE EXCEPTION 'a revoked preservation authorisation stays revoked';
  END IF;
  IF NEW.retrieval_count < OLD.retrieval_count THEN
    RAISE EXCEPTION 'the retrieval count on a preservation authorisation only rises';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER preservation_authorisation_guarded
  BEFORE UPDATE OR DELETE ON preservation_authorisation
  FOR EACH ROW EXECUTE FUNCTION lab.guard_preservation_authorisation();
CREATE TRIGGER preservation_authorisation_no_truncate
  BEFORE TRUNCATE ON preservation_authorisation
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_preservation_authorisation();

ALTER TABLE download_ticket
  ADD COLUMN purpose text NOT NULL DEFAULT 'download',
  ADD CONSTRAINT download_ticket_purpose_known
    CHECK (purpose IN ('download', 'preserved_retrieval'));
""")

    # A no-op where the role does not exist (every developer database and
    # the dev compose), for the reason 0060 gives: a REVOKE naming a missing
    # role is an error, not a no-op. After the CREATE TABLE above, never
    # before: the DELETE being taken back is the one 0060's default
    # privileges handed out the moment the table was created.
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON lab.preservation_authorisation FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")

    run("""
SET search_path = iam, core, public;

INSERT INTO permission (key, description, requires_step_up) VALUES
  ('sample.preserved.authorise',
   'Authorise one named person to retrieve one preserved (rejected) sample',
   true),
  ('sample.preserved.retrieve',
   'Retrieve a preserved sample, as its encrypted archive, under a live '
   'authorisation somebody else granted', true)
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
  ('SECURITY_OFFICER', 'sample.preserved.authorise'),
  ('CASE_OWNER', 'sample.preserved.retrieve')
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    # Every statement tolerates the objects being absent. Each group's
    # database clone reached 0065 through a no-op stub of this revision
    # (2026-09-22), so a downgrade through here can meet a schema this
    # upgrade never ran on; refusing there would strand the clone at 0063.
    run("""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = 'lab' AND table_name = 'sample'
                AND column_name = 'preserved_key') THEN
    IF EXISTS (SELECT 1 FROM lab.sample WHERE preserved_key IS NOT NULL) THEN
      RAISE EXCEPTION 'refusing to downgrade 0063: % sample(s) are preserved under a legal hold, and dropping the columns would leave held objects that no row names and nobody can delete',
        (SELECT count(*) FROM lab.sample WHERE preserved_key IS NOT NULL);
    END IF;
  END IF;
END $$;

DELETE FROM iam.role_permission WHERE permission_key IN
  ('sample.preserved.authorise', 'sample.preserved.retrieve');
DELETE FROM iam.permission WHERE key IN
  ('sample.preserved.authorise', 'sample.preserved.retrieve');

ALTER TABLE lab.download_ticket
  DROP CONSTRAINT IF EXISTS download_ticket_purpose_known,
  DROP COLUMN IF EXISTS purpose;

DROP TABLE IF EXISTS lab.preservation_authorisation;
DROP FUNCTION IF EXISTS lab.guard_preservation_authorisation();

ALTER TABLE lab.sample
  DROP CONSTRAINT IF EXISTS sample_preserved_keeps_its_key,
  DROP CONSTRAINT IF EXISTS sample_preserved_only_when_rejected,
  DROP CONSTRAINT IF EXISTS sample_preservation_complete,
  DROP COLUMN IF EXISTS preserved_at,
  DROP COLUMN IF EXISTS preserved_version_id,
  DROP COLUMN IF EXISTS preserved_key,
  DROP COLUMN IF EXISTS preserved_bucket;
""")
