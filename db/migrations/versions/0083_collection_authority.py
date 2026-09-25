"""The two-person collection authority (collection foundation,
2026-09-24; docs/00 decision 69).

## Why

Nothing recorded authority to collect. docs/16 L3 and docs/18 A3 said the
build told passive from active collection through a flag that exists
nowhere, and the only control was a notice string. Every forum and Telegram
source now needs a written authority, recorded by one person and confirmed,
with each source under it, by another, before anything is read from it.
Public boards included; RSS is unchanged.

The authority itself is a document outside this system (a warrant, a
directed-surveillance or covert-source authorisation, an internal covert
online authorisation). This schema records who declared it and who confirmed
it; it cannot verify the document, and every screen that shows one says so.

## What this adds

- `collect.collection_authority`: one persona (or none, for public reading
  with nothing signed in), a scope (PUBLIC_READ or MEMBER_READ, and no
  active scope because nothing in the product posts, messages or buys), a
  classification that only ever rises, the reference, the issuer, the
  jurisdiction, the legal basis, a member-access reference for MEMBER_READ,
  what it covers, a window of at most 366 days, and who recorded, confirmed
  and revoked it. `recorded_by <> confirmed_by` is a CHECK.
- `collect.collection_authority_target`: each source under an authority,
  added by one person and confirmed by another (`added_by <> confirmed_by`).
  At insert it snapshots the source's address (`target_base_url`) and, for
  a persona-less authority, the egress profile the source is read through
  (`target_egress_profile_id`): a target covers its source
  only while both still match, so neither a moved address nor a re-pointed
  exit is covered by a confirmation that never saw it.
- Guards on both tables: never deleted or truncated, the recorded facts
  never rewritten, a confirmation or a revocation never changed once set,
  a revoked row never confirmed, and the classification never lowered.
- `authority_target_fits()`: a target is refused when its source is labelled
  above the authority, or when the source is read through a different
  binding than the authority covers.
- `raise_authority_labels()`: a source reclassified upward raises every
  authority that covers it.
- `collect.collection_run.authority_id` and `authority_target_id`: which
  authority every poll of an authority adapter ran under.
- Permissions `collection.authority.record` (COLLECTOR) and
  `collection.authority.confirm` (SECURITY_OFFICER), both step-up, and two
  separated duties: the confirmer's role never records one, and never runs
  the collection it covers. `iam.separated_duty` is written through its
  ledger guard, disabled by name for this run only.
- The runtime role keeps SELECT, INSERT and UPDATE on both tables and loses
  the DELETE 0060's default privileges handed it (`GUARDED_TABLES`). A role
  created after this upgrade needs that REVOKE by hand, as 0060's notes say.

## Downgrade

Refuses while any authority exists: a schema rollback does not destroy the
record of who authorised collection. On an empty table it drops everything
this added.
"""
from alembic import op

revision = "0083"
down_revision = "0082"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060's `APP_ROLE` spells it.
APP_ROLE = "noctornal_app"

#: Guarded against deletion without being append-only: the table and the
#: privileges the runtime role KEEPS on it. Read by
#: test_app_role_privileges_pg.py beside 0060's LEDGERS.
GUARDED_TABLES = {
    "collect.collection_authority": ("SELECT", "INSERT", "UPDATE"),
    "collect.collection_authority_target": ("SELECT", "INSERT", "UPDATE"),
}

#: (permission, description, requires_step_up, role).
PERMISSIONS: tuple[tuple[str, str, bool, str], ...] = (
    ("collection.authority.record",
     "Record a written authority to collect from forum and Telegram sources",
     True, "COLLECTOR"),
    ("collection.authority.confirm",
     "Confirm a recorded collection authority, and each source under it, as "
     "the second person",
     True, "SECURITY_OFFICER"),
)

#: (permission_a, permission_b, why), as 0062 declares its pairs; read by
#: test_approvals_catalogue.py.
SEPARATED_DUTIES: tuple[tuple[str, str, str], ...] = (
    ("collection.authority.confirm", "collection.authority.record",
     "the person who confirms a collection authority is not the person who "
     "recorded it"),
    ("collection.authority.confirm", "collection.run",
     "the role that confirms a collection authority does not run the "
     "collection it covers"),
)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _q(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def upgrade() -> None:
    run("""
CREATE TABLE collect.collection_authority (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  collection_account_id uuid REFERENCES collect.collection_account(id),
  scope                 text NOT NULL,
  classification        core.tlp NOT NULL,
  authority_ref         text NOT NULL,
  issued_by             text NOT NULL,
  jurisdiction          text NOT NULL,
  legal_basis           text NOT NULL,
  member_authority_ref  text,
  target_description    text NOT NULL,
  valid_from            timestamptz NOT NULL,
  valid_until           timestamptz NOT NULL,
  recorded_by           uuid NOT NULL REFERENCES iam.app_user(id),
  recorded_at           timestamptz NOT NULL DEFAULT now(),
  confirmed_by          uuid REFERENCES iam.app_user(id),
  confirmed_at          timestamptz,
  confirm_note          text,
  revoked_by            uuid REFERENCES iam.app_user(id),
  revoked_at            timestamptz,
  revoke_reason         text,
  CONSTRAINT collection_authority_scope_known
    CHECK (scope IN ('PUBLIC_READ', 'MEMBER_READ')),
  CONSTRAINT collection_authority_member_needs_persona
    CHECK (scope = 'PUBLIC_READ' OR collection_account_id IS NOT NULL),
  CONSTRAINT collection_authority_member_needs_reference
    CHECK (scope <> 'MEMBER_READ'
           OR length(btrim(coalesce(member_authority_ref, ''))) > 0),
  CONSTRAINT collection_authority_two_people
    CHECK (confirmed_by IS NULL OR confirmed_by <> recorded_by),
  CONSTRAINT collection_authority_confirm_complete
    CHECK ((confirmed_by IS NULL) = (confirmed_at IS NULL)
           AND (confirmed_by IS NULL) = (confirm_note IS NULL)),
  CONSTRAINT collection_authority_revocation_complete
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
           AND (revoked_at IS NULL) = (revoke_reason IS NULL)),
  CONSTRAINT collection_authority_window
    CHECK (valid_until > valid_from
           AND valid_until <= valid_from + interval '366 days'),
  CONSTRAINT collection_authority_referenced
    CHECK (length(btrim(authority_ref)) >= 3
           AND length(btrim(issued_by)) > 0
           AND length(btrim(jurisdiction)) > 1
           AND length(btrim(legal_basis)) > 0
           AND length(btrim(target_description)) > 20)
);
CREATE INDEX collection_authority_live_idx
  ON collect.collection_authority (collection_account_id, valid_until)
  WHERE revoked_at IS NULL AND confirmed_at IS NOT NULL;
CREATE INDEX collection_authority_pending_idx
  ON collect.collection_authority (recorded_at)
  WHERE confirmed_at IS NULL AND revoked_at IS NULL;

COMMENT ON TABLE collect.collection_authority IS
  'A written authority to collect, which exists outside this system: who declared it (recorded_by) and who confirmed it (confirmed_by, never the same person). Every forum and Telegram read needs one covering its source. Never deleted and never rewritten: revocation is a column, and the classification only rises.';

CREATE TABLE collect.collection_authority_target (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  authority_id             uuid NOT NULL
                           REFERENCES collect.collection_authority(id),
  source_id                uuid NOT NULL REFERENCES collect.source(id),
  added_by                 uuid NOT NULL REFERENCES iam.app_user(id),
  added_at                 timestamptz NOT NULL DEFAULT now(),
  target_base_url          text,
  target_egress_profile_id uuid REFERENCES collect.egress_profile(id),
  confirmed_by             uuid REFERENCES iam.app_user(id),
  confirmed_at             timestamptz,
  revoked_by               uuid REFERENCES iam.app_user(id),
  revoked_at               timestamptz,
  revoke_reason            text,
  CONSTRAINT authority_target_two_people
    CHECK (confirmed_by IS NULL OR confirmed_by <> added_by),
  CONSTRAINT authority_target_confirm_complete
    CHECK ((confirmed_by IS NULL) = (confirmed_at IS NULL)),
  CONSTRAINT authority_target_revocation_complete
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
           AND (revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE UNIQUE INDEX authority_target_once
  ON collect.collection_authority_target (authority_id, source_id)
  WHERE revoked_at IS NULL;
CREATE INDEX authority_target_source_idx
  ON collect.collection_authority_target (source_id)
  WHERE revoked_at IS NULL;

COMMENT ON TABLE collect.collection_authority_target IS
  'One source under a collection authority, added by one person and confirmed by another. Covers its source only while the source''s address equals target_base_url and, for a persona-less authority, its exit equals target_egress_profile_id. Never deleted.';
COMMENT ON COLUMN collect.collection_authority_target.target_base_url IS
  'The source''s address when the target was added: the address the confirmer was shown. Frozen.';
COMMENT ON COLUMN collect.collection_authority_target.target_egress_profile_id IS
  'For a persona-less authority, the exit the source was read through when the target was added. Frozen. NULL for a persona''s target.';

CREATE FUNCTION collect.guard_collection_authority() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'collect.collection_authority is never deleted: it is the record of who allowed collection (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.collection_account_id IS DISTINCT FROM OLD.collection_account_id
     OR NEW.scope IS DISTINCT FROM OLD.scope
     OR NEW.authority_ref IS DISTINCT FROM OLD.authority_ref
     OR NEW.issued_by IS DISTINCT FROM OLD.issued_by
     OR NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction
     OR NEW.legal_basis IS DISTINCT FROM OLD.legal_basis
     OR NEW.member_authority_ref IS DISTINCT FROM OLD.member_authority_ref
     OR NEW.target_description IS DISTINCT FROM OLD.target_description
     OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
     OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
     OR NEW.recorded_by IS DISTINCT FROM OLD.recorded_by
     OR NEW.recorded_at IS DISTINCT FROM OLD.recorded_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a collection authority cannot be rewritten: revoke it and record another';
  END IF;
  IF NEW.classification < OLD.classification THEN
    RAISE EXCEPTION USING MESSAGE =
      'a collection authority''s classification only rises';
  END IF;
  IF OLD.confirmed_at IS NOT NULL
     AND (NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
          OR NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
          OR NEW.confirm_note IS DISTINCT FROM OLD.confirm_note) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a confirmed collection authority stays confirmed as it was';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked collection authority cannot then be confirmed';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked collection authority stays revoked';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER collection_authority_guarded
  BEFORE UPDATE OR DELETE ON collect.collection_authority
  FOR EACH ROW EXECUTE FUNCTION collect.guard_collection_authority();
CREATE TRIGGER collection_authority_no_truncate
  BEFORE TRUNCATE ON collect.collection_authority
  FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_collection_authority();

CREATE FUNCTION collect.guard_collection_authority_target() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'collect.collection_authority_target is never deleted: it is the record of which source an authority covered (revoke it instead)';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
     OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.added_by IS DISTINCT FROM OLD.added_by
     OR NEW.added_at IS DISTINCT FROM OLD.added_at
     OR NEW.target_base_url IS DISTINCT FROM OLD.target_base_url
     OR NEW.target_egress_profile_id IS DISTINCT FROM OLD.target_egress_profile_id THEN
    RAISE EXCEPTION USING MESSAGE =
      'a source under a collection authority cannot be rewritten: revoke it and add it again';
  END IF;
  IF OLD.confirmed_at IS NOT NULL
     AND (NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
          OR NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a confirmed source under a collection authority stays confirmed as it was';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked source under a collection authority cannot then be confirmed';
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
          OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
          OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a revoked source under a collection authority stays revoked';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER collection_authority_target_guarded
  BEFORE UPDATE OR DELETE ON collect.collection_authority_target
  FOR EACH ROW EXECUTE FUNCTION collect.guard_collection_authority_target();
CREATE TRIGGER collection_authority_target_no_truncate
  BEFORE TRUNCATE ON collect.collection_authority_target
  FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_collection_authority_target();

CREATE FUNCTION collect.authority_target_fits() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  src record;
  auth record;
BEGIN
  SELECT classification, collection_account_id, base_url, egress_profile_id
    INTO src FROM collect.source WHERE id = NEW.source_id;
  SELECT classification, collection_account_id
    INTO auth FROM collect.collection_authority WHERE id = NEW.authority_id;
  IF src.classification > auth.classification THEN
    RAISE EXCEPTION USING MESSAGE =
      'an authority is never labelled below a source it covers: raise its classification first';
  END IF;
  IF src.collection_account_id IS DISTINCT FROM auth.collection_account_id THEN
    RAISE EXCEPTION USING MESSAGE =
      'this source is read through a different binding than the one this authority covers';
  END IF;
  NEW.target_base_url := src.base_url;
  NEW.target_egress_profile_id :=
    CASE WHEN auth.collection_account_id IS NULL
         THEN src.egress_profile_id ELSE NULL END;
  RETURN NEW;
END
$f$;

CREATE TRIGGER collection_authority_target_fits
  BEFORE INSERT ON collect.collection_authority_target
  FOR EACH ROW EXECUTE FUNCTION collect.authority_target_fits();

CREATE FUNCTION collect.raise_authority_labels() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.classification > OLD.classification THEN
    UPDATE collect.collection_authority a
       SET classification = NEW.classification
     WHERE a.classification < NEW.classification
       AND a.id IN (SELECT t.authority_id
                      FROM collect.collection_authority_target t
                     WHERE t.source_id = NEW.id);
  END IF;
  RETURN NULL;
END
$f$;

CREATE TRIGGER source_raises_authority_labels
  AFTER UPDATE OF classification ON collect.source
  FOR EACH ROW EXECUTE FUNCTION collect.raise_authority_labels();

ALTER TABLE collect.collection_run
  ADD COLUMN authority_id uuid REFERENCES collect.collection_authority(id),
  ADD COLUMN authority_target_id uuid
    REFERENCES collect.collection_authority_target(id),
  ADD CONSTRAINT collection_run_target_needs_authority
    CHECK (authority_target_id IS NULL OR authority_id IS NOT NULL);
COMMENT ON COLUMN collect.collection_run.authority_id IS
  'The confirmed authority this poll of a forum or Telegram source ran under.';
""")

    permissions = ",\n  ".join(
        f"({_q(key)}, {_q(description)}, {'true' if step_up else 'false'})"
        for key, description, step_up, _role in PERMISSIONS)
    grants = ",\n  ".join(f"({_q(role)}, {_q(key)})"
                          for key, _d, _s, role in PERMISSIONS)
    pairs = ",\n  ".join(f"({_q(a)}, {_q(b)}, {_q(why)})"
                         for a, b, why in SEPARATED_DUTIES)
    run(f"""
INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  {permissions}
ON CONFLICT (key) DO NOTHING;
INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  {grants}
ON CONFLICT (role_key, permission_key) DO NOTHING;

ALTER TABLE iam.separated_duty DISABLE TRIGGER separated_duty_written_by_ledger;
INSERT INTO iam.separated_duty (permission_a, permission_b, why) VALUES
  {pairs}
ON CONFLICT (permission_a, permission_b) DO NOTHING;
ALTER TABLE iam.separated_duty ENABLE TRIGGER separated_duty_written_by_ledger;

DO $pre$
DECLARE
  bad record;
BEGIN
  SELECT * INTO bad FROM iam.separated_duty_violations() LIMIT 1;
  IF FOUND THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to upgrade 0083: role ' || bad.role_key || ' holds both '
      || bad.permission_a || ' and ' || bad.permission_b
      || ', the two halves of one two-person control';
  END IF;
END
$pre$;
""")

    # After the CREATE TABLEs, never before: the DELETE being taken back is
    # the one 0060's default privileges handed out at creation. A no-op
    # where the role does not exist, for the reason 0060 gives.
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON collect.collection_authority FROM %I',
                   '{APP_ROLE}');
    EXECUTE format('REVOKE DELETE ON collect.collection_authority_target FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    keys = ", ".join(_q(key) for key, _d, _s, _r in PERMISSIONS)
    pair_match = " OR ".join(
        f"(permission_a = {_q(a)} AND permission_b = {_q(b)})"
        for a, b, _why in SEPARATED_DUTIES)
    run(f"""
DO $pre$
DECLARE
  n bigint;
BEGIN
  IF to_regclass('collect.collection_authority') IS NOT NULL THEN
    SELECT count(*) INTO n FROM collect.collection_authority;
    IF n > 0 THEN
      RAISE EXCEPTION USING MESSAGE =
        'refusing to downgrade 0083: ' || n
        || CASE WHEN n = 1 THEN ' collection authority is' ELSE ' collection authorities are' END
        || ' recorded, and a schema rollback does not destroy the record of '
        || 'who authorised collection';
    END IF;
  END IF;
END
$pre$;

DROP TRIGGER IF EXISTS source_raises_authority_labels ON collect.source;
DROP FUNCTION IF EXISTS collect.raise_authority_labels();
ALTER TABLE collect.collection_run
  DROP CONSTRAINT IF EXISTS collection_run_target_needs_authority,
  DROP COLUMN IF EXISTS authority_target_id,
  DROP COLUMN IF EXISTS authority_id;
DROP TABLE IF EXISTS collect.collection_authority_target;
DROP TABLE IF EXISTS collect.collection_authority;
DROP FUNCTION IF EXISTS collect.authority_target_fits();
DROP FUNCTION IF EXISTS collect.guard_collection_authority_target();
DROP FUNCTION IF EXISTS collect.guard_collection_authority();

ALTER TABLE iam.separated_duty DISABLE TRIGGER separated_duty_written_by_ledger;
DELETE FROM iam.separated_duty WHERE {pair_match};
ALTER TABLE iam.separated_duty ENABLE TRIGGER separated_duty_written_by_ledger;
DELETE FROM iam.role_permission WHERE permission_key IN ({keys});
DELETE FROM iam.permission WHERE key IN ({keys});
""")
