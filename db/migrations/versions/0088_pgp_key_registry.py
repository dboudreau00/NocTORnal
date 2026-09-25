"""A case key registry: what vendor key was obtained, from where, and who
compared its fingerprint with the one the actor published (F10b, comms,
2026-09-24).

## What was wrong

Every verification pasted a key into an ephemeral keyring and threw it
away: `comms.pgp_verification` kept neither the key nor where it came
from, and the fingerprint it was checked against was typed with no record
of where the actor published it. docs/16 C11 item 3 calls key provenance
"a HUMAN step, and an unrecorded one weakens the whole chain".

## What this adds

1. `comms.pgp_fingerprint_norm(text)`: the ONE normalisation of a
   published fingerprint (whitespace out, upper case, a leading 0X
   dropped). The ontology's `upper_hex_nospace` keeps a "0X" prefix that
   `pgp.normalise_fingerprint` strips, so a "0x" contact-block line passed
   Python and failed a trigger as a 500; the service now reads this
   function through SQL, and so do the triggers, so the two cannot differ.
2. `comms.pgp_key_acquisition`: one immutable row per thing obtained (the
   raw bytes, their digest, how they came in, where from), carrying the
   labels. Labels are fixed at the floor of what it cites: never below its
   case (`core.enforce_tlp_floor`, as nodes, exhibits and captures), never
   below a cited binding, block or exhibit (the guard). Deduplication is
   on the bytes, the source reference AND the labels, so an identically
   labelled import finds the row its caller could already see, and a RED
   import never answers an AMBER caller.
3. `comms.pgp_key`: one row per primary key gpg read from an acquisition,
   a CHILD of it (no labels of its own, so row-level security reads the
   acquisition's; docs/00 decision 76). Never born confirmed or retired;
   what gpg read is immutable; a confirmation is set once, never on a
   retired key, and when it cites a contact block line that line must
   list this key's primary fingerprint in a block of the same case filed
   within the key's labels (block <= key, held here too so direct SQL
   cannot skip it). A retirement is final.
4. The compartment binding by 0069's contract (docs/05): the 0059-form
   trigger on the acquisition's compartments and `ADDED_BOUND_COLUMNS`.
   The registry functions are not touched.
5. Neither table is ever deleted from: triggers refuse DELETE and TRUNCATE,
   and DELETE is revoked from the runtime role as 0063 does
   (`GUARDED_TABLES`). An acquisition UPDATE may only rename a compartment
   (same cardinality), which is what compartment_lifecycle's rename does.

## Downgrade

Refuses while either table has a row: dropping the registry would lose
where each key came from. Otherwise drops the triggers, the tables and the
functions.
"""
from alembic import op

revision = "0088"
down_revision = "0087"
branch_labels = None
depends_on = None

#: The least-privilege runtime role, spelled as 0060 spells it (migrations
#: do not import each other).
APP_ROLE = "noctornal_app"

#: Guarded against deletion without being append-only: each table and the
#: privileges the runtime role KEEPS. Read by test_app_role_privileges_pg.py.
GUARDED_TABLES = {
    "comms.pgp_key_acquisition": ("SELECT", "INSERT", "UPDATE"),
    "comms.pgp_key": ("SELECT", "INSERT", "UPDATE"),
}

#: The columns this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("comms", "pgp_key_acquisition", "compartments", "array"),
)

TRIGGER_NAME = "compartments_registered"


def trigger_sql(schema: str, table: str, column: str, kind: str) -> str:
    """The binding on one column: a local copy of 0059's `trigger_sql`
    (migrations do not import each other)."""
    when = (f"cardinality(NEW.{column}) > 0" if kind == "array"
            else f"NEW.{column} IS NOT NULL")
    return (
        f"CREATE TRIGGER {TRIGGER_NAME}\n"
        f'  BEFORE INSERT OR UPDATE OF {column} ON {schema}."{table}"\n'
        f"  FOR EACH ROW WHEN ({when})\n"
        f"  EXECUTE FUNCTION iam.refuse_unregistered_compartment("
        f"'{column}', '{kind}');")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


UPGRADE_SQL = """
CREATE FUNCTION comms.pgp_fingerprint_norm(v text) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN regexp_replace(
           upper(regexp_replace(coalesce(v, ''), '[[:space:]]', '', 'g')),
           '^0X', '');

COMMENT ON FUNCTION comms.pgp_fingerprint_norm(text) IS
  'The one normalisation of a published PGP fingerprint: whitespace out, '
  'upper case, a leading 0X dropped (F10b). The service and the triggers '
  'both read it, so they cannot disagree.';

CREATE TABLE comms.pgp_key_acquisition (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id            uuid NOT NULL REFERENCES core."case"(id),
  source             text NOT NULL,
  raw_bytes          bytea NOT NULL,
  raw_sha256         bytea NOT NULL,
  filename           text,
  source_ref         text NOT NULL,
  channel_binding_id uuid,
  contact_block_id   uuid,
  evidence_id        uuid REFERENCES core.evidence(id),
  classification     core.tlp NOT NULL,
  compartments       text[] NOT NULL DEFAULT '{}',
  requested_by       uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pgp_key_acquisition_source_known
    CHECK (source IN ('PASTE', 'FILE')),
  CONSTRAINT pgp_key_acquisition_raw_size
    CHECK (octet_length(raw_bytes) BETWEEN 1 AND 1000000),
  CONSTRAINT pgp_key_acquisition_digest_is_sha256
    CHECK (octet_length(raw_sha256) = 32),
  CONSTRAINT pgp_key_acquisition_filename_size
    CHECK (filename IS NULL OR length(filename) <= 255),
  CONSTRAINT pgp_key_acquisition_file_is_named
    CHECK ((source = 'FILE') = (filename IS NOT NULL)),
  CONSTRAINT pgp_key_acquisition_source_ref_size
    CHECK (length(btrim(source_ref)) BETWEEN 3 AND 2000),
  CONSTRAINT pgp_key_acquisition_id_case_key UNIQUE (id, case_id),
  CONSTRAINT pgp_key_acquisition_binding_same_case
    FOREIGN KEY (channel_binding_id, case_id)
    REFERENCES comms.channel_binding(id, case_id),
  CONSTRAINT pgp_key_acquisition_block_same_case
    FOREIGN KEY (contact_block_id, case_id)
    REFERENCES comms.contact_block(id, case_id)
);

CREATE UNIQUE INDEX pgp_key_acquisition_once
  ON comms.pgp_key_acquisition
     (case_id, source, raw_sha256, source_ref, classification, compartments)
  WHERE source IN ('PASTE', 'FILE');
CREATE INDEX pgp_key_acquisition_case_idx
  ON comms.pgp_key_acquisition (case_id, requested_at DESC);

COMMENT ON TABLE comms.pgp_key_acquisition IS
  'What vendor key material was obtained for a case, how and from where. '
  'Immutable and never deleted; carries the labels its keys are read under '
  '(F10b).';

CREATE TABLE comms.pgp_key (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id             uuid NOT NULL,
  acquisition_id      uuid NOT NULL,
  primary_fingerprint text NOT NULL,
  algorithm           integer NOT NULL,
  curve               text,
  key_bits            integer,
  key_created_at      timestamptz NOT NULL,
  key_expires_at      timestamptz,
  revoked             boolean NOT NULL,
  capabilities        text NOT NULL,
  subkeys             jsonb NOT NULL DEFAULT '[]',
  user_ids            jsonb NOT NULL DEFAULT '[]',
  material            text NOT NULL,
  material_sha256     bytea NOT NULL,
  confirmed_fingerprint text,
  confirmed_against   text,
  confirmed_contact_block_entry_id uuid
                        REFERENCES comms.contact_block_entry(id),
  confirmed_source_ref text,
  confirmation_statement text,
  confirmed_by        uuid REFERENCES iam.app_user(id),
  confirmed_at        timestamptz,
  retired_at          timestamptz,
  retired_by          uuid REFERENCES iam.app_user(id),
  retired_reason      text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT pgp_key_acquisition_same_case
    FOREIGN KEY (acquisition_id, case_id)
    REFERENCES comms.pgp_key_acquisition(id, case_id),
  CONSTRAINT pgp_key_fp_shape
    CHECK (primary_fingerprint ~ '^[0-9A-F]{40}$'
        OR primary_fingerprint ~ '^[0-9A-F]{64}$'),
  CONSTRAINT pgp_key_algorithm_range CHECK (algorithm BETWEEN 0 AND 255),
  CONSTRAINT pgp_key_bits_range
    CHECK (key_bits IS NULL OR key_bits BETWEEN 0 AND 65536),
  CONSTRAINT pgp_key_curve_size CHECK (curve IS NULL OR length(curve) <= 64),
  CONSTRAINT pgp_key_capabilities_shape
    CHECK (capabilities ~ '^[A-Za-z?]{0,32}$'),
  CONSTRAINT pgp_key_material_size
    CHECK (length(material) BETWEEN 1 AND 1000000),
  CONSTRAINT pgp_key_material_digest_is_sha256
    CHECK (octet_length(material_sha256) = 32),
  CONSTRAINT pgp_key_against_known
    CHECK (confirmed_against IS NULL
        OR confirmed_against IN ('CONTACT_BLOCK', 'PUBLISHED_ELSEWHERE')),
  CONSTRAINT pgp_key_source_ref_size
    CHECK (confirmed_source_ref IS NULL OR length(confirmed_source_ref) <= 2000),
  CONSTRAINT pgp_key_statement_size
    CHECK (confirmation_statement IS NULL
        OR length(confirmation_statement) <= 2000),
  CONSTRAINT pgp_key_confirmation_complete
    CHECK ((confirmed_fingerprint IS NULL) = (confirmed_against IS NULL)
       AND (confirmed_fingerprint IS NULL) = (confirmed_by IS NULL)
       AND (confirmed_fingerprint IS NULL) = (confirmed_at IS NULL)),
  CONSTRAINT pgp_key_confirms_its_own_fingerprint
    CHECK (confirmed_fingerprint IS NULL
        OR confirmed_fingerprint = primary_fingerprint),
  CONSTRAINT pgp_key_confirmation_names_its_basis
    CHECK (confirmed_against IS NULL
        OR (confirmed_against = 'CONTACT_BLOCK'
            AND confirmed_contact_block_entry_id IS NOT NULL
            AND confirmed_source_ref IS NULL)
        OR (confirmed_against = 'PUBLISHED_ELSEWHERE'
            AND confirmed_contact_block_entry_id IS NULL
            AND length(btrim(coalesce(confirmed_source_ref, ''))) >= 3)),
  CONSTRAINT pgp_key_statement_needs_confirmation
    CHECK (confirmation_statement IS NULL OR confirmed_at IS NOT NULL),
  CONSTRAINT pgp_key_retirement_complete
    CHECK ((retired_at IS NULL) = (retired_by IS NULL)
       AND (retired_at IS NULL) = (retired_reason IS NULL)
       AND (retired_reason IS NULL OR length(btrim(retired_reason)) >= 3)),
  CONSTRAINT pgp_key_once_per_acquisition UNIQUE (acquisition_id, primary_fingerprint),
  CONSTRAINT pgp_key_id_case_key UNIQUE (id, case_id)
);
CREATE INDEX pgp_key_case_idx ON comms.pgp_key (case_id, created_at DESC);
CREATE INDEX pgp_key_fingerprint_idx ON comms.pgp_key (primary_fingerprint);

COMMENT ON TABLE comms.pgp_key IS
  'One primary key gpg read from an acquisition. A child of the acquisition '
  '(its labels). Never born confirmed; confirmed once, against a contact '
  'block line or a publication elsewhere; retired, never deleted (F10b).';

-- The acquisition's guard. Its labels are fixed at what it cites: a
-- floor set only in the service can be skipped by the next writer.
CREATE FUNCTION comms.guard_pgp_key_acquisition() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  cited_cls core.tlp;
  cited_comp text[];
  cited_case uuid;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key acquisition is the record of what was obtained and from where; it is never deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.case_id, NEW.source, NEW.raw_bytes, NEW.raw_sha256,
        NEW.filename, NEW.source_ref, NEW.channel_binding_id,
        NEW.contact_block_id, NEW.evidence_id, NEW.classification,
        NEW.requested_by, NEW.requested_at)
       IS DISTINCT FROM
       (OLD.id, OLD.case_id, OLD.source, OLD.raw_bytes, OLD.raw_sha256,
        OLD.filename, OLD.source_ref, OLD.channel_binding_id,
        OLD.contact_block_id, OLD.evidence_id, OLD.classification,
        OLD.requested_by, OLD.requested_at)
       OR cardinality(NEW.compartments) <> cardinality(OLD.compartments) THEN
      RAISE EXCEPTION 'an acquisition''s record and labels are fixed; only a compartment rename may touch them';
    END IF;
    RETURN NEW;
  END IF;
  -- INSERT: the case's compartments and every cited object's labels are
  -- a floor (the case's classification is core.enforce_tlp_floor's).
  IF NOT (NEW.compartments @> (SELECT compartments FROM core."case"
                                WHERE id = NEW.case_id)) THEN
    RAISE EXCEPTION 'an acquisition carries at least its case''s compartments';
  END IF;
  IF NEW.evidence_id IS NOT NULL THEN
    SELECT case_id, classification, compartments
      INTO cited_case, cited_cls, cited_comp
      FROM core.evidence WHERE id = NEW.evidence_id;
    IF cited_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the exhibit belongs to another case';
    END IF;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the exhibit it cites';
    END IF;
  END IF;
  IF NEW.channel_binding_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the channel binding it cites';
    END IF;
  END IF;
  IF NEW.contact_block_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.contact_block WHERE id = NEW.contact_block_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the contact block it cites';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pgp_key_acquisition_guarded
  BEFORE INSERT OR UPDATE OR DELETE ON comms.pgp_key_acquisition
  FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key_acquisition();
CREATE TRIGGER pgp_key_acquisition_no_truncate
  BEFORE TRUNCATE ON comms.pgp_key_acquisition
  FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key_acquisition();
CREATE TRIGGER acquisition_tlp
  BEFORE INSERT OR UPDATE ON comms.pgp_key_acquisition
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

-- The key's guard.
CREATE FUNCTION comms.guard_pgp_key() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  entry_case uuid;
  entry_type text;
  entry_value text;
  block_cls core.tlp;
  block_comp text[];
  acq_cls core.tlp;
  acq_comp text[];
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a vendor key record is never deleted: retire it';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.confirmed_at IS NOT NULL OR NEW.confirmed_fingerprint IS NOT NULL
       OR NEW.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'a key is never born confirmed or retired';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.id, NEW.case_id, NEW.acquisition_id, NEW.primary_fingerprint,
      NEW.algorithm, NEW.curve, NEW.key_bits, NEW.key_created_at,
      NEW.key_expires_at, NEW.revoked, NEW.capabilities, NEW.subkeys,
      NEW.user_ids, NEW.material, NEW.material_sha256, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.case_id, OLD.acquisition_id, OLD.primary_fingerprint,
      OLD.algorithm, OLD.curve, OLD.key_bits, OLD.key_created_at,
      OLD.key_expires_at, OLD.revoked, OLD.capabilities, OLD.subkeys,
      OLD.user_ids, OLD.material, OLD.material_sha256, OLD.created_at) THEN
    RAISE EXCEPTION 'what gpg read from a key is fixed';
  END IF;
  IF OLD.retired_at IS NOT NULL
     AND (NEW.retired_at, NEW.retired_by, NEW.retired_reason)
         IS DISTINCT FROM (OLD.retired_at, OLD.retired_by, OLD.retired_reason) THEN
    RAISE EXCEPTION 'a retired key stays retired';
  END IF;
  IF (NEW.confirmed_fingerprint, NEW.confirmed_against,
      NEW.confirmed_contact_block_entry_id, NEW.confirmed_source_ref,
      NEW.confirmation_statement, NEW.confirmed_by, NEW.confirmed_at)
     IS NOT DISTINCT FROM
     (OLD.confirmed_fingerprint, OLD.confirmed_against,
      OLD.confirmed_contact_block_entry_id, OLD.confirmed_source_ref,
      OLD.confirmation_statement, OLD.confirmed_by, OLD.confirmed_at) THEN
    RETURN NEW;
  END IF;
  IF OLD.confirmed_at IS NOT NULL THEN
    RAISE EXCEPTION 'a key''s confirmation is made once and never changed';
  END IF;
  IF OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retired key is not confirmed';
  END IF;
  IF NEW.confirmed_contact_block_entry_id IS NOT NULL THEN
    SELECT b.case_id, e.selector_type, e.durable_value,
           b.classification, b.compartments
      INTO entry_case, entry_type, entry_value, block_cls, block_comp
      FROM comms.contact_block_entry e
      JOIN comms.contact_block b ON b.id = e.block_id
     WHERE e.id = NEW.confirmed_contact_block_entry_id;
    IF entry_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the contact block line belongs to another case';
    END IF;
    IF entry_type IS DISTINCT FROM 'PGP_FPR' THEN
      RAISE EXCEPTION 'the contact block line is not a PGP fingerprint';
    END IF;
    IF comms.pgp_fingerprint_norm(entry_value) <> NEW.primary_fingerprint THEN
      RAISE EXCEPTION 'the contact block line lists a different fingerprint than this key''s';
    END IF;
    SELECT classification, compartments INTO acq_cls, acq_comp
      FROM comms.pgp_key_acquisition WHERE id = NEW.acquisition_id;
    IF block_cls > acq_cls OR NOT (block_comp <@ acq_comp) THEN
      RAISE EXCEPTION 'the contact block line is filed above this key; a confirmation shown with the key cannot rest on material its readers may not see';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pgp_key_guarded
  BEFORE INSERT OR UPDATE OR DELETE ON comms.pgp_key
  FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key();
CREATE TRIGGER pgp_key_no_truncate
  BEFORE TRUNCATE ON comms.pgp_key
  FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key();
"""

REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON comms.pgp_key_acquisition FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE DELETE ON comms.pgp_key FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

DOWNGRADE_SQL = """
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT (SELECT count(*) FROM comms.pgp_key_acquisition)
       + (SELECT count(*) FROM comms.pgp_key) INTO n;
  IF n > 0 THEN
    RAISE EXCEPTION 'refusing to downgrade 0088: % vendor key rows are recorded; dropping the registry would lose where each came from. Stay at this revision.', n;
  END IF;
END $$;

DROP TABLE comms.pgp_key;
DROP TABLE comms.pgp_key_acquisition;
DROP FUNCTION comms.guard_pgp_key();
DROP FUNCTION comms.guard_pgp_key_acquisition();
DROP FUNCTION comms.pgp_fingerprint_norm(text);
"""


def upgrade() -> None:
    run(UPGRADE_SQL)
    for schema, table, column, kind in ADDED_BOUND_COLUMNS:
        run(trigger_sql(schema, table, column, kind))
    # After the CREATE TABLEs, never before: the DELETE being taken back is
    # the one 0060's default privileges handed out when the tables were
    # created. A no-op where the role does not exist (0063's reason).
    run(REVOKE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
