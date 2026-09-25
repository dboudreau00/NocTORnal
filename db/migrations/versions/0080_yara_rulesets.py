"""YARA rule sets and their findings (F12, 2026-09-24).

## What was wrong

yara/ held a fetch script and a list of public rule repositories, and the
product had a free-text "YARA hits" box on the analysis form: no rule set
was stored, versioned, labelled or audited, and nothing scanned. A unit's
rules say what it hunts, third-party rules carry licences somebody has to
clear, and compiled rules carry native code, so none of that can be a
file on disk the API happens to read.

## What this adds

- `lab.yara_ruleset`: a named, labelled set. Never deleted; key and
  creator never change; a key is unique only among sets carrying the same
  labels, so creating one never reveals a set above the creator's labels; classification never lowered; compartments only
  gain keys, or change by the one-for-one replacement the compartment
  registry's rename writes (the added key registered IN THIS TRANSACTION
  with the removed key's creator and creation time, 2026-09-24), so a
  rename passes and a removal or a swap
  between keys registered together is refused.
- `lab.yara_ruleset_version`: immutable upload facts. The source is kept
  as one gzip member per file (`files[].offset`, `files[].length`), so a
  file view decompresses one file and rule text is never plain at rest.
  Files carry only what intake knows: accepted or ignored, with a
  reason; whether a file compiled belongs to each build's report.
  An imported version (no uploader) must be adopted by a lab member
  before anyone can activate it.
- `lab.yara_activation`: the periods a version was its set's active one.
  The activator is never the sponsor (uploader or adopter), a
  review-flagged version needs the activator's written acknowledgement of
  its licence, and a closed period is never reopened.
- `lab.yara_compiled`: a HISTORY of builds, insert-only, each keyed by
  engine, platform and a fingerprint of the host CPU features wasmtime
  checks, and authenticated by an HMAC keyed from the KEK ring. A build
  that fails its MAC or will not load goes into `lab.yara_compiled_rejected`
  (also insert-only) and a newer build is chosen; a unique index on that
  key would have made that recompile impossible.
- `lab.yara_compile_job`: the compile queue, ordinary DML, claimed under a
  per-job advisory lock and swept when its owner is gone.
- `lab.sample_analysis.yara_ruleset_version_id`: set on machine YARA rows
  (with the run) and on an analyst's assessment derived from one, so both
  are read through the set's labels.
- Two permissions, `sample.yara.manage` (MALWARE_ANALYST) and
  `sample.yara.activate` (SECURITY_OFFICER), registered as a separated
  duty so no role can ever hold both.

The compartments column is bound by the contract 0069 set (docs/05,
"Binding a compartment column"): the `compartments_registered` trigger,
rendered by a local copy of 0059's `trigger_sql`, and
`ADDED_BOUND_COLUMNS`. The registry functions are not touched.

## Grants

`GUARDED_TABLES` declares what the runtime role keeps on the five guarded
tables; the REVOKE below takes back exactly the rest, after the CREATE
TABLEs, because 0060's default privileges hand DELETE out at creation.
`lab.yara_compile_job` keeps full DML.

## Downgrade

Refuses while any rule set exists, naming the count: the guards forbid
deletion, and dropping the tables would orphan findings and erase licence
decisions (0063's precedent). On an empty set it drops everything this
added, the separated-duty row included.
"""
from __future__ import annotations

from alembic import op

revision = "0080"
down_revision = "0079"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: The columns this migration binds (0069's contract; docs/05).
#: compartment_lifecycle.BOUND_COLUMNS carries the same tuple.
ADDED_BOUND_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("lab", "yara_ruleset", "compartments", "array"),
)

#: Guarded against deletion without being append-only ledgers: the table
#: and the privileges the runtime role KEEPS on it. Read by
#: test_app_role_privileges_pg.py.
GUARDED_TABLES = {
    "lab.yara_ruleset": ("SELECT", "INSERT", "UPDATE"),
    "lab.yara_ruleset_version": ("SELECT", "INSERT", "UPDATE"),
    "lab.yara_activation": ("SELECT", "INSERT", "UPDATE"),
    "lab.yara_compiled": ("SELECT", "INSERT"),
    "lab.yara_compiled_rejected": ("SELECT", "INSERT"),
}

TRIGGER_NAME = "compartments_registered"

#: The separated duty this installs, and the trigger 0075 (the two-person
#: policy, F9) puts on iam.separated_duty: when it exists, a migration
#: writing the table disables it by name for
#: its own statement.
DUTY = ("sample.yara.manage", "sample.yara.activate",
        "the lab member who sponsors a YARA rule set version is never the "
        "person who activates it and clears its licence")
LEDGER_TRIGGER = "separated_duty_written_by_ledger"


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


def _with_ledger_trigger_off(statement: str) -> str:
    """`statement` against iam.separated_duty, with 0075's ledger
    trigger disabled by name when that trigger exists."""
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_trigger
              WHERE tgrelid = 'iam.separated_duty'::regclass
                AND tgname = '{LEDGER_TRIGGER}') THEN
    EXECUTE 'ALTER TABLE iam.separated_duty DISABLE TRIGGER {LEDGER_TRIGGER}';
    EXECUTE $s${statement}$s$;
    EXECUTE 'ALTER TABLE iam.separated_duty ENABLE TRIGGER {LEDGER_TRIGGER}';
  ELSE
    EXECUTE $s${statement}$s$;
  END IF;
END
$noc$;
"""


UPGRADE_SQL = f"""
SET search_path = lab, core, public;

CREATE TABLE yara_ruleset (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key            text NOT NULL
                 CHECK (key ~ '^[a-z0-9][a-z0-9-]{{1,62}}$'),
  display_name   text NOT NULL CHECK (length(btrim(display_name)) > 0),
  description    text,
  classification core.tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{{}}',
  created_by     uuid REFERENCES iam.app_user(id),
  created_via    text NOT NULL DEFAULT 'console'
                 CHECK (created_via IN ('console', 'yara_db.py')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT yara_ruleset_creator_named
    CHECK ((created_via = 'console') = (created_by IS NOT NULL))
);
COMMENT ON TABLE yara_ruleset IS
  'A labelled YARA rule set (F12). Never deleted; labels only rise; '
  'compartments change only by the registry''s rename.';

{trigger_sql("lab", "yara_ruleset", "compartments", "array")}

-- A key is unique among the sets that carry the SAME labels, never across
-- labels: a creator can always read every set at the labels they create
-- at, so a refused key names only a set they may see. A key unique across
-- every label would answer "exists already" for a RED or compartmented
-- set the creator cannot see, which says what another unit hunts
-- (2026-09-24). Compartments are compared as a set, as a
-- registry rename may leave them in any order.
CREATE FUNCTION lab.yara_label_set(text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{{}}')
    FROM unnest($1) AS x
$$;
CREATE UNIQUE INDEX yara_ruleset_key_per_labels
  ON yara_ruleset (key, classification, lab.yara_label_set(compartments));

CREATE FUNCTION lab.guard_yara_ruleset() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  removed text[];
  added   text[];
  old_reg iam.compartment%ROWTYPE;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a YARA rule set is never deleted: it is the record of '
      'what the lab hunted with and who cleared it; deactivate its version '
      'instead';
  END IF;
  IF NEW.id <> OLD.id OR NEW.key <> OLD.key
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_via <> OLD.created_via
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'a YARA rule set''s key and creator never change';
  END IF;
  IF NEW.classification < OLD.classification THEN
    RAISE EXCEPTION 'a YARA rule set''s classification is never lowered: '
      'findings made under it would be exposed';
  END IF;
  removed := ARRAY(SELECT unnest(OLD.compartments)
                   EXCEPT SELECT unnest(NEW.compartments));
  added := ARRAY(SELECT unnest(NEW.compartments)
                 EXCEPT SELECT unnest(OLD.compartments));
  IF cardinality(removed) > 0 THEN
    SELECT * INTO old_reg FROM iam.compartment WHERE key = removed[1];
    IF cardinality(removed) <> 1 OR cardinality(added) <> 1
       OR old_reg.key IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM iam.compartment c
          WHERE c.key = added[1]
            AND c.created_at = old_reg.created_at
            AND c.created_by IS NOT DISTINCT FROM old_reg.created_by
            -- Registered in this very transaction, as the lifecycle's
            -- rename registers it: keys backfilled together share a
            -- creator and a time, and a swap between two of them is
            -- not a rename.
            AND c.xmin::text::bigint
                = pg_current_xact_id()::text::bigint % 4294967296) THEN
      RAISE EXCEPTION 'a rule set''s compartments are only added to, or '
        'renamed through the compartment registry: removing one would '
        'expose findings made under it';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER yara_ruleset_guarded BEFORE UPDATE OR DELETE ON yara_ruleset
  FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_ruleset();
CREATE TRIGGER yara_ruleset_no_truncate BEFORE TRUNCATE ON yara_ruleset
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_ruleset();

CREATE TABLE yara_ruleset_version (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_id              uuid NOT NULL REFERENCES lab.yara_ruleset(id),
  version                 integer NOT NULL CHECK (version >= 1),
  source_sha256           bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  source_gz               bytea NOT NULL,
  source_bytes            bigint NOT NULL CHECK (source_bytes > 0),
  files                   jsonb NOT NULL,
  file_count              integer NOT NULL CHECK (file_count >= 0),
  licence                 text NOT NULL CHECK (length(btrim(licence)) > 0),
  licence_review_required boolean NOT NULL,
  provenance              jsonb NOT NULL DEFAULT '{{}}',
  note                    text,
  uploaded_by             uuid REFERENCES iam.app_user(id),
  uploaded_at             timestamptz NOT NULL DEFAULT now(),
  adopted_by              uuid REFERENCES iam.app_user(id),
  adopted_at              timestamptz,
  UNIQUE (ruleset_id, version),
  UNIQUE (ruleset_id, source_sha256),
  CONSTRAINT yara_version_uploader_or_script
    CHECK (uploaded_by IS NOT NULL OR provenance->>'via' = 'yara_db.py'),
  CONSTRAINT yara_version_adoption_complete
    CHECK ((adopted_by IS NULL) = (adopted_at IS NULL)),
  CONSTRAINT yara_version_adopted_only_when_imported
    CHECK (adopted_by IS NULL OR uploaded_by IS NULL),
  CONSTRAINT yara_version_files_is_a_list
    CHECK (jsonb_typeof(files) = 'array')
);

CREATE FUNCTION lab.guard_yara_ruleset_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a YARA rule set version is never deleted: findings '
      'and licence decisions name it';
  END IF;
  IF OLD.adopted_by IS NOT NULL
     OR NEW.id <> OLD.id OR NEW.ruleset_id <> OLD.ruleset_id
     OR NEW.version <> OLD.version OR NEW.source_sha256 <> OLD.source_sha256
     OR NEW.source_gz <> OLD.source_gz OR NEW.source_bytes <> OLD.source_bytes
     OR NEW.files <> OLD.files OR NEW.file_count <> OLD.file_count
     OR NEW.licence <> OLD.licence
     OR NEW.licence_review_required <> OLD.licence_review_required
     OR NEW.provenance <> OLD.provenance
     OR NEW.note IS DISTINCT FROM OLD.note
     OR NEW.uploaded_by IS DISTINCT FROM OLD.uploaded_by
     OR NEW.uploaded_at <> OLD.uploaded_at THEN
    RAISE EXCEPTION 'a YARA rule set version is immutable; only its '
      'adoption is recorded, once';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER yara_ruleset_version_guarded
  BEFORE UPDATE OR DELETE ON yara_ruleset_version
  FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_ruleset_version();
CREATE TRIGGER yara_ruleset_version_no_truncate
  BEFORE TRUNCATE ON yara_ruleset_version
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_ruleset_version();

CREATE TABLE yara_activation (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_id               uuid NOT NULL REFERENCES lab.yara_ruleset(id),
  version_id               uuid NOT NULL REFERENCES lab.yara_ruleset_version(id),
  activated_by             uuid NOT NULL REFERENCES iam.app_user(id),
  activated_at             timestamptz NOT NULL DEFAULT now(),
  licence_acknowledgement  text,
  deactivated_by           uuid REFERENCES iam.app_user(id),
  deactivated_at           timestamptz,
  deactivation_reason      text,
  CONSTRAINT yara_activation_ack_says_something
    CHECK (licence_acknowledgement IS NULL
           OR length(btrim(licence_acknowledgement)) > 20),
  CONSTRAINT yara_activation_close_complete
    CHECK ((deactivated_at IS NULL) = (deactivated_by IS NULL)
           AND (deactivated_at IS NULL) = (deactivation_reason IS NULL)),
  CONSTRAINT yara_activation_reason_says_something
    CHECK (deactivation_reason IS NULL
           OR length(btrim(deactivation_reason)) >= 10)
);
CREATE UNIQUE INDEX yara_activation_one_open ON yara_activation (ruleset_id)
  WHERE deactivated_at IS NULL;

CREATE FUNCTION lab.yara_activation_rules() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v lab.yara_ruleset_version%ROWTYPE;
  sponsor uuid;
BEGIN
  SELECT * INTO v FROM lab.yara_ruleset_version WHERE id = NEW.version_id;
  IF v.id IS NULL OR v.ruleset_id <> NEW.ruleset_id THEN
    RAISE EXCEPTION 'the version does not belong to this rule set';
  END IF;
  IF NEW.deactivated_at IS NOT NULL THEN
    RAISE EXCEPTION 'an activation starts open';
  END IF;
  sponsor := coalesce(v.uploaded_by, v.adopted_by);
  IF sponsor IS NULL THEN
    RAISE EXCEPTION 'an imported version must be adopted by a lab member '
      'before it can be activated';
  END IF;
  IF NEW.activated_by = sponsor THEN
    RAISE EXCEPTION 'the person who uploaded or adopted a version cannot '
      'activate it: somebody else has to';
  END IF;
  IF v.licence_review_required AND NEW.licence_acknowledgement IS NULL THEN
    RAISE EXCEPTION 'this version''s licence needs review: the activator '
      'must write down the clearance';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER yara_activation_rules BEFORE INSERT ON yara_activation
  FOR EACH ROW EXECUTE FUNCTION lab.yara_activation_rules();

CREATE FUNCTION lab.guard_yara_activation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'an activation is never deleted: it is when a rule set '
      'was live and who cleared it';
  END IF;
  IF OLD.deactivated_at IS NOT NULL
     OR NEW.id <> OLD.id OR NEW.ruleset_id <> OLD.ruleset_id
     OR NEW.version_id <> OLD.version_id
     OR NEW.activated_by <> OLD.activated_by
     OR NEW.activated_at <> OLD.activated_at
     OR NEW.licence_acknowledgement IS DISTINCT FROM OLD.licence_acknowledgement
     OR NEW.deactivated_at IS NULL THEN
    RAISE EXCEPTION 'an activation may only be closed, once';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER yara_activation_guarded BEFORE UPDATE OR DELETE ON yara_activation
  FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_activation();
CREATE TRIGGER yara_activation_no_truncate BEFORE TRUNCATE ON yara_activation
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_activation();

CREATE TABLE yara_compiled (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version_id    uuid NOT NULL REFERENCES lab.yara_ruleset_version(id),
  engine        text NOT NULL,
  platform      text NOT NULL,
  fingerprint   text NOT NULL,
  status        text NOT NULL CHECK (status IN ('COMPILED','PARTIAL','FAILED')),
  rule_count    integer NOT NULL DEFAULT 0,
  warning_count integer NOT NULL DEFAULT 0,
  report        jsonb NOT NULL,
  compiled      bytea,
  blob_sha256   bytea,
  mac_key_id    text,
  mac           bytea,
  compiled_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT yara_compiled_blob_when_built
    CHECK ((status = 'FAILED') = (compiled IS NULL)
       AND (compiled IS NULL) = (blob_sha256 IS NULL)
       AND (compiled IS NULL) = (mac IS NULL)
       AND (compiled IS NULL) = (mac_key_id IS NULL))
);
CREATE INDEX yara_compiled_lookup
  ON yara_compiled (version_id, engine, platform, fingerprint, compiled_at DESC);

CREATE TABLE yara_compiled_rejected (
  compiled_id uuid PRIMARY KEY REFERENCES lab.yara_compiled(id),
  reason      text NOT NULL CHECK (reason IN ('mac_mismatch', 'undecodable')),
  rejected_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION lab.guard_yara_insert_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is insert-only: a build and its rejection are history, '
    'and a newer row supersedes an older one', TG_TABLE_NAME;
END $$;
CREATE TRIGGER yara_compiled_insert_only BEFORE UPDATE OR DELETE ON yara_compiled
  FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_insert_only();
CREATE TRIGGER yara_compiled_no_truncate BEFORE TRUNCATE ON yara_compiled
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_insert_only();
CREATE TRIGGER yara_compiled_rejected_insert_only
  BEFORE UPDATE OR DELETE ON yara_compiled_rejected
  FOR EACH ROW EXECUTE FUNCTION lab.guard_yara_insert_only();
CREATE TRIGGER yara_compiled_rejected_no_truncate
  BEFORE TRUNCATE ON yara_compiled_rejected
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_yara_insert_only();

CREATE TABLE yara_compile_job (
  version_id  uuid NOT NULL REFERENCES lab.yara_ruleset_version(id),
  engine      text NOT NULL,
  platform    text NOT NULL,
  fingerprint text NOT NULL,
  status      text NOT NULL DEFAULT 'QUEUED'
              CHECK (status IN ('QUEUED','RUNNING','FAILED')),
  attempts    integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error  text,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (version_id, engine, platform, fingerprint)
);

ALTER TABLE sample_analysis
  ADD COLUMN yara_ruleset_version_id uuid
    REFERENCES lab.yara_ruleset_version(id),
  ADD CONSTRAINT sample_analysis_machine_yara_names_its_rules
    CHECK (NOT (origin = 'machine' AND kind = 'YARA')
           OR (run_id IS NOT NULL AND yara_ruleset_version_id IS NOT NULL));
CREATE INDEX sample_analysis_yara_version_idx
  ON sample_analysis (yara_ruleset_version_id)
  WHERE yara_ruleset_version_id IS NOT NULL;
CREATE INDEX sample_analysis_machine_yara_hits_idx
  ON sample_analysis USING gin (yara_hits)
  WHERE origin = 'machine' AND yara_ruleset_version_id IS NOT NULL;
"""

REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON lab.yara_ruleset, lab.yara_ruleset_version, '
                   'lab.yara_activation FROM %I', '{APP_ROLE}');
    EXECUTE format('REVOKE UPDATE, DELETE ON lab.yara_compiled, '
                   'lab.yara_compiled_rejected FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

PERMISSIONS_SQL = """
INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  ('sample.yara.manage',
   'Create YARA rule sets, upload and adopt versions, and queue rescans',
   true),
  ('sample.yara.activate',
   'Activate or deactivate a YARA rule set version somebody else '
   'sponsored, clearing its licence',
   true)
ON CONFLICT (key) DO NOTHING;
"""

GRANTS_SQL = """
INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  ('MALWARE_ANALYST', 'sample.yara.manage'),
  ('SECURITY_OFFICER', 'sample.yara.activate')
ON CONFLICT DO NOTHING;
"""


def downgrade_refusal(n: int) -> str:
    return (f"refusing to downgrade 0080: {n} YARA rule "
            f"{'set exists' if n == 1 else 'sets exist'}. Rule sets are never "
            "deleted: dropping them would orphan their findings and erase "
            "the licence decisions recorded on their activations. Stay at "
            "this revision.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)
    run(REVOKE_SQL)
    run(PERMISSIONS_SQL)
    a, b, why = DUTY
    run(_with_ledger_trigger_off(
        "INSERT INTO iam.separated_duty (permission_a, permission_b, why) "
        f"VALUES ('{a}', '{b}', '{why}')"))
    run(GRANTS_SQL)


def downgrade() -> None:
    n = query("SELECT count(*) FROM lab.yara_ruleset")[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    a, b, _why = DUTY
    run(f"""
DELETE FROM iam.role_permission
 WHERE permission_key IN ('{a}', '{b}');
""")
    run(_with_ledger_trigger_off(
        "DELETE FROM iam.separated_duty "
        f"WHERE permission_a = '{a}' AND permission_b = '{b}'"))
    run(f"""
DELETE FROM iam.permission WHERE key IN ('{a}', '{b}');
SET search_path = lab, core, public;
DROP INDEX sample_analysis_machine_yara_hits_idx;
DROP INDEX sample_analysis_yara_version_idx;
ALTER TABLE sample_analysis
  DROP CONSTRAINT sample_analysis_machine_yara_names_its_rules,
  DROP COLUMN yara_ruleset_version_id;
DROP TABLE yara_compile_job;
DROP TABLE yara_compiled_rejected;
DROP TABLE yara_compiled;
DROP TABLE yara_activation;
DROP TABLE yara_ruleset_version;
DROP TABLE yara_ruleset;
DROP FUNCTION lab.guard_yara_insert_only();
DROP FUNCTION lab.guard_yara_activation();
DROP FUNCTION lab.yara_activation_rules();
DROP FUNCTION lab.guard_yara_ruleset_version();
DROP FUNCTION lab.guard_yara_ruleset();
DROP FUNCTION lab.yara_label_set(text[]);
""")
