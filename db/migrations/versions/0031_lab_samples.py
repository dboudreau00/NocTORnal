"""Phase 8 -- malware sample handling (docs/11).

=====================================================================
COUNSEL MUST REVIEW THIS DEPLOYMENT BEFORE IT IS USED IN ANY ABSOLUTE
SENSE.

Built on an operator directive of 2026-07-25, which supersedes decision
36's block. The block was never about the code: it was about the fact that
a store of attacker-supplied binaries WILL eventually receive material
whose possession alone is an offence, that the handling rules differ
between the two target jurisdictions this platform is built for (decision
13: US and Canada), and that finding that out after the first ingest is a
legal problem rather than a technical one.

Nothing in this migration changes that. The schema can be correct and the
deployment still unlawful. What is built here is the machinery to hold the
policy once counsel has written it -- a screening hook, a REJECTED path
that records the fact of a rejection without retaining the content, and a
hard runtime refusal to accept anything until an operator has declared that
a policy exists. See `samples.py` and the README warning block.
=====================================================================

## Invariant 10, in the schema

    Samples never render, never execute. The binary is only ever an
    encrypted archive download from a separate origin. Sample metadata
    may render; sample bytes may not.

Three columns carry that:

- `sha256` is the object key. **Never the original filename** -- filenames
  are attacker-controlled and are themselves a payload vector. The original
  is retained in `original_filename` for the record, never used as a path
  component and never rendered unescaped.
- `data_key_ciphertext` -- every sample is encrypted at rest under a
  per-sample key, envelope-encrypted the same way persona credentials and
  TOTP secrets are. There is no point in the pipeline where a raw PE sits
  on a filesystem with its original name. This also incidentally solves the
  problem docs/11 calls routine and embarrassing: your own EDR quarantining
  or deleting the evidence, because the bytes on disk are not recognisable
  as malware.
- `state` defaults to SUBMITTED and the service moves it straight to
  QUARANTINED. **Nothing is visible to the RE queue until triage has run.**

## Two roles that deliberately do not imply each other

`MALWARE_ANALYST` sees the sample queue and sample metadata and can
download the archive; it does NOT grant case access. Case analysts see that
a sample exists and its analysis summary; downloading the binary needs the
sample role. docs/11: "the RE channel is a role, not a folder."

## Detonation is an overt act

`detonation.exposure_level` and the CHECK on it exist because submitting to
a public sandbox may expose the sample and your interest in it, and
operators watch public sandboxes for their own samples and treat submission
as a signal they have been noticed. Anything other than NONE needs a named
authoriser recorded in the row.
"""
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None

# The RE channel is a role, not a folder. Note what is ABSENT: no
# case.read, no evidence.read, no graph write. A malware analyst is
# trusted with hostile binaries, which is a different trust to being
# trusted with the case file, and conflating them is how a lab handoff
# becomes an access-control hole.
_MALWARE_ANALYST_PERMISSIONS = [
    "sample.read", "sample.download", "sample.analyse",
]

_NEW_PERMISSIONS = [
    # Seeing that a sample exists, and its metadata and analysis summary.
    ("sample.read", False, "See sample metadata and analysis"),
    # Taking a copy of a live hostile binary. Step-up: this is the one
    # action in the system that puts working malware on someone's disk.
    ("sample.download", True, "Download the encrypted sample archive"),
    ("sample.submit", False, "Submit a sample into quarantine"),
    ("sample.analyse", False, "Record analysis findings against a sample"),
    # Detonation is an overt act that can burn an operation.
    ("sample.detonate", True, "Submit a sample to a sandbox"),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE SCHEMA IF NOT EXISTS lab;
SET search_path = lab, core, public;

CREATE TYPE sample_state AS ENUM
  ('SUBMITTED','QUARANTINED','TRIAGED','ASSIGNED','IN_ANALYSIS','REPORTED','REJECTED');

CREATE TABLE sample (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid REFERENCES core."case"(id),
  node_id         uuid REFERENCES core.node(id),
  -- The object key. NEVER the original filename.
  sha256          bytea NOT NULL,
  sha1            bytea,
  md5             bytea,
  -- Kept for the record. Never a path component, never rendered unescaped.
  original_filename text,
  byte_size       bigint NOT NULL,
  storage_key     text NOT NULL,
  storage_bucket  text NOT NULL,
  -- Per-sample data key, envelope-encrypted. There is no point in the
  -- pipeline where a raw executable sits on disk as an executable.
  data_key_ciphertext bytea NOT NULL,
  data_key_id     text NOT NULL,
  state           sample_state NOT NULL DEFAULT 'SUBMITTED',
  reject_reason   text,
  -- Cluster keys. These are what link a sample to a BUILDER and therefore
  -- to a developer, who is usually a more interesting node than any
  -- individual affiliate (docs/11).
  imphash         text,
  rich_header_hash text,
  ssdeep          text,
  tlsh            text,
  file_type       text,
  entropy         numeric(6,4),
  -- Which triage steps ran and which did not, and why. Invariant 12: a
  -- hash that was not computed is a recorded absence, not a silent NULL
  -- that reads as "this sample has no imports".
  triage_gaps     jsonb NOT NULL DEFAULT '[]'::jsonb,
  submitted_by    uuid NOT NULL REFERENCES iam.app_user(id),
  submitted_at    timestamptz NOT NULL DEFAULT now(),
  source_note     text,
  assigned_to     uuid REFERENCES iam.app_user(id),
  assigned_at     timestamptz,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  legal_hold      boolean NOT NULL DEFAULT false,

  UNIQUE (sha256),
  -- A rejection explains itself or it did not happen. This is the row that
  -- has to survive when the content does not.
  CONSTRAINT sample_rejection_has_reason
    CHECK ((state = 'REJECTED') = (reject_reason IS NOT NULL)),
  CONSTRAINT sample_assignment_complete
    CHECK ((assigned_to IS NULL) = (assigned_at IS NULL))
);
CREATE INDEX sample_queue_idx ON sample (state, submitted_at DESC)
  WHERE state IN ('QUARANTINED','TRIAGED','ASSIGNED','IN_ANALYSIS');
CREATE INDEX sample_case_idx ON sample (case_id, submitted_at DESC);
CREATE INDEX sample_imphash_idx ON sample (imphash) WHERE imphash IS NOT NULL;
CREATE INDEX sample_tlsh_idx ON sample (tlsh) WHERE tlsh IS NOT NULL;
CREATE INDEX sample_assigned_idx ON sample (assigned_to)
  WHERE assigned_to IS NOT NULL;

CREATE TABLE sample_analysis (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id       uuid NOT NULL REFERENCES sample(id) ON DELETE CASCADE,
  kind            text NOT NULL,
  analyst_id      uuid REFERENCES iam.app_user(id),
  tool            text,
  tool_version    text,
  -- Machine-readable, because this is where the graph value comes from.
  -- docs/11: a PDF report is where analysis goes to die.
  findings        jsonb NOT NULL DEFAULT '{}'::jsonb,
  extracted_selectors jsonb NOT NULL DEFAULT '[]'::jsonb,
  yara_hits       text[],
  -- An ASSESSMENT, never a fact stamped on an actor. It reaches the graph
  -- as a core.assertion with a source and a confidence, like everything
  -- else (invariant 1).
  family_assessment text,
  confidence      core.analytic_confidence,
  narrative       text,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT sample_analysis_kind_known
    CHECK (kind IN ('STATIC','YARA','MANUAL_RE','SANDBOX','VENDOR')),
  -- A family attribution without a confidence is a fact wearing an
  -- assessment's clothes.
  CONSTRAINT sample_analysis_family_needs_confidence
    CHECK (family_assessment IS NULL OR confidence IS NOT NULL)
);
CREATE INDEX sample_analysis_sample_idx ON sample_analysis (sample_id, created_at DESC);

CREATE TABLE detonation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sample_id       uuid NOT NULL REFERENCES sample(id),
  target          text NOT NULL,
  exposure_level  text NOT NULL,
  authorised_by   uuid REFERENCES iam.app_user(id),
  authorisation_note text,
  requested_by    uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at    timestamptz NOT NULL DEFAULT now(),
  submitted_at    timestamptz,
  external_ref    text,
  status          text NOT NULL DEFAULT 'PENDING',
  report          jsonb,

  CONSTRAINT detonation_exposure_known
    CHECK (exposure_level IN ('NONE','VENDOR','PUBLIC')),
  CONSTRAINT detonation_status_known
    CHECK (status IN ('PENDING','AUTHORISED','SUBMITTED','REPORTED','REFUSED')),
  -- Anything that leaves the building needs a named human on the row.
  -- Operators watch public sandboxes for their own samples and treat a
  -- submission as a signal they have been noticed; that can end an
  -- operation, so it cannot be a side effect of clicking Analyse.
  CONSTRAINT detonation_exposure_needs_authoriser
    CHECK (exposure_level = 'NONE' OR authorised_by IS NOT NULL),
  CONSTRAINT detonation_exposure_needs_note
    CHECK (exposure_level = 'NONE' OR authorisation_note IS NOT NULL)
);
CREATE INDEX detonation_sample_idx ON detonation (sample_id, requested_at DESC);

-- Custody for samples, the same discipline core.evidence_custody applies
-- to exhibits. Downloads especially: who took a copy of a live binary,
-- when, and in what wrapper.
CREATE TABLE sample_access (
  id             bigserial PRIMARY KEY,
  sample_id      uuid NOT NULL REFERENCES sample(id),
  actor_id       uuid NOT NULL REFERENCES iam.app_user(id),
  action         text NOT NULL,
  occurred_at    timestamptz NOT NULL DEFAULT now(),
  archive_format text,
  detail         jsonb NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT sample_access_action_known
    CHECK (action IN ('VIEWED_META','DOWNLOADED','SHARED','DETONATED',
                      'REJECTED','ASSIGNED','ANALYSED'))
);
CREATE INDEX sample_access_sample_idx ON sample_access (sample_id, occurred_at DESC);
CREATE INDEX sample_access_actor_idx ON sample_access (actor_id, occurred_at DESC);

-- Append-only, for the same reason audit.event is: "who took a copy of a
-- live binary" is not a question anybody may quietly re-answer.
CREATE FUNCTION lab.block_access_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'lab.sample_access is append-only (docs/11 custody)';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER sample_access_append_only
  BEFORE UPDATE OR DELETE ON sample_access
  FOR EACH ROW EXECUTE FUNCTION lab.block_access_mutation();
""")

    perms = ",\n".join(
        f"('{k}', '{label}', {str(step_up).lower()})"
        for k, step_up, label in _NEW_PERMISSIONS)
    run(f"""
SET search_path = iam, core, public;

INSERT INTO permission (key, description, requires_step_up) VALUES
{perms}
ON CONFLICT (key) DO NOTHING;

INSERT INTO role (key, display_name, description) VALUES
  ('MALWARE_ANALYST', 'Malware analyst',
   'Sees the sample queue and sample metadata, and may download the '
   'encrypted archive. Deliberately grants NO case access: being trusted '
   'with hostile binaries is a different trust to being trusted with the '
   'case file (docs/11).')
ON CONFLICT (key) DO NOTHING;
""")

    pairs = ",\n".join(f"('MALWARE_ANALYST','{p}')"
                       for p in _MALWARE_ANALYST_PERMISSIONS)
    # Case-side roles can SEE that a sample exists and submit one; taking a
    # copy of the binary needs the lab role.
    pairs += ",\n" + ",\n".join(
        f"('{role}','{perm}')"
        for role in ("CASE_OWNER", "ANALYST", "REVIEWER")
        for perm in ("sample.read", "sample.submit"))
    run(f"""
SET search_path = iam, core, public;
INSERT INTO role_permission (role_key, permission_key) VALUES
{pairs}
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    keys = ",".join(f"'{k}'" for k, _, _ in _NEW_PERMISSIONS)
    run(f"""
DELETE FROM iam.role_permission WHERE permission_key IN ({keys});
DELETE FROM iam.role WHERE key = 'MALWARE_ANALYST';
DELETE FROM iam.permission WHERE key IN ({keys});

DROP TRIGGER sample_access_append_only ON lab.sample_access;
DROP FUNCTION lab.block_access_mutation();
DROP TABLE lab.sample_access;
DROP TABLE lab.detonation;
DROP TABLE lab.sample_analysis;
DROP TABLE lab.sample;
DROP TYPE lab.sample_state;
DROP SCHEMA lab;
""")
