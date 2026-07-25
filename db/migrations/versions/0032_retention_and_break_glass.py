"""Retention, purge tombstones, and break-glass activation (Phase 6, docs/08).

## The tombstone is the point

docs/08:

    Purge writes a tombstone to the audit log: what was destroyed, under
    what authority, by whom. **The record of destruction survives the
    data.**

A purge that leaves nothing behind is indistinguishable from data that was
never collected, and from data somebody deleted to hide it. So
`core.purge_tombstone` is append-only and outlives everything it describes:
it holds counts, the authority, the actor and the retention rule that fired
-- and deliberately holds NO content, because a tombstone that quoted what
it destroyed would be a copy of it.

## Per-category retention, enforced independently

Per-case `retention_until` has been mandatory since Phase 1. It is not
enough once ingest exists: a stealer log inside a two-year case is
third-party personal data belonging to thousands of people who are not the
subject, and it should not inherit that case's clock.

`core.retention_rule` therefore holds per-category periods that can only be
SHORTER than the case default, enforced by a check at purge time rather
than by hoping nobody sets a longer one. **The numbers are placeholders**
-- see docs/16 D3. `STEALER_LOG` at 90 days is a guess with a legal answer.

## Legal hold beats everything

docs/08: "legal_hold overrides all deletion, everywhere." It is on the case
already; this adds it to evidence and documents so a hold can be narrower
than a whole case. Purge checks it at three levels and refuses at any.

**The unresolved tension, recorded rather than papered over** (docs/16 C2):
evidence sits under MinIO COMPLIANCE-mode object lock, which cannot be
deleted before its retention expires *even to satisfy a deletion order*.
Purge marks the row and writes the tombstone; the bytes may outlive both.
`purge_tombstone.storage_outcome` records which happened, so nobody later
assumes a purge that reported success actually removed the object.

## Break-glass

`iam.break_glass` has existed since Phase 0 with nothing writing it.
docs/05: "available, loud and short -- mandatory justification, hard expiry,
immediate alert to the security officer, and mandatory post-hoc review. The
access is granted; the visibility is what makes it safe."

Three columns are added to make the review real rather than nominal: the
scope actually granted, whether it was used, and what was touched while it
was live. An emergency access that nobody can audit afterwards is just
access.
"""
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None

# Placeholders. Every one of these is a legal determination (docs/16 D3),
# and the shortest is the one that matters most: a stealer log is
# third-party personal data belonging to people who are not the subject.
_DEFAULT_RULES = [
    ("STEALER_LOG", 90, "Third-party personal data at scale. docs/12: the "
                        "most likely route by which this platform becomes a "
                        "data protection incident."),
    ("CREDENTIAL_DUMP", 180, "Third-party credentials; same exposure, lower "
                             "volume."),
    ("DATABASE_LEAK", 365, "Often contains uninvolved account holders."),
    ("CHAT_EXPORT", 730, "May contain uninvolved third parties in group "
                         "channels (docs/16 L4)."),
    ("PASTE", 365, "Mixed content, frequently personal data."),
    ("TELEMETRY", 180, "High volume, low individual value."),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

-- Per-category retention. May only SHORTEN the case default, never extend
-- it: a rule that could extend would let an ingest category quietly
-- outlive the authority the case was opened under.
CREATE TABLE retention_rule (
  category        text PRIMARY KEY,
  retain_days     integer NOT NULL,
  rationale       text NOT NULL,
  -- Set when an operator has actually decided this, as opposed to running
  -- on the placeholder the migration shipped. Purge WARNS on placeholders
  -- rather than refusing, because refusing would make the first purge the
  -- moment somebody discovers the question.
  confirmed_by    uuid REFERENCES iam.app_user(id),
  confirmed_at    timestamptz,
  updated_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT retention_rule_positive CHECK (retain_days > 0),
  CONSTRAINT retention_rule_confirmation_complete
    CHECK ((confirmed_by IS NULL) = (confirmed_at IS NULL))
);

-- The record of destruction, which survives the data. Append-only, and
-- holds NO content: a tombstone that quoted what it destroyed would be a
-- copy of it.
CREATE TABLE purge_tombstone (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid REFERENCES "case"(id),
  -- What kind of thing, and how many. Never which, never what.
  object_type     text NOT NULL,
  object_count    integer NOT NULL,
  -- The oldest and newest thing destroyed, so a later question about a
  -- date range can be answered without the data.
  earliest        timestamptz,
  latest          timestamptz,
  -- WHY it was destroyed: the rule that fired, or the authority for an
  -- out-of-schedule purge.
  rule            text,
  authority       text NOT NULL,
  approval_request_id uuid REFERENCES approval_request(id),
  purged_by       uuid NOT NULL REFERENCES iam.app_user(id),
  purged_at       timestamptz NOT NULL DEFAULT now(),
  -- docs/16 C2. Evidence under COMPLIANCE-mode object lock cannot be
  -- deleted before its retention expires, even to satisfy a deletion
  -- order. This says which actually happened, so nobody later assumes a
  -- purge that reported success removed the bytes.
  storage_outcome text NOT NULL DEFAULT 'NOT_APPLICABLE',
  detail          jsonb NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT purge_tombstone_count_positive CHECK (object_count > 0),
  CONSTRAINT purge_tombstone_authority_present
    CHECK (length(btrim(authority)) > 0),
  CONSTRAINT purge_tombstone_storage_outcome_known
    CHECK (storage_outcome IN ('DELETED', 'LOCKED_UNTIL_RETENTION',
                               'FAILED', 'NOT_APPLICABLE'))
);
CREATE INDEX purge_tombstone_case_idx ON purge_tombstone (case_id, purged_at DESC);
CREATE INDEX purge_tombstone_time_idx ON purge_tombstone (purged_at DESC);

CREATE FUNCTION core.block_tombstone_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'core.purge_tombstone is append-only: the record of '
                  'destruction survives the data (docs/08)';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER purge_tombstone_append_only
  BEFORE UPDATE OR DELETE ON purge_tombstone
  FOR EACH ROW EXECUTE FUNCTION core.block_tombstone_mutation();

-- docs/08: "legal_hold overrides all deletion, everywhere." It was on
-- NOTHING. `core."case"` never had the column, and neither did evidence's
-- reason -- so the rule that is supposed to beat every other retention
-- decision had no way to be expressed at all. Found while writing the
-- purge tests, which is the right place to find it and a late one.
ALTER TABLE "case" ADD COLUMN legal_hold boolean NOT NULL DEFAULT false;
ALTER TABLE "case" ADD COLUMN legal_hold_reason text;
ALTER TABLE "case" ADD CONSTRAINT case_hold_has_reason
  CHECK (NOT legal_hold OR legal_hold_reason IS NOT NULL);

-- A hold narrower than a whole case. docs/08: legal_hold overrides all
-- deletion, everywhere -- and "everywhere" has to include the exhibit a
-- court named specifically. `legal_hold` already existed on evidence with
-- nothing reading it; what was missing is the REASON, because a hold whose
-- authority nobody recorded is a hold nobody can lift.
ALTER TABLE evidence ADD COLUMN legal_hold_reason text;
ALTER TABLE evidence ADD COLUMN purged_at timestamptz;

ALTER TABLE evidence ADD CONSTRAINT evidence_hold_has_reason
  CHECK (NOT legal_hold OR legal_hold_reason IS NOT NULL);

CREATE INDEX evidence_purgeable_idx ON evidence (case_id)
  WHERE purged_at IS NULL AND NOT legal_hold;
""")

    run("""
SET search_path = collect, core, public;

-- Documents carry their own category and their own clock, because a
-- stealer log inside a two-year case must not inherit that case's.
ALTER TABLE document ADD COLUMN category text NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE document ADD COLUMN retain_until timestamptz;
ALTER TABLE document ADD COLUMN legal_hold boolean NOT NULL DEFAULT false;
ALTER TABLE document ADD COLUMN purged_at timestamptz;

CREATE INDEX document_retention_idx ON document (retain_until)
  WHERE purged_at IS NULL AND NOT legal_hold;
CREATE INDEX document_category_idx ON document (category);
""")

    run("""
SET search_path = iam, core, public;

-- Break-glass: what was actually granted, whether it was used, and what it
-- touched. Without these the "mandatory post-hoc review" docs/05 requires
-- is a review of a justification string.
ALTER TABLE break_glass ADD COLUMN granted_permissions text[] NOT NULL DEFAULT '{}';
ALTER TABLE break_glass ADD COLUMN granted_classification core.tlp;
ALTER TABLE break_glass ADD COLUMN used_at timestamptz;
ALTER TABLE break_glass ADD COLUMN action_count integer NOT NULL DEFAULT 0;
ALTER TABLE break_glass ADD COLUMN revoked_at timestamptz;
ALTER TABLE break_glass ADD COLUMN revoked_by uuid REFERENCES iam.app_user(id);

-- Short by construction. docs/05: "available, loud and SHORT." A
-- break-glass that can be granted for a week is a role.
ALTER TABLE break_glass ADD CONSTRAINT break_glass_is_short
  CHECK (expires_at <= started_at + interval '8 hours');
ALTER TABLE break_glass ADD CONSTRAINT break_glass_justification_present
  CHECK (length(btrim(justification)) > 20);
ALTER TABLE break_glass ADD CONSTRAINT break_glass_review_complete
  CHECK ((reviewed_by IS NULL) = (reviewed_at IS NULL));

CREATE INDEX break_glass_live_idx ON break_glass (user_id, expires_at)
  WHERE revoked_at IS NULL;
-- The review queue: everything that has expired and nobody has looked at.
CREATE INDEX break_glass_unreviewed_idx ON break_glass (started_at DESC)
  WHERE reviewed_at IS NULL;
""")

    values = ",\n".join(
        f"('{category}', {days}, '{rationale}')"
        for category, days, rationale in _DEFAULT_RULES)
    run(f"""
INSERT INTO core.retention_rule (category, retain_days, rationale) VALUES
{values}
ON CONFLICT (category) DO NOTHING;
""")


def downgrade() -> None:
    categories = ",".join(f"'{c}'" for c, _, _ in _DEFAULT_RULES)
    run(f"""
DELETE FROM core.retention_rule WHERE category IN ({categories});

ALTER TABLE iam.break_glass DROP CONSTRAINT break_glass_review_complete;
ALTER TABLE iam.break_glass DROP CONSTRAINT break_glass_justification_present;
ALTER TABLE iam.break_glass DROP CONSTRAINT break_glass_is_short;
DROP INDEX iam.break_glass_unreviewed_idx;
DROP INDEX iam.break_glass_live_idx;
ALTER TABLE iam.break_glass DROP COLUMN revoked_by;
ALTER TABLE iam.break_glass DROP COLUMN revoked_at;
ALTER TABLE iam.break_glass DROP COLUMN action_count;
ALTER TABLE iam.break_glass DROP COLUMN used_at;
ALTER TABLE iam.break_glass DROP COLUMN granted_classification;
ALTER TABLE iam.break_glass DROP COLUMN granted_permissions;

DROP INDEX collect.document_category_idx;
DROP INDEX collect.document_retention_idx;
ALTER TABLE collect.document DROP COLUMN purged_at;
ALTER TABLE collect.document DROP COLUMN legal_hold;
ALTER TABLE collect.document DROP COLUMN retain_until;
ALTER TABLE collect.document DROP COLUMN category;

ALTER TABLE core."case" DROP CONSTRAINT case_hold_has_reason;
ALTER TABLE core."case" DROP COLUMN legal_hold_reason;
ALTER TABLE core."case" DROP COLUMN legal_hold;

DROP INDEX core.evidence_purgeable_idx;
ALTER TABLE core.evidence DROP CONSTRAINT evidence_hold_has_reason;
ALTER TABLE core.evidence DROP COLUMN purged_at;
ALTER TABLE core.evidence DROP COLUMN legal_hold_reason;

DROP TRIGGER purge_tombstone_append_only ON core.purge_tombstone;
DROP FUNCTION core.block_tombstone_mutation();
DROP TABLE core.purge_tombstone;
DROP TABLE core.retention_rule;
""")
